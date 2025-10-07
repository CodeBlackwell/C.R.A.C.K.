"""
Nmap XML output parser

Parses nmap XML files (-oX or -oA output) and emits events
for discovered ports, services, and versions.
"""

import xml.etree.ElementTree as ET
from typing import Dict, Any, List
from .base import Parser
from .registry import ParserRegistry
from ..core.events import EventBus
import logging

logger = logging.getLogger(__name__)


@ParserRegistry.register
class NmapXMLParser(Parser):
    """Parse nmap XML output"""

    @property
    def name(self) -> str:
        return "nmap-xml"

    def can_parse(self, filepath: str) -> bool:
        """Check if file is nmap XML"""
        if not self.validate_file(filepath):
            return False

        if not filepath.endswith('.xml'):
            return False

        # Check for nmap XML signature
        try:
            with open(filepath, 'r') as f:
                first_lines = f.read(500)
                return 'nmaprun' in first_lines.lower() or '<?xml' in first_lines

        except Exception:
            return False

    def parse(self, filepath: str, target: str = None) -> Dict[str, Any]:
        """Parse nmap XML file

        Args:
            filepath: Path to nmap XML file
            target: Optional target hint (not needed for XML)

        Returns:
            Dictionary with parsed data
        """
        try:
            tree = ET.parse(filepath)
            root = tree.getroot()

            # Extract data
            data = {
                'target': None,
                'ports': [],
                'hostnames': [],
                'os_guess': None,
                'scan_info': {}
            }

            # Process each host
            for host in root.findall('.//host'):
                # Get host address
                address = host.find('.//address[@addrtype="ipv4"]')
                if address is not None:
                    data['target'] = address.get('addr')
                else:
                    # Try IPv6
                    address = host.find('.//address[@addrtype="ipv6"]')
                    if address is not None:
                        data['target'] = address.get('addr')

                # Get hostnames
                hostnames = host.findall('.//hostname')
                for hostname in hostnames:
                    name = hostname.get('name')
                    if name:
                        data['hostnames'].append(name)

                # Get OS detection
                osmatch = host.find('.//osmatch')
                if osmatch is not None:
                    data['os_guess'] = osmatch.get('name')

                # Get ports
                for port in host.findall('.//port'):
                    port_data = self._parse_port(port, data['target'])
                    if port_data:
                        data['ports'].append(port_data)

                        # Emit events for service detection
                        self._emit_port_events(port_data, data['target'])

            # Get scan info
            scaninfo = root.find('.//scaninfo')
            if scaninfo is not None:
                data['scan_info'] = {
                    'type': scaninfo.get('type'),
                    'protocol': scaninfo.get('protocol'),
                    'services': scaninfo.get('services')
                }

            logger.info(f"Parsed {filepath}: {len(data['ports'])} ports found")

            return data

        except ET.ParseError as e:
            logger.error(f"XML parse error in {filepath}: {e}")
            raise ValueError(f"Invalid XML file: {e}")

        except Exception as e:
            logger.error(f"Error parsing {filepath}: {e}")
            raise

    def _parse_port(self, port_elem, target: str) -> Dict[str, Any]:
        """Parse port element from XML

        Args:
            port_elem: XML port element
            target: Target IP

        Returns:
            Port data dictionary
        """
        port_num = int(port_elem.get('portid'))
        protocol = port_elem.get('protocol', 'tcp')

        # Get state
        state_elem = port_elem.find('state')
        state = state_elem.get('state') if state_elem is not None else 'unknown'

        # Only process open ports
        if state != 'open':
            return None

        # Get service info
        service_elem = port_elem.find('service')
        service_name = None
        service_product = None
        service_version = None
        service_extra = None

        if service_elem is not None:
            service_name = service_elem.get('name')
            service_product = service_elem.get('product')
            service_version = service_elem.get('version')
            service_extra = service_elem.get('extrainfo')

        # Build version string
        version_parts = []
        if service_product:
            version_parts.append(service_product)
        if service_version:
            version_parts.append(service_version)
        if service_extra:
            version_parts.append(f"({service_extra})")

        version_string = ' '.join(version_parts) if version_parts else None

        # Get script output
        scripts = {}
        for script in port_elem.findall('.//script'):
            script_id = script.get('id')
            script_output = script.get('output')
            if script_id and script_output:
                scripts[script_id] = script_output

        return {
            'port': port_num,
            'protocol': protocol,
            'state': state,
            'service': service_name,
            'version': version_string,
            'extra': {
                'product': service_product,
                'version_detail': service_version,
                'extrainfo': service_extra,
                'scripts': scripts
            }
        }

    def _emit_port_events(self, port_data: Dict[str, Any], target: str):
        """Emit events for port discovery

        Args:
            port_data: Port information dictionary
            target: Target IP
        """
        # Emit port discovered event
        EventBus.emit('port_discovered', {
            'target': target,
            'port': port_data['port'],
            'state': port_data['state']
        })

        # Emit service detected event if service identified
        if port_data.get('service'):
            EventBus.emit('service_detected', {
                'target': target,
                'port': port_data['port'],
                'service': port_data['service'],
                'version': port_data.get('version')
            })

        # Emit version detected event if version identified
        if port_data.get('version'):
            EventBus.emit('version_detected', {
                'target': target,
                'port': port_data['port'],
                'service': port_data['service'],
                'version': port_data['version']
            })
