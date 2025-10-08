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
                'os_details': {},
                'scan_info': {},
                'scan_stats': {},
                'nmap_command': None,
                'traceroute': []
            }

            # Extract nmap command from XML metadata (Chapter 8: Command reconstruction)
            data['nmap_command'] = self._extract_nmap_command(root)

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

                # Get OS detection (enhanced with accuracy and CPE)
                data['os_details'] = self._parse_os_detection(host)
                if data['os_details'].get('best_match'):
                    data['os_guess'] = data['os_details']['best_match']

                # Get traceroute data (Chapter 8: Network topology)
                traceroute = self._parse_traceroute(host)
                if traceroute:
                    data['traceroute'] = traceroute

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
                    'services': scaninfo.get('services'),
                    'numservices': scaninfo.get('numservices')
                }

            # Get scan statistics (Chapter 8: Performance metrics)
            data['scan_stats'] = self._parse_scan_stats(root)

            logger.info(f"Parsed {filepath}: {len(data['ports'])} ports found in {data['scan_stats'].get('elapsed', 'N/A')}s")

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

        # Get state (Chapter 8: --reason flag support)
        state_elem = port_elem.find('state')
        state = state_elem.get('state') if state_elem is not None else 'unknown'
        reason = state_elem.get('reason') if state_elem is not None else None
        reason_ttl = state_elem.get('reason_ttl') if state_elem is not None else None

        # Only process open ports
        if state != 'open':
            return None

        # Get service info
        service_elem = port_elem.find('service')
        service_name = None
        service_product = None
        service_version = None
        service_extra = None
        service_cpe = []

        if service_elem is not None:
            service_name = service_elem.get('name')
            service_product = service_elem.get('product')
            service_version = service_elem.get('version')
            service_extra = service_elem.get('extrainfo')

            # Extract CPE identifiers (for CVE matching)
            for cpe_elem in service_elem.findall('.//cpe'):
                if cpe_elem.text:
                    service_cpe.append(cpe_elem.text)

        # Build version string
        version_parts = []
        if service_product:
            version_parts.append(service_product)
        if service_version:
            version_parts.append(service_version)
        if service_extra:
            version_parts.append(f"({service_extra})")

        version_string = ' '.join(version_parts) if version_parts else None

        # Get script output (Chapter 8: Enhanced NSE structured output)
        scripts = {}
        scripts_structured = {}

        for script in port_elem.findall('.//script'):
            script_id = script.get('id')
            script_output = script.get('output')

            if script_id and script_output:
                scripts[script_id] = script_output

                # Parse structured output (Nmap 6+ feature from Chapter 8)
                structured = self._parse_nse_structured_output(script)
                if structured:
                    scripts_structured[script_id] = structured

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
                'cpe': service_cpe,
                'reason': reason,
                'reason_ttl': reason_ttl,
                'scripts': scripts,
                'scripts_structured': scripts_structured
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

    def _extract_nmap_command(self, root) -> str:
        """Extract nmap command from XML metadata

        Chapter 8: Command reconstruction for OSCP documentation

        Args:
            root: XML root element

        Returns:
            Nmap command string
        """
        nmaprun = root
        if nmaprun.tag == 'nmaprun':
            args = nmaprun.get('args')
            if args:
                return args

        return None

    def _parse_os_detection(self, host_elem) -> Dict[str, Any]:
        """Parse OS detection results with accuracy scores

        Args:
            host_elem: Host XML element

        Returns:
            OS detection details
        """
        os_data = {
            'best_match': None,
            'accuracy': 0,
            'matches': [],
            'cpe': []
        }

        os = host_elem.find('.//os')
        if os is None:
            return os_data

        # Get all OS matches (ordered by accuracy)
        for osmatch in os.findall('.//osmatch'):
            match_name = osmatch.get('name')
            accuracy = int(osmatch.get('accuracy', 0))

            match_data = {
                'name': match_name,
                'accuracy': accuracy
            }

            # Extract OS classes
            osclasses = []
            for osclass in osmatch.findall('.//osclass'):
                osclasses.append({
                    'type': osclass.get('type'),
                    'vendor': osclass.get('vendor'),
                    'osfamily': osclass.get('osfamily'),
                    'osgen': osclass.get('osgen'),
                    'accuracy': osclass.get('accuracy')
                })

                # Extract CPE
                for cpe_elem in osclass.findall('.//cpe'):
                    if cpe_elem.text and cpe_elem.text not in os_data['cpe']:
                        os_data['cpe'].append(cpe_elem.text)

            match_data['osclasses'] = osclasses
            os_data['matches'].append(match_data)

            # Track best match
            if accuracy > os_data['accuracy']:
                os_data['best_match'] = match_name
                os_data['accuracy'] = accuracy

        return os_data

    def _parse_traceroute(self, host_elem) -> List[Dict[str, Any]]:
        """Parse traceroute data for network topology

        Chapter 8: Network topology mapping

        Args:
            host_elem: Host XML element

        Returns:
            List of hop dictionaries
        """
        hops = []

        trace = host_elem.find('.//trace')
        if trace is None:
            return hops

        for hop_elem in trace.findall('.//hop'):
            hop = {
                'ttl': int(hop_elem.get('ttl', 0)),
                'ipaddr': hop_elem.get('ipaddr'),
                'host': hop_elem.get('host', ''),
                'rtt': hop_elem.get('rtt', '')
            }
            hops.append(hop)

        return hops

    def _parse_scan_stats(self, root) -> Dict[str, Any]:
        """Parse scan statistics and performance metrics

        Chapter 8: Scan performance tracking for OSCP time management

        Args:
            root: XML root element

        Returns:
            Scan statistics dictionary
        """
        stats = {
            'elapsed': None,
            'exit_status': None,
            'summary': None,
            'hosts_up': 0,
            'hosts_down': 0,
            'hosts_total': 0
        }

        runstats = root.find('.//runstats')
        if runstats is None:
            return stats

        # Get timing information
        finished = runstats.find('.//finished')
        if finished is not None:
            stats['elapsed'] = finished.get('elapsed')
            stats['exit_status'] = finished.get('exit')
            stats['summary'] = finished.get('summary')

        # Get host statistics
        hosts = runstats.find('.//hosts')
        if hosts is not None:
            stats['hosts_up'] = int(hosts.get('up', 0))
            stats['hosts_down'] = int(hosts.get('down', 0))
            stats['hosts_total'] = int(hosts.get('total', 0))

        return stats

    def _parse_nse_structured_output(self, script_elem) -> Dict[str, Any]:
        """Parse NSE structured XML output

        Chapter 8: Nmap 6+ structured script output feature

        Args:
            script_elem: Script XML element

        Returns:
            Structured data dictionary or None
        """
        structured = {}

        # Parse elem tags (key-value pairs)
        for elem in script_elem.findall('.//elem'):
            key = elem.get('key')
            value = elem.text

            if key:
                structured[key] = value
            else:
                # Anonymous elem (list item)
                if '_items' not in structured:
                    structured['_items'] = []
                structured['_items'].append(value)

        # Parse table tags (nested structures)
        for table in script_elem.findall('.//table'):
            table_key = table.get('key')
            table_data = self._parse_nse_table(table)

            if table_key:
                structured[table_key] = table_data
            else:
                if '_tables' not in structured:
                    structured['_tables'] = []
                structured['_tables'].append(table_data)

        return structured if structured else None

    def _parse_nse_table(self, table_elem) -> Dict[str, Any]:
        """Recursively parse NSE table elements

        Args:
            table_elem: Table XML element

        Returns:
            Table data dictionary
        """
        table_data = {}

        # Parse elem children
        for elem in table_elem.findall('./elem'):
            key = elem.get('key')
            value = elem.text

            if key:
                table_data[key] = value
            else:
                if '_items' not in table_data:
                    table_data['_items'] = []
                table_data['_items'].append(value)

        # Parse nested tables
        for nested_table in table_elem.findall('./table'):
            table_key = nested_table.get('key')
            nested_data = self._parse_nse_table(nested_table)

            if table_key:
                table_data[table_key] = nested_data
            else:
                if '_tables' not in table_data:
                    table_data['_tables'] = []
                table_data['_tables'].append(nested_data)

        return table_data
