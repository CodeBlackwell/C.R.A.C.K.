"""
Nmap greppable format parser

Parses nmap .gnmap files (greppable output from -oG or -oA)
"""

import re
from typing import Dict, Any, List
from .base import Parser
from .registry import ParserRegistry
from ..core.events import EventBus
import logging

logger = logging.getLogger(__name__)


@ParserRegistry.register
class NmapGnmapParser(Parser):
    """Parse nmap greppable (.gnmap) output"""

    @property
    def name(self) -> str:
        return "nmap-gnmap"

    def can_parse(self, filepath: str) -> bool:
        """Check if file is nmap greppable format"""
        if not self.validate_file(filepath):
            return False

        if not filepath.endswith('.gnmap'):
            return False

        # Check for gnmap signature
        try:
            with open(filepath, 'r') as f:
                first_line = f.readline()
                return first_line.startswith('# Nmap')

        except Exception:
            return False

    def parse(self, filepath: str, target: str = None) -> Dict[str, Any]:
        """Parse nmap greppable file

        Args:
            filepath: Path to .gnmap file
            target: Optional target hint

        Returns:
            Dictionary with parsed data
        """
        data = {
            'target': target,
            'ports': [],
            'hostnames': [],
            'os_guess': None,
            'scan_info': {}
        }

        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()

                    # Skip comments and empty lines
                    if not line or line.startswith('#'):
                        continue

                    # Parse host line
                    if line.startswith('Host:'):
                        host_data = self._parse_host_line(line)
                        if host_data:
                            # Update target if not set
                            if not data['target']:
                                data['target'] = host_data['ip']

                            # Add hostname if found
                            if host_data.get('hostname'):
                                data['hostnames'].append(host_data['hostname'])

                            # Add ports
                            for port_data in host_data.get('ports', []):
                                data['ports'].append(port_data)

                                # Emit events
                                self._emit_port_events(port_data, data['target'])

            logger.info(f"Parsed {filepath}: {len(data['ports'])} ports found")

            return data

        except Exception as e:
            logger.error(f"Error parsing {filepath}: {e}")
            raise

    def _parse_host_line(self, line: str) -> Dict[str, Any]:
        """Parse a host line from gnmap

        Format: Host: IP (HOSTNAME) Status: STATE Ports: PORT/STATE/PROTO/OWNER/SVC/REASON/VERSION

        Args:
            line: Host line from gnmap file

        Returns:
            Dictionary with host data
        """
        data = {
            'ip': None,
            'hostname': None,
            'status': None,
            'ports': []
        }

        # Extract IP and hostname
        # Format: Host: 192.168.1.1 (hostname.com)
        host_match = re.search(r'Host:\s+([\d\.]+)\s*(?:\(([^\)]+)\))?', line)
        if host_match:
            data['ip'] = host_match.group(1)
            if host_match.group(2):
                data['hostname'] = host_match.group(2)

        # Extract status
        status_match = re.search(r'Status:\s+(\w+)', line)
        if status_match:
            data['status'] = status_match.group(1)

        # Only process if host is up
        if data['status'] != 'Up':
            return data

        # Extract ports
        # Format: Ports: 22/open/tcp//ssh//OpenSSH 7.6p1/, 80/open/tcp//http//Apache httpd 2.4.29/
        ports_match = re.search(r'Ports:\s+(.+?)(?:\s+Ignored|$)', line)
        if ports_match:
            ports_str = ports_match.group(1)

            # Split by comma to get individual ports
            for port_entry in ports_str.split(','):
                port_entry = port_entry.strip()
                if not port_entry:
                    continue

                # Parse port entry: PORT/STATE/PROTO/OWNER/SERVICE/REASON/VERSION
                parts = port_entry.split('/')

                if len(parts) >= 3:
                    port_num = parts[0].strip()
                    state = parts[1].strip()
                    protocol = parts[2].strip()

                    # Only process open ports
                    if state != 'open':
                        continue

                    service = parts[4].strip() if len(parts) > 4 else None
                    version = parts[6].strip() if len(parts) > 6 else None

                    # Clean up service and version
                    if service and not service:
                        service = None
                    if version and not version:
                        version = None

                    try:
                        data['ports'].append({
                            'port': int(port_num),
                            'state': state,
                            'protocol': protocol,
                            'service': service,
                            'version': version,
                            'extra': {}
                        })
                    except ValueError:
                        # Skip invalid port numbers
                        continue

        return data

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
