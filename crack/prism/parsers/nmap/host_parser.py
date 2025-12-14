"""
Nmap Host Parser

State machine parser for extracting hosts from nmap output.
"""

import logging
from enum import Enum, auto
from typing import List, Optional

from ...models import NmapHost, NmapPort, NmapScript, PortState
from . import patterns

logger = logging.getLogger(__name__)


class ParseState(Enum):
    """Parser state machine states"""
    IDLE = auto()
    IN_HOST = auto()
    IN_PORT_TABLE = auto()
    IN_SCRIPT = auto()
    IN_HOST_SCRIPTS = auto()
    IN_OS_SECTION = auto()
    IN_TRACEROUTE = auto()


class HostParser:
    """State machine parser for nmap host blocks"""

    def __init__(self):
        self.state = ParseState.IDLE
        self.hosts: List[NmapHost] = []
        self.current_host: Optional[NmapHost] = None
        self.current_port: Optional[NmapPort] = None
        self.current_script_name: str = ""
        self.current_script_output: List[str] = []
        self.in_host_scripts = False

    def parse(self, lines: List[str]) -> List[NmapHost]:
        """Parse lines and return list of hosts"""
        self.hosts = []
        self.state = ParseState.IDLE
        self.current_host = None

        for line_num, line in enumerate(lines, 1):
            try:
                self._process_line(line, line_num)
            except Exception as e:
                logger.debug(f"Error processing line {line_num}: {e}")

        # Save any pending host
        self._save_current_host()

        return self.hosts

    def _process_line(self, line: str, line_num: int):
        """Process a single line based on current state"""
        stripped = line.strip()

        # Check for new host report (always transitions)
        if patterns.is_host_report(stripped):
            self._save_current_host()
            self._start_new_host(stripped)
            return

        # Handle based on current state
        if self.state == ParseState.IDLE:
            return

        elif self.state == ParseState.IN_HOST:
            self._process_host_line(stripped, line)

        elif self.state == ParseState.IN_PORT_TABLE:
            self._process_port_table_line(stripped, line)

        elif self.state == ParseState.IN_SCRIPT:
            self._process_script_line(stripped, line)

        elif self.state == ParseState.IN_HOST_SCRIPTS:
            self._process_host_script_line(stripped, line)

        elif self.state == ParseState.IN_TRACEROUTE:
            self._process_traceroute_line(stripped, line)

    def _start_new_host(self, line: str):
        """Start a new host block"""
        match = patterns.HOST_REPORT.match(line)
        if not match:
            return

        hostname, ip_with_hostname, ip_only, extra = match.groups()

        # Determine IP and hostname
        if ip_with_hostname:
            ip = ip_with_hostname
        else:
            ip = ip_only
            hostname = None

        self.current_host = NmapHost(ip=ip, hostname=hostname)

        # Check for [host down] marker
        if extra:
            down_match = patterns.HOST_DOWN_MARKER.search(extra)
            if down_match:
                self.current_host.status = "down"
                self.current_host.status_reason = down_match.group(1)

        self.state = ParseState.IN_HOST
        self.in_host_scripts = False
        logger.debug(f"Started host: {ip}")

    def _process_host_line(self, stripped: str, line: str):
        """Process line in IN_HOST state"""
        if not self.current_host:
            return

        # Host status
        status_match = patterns.HOST_STATUS.match(stripped)
        if status_match:
            status, reason, ttl, latency = status_match.groups()
            self.current_host.status = status.lower()
            if reason:
                self.current_host.status_reason = reason
            if ttl:
                self.current_host.ttl = int(ttl)
            if latency:
                self.current_host.latency = float(latency)
            return

        # Port table header - transition to port table
        if patterns.PORT_TABLE_HEADER.match(stripped):
            self.state = ParseState.IN_PORT_TABLE
            return

        # Scanned at timestamp
        scanned_match = patterns.SCANNED_AT.match(stripped)
        if scanned_match:
            self.current_host.scan_time = scanned_match.group(1)
            self.current_host.scan_duration = int(scanned_match.group(2))
            return

        # Service Info line
        service_match = patterns.SERVICE_INFO.match(stripped)
        if service_match:
            self._parse_service_info(service_match.group(1))
            return

        # OS details
        os_match = patterns.OS_DETAILS.match(stripped)
        if os_match:
            self.current_host.os_name = os_match.group(1).strip()
            return

        # OS guesses
        os_guess_match = patterns.OS_GUESS.match(stripped)
        if os_guess_match:
            guess = os_guess_match.group(1)
            # Take first guess (before comma)
            if ',' in guess:
                guess = guess.split(',')[0]
            # Extract accuracy if present
            if '(' in guess and '%' in guess:
                parts = guess.rsplit('(', 1)
                self.current_host.os_name = parts[0].strip()
                try:
                    acc = parts[1].replace('%)', '').replace(')', '').strip()
                    self.current_host.os_accuracy = int(acc)
                except ValueError:
                    pass
            else:
                self.current_host.os_name = guess.strip()
            return

        # OS CPE
        cpe_match = patterns.OS_CPE.match(stripped)
        if cpe_match:
            self.current_host.os_cpe = cpe_match.group(1).strip()
            return

        # Network distance
        dist_match = patterns.NETWORK_DISTANCE.match(stripped)
        if dist_match:
            self.current_host.network_distance = int(dist_match.group(1))
            return

        # Uptime guess
        uptime_match = patterns.UPTIME_GUESS.match(stripped)
        if uptime_match:
            days = float(uptime_match.group(1))
            self.current_host.uptime_seconds = days * 86400
            if uptime_match.group(2):
                self.current_host.uptime_last_boot = uptime_match.group(2)
            return

        # Host script results header
        if patterns.HOST_SCRIPT_HEADER.match(stripped):
            self.state = ParseState.IN_HOST_SCRIPTS
            self.in_host_scripts = True
            return

        # Traceroute header
        traceroute_match = patterns.TRACEROUTE_HEADER.match(stripped)
        if traceroute_match:
            self.state = ParseState.IN_TRACEROUTE
            return

    def _process_port_table_line(self, stripped: str, line: str):
        """Process line in port table"""
        if not self.current_host:
            return

        # Check for port entry
        port_match = patterns.PORT_ENTRY.match(stripped)
        if port_match:
            self._save_current_port()
            port_num, protocol, state, service, version = port_match.groups()
            self.current_port = NmapPort(
                port=int(port_num),
                protocol=protocol.lower(),
                state=PortState.from_string(state),
                service=service or "",
                version=version.strip() if version else "",
            )

            # Try to extract reason and ttl from verbose format
            verbose_match = patterns.PORT_ENTRY_VERBOSE.match(stripped)
            if verbose_match:
                _, _, _, _, reason, ttl, ver = verbose_match.groups()
                self.current_port.reason = reason
                self.current_port.reason_ttl = int(ttl)
                if ver:
                    self.current_port.version = ver.strip()

            return

        # Script output line
        if patterns.is_script_line(stripped):
            self._save_current_port()
            self.state = ParseState.IN_SCRIPT
            self._process_script_line(stripped, line)
            return

        # Service Info
        service_match = patterns.SERVICE_INFO.match(stripped)
        if service_match:
            self._save_current_port()
            self._parse_service_info(service_match.group(1))
            self.state = ParseState.IN_HOST
            return

        # Host script results
        if patterns.HOST_SCRIPT_HEADER.match(stripped):
            self._save_current_port()
            self.state = ParseState.IN_HOST_SCRIPTS
            self.in_host_scripts = True
            return

        # OS Detection section
        if stripped.startswith('OS ') or stripped.startswith('Aggressive OS'):
            self._save_current_port()
            self.state = ParseState.IN_HOST
            self._process_host_line(stripped, line)
            return

        # Traceroute
        if patterns.TRACEROUTE_HEADER.match(stripped):
            self._save_current_port()
            self.state = ParseState.IN_TRACEROUTE
            return

    def _process_script_line(self, stripped: str, line: str):
        """Process NSE script output line"""
        if not self.current_host:
            return

        # Not a script line - end of script section
        if not patterns.is_script_line(stripped):
            self._save_current_script()

            # Check what this line is
            if patterns.is_port_line(stripped):
                self.state = ParseState.IN_PORT_TABLE
                self._process_port_table_line(stripped, line)
            elif patterns.SERVICE_INFO.match(stripped):
                self._parse_service_info(patterns.SERVICE_INFO.match(stripped).group(1))
                self.state = ParseState.IN_HOST
            elif patterns.HOST_SCRIPT_HEADER.match(stripped):
                self.state = ParseState.IN_HOST_SCRIPTS
                self.in_host_scripts = True
            elif patterns.TRACEROUTE_HEADER.match(stripped):
                self.state = ParseState.IN_TRACEROUTE
            else:
                self.state = ParseState.IN_HOST
                self._process_host_line(stripped, line)
            return

        # Parse script line
        script_match = patterns.SCRIPT_NAME.match(stripped)
        if script_match:
            # New script - save previous
            self._save_current_script()
            self.current_script_name = script_match.group(1)
            output = script_match.group(2)
            if output:
                self.current_script_output = [output]
            else:
                self.current_script_output = []
        else:
            # Continuation line
            content = patterns.SCRIPT_LINE.match(stripped)
            if content:
                self.current_script_output.append(content.group(1))

        # Extract domain info from script output
        self._extract_domain_info(stripped)

    def _process_host_script_line(self, stripped: str, line: str):
        """Process host script section"""
        if not self.current_host:
            return

        # Not a script line - end of host scripts
        if not patterns.is_script_line(stripped):
            self._save_current_script()
            self.in_host_scripts = False

            if patterns.TRACEROUTE_HEADER.match(stripped):
                self.state = ParseState.IN_TRACEROUTE
            else:
                self.state = ParseState.IN_HOST
                self._process_host_line(stripped, line)
            return

        # Parse as script
        script_match = patterns.SCRIPT_NAME.match(stripped)
        if script_match:
            self._save_current_script()
            self.current_script_name = script_match.group(1)
            output = script_match.group(2)
            self.current_script_output = [output] if output else []
        else:
            content = patterns.SCRIPT_LINE.match(stripped)
            if content:
                self.current_script_output.append(content.group(1))

        # Extract domain info
        self._extract_domain_info(stripped)

    def _process_traceroute_line(self, stripped: str, line: str):
        """Process traceroute section"""
        if not self.current_host:
            return

        # Traceroute hop
        hop_match = patterns.TRACEROUTE_HOP.match(stripped)
        if hop_match:
            hop_num, latency, addr = hop_match.groups()
            self.current_host.traceroute_hops.append({
                'hop': int(hop_num),
                'latency_ms': float(latency),
                'address': addr,
            })
            return

        # End of traceroute
        if not stripped or stripped.startswith('Nmap') or stripped.startswith('#'):
            self.state = ParseState.IN_HOST
            return

    def _save_current_host(self):
        """Save current host to hosts list"""
        self._save_current_port()
        self._save_current_script()

        if self.current_host:
            self.hosts.append(self.current_host)
            logger.debug(f"Saved host: {self.current_host.ip} "
                        f"({len(self.current_host.open_ports)} open ports)")
        self.current_host = None

    def _save_current_port(self):
        """Save current port to current host"""
        if self.current_port and self.current_host:
            self.current_host.ports.append(self.current_port)
        self.current_port = None

    def _save_current_script(self):
        """Save current script output"""
        if not self.current_script_name or not self.current_host:
            self.current_script_name = ""
            self.current_script_output = []
            return

        script = NmapScript(
            name=self.current_script_name,
            output='\n'.join(self.current_script_output),
        )

        if self.in_host_scripts:
            self.current_host.host_scripts.append(script)
        elif self.current_port:
            self.current_port.scripts.append(script)
        elif self.current_host.ports:
            # Attach to last port
            self.current_host.ports[-1].scripts.append(script)

        self.current_script_name = ""
        self.current_script_output = []

    def _parse_service_info(self, info: str):
        """Parse Service Info line"""
        if not self.current_host:
            return

        # Extract OS
        os_match = patterns.SERVICE_INFO_OS.search(info)
        if os_match:
            self.current_host.service_info_os = os_match.group(1).strip()

        # Extract Host
        host_match = patterns.SERVICE_INFO_HOST.search(info)
        if host_match:
            self.current_host.service_info_host = host_match.group(1).strip()

        # Extract CPE
        cpe_match = patterns.SERVICE_INFO_CPE.search(info)
        if cpe_match and not self.current_host.os_cpe:
            self.current_host.os_cpe = cpe_match.group(1).strip()

    def _extract_domain_info(self, line: str):
        """Extract domain information from script output"""
        if not self.current_host:
            return

        # NTLM info
        netbios_domain = patterns.NTLM_NETBIOS_DOMAIN.search(line)
        if netbios_domain:
            self.current_host.netbios_domain = netbios_domain.group(1)

        netbios_computer = patterns.NTLM_NETBIOS_COMPUTER.search(line)
        if netbios_computer:
            self.current_host.netbios_name = netbios_computer.group(1)

        dns_domain = patterns.NTLM_DNS_DOMAIN.search(line)
        if dns_domain:
            self.current_host.dns_domain = dns_domain.group(1)

        dns_computer = patterns.NTLM_DNS_COMPUTER.search(line)
        if dns_computer:
            self.current_host.dns_computer = dns_computer.group(1)

        # LDAP domain
        ldap_domain = patterns.LDAP_DOMAIN.search(line)
        if ldap_domain:
            self.current_host.domain = ldap_domain.group(1)
