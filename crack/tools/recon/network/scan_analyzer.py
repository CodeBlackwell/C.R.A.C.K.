#!/usr/bin/env python3
"""
Nmap Scan Analyzer - Educational scan result interpretation
Parses nmap output to identify attack vectors and prioritize targets
Helps security professionals understand what to investigate without LLM assistance
"""

import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import xml.etree.ElementTree as ET

try:
    from crack.core.themes import Colors
except ImportError:
    class Colors:
        HEADER = '\033[95m'
        BLUE = '\033[94m'
        CYAN = '\033[96m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        RED = '\033[91m'
        BOLD = '\033[1m'
        END = '\033[0m'


class ScanAnalyzer:
    """Analyzes nmap scans to identify and prioritize attack vectors"""

    # Standard ports by OS type
    STANDARD_PORTS = {
        'windows': {
            21,    # FTP
            25,    # SMTP
            53,    # DNS
            80,    # HTTP
            88,    # Kerberos
            135,   # MSRPC
            139,   # NetBIOS-SSN
            443,   # HTTPS
            445,   # Microsoft-DS
            464,   # Kerberos Password
            593,   # HTTP RPC Endpoint
            636,   # LDAPS
            1433,  # MSSQL
            3268,  # Global Catalog
            3269,  # Global Catalog SSL
            3389,  # RDP
            5985,  # WinRM HTTP
            5986,  # WinRM HTTPS
            8080,  # HTTP Alternate
            8443,  # HTTPS Alternate
            *range(49152, 65536)  # Dynamic RPC ports
        },
        'linux': {
            21,    # FTP
            22,    # SSH
            23,    # Telnet
            25,    # SMTP
            53,    # DNS
            80,    # HTTP
            110,   # POP3
            111,   # RPCBind
            143,   # IMAP
            443,   # HTTPS
            445,   # SMB
            631,   # IPP (CUPS)
            2049,  # NFS
            3306,  # MySQL
            5432,  # PostgreSQL
            5900,  # VNC
            6000,  # X11
            8080,  # HTTP Alternate
            8443,  # HTTPS Alternate
        },
        'common': {
            21, 22, 23, 25, 53, 80, 110, 143, 443,
            445, 3306, 5432, 8080, 8443
        }
    }

    # Known service patterns for quick identification
    SERVICE_PATTERNS = {
        'web': ['http', 'https', 'ssl/http', 'www', 'web'],
        'database': ['mysql', 'postgresql', 'mssql', 'oracle', 'mongodb'],
        'remote': ['ssh', 'telnet', 'rdp', 'vnc', 'winrm'],
        'file': ['ftp', 'smb', 'netbios', 'nfs', 'microsoft-ds'],
        'mail': ['smtp', 'pop3', 'imap'],
    }

    # NSE script recommendations per service type
    NSE_SCRIPTS = {
        'ssh': [
            ('ssh-auth-methods', 'Check authentication methods'),
            ('ssh2-enum-algos', 'Enumerate crypto algorithms (find weak ones)'),
            ('ssh-brute', 'Brute force if password auth is enabled'),
        ],
        'http': [
            ('http-enum', 'Enumerate common directories and files'),
            ('http-methods', 'Check allowed HTTP methods (PUT/DELETE?)'),
            ('http-title', 'Get page title for context'),
            ('http-shellshock', 'Test for Shellshock (older systems)'),
        ],
        'https': [
            ('ssl-cert', 'Certificate information (domains, expiry)'),
            ('ssl-enum-ciphers', 'Check for weak SSL/TLS ciphers'),
            ('http-security-headers', 'Check security headers'),
        ],
        'apache': [
            ('http-apache-server-status', 'Check for exposed server-status'),
            ('http-config-backup', 'Search for backup config files'),
        ],
        'smb': [
            ('smb-enum-shares', 'Enumerate shares'),
            ('smb-enum-users', 'Enumerate users'),
            ('smb-os-discovery', 'Get OS information'),
            ('smb-vuln-*', 'Check all SMB vulnerabilities'),
        ],
        'ftp': [
            ('ftp-anon', 'Check anonymous FTP access'),
            ('ftp-bounce', 'Check FTP bounce attack'),
            ('ftp-vsftpd-backdoor', 'Check for vsftpd 2.3.4 backdoor'),
        ],
        'mysql': [
            ('mysql-empty-password', 'Check for empty root password'),
            ('mysql-enum', 'Enumerate MySQL users and databases'),
            ('mysql-info', 'Get MySQL server information'),
        ],
        'rdp': [
            ('rdp-enum-encryption', 'Check RDP encryption levels'),
            ('rdp-ntlm-info', 'Get NTLM info (OS version, domain)'),
        ],
    }

    def __init__(self, scan_file: str, os_type: str = 'auto'):
        """Initialize analyzer with scan file"""
        self.scan_file = Path(scan_file)
        self.os_type = os_type.lower()
        self.services = []
        self.target_info = {}

    def analyze(self) -> Dict:
        """Main analysis function"""
        # Parse the scan file
        self.parse_scan_file()

        # Auto-detect OS if needed
        if self.os_type == 'auto':
            self.detect_os_type()

        # Classify ports
        classified = self.classify_ports()

        # Calculate priorities
        priorities = self.calculate_priorities()

        # Generate report
        return self.generate_report(classified, priorities)

    def parse_scan_file(self):
        """Parse nmap output file based on format"""
        if not self.scan_file.exists():
            print(f"{Colors.RED}Error: Scan file not found: {self.scan_file}{Colors.END}")
            sys.exit(1)

        content = self.scan_file.read_text()

        # Detect format and parse accordingly
        if self.scan_file.suffix == '.xml':
            self.parse_xml_output(content)
        elif self.scan_file.suffix == '.gnmap':
            self.parse_gnmap_output(content)
        else:  # Assume .nmap or standard text output
            self.parse_text_output(content)

    def parse_text_output(self, content: str):
        """Parse standard nmap text output"""
        # Extract target IP and hostname from scan report line
        scan_report_match = re.search(r'Nmap scan report for\s+([^\s(]+)(?:\s+\(([^)]+)\))?', content)
        if scan_report_match:
            # If there's a hostname and IP in parentheses
            if scan_report_match.group(2):
                self.target_info['hostname'] = scan_report_match.group(1)
                self.target_info['ip'] = scan_report_match.group(2)
            else:
                self.target_info['ip'] = scan_report_match.group(1)

        # Extract hostname from Service Info
        host_match = re.search(r'Service Info:\s+Host:\s+([^;]+)', content)
        if host_match:
            self.target_info['hostname'] = host_match.group(1).strip()

        # Extract hostname from NetBIOS computer name
        netbios_match = re.search(r'NetBIOS computer name:\s+([^\\]+)', content)
        if netbios_match:
            self.target_info['netbios_name'] = netbios_match.group(1).strip()

        # Extract OS info
        os_match = re.search(r'OS:\s+([^;]+)', content)
        if os_match:
            self.target_info['os'] = os_match.group(1).strip()

        # Parse NSE script results
        self.target_info['nse_results'] = self.parse_nse_output(content)

        # Parse services - look for port lines
        port_pattern = r'^(\d+)/tcp\s+(\S+)\s+(\S+)\s*(.*?)$'

        for line in content.split('\n'):
            match = re.match(port_pattern, line, re.MULTILINE)
            if match:
                port = int(match.group(1))
                state = match.group(2)
                service = match.group(3)
                version = match.group(4) if match.group(4) else ''

                if state == 'open':
                    service_info = {
                        'port': port,
                        'service': service,
                        'version': version,
                        'banner': ''
                    }

                    # Look for banner/fingerprint data SPECIFICALLY for this port
                    # Search for the fingerprint section that shows the actual banner response
                    port_section_pattern = rf'{port}/tcp.*?(?=^\d+/tcp|^Service detection|^$)'
                    port_section = re.search(port_section_pattern, content, re.MULTILINE | re.DOTALL)

                    if port_section:
                        # Look for fingerprint-strings section within this port's section
                        if 'fingerprint-strings:' in port_section.group(0):
                            # Extract the banner response (after |_ )
                            banner_match = re.search(
                                r'\|_\s+([^\n]+(?:\n\|_\s+[^\n]+)*)',
                                port_section.group(0)
                            )
                            if banner_match:
                                # Clean up the banner text
                                banner_text = banner_match.group(1)
                                banner_text = re.sub(r'\n\|_\s+', '\n', banner_text)
                                service_info['banner'] = banner_text.strip()

                    self.services.append(service_info)

    def parse_xml_output(self, content: str):
        """Parse nmap XML output"""
        try:
            root = ET.fromstring(content)

            # Get host information
            host = root.find('.//host')
            if host:
                address = host.find('address[@addrtype="ipv4"]')
                if address:
                    self.target_info['ip'] = address.get('addr')

                # Get OS information
                os_elem = host.find('.//osmatch')
                if os_elem:
                    self.target_info['os'] = os_elem.get('name')

                # Parse ports
                for port in host.findall('.//port'):
                    if port.find('state').get('state') == 'open':
                        service = port.find('service')
                        service_info = {
                            'port': int(port.get('portid')),
                            'service': service.get('name', 'unknown') if service else 'unknown',
                            'version': '',
                            'banner': ''
                        }

                        if service:
                            version_parts = []
                            if service.get('product'):
                                version_parts.append(service.get('product'))
                            if service.get('version'):
                                version_parts.append(service.get('version'))
                            service_info['version'] = ' '.join(version_parts)

                            # Check for banner info in script output
                            for script in port.findall('.//script'):
                                if 'banner' in script.get('id', '').lower():
                                    service_info['banner'] = script.get('output', '')

                        self.services.append(service_info)
        except ET.ParseError:
            print(f"{Colors.RED}Error parsing XML file{Colors.END}")
            sys.exit(1)

    def parse_nse_output(self, content: str) -> Dict:
        """Parse NSE script output for security findings"""
        nse_results = {}

        # Parse SMB security mode - look for the whole script output block
        # The format is:
        # | smb-security-mode:
        # |   account_used: guest
        # |   ...
        # |_  message_signing: disabled
        smb_sec_match = re.search(r'\| smb-security-mode:.*?\|_.*?$', content, re.MULTILINE | re.DOTALL)
        if smb_sec_match:
            smb_text = smb_sec_match.group(0)
            nse_results['smb_security'] = {
                'guest_access': 'account_used: guest' in smb_text,
                'message_signing': 'message_signing: disabled' in smb_text,
                'challenge_response': 'challenge_response: supported' in smb_text
            }

        # Parse SMB OS discovery
        smb_os_match = re.search(r'\| smb-os-discovery:.*?\|_.*?$', content, re.MULTILINE | re.DOTALL)
        if smb_os_match:
            smb_os_text = smb_os_match.group(0)
            # Extract OS version
            os_version_match = re.search(r'OS:\s+([^\n]+)', smb_os_text)
            if os_version_match:
                nse_results['smb_os'] = os_version_match.group(1).strip()

            # Extract computer name
            comp_name_match = re.search(r'Computer name:\s+([^\n]+)', smb_os_text)
            if comp_name_match:
                nse_results['computer_name'] = comp_name_match.group(1).strip()

        # Parse SMB2 security mode
        smb2_sec_match = re.search(r'\| smb2-security-mode:.*?\|_.*?$', content, re.MULTILINE | re.DOTALL)
        if smb2_sec_match:
            nse_results['smb2_signing'] = 'Message signing enabled but not required' in smb2_sec_match.group(0)

        return nse_results

    def parse_gnmap_output(self, content: str):
        """Parse greppable nmap output"""
        for line in content.split('\n'):
            if 'Host:' in line and 'Ports:' in line:
                # Extract IP
                ip_match = re.search(r'Host:\s+(\S+)', line)
                if ip_match:
                    self.target_info['ip'] = ip_match.group(1)

                # Extract ports
                ports_section = re.search(r'Ports:\s+(.+?)(?:\s+Ignored|$)', line)
                if ports_section:
                    port_entries = ports_section.group(1).split(', ')
                    for entry in port_entries:
                        parts = entry.split('/')
                        if len(parts) >= 5 and parts[1] == 'open':
                            self.services.append({
                                'port': int(parts[0]),
                                'service': parts[4] if len(parts) > 4 else 'unknown',
                                'version': parts[6] if len(parts) > 6 else '',
                                'banner': ''
                            })

    def detect_os_type(self):
        """Auto-detect OS type from scan results"""
        # Check for Windows indicators
        windows_indicators = ['microsoft', 'windows', 'msrpc', 'netbios', 'smb']
        linux_indicators = ['linux', 'ubuntu', 'debian', 'centos', 'ssh']

        os_string = self.target_info.get('os', '').lower()
        service_string = ' '.join([s['service'].lower() for s in self.services])

        # Check OS string first
        if any(ind in os_string for ind in windows_indicators):
            self.os_type = 'windows'
        elif any(ind in os_string for ind in linux_indicators):
            self.os_type = 'linux'
        # Then check services
        elif any(ind in service_string for ind in windows_indicators):
            self.os_type = 'windows'
        elif any(ind in service_string for ind in linux_indicators):
            self.os_type = 'linux'
        else:
            self.os_type = 'unknown'

    def classify_ports(self) -> Dict:
        """Classify ports as standard or unusual"""
        standard_ports = self.STANDARD_PORTS.get(self.os_type, self.STANDARD_PORTS['common'])

        classified = {
            'standard': [],
            'unusual': [],
            'web': [],
            'database': [],
            'remote': [],
            'file': [],
            'mail': [],
            'unknown': []
        }

        for service in self.services:
            port = service['port']
            service_name = service['service'].lower()

            # Classify by port number
            if port in standard_ports:
                classified['standard'].append(service)
            else:
                classified['unusual'].append(service)

            # Also classify by service type
            categorized = False
            for category, patterns in self.SERVICE_PATTERNS.items():
                if any(pattern in service_name for pattern in patterns):
                    classified[category].append(service)
                    categorized = True
                    break

            # Unknown services
            if not categorized and ('unknown' in service_name or '?' in service_name):
                classified['unknown'].append(service)

        return classified

    def calculate_priorities(self) -> List[Tuple[Dict, int, List[str]]]:
        """Calculate priority scores for each service"""
        priorities = []

        standard_ports = self.STANDARD_PORTS.get(self.os_type, self.STANDARD_PORTS['common'])

        for service in self.services:
            score = 0
            reasons = []

            # Non-standard port = high priority
            if service['port'] not in standard_ports:
                score += 3
                reasons.append("non-standard port")

            # Unknown service = very high priority
            if 'unknown' in service['service'].lower() or '?' in service['service']:
                score += 3
                reasons.append("unknown/custom service")

            # Has unique banner = high priority
            if service['banner']:
                score += 2
                reasons.append("unique banner found")
                # Analyze banner dynamically
                banner_lower = service['banner'].lower()
                # Check for non-standard responses (not typical service banners)
                common_banners = ['apache', 'nginx', 'microsoft', 'openssh', 'proftpd', 'vsftpd']
                if not any(common in banner_lower for common in common_banners):
                    score += 1
                    reasons.append("non-standard banner response")

            # Has version info = medium priority
            if service['version']:
                score += 1
                reasons.append("version info available")

            # Web service = medium priority (often vulnerable)
            if any(web in service['service'].lower() for web in ['http', 'https', 'www']):
                score += 1
                reasons.append("web service")

            # Guest/anonymous access indicators
            if 'guest' in service.get('version', '').lower():
                score += 1
                reasons.append("guest access possible")

            priorities.append((service, score, reasons))

        # Sort by score descending
        priorities.sort(key=lambda x: x[1], reverse=True)

        return priorities

    def generate_report(self, classified: Dict, priorities: List) -> Dict:
        """Generate educational analysis report"""
        report = {
            'target_info': self.target_info,
            'classified_ports': classified,
            'priorities': priorities,
            'commands': self.generate_commands(priorities),
            'methodology': self.explain_methodology(priorities)
        }

        return report

    def generate_version_searches(self, version_string: str) -> List[str]:
        """Generate cascade of searchsploit queries from version info"""
        searches = []
        if not version_string:
            return searches

        # Parse version components
        # Example: "Apache httpd 2.4.7 ((Ubuntu))"
        parts = version_string.split()

        # Try to identify product and version
        product = []
        version = None

        for part in parts:
            # Check if this looks like a version number
            if re.match(r'^\d+\.[\d\.]+', part):
                version = part
                break
            # Skip parenthetical info
            elif part.startswith('('):
                break
            else:
                product.append(part)

        product_name = ' '.join(product).lower()

        if version:
            # Generate searches from most specific to least
            # Full version: "apache 2.4.7"
            searches.append(f'searchsploit "{product_name} {version}"')

            # Minor version: "apache 2.4"
            version_parts = version.split('.')
            if len(version_parts) >= 2:
                minor_version = '.'.join(version_parts[:2])
                searches.append(f'searchsploit "{product_name} {minor_version}"')

            # Major version: "apache 2"
            if len(version_parts) >= 1:
                major_version = version_parts[0]
                searches.append(f'searchsploit "{product_name} {major_version}"')

        # Product only
        if product_name:
            searches.append(f"searchsploit {product_name}")
            # Also search individual product words if multi-word
            if ' ' in product_name:
                for word in product_name.split():
                    if len(word) > 3:  # Skip short words
                        searches.append(f"searchsploit {word}")

        return searches

    def get_nse_scripts(self, service: Dict) -> List[Tuple[str, str]]:
        """Get relevant NSE scripts for a service"""
        scripts = []
        service_lower = service['service'].lower()
        version_lower = service.get('version', '').lower()

        # Check for direct service matches
        for key, script_list in self.NSE_SCRIPTS.items():
            if key in service_lower:
                scripts.extend(script_list)

        # Check for Apache specifically
        if 'apache' in version_lower:
            scripts.extend(self.NSE_SCRIPTS.get('apache', []))

        # Add HTTPS scripts if it's HTTPS
        if service['port'] == 443 or 'https' in service_lower or 'ssl' in service_lower:
            scripts.extend(self.NSE_SCRIPTS.get('https', []))

        return scripts

    def calculate_windows_build_age(self, os_string: str) -> Optional[str]:
        """Assess Windows build age and security risk"""
        # Windows 10/11 build numbers and release dates
        WINDOWS_BUILDS = {
            '15063': (2017, 'Creators Update', 'CRITICAL'),  # v1703 - EOL
            '16299': (2017, 'Fall Creators', 'CRITICAL'),    # v1709 - EOL
            '17134': (2018, 'April 2018', 'HIGH'),           # v1803 - EOL
            '17763': (2018, 'October 2018', 'HIGH'),         # v1809 - EOL
            '18362': (2019, 'May 2019', 'HIGH'),             # v1903 - EOL
            '18363': (2019, 'November 2019', 'MEDIUM'),      # v1909 - EOL
            '19041': (2020, 'May 2020', 'MEDIUM'),           # v2004
            '19042': (2020, 'October 2020', 'MEDIUM'),       # v20H2
            '19043': (2021, 'May 2021', 'LOW'),              # v21H1
            '19044': (2021, 'November 2021', 'LOW'),         # v21H2
            '22000': (2021, 'Windows 11', 'LOW'),            # Win11 21H2
        }

        # Extract build number
        build_match = re.search(r'Windows \d+ (?:Pro |Enterprise |Home )?(\d{5})', os_string)
        if build_match:
            build = build_match.group(1)
            if build in WINDOWS_BUILDS:
                year, version_name, risk = WINDOWS_BUILDS[build]
                age = 2025 - year
                return f"Build {build} ({version_name}) - {age} years old [{risk} RISK]"

        return None

    def detect_version_discrepancies(self) -> List[str]:
        """Detect discrepancies between different version reports"""
        discrepancies = []

        # Check for Windows version mismatches
        if 'nse_results' in self.target_info and self.target_info['nse_results']:
            nse = self.target_info['nse_results']

            # Compare SMB OS discovery with banner versions
            for service in self.services:
                if service.get('banner'):
                    # Check if banner reports different Windows version
                    banner_win_match = re.search(r'windows\s+([\d\.]+)', service['banner'].lower())
                    if banner_win_match and 'smb_os' in nse:
                        banner_version = banner_win_match.group(1)
                        # Windows 6.2 = Windows 8/Server 2012
                        # Windows 6.3 = Windows 8.1/Server 2012 R2
                        # Windows 10.0 = Windows 10/11
                        if banner_version == '6.2' and 'Windows 10' in nse['smb_os']:
                            discrepancies.append(
                                f"Port {service['port']} reports Windows 6.2 (Win8) but OS is Windows 10"
                            )

        return discrepancies

    def calculate_software_age(self, version_string: str) -> Optional[str]:
        """Estimate software age and risk based on version"""
        # Common software release dates (simplified)
        SOFTWARE_DATES = {
            'apache httpd 2.4.7': (2013, 'HIGH'),  # 11+ years old
            'apache 2.4.7': (2013, 'HIGH'),
            'apache 2.4.6': (2013, 'HIGH'),
            'apache 2.4': (2012, 'MEDIUM'),
            'apache 2.2': (2005, 'CRITICAL'),  # EOL
            'openssh 6.6.1': (2014, 'HIGH'),  # 10+ years old
            'openssh 6.6': (2014, 'HIGH'),
            'openssh 6': (2012, 'HIGH'),
            'openssh 7': (2015, 'MEDIUM'),
            'openssh 8': (2019, 'LOW'),
            'openssh 9': (2022, 'LOW'),
            'proftpd 1.3.3': (2010, 'CRITICAL'),  # Known vulnerable
            'vsftpd 2.3.4': (2011, 'CRITICAL'),  # Backdoor version
            'samba 3': (2003, 'CRITICAL'),
            'samba 4.1': (2013, 'HIGH'),
            'mysql 5.5': (2010, 'HIGH'),
            'mysql 5.7': (2015, 'MEDIUM'),
            'postgresql 9': (2011, 'HIGH'),
            'postgresql 10': (2017, 'MEDIUM'),
        }

        if not version_string:
            return None

        # Normalize version string - remove extra info like ((Ubuntu))
        # Handle nested parentheses
        version_clean = re.sub(r'\s*\([^)]*\)+', '', version_string).lower()
        version_clean = version_clean.strip()

        # Try exact matches first
        for key, (year, risk) in sorted(SOFTWARE_DATES.items(), key=lambda x: -len(x[0])):
            if key in version_clean:
                age = 2025 - year
                return f"{age}+ years old ({risk} RISK)"

        return None

    def generate_commands(self, priorities: List) -> Dict:
        """Generate specific commands for top priority targets"""
        commands = {}

        for service, score, reasons in priorities[:3]:  # Top 3 priorities
            port = service['port']
            cmd_dict = {
                'searchsploit': [],
                'nse_scripts': [],
                'manual': [],
                'enumeration': [],
                'info': []
            }

            # Generate hostname-based searches if port is unusual
            if 'hostname' in self.target_info and port not in self.STANDARD_PORTS.get(self.os_type, []):
                hostname = self.target_info['hostname']
                # Add hostname-based searches
                if hostname:
                    # Search exact hostname
                    cmd_dict['searchsploit'].append(f'searchsploit {hostname.lower()}')

                    # Try to split compound words (e.g., REMOTEMOUSE -> remote mouse)
                    # Common patterns: RemoteMouse, REMOTEMOUSE, remote-mouse
                    # Look for common word boundaries in security software names
                    word_patterns = [
                        (r'(REMOTE)(MOUSE)', r'\1 \2'),
                        (r'(WIFI)(MOUSE)', r'\1 \2'),
                        (r'(MOBILE)(MOUSE)', r'\1 \2'),
                        (r'(TEAM)(VIEWER)', r'\1 \2'),
                        (r'(ANY)(DESK)', r'\1 \2'),
                        (r'(ULTRA)(VNC)', r'\1 \2'),
                        (r'(REAL)(VNC)', r'\1 \2'),
                    ]

                    hostname_upper = hostname.upper()
                    for pattern, replacement in word_patterns:
                        if re.search(pattern, hostname_upper):
                            spaced_name = re.sub(pattern, replacement, hostname_upper).lower()
                            cmd_dict['searchsploit'].append(f'searchsploit "{spaced_name}"')
                            break

            # Generate version-based searches
            if service['version']:
                version_searches = self.generate_version_searches(service['version'])
                cmd_dict['searchsploit'].extend(version_searches)

                # Add age assessment
                age = self.calculate_software_age(service['version'])
                if age:
                    cmd_dict['info'].append(f"Software Age: {age}")

            # Add NSE script recommendations
            nse_scripts = self.get_nse_scripts(service)
            for script, desc in nse_scripts:
                cmd_dict['nse_scripts'].append(f"nmap -p{port} --script {script} {self.target_info.get('ip', 'TARGET')}  # {desc}")

            # Manual interaction
            cmd_dict['manual'].append(f"nc -nv {self.target_info.get('ip', 'TARGET')} {port}")

            # Service-specific enumeration
            service_lower = service['service'].lower()
            if 'http' in service_lower:
                cmd_dict['enumeration'].append(f"curl -I http://{self.target_info.get('ip', 'TARGET')}:{port}  # Check headers")
                cmd_dict['enumeration'].append(f"nikto -h http://{self.target_info.get('ip', 'TARGET')}:{port}  # Web scanner")
                cmd_dict['enumeration'].append(f"dirb http://{self.target_info.get('ip', 'TARGET')}:{port}  # Directory brute")
            elif 'smb' in service_lower or 'netbios' in service_lower:
                cmd_dict['enumeration'].append(f"enum4linux -a {self.target_info.get('ip', 'TARGET')}  # Full SMB enumeration")
                cmd_dict['enumeration'].append(f"smbclient -L //{self.target_info.get('ip', 'TARGET')} -N  # List shares")
                cmd_dict['enumeration'].append(f"crackmapexec smb {self.target_info.get('ip', 'TARGET')}  # Quick SMB info")
            elif 'ftp' in service_lower:
                cmd_dict['enumeration'].append(f"ftp {self.target_info.get('ip', 'TARGET')} {port}  # Try anonymous login")
                cmd_dict['enumeration'].append("# Username: anonymous, Password: (blank)")
            elif 'ssh' in service_lower:
                cmd_dict['enumeration'].append(f"ssh-audit {self.target_info.get('ip', 'TARGET')}  # Check for weak algorithms")
                cmd_dict['enumeration'].append(f"hydra -L users.txt -P passwords.txt ssh://{self.target_info.get('ip', 'TARGET')}  # If password auth enabled")

            # Extract unique banner terms if present
            if service['banner']:
                banner_terms = self.extract_banner_terms(service['banner'])
                for term in banner_terms[:2]:  # Top 2 unique terms
                    cmd_dict['searchsploit'].append(f"searchsploit {term}")

            commands[port] = cmd_dict

        return commands

    def extract_banner_terms(self, banner: str) -> List[str]:
        """Extract unique searchable terms from banner"""
        # More intelligent term extraction
        terms = []

        # Look for product names and versions
        # Pattern: Word followed by optional version
        products = re.findall(r'([A-Za-z][A-Za-z0-9_-]+)(?:\s+v?[\d\.]+)?', banner)

        # Exclude common generic terms
        exclude = {
            'system', 'windows', 'linux', 'server', 'version', 'protocol',
            'tcp', 'udp', 'http', 'https', 'ssl', 'tls', 'connection'
        }

        for product in products:
            if product.lower() not in exclude and len(product) > 3:
                terms.append(product.lower())

        # Remove duplicates while preserving order
        seen = set()
        unique_terms = []
        for term in terms:
            if term not in seen:
                seen.add(term)
                unique_terms.append(term)

        return unique_terms

    def explain_methodology(self, priorities: List) -> str:
        """Explain why certain ports were prioritized"""
        if not priorities:
            return "No services found to analyze"

        top_service, top_score, top_reasons = priorities[0]

        explanation = f"""
Attack Vector Priority Methodology:
===================================

TOP PRIORITY: Port {top_service['port']} (Score: {top_score}/10)
Reasons: {', '.join(top_reasons)}

Why This Port First:
"""

        if 'non-standard port' in top_reasons:
            explanation += """
- Non-standard ports often run custom/third-party applications
- These have higher exploit probability than hardened OS services
"""

        if 'unknown/custom service' in top_reasons:
            explanation += """
- Unknown services = nmap couldn't identify = likely custom
- Custom applications often have less security testing
"""

        if 'unique banner found' in top_reasons:
            explanation += f"""
- Banner reveals specific software: {top_service['banner'][:50]}
- Can search for exact exploits using banner keywords
"""

        if 'web service' in top_reasons:
            explanation += """
- Web services have large attack surface (SQLi, XSS, RCE)
- Often misconfigured or running vulnerable versions
"""

        explanation += """
Mental Checklist for Exam:
1. Circle all non-standard ports first
2. Highlight unknown/custom services
3. Extract unique banner text for searching
4. Note any version numbers
5. Check chapter context for hints
6. Attack unusual ports before standard services
"""

        return explanation

    def print_report(self):
        """Print formatted educational report"""
        report = self.analyze()

        # Header
        print(f"\n{Colors.BOLD}{'='*70}{Colors.END}")
        print(f"{Colors.HEADER}🎯 SCAN ANALYSIS - {report['target_info'].get('ip', 'Unknown Target')}{Colors.END}")

        # Display hostname prominently if present
        if 'hostname' in report['target_info']:
            print(f"{Colors.YELLOW}Hostname: {report['target_info']['hostname']}{Colors.END}")
        if 'netbios_name' in report['target_info']:
            print(f"NetBIOS Name: {report['target_info']['netbios_name']}")

        if 'os' in report['target_info']:
            print(f"OS: {report['target_info']['os']}")
        print(f"Detected OS Type: {self.os_type.upper()}")

        # Display Windows build age if applicable
        # Try SMB OS discovery first (more detailed), then fall back to basic OS info
        os_for_build = None
        if 'nse_results' in report['target_info'] and report['target_info']['nse_results']:
            if 'smb_os' in report['target_info']['nse_results']:
                os_for_build = report['target_info']['nse_results']['smb_os']
        if not os_for_build and 'os' in report['target_info']:
            os_for_build = report['target_info']['os']

        if os_for_build:
            build_age = self.calculate_windows_build_age(os_for_build)
            if build_age:
                print(f"{Colors.YELLOW}Windows Build: {build_age}{Colors.END}")

        # Display SMB security findings if present
        if 'nse_results' in report['target_info'] and report['target_info']['nse_results']:
            nse = report['target_info']['nse_results']
            if 'smb_security' in nse:
                print(f"\n{Colors.RED}⚠️  SMB Security Issues:{Colors.END}")
                if nse['smb_security'].get('guest_access'):
                    print(f"  • {Colors.YELLOW}Guest access enabled{Colors.END}")
                if nse['smb_security'].get('message_signing'):
                    print(f"  • {Colors.YELLOW}Message signing disabled (vulnerable to relay attacks){Colors.END}")

        # Display version discrepancies if found
        discrepancies = self.detect_version_discrepancies()
        if discrepancies:
            print(f"\n{Colors.RED}⚠️  Version Discrepancies Detected:{Colors.END}")
            for discrepancy in discrepancies:
                print(f"  • {Colors.YELLOW}{discrepancy}{Colors.END}")

        print(f"{Colors.BOLD}{'='*70}{Colors.END}\n")

        # Port Classification
        print(f"{Colors.CYAN}📊 PORT CLASSIFICATION:{Colors.END}")

        classified = report['classified_ports']
        if classified['standard']:
            ports_str = ', '.join([str(s['port']) for s in classified['standard']])
            print(f"  ✓ Standard {self.os_type} ports: {ports_str}")

        if classified['unusual']:
            print(f"  {Colors.YELLOW}⚠️  UNUSUAL PORTS:{Colors.END}")
            for svc in classified['unusual']:
                banner_preview = f" - Banner: {svc['banner'][:40]}..." if svc['banner'] else ""
                print(f"    • {svc['port']}/tcp ({svc['service']}){banner_preview}")

        if classified['unknown']:
            print(f"  {Colors.RED}❓ UNKNOWN SERVICES:{Colors.END}")
            for svc in classified['unknown']:
                print(f"    • {svc['port']}/tcp - Unable to identify")

        # Priority Targets
        print(f"\n{Colors.RED}🚨 ATTACK PRIORITY (Ranked by Score):{Colors.END}")

        for i, (service, score, reasons) in enumerate(report['priorities'][:5], 1):
            if score == 0:
                break

            # Color code by score
            if score >= 5:
                color = Colors.RED
                priority = "CRITICAL"
            elif score >= 3:
                color = Colors.YELLOW
                priority = "HIGH"
            else:
                color = Colors.GREEN
                priority = "MEDIUM"

            print(f"\n{color}#{i} - Port {service['port']} [{priority} - Score: {score}/10]{Colors.END}")
            print(f"  Service: {service['service']}")
            if service['version']:
                print(f"  Version: {service['version']}")
            if service['banner']:
                print(f"  Banner: {service['banner'][:60]}...")
            print(f"  Reasons: {', '.join(reasons)}")

        # Commands for top priorities - Enhanced display
        print(f"\n{Colors.BLUE}🔍 SERVICE ANALYSIS & COMMANDS:{Colors.END}")

        for i, (port, cmd_dict) in enumerate(list(report['commands'].items())[:3], 1):
            # Get service info for this port
            service_info = None
            for svc, _, _ in report['priorities']:
                if svc['port'] == port:
                    service_info = svc
                    break

            print(f"\n{Colors.BOLD}{'='*60}{Colors.END}")
            print(f"{Colors.BOLD}Priority #{i} - Port {port}{Colors.END}")

            if service_info:
                print(f"├─ Service: {service_info['service']}")
                if service_info['version']:
                    print(f"├─ Version: {service_info['version']}")

                    # Show software age if available
                    for info in cmd_dict.get('info', []):
                        if 'Software Age' in info:
                            print(f"├─ {Colors.YELLOW}{info}{Colors.END}")

            print("│")

            # SearchSploit cascade
            if cmd_dict.get('searchsploit'):
                print(f"├─ {Colors.GREEN}📚 SearchSploit Commands (Specific → General):{Colors.END}")
                for cmd in cmd_dict['searchsploit']:
                    print(f"│  {cmd}")

            # NSE Scripts
            if cmd_dict.get('nse_scripts'):
                print(f"│\n├─ {Colors.CYAN}🔧 NSE Scripts:{Colors.END}")
                for cmd in cmd_dict['nse_scripts'][:3]:  # Show top 3
                    print(f"│  {cmd}")

            # Manual Testing
            if cmd_dict.get('manual'):
                print(f"│\n├─ {Colors.YELLOW}✋ Manual Testing:{Colors.END}")
                for cmd in cmd_dict['manual']:
                    print(f"│  {cmd}")
                print(f"│  # Try: help, version, blank line, Ctrl+C to exit")

            # Service-specific enumeration
            if cmd_dict.get('enumeration'):
                print(f"│\n└─ {Colors.BLUE}🔍 Enumeration:{Colors.END}")
                for cmd in cmd_dict['enumeration']:
                    print(f"   {cmd}")

        # Methodology explanation
        print(f"\n{Colors.CYAN}📚 METHODOLOGY EXPLAINED:{Colors.END}")
        print(report['methodology'])

        # Time estimates
        print(f"\n{Colors.YELLOW}⏱️  TIME ESTIMATES FOR EXAM:{Colors.END}")
        print(f"  • Initial research (searchsploit): 5-10 minutes")
        print(f"  • Manual service interaction: 5-10 minutes")
        print(f"  • Exploit modification/testing: 10-30 minutes")
        print(f"  • Total for initial compromise: 20-50 minutes")

        print(f"\n{Colors.BOLD}{'='*70}{Colors.END}\n")


def main():
    """CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(
        description='Analyze nmap scans to identify and prioritize attack vectors',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  crack scan-analyze target_scan.nmap
  crack scan-analyze scan.xml --os windows
  crack scan-analyze scan.gnmap --verbose

  # Pipe from nmap directly:
  nmap -sV -sC target -oA scan && crack scan-analyze scan.nmap
        """
    )

    parser.add_argument('scan_file', help='Nmap scan output file (.nmap, .xml, or .gnmap)')
    parser.add_argument('--os', choices=['auto', 'windows', 'linux'], default='auto',
                       help='Target OS type (default: auto-detect)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output with all details')

    args = parser.parse_args()

    # Create analyzer and run
    analyzer = ScanAnalyzer(args.scan_file, args.os)
    analyzer.print_report()


if __name__ == '__main__':
    main()