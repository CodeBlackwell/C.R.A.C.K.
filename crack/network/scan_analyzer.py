#!/usr/bin/env python3
"""
Nmap Scan Analyzer - Educational scan result interpretation
Parses nmap output to identify attack vectors and prioritize targets
Helps OSCP students understand what to investigate without LLM assistance
"""

import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import xml.etree.ElementTree as ET

try:
    from crack.utils.colors import Colors
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
        # Extract target IP
        ip_match = re.search(r'Nmap scan report for\s+(\S+)', content)
        if ip_match:
            self.target_info['ip'] = ip_match.group(1)

        # Extract hostname if present
        host_match = re.search(r'Host:\s+(\S+);', content)
        if host_match:
            self.target_info['hostname'] = host_match.group(1)

        # Extract OS info
        os_match = re.search(r'OS:\s+([^;]+)', content)
        if os_match:
            self.target_info['os'] = os_match.group(1).strip()

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

                    # Look for banner/fingerprint data for this port
                    # Search for the fingerprint section that shows the actual banner response
                    banner_section = re.search(
                        rf'{port}/tcp.*?fingerprint-strings:(.*?)(?=^\d+/tcp|^1 service|^Service Info|^Host script)',
                        content,
                        re.MULTILINE | re.DOTALL
                    )
                    if banner_section:
                        # Look for the actual response lines (after |_ )
                        # Format is usually: |_    actual_banner_text
                        banner_match = re.search(
                            r'\|_\s+([^\n]+(?:\n\|_\s+[^\n]+)*)',
                            banner_section.group(0)
                        )
                        if banner_match:
                            # Clean up the banner text - remove |_ prefixes from multiline
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

    def generate_commands(self, priorities: List) -> Dict:
        """Generate specific commands for top priority targets"""
        commands = {}

        # Common/generic words to exclude from searches
        exclude_words = {
            'system', 'windows', 'linux', 'server', 'service', 'version',
            'running', 'port', 'tcp', 'udp', 'http', 'https', 'protocol',
            'connection', 'response', 'request', 'error', 'denied', 'refused',
            'open', 'closed', 'filtered', 'unknown', 'microsoft', 'apache'
        }

        for service, score, reasons in priorities[:3]:  # Top 3 priorities
            port = service['port']
            cmds = []

            # SearchSploit commands based on dynamic banner analysis
            if service['banner']:
                # Extract alphanumeric terms and product names from banner
                # Look for patterns like "ProductName/1.2.3" or "SoftwareName"
                banner_terms = re.findall(r'\b[a-zA-Z][a-zA-Z0-9_\-\.]+', service['banner'])

                # Filter out common words and keep unique/interesting terms
                unique_terms = []
                for term in banner_terms:
                    term_lower = term.lower()
                    # Keep terms that are 3+ chars and not in exclude list
                    if len(term) >= 3 and term_lower not in exclude_words:
                        # Check if it looks like a product name (mixed case or has numbers)
                        if (any(c.isupper() for c in term[1:]) or  # Has mixed case
                            any(c.isdigit() for c in term) or       # Has numbers
                            '_' in term or '-' in term):            # Has special chars
                            unique_terms.append(term)
                        elif len(term) >= 4:  # Longer terms without special chars
                            unique_terms.append(term)

                # Remove duplicates while preserving order
                seen = set()
                unique_terms = [t for t in unique_terms if t.lower() not in seen and not seen.add(t.lower())]

                # Generate searchsploit commands for top unique terms
                for term in unique_terms[:3]:
                    cmds.append(f"searchsploit {term.lower()}")

            if service['version']:
                # Extract product name from version
                product = service['version'].split()[0] if service['version'] else service['service']
                cmds.append(f"searchsploit {product.lower()}")

            # Manual interaction
            cmds.append(f"nc -nv {self.target_info.get('ip', 'TARGET')} {port}")

            # Service-specific enumeration
            if 'http' in service['service'].lower():
                cmds.append(f"nikto -h http://{self.target_info.get('ip', 'TARGET')}:{port}")
                cmds.append(f"gobuster dir -u http://{self.target_info.get('ip', 'TARGET')}:{port} -w /usr/share/wordlists/dirb/common.txt")
            elif 'smb' in service['service'].lower() or 'netbios' in service['service'].lower():
                cmds.append(f"enum4linux -a {self.target_info.get('ip', 'TARGET')}")
                cmds.append(f"smbclient -L //{self.target_info.get('ip', 'TARGET')} -N")
            elif 'ftp' in service['service'].lower():
                cmds.append(f"ftp {self.target_info.get('ip', 'TARGET')} {port}")
                cmds.append("# Try anonymous login: username 'anonymous', password blank")

            commands[port] = cmds

        return commands

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
        if 'os' in report['target_info']:
            print(f"OS: {report['target_info']['os']}")
        print(f"Detected OS Type: {self.os_type.upper()}")
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

        # Commands for top priorities
        print(f"\n{Colors.BLUE}🔍 ENUMERATION COMMANDS:{Colors.END}")

        for i, (port, cmds) in enumerate(list(report['commands'].items())[:3], 1):
            print(f"\n{Colors.BOLD}Priority #{i} - Port {port}:{Colors.END}")
            print(f"{Colors.GREEN}Research:{Colors.END}")
            for cmd in cmds[:3]:  # Show first 3 commands
                if 'searchsploit' in cmd:
                    print(f"  {cmd}")
                    print(f"  {cmd} -w  # Get online URLs")
            print(f"\n{Colors.GREEN}Manual Interaction:{Colors.END}")
            for cmd in cmds:
                if 'nc' in cmd or 'telnet' in cmd or 'ftp' in cmd:
                    print(f"  {cmd}")
            print(f"  # Try: help, version, blank line")

            # Service-specific enumeration
            if any('nikto' in cmd or 'gobuster' in cmd for cmd in cmds):
                print(f"\n{Colors.GREEN}Web Enumeration:{Colors.END}")
                for cmd in cmds:
                    if 'nikto' in cmd or 'gobuster' in cmd:
                        print(f"  {cmd}")

            if any('enum4linux' in cmd or 'smbclient' in cmd for cmd in cmds):
                print(f"\n{Colors.GREEN}SMB Enumeration:{Colors.END}")
                for cmd in cmds:
                    if 'enum4linux' in cmd or 'smbclient' in cmd:
                        print(f"  {cmd}")

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