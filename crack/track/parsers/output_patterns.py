"""
Output Pattern Matcher - Real-time command output analysis

Pattern-based parsing for automatic finding extraction.
Tool-specific patterns for common OSCP tools.
"""

import re
from typing import Dict, Any, List, Optional
from ..core.task_tree import TaskNode


class OutputPatternMatcher:
    """
    Pattern matching for command output analysis

    Minimalist design:
    - Compiled regex patterns for efficiency
    - Tool-specific matchers inherit base patterns
    - Graceful fallback on parse failure
    """

    # Base patterns for common findings
    BASE_PATTERNS = {
        'success': [
            re.compile(r'(\d+)\s+port[s]?\s+open', re.IGNORECASE),
            re.compile(r'scan\s+complete', re.IGNORECASE),
            re.compile(r'found\s+(\d+)\s+result', re.IGNORECASE),
            re.compile(r'successfully', re.IGNORECASE),
            re.compile(r'succeeded', re.IGNORECASE),
        ],
        'failure': [
            re.compile(r'error:', re.IGNORECASE),
            re.compile(r'failed', re.IGNORECASE),
            re.compile(r'permission\s+denied', re.IGNORECASE),
            re.compile(r'no\s+such\s+file', re.IGNORECASE),
            re.compile(r'command\s+not\s+found', re.IGNORECASE),
            re.compile(r'unable\s+to', re.IGNORECASE),
            re.compile(r'could\s+not', re.IGNORECASE),
        ],
        'credentials': [
            re.compile(r'password[:\s]+([^\s]+)', re.IGNORECASE),
            re.compile(r'username[:\s]+([^\s]+)', re.IGNORECASE),
            re.compile(r'user[:\s]+([^\s]+)[\s]+pass(?:word)?[:\s]+([^\s]+)', re.IGNORECASE),
            re.compile(r'login[:\s]+([^\s]+)', re.IGNORECASE),
        ],
        'ports': [
            re.compile(r'(\d+)/tcp\s+open\s+(\S+)(?:\s+(.+))?'),
            re.compile(r'(\d+)/udp\s+open\s+(\S+)(?:\s+(.+))?'),
            re.compile(r'Port\s+(\d+):\s+open'),
        ],
        'services': [
            re.compile(r'Service:\s+(\S+)\s+Version:\s+(.+)'),
            re.compile(r'(\S+)\s+(\d+\.\d+(?:\.\d+)?)'),  # Apache 2.4.41
        ],
        'vulnerabilities': [
            re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE),
            re.compile(r'vulnerable\s+to\s+(\S+)', re.IGNORECASE),
            re.compile(r'exploitation\s+successful', re.IGNORECASE),
        ],
        'directories': [
            re.compile(r'/[\w\-/.]+\s+\(Status:\s+(\d+)\)'),  # Gobuster
            re.compile(r'Found:\s+(/[\w\-/.]+)'),  # Generic
        ],
        'files': [
            re.compile(r'\.[\w]+\s+\(Status:\s+200\)'),
            re.compile(r'File\s+found:\s+([\w\-/.]+)'),
        ]
    }

    def __init__(self):
        """Initialize pattern matcher"""
        self.patterns = self.BASE_PATTERNS.copy()
        self.tool_matchers = {
            'nmap': NmapOutputMatcher(),
            'gobuster': GobusterOutputMatcher(),
            'enum4linux': Enum4LinuxOutputMatcher(),
            'sqlmap': SqlmapOutputMatcher(),
            'nikto': NiktoOutputMatcher(),
        }

    def analyze(self, output: List[str], task: TaskNode) -> Dict[str, Any]:
        """
        Analyze output and extract findings

        Args:
            output: Command output lines
            task: Task node for context

        Returns:
            Dictionary of findings by type
        """
        findings = {
            'ports': [],
            'services': [],
            'credentials': [],
            'vulnerabilities': [],
            'directories': [],
            'files': [],
            'custom': []
        }

        # Detect tool from command
        command = task.metadata.get('command', '').lower()
        tool = self._detect_tool(command)

        # Use tool-specific matcher if available
        if tool and tool in self.tool_matchers:
            tool_findings = self.tool_matchers[tool].parse(output, task)
            findings.update(tool_findings)
        else:
            # Use generic patterns
            for line in output:
                self._match_line(line, findings)

        # Check overall success/failure
        success = self._check_success(output)
        findings['success'] = success

        return findings

    def _detect_tool(self, command: str) -> Optional[str]:
        """
        Detect tool from command string

        Args:
            command: Command string

        Returns:
            Tool name or None
        """
        tools = ['nmap', 'gobuster', 'enum4linux', 'sqlmap', 'nikto',
                 'dirb', 'wfuzz', 'hydra', 'john', 'hashcat']

        for tool in tools:
            if tool in command:
                return tool

        return None

    def _match_line(self, line: str, findings: Dict):
        """
        Match line against patterns

        Args:
            line: Output line
            findings: Findings dictionary to update
        """
        # Check ports
        for pattern in self.patterns['ports']:
            match = pattern.search(line)
            if match:
                port_info = {
                    'port': int(match.group(1)),
                    'service': match.group(2) if match.lastindex >= 2 else 'unknown',
                    'version': match.group(3) if match.lastindex >= 3 else None
                }
                if port_info not in findings['ports']:
                    findings['ports'].append(port_info)

        # Check credentials
        for pattern in self.patterns['credentials']:
            match = pattern.search(line)
            if match:
                cred_info = {
                    'username': match.group(1),
                    'password': match.group(2) if match.lastindex >= 2 else None,
                    'source': line
                }
                if cred_info not in findings['credentials']:
                    findings['credentials'].append(cred_info)

        # Check vulnerabilities
        for pattern in self.patterns['vulnerabilities']:
            match = pattern.search(line)
            if match:
                vuln_info = {
                    'type': match.group(0),
                    'description': line
                }
                if vuln_info not in findings['vulnerabilities']:
                    findings['vulnerabilities'].append(vuln_info)

    def _check_success(self, output: List[str]) -> bool:
        """
        Check if command was successful

        Args:
            output: Output lines

        Returns:
            True if successful
        """
        full_output = '\n'.join(output).lower()

        # Check failure patterns first
        for pattern in self.patterns['failure']:
            if pattern.search(full_output):
                return False

        # Check success patterns
        for pattern in self.patterns['success']:
            if pattern.search(full_output):
                return True

        # Default to success if no errors
        return True


class NmapOutputMatcher:
    """Nmap-specific output parsing"""

    def parse(self, output: List[str], task: TaskNode) -> Dict[str, Any]:
        """Parse nmap output"""
        findings = {
            'ports': [],
            'services': [],
            'os_detection': []
        }

        for line in output:
            # Port line: 80/tcp open http Apache 2.4.41
            port_match = re.match(r'^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.+))?', line)
            if port_match:
                port_info = {
                    'port': int(port_match.group(1)),
                    'protocol': port_match.group(2),
                    'state': port_match.group(3),
                    'service': port_match.group(4),
                    'version': port_match.group(5) if port_match.lastindex >= 5 else None
                }
                findings['ports'].append(port_info)

                # Also add to services
                if port_match.group(5):
                    findings['services'].append({
                        'name': port_match.group(4),
                        'version': port_match.group(5),
                        'port': int(port_match.group(1))
                    })

            # OS detection
            os_match = re.search(r'OS:\s+(.+)', line)
            if os_match:
                findings['os_detection'].append(os_match.group(1))

            # Script output
            script_match = re.search(r'\|_(.+):\s+(.+)', line)
            if script_match:
                findings.setdefault('scripts', []).append({
                    'name': script_match.group(1),
                    'output': script_match.group(2)
                })

        return findings


class GobusterOutputMatcher:
    """Gobuster-specific output parsing"""

    def parse(self, output: List[str], task: TaskNode) -> Dict[str, Any]:
        """Parse gobuster output"""
        findings = {
            'directories': [],
            'files': []
        }

        for line in output:
            # Directory found: /admin (Status: 301)
            dir_match = re.search(r'(/[\w\-/.]+)\s+\(Status:\s+(\d+)\)', line)
            if dir_match:
                status = int(dir_match.group(2))
                path = dir_match.group(1)

                if status in [200, 301, 302, 403]:
                    if path.endswith('/'):
                        findings['directories'].append({
                            'path': path,
                            'status': status
                        })
                    else:
                        findings['files'].append({
                            'path': path,
                            'status': status
                        })

        return findings


class Enum4LinuxOutputMatcher:
    """Enum4linux-specific output parsing"""

    def parse(self, output: List[str], task: TaskNode) -> Dict[str, Any]:
        """Parse enum4linux output"""
        findings = {
            'users': [],
            'shares': [],
            'groups': []
        }

        current_section = None

        for line in output:
            # Section headers
            if 'Share Enumeration' in line:
                current_section = 'shares'
            elif 'Users on' in line:
                current_section = 'users'
            elif 'Groups on' in line:
                current_section = 'groups'

            # Parse based on section
            if current_section == 'shares':
                share_match = re.search(r'^\s+(\S+)\s+Disk', line)
                if share_match:
                    findings['shares'].append(share_match.group(1))

            elif current_section == 'users':
                user_match = re.search(r'user:\[([^\]]+)\]', line)
                if user_match:
                    findings['users'].append(user_match.group(1))

            elif current_section == 'groups':
                group_match = re.search(r'group:\[([^\]]+)\]', line)
                if group_match:
                    findings['groups'].append(group_match.group(1))

        return findings


class SqlmapOutputMatcher:
    """SQLMap-specific output parsing"""

    def parse(self, output: List[str], task: TaskNode) -> Dict[str, Any]:
        """Parse sqlmap output"""
        findings = {
            'vulnerabilities': [],
            'databases': [],
            'tables': []
        }

        for line in output:
            # Vulnerability found
            if 'vulnerable' in line.lower():
                findings['vulnerabilities'].append({
                    'type': 'SQL Injection',
                    'description': line
                })

            # Database found
            db_match = re.search(r'Database:\s+(\S+)', line)
            if db_match:
                findings['databases'].append(db_match.group(1))

            # Table found
            table_match = re.search(r'Table:\s+(\S+)', line)
            if table_match:
                findings['tables'].append(table_match.group(1))

            # Extracted data
            if 'retrieved:' in line.lower():
                findings.setdefault('extracted_data', []).append(line)

        return findings


class NiktoOutputMatcher:
    """Nikto-specific output parsing"""

    def parse(self, output: List[str], task: TaskNode) -> Dict[str, Any]:
        """Parse nikto output"""
        findings = {
            'vulnerabilities': [],
            'interesting_files': [],
            'server_info': []
        }

        for line in output:
            # OSVDB references
            osvdb_match = re.search(r'OSVDB-(\d+):\s+(.+)', line)
            if osvdb_match:
                findings['vulnerabilities'].append({
                    'id': f'OSVDB-{osvdb_match.group(1)}',
                    'description': osvdb_match.group(2)
                })

            # Interesting files
            if '+ /' in line and 'found' in line.lower():
                findings['interesting_files'].append(line.strip())

            # Server information
            if 'Server:' in line:
                findings['server_info'].append(line.strip())

        return findings