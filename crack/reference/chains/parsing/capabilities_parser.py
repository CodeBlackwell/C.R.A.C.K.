"""
Linux capabilities parser.

Extracts file capabilities and classifies by exploitability.
Parses getcap output and identifies dangerous capabilities that enable
privilege escalation through various techniques.
"""

import re
from typing import Dict, Any, List
from .base import BaseOutputParser, ParsingResult
from .registry import ParserRegistry


# Dangerous capabilities that enable privilege escalation
EXPLOITABLE_CAPABILITIES = {
    'cap_setuid': {
        'severity': 'critical',
        'description': 'Can change process UID (root shell)',
        'techniques': ['python setuid(0)', 'perl setuid(0)', 'ruby setuid(0)']
    },
    'cap_setgid': {
        'severity': 'high',
        'description': 'Can change process GID (group escalation)',
        'techniques': ['setgid(0) to gain root group']
    },
    'cap_dac_override': {
        'severity': 'critical',
        'description': 'Bypass file permission checks (read/write any file)',
        'techniques': ['vim/nano to edit /etc/passwd', 'tar to extract as root']
    },
    'cap_dac_read_search': {
        'severity': 'high',
        'description': 'Bypass read permission checks',
        'techniques': ['tar to read sensitive files', 'base64 to exfiltrate']
    },
    'cap_chown': {
        'severity': 'medium',
        'description': 'Change file ownership',
        'techniques': ['chown /etc/passwd to gain write access']
    },
    'cap_fowner': {
        'severity': 'medium',
        'description': 'Bypass permission checks for file operations',
        'techniques': ['Similar to cap_dac_override but more limited']
    },
    'cap_sys_admin': {
        'severity': 'critical',
        'description': 'Full system administration (mount, etc.)',
        'techniques': ['mount privileged filesystems']
    },
    'cap_sys_ptrace': {
        'severity': 'high',
        'description': 'Trace arbitrary processes (inject code)',
        'techniques': ['gdb attach to root process, inject shellcode']
    },
}

# GTFOBins binaries with capability exploitation techniques
GTFOBINS_CAP_BINARIES = {
    'python', 'python2', 'python3', 'python2.7', 'python3.8', 'python3.9', 'python3.10',
    'perl', 'perl5', 'ruby', 'ruby2', 'ruby3', 'node', 'nodejs', 'php', 'php7', 'php8',
    'vim', 'vim.basic', 'vim.tiny', 'vi', 'nano', 'emacs', 'ed', 'sed',
    'tar', 'zip', 'gzip', 'bzip2', 'base64', 'xxd', 'od', 'hexdump',
    'gdb', 'strace', 'ltrace',
    'bash', 'sh', 'dash', 'ash', 'zsh', 'ksh',
    'cp', 'mv', 'dd', 'install',
}


@ParserRegistry.register
class CapabilitiesParser(BaseOutputParser):
    """Parse output from getcap enumeration"""

    # Pattern: /usr/bin/python3.8 = cap_setuid+ep
    # Also handles: /usr/bin/python3.8 cap_setuid=ep (without =)
    # Also handles: /usr/bin/python3.8 = cap_net_admin,cap_net_raw+eip (multiple)
    CAP_PATTERN = re.compile(r'^([\w/.-]+)\s*=?\s*(.+)$')

    @property
    def name(self) -> str:
        return "capabilities"

    def can_parse(self, step: Dict[str, Any], command: str) -> bool:
        """Detect getcap commands"""
        cmd_lower = command.lower()
        return 'getcap' in cmd_lower and '-r' in cmd_lower

    def parse(self, output: str, step: Dict[str, Any], command: str) -> ParsingResult:
        """
        Extract binaries with capabilities and classify by exploitability.

        Returns ParsingResult with:
        - findings['all_capabilities']: All binaries with capabilities
        - findings['exploitable_capabilities']: Dangerous capabilities only
        - findings['gtfobins_binaries']: Binaries with documented techniques
        - variables['<CAP_BINARY>']: Auto-selected if single exploitable
        - variables['<CAPABILITY>']: Most dangerous capability found
        - selection_required['<CAP_BINARY>']: User selection if multiple
        """
        result = ParsingResult(parser_name=self.name)

        # Check for errors
        if self._is_error_output(output):
            result.success = False
            result.warnings.append("getcap command failed or permission denied")
            return result

        # Extract capabilities: /usr/bin/python3.8 = cap_setuid+ep
        lines = self._extract_lines(output)
        if not lines:
            result.success = False
            result.warnings.append("No capabilities found on system")
            return result

        all_capabilities = []
        exploitable_capabilities = []
        gtfobins_binaries = []

        for line in lines:
            match = self.CAP_PATTERN.match(line)
            if not match:
                continue

            binary_path = match.group(1)
            caps_string = match.group(2)

            # Parse capabilities (may be comma-separated)
            # Format: cap_name+ep or cap_name=eip
            cap_list = [c.strip() for c in caps_string.split(',')]

            for cap_full in cap_list:
                # Extract capability name (before + or =)
                cap_name = re.split(r'[+=]', cap_full)[0].strip()

                # Store all capabilities
                cap_entry = {
                    'binary': binary_path,
                    'capability': cap_name,
                    'full_capability': cap_full,
                    'raw_line': line
                }
                all_capabilities.append(cap_entry)

                # Check if exploitable
                if cap_name in EXPLOITABLE_CAPABILITIES:
                    cap_info = EXPLOITABLE_CAPABILITIES[cap_name]
                    exploitable_entry = {
                        **cap_entry,
                        'severity': cap_info['severity'],
                        'description': cap_info['description'],
                        'techniques': cap_info['techniques']
                    }
                    exploitable_capabilities.append(exploitable_entry)

                    # Check if binary is in GTFOBins
                    binary_name = binary_path.split('/')[-1]
                    if binary_name in GTFOBINS_CAP_BINARIES:
                        gtfobins_entry = {
                            **exploitable_entry,
                            'gtfobins': True,
                            'binary_name': binary_name
                        }
                        gtfobins_binaries.append(gtfobins_entry)

        # Store findings
        result.findings['all_capabilities'] = all_capabilities
        result.findings['exploitable_capabilities'] = exploitable_capabilities
        result.findings['gtfobins_binaries'] = gtfobins_binaries

        # Determine variable resolution
        if not exploitable_capabilities:
            result.success = False
            result.warnings.append("No exploitable capabilities found (only network caps)")
            return result

        # Sort exploitable by severity (critical first)
        severity_order = {'critical': 0, 'high': 1, 'medium': 2}
        exploitable_capabilities.sort(key=lambda x: severity_order.get(x['severity'], 999))

        # Auto-select if single exploitable capability
        if len(exploitable_capabilities) == 1:
            cap = exploitable_capabilities[0]
            result.variables['<CAP_BINARY>'] = cap['binary']
            result.variables['<CAPABILITY>'] = cap['capability']
        else:
            # Multiple exploitable - require user selection
            binary_options = [f"{cap['binary']} ({cap['capability']}, {cap['severity']})"
                              for cap in exploitable_capabilities]
            result.selection_required['<CAP_BINARY>'] = binary_options

            # Set most dangerous capability as default
            result.variables['<CAPABILITY>'] = exploitable_capabilities[0]['capability']

        return result

    def _extract_binary_name(self, path: str) -> str:
        """Extract binary name from full path"""
        return path.split('/')[-1]

    def _classify_severity(self, capability: str) -> str:
        """Get severity classification for capability"""
        if capability in EXPLOITABLE_CAPABILITIES:
            return EXPLOITABLE_CAPABILITIES[capability]['severity']
        return 'unknown'
