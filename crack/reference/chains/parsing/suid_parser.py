"""
SUID binary enumeration parser.

Extracts SUID binary paths and classifies exploitability based on GTFOBins database.
"""

import re
from typing import Dict, Any, List
from .base import BaseOutputParser, ParsingResult, ChainActivation
from .registry import ParserRegistry


# GTFOBins binaries known to have SUID exploitation techniques
# Source: https://gtfobins.github.io/ (filtered for SUID capability)
GTFOBINS_SUID_BINARIES = {
    'aria2c',
    'arp',
    'ash',
    'awk',
    'base64',
    'bash',
    'busybox',
    'cat',
    'chmod',
    'chown',
    'cp',
    'csh',
    'curl',
    'cut',
    'dash',
    'date',
    'dd',
    'diff',
    'dmsetup',
    'docker',
    'ed',
    'emacs',
    'env',
    'expand',
    'expect',
    'file',
    'find',
    'flock',
    'fmt',
    'fold',
    'gawk',
    'gdb',
    'gimp',
    'git',
    'grep',
    'head',
    'hexdump',
    'ionice',
    'ip',
    'jjs',
    'jq',
    'jrunscript',
    'ksh',
    'ld.so',
    'less',
    'logsave',
    'lua',
    'make',
    'mawk',
    'more',
    'mv',
    'nano',
    'nawk',
    'nice',
    'nl',
    'nmap',
    'node',
    'od',
    'openssl',
    'perl',
    'pg',
    'php',
    'pic',
    'pico',
    'python',
    'python2',
    'python3',
    'readelf',
    'rlwrap',
    'rpm',
    'rpmquery',
    'rsync',
    'run-parts',
    'rvim',
    'sed',
    'setarch',
    'shuf',
    'soelim',
    'sort',
    'sqlite3',
    'ssh-keygen',
    'start-stop-daemon',
    'stdbuf',
    'strace',
    'systemctl',
    'tac',
    'tail',
    'taskset',
    'tclsh',
    'tee',
    'time',
    'timeout',
    'ul',
    'unexpand',
    'uniq',
    'unshare',
    'vi',
    'vim',
    'watch',
    'wget',
    'wish',
    'xargs',
    'xxd',
    'xz',
    'zip',
    'zsh',
}

# Standard system binaries that are SUID by design (filter out)
STANDARD_SUID_BINARIES = {
    'passwd',
    'sudo',
    'su',
    'pkexec',
    'polkit',
    'mount',
    'umount',
    'ping',
    'ping6',
    'fusermount',
    'fusermount3',
    'newgrp',
    'chsh',
    'chfn',
    'gpasswd',
    'chage',
    'expiry',
    'unix_chkpwd',
    'ssh-keysign',
    'dbus-daemon-launch-helper',
    'polkit-agent-helper-1',
    'chrome-sandbox',
    'snap-confine',
    # Container/namespace management
    'newuidmap',
    'newgidmap',
    # Filesystem drivers
    'ntfs-3g',
    # VMware integration
    'vmware-user-suid-wrapper',
    # Legacy remote shell (no SUID exploits in GTFOBins)
    'rsh',
    'rsh-redone-rsh',
    'rlogin',
    'rsh-redone-rlogin',
    # Kali wireless capture tools
    'kismet_cap_hak5_wifi_coconut',
    'kismet_cap_linux_bluetooth',
    'kismet_cap_linux_wifi',
    'kismet_cap_nrf_51822',
    'kismet_cap_nrf_52840',
    'kismet_cap_nrf_mousejack',
    'kismet_cap_nxp_kw41z',
    'kismet_cap_rz_killerbee',
    'kismet_cap_ti_cc_2531',
    'kismet_cap_ti_cc_2540',
    'kismet_cap_ubertooth_one',
}


@ParserRegistry.register
class SUIDParser(BaseOutputParser):
    """
    Parse output from SUID binary enumeration commands.

    Handles commands like:
    - find / -perm -4000 -type f 2>/dev/null
    - find / -perm /4000 -type f 2>/dev/null
    """

    # Match absolute paths: /usr/bin/find, /bin/vim
    BINARY_PATH_PATTERN = re.compile(r'^(/[\w/.+-]+/([^/\s]+))$')

    @property
    def name(self) -> str:
        return "suid"

    def can_parse(self, step: Dict[str, Any], command: str) -> bool:
        """Detect SUID enumeration commands"""
        command_lower = command.lower()

        # Must be a find command looking for SUID binaries
        return (
            'find' in command_lower
            and '-perm' in command_lower
            and ('4000' in command or '-u=s' in command_lower)
        )

    def _fuzzy_match_gtfobin(self, binary_name: str) -> tuple:
        """
        Fuzzy match binary name to GTFOBins database.

        Tries multiple strategies to match binary variants:
        1. Exact match (highest confidence)
        2. Strip version numbers and suffixes (python3 → python)
        3. Strip vendor prefixes (rsh-redone-rsh → rsh)
        4. Contains match (gawk → awk)

        Args:
            binary_name: Binary name to match

        Returns:
            (matched_name, match_type) where match_type is:
            - 'exact': Direct match in GTFOBins database
            - 'fuzzy': Variant matched (indicates user should verify)
            - (None, None): No match found
        """
        # 1. Exact match (highest confidence)
        if binary_name in GTFOBINS_SUID_BINARIES:
            return binary_name, 'exact'

        # 2. Strip version numbers and suffixes
        clean = re.sub(r'[0-9.]+$', '', binary_name)  # python3 → python
        clean = re.sub(r'\.(basic|tiny|bin)$', '', clean)  # vim.basic → vim
        if clean in GTFOBINS_SUID_BINARIES:
            return clean, 'fuzzy'

        # 3. Strip vendor prefixes
        clean = re.sub(r'^[a-z]+-[a-z]+-', '', binary_name)  # rsh-redone-rsh → rsh
        if clean in GTFOBINS_SUID_BINARIES:
            return clean, 'fuzzy'

        # 4. Contains match (lowest confidence)
        for gtfobin in GTFOBINS_SUID_BINARIES:
            if gtfobin in binary_name:
                return gtfobin, 'fuzzy'

        return None, None

    def parse(self, output: str, step: Dict[str, Any], command: str) -> ParsingResult:
        """
        Extract SUID binaries and classify by exploitability using fuzzy matching.

        Returns:
            ParsingResult with:
            - findings['all_binaries']: All SUID binaries found (with match metadata)
            - findings['exploitable_binaries']: GTFOBins-exploitable subset
            - findings['standard_binaries']: Expected system binaries
            - findings['unknown_binaries']: Unclassified binaries needing manual review
            - selection_required['<TARGET_BIN>']: Exploitable binaries for user selection
        """
        result = ParsingResult(parser_name=self.name)

        # Check for errors
        if self._is_error_output(output):
            result.success = False
            result.warnings.append("Command output contains errors")
            return result

        # Extract binary paths
        all_binaries = []
        exploitable_binaries = []
        standard_binaries = []
        unknown_binaries = []

        for line in self._extract_lines(output):
            match = self.BINARY_PATH_PATTERN.match(line)
            if not match:
                continue

            full_path = match.group(1)
            binary_name = match.group(2)

            # Check if standard binary FIRST (avoid false positive fuzzy matches)
            is_standard = binary_name in STANDARD_SUID_BINARIES

            # Only try fuzzy matching if NOT a standard binary
            if not is_standard:
                gtfobin_match, match_type = self._fuzzy_match_gtfobin(binary_name)
            else:
                gtfobin_match, match_type = None, None

            binary_info = {
                'path': full_path,
                'name': binary_name,
                'exploitable': gtfobin_match is not None,
                'gtfobin_match': gtfobin_match,
                'match_type': match_type,
                'standard': is_standard,
            }

            all_binaries.append(binary_info)

            # Categorize (standard check already done above)
            if is_standard:
                standard_binaries.append(full_path)
            elif gtfobin_match:
                exploitable_binaries.append(binary_info)
            else:
                unknown_binaries.append(full_path)

        # Store findings
        result.findings = {
            'all_binaries': all_binaries,
            'exploitable_binaries': exploitable_binaries,
            'standard_binaries': standard_binaries,
            'unknown_binaries': unknown_binaries,
            'total_count': len(all_binaries),
            'exploitable_count': len(exploitable_binaries),
            'standard_count': len(standard_binaries),
            'unknown_count': len(unknown_binaries),
        }

        # Determine variable resolution
        if len(exploitable_binaries) == 0:
            result.success = False
            result.warnings.append("No exploitable SUID binaries found")
        elif len(exploitable_binaries) == 1:
            # Auto-select single option
            result.variables['<TARGET_BIN>'] = exploitable_binaries[0]['path']
        else:
            # User selection required (pass full dicts for display formatting)
            result.selection_required['<TARGET_BIN>'] = exploitable_binaries

        # Add chain activations for exploitable binaries (limit to top 3)
        if exploitable_binaries:
            for binary_info in exploitable_binaries[:3]:
                # Only activate for high-confidence matches
                if binary_info.get('match_type') == 'exact':
                    activation = ChainActivation(
                        chain_id='linux-privesc-suid-exploit',
                        reason=f"Exploitable SUID binary found: {binary_info['name']} ({binary_info['path']})",
                        confidence='high',
                        variables={'<TARGET_BIN>': binary_info['path']}
                    )
                    result.activates_chains.append(activation)
                elif binary_info.get('match_type') == 'fuzzy':
                    activation = ChainActivation(
                        chain_id='linux-privesc-suid-exploit',
                        reason=f"Potentially exploitable SUID binary: {binary_info['name']} ({binary_info['path']})",
                        confidence='medium',
                        variables={'<TARGET_BIN>': binary_info['path']}
                    )
                    result.activates_chains.append(activation)

        return result
