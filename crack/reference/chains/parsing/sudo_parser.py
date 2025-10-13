"""
Sudo configuration parser.

Extracts exploitable sudo configurations from 'sudo -l' output.
Identifies NOPASSWD entries, GTFOBins-exploitable binaries, and dangerous environment settings.
"""

import re
from typing import Dict, Any, List, Tuple, Optional
from .base import BaseOutputParser, ParsingResult, ChainActivation
from .registry import ParserRegistry


# GTFOBins binaries with sudo exploitation techniques
# Source: https://gtfobins.github.io/ (filtered for sudo capability)
# Last updated: 2025-10-13
GTFOBINS_SUDO_BINARIES = {
    'apt',
    'apt-get',
    'aria2c',
    'arp',
    'ash',
    'awk',
    'base64',
    'bash',
    'busybox',
    'bundler',
    'byebug',
    'cancel',
    'cat',
    'chmod',
    'chown',
    'cp',
    'cpan',
    'cpulimit',
    'crontab',
    'csh',
    'curl',
    'cut',
    'dash',
    'date',
    'dd',
    'diff',
    'dmesg',
    'dmsetup',
    'dnf',
    'docker',
    'dpkg',
    'easy_install',
    'ed',
    'emacs',
    'env',
    'expand',
    'expect',
    'facter',
    'file',
    'find',
    'flock',
    'fmt',
    'fold',
    'ftp',
    'gawk',
    'gcc',
    'gdb',
    'gem',
    'genie',
    'git',
    'grep',
    'gtester',
    'gzip',
    'hd',
    'head',
    'hexdump',
    'highlight',
    'iconv',
    'iftop',
    'ionice',
    'ip',
    'irb',
    'jjs',
    'journalctl',
    'jq',
    'jrunscript',
    'ksh',
    'ld.so',
    'less',
    'logsave',
    'look',
    'ltrace',
    'lua',
    'mail',
    'make',
    'man',
    'mawk',
    'more',
    'mount',
    'mtr',
    'mv',
    'mysql',
    'nano',
    'nawk',
    'nc',
    'netcat',
    'nice',
    'nl',
    'nmap',
    'node',
    'nohup',
    'od',
    'openssl',
    'perl',
    'pg',
    'php',
    'pic',
    'pico',
    'pip',
    'python',
    'python2',
    'python3',
    'rake',
    'readelf',
    'red',
    'redcarpet',
    'rlwrap',
    'rpm',
    'rpmquery',
    'rsync',
    'ruby',
    'run-mailcap',
    'run-parts',
    'rvim',
    'scp',
    'screen',
    'script',
    'sed',
    'service',
    'setarch',
    'sftp',
    'sh',
    'shuf',
    'smbclient',
    'socat',
    'soelim',
    'sort',
    'sqlite3',
    'ssh',
    'ssh-keygen',
    'start-stop-daemon',
    'stdbuf',
    'strace',
    'systemctl',
    'tac',
    'tail',
    'tar',
    'taskset',
    'tclsh',
    'tcpdump',
    'tee',
    'telnet',
    'tftp',
    'time',
    'timeout',
    'tmux',
    'ul',
    'unexpand',
    'uniq',
    'unshare',
    'unzip',
    'update-alternatives',
    'vi',
    'vim',
    'watch',
    'wget',
    'wish',
    'xargs',
    'xxd',
    'xz',
    'yum',
    'zip',
    'zsh',
}

# Standard sudo entries that are NOT exploitable (filter out)
STANDARD_SUDO_COMMANDS = {
    'passwd',
    'su',
    'visudo',
    'reboot',
    'shutdown',
    'halt',
    'poweroff',
    'systemctl reboot',
    'systemctl restart',
    'systemctl stop',
    'systemctl start',
}


@ParserRegistry.register
class SudoParser(BaseOutputParser):
    """
    Parse output from sudo -l command.

    Extracts:
    - NOPASSWD commands (runnable without password)
    - GTFOBins-exploitable binaries
    - env_keep settings (LD_PRELOAD, LD_LIBRARY_PATH)
    - Wildcard usage in command specifications
    """

    # Regex patterns for parsing sudo -l output
    SUDO_ENTRY_PATTERN = re.compile(
        r'\((.*?)\)\s+(NOPASSWD:?|PASSWD:?|SETENV:?)?\s*(.*)',
        re.IGNORECASE
    )
    ENV_KEEP_PATTERN = re.compile(r'env_keep\s*\+=\s*["\']?([^"\'  ,]+)["\']?')  # Match single variable
    SETENV_PATTERN = re.compile(r'SETENV:', re.IGNORECASE)
    BINARY_PATH_PATTERN = re.compile(r'(/[\w/.+-]+/([^/\s,]+))')

    @property
    def name(self) -> str:
        return "sudo"

    def can_parse(self, step: Dict[str, Any], command: str) -> bool:
        """Detect sudo -l commands"""
        command_lower = command.lower()
        return 'sudo' in command_lower and '-l' in command_lower

    def _fuzzy_match_gtfobin(self, binary_name: str) -> Tuple[Optional[str], Optional[str]]:
        """
        Fuzzy match binary name to GTFOBins database.

        Tries multiple strategies:
        1. Exact match (highest confidence)
        2. Strip version numbers (python3 → python)
        3. Strip suffixes (.bin, .basic, .tiny)
        4. Contains match (lowest confidence)

        Args:
            binary_name: Binary name to match

        Returns:
            (matched_name, match_type) where match_type is:
            - 'exact': Direct match in GTFOBins database
            - 'fuzzy': Variant matched (user should verify)
            - (None, None): No match found
        """
        # 1. Exact match
        if binary_name in GTFOBINS_SUDO_BINARIES:
            return binary_name, 'exact'

        # 2. Strip version numbers
        clean = re.sub(r'[0-9.]+$', '', binary_name)  # python3 → python
        if clean != binary_name and clean in GTFOBINS_SUDO_BINARIES:
            return clean, 'fuzzy'

        # 3. Strip suffixes
        clean = re.sub(r'\.(basic|tiny|bin)$', '', binary_name)  # vim.basic → vim
        if clean != binary_name and clean in GTFOBINS_SUDO_BINARIES:
            return clean, 'fuzzy'

        # 4. Strip vendor prefixes
        clean = re.sub(r'^[a-z]+-[a-z]+-', '', binary_name)  # busybox-awk → awk
        if clean != binary_name and clean in GTFOBINS_SUDO_BINARIES:
            return clean, 'fuzzy'

        # 5. Contains match (lowest confidence)
        for gtfobin in GTFOBINS_SUDO_BINARIES:
            if gtfobin in binary_name:
                return gtfobin, 'fuzzy'

        return None, None

    def _extract_binary_from_command(self, command_str: str) -> Optional[str]:
        """
        Extract binary name from sudo command specification.

        Handles formats:
        - /usr/bin/find
        - /usr/bin/vim *
        - /usr/bin/python /path/to/script.py
        - ALL (wildcard - all commands)

        Args:
            command_str: Command string from sudo -l

        Returns:
            Binary name or None
        """
        command_str = command_str.strip()

        # Handle ALL wildcard
        if command_str.upper() == 'ALL':
            return None  # Cannot determine specific binary

        # Extract binary path
        match = self.BINARY_PATH_PATTERN.match(command_str)
        if match:
            full_path = match.group(1)
            binary_name = match.group(2)
            return binary_name

        # Fallback: first word is binary
        parts = command_str.split()
        if parts:
            binary = parts[0].split('/')[-1]  # Get last component if path
            return binary

        return None

    def _is_standard_command(self, command: str) -> bool:
        """Check if command is a standard (non-exploitable) sudo entry"""
        command_lower = command.lower()
        # Check for full command matches (service, systemctl with specific subcommands)
        for std in STANDARD_SUDO_COMMANDS:
            if std in command_lower:
                return True
        # Check for service/systemctl with restart/start/stop/reboot
        if 'service' in command_lower and any(x in command_lower for x in ['restart', 'start', 'stop']):
            return True
        if 'systemctl' in command_lower and any(x in command_lower for x in ['restart', 'start', 'stop', 'reboot']):
            return True
        return False

    def parse(self, output: str, step: Dict[str, Any], command: str) -> ParsingResult:
        """
        Extract NOPASSWD commands, GTFOBins binaries, env_keep flags.

        Returns ParsingResult with:
        - findings['nopasswd_commands']: Commands runnable without password
        - findings['gtfobins_binaries']: Exploitable binaries with sudo
        - findings['env_keep_flags']: Preserved environment variables
        - findings['setenv_enabled']: Boolean - SETENV allowed
        - variables['<SUDO_BINARY>']: Auto-selected if single GTFOBins match
        - selection_required['<SUDO_BINARY>']: User selection if multiple
        """
        result = ParsingResult(parser_name=self.name)

        # Check for errors
        if self._is_error_output(output):
            result.success = False
            result.warnings.append("sudo -l failed or requires password")
            return result

        # Check for "not allowed" message
        if 'not allowed to run sudo' in output.lower():
            result.success = False
            result.warnings.append("User not allowed to run sudo on this host")
            return result

        # Check for password required
        if 'password is required' in output.lower():
            result.success = False
            result.warnings.append("Password required for sudo")
            return result

        # Extract sudo entries
        nopasswd_commands = []
        all_commands = []
        gtfobins_binaries = []
        env_keep_flags = []
        setenv_enabled = False

        for line in self._extract_lines(output):
            # Extract env_keep settings (can be multiple on same line)
            env_matches = self.ENV_KEEP_PATTERN.finditer(line)
            for match in env_matches:
                # Extract variable, clean up trailing commas and whitespace
                env_var = match.group(1).strip().rstrip(',')
                if env_var:
                    env_keep_flags.append(env_var)

            # Check for SETENV
            if self.SETENV_PATTERN.search(line):
                setenv_enabled = True

            # Extract sudo command entries
            # Format: (ALL) NOPASSWD: /usr/bin/find
            #         (root) /usr/bin/vim
            sudo_match = self.SUDO_ENTRY_PATTERN.search(line)
            if sudo_match:
                run_as = sudo_match.group(1)  # ALL, root, etc.
                password_flag = sudo_match.group(2)  # NOPASSWD, PASSWD, SETENV
                command_spec = sudo_match.group(3)  # /usr/bin/find, etc.

                if not command_spec:
                    continue

                # Track all commands
                all_commands.append({
                    'run_as': run_as,
                    'requires_password': 'NOPASSWD' not in (password_flag or ''),
                    'command': command_spec,
                })

                # Track NOPASSWD commands specifically
                if password_flag and 'NOPASSWD' in password_flag:
                    nopasswd_commands.append(command_spec)

                    # Extract binary and check GTFOBins
                    binary_name = self._extract_binary_from_command(command_spec)
                    if binary_name and not self._is_standard_command(command_spec):
                        gtfobin_match, match_type = self._fuzzy_match_gtfobin(binary_name)
                        if gtfobin_match:
                            gtfobins_binaries.append({
                                'command': command_spec,
                                'binary': binary_name,
                                'gtfobin_match': gtfobin_match,
                                'match_type': match_type,
                                'run_as': run_as,
                            })

        # Store findings
        result.findings = {
            'all_commands': all_commands,
            'nopasswd_commands': nopasswd_commands,
            'gtfobins_binaries': gtfobins_binaries,
            'env_keep_flags': env_keep_flags,
            'setenv_enabled': setenv_enabled,
            'nopasswd_count': len(nopasswd_commands),
            'gtfobins_count': len(gtfobins_binaries),
            'env_keep_count': len(env_keep_flags),
        }

        # Determine variable resolution
        # Special case: If user can run ALL commands with NOPASSWD, that's a success
        # even though we can't determine a specific binary
        has_all_wildcard = any('ALL' == cmd.upper() for cmd in nopasswd_commands)

        if len(gtfobins_binaries) == 0:
            if has_all_wildcard:
                # User can run ANY command - this is a success, just no specific binary to recommend
                result.success = True
                result.warnings.append("NOPASSWD ALL found - user can run any command as root")
            else:
                result.success = False
                result.warnings.append("No GTFOBins-exploitable sudo binaries found")
        elif len(gtfobins_binaries) == 1:
            # Auto-select single option
            result.variables['<SUDO_BINARY>'] = gtfobins_binaries[0]['binary']
            result.variables['<SUDO_COMMAND>'] = gtfobins_binaries[0]['command']
        else:
            # User selection required (pass full dicts for display formatting)
            result.selection_required['<SUDO_BINARY>'] = gtfobins_binaries

        # Activate sudo chain if NOPASSWD found
        if nopasswd_commands:
            # Single activation summarizing all NOPASSWD entries
            activation = ChainActivation(
                chain_id='linux-privesc-sudo',
                reason=f"NOPASSWD sudo privileges found: {len(nopasswd_commands)} command(s) - {nopasswd_commands[0]}",
                confidence='high',
                variables={
                    '<SUDO_COMMAND>': nopasswd_commands[0],
                }
            )
            # If we have GTFOBins binary info, add it to variables
            if gtfobins_binaries:
                activation.variables['<SUDO_BINARY>'] = gtfobins_binaries[0]['binary']
                activation.variables['<SUDO_USER>'] = gtfobins_binaries[0].get('run_as', 'ALL')
            result.activates_chains.append(activation)

        return result
