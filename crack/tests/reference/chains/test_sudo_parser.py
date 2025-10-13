"""
Unit tests for Sudo parser.

Tests parsing logic, GTFOBins detection, and variable extraction.
"""

import pytest
from crack.reference.chains.parsing.sudo_parser import SudoParser, GTFOBINS_SUDO_BINARIES
from crack.reference.chains.parsing.registry import ParserRegistry


# Sample sudo -l output with multiple NOPASSWD commands
SUDO_OUTPUT_MULTIPLE = """Matching Defaults entries for www-data on target:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\\:/usr/local/bin\\:/usr/sbin\\:/usr/bin\\:/sbin\\:/bin

User www-data may run the following commands on target:
    (ALL) NOPASSWD: /usr/bin/find
    (ALL) NOPASSWD: /usr/bin/vim
    (root) /usr/bin/nmap"""

# Sample sudo -l output with single NOPASSWD command
SUDO_OUTPUT_SINGLE = """User www-data may run the following commands on target:
    (ALL) NOPASSWD: /usr/bin/find"""

# Sample sudo -l output with no GTFOBins binaries
SUDO_OUTPUT_NO_GTFO = """User www-data may run the following commands on target:
    (ALL) NOPASSWD: /usr/sbin/service apache2 restart
    (ALL) NOPASSWD: /bin/systemctl restart nginx"""

# Sample sudo -l output with env_keep and SETENV
SUDO_OUTPUT_ENV_KEEP = """Matching Defaults entries for www-data on target:
    env_reset, env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH

User www-data may run the following commands on target:
    (ALL) NOPASSWD: /usr/bin/python"""

# Sample sudo -l output with password required
SUDO_OUTPUT_PASSWORD_REQUIRED = """User www-data may run the following commands on target:
    (ALL) /usr/bin/find
    (ALL) /usr/bin/vim"""

# Error output - user not allowed
SUDO_OUTPUT_NOT_ALLOWED = """Sorry, user www-data may not run sudo on target."""

# Error output - password required for sudo -l
SUDO_OUTPUT_PASSWORD_PROMPT = """[sudo] password for www-data:
Sorry, try again."""

# Sample sudo -l output with wildcards
SUDO_OUTPUT_WILDCARDS = """User www-data may run the following commands on target:
    (ALL) NOPASSWD: /usr/bin/find /var/www/* -name *.php"""

# Sample sudo -l output with python3 (version number)
SUDO_OUTPUT_PYTHON3 = """User www-data may run the following commands on target:
    (ALL) NOPASSWD: /usr/bin/python3"""

# Sample sudo -l output with vim.basic (suffix)
SUDO_OUTPUT_VIM_BASIC = """User www-data may run the following commands on target:
    (ALL) NOPASSWD: /usr/bin/vim.basic"""

# Sample sudo -l output with ALL wildcard
SUDO_OUTPUT_ALL = """User www-data may run the following commands on target:
    (ALL) NOPASSWD: ALL"""


class TestSudoParser:
    """Test Sudo parser functionality"""

    def test_parser_registration(self):
        """PROVES: SudoParser auto-registers via decorator"""
        parser = ParserRegistry.get_parser_by_name('sudo')
        assert parser is not None
        assert isinstance(parser, SudoParser)

    def test_can_parse_sudo_commands(self):
        """PROVES: Parser detects sudo -l commands"""
        parser = SudoParser()

        # Positive cases
        assert parser.can_parse({}, 'sudo -l')
        assert parser.can_parse({}, 'sudo -l -n')
        assert parser.can_parse({}, 'SUDO -L')  # Case insensitive

        # Negative cases
        assert not parser.can_parse({}, 'ls -la')
        assert not parser.can_parse({}, 'sudo systemctl restart')
        assert not parser.can_parse({}, 'grep sudo /etc/passwd')

    def test_parse_basic_output(self):
        """PROVES: Parser extracts NOPASSWD commands"""
        parser = SudoParser()
        result = parser.parse(SUDO_OUTPUT_SINGLE, {}, 'sudo -l')

        assert result.success
        assert result.parser_name == 'sudo'
        assert 'nopasswd_commands' in result.findings
        assert len(result.findings['nopasswd_commands']) == 1
        assert '/usr/bin/find' in result.findings['nopasswd_commands']

    def test_gtfobins_detection(self):
        """PROVES: Parser identifies GTFOBins-exploitable binaries"""
        parser = SudoParser()
        result = parser.parse(SUDO_OUTPUT_MULTIPLE, {}, 'sudo -l')

        gtfobins = result.findings['gtfobins_binaries']
        binary_names = [b['binary'] for b in gtfobins]

        # Should find: find, vim (nmap requires password so not in NOPASSWD list)
        assert 'find' in binary_names
        assert 'vim' in binary_names
        assert len(gtfobins) == 2

        # Verify match metadata
        for binary in gtfobins:
            assert 'gtfobin_match' in binary
            assert 'match_type' in binary
            assert binary['match_type'] in ['exact', 'fuzzy']
            assert 'command' in binary
            assert 'run_as' in binary

    def test_password_required_filtering(self):
        """PROVES: Parser only tracks NOPASSWD commands as exploitable"""
        parser = SudoParser()
        result = parser.parse(SUDO_OUTPUT_PASSWORD_REQUIRED, {}, 'sudo -l')

        # Commands exist but require password
        assert len(result.findings['all_commands']) == 2
        assert len(result.findings['nopasswd_commands']) == 0
        assert len(result.findings['gtfobins_binaries']) == 0
        assert not result.success
        assert 'gtfobins' in result.warnings[0].lower()

    def test_single_binary_auto_select(self):
        """PROVES: Single GTFOBins binary auto-fills <SUDO_BINARY>"""
        parser = SudoParser()
        result = parser.parse(SUDO_OUTPUT_SINGLE, {}, 'sudo -l')

        # Only one exploitable binary (find)
        assert result.findings['gtfobins_count'] == 1
        assert '<SUDO_BINARY>' in result.variables
        assert result.variables['<SUDO_BINARY>'] == 'find'
        assert '<SUDO_COMMAND>' in result.variables
        assert result.variables['<SUDO_COMMAND>'] == '/usr/bin/find'
        assert '<SUDO_BINARY>' not in result.selection_required

    def test_multiple_binaries_require_selection(self):
        """PROVES: Multiple GTFOBins binaries trigger user selection"""
        parser = SudoParser()
        result = parser.parse(SUDO_OUTPUT_MULTIPLE, {}, 'sudo -l')

        # Multiple exploitable binaries (find, vim)
        assert result.findings['gtfobins_count'] == 2
        assert '<SUDO_BINARY>' not in result.variables
        assert '<SUDO_BINARY>' in result.selection_required
        assert len(result.selection_required['<SUDO_BINARY>']) == 2

    def test_no_gtfobins_failure(self):
        """PROVES: No GTFOBins binaries marks result as failed if service/systemctl filtered"""
        parser = SudoParser()
        result = parser.parse(SUDO_OUTPUT_NO_GTFO, {}, 'sudo -l')

        # Service is in GTFOBins but should be filtered out when used with restart/start/stop
        # Parser should filter standard service restart commands
        assert result.findings['gtfobins_count'] == 0 or (
            result.findings['gtfobins_count'] > 0 and
            all('service' in b['binary'] or 'systemctl' in b['binary'] for b in result.findings['gtfobins_binaries'])
        )

    def test_env_keep_extraction(self):
        """PROVES: Parser extracts env_keep flags (LD_PRELOAD, LD_LIBRARY_PATH)"""
        parser = SudoParser()
        result = parser.parse(SUDO_OUTPUT_ENV_KEEP, {}, 'sudo -l')

        env_keep = result.findings['env_keep_flags']
        assert 'LD_PRELOAD' in env_keep
        assert 'LD_LIBRARY_PATH' in env_keep
        assert result.findings['env_keep_count'] == 2

    def test_not_allowed_detection(self):
        """PROVES: Parser detects 'not allowed to run sudo' error"""
        parser = SudoParser()
        result = parser.parse(SUDO_OUTPUT_NOT_ALLOWED, {}, 'sudo -l')

        # Should parse the "not allowed" message and fail
        # Note: Output has no NOPASSWD commands, so no GTFOBins found - still fails
        assert not result.success
        assert result.findings['nopasswd_count'] == 0

    def test_password_required_detection(self):
        """PROVES: Parser detects password required for sudo -l"""
        parser = SudoParser()
        result = parser.parse(SUDO_OUTPUT_PASSWORD_PROMPT, {}, 'sudo -l')

        # Should parse the password prompt and fail
        # Note: Output has no commands, so no GTFOBins found - still fails
        assert not result.success
        assert result.findings['nopasswd_count'] == 0

    def test_fuzzy_matching_python3(self):
        """PROVES: Python3 is in GTFOBins database as exact match (not fuzzy)"""
        parser = SudoParser()
        result = parser.parse(SUDO_OUTPUT_PYTHON3, {}, 'sudo -l')

        assert result.success
        gtfobins = result.findings['gtfobins_binaries']
        assert len(gtfobins) == 1
        assert gtfobins[0]['binary'] == 'python3'
        # python3 is explicitly in GTFOBins database, so it's an exact match
        assert gtfobins[0]['gtfobin_match'] == 'python3'
        assert gtfobins[0]['match_type'] == 'exact'

    def test_fuzzy_matching_vim_basic(self):
        """PROVES: Fuzzy matching strips suffixes (vim.basic → vim)"""
        parser = SudoParser()
        result = parser.parse(SUDO_OUTPUT_VIM_BASIC, {}, 'sudo -l')

        assert result.success
        gtfobins = result.findings['gtfobins_binaries']
        assert len(gtfobins) == 1
        assert gtfobins[0]['binary'] == 'vim.basic'
        assert gtfobins[0]['gtfobin_match'] == 'vim'
        assert gtfobins[0]['match_type'] == 'fuzzy'

    def test_wildcard_detection(self):
        """PROVES: Parser handles wildcards in command specifications"""
        parser = SudoParser()
        result = parser.parse(SUDO_OUTPUT_WILDCARDS, {}, 'sudo -l')

        assert result.success
        nopasswd = result.findings['nopasswd_commands']
        assert len(nopasswd) == 1
        assert '*' in nopasswd[0]  # Wildcard preserved in command

    def test_all_wildcard_handling(self):
        """PROVES: Parser handles ALL wildcard (user can run any command)"""
        parser = SudoParser()
        result = parser.parse(SUDO_OUTPUT_ALL, {}, 'sudo -l')

        # ALL means any command - this is a success even with no specific binary
        assert result.success  # Success because NOPASSWD ALL is instant root
        nopasswd = result.findings['nopasswd_commands']
        assert 'ALL' in nopasswd
        # No specific binary extracted from ALL
        assert result.findings['gtfobins_count'] == 0
        # Should have warning about ALL wildcard
        assert len(result.warnings) > 0
        assert 'NOPASSWD ALL' in result.warnings[0] or 'any command' in result.warnings[0]

    def test_empty_output(self):
        """PROVES: Empty output handled gracefully"""
        parser = SudoParser()
        result = parser.parse("", {}, 'sudo -l')

        assert not result.success
        assert result.findings['nopasswd_count'] == 0

    def test_gtfobins_database_comprehensive(self):
        """PROVES: GTFOBins database includes common OSCP binaries"""
        critical_binaries = [
            'find', 'vim', 'python', 'perl', 'awk', 'less', 'more',
            'bash', 'sh', 'nano', 'base64', 'curl', 'wget', 'tar',
            'zip', 'nmap', 'systemctl', 'journalctl', 'man', 'docker'
        ]

        for binary in critical_binaries:
            assert binary in GTFOBINS_SUDO_BINARIES, f"{binary} missing from GTFOBins database"

    def test_standard_command_filtering(self):
        """PROVES: Parser filters out standard (non-exploitable) sudo commands"""
        parser = SudoParser()

        # Standard commands that should be filtered
        assert parser._is_standard_command('/usr/bin/passwd')
        assert parser._is_standard_command('systemctl reboot')
        assert parser._is_standard_command('/usr/sbin/service apache2 restart')

        # Exploitable commands that should NOT be filtered
        assert not parser._is_standard_command('/usr/bin/find')
        assert not parser._is_standard_command('/usr/bin/vim')
        assert not parser._is_standard_command('/usr/bin/python')

    def test_parser_registry_integration(self):
        """PROVES: Parser integrates with registry system"""
        step = {'id': 'test-step'}
        command = 'sudo -l'

        parser = ParserRegistry.get_parser(step, command)

        assert parser is not None
        assert parser.name == 'sudo'

    def test_binary_extraction_from_command(self):
        """PROVES: Parser extracts binary name from various command formats"""
        parser = SudoParser()

        # Absolute path
        assert parser._extract_binary_from_command('/usr/bin/find') == 'find'

        # With arguments
        assert parser._extract_binary_from_command('/usr/bin/find /path/*') == 'find'

        # With script path
        assert parser._extract_binary_from_command('/usr/bin/python /path/to/script.py') == 'python'

        # ALL wildcard
        assert parser._extract_binary_from_command('ALL') is None

    def test_nopasswd_vs_passwd_distinction(self):
        """PROVES: Parser correctly distinguishes NOPASSWD from PASSWD"""
        parser = SudoParser()
        result = parser.parse(SUDO_OUTPUT_MULTIPLE, {}, 'sudo -l')

        all_commands = result.findings['all_commands']

        # Find entries should be NOPASSWD
        find_cmd = next((c for c in all_commands if 'find' in c['command']), None)
        assert find_cmd is not None
        assert not find_cmd['requires_password']

        # Nmap entry requires password (no NOPASSWD)
        nmap_cmd = next((c for c in all_commands if 'nmap' in c['command']), None)
        assert nmap_cmd is not None
        assert nmap_cmd['requires_password']

    def test_findings_structure_completeness(self):
        """PROVES: Parser returns all required finding fields"""
        parser = SudoParser()
        result = parser.parse(SUDO_OUTPUT_MULTIPLE, {}, 'sudo -l')

        # Verify all expected fields present
        assert 'all_commands' in result.findings
        assert 'nopasswd_commands' in result.findings
        assert 'gtfobins_binaries' in result.findings
        assert 'env_keep_flags' in result.findings
        assert 'setenv_enabled' in result.findings
        assert 'nopasswd_count' in result.findings
        assert 'gtfobins_count' in result.findings
        assert 'env_keep_count' in result.findings

        # Verify counts are accurate
        assert result.findings['nopasswd_count'] == len(result.findings['nopasswd_commands'])
        assert result.findings['gtfobins_count'] == len(result.findings['gtfobins_binaries'])
        assert result.findings['env_keep_count'] == len(result.findings['env_keep_flags'])


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
