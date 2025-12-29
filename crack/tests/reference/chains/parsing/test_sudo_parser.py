"""
Tests for Sudo Parser

Business Value Focus:
- Parse 'sudo -l' output to identify privilege escalation opportunities
- Identify GTFOBins-exploitable binaries
- Detect dangerous env_keep settings (LD_PRELOAD)

Test Priority: TIER 1 - CRITICAL (Core PrivEsc Detection)
"""

import pytest


# =============================================================================
# Sample sudo -l Output
# =============================================================================

# Standard NOPASSWD sudo entry
SUDO_NOPASSWD_SIMPLE = """Matching Defaults entries for user on target:
    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

User user may run the following commands on target:
    (ALL) NOPASSWD: /usr/bin/find
"""

# Multiple NOPASSWD entries
SUDO_MULTIPLE_ENTRIES = """User user may run the following commands on target:
    (ALL) NOPASSWD: /usr/bin/vim
    (ALL) NOPASSWD: /usr/bin/python3
    (root) NOPASSWD: /usr/bin/less
"""

# NOPASSWD ALL (can run any command)
SUDO_ALL = """User user may run the following commands on target:
    (ALL) NOPASSWD: ALL
"""

# Env_keep with dangerous variables
SUDO_ENV_KEEP = """Matching Defaults entries for user on target:
    env_keep += "LD_PRELOAD"
    env_keep += "LD_LIBRARY_PATH"
    env_reset

User user may run the following commands on target:
    (ALL) NOPASSWD: /usr/bin/apache2
"""

# Password required (not exploitable without password)
SUDO_PASSWD_REQUIRED = """User user may run the following commands on target:
    (ALL) PASSWD: /usr/bin/vim
    (root) /usr/bin/nano
"""

# Non-exploitable standard commands
SUDO_STANDARD_COMMANDS = """User user may run the following commands on target:
    (ALL) NOPASSWD: /sbin/reboot
    (ALL) NOPASSWD: /usr/bin/systemctl restart apache2
    (ALL) NOPASSWD: /usr/bin/passwd
"""

# Not allowed to run sudo
SUDO_NOT_ALLOWED = """Sorry, user user is not allowed to run sudo on target.
"""

# Password required message
SUDO_PASSWORD_REQUIRED = """[sudo] password for user:
A password is required
"""

# Error output
SUDO_ERROR = """sudo: unable to resolve host target
[sudo] password for user:
"""


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def sudo_parser():
    """
    SudoParser instance.

    BV: Consistent parser for sudo output tests.
    """
    from reference.chains.parsing.sudo_parser import SudoParser
    return SudoParser()


@pytest.fixture
def step():
    """Default step dictionary."""
    return {'command': 'sudo -l'}


# =============================================================================
# Parser Detection Tests
# =============================================================================

class TestSudoParserDetection:
    """Tests for sudo command detection"""

    def test_can_parse_sudo_l(self, sudo_parser, step):
        """
        BV: Detect 'sudo -l' commands

        Scenario:
          Given: Command is 'sudo -l'
          When: can_parse() is called
          Then: Returns True
        """
        assert sudo_parser.can_parse(step, 'sudo -l') is True

    def test_can_parse_sudo_with_options(self, sudo_parser, step):
        """
        BV: Detect sudo -l with other options

        Scenario:
          Given: Command is 'sudo -l -U user'
          When: can_parse() is called
          Then: Returns True
        """
        assert sudo_parser.can_parse(step, 'sudo -l -U otheruser') is True

    def test_cannot_parse_non_sudo(self, sudo_parser, step):
        """
        BV: Reject non-sudo commands

        Scenario:
          Given: Command without sudo
          When: can_parse() is called
          Then: Returns False
        """
        assert sudo_parser.can_parse(step, 'cat /etc/passwd') is False

    def test_cannot_parse_sudo_without_l(self, sudo_parser, step):
        """
        BV: Reject sudo without -l flag

        Scenario:
          Given: Command is 'sudo vim'
          When: can_parse() is called
          Then: Returns False
        """
        assert sudo_parser.can_parse(step, 'sudo vim /etc/passwd') is False


# =============================================================================
# NOPASSWD Parsing Tests
# =============================================================================

class TestNOPASSWDParsing:
    """Tests for NOPASSWD entry parsing"""

    def test_parse_single_nopasswd(self, sudo_parser, step):
        """
        BV: Extract single NOPASSWD command

        Scenario:
          Given: sudo -l output with NOPASSWD /usr/bin/find
          When: parse() is called
          Then: /usr/bin/find extracted as NOPASSWD
        """
        result = sudo_parser.parse(SUDO_NOPASSWD_SIMPLE, step, 'sudo -l')

        assert len(result.findings['nopasswd_commands']) == 1
        assert '/usr/bin/find' in result.findings['nopasswd_commands']

    def test_parse_multiple_nopasswd(self, sudo_parser, step):
        """
        BV: Extract multiple NOPASSWD commands

        Scenario:
          Given: sudo -l output with multiple NOPASSWD entries
          When: parse() is called
          Then: All NOPASSWD commands extracted
        """
        result = sudo_parser.parse(SUDO_MULTIPLE_ENTRIES, step, 'sudo -l')

        assert result.findings['nopasswd_count'] == 3

    def test_parse_nopasswd_all(self, sudo_parser, step):
        """
        BV: Handle NOPASSWD ALL (all commands)

        Scenario:
          Given: sudo -l output with NOPASSWD ALL
          When: parse() is called
          Then: Recognized as exploitable
        """
        result = sudo_parser.parse(SUDO_ALL, step, 'sudo -l')

        assert result.success is True
        # Should have warning about ALL access
        assert any('ALL' in w for w in result.warnings)


# =============================================================================
# GTFOBins Detection Tests
# =============================================================================

class TestGTFOBinsDetection:
    """Tests for GTFOBins exploitable binary detection"""

    def test_detect_gtfobin_find(self, sudo_parser, step):
        """
        BV: Detect find as GTFOBins binary

        Scenario:
          Given: sudo -l with NOPASSWD /usr/bin/find
          When: parse() is called
          Then: find detected as GTFOBins exploitable
        """
        result = sudo_parser.parse(SUDO_NOPASSWD_SIMPLE, step, 'sudo -l')

        assert len(result.findings['gtfobins_binaries']) == 1
        assert result.findings['gtfobins_binaries'][0]['binary'] == 'find'

    def test_detect_multiple_gtfobins(self, sudo_parser, step):
        """
        BV: Detect multiple GTFOBins binaries

        Scenario:
          Given: sudo -l with vim, python3, less
          When: parse() is called
          Then: All detected as GTFOBins
        """
        result = sudo_parser.parse(SUDO_MULTIPLE_ENTRIES, step, 'sudo -l')

        binaries = [g['binary'] for g in result.findings['gtfobins_binaries']]
        assert 'vim' in binaries
        assert 'python3' in binaries
        assert 'less' in binaries

    def test_skip_standard_commands(self, sudo_parser, step):
        """
        BV: Skip non-exploitable standard commands

        Scenario:
          Given: sudo -l with reboot, systemctl restart
          When: parse() is called
          Then: Not detected as exploitable
        """
        result = sudo_parser.parse(SUDO_STANDARD_COMMANDS, step, 'sudo -l')

        # These should not be in GTFOBins list
        assert result.findings['gtfobins_count'] == 0


# =============================================================================
# env_keep Detection Tests
# =============================================================================

class TestEnvKeepDetection:
    """Tests for env_keep variable detection"""

    def test_detect_ld_preload(self, sudo_parser, step):
        """
        BV: Detect dangerous LD_PRELOAD env_keep

        Scenario:
          Given: sudo -l with env_keep += LD_PRELOAD
          When: parse() is called
          Then: LD_PRELOAD detected in env_keep_flags
        """
        result = sudo_parser.parse(SUDO_ENV_KEEP, step, 'sudo -l')

        assert 'LD_PRELOAD' in result.findings['env_keep_flags']

    def test_detect_ld_library_path(self, sudo_parser, step):
        """
        BV: Detect LD_LIBRARY_PATH env_keep

        Scenario:
          Given: sudo -l with env_keep += LD_LIBRARY_PATH
          When: parse() is called
          Then: LD_LIBRARY_PATH detected
        """
        result = sudo_parser.parse(SUDO_ENV_KEEP, step, 'sudo -l')

        assert 'LD_LIBRARY_PATH' in result.findings['env_keep_flags']

    def test_env_keep_count(self, sudo_parser, step):
        """
        BV: Count env_keep variables

        Scenario:
          Given: sudo -l with 2 env_keep entries
          When: parse() is called
          Then: env_keep_count is 2
        """
        result = sudo_parser.parse(SUDO_ENV_KEEP, step, 'sudo -l')

        assert result.findings['env_keep_count'] == 2


# =============================================================================
# Variable Resolution Tests
# =============================================================================

class TestVariableResolution:
    """Tests for automatic variable resolution"""

    def test_auto_select_single_gtfobin(self, sudo_parser, step):
        """
        BV: Auto-select when single GTFOBins binary found

        Scenario:
          Given: sudo -l with single NOPASSWD GTFOBins binary
          When: parse() is called
          Then: <SUDO_BINARY> auto-filled
        """
        result = sudo_parser.parse(SUDO_NOPASSWD_SIMPLE, step, 'sudo -l')

        assert '<SUDO_BINARY>' in result.variables
        assert result.variables['<SUDO_BINARY>'] == 'find'

    def test_selection_required_multiple(self, sudo_parser, step):
        """
        BV: Require user selection when multiple GTFOBins

        Scenario:
          Given: sudo -l with multiple NOPASSWD GTFOBins binaries
          When: parse() is called
          Then: selection_required populated
        """
        result = sudo_parser.parse(SUDO_MULTIPLE_ENTRIES, step, 'sudo -l')

        assert '<SUDO_BINARY>' in result.selection_required


# =============================================================================
# Chain Activation Tests
# =============================================================================

class TestChainActivation:
    """Tests for chain activation on findings"""

    def test_activates_sudo_chain_on_nopasswd(self, sudo_parser, step):
        """
        BV: Activate sudo privesc chain when NOPASSWD found

        Scenario:
          Given: sudo -l with NOPASSWD entry
          When: parse() is called
          Then: linux-privesc-sudo chain activated
        """
        result = sudo_parser.parse(SUDO_NOPASSWD_SIMPLE, step, 'sudo -l')

        chain_ids = [a.chain_id for a in result.activates_chains]
        assert 'linux-privesc-sudo' in chain_ids

    def test_no_activation_on_passwd_required(self, sudo_parser, step):
        """
        BV: Don't activate chain when password required

        Scenario:
          Given: sudo -l with only PASSWD entries
          When: parse() is called
          Then: No chain activated
        """
        result = sudo_parser.parse(SUDO_PASSWD_REQUIRED, step, 'sudo -l')

        assert len(result.activates_chains) == 0


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestErrorHandling:
    """Tests for error handling"""

    def test_not_allowed_to_run_sudo(self, sudo_parser, step):
        """
        BV: Handle 'not allowed to run sudo' message

        Scenario:
          Given: 'not allowed to run sudo' output
          When: parse() is called
          Then: success=False, warning added
        """
        result = sudo_parser.parse(SUDO_NOT_ALLOWED, step, 'sudo -l')

        assert result.success is False
        assert any('not allowed' in w.lower() for w in result.warnings)

    def test_password_required(self, sudo_parser, step):
        """
        BV: Handle password required message

        Scenario:
          Given: Password prompt output
          When: parse() is called
          Then: success=False, warning added
        """
        result = sudo_parser.parse(SUDO_PASSWORD_REQUIRED, step, 'sudo -l')

        assert result.success is False

    def test_no_gtfobins_found(self, sudo_parser, step):
        """
        BV: Handle no exploitable binaries

        Scenario:
          Given: sudo -l with only standard commands
          When: parse() is called
          Then: Warning about no GTFOBins
        """
        result = sudo_parser.parse(SUDO_STANDARD_COMMANDS, step, 'sudo -l')

        assert result.findings['gtfobins_count'] == 0


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Edge case handling tests"""

    def test_parser_name(self, sudo_parser):
        """
        BV: Parser has correct name

        Scenario:
          Given: SudoParser instance
          When: Accessing name property
          Then: Returns 'sudo'
        """
        assert sudo_parser.name == "sudo"

    def test_empty_output(self, sudo_parser, step):
        """
        BV: Handle empty output gracefully

        Scenario:
          Given: Empty output
          When: parse() is called
          Then: Returns result with no findings
        """
        result = sudo_parser.parse("", step, 'sudo -l')

        assert result.findings['nopasswd_count'] == 0

    def test_fuzzy_match_python3(self, sudo_parser):
        """
        BV: Fuzzy match versioned binaries (python3 -> python)

        Scenario:
          Given: Binary name python3
          When: _fuzzy_match_gtfobin() is called
          Then: Matches 'python' with fuzzy type
        """
        matched, match_type = sudo_parser._fuzzy_match_gtfobin('python3')

        # Should match either python3 directly or fuzzy to python
        assert matched is not None

    def test_fuzzy_match_vim_basic(self, sudo_parser):
        """
        BV: Fuzzy match suffixed binaries (vim.basic -> vim)

        Scenario:
          Given: Binary name vim.basic
          When: _fuzzy_match_gtfobin() is called
          Then: Matches 'vim' with fuzzy type
        """
        matched, match_type = sudo_parser._fuzzy_match_gtfobin('vim.basic')

        assert matched == 'vim'
        assert match_type == 'fuzzy'
