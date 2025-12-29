"""
Tests for Capabilities Parser

Business Value Focus:
- Parse getcap output to identify privilege escalation opportunities
- Classify capabilities by exploitability severity
- Detect GTFOBins binaries with documented techniques

Test Priority: TIER 1 - CRITICAL (Core PrivEsc Detection)
"""

import pytest


# =============================================================================
# Sample getcap Output Data
# =============================================================================

# Single exploitable capability (cap_setuid)
GETCAP_SETUID = """/usr/bin/python3.8 = cap_setuid+ep"""

# Multiple exploitable capabilities
GETCAP_MULTIPLE = """/usr/bin/python3.8 = cap_setuid+ep
/usr/bin/vim.basic = cap_dac_override+ep
/usr/bin/tar = cap_dac_read_search+ep"""

# Non-exploitable capabilities only (network caps)
GETCAP_NETWORK_ONLY = """/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute = cap_net_admin+ep"""

# Mixed capabilities (exploitable and non-exploitable)
GETCAP_MIXED = """/usr/bin/python3.8 = cap_setuid+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/vim = cap_dac_override+ep"""

# Capability with different format (= instead of +)
GETCAP_ALT_FORMAT = """/usr/bin/ruby = cap_setgid=eip"""

# Multiple capabilities on single binary
GETCAP_MULTI_CAPS = """/usr/bin/python3 = cap_setuid,cap_setgid+ep"""

# Permission denied error
GETCAP_ERROR = """Failed to get capabilities on '/proc/1': Operation not permitted
/usr/bin/python3.8 = cap_setuid+ep"""

# Empty output (no capabilities)
GETCAP_EMPTY = """"""

# Non-GTFOBins binary with capability
GETCAP_CUSTOM_BINARY = """/opt/custom/myapp = cap_setuid+ep"""


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def cap_parser():
    """
    CapabilitiesParser instance.

    BV: Consistent parser for getcap output tests.
    """
    from reference.chains.parsing.capabilities_parser import CapabilitiesParser
    return CapabilitiesParser()


@pytest.fixture
def step():
    """Default step dictionary."""
    return {'command': 'getcap -r / 2>/dev/null'}


# =============================================================================
# Parser Detection Tests
# =============================================================================

class TestCapabilitiesParserDetection:
    """Tests for getcap command detection"""

    def test_can_parse_getcap_recursive(self, cap_parser, step):
        """
        BV: Detect 'getcap -r' command

        Scenario:
          Given: Command is 'getcap -r /'
          When: can_parse() is called
          Then: Returns True
        """
        assert cap_parser.can_parse(step, 'getcap -r / 2>/dev/null') is True

    def test_can_parse_getcap_with_path(self, cap_parser, step):
        """
        BV: Detect getcap with specific path

        Scenario:
          Given: Command is 'getcap -r /usr'
          When: can_parse() is called
          Then: Returns True
        """
        assert cap_parser.can_parse(step, 'getcap -r /usr') is True

    def test_cannot_parse_without_r_flag(self, cap_parser, step):
        """
        BV: Reject getcap without -r flag

        Scenario:
          Given: Command is 'getcap /usr/bin/python'
          When: can_parse() is called
          Then: Returns False
        """
        assert cap_parser.can_parse(step, 'getcap /usr/bin/python') is False

    def test_cannot_parse_non_getcap(self, cap_parser, step):
        """
        BV: Reject non-getcap commands

        Scenario:
          Given: Unrelated command
          When: can_parse() is called
          Then: Returns False
        """
        assert cap_parser.can_parse(step, 'ls -la /etc') is False


# =============================================================================
# Basic Parsing Tests
# =============================================================================

class TestBasicParsing:
    """Tests for basic capability parsing"""

    def test_parse_single_capability(self, cap_parser, step):
        """
        BV: Parse single capability line

        Scenario:
          Given: getcap output with one entry
          When: parse() is called
          Then: Capability extracted
        """
        result = cap_parser.parse(GETCAP_SETUID, step, 'getcap -r / 2>/dev/null')

        assert len(result.findings['all_capabilities']) == 1
        assert result.findings['all_capabilities'][0]['capability'] == 'cap_setuid'

    def test_parse_extracts_binary_path(self, cap_parser, step):
        """
        BV: Extract binary path

        Scenario:
          Given: getcap output
          When: parse() is called
          Then: Binary path extracted
        """
        result = cap_parser.parse(GETCAP_SETUID, step, 'getcap -r / 2>/dev/null')

        assert result.findings['all_capabilities'][0]['binary'] == '/usr/bin/python3.8'

    def test_parse_multiple_capabilities(self, cap_parser, step):
        """
        BV: Parse multiple capability lines

        Scenario:
          Given: getcap output with multiple entries
          When: parse() is called
          Then: All capabilities extracted
        """
        result = cap_parser.parse(GETCAP_MULTIPLE, step, 'getcap -r / 2>/dev/null')

        assert len(result.findings['all_capabilities']) == 3

    def test_parse_alt_format(self, cap_parser, step):
        """
        BV: Parse alternative capability format

        Scenario:
          Given: getcap with = format
          When: parse() is called
          Then: Capability extracted
        """
        result = cap_parser.parse(GETCAP_ALT_FORMAT, step, 'getcap -r / 2>/dev/null')

        assert len(result.findings['all_capabilities']) >= 1
        assert result.findings['all_capabilities'][0]['capability'] == 'cap_setgid'


# =============================================================================
# Exploitability Classification Tests
# =============================================================================

class TestExploitabilityClassification:
    """Tests for capability severity classification"""

    def test_cap_setuid_is_critical(self, cap_parser, step):
        """
        BV: cap_setuid classified as critical

        Scenario:
          Given: getcap with cap_setuid
          When: parse() is called
          Then: Classified as critical severity
        """
        result = cap_parser.parse(GETCAP_SETUID, step, 'getcap -r / 2>/dev/null')

        exploitable = result.findings['exploitable_capabilities']
        assert len(exploitable) == 1
        assert exploitable[0]['severity'] == 'critical'

    def test_cap_dac_override_is_critical(self, cap_parser, step):
        """
        BV: cap_dac_override classified as critical

        Scenario:
          Given: getcap with cap_dac_override
          When: parse() is called
          Then: Classified as critical severity
        """
        output = "/usr/bin/vim = cap_dac_override+ep"
        result = cap_parser.parse(output, step, 'getcap -r / 2>/dev/null')

        exploitable = result.findings['exploitable_capabilities']
        assert len(exploitable) == 1
        assert exploitable[0]['severity'] == 'critical'

    def test_cap_dac_read_search_is_high(self, cap_parser, step):
        """
        BV: cap_dac_read_search classified as high

        Scenario:
          Given: getcap with cap_dac_read_search
          When: parse() is called
          Then: Classified as high severity
        """
        output = "/usr/bin/tar = cap_dac_read_search+ep"
        result = cap_parser.parse(output, step, 'getcap -r / 2>/dev/null')

        exploitable = result.findings['exploitable_capabilities']
        assert len(exploitable) == 1
        assert exploitable[0]['severity'] == 'high'

    def test_network_caps_not_exploitable(self, cap_parser, step):
        """
        BV: Network capabilities not exploitable

        Scenario:
          Given: getcap with only network caps
          When: parse() is called
          Then: No exploitable capabilities
        """
        result = cap_parser.parse(GETCAP_NETWORK_ONLY, step, 'getcap -r / 2>/dev/null')

        assert len(result.findings['exploitable_capabilities']) == 0
        assert result.success is False


# =============================================================================
# GTFOBins Detection Tests
# =============================================================================

class TestGTFOBinsDetection:
    """Tests for GTFOBins binary detection"""

    def test_python_detected_as_gtfobins(self, cap_parser, step):
        """
        BV: Python detected as GTFOBins binary

        Scenario:
          Given: getcap with python3.8
          When: parse() is called
          Then: Detected as GTFOBins binary
        """
        result = cap_parser.parse(GETCAP_SETUID, step, 'getcap -r / 2>/dev/null')

        gtfobins = result.findings['gtfobins_binaries']
        assert len(gtfobins) == 1
        assert gtfobins[0]['binary_name'] == 'python3.8'

    def test_vim_detected_as_gtfobins(self, cap_parser, step):
        """
        BV: Vim detected as GTFOBins binary

        Scenario:
          Given: getcap with vim
          When: parse() is called
          Then: Detected as GTFOBins binary
        """
        output = "/usr/bin/vim.basic = cap_dac_override+ep"
        result = cap_parser.parse(output, step, 'getcap -r / 2>/dev/null')

        gtfobins = result.findings['gtfobins_binaries']
        assert len(gtfobins) == 1
        assert gtfobins[0]['binary_name'] == 'vim.basic'

    def test_custom_binary_not_gtfobins(self, cap_parser, step):
        """
        BV: Custom binary not in GTFOBins list

        Scenario:
          Given: getcap with unknown binary
          When: parse() is called
          Then: Not in GTFOBins list
        """
        result = cap_parser.parse(GETCAP_CUSTOM_BINARY, step, 'getcap -r / 2>/dev/null')

        # Still exploitable, but not in GTFOBins
        assert len(result.findings['exploitable_capabilities']) == 1
        assert len(result.findings['gtfobins_binaries']) == 0


# =============================================================================
# Variable Resolution Tests
# =============================================================================

class TestVariableResolution:
    """Tests for automatic variable resolution"""

    def test_auto_select_single_exploitable(self, cap_parser, step):
        """
        BV: Auto-select when single exploitable binary

        Scenario:
          Given: getcap with single exploitable entry
          When: parse() is called
          Then: <CAP_BINARY> auto-filled
        """
        result = cap_parser.parse(GETCAP_SETUID, step, 'getcap -r / 2>/dev/null')

        assert '<CAP_BINARY>' in result.variables
        assert result.variables['<CAP_BINARY>'] == '/usr/bin/python3.8'

    def test_auto_set_capability_variable(self, cap_parser, step):
        """
        BV: Auto-set <CAPABILITY> variable

        Scenario:
          Given: getcap with exploitable entry
          When: parse() is called
          Then: <CAPABILITY> auto-filled
        """
        result = cap_parser.parse(GETCAP_SETUID, step, 'getcap -r / 2>/dev/null')

        assert '<CAPABILITY>' in result.variables
        assert result.variables['<CAPABILITY>'] == 'cap_setuid'

    def test_selection_required_multiple(self, cap_parser, step):
        """
        BV: Require selection when multiple exploitable

        Scenario:
          Given: getcap with multiple exploitable entries
          When: parse() is called
          Then: selection_required populated
        """
        result = cap_parser.parse(GETCAP_MULTIPLE, step, 'getcap -r / 2>/dev/null')

        assert '<CAP_BINARY>' in result.selection_required

    def test_most_dangerous_selected_first(self, cap_parser, step):
        """
        BV: Most dangerous capability set as default

        Scenario:
          Given: getcap with mixed severities
          When: parse() is called
          Then: Critical severity selected first
        """
        result = cap_parser.parse(GETCAP_MULTIPLE, step, 'getcap -r / 2>/dev/null')

        # cap_setuid (critical) should be first/default
        assert result.variables['<CAPABILITY>'] == 'cap_setuid'


# =============================================================================
# Success/Failure Tests
# =============================================================================

class TestSuccessDetection:
    """Tests for success/failure detection"""

    def test_success_when_exploitable_found(self, cap_parser, step):
        """
        BV: Success when exploitable capability found

        Scenario:
          Given: getcap with exploitable capability
          When: parse() is called
          Then: success is True
        """
        result = cap_parser.parse(GETCAP_SETUID, step, 'getcap -r / 2>/dev/null')

        assert result.success is True

    def test_failure_when_only_network_caps(self, cap_parser, step):
        """
        BV: Failure when only network capabilities

        Scenario:
          Given: getcap with only network caps
          When: parse() is called
          Then: success is False with warning
        """
        result = cap_parser.parse(GETCAP_NETWORK_ONLY, step, 'getcap -r / 2>/dev/null')

        assert result.success is False
        assert any('no exploitable' in w.lower() for w in result.warnings)

    def test_failure_on_empty_output(self, cap_parser, step):
        """
        BV: Failure on empty output

        Scenario:
          Given: Empty getcap output
          When: parse() is called
          Then: success is False
        """
        result = cap_parser.parse(GETCAP_EMPTY, step, 'getcap -r / 2>/dev/null')

        assert result.success is False


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Edge case handling tests"""

    def test_parser_name(self, cap_parser):
        """
        BV: Parser has correct name

        Scenario:
          Given: CapabilitiesParser instance
          When: Accessing name property
          Then: Returns 'capabilities'
        """
        assert cap_parser.name == "capabilities"

    def test_handles_permission_errors(self, cap_parser, step):
        """
        BV: Handle permission errors gracefully

        Scenario:
          Given: getcap output with permission errors but valid data
          When: parse() is called
          Then: Returns failure with warning (error line triggers early return)
        """
        result = cap_parser.parse(GETCAP_ERROR, step, 'getcap -r / 2>/dev/null')

        # Parser returns early on error output
        assert result.success is False
        assert any('failed' in w.lower() or 'error' in w.lower() for w in result.warnings)

    def test_multiple_caps_on_binary(self, cap_parser, step):
        """
        BV: Parse multiple capabilities on single binary

        Scenario:
          Given: Binary with multiple capabilities
          When: parse() is called
          Then: All capabilities extracted
        """
        result = cap_parser.parse(GETCAP_MULTI_CAPS, step, 'getcap -r / 2>/dev/null')

        # Should have both cap_setuid and cap_setgid
        caps = [c['capability'] for c in result.findings['all_capabilities']]
        assert 'cap_setuid' in caps
        assert 'cap_setgid' in caps

    def test_exploitable_has_techniques(self, cap_parser, step):
        """
        BV: Exploitable capabilities include techniques

        Scenario:
          Given: Exploitable capability found
          When: parse() is called
          Then: Techniques array included
        """
        result = cap_parser.parse(GETCAP_SETUID, step, 'getcap -r / 2>/dev/null')

        exploitable = result.findings['exploitable_capabilities'][0]
        assert 'techniques' in exploitable
        assert len(exploitable['techniques']) > 0
