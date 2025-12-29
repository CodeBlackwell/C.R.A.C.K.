"""
Tests for SUID Parser

Business Value Focus:
- Parse SUID binary enumeration for privilege escalation opportunities
- Classify binaries using GTFOBins database
- Detect exploitable vs standard system binaries

Test Priority: TIER 1 - CRITICAL (Core PrivEsc Detection)
"""

import pytest


# =============================================================================
# Sample find Output Data
# =============================================================================

# Single exploitable SUID binary
SUID_SINGLE = """/usr/bin/find"""

# Multiple exploitable binaries
SUID_MULTIPLE = """/usr/bin/find
/usr/bin/vim
/usr/bin/python3"""

# Standard system binaries only
SUID_STANDARD_ONLY = """/usr/bin/sudo
/usr/bin/passwd
/usr/bin/su
/usr/bin/mount"""

# Mixed output (exploitable and standard)
SUID_MIXED = """/usr/bin/find
/usr/bin/sudo
/usr/bin/vim
/usr/bin/passwd
/usr/bin/python3.8
/usr/bin/su"""

# Unknown binaries (not in GTFOBins or standard)
SUID_UNKNOWN = """/opt/custom/myapp
/usr/local/bin/customtool"""

# Versioned binary (fuzzy matching test)
SUID_VERSIONED = """/usr/bin/python3.8"""

# Vim variant (fuzzy matching test)
SUID_VIM_VARIANT = """/usr/bin/vim.basic"""

# Empty output
SUID_EMPTY = """"""


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def suid_parser():
    """
    SUIDParser instance.

    BV: Consistent parser for SUID enumeration tests.
    """
    from reference.chains.parsing.suid_parser import SUIDParser
    return SUIDParser()


@pytest.fixture
def step():
    """Default step dictionary."""
    return {'command': 'find / -perm -4000 -type f 2>/dev/null'}


# =============================================================================
# Parser Detection Tests
# =============================================================================

class TestSUIDParserDetection:
    """Tests for SUID command detection"""

    def test_can_parse_find_perm_4000(self, suid_parser, step):
        """
        BV: Detect 'find / -perm -4000' command

        Scenario:
          Given: Command is 'find / -perm -4000 -type f'
          When: can_parse() is called
          Then: Returns True
        """
        assert suid_parser.can_parse(step, 'find / -perm -4000 -type f 2>/dev/null') is True

    def test_can_parse_find_perm_slash_4000(self, suid_parser, step):
        """
        BV: Detect 'find / -perm /4000' command

        Scenario:
          Given: Command uses /4000 format
          When: can_parse() is called
          Then: Returns True
        """
        assert suid_parser.can_parse(step, 'find / -perm /4000 -type f') is True

    def test_can_parse_find_with_user_flag(self, suid_parser, step):
        """
        BV: Detect 'find / -perm -u=s' command

        Scenario:
          Given: Command uses -u=s format
          When: can_parse() is called
          Then: Returns True
        """
        assert suid_parser.can_parse(step, 'find / -perm -u=s -type f') is True

    def test_cannot_parse_non_find(self, suid_parser, step):
        """
        BV: Reject non-find commands

        Scenario:
          Given: Command is not find
          When: can_parse() is called
          Then: Returns False
        """
        assert suid_parser.can_parse(step, 'ls -la /usr/bin') is False

    def test_cannot_parse_find_without_perm(self, suid_parser, step):
        """
        BV: Reject find without -perm flag

        Scenario:
          Given: Command is find but no -perm
          When: can_parse() is called
          Then: Returns False
        """
        assert suid_parser.can_parse(step, 'find / -name "*.txt"') is False


# =============================================================================
# Basic Parsing Tests
# =============================================================================

class TestBasicParsing:
    """Tests for basic SUID binary parsing"""

    def test_parse_single_binary(self, suid_parser, step):
        """
        BV: Parse single SUID binary

        Scenario:
          Given: Output with one SUID binary
          When: parse() is called
          Then: Binary extracted
        """
        result = suid_parser.parse(SUID_SINGLE, step, 'find / -perm -4000 -type f')

        assert result.findings['total_count'] == 1

    def test_parse_extracts_path(self, suid_parser, step):
        """
        BV: Extract full binary path

        Scenario:
          Given: Output with SUID binary
          When: parse() is called
          Then: Full path extracted
        """
        result = suid_parser.parse(SUID_SINGLE, step, 'find / -perm -4000 -type f')

        assert result.findings['all_binaries'][0]['path'] == '/usr/bin/find'

    def test_parse_extracts_name(self, suid_parser, step):
        """
        BV: Extract binary name from path

        Scenario:
          Given: Output with SUID binary
          When: parse() is called
          Then: Binary name extracted
        """
        result = suid_parser.parse(SUID_SINGLE, step, 'find / -perm -4000 -type f')

        assert result.findings['all_binaries'][0]['name'] == 'find'

    def test_parse_multiple_binaries(self, suid_parser, step):
        """
        BV: Parse multiple SUID binaries

        Scenario:
          Given: Output with multiple binaries
          When: parse() is called
          Then: All binaries extracted
        """
        result = suid_parser.parse(SUID_MULTIPLE, step, 'find / -perm -4000 -type f')

        assert result.findings['total_count'] == 3


# =============================================================================
# GTFOBins Classification Tests
# =============================================================================

class TestGTFOBinsClassification:
    """Tests for GTFOBins exploitability detection"""

    def test_find_is_exploitable(self, suid_parser, step):
        """
        BV: 'find' detected as exploitable

        Scenario:
          Given: find binary in output
          When: parse() is called
          Then: Classified as exploitable
        """
        result = suid_parser.parse(SUID_SINGLE, step, 'find / -perm -4000 -type f')

        assert result.findings['exploitable_count'] == 1
        assert result.findings['exploitable_binaries'][0]['name'] == 'find'

    def test_vim_is_exploitable(self, suid_parser, step):
        """
        BV: 'vim' detected as exploitable

        Scenario:
          Given: vim binary in output
          When: parse() is called
          Then: Classified as exploitable
        """
        output = "/usr/bin/vim"
        result = suid_parser.parse(output, step, 'find / -perm -4000 -type f')

        assert result.findings['exploitable_count'] == 1

    def test_multiple_exploitable(self, suid_parser, step):
        """
        BV: Multiple exploitable binaries detected

        Scenario:
          Given: Output with multiple GTFOBins binaries
          When: parse() is called
          Then: All classified as exploitable
        """
        result = suid_parser.parse(SUID_MULTIPLE, step, 'find / -perm -4000 -type f')

        assert result.findings['exploitable_count'] == 3


# =============================================================================
# Standard Binary Classification Tests
# =============================================================================

class TestStandardBinaryClassification:
    """Tests for standard system binary detection"""

    def test_sudo_is_standard(self, suid_parser, step):
        """
        BV: 'sudo' classified as standard

        Scenario:
          Given: sudo binary in output
          When: parse() is called
          Then: Classified as standard
        """
        output = "/usr/bin/sudo"
        result = suid_parser.parse(output, step, 'find / -perm -4000 -type f')

        assert result.findings['standard_count'] == 1
        assert '/usr/bin/sudo' in result.findings['standard_binaries']

    def test_passwd_is_standard(self, suid_parser, step):
        """
        BV: 'passwd' classified as standard

        Scenario:
          Given: passwd binary in output
          When: parse() is called
          Then: Classified as standard
        """
        output = "/usr/bin/passwd"
        result = suid_parser.parse(output, step, 'find / -perm -4000 -type f')

        assert result.findings['standard_count'] == 1

    def test_mixed_classification(self, suid_parser, step):
        """
        BV: Mixed binaries classified correctly

        Scenario:
          Given: Output with exploitable and standard binaries
          When: parse() is called
          Then: Both categories populated correctly
        """
        result = suid_parser.parse(SUID_MIXED, step, 'find / -perm -4000 -type f')

        assert result.findings['exploitable_count'] >= 2  # find, vim, python3.8
        assert result.findings['standard_count'] >= 3  # sudo, passwd, su


# =============================================================================
# Fuzzy Matching Tests
# =============================================================================

class TestFuzzyMatching:
    """Tests for fuzzy binary name matching"""

    def test_fuzzy_match_python3(self, suid_parser, step):
        """
        BV: 'python3.8' fuzzy matches 'python'

        Scenario:
          Given: Versioned python binary
          When: parse() is called
          Then: Matches 'python' with fuzzy type
        """
        result = suid_parser.parse(SUID_VERSIONED, step, 'find / -perm -4000 -type f')

        exploitable = result.findings['exploitable_binaries']
        assert len(exploitable) == 1
        assert exploitable[0]['match_type'] == 'fuzzy'
        assert exploitable[0]['gtfobin_match'] == 'python'

    def test_fuzzy_match_vim_basic(self, suid_parser, step):
        """
        BV: 'vim.basic' fuzzy matches 'vim'

        Scenario:
          Given: vim.basic binary
          When: parse() is called
          Then: Matches 'vim' with fuzzy type
        """
        result = suid_parser.parse(SUID_VIM_VARIANT, step, 'find / -perm -4000 -type f')

        exploitable = result.findings['exploitable_binaries']
        assert len(exploitable) == 1
        assert exploitable[0]['gtfobin_match'] == 'vim'


# =============================================================================
# Unknown Binary Tests
# =============================================================================

class TestUnknownBinaries:
    """Tests for unknown/unclassified binaries"""

    def test_unknown_binaries_detected(self, suid_parser, step):
        """
        BV: Unknown binaries collected for review

        Scenario:
          Given: Custom binaries not in database
          When: parse() is called
          Then: Classified as unknown
        """
        result = suid_parser.parse(SUID_UNKNOWN, step, 'find / -perm -4000 -type f')

        assert result.findings['unknown_count'] == 2


# =============================================================================
# Variable Resolution Tests
# =============================================================================

class TestVariableResolution:
    """Tests for automatic variable resolution"""

    def test_auto_select_single_exploitable(self, suid_parser, step):
        """
        BV: Auto-select when single exploitable binary

        Scenario:
          Given: Output with single exploitable binary
          When: parse() is called
          Then: <TARGET_BIN> auto-filled
        """
        result = suid_parser.parse(SUID_SINGLE, step, 'find / -perm -4000 -type f')

        assert '<TARGET_BIN>' in result.variables
        assert result.variables['<TARGET_BIN>'] == '/usr/bin/find'

    def test_selection_required_multiple(self, suid_parser, step):
        """
        BV: Require selection when multiple exploitable

        Scenario:
          Given: Output with multiple exploitable binaries
          When: parse() is called
          Then: selection_required populated
        """
        result = suid_parser.parse(SUID_MULTIPLE, step, 'find / -perm -4000 -type f')

        assert '<TARGET_BIN>' in result.selection_required


# =============================================================================
# Chain Activation Tests
# =============================================================================

class TestChainActivation:
    """Tests for chain activation on findings"""

    def test_activates_chain_on_exploitable(self, suid_parser, step):
        """
        BV: Activate SUID exploit chain when exploitable found

        Scenario:
          Given: Output with exploitable binary
          When: parse() is called
          Then: linux-privesc-suid-exploit chain activated
        """
        result = suid_parser.parse(SUID_SINGLE, step, 'find / -perm -4000 -type f')

        chain_ids = [a.chain_id for a in result.activates_chains]
        assert 'linux-privesc-suid-exploit' in chain_ids

    def test_high_confidence_for_exact_match(self, suid_parser, step):
        """
        BV: High confidence for exact GTFOBins match

        Scenario:
          Given: Exact GTFOBins binary
          When: parse() is called
          Then: Chain activation has high confidence
        """
        result = suid_parser.parse(SUID_SINGLE, step, 'find / -perm -4000 -type f')

        # find is an exact match
        activations = [a for a in result.activates_chains if 'find' in a.reason]
        assert len(activations) > 0
        assert activations[0].confidence == 'high'

    def test_no_activation_on_standard_only(self, suid_parser, step):
        """
        BV: No chain activation for standard binaries only

        Scenario:
          Given: Output with only standard binaries
          When: parse() is called
          Then: No chain activated
        """
        result = suid_parser.parse(SUID_STANDARD_ONLY, step, 'find / -perm -4000 -type f')

        assert len(result.activates_chains) == 0


# =============================================================================
# Success/Failure Tests
# =============================================================================

class TestSuccessDetection:
    """Tests for success/failure detection"""

    def test_success_when_exploitable_found(self, suid_parser, step):
        """
        BV: Success when exploitable binary found

        Scenario:
          Given: Output with exploitable binary
          When: parse() is called
          Then: success is True (implicit)
        """
        result = suid_parser.parse(SUID_SINGLE, step, 'find / -perm -4000 -type f')

        # No failure warnings means success
        assert result.findings['exploitable_count'] > 0

    def test_failure_when_no_exploitable(self, suid_parser, step):
        """
        BV: Warning when no exploitable binaries

        Scenario:
          Given: Output with only standard binaries
          When: parse() is called
          Then: Warning about no exploitable binaries
        """
        result = suid_parser.parse(SUID_STANDARD_ONLY, step, 'find / -perm -4000 -type f')

        assert result.success is False
        assert any('no exploitable' in w.lower() for w in result.warnings)

    def test_failure_on_empty_output(self, suid_parser, step):
        """
        BV: Warning on empty output

        Scenario:
          Given: Empty output
          When: parse() is called
          Then: Warning added
        """
        result = suid_parser.parse(SUID_EMPTY, step, 'find / -perm -4000 -type f')

        assert result.success is False


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Edge case handling tests"""

    def test_parser_name(self, suid_parser):
        """
        BV: Parser has correct name

        Scenario:
          Given: SUIDParser instance
          When: Accessing name property
          Then: Returns 'suid'
        """
        assert suid_parser.name == "suid"

    def test_fuzzy_match_method(self, suid_parser):
        """
        BV: Fuzzy match works standalone

        Scenario:
          Given: Binary name
          When: _fuzzy_match_gtfobin() is called
          Then: Returns match and type
        """
        match, match_type = suid_parser._fuzzy_match_gtfobin('python3.10')

        assert match == 'python'
        assert match_type == 'fuzzy'

    def test_exact_match_type(self, suid_parser):
        """
        BV: Exact match returns 'exact' type

        Scenario:
          Given: Exact GTFOBins binary name
          When: _fuzzy_match_gtfobin() is called
          Then: Returns 'exact' type
        """
        match, match_type = suid_parser._fuzzy_match_gtfobin('find')

        assert match == 'find'
        assert match_type == 'exact'

    def test_no_match_returns_none(self, suid_parser):
        """
        BV: Unknown binary returns None

        Scenario:
          Given: Unknown binary name
          When: _fuzzy_match_gtfobin() is called
          Then: Returns (None, None)
        """
        match, match_type = suid_parser._fuzzy_match_gtfobin('customapp')

        assert match is None
        assert match_type is None
