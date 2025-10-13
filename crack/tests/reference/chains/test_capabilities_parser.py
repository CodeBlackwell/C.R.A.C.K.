"""
Unit tests for Capabilities parser.

Tests parsing logic, exploitability classification, and variable extraction.
"""

import pytest
from crack.reference.chains.parsing.capabilities_parser import (
    CapabilitiesParser,
    EXPLOITABLE_CAPABILITIES,
    GTFOBINS_CAP_BINARIES
)
from crack.reference.chains.parsing.registry import ParserRegistry


# Sample outputs
CAP_OUTPUT_SAMPLE = """/usr/bin/python3.8 = cap_setuid+ep
/usr/bin/dumpcap = cap_net_admin,cap_net_raw+ep
/usr/bin/nmap = cap_net_admin,cap_net_raw+ep
/usr/bin/vim.basic = cap_dac_override+ep"""

CAP_OUTPUT_SINGLE = "/usr/bin/python3.8 = cap_setuid+ep"

CAP_OUTPUT_NO_EXPLOIT = """/usr/bin/dumpcap = cap_net_admin,cap_net_raw+ep
/usr/sbin/fping = cap_net_raw+ep"""

CAP_OUTPUT_MULTIPLE_EXPLOITABLE = """/usr/bin/python3.8 = cap_setuid+ep
/usr/bin/vim.basic = cap_dac_override+ep
/usr/bin/tar = cap_dac_read_search+ep"""

CAP_OUTPUT_MIXED_FORMAT = """/usr/bin/python3.8 cap_setuid=ep
/usr/bin/vim.basic = cap_dac_override+eip
/usr/bin/tar cap_dac_read_search=eip"""

CAP_OUTPUT_MULTIPLE_CAPS_PER_BINARY = """/usr/bin/gdb = cap_sys_ptrace,cap_dac_read_search+ep
/usr/bin/python3 = cap_setuid,cap_setgid+ep"""

CAP_OUTPUT_ERROR = """getcap: error while loading shared libraries: libcap.so.2: cannot open shared object file: No such file or directory"""

CAP_OUTPUT_PERMISSION_DENIED = """getcap: /proc/1/root: Permission denied
getcap: /proc/2/root: Permission denied"""

CAP_OUTPUT_EMPTY = ""


class TestCapabilitiesParser:
    """Test Capabilities parser functionality"""

    def test_parser_registration(self):
        """PROVES: CapabilitiesParser auto-registers"""
        parser = ParserRegistry.get_parser_by_name('capabilities')
        assert parser is not None
        assert isinstance(parser, CapabilitiesParser)
        assert parser.name == 'capabilities'

    def test_can_parse_getcap(self):
        """PROVES: Detects getcap commands"""
        parser = CapabilitiesParser()
        step = {}

        # Positive cases
        assert parser.can_parse(step, 'getcap -r / 2>/dev/null')
        assert parser.can_parse(step, 'getcap -r /usr/bin 2>/dev/null')
        assert parser.can_parse(step, 'GETCAP -R / 2>/dev/null')  # Case insensitive

        # Negative cases
        assert not parser.can_parse(step, 'getcap /usr/bin/python3')  # No -r
        assert not parser.can_parse(step, 'find / -perm -4000 2>/dev/null')
        assert not parser.can_parse(step, 'ls -la /usr/bin')

    def test_parse_basic_output(self):
        """PROVES: Extracts binary paths and capabilities"""
        parser = CapabilitiesParser()
        step = {}
        command = 'getcap -r / 2>/dev/null'

        result = parser.parse(CAP_OUTPUT_SAMPLE, step, command)

        assert result.success
        assert result.parser_name == 'capabilities'
        assert 'all_capabilities' in result.findings
        assert len(result.findings['all_capabilities']) == 6  # 4 binaries, 6 total caps

        # Check structure
        all_caps = result.findings['all_capabilities']
        assert all(isinstance(cap, dict) for cap in all_caps)
        assert all('binary' in cap for cap in all_caps)
        assert all('capability' in cap for cap in all_caps)

    def test_exploitable_classification(self):
        """PROVES: Identifies dangerous capabilities"""
        parser = CapabilitiesParser()
        step = {}
        command = 'getcap -r / 2>/dev/null'

        result = parser.parse(CAP_OUTPUT_SAMPLE, step, command)

        exploitable = result.findings['exploitable_capabilities']
        assert len(exploitable) == 2  # python3.8 (setuid), vim.basic (dac_override)

        # Check exploitable entries have metadata
        for cap in exploitable:
            assert 'severity' in cap
            assert 'description' in cap
            assert 'techniques' in cap
            assert cap['severity'] in ['critical', 'high', 'medium']

        # Check specific capabilities
        setuid_cap = next((c for c in exploitable if c['capability'] == 'cap_setuid'), None)
        assert setuid_cap is not None
        assert setuid_cap['severity'] == 'critical'

        dac_cap = next((c for c in exploitable if c['capability'] == 'cap_dac_override'), None)
        assert dac_cap is not None
        assert dac_cap['severity'] == 'critical'

    def test_gtfobins_detection(self):
        """PROVES: Matches binaries against GTFOBins database"""
        parser = CapabilitiesParser()
        step = {}
        command = 'getcap -r / 2>/dev/null'

        result = parser.parse(CAP_OUTPUT_SAMPLE, step, command)

        gtfobins = result.findings['gtfobins_binaries']
        assert len(gtfobins) == 2  # python3.8, vim.basic

        # Check GTFOBins metadata
        for binary in gtfobins:
            assert 'gtfobins' in binary
            assert binary['gtfobins'] is True
            assert 'binary_name' in binary
            assert binary['binary_name'] in GTFOBINS_CAP_BINARIES

    def test_single_exploitable_auto_select(self):
        """PROVES: Single exploitable auto-fills <CAP_BINARY>"""
        parser = CapabilitiesParser()
        step = {}
        command = 'getcap -r / 2>/dev/null'

        result = parser.parse(CAP_OUTPUT_SINGLE, step, command)

        assert result.success
        assert '<CAP_BINARY>' in result.variables
        assert result.variables['<CAP_BINARY>'] == '/usr/bin/python3.8'
        assert '<CAPABILITY>' in result.variables
        assert result.variables['<CAPABILITY>'] == 'cap_setuid'
        assert not result.has_selections()

    def test_multiple_exploitable_require_selection(self):
        """PROVES: Multiple exploitable trigger user selection"""
        parser = CapabilitiesParser()
        step = {}
        command = 'getcap -r / 2>/dev/null'

        result = parser.parse(CAP_OUTPUT_MULTIPLE_EXPLOITABLE, step, command)

        assert result.success
        assert result.has_selections()
        assert '<CAP_BINARY>' in result.selection_required
        assert len(result.selection_required['<CAP_BINARY>']) == 3

        # Check default capability is most dangerous (critical severity first)
        assert '<CAPABILITY>' in result.variables
        # cap_setuid and cap_dac_override are both critical, either is valid
        assert result.variables['<CAPABILITY>'] in ['cap_setuid', 'cap_dac_override']

    def test_no_exploitable_failure(self):
        """PROVES: No exploitable capabilities marks result as failed"""
        parser = CapabilitiesParser()
        step = {}
        command = 'getcap -r / 2>/dev/null'

        result = parser.parse(CAP_OUTPUT_NO_EXPLOIT, step, command)

        assert not result.success
        assert len(result.warnings) > 0
        assert 'No exploitable' in result.warnings[0]

    def test_severity_classification(self):
        """PROVES: Capabilities classified by severity"""
        parser = CapabilitiesParser()
        step = {}
        command = 'getcap -r / 2>/dev/null'

        result = parser.parse(CAP_OUTPUT_MULTIPLE_EXPLOITABLE, step, command)

        exploitable = result.findings['exploitable_capabilities']

        # Check severity ordering (critical first)
        severities = [cap['severity'] for cap in exploitable]
        critical_count = severities.count('critical')
        assert critical_count >= 1

        # First capability should be critical (sorted by severity)
        assert exploitable[0]['severity'] == 'critical'

    def test_multiple_capabilities_per_binary(self):
        """PROVES: Handles comma-separated capabilities"""
        parser = CapabilitiesParser()
        step = {}
        command = 'getcap -r / 2>/dev/null'

        result = parser.parse(CAP_OUTPUT_MULTIPLE_CAPS_PER_BINARY, step, command)

        assert result.success

        # Check all caps extracted
        all_caps = result.findings['all_capabilities']
        assert len(all_caps) == 4  # 2 binaries × 2 caps each

        # Check exploitable caps
        exploitable = result.findings['exploitable_capabilities']
        assert len(exploitable) == 4  # All are exploitable

        # Check gdb has both caps
        gdb_caps = [c for c in exploitable if c['binary'] == '/usr/bin/gdb']
        assert len(gdb_caps) == 2
        gdb_cap_names = {c['capability'] for c in gdb_caps}
        assert 'cap_sys_ptrace' in gdb_cap_names
        assert 'cap_dac_read_search' in gdb_cap_names

    def test_mixed_format_parsing(self):
        """PROVES: Handles different capability notation formats"""
        parser = CapabilitiesParser()
        step = {}
        command = 'getcap -r / 2>/dev/null'

        result = parser.parse(CAP_OUTPUT_MIXED_FORMAT, step, command)

        assert result.success

        # Check all formats parsed
        all_caps = result.findings['all_capabilities']
        assert len(all_caps) == 3

        # Check capability names extracted correctly (without +ep or =eip)
        cap_names = {c['capability'] for c in all_caps}
        assert 'cap_setuid' in cap_names
        assert 'cap_dac_override' in cap_names
        assert 'cap_dac_read_search' in cap_names

    def test_error_output_handling(self):
        """PROVES: Detects error conditions"""
        parser = CapabilitiesParser()
        step = {}
        command = 'getcap -r / 2>/dev/null'

        result = parser.parse(CAP_OUTPUT_ERROR, step, command)

        assert not result.success
        assert len(result.warnings) > 0

    def test_permission_denied_handling(self):
        """PROVES: Handles permission denied gracefully"""
        parser = CapabilitiesParser()
        step = {}
        command = 'getcap -r / 2>/dev/null'

        result = parser.parse(CAP_OUTPUT_PERMISSION_DENIED, step, command)

        assert not result.success

    def test_empty_output_handling(self):
        """PROVES: Handles no capabilities found"""
        parser = CapabilitiesParser()
        step = {}
        command = 'getcap -r / 2>/dev/null'

        result = parser.parse(CAP_OUTPUT_EMPTY, step, command)

        assert not result.success
        assert 'No capabilities found' in result.warnings[0]

    def test_exploitable_capabilities_dict_structure(self):
        """PROVES: EXPLOITABLE_CAPABILITIES dict has correct structure"""
        # Check all required fields present
        for cap_name, cap_info in EXPLOITABLE_CAPABILITIES.items():
            assert 'severity' in cap_info
            assert 'description' in cap_info
            assert 'techniques' in cap_info
            assert cap_info['severity'] in ['critical', 'high', 'medium']
            assert isinstance(cap_info['techniques'], list)
            assert len(cap_info['techniques']) > 0

    def test_gtfobins_binaries_set_structure(self):
        """PROVES: GTFOBINS_CAP_BINARIES contains common binaries"""
        # Check essential binaries present
        essential_binaries = ['python3', 'vim', 'tar', 'perl', 'ruby', 'node', 'gdb']
        for binary in essential_binaries:
            assert binary in GTFOBINS_CAP_BINARIES

        # Check all entries are strings
        assert all(isinstance(binary, str) for binary in GTFOBINS_CAP_BINARIES)

    def test_binary_name_extraction(self):
        """PROVES: Correctly extracts binary name from full path"""
        parser = CapabilitiesParser()

        assert parser._extract_binary_name('/usr/bin/python3.8') == 'python3.8'
        assert parser._extract_binary_name('/usr/local/bin/vim') == 'vim'
        assert parser._extract_binary_name('python3') == 'python3'

    def test_severity_classification_method(self):
        """PROVES: Severity classification works for known and unknown capabilities"""
        parser = CapabilitiesParser()

        assert parser._classify_severity('cap_setuid') == 'critical'
        assert parser._classify_severity('cap_dac_override') == 'critical'
        assert parser._classify_severity('cap_dac_read_search') == 'high'
        assert parser._classify_severity('cap_chown') == 'medium'
        assert parser._classify_severity('cap_net_raw') == 'unknown'
        assert parser._classify_severity('cap_unknown_future') == 'unknown'
