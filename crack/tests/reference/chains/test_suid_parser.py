"""
Unit tests for SUID parser.

Tests parsing logic, GTFOBins detection, and variable extraction.
"""

import pytest
from crack.reference.chains.parsing.suid_parser import SUIDParser, GTFOBINS_SUID_BINARIES
from crack.reference.chains.parsing.registry import ParserRegistry


# Sample SUID enumeration output
SUID_OUTPUT_SAMPLE = """/usr/bin/passwd
/usr/bin/sudo
/usr/bin/find
/usr/bin/vim
/usr/bin/newgrp
/usr/bin/chsh
/usr/bin/base64
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
"""

SUID_OUTPUT_SINGLE_EXPLOIT = """/usr/bin/passwd
/usr/bin/sudo
/usr/bin/find
/usr/bin/newgrp
"""

SUID_OUTPUT_NO_EXPLOIT = """/usr/bin/passwd
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/chsh
"""


class TestSUIDParser:
    """Test SUID parser functionality"""

    def test_parser_registration(self):
        """PROVES: SUIDParser auto-registers via decorator"""
        parser = ParserRegistry.get_parser_by_name('suid')
        assert parser is not None
        assert isinstance(parser, SUIDParser)

    def test_can_parse_suid_commands(self):
        """PROVES: Parser detects SUID enumeration commands"""
        parser = SUIDParser()

        # Positive cases
        assert parser.can_parse({}, 'find / -perm -4000 -type f 2>/dev/null')
        assert parser.can_parse({}, 'find / -perm /4000 -type f')
        assert parser.can_parse({}, 'find / -perm -u=s -type f')

        # Negative cases
        assert not parser.can_parse({}, 'ls -la')
        assert not parser.can_parse({}, 'grep something')
        assert not parser.can_parse({}, 'find / -name "*.txt"')

    def test_parse_basic_output(self):
        """PROVES: Parser extracts binary paths correctly"""
        parser = SUIDParser()
        result = parser.parse(SUID_OUTPUT_SAMPLE, {}, 'find / -perm -4000')

        assert result.success
        assert result.parser_name == 'suid'
        assert 'all_binaries' in result.findings
        assert result.findings['total_count'] == 9

    def test_exploitable_binary_detection(self):
        """PROVES: Parser identifies GTFOBins-exploitable binaries"""
        parser = SUIDParser()
        result = parser.parse(SUID_OUTPUT_SAMPLE, {}, 'find / -perm -4000')

        exploitable = result.findings['exploitable_binaries']
        exploitable_paths = [b['path'] for b in exploitable]

        # Should find: find, vim, base64
        assert '/usr/bin/find' in exploitable_paths
        assert '/usr/bin/vim' in exploitable_paths
        assert '/usr/bin/base64' in exploitable_paths

        # Verify match metadata
        for binary in exploitable:
            assert 'gtfobin_match' in binary
            assert 'match_type' in binary
            assert binary['match_type'] in ['exact', 'fuzzy']

        # Should not include standard binaries
        assert '/usr/bin/passwd' not in exploitable_paths
        assert '/usr/bin/sudo' not in exploitable_paths

        assert result.findings['exploitable_count'] == 3

    def test_standard_binary_filtering(self):
        """PROVES: Parser filters out standard system binaries"""
        parser = SUIDParser()
        result = parser.parse(SUID_OUTPUT_SAMPLE, {}, 'find / -perm -4000')

        standard = result.findings['standard_binaries']

        # Should identify standard binaries
        assert '/usr/bin/passwd' in standard
        assert '/usr/bin/sudo' in standard
        assert '/usr/bin/newgrp' in standard
        assert '/usr/bin/chsh' in standard

        # Test includes: passwd, sudo, newgrp, chsh, dbus-daemon-launch-helper, ssh-keysign
        assert result.findings['standard_count'] == 6

    def test_single_exploitable_auto_select(self):
        """PROVES: Single exploitable binary auto-fills <TARGET_BIN>"""
        parser = SUIDParser()
        result = parser.parse(SUID_OUTPUT_SINGLE_EXPLOIT, {}, 'find / -perm -4000')

        # Only one exploitable binary (find)
        assert result.findings['exploitable_count'] == 1
        assert '<TARGET_BIN>' in result.variables
        assert result.variables['<TARGET_BIN>'] == '/usr/bin/find'
        assert '<TARGET_BIN>' not in result.selection_required

    def test_multiple_exploitable_requires_selection(self):
        """PROVES: Multiple exploitable binaries trigger user selection"""
        parser = SUIDParser()
        result = parser.parse(SUID_OUTPUT_SAMPLE, {}, 'find / -perm -4000')

        # Multiple exploitable binaries (find, vim, base64)
        assert result.findings['exploitable_count'] == 3
        assert '<TARGET_BIN>' not in result.variables
        assert '<TARGET_BIN>' in result.selection_required
        assert len(result.selection_required['<TARGET_BIN>']) == 3

    def test_no_exploitable_failure(self):
        """PROVES: No exploitable binaries marks result as failed"""
        parser = SUIDParser()
        result = parser.parse(SUID_OUTPUT_NO_EXPLOIT, {}, 'find / -perm -4000')

        assert not result.success
        assert result.findings['exploitable_count'] == 0
        assert len(result.warnings) > 0
        assert 'no exploitable' in result.warnings[0].lower()

    def test_error_output_detection(self):
        """PROVES: Parser detects error output"""
        parser = SUIDParser()
        error_output = "find: /root: Permission denied\ncommand not found"

        result = parser.parse(error_output, {}, 'find / -perm -4000')

        assert not result.success

    def test_empty_output(self):
        """PROVES: Empty output handled gracefully"""
        parser = SUIDParser()
        result = parser.parse("", {}, 'find / -perm -4000')

        assert result.findings['total_count'] == 0
        assert not result.success

    def test_gtfobins_database_comprehensive(self):
        """PROVES: GTFOBins database includes common OSCP binaries"""
        critical_binaries = ['find', 'vim', 'nmap', 'python', 'perl', 'awk', 'base64', 'less', 'more']

        for binary in critical_binaries:
            assert binary in GTFOBINS_SUID_BINARIES, f"{binary} missing from GTFOBins database"

    def test_parser_registry_integration(self):
        """PROVES: Parser integrates with registry system"""
        step = {'id': 'test-step'}
        command = 'find / -perm -4000 -type f'

        parser = ParserRegistry.get_parser(step, command)

        assert parser is not None
        assert parser.name == 'suid'

    def test_binary_path_extraction(self):
        """PROVES: Parser handles various path formats"""
        parser = SUIDParser()
        varied_output = """/usr/bin/find
/usr/local/bin/custom-tool
/opt/app/bin/service
/bin/vi
"""
        result = parser.parse(varied_output, {}, 'find / -perm -4000')

        paths = [b['path'] for b in result.findings['all_binaries']]

        assert '/usr/bin/find' in paths
        assert '/usr/local/bin/custom-tool' in paths
        assert '/opt/app/bin/service' in paths
        assert '/bin/vi' in paths


class TestSUIDParserActivations:
    """Test SUID parser chain activation logic (Phase 2)"""

    def test_no_exploitable_no_activation(self):
        """PROVES: No exploitable binaries → no activations"""
        parser = SUIDParser()
        result = parser.parse(SUID_OUTPUT_NO_EXPLOIT, {}, 'find / -perm -4000')

        assert len(result.activates_chains) == 0
        assert not result.has_activations()

    def test_single_exact_match_activation(self):
        """PROVES: Single exact match → single high-confidence activation"""
        parser = SUIDParser()
        result = parser.parse(SUID_OUTPUT_SINGLE_EXPLOIT, {}, 'find / -perm -4000')

        assert len(result.activates_chains) == 1
        assert result.has_activations()

        activation = result.activates_chains[0]
        assert activation.chain_id == 'linux-privesc-suid-exploit'
        assert activation.confidence == 'high'
        assert '<TARGET_BIN>' in activation.variables
        assert activation.variables['<TARGET_BIN>'] == '/usr/bin/find'
        assert 'Exploitable SUID binary found' in activation.reason
        assert 'find' in activation.reason

    def test_multiple_exact_matches_max_3_activations(self):
        """PROVES: Multiple exact matches → max 3 activations"""
        parser = SUIDParser()
        result = parser.parse(SUID_OUTPUT_SAMPLE, {}, 'find / -perm -4000')

        # Should have 3 exploitable binaries (find, vim, base64), all exact matches
        assert result.findings['exploitable_count'] == 3
        assert len(result.activates_chains) == 3  # Limited to 3

        # Verify all activations
        for activation in result.activates_chains:
            assert activation.chain_id == 'linux-privesc-suid-exploit'
            assert activation.confidence == 'high'  # All exact matches
            assert '<TARGET_BIN>' in activation.variables
            assert activation.variables['<TARGET_BIN>'].startswith('/usr/bin/')

    def test_fuzzy_match_medium_confidence(self):
        """PROVES: Fuzzy match → medium-confidence activation"""
        parser = SUIDParser()

        # Create output with fuzzy match binary (vim.basic → vim)
        fuzzy_output = """/usr/bin/passwd
/usr/bin/vim.basic
"""
        result = parser.parse(fuzzy_output, {}, 'find / -perm -4000')

        assert len(result.activates_chains) == 1
        activation = result.activates_chains[0]

        assert activation.confidence == 'medium'
        assert 'Potentially exploitable' in activation.reason
        assert '<TARGET_BIN>' in activation.variables
        assert activation.variables['<TARGET_BIN>'] == '/usr/bin/vim.basic'

    def test_activation_variables_populated(self):
        """PROVES: Variables correctly populated in activation"""
        parser = SUIDParser()
        result = parser.parse(SUID_OUTPUT_SINGLE_EXPLOIT, {}, 'find / -perm -4000')

        activation = result.activates_chains[0]

        assert '<TARGET_BIN>' in activation.variables
        assert activation.variables['<TARGET_BIN>'] == '/usr/bin/find'

    def test_activation_chain_id_correct(self):
        """PROVES: Chain ID is correct"""
        parser = SUIDParser()
        result = parser.parse(SUID_OUTPUT_SINGLE_EXPLOIT, {}, 'find / -perm -4000')

        activation = result.activates_chains[0]
        assert activation.chain_id == 'linux-privesc-suid-exploit'

    def test_existing_parser_behavior_unchanged(self):
        """PROVES: Existing parser behavior unchanged (backward compat)"""
        parser = SUIDParser()
        result = parser.parse(SUID_OUTPUT_SAMPLE, {}, 'find / -perm -4000')

        # Original behavior: findings extraction
        assert 'all_binaries' in result.findings
        assert 'exploitable_binaries' in result.findings
        assert 'standard_binaries' in result.findings

        # Original behavior: variable auto-selection (multiple, so selection required)
        assert '<TARGET_BIN>' in result.selection_required

        # New behavior: activations added without breaking old logic
        assert len(result.activates_chains) > 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
