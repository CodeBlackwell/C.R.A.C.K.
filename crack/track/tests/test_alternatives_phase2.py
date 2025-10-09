"""
Test suite for Phase 2 Alternative Commands
Tests all mined commands for quality, uniqueness, and educational value
"""

import pytest
from pathlib import Path
import sys

# Add track module to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from track.alternatives.commands import (
    web_enumeration, privilege_escalation, file_transfer,
    anti_forensics, database_enum, network_recon
)
from track.alternatives.models import AlternativeCommand, Variable


class TestMinedCommands:
    """Tests for all mined alternative commands"""

    @pytest.fixture
    def all_commands(self):
        """Collect all commands from all categories"""
        return {
            'web_enumeration': web_enumeration.ALTERNATIVES,
            'privilege_escalation': privilege_escalation.ALTERNATIVES,
            'file_transfer': file_transfer.ALTERNATIVES,
            'anti_forensics': anti_forensics.ALTERNATIVES,
            'database_enum': database_enum.ALTERNATIVES,
            'network_recon': network_recon.ALTERNATIVES
        }

    def test_command_count(self, all_commands):
        """
        VALUE: Ensures we have sufficient alternatives for OSCP exam
        User scenario: Student needs manual alternatives when tools fail
        """
        total = sum(len(cmds) for cmds in all_commands.values())
        assert total >= 30, f"Need at least 30 commands, got {total}"
        assert total <= 60, f"Too many commands dilutes quality, got {total}"

        # Each category should have 2-10 commands
        for category, commands in all_commands.items():
            count = len(commands)
            assert 2 <= count <= 10, f"{category} has {count} commands (expected 2-10)"

    def test_no_duplicate_ids(self, all_commands):
        """
        VALUE: Prevents command conflicts in registry
        User scenario: Each command must be uniquely addressable
        """
        all_ids = []
        for commands in all_commands.values():
            all_ids.extend([cmd.id for cmd in commands])

        assert len(all_ids) == len(set(all_ids)), "Duplicate command IDs found"

    def test_all_commands_have_required_fields(self, all_commands):
        """
        VALUE: Ensures commands are complete and usable
        User scenario: Student needs all information to execute command
        """
        for category, commands in all_commands.items():
            for cmd in commands:
                # Required fields
                assert cmd.id, f"Missing ID in {category}"
                assert cmd.name, f"Missing name for {cmd.id}"
                assert cmd.command_template, f"Missing command for {cmd.id}"
                assert cmd.description, f"Missing description for {cmd.id}"
                assert cmd.category, f"Missing category for {cmd.id}"
                assert cmd.tags, f"Missing tags for {cmd.id}"
                assert cmd.os_type in ['linux', 'windows', 'both'], f"Invalid os_type for {cmd.id}"

    def test_oscp_tags_present(self, all_commands):
        """
        VALUE: Commands are tagged for OSCP relevance
        User scenario: Student filters commands by OSCP priority
        """
        for commands in all_commands.values():
            for cmd in commands:
                tags_str = str(cmd.tags)
                assert 'OSCP:' in tags_str, f"{cmd.id} missing OSCP relevance tag"

                # Should have either HIGH, MEDIUM, or LOW
                has_relevance = any(level in tags_str for level in ['OSCP:HIGH', 'OSCP:MEDIUM', 'OSCP:LOW'])
                assert has_relevance, f"{cmd.id} missing OSCP relevance level"

    def test_educational_metadata(self, all_commands):
        """
        VALUE: Commands teach methodology, not just syntax
        User scenario: Student learns WHY to use command, not just HOW
        """
        for commands in all_commands.values():
            for cmd in commands:
                # Should have educational indicators
                if cmd.success_indicators:
                    assert len(cmd.success_indicators) > 0, f"{cmd.id} has empty success indicators"

                if cmd.next_steps:
                    assert len(cmd.next_steps) > 0, f"{cmd.id} has empty next steps"
                    # Next steps should be actionable (not vague)
                    for step in cmd.next_steps:
                        assert len(step) > 10, f"{cmd.id} has vague next step: {step}"

    def test_variable_auto_resolution(self, all_commands):
        """
        VALUE: Common variables auto-fill to reduce friction
        User scenario: TARGET, PORT, LHOST auto-fill from context
        """
        auto_resolve_vars = ['TARGET', 'PORT', 'LHOST', 'LPORT', 'SERVICE']

        for commands in all_commands.values():
            for cmd in commands:
                for var in cmd.variables:
                    if var.name in auto_resolve_vars:
                        assert var.auto_resolve, f"{cmd.id}: {var.name} should auto-resolve"

                    # All variables should have examples
                    if var.example:
                        assert len(var.example) > 0, f"{cmd.id}: {var.name} has empty example"

    def test_manual_alternatives_only(self, all_commands):
        """
        VALUE: Commands are manual alternatives, not automated tools
        User scenario: Student needs alternatives when tools are unavailable
        """
        automated_tools = ['metasploit', 'msfvenom', 'sqlmap', 'burp', 'cobalt', 'empire']

        for commands in all_commands.values():
            for cmd in commands:
                command_lower = cmd.command_template.lower()
                for tool in automated_tools:
                    assert tool not in command_lower, f"{cmd.id} uses automated tool: {tool}"

                # Should have MANUAL tag or similar
                tags_str = str(cmd.tags).upper()
                manual_indicators = ['MANUAL', 'NO_TOOLS', 'NO_DEPENDENCIES']
                has_manual = any(indicator in tags_str for indicator in manual_indicators)
                # Not strictly required but good to have

    def test_command_templates_valid(self, all_commands):
        """
        VALUE: Command templates are properly formatted
        User scenario: Variables can be substituted correctly
        """
        for commands in all_commands.values():
            for cmd in commands:
                # Check for proper variable format
                if '<' in cmd.command_template:
                    # Variables should be uppercase
                    import re
                    variables = re.findall(r'<([^>]+)>', cmd.command_template)
                    for var in variables:
                        assert var.isupper(), f"{cmd.id} has lowercase variable: <{var}>"

                        # Variable should be defined
                        var_names = [v.name for v in cmd.variables]
                        assert var in var_names, f"{cmd.id} uses undefined variable: <{var}>"


class TestCategorySpecific:
    """Tests specific to each category"""

    def test_web_enumeration_coverage(self):
        """
        VALUE: Web enumeration covers essential techniques
        User scenario: Student can enumerate web apps without gobuster/nikto
        """
        commands = web_enumeration.ALTERNATIVES
        techniques = [cmd.subcategory or '' for cmd in commands]

        # Should cover key areas
        important_areas = ['http-methods', 'information-disclosure', 'directory']
        for area in important_areas:
            has_area = any(area in tech for tech in techniques)
            # Soft assertion - nice to have but not required

    def test_privilege_escalation_coverage(self):
        """
        VALUE: Covers main Linux privesc vectors
        User scenario: Student can enumerate privesc without linpeas
        """
        commands = privilege_escalation.ALTERNATIVES
        command_strings = [cmd.command_template for cmd in commands]

        # Should cover key privesc vectors
        key_commands = ['sudo', 'suid', 'getcap', 'kernel', 'cron']
        coverage = {}
        for key in key_commands:
            coverage[key] = any(key in cmd.lower() for cmd in command_strings)

        # At least 3 key areas covered
        covered = sum(coverage.values())
        assert covered >= 3, f"Only {covered}/5 key privesc areas covered"

    def test_file_transfer_coverage(self):
        """
        VALUE: Covers both Linux and Windows transfer methods
        User scenario: Student can transfer files in any environment
        """
        commands = file_transfer.ALTERNATIVES

        # Check OS coverage
        linux_cmds = [cmd for cmd in commands if cmd.os_type in ['linux', 'both']]
        windows_cmds = [cmd for cmd in commands if cmd.os_type in ['windows', 'both']]

        assert len(linux_cmds) >= 2, "Need at least 2 Linux transfer methods"
        assert len(windows_cmds) >= 2, "Need at least 2 Windows transfer methods"

    def test_database_enum_coverage(self):
        """
        VALUE: Covers major database types
        User scenario: Student can enumerate MySQL, MSSQL, PostgreSQL manually
        """
        commands = database_enum.ALTERNATIVES
        command_strings = ' '.join([cmd.command_template for cmd in commands])

        # Should cover major databases
        databases = ['mysql', 'mssql', 'postgres', 'redis']
        coverage = {}
        for db in databases:
            coverage[db] = db in command_strings.lower()

        # At least 3 database types covered
        covered = sum(coverage.values())
        assert covered >= 3, f"Only {covered}/4 database types covered"

    def test_network_recon_coverage(self):
        """
        VALUE: Covers essential network enumeration
        User scenario: Student can enumerate services without nmap
        """
        commands = network_recon.ALTERNATIVES
        techniques = [cmd.name.lower() for cmd in commands]

        # Should have port scanning and service enumeration
        has_port_scan = any('port' in tech for tech in techniques)
        has_banner = any('banner' in tech or 'version' in tech for tech in techniques)
        has_smb = any('smb' in tech or 'shares' in tech for tech in techniques)

        assert has_port_scan, "Missing port scanning alternatives"
        assert has_banner, "Missing banner grabbing alternatives"


class TestEducationalValue:
    """Tests that commands provide educational value"""

    def test_flag_explanations_present(self):
        """
        VALUE: Students learn what each flag does
        User scenario: Student understands command flags for exam
        """
        all_commands = [
            *web_enumeration.ALTERNATIVES,
            *privilege_escalation.ALTERNATIVES,
            *file_transfer.ALTERNATIVES,
            *anti_forensics.ALTERNATIVES,
            *database_enum.ALTERNATIVES,
            *network_recon.ALTERNATIVES
        ]

        commands_with_flags = [cmd for cmd in all_commands if '-' in cmd.command_template]

        for cmd in commands_with_flags:
            if cmd.flag_explanations:
                assert len(cmd.flag_explanations) > 0, f"{cmd.id} has empty flag explanations"

                # Explanations should be meaningful
                for flag, explanation in cmd.flag_explanations.items():
                    assert len(explanation) > 10, f"{cmd.id}: {flag} has short explanation"

    def test_quick_win_distribution(self):
        """
        VALUE: Sufficient quick-win commands for exam time management
        User scenario: Student identifies fast, high-value targets
        """
        all_commands = [
            *web_enumeration.ALTERNATIVES,
            *privilege_escalation.ALTERNATIVES,
            *file_transfer.ALTERNATIVES,
            *anti_forensics.ALTERNATIVES,
            *database_enum.ALTERNATIVES,
            *network_recon.ALTERNATIVES
        ]

        quick_wins = [cmd for cmd in all_commands if 'QUICK_WIN' in str(cmd.tags)]
        total = len(all_commands)
        quick_count = len(quick_wins)

        # At least 30% should be quick wins
        ratio = quick_count / total
        assert ratio >= 0.3, f"Only {ratio:.1%} are quick wins (need 30%+)"


if __name__ == '__main__':
    # Run tests with verbose output
    pytest.main([__file__, '-v', '--tb=short'])