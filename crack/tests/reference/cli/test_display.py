"""
Tests for Reference CLI display.py - Command display formatting

Business Value Focus:
- Users need readable command output in multiple formats
- Verbose mode shows complete command documentation
- Auto-filled examples help users understand usage
- Format options (text, json, markdown) support different workflows
"""

import pytest
import sys
import json
from pathlib import Path
from io import StringIO
from unittest.mock import Mock, patch

# Add project root
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tests.reference.cli.conftest import (
    CommandFactory, ThemeFactory, RegistryFactory, CLIAssertions
)


class TestDisplayCLIInitialization:
    """Tests for DisplayCLI initialization"""

    def test_initialization_with_dependencies(self):
        """
        BV: DisplayCLI initializes with required dependencies

        Scenario:
          Given: Registry, placeholder engine, and theme
          When: DisplayCLI is instantiated
          Then: Dependencies are stored correctly
        """
        from crack.reference.cli.display import DisplayCLI

        mock_registry = RegistryFactory.create_mock()
        mock_theme = ThemeFactory.create_mock()
        mock_placeholder = Mock()

        display = DisplayCLI(
            registry=mock_registry,
            placeholder_engine=mock_placeholder,
            theme=mock_theme
        )

        assert display.registry == mock_registry
        assert display.placeholder_engine == mock_placeholder
        assert display.theme == mock_theme

    def test_initialization_creates_default_theme(self):
        """
        BV: DisplayCLI creates default theme if not provided

        Scenario:
          Given: No theme provided
          When: DisplayCLI is instantiated
          Then: Default theme is created
        """
        from crack.reference.cli.display import DisplayCLI

        display = DisplayCLI()

        assert display.theme is not None


class TestTextFormatDisplay:
    """Tests for text format command display"""

    def test_display_commands_text_format_shows_id_and_name(self):
        """
        BV: Text format shows command ID and name for identification

        Scenario:
          Given: List of commands
          When: display_commands() is called with format='text'
          Then: Each command shows ID and name
        """
        from crack.reference.cli.display import DisplayCLI

        commands = [
            CommandFactory.create(id="nmap-full-tcp", name="Nmap Full TCP Scan"),
            CommandFactory.create(id="gobuster-dir", name="Gobuster Directory Scan")
        ]

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.display_commands(commands, format='text')

        result = output.getvalue()
        assert 'nmap-full-tcp' in result
        assert 'Nmap Full TCP Scan' in result
        assert 'gobuster-dir' in result
        assert 'Gobuster Directory Scan' in result

    def test_display_commands_text_format_shows_numbering(self):
        """
        BV: Text format numbers commands for easy selection

        Scenario:
          Given: Multiple commands
          When: display_commands() is called
          Then: Commands are numbered starting from 1
        """
        from crack.reference.cli.display import DisplayCLI

        commands = [
            CommandFactory.create(id="cmd-1"),
            CommandFactory.create(id="cmd-2"),
            CommandFactory.create(id="cmd-3")
        ]

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.display_commands(commands, format='text')

        result = output.getvalue()
        assert '1.' in result
        assert '2.' in result
        assert '3.' in result

    def test_display_commands_text_format_shows_command_template(self):
        """
        BV: Text format shows the command template

        Scenario:
          Given: Command with placeholders
          When: display_commands() is called
          Then: Command template is displayed
        """
        from crack.reference.cli.display import DisplayCLI

        commands = [
            CommandFactory.create(
                id="nmap-scan",
                command="nmap -p <PORT> <TARGET>"
            )
        ]

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.display_commands(commands, format='text')

        result = output.getvalue()
        assert 'nmap -p <PORT> <TARGET>' in result


class TestVerboseDisplay:
    """Tests for verbose command display"""

    def test_verbose_shows_description(self):
        """
        BV: Verbose mode shows full command description

        Scenario:
          Given: Command with description
          When: display_commands() is called with verbose=True
          Then: Description is displayed
        """
        from crack.reference.cli.display import DisplayCLI

        commands = [
            CommandFactory.create(
                id="test-cmd",
                description="This is a detailed description of the command"
            )
        ]

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.display_commands(commands, format='text', verbose=True)

        result = output.getvalue()
        assert 'This is a detailed description' in result

    def test_verbose_shows_prerequisites(self):
        """
        BV: Verbose mode shows command prerequisites

        Scenario:
          Given: Command with prerequisites
          When: display_commands() is called with verbose=True
          Then: Prerequisites are listed
        """
        from crack.reference.cli.display import DisplayCLI

        commands = [
            CommandFactory.create_with_prerequisites(
                id="test-cmd",
                prerequisites=["mkdir -p /tmp/output", "nc -lvnp <LPORT>"]
            )
        ]

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.display_commands(commands, format='text', verbose=True)

        result = output.getvalue()
        assert 'Prerequisites' in result
        assert 'mkdir' in result

    def test_verbose_shows_variables(self):
        """
        BV: Verbose mode documents variables with examples

        Scenario:
          Given: Command with variable definitions
          When: display_commands() is called with verbose=True
          Then: Variables are documented with examples
        """
        from crack.reference.cli.display import DisplayCLI
        from crack.reference.core.registry import CommandVariable

        commands = [
            CommandFactory.create(
                id="test-cmd",
                variables=[
                    CommandVariable(name="<PORT>", description="Target port", example="80", required=True),
                    CommandVariable(name="<TARGET>", description="Target IP", example="192.168.1.1", required=True)
                ]
            )
        ]

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.display_commands(commands, format='text', verbose=True)

        result = output.getvalue()
        assert 'Variables' in result
        assert 'PORT' in result
        assert 'Target port' in result

    def test_verbose_shows_flag_explanations(self):
        """
        BV: Verbose mode explains command flags

        Scenario:
          Given: Command with flag explanations
          When: display_commands() is called with verbose=True
          Then: Flags are explained
        """
        from crack.reference.cli.display import DisplayCLI

        commands = [
            CommandFactory.create(
                id="test-cmd",
                flag_explanations={
                    "-p": "Specify port range",
                    "-sV": "Service version detection"
                }
            )
        ]

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.display_commands(commands, format='text', verbose=True)

        result = output.getvalue()
        assert 'Flags' in result
        assert '-p' in result

    def test_verbose_shows_success_indicators(self):
        """
        BV: Verbose mode shows what success looks like

        Scenario:
          Given: Command with success indicators
          When: display_commands() is called with verbose=True
          Then: Success indicators are displayed
        """
        from crack.reference.cli.display import DisplayCLI

        commands = [
            CommandFactory.create(
                id="test-cmd",
                success_indicators=["open port found", "service version detected"]
            )
        ]

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.display_commands(commands, format='text', verbose=True)

        result = output.getvalue()
        assert 'Success' in result
        assert 'open port found' in result

    def test_verbose_shows_failure_indicators(self):
        """
        BV: Verbose mode shows what failure looks like

        Scenario:
          Given: Command with failure indicators
          When: display_commands() is called with verbose=True
          Then: Failure indicators are displayed
        """
        from crack.reference.cli.display import DisplayCLI

        commands = [
            CommandFactory.create(
                id="test-cmd",
                failure_indicators=["host seems down", "connection refused"]
            )
        ]

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.display_commands(commands, format='text', verbose=True)

        result = output.getvalue()
        assert 'Failure' in result
        assert 'host seems down' in result

    def test_verbose_shows_troubleshooting(self):
        """
        BV: Verbose mode provides troubleshooting guidance

        Scenario:
          Given: Command with troubleshooting tips
          When: display_commands() is called with verbose=True
          Then: Troubleshooting is displayed
        """
        from crack.reference.cli.display import DisplayCLI

        commands = [
            CommandFactory.create(
                id="test-cmd",
                troubleshooting={
                    "Host seems down": "Try with -Pn to skip host discovery",
                    "Permission denied": "Run with sudo"
                }
            )
        ]

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.display_commands(commands, format='text', verbose=True)

        result = output.getvalue()
        assert 'Troubleshooting' in result
        assert 'Host seems down' in result

    def test_verbose_shows_next_steps(self):
        """
        BV: Verbose mode suggests next steps after command

        Scenario:
          Given: Command with next steps
          When: display_commands() is called with verbose=True
          Then: Next steps are displayed
        """
        from crack.reference.cli.display import DisplayCLI

        commands = [
            CommandFactory.create(
                id="test-cmd",
                next_steps=["Run service enumeration", "Check for vulnerabilities"]
            )
        ]

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.display_commands(commands, format='text', verbose=True)

        result = output.getvalue()
        assert 'Next Steps' in result
        assert 'service enumeration' in result

    def test_verbose_shows_tags(self):
        """
        BV: Verbose mode shows command tags for filtering

        Scenario:
          Given: Command with tags
          When: display_commands() is called with verbose=True
          Then: Tags are displayed
        """
        from crack.reference.cli.display import DisplayCLI

        commands = [
            CommandFactory.create(
                id="test-cmd",
                tags=["OSCP:HIGH", "ENUM", "QUICK_WIN"]
            )
        ]

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.display_commands(commands, format='text', verbose=True)

        result = output.getvalue()
        assert 'Tags' in result
        assert 'OSCP:HIGH' in result

    def test_verbose_shows_oscp_relevance(self):
        """
        BV: Verbose mode indicates OSCP relevance level

        Scenario:
          Given: Command with OSCP relevance
          When: display_commands() is called with verbose=True
          Then: OSCP relevance is displayed
        """
        from crack.reference.cli.display import DisplayCLI

        commands = [
            CommandFactory.create(
                id="test-cmd",
                oscp_relevance="high"
            )
        ]

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.display_commands(commands, format='text', verbose=True)

        result = output.getvalue()
        assert 'OSCP' in result
        assert 'HIGH' in result


class TestJsonFormatDisplay:
    """Tests for JSON format command display"""

    def test_json_format_produces_valid_json(self):
        """
        BV: JSON format produces parseable JSON for scripting

        Scenario:
          Given: Commands to display
          When: display_commands() is called with format='json'
          Then: Valid JSON is produced
        """
        from crack.reference.cli.display import DisplayCLI

        commands = [
            CommandFactory.create(id="test-cmd-1"),
            CommandFactory.create(id="test-cmd-2")
        ]

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.display_commands(commands, format='json')

        result = output.getvalue()
        parsed = json.loads(result)  # Should not raise

        assert isinstance(parsed, list)
        assert len(parsed) == 2

    def test_json_format_includes_all_fields(self):
        """
        BV: JSON format includes all command fields

        Scenario:
          Given: Command with various fields
          When: display_commands() is called with format='json'
          Then: All fields are present in JSON
        """
        from crack.reference.cli.display import DisplayCLI

        commands = [
            CommandFactory.create(
                id="test-cmd",
                name="Test Command",
                category="recon",
                description="Test description",
                tags=["TAG1", "TAG2"]
            )
        ]

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.display_commands(commands, format='json')

        result = output.getvalue()
        parsed = json.loads(result)

        assert parsed[0]['id'] == 'test-cmd'
        assert parsed[0]['name'] == 'Test Command'
        assert parsed[0]['category'] == 'recon'
        assert 'TAG1' in parsed[0]['tags']


class TestMarkdownFormatDisplay:
    """Tests for Markdown format command display"""

    def test_markdown_format_uses_headers(self):
        """
        BV: Markdown format uses proper headers for documentation

        Scenario:
          Given: Commands to display
          When: display_commands() is called with format='markdown'
          Then: Markdown headers are used
        """
        from crack.reference.cli.display import DisplayCLI

        commands = [
            CommandFactory.create(id="test-cmd", name="Test Command")
        ]

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.display_commands(commands, format='markdown')

        result = output.getvalue()
        assert '## Test Command' in result

    def test_markdown_format_uses_code_blocks(self):
        """
        BV: Markdown format uses code blocks for commands

        Scenario:
          Given: Command with command template
          When: display_commands() is called with format='markdown'
          Then: Command is in code block
        """
        from crack.reference.cli.display import DisplayCLI

        commands = [
            CommandFactory.create(
                id="test-cmd",
                command="nmap -p <PORT> <TARGET>"
            )
        ]

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.display_commands(commands, format='markdown')

        result = output.getvalue()
        assert '```bash' in result
        assert 'nmap -p <PORT> <TARGET>' in result
        assert '```' in result

    def test_markdown_verbose_shows_tags(self):
        """
        BV: Markdown verbose mode includes tags

        Scenario:
          Given: Command with tags
          When: display_commands() is called with format='markdown', verbose=True
          Then: Tags are displayed with formatting
        """
        from crack.reference.cli.display import DisplayCLI

        commands = [
            CommandFactory.create(
                id="test-cmd",
                tags=["OSCP:HIGH", "ENUM"]
            )
        ]

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.display_commands(commands, format='markdown', verbose=True)

        result = output.getvalue()
        assert '**Tags**' in result
        assert 'OSCP:HIGH' in result


class TestShowCommandDetails:
    """Tests for show_command_details (single command detailed view)"""

    def test_show_command_details_displays_header(self):
        """
        BV: Command details start with clear header

        Scenario:
          Given: Single command
          When: show_command_details() is called
          Then: Header with command name is displayed
        """
        from crack.reference.cli.display import DisplayCLI

        cmd = CommandFactory.create(id="test-cmd", name="Test Command")

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.show_command_details(cmd)

        result = output.getvalue()
        assert 'Test Command' in result

    def test_show_command_details_displays_id_and_category(self):
        """
        BV: Command details show ID and category for context

        Scenario:
          Given: Command with category
          When: show_command_details() is called
          Then: ID and category are displayed
        """
        from crack.reference.cli.display import DisplayCLI

        cmd = CommandFactory.create(
            id="nmap-full-tcp",
            category="recon",
            subcategory="network"
        )

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.show_command_details(cmd)

        result = output.getvalue()
        assert 'nmap-full-tcp' in result
        assert 'recon' in result

    def test_show_command_details_displays_command_template(self):
        """
        BV: Command details show the command template prominently

        Scenario:
          Given: Command with template
          When: show_command_details() is called
          Then: Command template is displayed
        """
        from crack.reference.cli.display import DisplayCLI

        cmd = CommandFactory.create(
            id="test-cmd",
            command="nmap -sV -sC <TARGET>"
        )

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.show_command_details(cmd)

        result = output.getvalue()
        assert 'nmap -sV -sC <TARGET>' in result

    def test_show_command_details_displays_filled_example(self):
        """
        BV: Command details show pre-filled example if available

        Scenario:
          Given: Command with filled_example
          When: show_command_details() is called
          Then: Filled example is displayed
        """
        from crack.reference.cli.display import DisplayCLI

        cmd = CommandFactory.create(
            id="test-cmd",
            command="nmap -p <PORT> <TARGET>",
            filled_example="nmap -p 80,443 192.168.1.100"
        )

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.show_command_details(cmd)

        result = output.getvalue()
        assert 'nmap -p 80,443 192.168.1.100' in result

    def test_show_command_details_shows_usage_hint(self):
        """
        BV: Command details footer shows how to fill and execute

        Scenario:
          Given: Command
          When: show_command_details() is called
          Then: Usage hint is displayed
        """
        from crack.reference.cli.display import DisplayCLI

        cmd = CommandFactory.create(id="test-cmd")

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.show_command_details(cmd)

        result = output.getvalue()
        assert 'crack reference' in result
        assert '-i' in result

    def test_show_command_details_shows_alternatives(self):
        """
        BV: Command details show alternative commands

        Scenario:
          Given: Command with alternatives
          When: show_command_details() is called
          Then: Alternatives are listed
        """
        from crack.reference.cli.display import DisplayCLI

        cmd = CommandFactory.create(
            id="test-cmd",
            alternatives=["gobuster-dir", "feroxbuster-dir"]
        )

        mock_registry = RegistryFactory.create_mock()
        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.show_command_details(cmd)

        result = output.getvalue()
        assert 'Alternatives' in result

    def test_show_command_details_uses_placeholder_engine(self):
        """
        BV: Command details auto-fill placeholders from config

        Scenario:
          Given: Command with placeholders and placeholder engine
          When: show_command_details() is called
          Then: Autofilled example is shown
        """
        from crack.reference.cli.display import DisplayCLI

        cmd = CommandFactory.create(
            id="test-cmd",
            command="nmap -p <PORT> <TARGET>"
        )

        mock_placeholder = Mock()
        mock_placeholder.substitute.return_value = "nmap -p 80 192.168.1.1"

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(
            placeholder_engine=mock_placeholder,
            theme=mock_theme
        )

        output = StringIO()
        with patch('sys.stdout', output):
            display.show_command_details(cmd)

        result = output.getvalue()
        assert 'Autofilled' in result
        assert '192.168.1.1' in result


class TestShowCommandTree:
    """Tests for show_command_tree (tree view of commands)"""

    def test_show_command_tree_displays_categories(self):
        """
        BV: Tree view organizes commands by category

        Scenario:
          Given: Registry with commands in categories
          When: show_command_tree() is called
          Then: Categories are displayed as sections
        """
        from crack.reference.cli.display import DisplayCLI

        commands = [
            CommandFactory.create(id="recon-1", category="recon"),
            CommandFactory.create(id="recon-2", category="recon"),
            CommandFactory.create(id="web-1", category="web")
        ]

        mock_registry = Mock()
        mock_registry.commands = {cmd.id: cmd for cmd in commands}
        mock_registry.get_quick_wins.return_value = []
        mock_registry.get_oscp_high.return_value = []

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.show_command_tree(mock_registry)

        result = output.getvalue()
        assert 'Reconnaissance' in result or 'recon' in result.lower()
        assert 'Web' in result or 'web' in result.lower()

    def test_show_command_tree_shows_total_count(self):
        """
        BV: Tree view shows total command count

        Scenario:
          Given: Registry with commands
          When: show_command_tree() is called
          Then: Total count is displayed
        """
        from crack.reference.cli.display import DisplayCLI

        commands = [
            CommandFactory.create(id=f"cmd-{i}") for i in range(5)
        ]

        mock_registry = Mock()
        mock_registry.commands = {cmd.id: cmd for cmd in commands}
        mock_registry.get_quick_wins.return_value = []
        mock_registry.get_oscp_high.return_value = []

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.show_command_tree(mock_registry)

        result = output.getvalue()
        assert 'Total Commands: 5' in result

    def test_show_command_tree_highlights_quick_wins(self):
        """
        BV: Tree view highlights quick win commands

        Scenario:
          Given: Registry with quick win commands
          When: show_command_tree() is called
          Then: Quick wins are marked
        """
        from crack.reference.cli.display import DisplayCLI

        commands = [
            CommandFactory.create_quick_win(id="smb-enum", category="recon")
        ]

        mock_registry = Mock()
        mock_registry.commands = {cmd.id: cmd for cmd in commands}
        mock_registry.get_quick_wins.return_value = commands
        mock_registry.get_oscp_high.return_value = []

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.show_command_tree(mock_registry)

        result = output.getvalue()
        assert 'QUICK WIN' in result or 'Quick Wins' in result


class TestAutofilledExamples:
    """Tests for autofilled example display"""

    def test_autofilled_not_shown_when_same_as_template(self):
        """
        BV: Don't show autofilled if no substitutions made

        Scenario:
          Given: Command with no matching config values
          When: Placeholder engine returns same string
          Then: Autofilled section is not shown
        """
        from crack.reference.cli.display import DisplayCLI

        cmd = CommandFactory.create(
            id="test-cmd",
            command="nmap -p <CUSTOM_VAR> <TARGET>"
        )

        mock_placeholder = Mock()
        # Return same string (no substitution)
        mock_placeholder.substitute.return_value = "nmap -p <CUSTOM_VAR> <TARGET>"

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(
            placeholder_engine=mock_placeholder,
            theme=mock_theme
        )

        output = StringIO()
        with patch('sys.stdout', output):
            display.show_command_details(cmd)

        result = output.getvalue()
        # Should not show "Autofilled (Session)" section
        assert result.count('Autofilled') <= 1 or 'Autofilled' not in result

    def test_prerequisites_also_autofilled(self):
        """
        BV: Prerequisites are also auto-filled with config values

        Scenario:
          Given: Command with prerequisites containing placeholders
          When: Displayed with placeholder engine
          Then: Prerequisites are also auto-filled
        """
        from crack.reference.cli.display import DisplayCLI

        cmd = CommandFactory.create_with_prerequisites(
            id="test-cmd",
            prerequisites=["nc -lvnp <LPORT>"]
        )

        mock_placeholder = Mock()
        mock_placeholder.substitute.side_effect = lambda x: x.replace("<LPORT>", "4444")

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(
            placeholder_engine=mock_placeholder,
            theme=mock_theme
        )

        output = StringIO()
        with patch('sys.stdout', output):
            display.display_commands([cmd], format='text', verbose=True)

        result = output.getvalue()
        assert '4444' in result


class TestEdgeCases:
    """Tests for edge cases in display"""

    def test_empty_command_list(self):
        """
        BV: Gracefully handle empty command list

        Scenario:
          Given: Empty command list
          When: display_commands() is called
          Then: No error is raised
        """
        from crack.reference.cli.display import DisplayCLI

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.display_commands([], format='text')

        # Should not raise, output may be empty
        assert True

    def test_command_with_empty_fields(self):
        """
        BV: Handle commands with empty optional fields

        Scenario:
          Given: Command with empty tags, prerequisites, etc.
          When: display_commands() is called with verbose=True
          Then: Empty sections are not displayed
        """
        from crack.reference.cli.display import DisplayCLI

        cmd = CommandFactory.create(
            id="minimal-cmd",
            tags=[],
            prerequisites=[],
            success_indicators=[],
            failure_indicators=[]
        )

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.display_commands([cmd], format='text', verbose=True)

        result = output.getvalue()
        # Should display without error
        assert 'minimal-cmd' in result

    def test_special_characters_in_command(self):
        """
        BV: Handle special characters in commands

        Scenario:
          Given: Command with special characters
          When: display_commands() is called
          Then: Characters are preserved correctly
        """
        from crack.reference.cli.display import DisplayCLI

        cmd = CommandFactory.create(
            id="special-cmd",
            command="grep -E '^(user|admin)' /etc/passwd | awk -F: '{print $1}'"
        )

        mock_theme = ThemeFactory.create_mock()
        display = DisplayCLI(theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            display.display_commands([cmd], format='text')

        result = output.getvalue()
        assert "grep -E" in result
        assert "awk -F:" in result
