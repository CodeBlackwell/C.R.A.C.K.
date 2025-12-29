"""
Tests for Reference CLI cheatsheet.py - Cheatsheet display and interaction

Business Value Focus:
- Users need educational cheatsheets for OSCP preparation
- Search must find relevant cheatsheets quickly
- Display must be readable and educational
- Command filling helps users execute techniques
"""

import pytest
import sys
from pathlib import Path
from io import StringIO
from unittest.mock import Mock, patch, MagicMock
from dataclasses import dataclass, field
from typing import List

# Add project root
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tests.reference.cli.conftest import (
    ThemeFactory, CommandFactory, RegistryFactory, CLIAssertions
)


# Mock cheatsheet classes for testing
@dataclass
class MockEducationalHeader:
    """Mock educational header"""
    how_to_recognize: List[str] = field(default_factory=list)
    when_to_look_for: List[str] = field(default_factory=list)


@dataclass
class MockScenario:
    """Mock scenario"""
    title: str = "Test Scenario"
    context: str = "Context for the scenario"
    approach: str = "Step by step approach"
    expected_outcome: str = "What should happen"
    why_this_works: str = "Technical explanation"


@dataclass
class MockSection:
    """Mock command section"""
    title: str = "Test Section"
    notes: str = "Section notes"
    commands: List[str] = field(default_factory=list)


@dataclass
class MockCheatsheet:
    """Mock cheatsheet for testing"""
    id: str = "test-cheatsheet"
    name: str = "Test Cheatsheet"
    description: str = "A test cheatsheet"
    tags: List[str] = field(default_factory=list)
    educational_header: MockEducationalHeader = field(default_factory=MockEducationalHeader)
    scenarios: List[MockScenario] = field(default_factory=list)
    sections: List[MockSection] = field(default_factory=list)


class CheatsheetFactory:
    """Factory for creating test cheatsheets"""

    _counter = 0

    @classmethod
    def create(cls,
               id: str = None,
               name: str = None,
               description: str = None,
               tags: list = None,
               sections: list = None,
               scenarios: list = None) -> MockCheatsheet:
        """Create a mock cheatsheet"""
        cls._counter += 1
        if id is None:
            id = f"test-sheet-{cls._counter}"
        if name is None:
            name = f"Test Cheatsheet {cls._counter}"
        if description is None:
            description = f"Description for {name}"
        if tags is None:
            tags = ["TEST"]
        if sections is None:
            sections = [
                MockSection(
                    title="Basic Commands",
                    notes="Basic usage notes",
                    commands=["test-cmd-1", "test-cmd-2"]
                )
            ]
        if scenarios is None:
            scenarios = [
                MockScenario(title="Default Scenario")
            ]

        return MockCheatsheet(
            id=id,
            name=name,
            description=description,
            tags=tags,
            educational_header=MockEducationalHeader(
                how_to_recognize=["Pattern 1", "Pattern 2"],
                when_to_look_for=["Situation 1", "Situation 2"]
            ),
            scenarios=scenarios,
            sections=sections
        )


class TestCheatsheetCLIInitialization:
    """Tests for CheatsheetCLI initialization"""

    def test_initialization_with_dependencies(self):
        """
        BV: CheatsheetCLI initializes with required dependencies

        Scenario:
          Given: Cheatsheet registry and command registry
          When: CheatsheetCLI is instantiated
          Then: Dependencies are stored correctly
        """
        from crack.reference.cli.cheatsheet import CheatsheetCLI

        mock_cheatsheet_registry = Mock()
        mock_command_registry = RegistryFactory.create_mock()
        mock_theme = ThemeFactory.create_mock()

        cli = CheatsheetCLI(
            cheatsheet_registry=mock_cheatsheet_registry,
            command_registry=mock_command_registry,
            theme=mock_theme
        )

        assert cli.cheatsheet_registry == mock_cheatsheet_registry
        assert cli.command_registry == mock_command_registry
        assert cli.theme == mock_theme


class TestListCheatsheets:
    """Tests for list_cheatsheets command"""

    def test_list_shows_all_cheatsheets(self):
        """
        BV: List displays all available cheatsheets

        Scenario:
          Given: Multiple cheatsheets
          When: list_cheatsheets() is called
          Then: All cheatsheets are displayed
        """
        from crack.reference.cli.cheatsheet import CheatsheetCLI

        sheets = [
            CheatsheetFactory.create(id="sheet-1", name="SQL Injection"),
            CheatsheetFactory.create(id="sheet-2", name="LFI Techniques")
        ]

        mock_registry = Mock()
        mock_registry.list_cheatsheets.return_value = sheets

        mock_theme = ThemeFactory.create_mock()
        cli = CheatsheetCLI(cheatsheet_registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            result = cli.list_cheatsheets()

        output_text = output.getvalue()
        assert 'sheet-1' in output_text
        assert 'sheet-2' in output_text
        assert len(result) == 2

    def test_list_handles_empty(self):
        """
        BV: List handles no cheatsheets gracefully

        Scenario:
          Given: No cheatsheets available
          When: list_cheatsheets() is called
          Then: Appropriate message is shown
        """
        from crack.reference.cli.cheatsheet import CheatsheetCLI

        mock_registry = Mock()
        mock_registry.list_cheatsheets.return_value = []

        mock_theme = ThemeFactory.create_mock()
        cli = CheatsheetCLI(cheatsheet_registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            result = cli.list_cheatsheets()

        assert result == []
        assert 'No cheatsheets' in output.getvalue()

    def test_list_groups_by_category(self):
        """
        BV: List groups cheatsheets by category

        Scenario:
          Given: Cheatsheets with different tags
          When: list_cheatsheets() is called
          Then: Grouped by primary tag
        """
        from crack.reference.cli.cheatsheet import CheatsheetCLI

        sheets = [
            CheatsheetFactory.create(id="web-1", tags=["WEB", "SQLI"]),
            CheatsheetFactory.create(id="web-2", tags=["WEB", "LFI"]),
            CheatsheetFactory.create(id="linux-1", tags=["LINUX", "PRIVESC"])
        ]

        mock_registry = Mock()
        mock_registry.list_cheatsheets.return_value = sheets

        mock_theme = ThemeFactory.create_mock()
        cli = CheatsheetCLI(cheatsheet_registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            cli.list_cheatsheets()

        output_text = output.getvalue()
        # Should contain category groupings
        assert 'WEB' in output_text or 'LINUX' in output_text

    def test_list_numbered_for_selection(self):
        """
        BV: Numbered list allows easy selection

        Scenario:
          Given: Multiple cheatsheets
          When: list_cheatsheets(numbered=True) is called
          Then: Numbers are displayed for selection
        """
        from crack.reference.cli.cheatsheet import CheatsheetCLI

        sheets = [
            CheatsheetFactory.create(id="sheet-1"),
            CheatsheetFactory.create(id="sheet-2")
        ]

        mock_registry = Mock()
        mock_registry.list_cheatsheets.return_value = sheets

        mock_theme = ThemeFactory.create_mock()
        cli = CheatsheetCLI(cheatsheet_registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            cli.list_cheatsheets(numbered=True)

        output_text = output.getvalue()
        assert '1.' in output_text
        assert '2.' in output_text


class TestShowCheatsheet:
    """Tests for show_cheatsheet command"""

    def test_show_exact_id_match(self):
        """
        BV: Exact ID shows full cheatsheet

        Scenario:
          Given: Cheatsheet with exact ID
          When: show_cheatsheet() is called with ID
          Then: Full cheatsheet is displayed
        """
        from crack.reference.cli.cheatsheet import CheatsheetCLI

        sheet = CheatsheetFactory.create(
            id="log-poisoning",
            name="Log Poisoning Techniques"
        )

        mock_cheatsheet_registry = Mock()
        mock_cheatsheet_registry.get_cheatsheet.return_value = sheet

        mock_command_registry = RegistryFactory.create_mock()
        mock_theme = ThemeFactory.create_mock()

        cli = CheatsheetCLI(
            cheatsheet_registry=mock_cheatsheet_registry,
            command_registry=mock_command_registry,
            theme=mock_theme
        )

        output = StringIO()
        with patch('sys.stdout', output):
            cli.show_cheatsheet("log-poisoning")

        output_text = output.getvalue()
        assert 'Log Poisoning Techniques' in output_text

    def test_show_partial_match_lists_options(self):
        """
        BV: Partial match lists matching cheatsheets

        Scenario:
          Given: Partial ID that matches multiple
          When: show_cheatsheet() is called
          Then: List of matches is shown
        """
        from crack.reference.cli.cheatsheet import CheatsheetCLI

        sheets = {
            "sql-injection-basic": CheatsheetFactory.create(id="sql-injection-basic"),
            "sql-injection-advanced": CheatsheetFactory.create(id="sql-injection-advanced")
        }

        mock_cheatsheet_registry = Mock()
        mock_cheatsheet_registry.get_cheatsheet.return_value = None  # No exact match
        mock_cheatsheet_registry.cheatsheets = sheets
        mock_cheatsheet_registry.search_cheatsheets.return_value = list(sheets.values())

        mock_theme = ThemeFactory.create_mock()
        cli = CheatsheetCLI(
            cheatsheet_registry=mock_cheatsheet_registry,
            theme=mock_theme
        )

        output = StringIO()
        with patch('sys.stdout', output):
            cli.show_cheatsheet("sql")

        output_text = output.getvalue()
        assert 'sql-injection-basic' in output_text or 'Found' in output_text

    def test_show_not_found(self):
        """
        BV: Not found shows helpful message

        Scenario:
          Given: Non-existent cheatsheet ID
          When: show_cheatsheet() is called
          Then: Error and available cheatsheets shown
        """
        from crack.reference.cli.cheatsheet import CheatsheetCLI

        mock_cheatsheet_registry = Mock()
        mock_cheatsheet_registry.get_cheatsheet.return_value = None
        mock_cheatsheet_registry.cheatsheets = {}
        mock_cheatsheet_registry.search_cheatsheets.return_value = []

        mock_theme = ThemeFactory.create_mock()
        cli = CheatsheetCLI(
            cheatsheet_registry=mock_cheatsheet_registry,
            theme=mock_theme
        )

        output = StringIO()
        with patch('sys.stdout', output):
            cli.show_cheatsheet("nonexistent")

        output_text = output.getvalue()
        assert 'No cheatsheets found' in output_text

    def test_show_numeric_selection(self):
        """
        BV: Numeric suffix selects from results

        Scenario:
          Given: Multiple matching cheatsheets
          When: show_cheatsheet("sql 1") is called
          Then: First match is shown
        """
        from crack.reference.cli.cheatsheet import CheatsheetCLI

        sheets = {
            "sql-1": CheatsheetFactory.create(id="sql-1", name="SQL Basic"),
            "sql-2": CheatsheetFactory.create(id="sql-2", name="SQL Advanced")
        }

        mock_cheatsheet_registry = Mock()
        mock_cheatsheet_registry.get_cheatsheet.return_value = None
        mock_cheatsheet_registry.cheatsheets = sheets
        mock_cheatsheet_registry.search_cheatsheets.return_value = []

        mock_command_registry = RegistryFactory.create_mock()
        mock_theme = ThemeFactory.create_mock()

        cli = CheatsheetCLI(
            cheatsheet_registry=mock_cheatsheet_registry,
            command_registry=mock_command_registry,
            theme=mock_theme
        )

        output = StringIO()
        with patch('sys.stdout', output):
            cli.show_cheatsheet("sql 1")

        output_text = output.getvalue()
        # Should show first match or "Selected" message
        assert 'sql-1' in output_text or 'Selected' in output_text


class TestCheatsheetDisplay:
    """Tests for cheatsheet content display"""

    def test_displays_educational_header(self):
        """
        BV: Display includes educational context

        Scenario:
          Given: Cheatsheet with educational header
          When: Displayed
          Then: How to recognize and when to look sections shown
        """
        from crack.reference.cli.cheatsheet import CheatsheetCLI

        sheet = CheatsheetFactory.create(id="test-sheet")

        mock_cheatsheet_registry = Mock()
        mock_cheatsheet_registry.get_cheatsheet.return_value = sheet

        mock_command_registry = RegistryFactory.create_mock()
        mock_theme = ThemeFactory.create_mock()

        cli = CheatsheetCLI(
            cheatsheet_registry=mock_cheatsheet_registry,
            command_registry=mock_command_registry,
            theme=mock_theme
        )

        output = StringIO()
        with patch('sys.stdout', output):
            cli.show_cheatsheet("test-sheet")

        output_text = output.getvalue()
        assert 'HOW TO RECOGNIZE' in output_text
        assert 'WHEN TO LOOK' in output_text

    def test_displays_scenarios(self):
        """
        BV: Display includes real-world scenarios

        Scenario:
          Given: Cheatsheet with scenarios
          When: Displayed
          Then: Scenarios are shown with context
        """
        from crack.reference.cli.cheatsheet import CheatsheetCLI

        sheet = CheatsheetFactory.create(
            id="test-sheet",
            scenarios=[
                MockScenario(
                    title="Web App Scenario",
                    context="You found a web form",
                    approach="Test for injection",
                    expected_outcome="SQL error returned",
                    why_this_works="Input not sanitized"
                )
            ]
        )

        mock_cheatsheet_registry = Mock()
        mock_cheatsheet_registry.get_cheatsheet.return_value = sheet

        mock_command_registry = RegistryFactory.create_mock()
        mock_theme = ThemeFactory.create_mock()

        cli = CheatsheetCLI(
            cheatsheet_registry=mock_cheatsheet_registry,
            command_registry=mock_command_registry,
            theme=mock_theme
        )

        output = StringIO()
        with patch('sys.stdout', output):
            cli.show_cheatsheet("test-sheet")

        output_text = output.getvalue()
        assert 'SCENARIOS' in output_text
        assert 'Web App Scenario' in output_text

    def test_displays_command_sections(self):
        """
        BV: Display shows command sections with numbering

        Scenario:
          Given: Cheatsheet with command sections
          When: Displayed
          Then: Sections and commands are numbered
        """
        from crack.reference.cli.cheatsheet import CheatsheetCLI

        sheet = CheatsheetFactory.create(
            id="test-sheet",
            sections=[
                MockSection(
                    title="Enumeration",
                    notes="Start with enumeration",
                    commands=["nmap-full-tcp", "gobuster-dir"]
                )
            ]
        )

        mock_cheatsheet_registry = Mock()
        mock_cheatsheet_registry.get_cheatsheet.return_value = sheet

        mock_command_registry = RegistryFactory.create_mock()
        mock_theme = ThemeFactory.create_mock()

        cli = CheatsheetCLI(
            cheatsheet_registry=mock_cheatsheet_registry,
            command_registry=mock_command_registry,
            theme=mock_theme
        )

        output = StringIO()
        with patch('sys.stdout', output):
            cli.show_cheatsheet("test-sheet")

        output_text = output.getvalue()
        assert 'ENUMERATION' in output_text
        assert '1.' in output_text

    def test_resolves_command_references(self):
        """
        BV: Command IDs are resolved to full commands

        Scenario:
          Given: Cheatsheet with command IDs
          When: Displayed
          Then: Full command details are shown
        """
        from crack.reference.cli.cheatsheet import CheatsheetCLI

        sheet = CheatsheetFactory.create(
            id="test-sheet",
            sections=[
                MockSection(
                    title="Commands",
                    notes="Test",
                    commands=["nmap-full-tcp"]
                )
            ]
        )

        mock_cheatsheet_registry = Mock()
        mock_cheatsheet_registry.get_cheatsheet.return_value = sheet

        test_cmd = CommandFactory.create(
            id="nmap-full-tcp",
            name="Nmap Full TCP",
            command="nmap -p- -T4 <TARGET>"
        )
        mock_command_registry = Mock()
        mock_command_registry.get_command.return_value = test_cmd

        mock_theme = ThemeFactory.create_mock()

        cli = CheatsheetCLI(
            cheatsheet_registry=mock_cheatsheet_registry,
            command_registry=mock_command_registry,
            theme=mock_theme
        )

        output = StringIO()
        with patch('sys.stdout', output):
            cli.show_cheatsheet("test-sheet")

        output_text = output.getvalue()
        assert 'Nmap Full TCP' in output_text
        assert 'nmap -p-' in output_text


class TestFillCommand:
    """Tests for fill_command functionality"""

    def test_fill_specific_command(self):
        """
        BV: Fill specific command by number

        Scenario:
          Given: Cheatsheet with commands
          When: fill_command(sheet_id, 1) is called
          Then: First command is interactively filled
        """
        from crack.reference.cli.cheatsheet import CheatsheetCLI

        sheet = CheatsheetFactory.create(
            id="test-sheet",
            sections=[
                MockSection(commands=["nmap-full-tcp", "gobuster-dir"])
            ]
        )

        mock_cheatsheet_registry = Mock()
        mock_cheatsheet_registry.get_cheatsheet.return_value = sheet

        test_cmd = CommandFactory.create(id="nmap-full-tcp", command="nmap -p- <TARGET>")

        mock_command_registry = Mock()
        mock_command_registry.get_command.return_value = test_cmd
        mock_command_registry.interactive_fill.return_value = "nmap -p- 192.168.1.1"

        mock_theme = ThemeFactory.create_mock()

        cli = CheatsheetCLI(
            cheatsheet_registry=mock_cheatsheet_registry,
            command_registry=mock_command_registry,
            theme=mock_theme
        )

        output = StringIO()
        with patch('sys.stdout', output):
            cli.fill_command("test-sheet", 1)

        output_text = output.getvalue()
        assert 'nmap -p- 192.168.1.1' in output_text
        mock_command_registry.interactive_fill.assert_called_once()

    def test_fill_invalid_command_number(self):
        """
        BV: Invalid command number shows error

        Scenario:
          Given: Cheatsheet with 2 commands
          When: fill_command(sheet_id, 5) is called
          Then: Error message about invalid number
        """
        from crack.reference.cli.cheatsheet import CheatsheetCLI

        sheet = CheatsheetFactory.create(
            id="test-sheet",
            sections=[
                MockSection(commands=["cmd-1", "cmd-2"])
            ]
        )

        mock_cheatsheet_registry = Mock()
        mock_cheatsheet_registry.get_cheatsheet.return_value = sheet

        mock_theme = ThemeFactory.create_mock()
        cli = CheatsheetCLI(
            cheatsheet_registry=mock_cheatsheet_registry,
            theme=mock_theme
        )

        output = StringIO()
        with patch('sys.stdout', output):
            cli.fill_command("test-sheet", 5)

        output_text = output.getvalue()
        assert 'Invalid command number' in output_text

    def test_fill_command_not_found(self):
        """
        BV: Command not in registry shows error

        Scenario:
          Given: Cheatsheet with non-existent command
          When: fill_command() is called
          Then: Error about command not found
        """
        from crack.reference.cli.cheatsheet import CheatsheetCLI

        sheet = CheatsheetFactory.create(
            id="test-sheet",
            sections=[
                MockSection(commands=["nonexistent-cmd"])
            ]
        )

        mock_cheatsheet_registry = Mock()
        mock_cheatsheet_registry.get_cheatsheet.return_value = sheet

        mock_command_registry = Mock()
        mock_command_registry.get_command.return_value = None

        mock_theme = ThemeFactory.create_mock()

        cli = CheatsheetCLI(
            cheatsheet_registry=mock_cheatsheet_registry,
            command_registry=mock_command_registry,
            theme=mock_theme
        )

        output = StringIO()
        with patch('sys.stdout', output):
            cli.fill_command("test-sheet", 1)

        output_text = output.getvalue()
        assert 'not found' in output_text


class TestFillAllCommands:
    """Tests for fill_all_commands functionality"""

    def test_fill_all_commands_sequentially(self):
        """
        BV: Fill all fills each command in order

        Scenario:
          Given: Cheatsheet with multiple commands
          When: fill_all_commands() is called
          Then: Each command is filled sequentially
        """
        from crack.reference.cli.cheatsheet import CheatsheetCLI

        sheet = CheatsheetFactory.create(
            id="test-sheet",
            sections=[
                MockSection(commands=["cmd-1", "cmd-2"])
            ]
        )

        mock_cheatsheet_registry = Mock()
        mock_cheatsheet_registry.get_cheatsheet.return_value = sheet

        test_cmd = CommandFactory.create(id="cmd-1", command="test <VAR>")

        mock_command_registry = Mock()
        mock_command_registry.get_command.return_value = test_cmd
        mock_command_registry.interactive_fill.return_value = "test value"

        mock_theme = ThemeFactory.create_mock()

        cli = CheatsheetCLI(
            cheatsheet_registry=mock_cheatsheet_registry,
            command_registry=mock_command_registry,
            theme=mock_theme
        )

        output = StringIO()
        with patch('sys.stdout', output):
            cli.fill_all_commands("test-sheet")

        # Should call interactive_fill twice
        assert mock_command_registry.interactive_fill.call_count == 2

    def test_fill_all_shows_summary(self):
        """
        BV: Fill all shows copy-paste summary

        Scenario:
          Given: Successfully filled commands
          When: fill_all_commands() completes
          Then: Summary with all filled commands shown
        """
        from crack.reference.cli.cheatsheet import CheatsheetCLI

        sheet = CheatsheetFactory.create(
            id="test-sheet",
            sections=[
                MockSection(commands=["cmd-1"])
            ]
        )

        mock_cheatsheet_registry = Mock()
        mock_cheatsheet_registry.get_cheatsheet.return_value = sheet

        test_cmd = CommandFactory.create(id="cmd-1")

        mock_command_registry = Mock()
        mock_command_registry.get_command.return_value = test_cmd
        mock_command_registry.interactive_fill.return_value = "filled command"

        mock_theme = ThemeFactory.create_mock()

        cli = CheatsheetCLI(
            cheatsheet_registry=mock_cheatsheet_registry,
            command_registry=mock_command_registry,
            theme=mock_theme
        )

        output = StringIO()
        with patch('sys.stdout', output):
            cli.fill_all_commands("test-sheet")

        output_text = output.getvalue()
        assert 'copy-paste' in output_text.lower() or 'ALL COMMANDS' in output_text


class TestTextWrapping:
    """Tests for text wrapping functionality"""

    def test_wrap_text_preserves_newlines(self):
        """
        BV: Text wrapping preserves intentional line breaks

        Scenario:
          Given: Text with newline characters
          When: _wrap_text() is called
          Then: Newlines are preserved
        """
        from crack.reference.cli.cheatsheet import CheatsheetCLI

        mock_theme = ThemeFactory.create_mock()
        cli = CheatsheetCLI(cheatsheet_registry=Mock(), theme=mock_theme)

        text = "Line one\nLine two\nLine three"
        result = cli._wrap_text(text, 50)

        # Should have 3 lines
        assert len(result) >= 3

    def test_wrap_text_handles_long_lines(self):
        """
        BV: Long lines are wrapped appropriately

        Scenario:
          Given: Very long text
          When: _wrap_text() is called with width=50
          Then: Lines are wrapped at width
        """
        from crack.reference.cli.cheatsheet import CheatsheetCLI

        mock_theme = ThemeFactory.create_mock()
        cli = CheatsheetCLI(cheatsheet_registry=Mock(), theme=mock_theme)

        text = "This is a very long line that should be wrapped because it exceeds the maximum width"
        result = cli._wrap_text(text, 30)

        # Should have multiple lines
        assert len(result) > 1


class TestCollectAllCommands:
    """Tests for _collect_all_commands helper"""

    def test_collects_from_all_sections(self):
        """
        BV: Commands collected from all sections

        Scenario:
          Given: Cheatsheet with multiple sections
          When: _collect_all_commands() is called
          Then: All commands are collected in order
        """
        from crack.reference.cli.cheatsheet import CheatsheetCLI

        sheet = CheatsheetFactory.create(
            id="test-sheet",
            sections=[
                MockSection(commands=["cmd-1", "cmd-2"]),
                MockSection(commands=["cmd-3"])
            ]
        )

        mock_theme = ThemeFactory.create_mock()
        cli = CheatsheetCLI(cheatsheet_registry=Mock(), theme=mock_theme)

        result = cli._collect_all_commands(sheet)

        assert result == ["cmd-1", "cmd-2", "cmd-3"]

    def test_handles_dict_command_format(self):
        """
        BV: Handles both string and dict command formats

        Scenario:
          Given: Section with dict-style commands
          When: _collect_all_commands() is called
          Then: Command IDs are extracted
        """
        from crack.reference.cli.cheatsheet import CheatsheetCLI

        sheet = CheatsheetFactory.create(
            id="test-sheet",
            sections=[
                MockSection(commands=[
                    {"id": "cmd-1", "example": "filled example"},
                    "cmd-2"
                ])
            ]
        )

        mock_theme = ThemeFactory.create_mock()
        cli = CheatsheetCLI(cheatsheet_registry=Mock(), theme=mock_theme)

        result = cli._collect_all_commands(sheet)

        assert "cmd-1" in result
        assert "cmd-2" in result


class TestResolveCheatsheetId:
    """Tests for _resolve_cheatsheet_id helper"""

    def test_exact_match_returns_immediately(self):
        """
        BV: Exact ID match returns cheatsheet directly

        Scenario:
          Given: Exact cheatsheet ID
          When: _resolve_cheatsheet_id() is called
          Then: Cheatsheet is returned without search
        """
        from crack.reference.cli.cheatsheet import CheatsheetCLI

        sheet = CheatsheetFactory.create(id="exact-id")

        mock_registry = Mock()
        mock_registry.get_cheatsheet.return_value = sheet

        mock_theme = ThemeFactory.create_mock()
        cli = CheatsheetCLI(cheatsheet_registry=mock_registry, theme=mock_theme)

        result = cli._resolve_cheatsheet_id("exact-id")

        assert result == sheet

    def test_partial_match_shows_list(self):
        """
        BV: Partial match shows list, doesn't auto-select

        Scenario:
          Given: Partial ID matching multiple
          When: _resolve_cheatsheet_id() is called
          Then: List is shown, None returned
        """
        from crack.reference.cli.cheatsheet import CheatsheetCLI

        sheets = {
            "sql-basic": CheatsheetFactory.create(id="sql-basic"),
            "sql-advanced": CheatsheetFactory.create(id="sql-advanced")
        }

        mock_registry = Mock()
        mock_registry.get_cheatsheet.return_value = None
        mock_registry.cheatsheets = sheets
        mock_registry.search_cheatsheets.return_value = []

        mock_theme = ThemeFactory.create_mock()
        cli = CheatsheetCLI(cheatsheet_registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            result = cli._resolve_cheatsheet_id("sql")

        # Should return None (user needs to be more specific)
        assert result is None
        # Should show matches
        assert 'sql-basic' in output.getvalue() or 'Found' in output.getvalue()


class TestEdgeCases:
    """Tests for edge cases"""

    def test_cheatsheet_with_empty_sections(self):
        """
        BV: Handle cheatsheet with empty sections

        Scenario:
          Given: Cheatsheet with no commands
          When: Displayed
          Then: No error occurs
        """
        from crack.reference.cli.cheatsheet import CheatsheetCLI

        sheet = CheatsheetFactory.create(
            id="empty-sheet",
            sections=[]
        )

        mock_cheatsheet_registry = Mock()
        mock_cheatsheet_registry.get_cheatsheet.return_value = sheet

        mock_theme = ThemeFactory.create_mock()
        cli = CheatsheetCLI(
            cheatsheet_registry=mock_cheatsheet_registry,
            theme=mock_theme
        )

        output = StringIO()
        with patch('sys.stdout', output):
            cli.show_cheatsheet("empty-sheet")

        # Should not raise
        assert 'empty-sheet' in output.getvalue() or len(output.getvalue()) > 0

    def test_keyboard_interrupt_during_fill(self):
        """
        BV: Ctrl+C during fill cancels gracefully

        Scenario:
          Given: Interactive fill in progress
          When: User presses Ctrl+C
          Then: Cancellation message shown
        """
        from crack.reference.cli.cheatsheet import CheatsheetCLI

        sheet = CheatsheetFactory.create(
            id="test-sheet",
            sections=[MockSection(commands=["cmd-1"])]
        )

        mock_cheatsheet_registry = Mock()
        mock_cheatsheet_registry.get_cheatsheet.return_value = sheet

        test_cmd = CommandFactory.create(id="cmd-1")

        mock_command_registry = Mock()
        mock_command_registry.get_command.return_value = test_cmd
        mock_command_registry.interactive_fill.side_effect = KeyboardInterrupt()

        mock_theme = ThemeFactory.create_mock()

        cli = CheatsheetCLI(
            cheatsheet_registry=mock_cheatsheet_registry,
            command_registry=mock_command_registry,
            theme=mock_theme
        )

        output = StringIO()
        with patch('sys.stdout', output):
            cli.fill_command("test-sheet", 1)

        assert 'Cancelled' in output.getvalue()
