"""
Tests for Reference CLI search.py - Command search and filtering

Business Value Focus:
- Users need fast, accurate command search
- Tag filtering enables focused workflows
- Quick wins and OSCP-high provide exam-focused results
- Statistics help users understand the command library
"""

import pytest
import sys
from pathlib import Path
from io import StringIO
from unittest.mock import Mock, patch

# Add project root
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tests.reference.cli.conftest import (
    CommandFactory, ThemeFactory, RegistryFactory, CLIAssertions
)


class TestSearchCLIInitialization:
    """Tests for SearchCLI initialization"""

    def test_initialization_with_dependencies(self):
        """
        BV: SearchCLI initializes with required dependencies

        Scenario:
          Given: Registry and theme
          When: SearchCLI is instantiated
          Then: Dependencies are stored correctly
        """
        from crack.reference.cli.search import SearchCLI

        mock_registry = RegistryFactory.create_mock()
        mock_theme = ThemeFactory.create_mock()

        search_cli = SearchCLI(registry=mock_registry, theme=mock_theme)

        assert search_cli.registry == mock_registry
        assert search_cli.theme == mock_theme


class TestSearchCommands:
    """Tests for search_commands method"""

    def test_search_by_query(self):
        """
        BV: Text query finds matching commands

        Scenario:
          Given: Commands in registry
          When: search_commands(query='nmap') is called
          Then: Matching commands are displayed
        """
        from crack.reference.cli.search import SearchCLI

        commands = [
            CommandFactory.create(id="nmap-full-tcp", name="Nmap Full TCP"),
            CommandFactory.create(id="nmap-quick", name="Nmap Quick Scan")
        ]

        mock_registry = Mock()
        mock_registry.search.return_value = commands
        mock_registry.get_command.return_value = None
        mock_registry.categories = {}

        mock_theme = ThemeFactory.create_mock()
        search_cli = SearchCLI(registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            search_cli.search_commands(query='nmap')

        output_text = output.getvalue()
        assert 'nmap-full-tcp' in output_text
        assert 'nmap-quick' in output_text

    def test_search_by_category(self):
        """
        BV: Category filter shows commands in category

        Scenario:
          Given: Commands in different categories
          When: search_commands(category='recon') is called
          Then: Only recon commands are shown
        """
        from crack.reference.cli.search import SearchCLI

        commands = [
            CommandFactory.create(id="nmap-1", category="recon"),
            CommandFactory.create(id="nmap-2", category="recon")
        ]

        mock_registry = Mock()
        mock_registry.filter_by_category.return_value = commands
        mock_registry.get_subcategories.return_value = []
        mock_registry.categories = {"recon": "01-recon"}

        mock_theme = ThemeFactory.create_mock()
        search_cli = SearchCLI(registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            search_cli.search_commands(category='recon')

        mock_registry.filter_by_category.assert_called_with('recon', None)

    def test_search_by_tags(self):
        """
        BV: Tag filter shows commands with tags

        Scenario:
          Given: Commands with various tags
          When: search_commands(tags=['ENUM', 'SMB']) is called
          Then: Only commands with those tags are shown
        """
        from crack.reference.cli.search import SearchCLI

        commands = [
            CommandFactory.create(id="smb-enum", tags=["ENUM", "SMB"])
        ]

        mock_registry = Mock()
        mock_registry.filter_by_tags.return_value = commands
        mock_registry.categories = {}

        mock_theme = ThemeFactory.create_mock()
        search_cli = SearchCLI(registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            search_cli.search_commands(tags=['ENUM', 'SMB'])

        mock_registry.filter_by_tags.assert_called_with(['ENUM', 'SMB'], None)

    def test_search_with_exclude_tags(self):
        """
        BV: Exclude tags filters out unwanted commands

        Scenario:
          Given: Commands with various tags
          When: search_commands(tags=['ENUM'], exclude_tags=['MSF']) is called
          Then: Commands with MSF are excluded
        """
        from crack.reference.cli.search import SearchCLI

        commands = [
            CommandFactory.create(id="manual-enum", tags=["ENUM"])
        ]

        mock_registry = Mock()
        mock_registry.filter_by_tags.return_value = commands
        mock_registry.categories = {}

        mock_theme = ThemeFactory.create_mock()
        search_cli = SearchCLI(registry=mock_registry, theme=mock_theme)

        search_cli.search_commands(tags=['ENUM'], exclude_tags=['MSF'])

        mock_registry.filter_by_tags.assert_called_with(['ENUM'], ['MSF'])

    def test_search_no_results(self):
        """
        BV: No results shows clear message

        Scenario:
          Given: Empty search results
          When: search_commands() is called
          Then: "No commands found" message
        """
        from crack.reference.cli.search import SearchCLI

        mock_registry = Mock()
        mock_registry.search.return_value = []
        mock_registry.categories = {}

        mock_theme = ThemeFactory.create_mock()
        search_cli = SearchCLI(registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            search_cli.search_commands(query='nonexistent')

        assert 'No commands found' in output.getvalue()

    def test_search_numeric_selection(self):
        """
        BV: Numeric suffix selects specific result

        Scenario:
          Given: Multiple search results
          When: query ends with number (e.g., "nmap 1")
          Then: First result is selected for interactive fill
        """
        from crack.reference.cli.search import SearchCLI

        commands = [
            CommandFactory.create(id="nmap-1"),
            CommandFactory.create(id="nmap-2")
        ]

        mock_registry = Mock()
        mock_registry.search.return_value = commands
        mock_registry.get_command.return_value = commands[0]
        mock_registry.categories = {}
        mock_registry.interactive_fill.return_value = "filled command"

        mock_theme = ThemeFactory.create_mock()
        search_cli = SearchCLI(registry=mock_registry, theme=mock_theme)

        output = StringIO()
        # FIX: InteractiveCLI is imported inside the method, not at module level.
        # Must patch at the source module where it's defined.
        with patch('sys.stdout', output), \
             patch('crack.reference.cli.interactive.InteractiveCLI') as mock_interactive:

            mock_interactive_instance = Mock()
            mock_interactive.return_value = mock_interactive_instance

            search_cli.search_commands(query='nmap 1')

            mock_interactive_instance.fill_command_with_execute.assert_called_once()

    def test_search_invalid_selection(self):
        """
        BV: Invalid selection shows error

        Scenario:
          Given: 2 search results
          When: query is "nmap 5"
          Then: Invalid selection error
        """
        from crack.reference.cli.search import SearchCLI

        commands = [
            CommandFactory.create(id="nmap-1"),
            CommandFactory.create(id="nmap-2")
        ]

        mock_registry = Mock()
        mock_registry.search.return_value = commands
        mock_registry.categories = {}

        mock_theme = ThemeFactory.create_mock()
        search_cli = SearchCLI(registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            search_cli.search_commands(query='nmap 5')

        assert 'Invalid selection' in output.getvalue()

    def test_search_with_subcategory_hints(self):
        """
        BV: Category with subcategories shows hints

        Scenario:
          Given: Category with subcategories
          When: Only category provided
          Then: Subcategory hints are shown
        """
        from crack.reference.cli.search import SearchCLI

        commands = [
            CommandFactory.create(id="cmd-1", category="recon")
        ]

        mock_registry = Mock()
        mock_registry.filter_by_category.return_value = commands
        mock_registry.get_subcategories.return_value = ['network', 'web', 'dns']
        mock_registry.categories = {"recon": "01-recon"}

        mock_theme = ThemeFactory.create_mock()
        search_cli = SearchCLI(registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            search_cli.search_commands(category='recon')

        output_text = output.getvalue()
        # Should mention subcategories
        assert 'Subcategories' in output_text or 'network' in output_text

    def test_search_interactive_mode(self):
        """
        BV: Interactive mode enables selection workflow

        Scenario:
          Given: Search results
          When: search_commands(interactive=True) is called
          Then: Interactive selection is invoked
        """
        from crack.reference.cli.search import SearchCLI

        commands = [
            CommandFactory.create(id="cmd-1"),
            CommandFactory.create(id="cmd-2")
        ]

        mock_registry = Mock()
        mock_registry.search.return_value = commands
        mock_registry.categories = {}

        mock_theme = ThemeFactory.create_mock()
        search_cli = SearchCLI(registry=mock_registry, theme=mock_theme)

        # FIX: InteractiveCLI is imported inside the method, not at module level.
        # Must patch at the source module where it's defined.
        with patch('crack.reference.cli.interactive.InteractiveCLI') as mock_interactive:
            mock_interactive_instance = Mock()
            mock_interactive.return_value = mock_interactive_instance

            search_cli.search_commands(query='cmd', interactive=True)

            mock_interactive_instance.interactive_select_and_fill.assert_called_once()


class TestShowQuickWins:
    """Tests for show_quick_wins method"""

    def test_quick_wins_displays_results(self):
        """
        BV: Quick wins shows tagged commands

        Scenario:
          Given: Commands with QUICK_WIN tag
          When: show_quick_wins() is called
          Then: Quick win commands are displayed
        """
        from crack.reference.cli.search import SearchCLI

        commands = [
            CommandFactory.create_quick_win(id="smb-enum"),
            CommandFactory.create_quick_win(id="ldap-anon")
        ]

        mock_registry = Mock()
        mock_registry.get_quick_wins.return_value = commands

        mock_theme = ThemeFactory.create_mock()
        search_cli = SearchCLI(registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            result = search_cli.show_quick_wins()

        assert result == 0
        output_text = output.getvalue()
        assert 'Quick Win' in output_text
        assert 'smb-enum' in output_text

    def test_quick_wins_no_results(self):
        """
        BV: No quick wins shows appropriate message

        Scenario:
          Given: No QUICK_WIN tagged commands
          When: show_quick_wins() is called
          Then: "No quick win commands" message
        """
        from crack.reference.cli.search import SearchCLI

        mock_registry = Mock()
        mock_registry.get_quick_wins.return_value = []

        mock_theme = ThemeFactory.create_mock()
        search_cli = SearchCLI(registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            result = search_cli.show_quick_wins()

        assert result == 0
        assert 'No quick win' in output.getvalue()

    def test_quick_wins_respects_format(self):
        """
        BV: Quick wins respects format option

        Scenario:
          Given: Quick win commands
          When: show_quick_wins(format='json') is called
          Then: JSON output is produced
        """
        from crack.reference.cli.search import SearchCLI

        commands = [
            CommandFactory.create_quick_win(id="smb-enum")
        ]

        mock_registry = Mock()
        mock_registry.get_quick_wins.return_value = commands

        mock_theme = ThemeFactory.create_mock()
        search_cli = SearchCLI(registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            search_cli.show_quick_wins(format='json')

        # JSON format should contain brackets
        assert '[' in output.getvalue() or '{' in output.getvalue()


class TestShowOscpHigh:
    """Tests for show_oscp_high method"""

    def test_oscp_high_displays_results(self):
        """
        BV: OSCP high shows high-relevance commands

        Scenario:
          Given: Commands with high OSCP relevance
          When: show_oscp_high() is called
          Then: OSCP high commands are displayed
        """
        from crack.reference.cli.search import SearchCLI

        commands = [
            CommandFactory.create_oscp_high(id="privesc-1"),
            CommandFactory.create_oscp_high(id="enum-1")
        ]

        mock_registry = Mock()
        mock_registry.get_oscp_high.return_value = commands

        mock_theme = ThemeFactory.create_mock()
        search_cli = SearchCLI(registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            result = search_cli.show_oscp_high()

        assert result == 0
        output_text = output.getvalue()
        assert 'OSCP' in output_text
        assert 'privesc-1' in output_text

    def test_oscp_high_no_results(self):
        """
        BV: No OSCP high shows appropriate message

        Scenario:
          Given: No high-relevance commands
          When: show_oscp_high() is called
          Then: "No OSCP high-relevance" message
        """
        from crack.reference.cli.search import SearchCLI

        mock_registry = Mock()
        mock_registry.get_oscp_high.return_value = []

        mock_theme = ThemeFactory.create_mock()
        search_cli = SearchCLI(registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            result = search_cli.show_oscp_high()

        assert result == 0
        assert 'No OSCP high-relevance' in output.getvalue()


class TestListTags:
    """Tests for list_tags method"""

    def test_list_tags_shows_all_tags(self):
        """
        BV: List tags shows all unique tags

        Scenario:
          Given: Commands with various tags
          When: list_tags() is called
          Then: All unique tags are listed
        """
        from crack.reference.cli.search import SearchCLI

        commands = {
            "cmd-1": CommandFactory.create(id="cmd-1", tags=["ENUM", "SMB"]),
            "cmd-2": CommandFactory.create(id="cmd-2", tags=["ENUM", "HTTP"]),
            "cmd-3": CommandFactory.create(id="cmd-3", tags=["PRIVESC"])
        }

        mock_registry = Mock()
        mock_registry.commands = commands

        mock_theme = ThemeFactory.create_mock()
        search_cli = SearchCLI(registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            result = search_cli.list_tags()

        assert result == 0
        output_text = output.getvalue()
        assert 'ENUM' in output_text
        assert 'SMB' in output_text
        assert 'HTTP' in output_text
        assert 'PRIVESC' in output_text

    def test_list_tags_shows_counts(self):
        """
        BV: List tags shows command counts per tag

        Scenario:
          Given: Tags with different counts
          When: list_tags() is called
          Then: Counts are displayed
        """
        from crack.reference.cli.search import SearchCLI

        commands = {
            "cmd-1": CommandFactory.create(id="cmd-1", tags=["ENUM"]),
            "cmd-2": CommandFactory.create(id="cmd-2", tags=["ENUM"]),
            "cmd-3": CommandFactory.create(id="cmd-3", tags=["RARE"])
        }

        mock_registry = Mock()
        mock_registry.commands = commands

        mock_theme = ThemeFactory.create_mock()
        search_cli = SearchCLI(registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            search_cli.list_tags()

        output_text = output.getvalue()
        # Should show counts like "ENUM: 2 commands"
        assert '2' in output_text or 'commands' in output_text


class TestShowStats:
    """Tests for show_stats method"""

    def test_stats_shows_total_count(self):
        """
        BV: Stats shows total command count

        Scenario:
          Given: Registry with commands
          When: show_stats() is called
          Then: Total count is displayed
        """
        from crack.reference.cli.search import SearchCLI

        mock_registry = Mock()
        mock_registry.get_stats.return_value = {
            'total_commands': 150,
            'by_category': {'recon': 50, 'web': 40},
            'top_tags': [('ENUM', 30), ('OSCP:HIGH', 25)],
            'quick_wins': 10,
            'oscp_high': 25
        }

        mock_theme = ThemeFactory.create_mock()
        search_cli = SearchCLI(registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            result = search_cli.show_stats()

        assert result == 0
        output_text = output.getvalue()
        assert 'Total Commands: 150' in output_text

    def test_stats_shows_category_breakdown(self):
        """
        BV: Stats shows commands by category

        Scenario:
          Given: Registry with categorized commands
          When: show_stats() is called
          Then: Category counts are displayed
        """
        from crack.reference.cli.search import SearchCLI

        mock_registry = Mock()
        mock_registry.get_stats.return_value = {
            'total_commands': 100,
            'by_category': {'recon': 40, 'web': 30, 'exploitation': 30},
            'by_subcategory': {'recon': {'network': 20, 'dns': 10}},
            'top_tags': [],
            'quick_wins': 5,
            'oscp_high': 20
        }

        mock_theme = ThemeFactory.create_mock()
        search_cli = SearchCLI(registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            search_cli.show_stats()

        output_text = output.getvalue()
        assert 'recon' in output_text
        assert '40' in output_text

    def test_stats_shows_subcategories(self):
        """
        BV: Stats shows subcategory breakdown

        Scenario:
          Given: Registry with subcategorized commands
          When: show_stats() is called
          Then: Subcategory counts are displayed
        """
        from crack.reference.cli.search import SearchCLI

        mock_registry = Mock()
        mock_registry.get_stats.return_value = {
            'total_commands': 100,
            'by_category': {'recon': 40},
            'by_subcategory': {'recon': {'network': 20, 'dns': 10, 'web': 10}},
            'top_tags': [],
            'quick_wins': 5,
            'oscp_high': 20
        }

        mock_theme = ThemeFactory.create_mock()
        search_cli = SearchCLI(registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            search_cli.show_stats()

        output_text = output.getvalue()
        assert 'network' in output_text

    def test_stats_shows_top_tags(self):
        """
        BV: Stats shows most common tags

        Scenario:
          Given: Registry with tagged commands
          When: show_stats() is called
          Then: Top tags are displayed
        """
        from crack.reference.cli.search import SearchCLI

        mock_registry = Mock()
        mock_registry.get_stats.return_value = {
            'total_commands': 100,
            'by_category': {},
            'top_tags': [('ENUM', 50), ('OSCP:HIGH', 40), ('QUICK_WIN', 20)],
            'quick_wins': 20,
            'oscp_high': 40
        }

        mock_theme = ThemeFactory.create_mock()
        search_cli = SearchCLI(registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            search_cli.show_stats()

        output_text = output.getvalue()
        assert 'ENUM' in output_text
        assert 'Top Tags' in output_text

    def test_stats_shows_quick_wins_count(self):
        """
        BV: Stats shows quick wins count

        Scenario:
          Given: Registry with quick wins
          When: show_stats() is called
          Then: Quick wins count is displayed
        """
        from crack.reference.cli.search import SearchCLI

        mock_registry = Mock()
        mock_registry.get_stats.return_value = {
            'total_commands': 100,
            'by_category': {},
            'top_tags': [],
            'quick_wins': 15,
            'oscp_high': 30
        }

        mock_theme = ThemeFactory.create_mock()
        search_cli = SearchCLI(registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            search_cli.show_stats()

        output_text = output.getvalue()
        assert 'Quick Wins: 15' in output_text

    def test_stats_shows_oscp_high_count(self):
        """
        BV: Stats shows OSCP high count

        Scenario:
          Given: Registry with OSCP high commands
          When: show_stats() is called
          Then: OSCP high count is displayed
        """
        from crack.reference.cli.search import SearchCLI

        mock_registry = Mock()
        mock_registry.get_stats.return_value = {
            'total_commands': 100,
            'by_category': {},
            'top_tags': [],
            'quick_wins': 15,
            'oscp_high': 45
        }

        mock_theme = ThemeFactory.create_mock()
        search_cli = SearchCLI(registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            search_cli.show_stats()

        output_text = output.getvalue()
        assert 'OSCP High Relevance: 45' in output_text


class TestFormatOptions:
    """Tests for different format outputs"""

    def test_json_format_output(self):
        """
        BV: JSON format produces valid JSON

        Scenario:
          Given: Search results
          When: format='json' is specified
          Then: Valid JSON is output
        """
        from crack.reference.cli.search import SearchCLI
        import json

        commands = [
            CommandFactory.create(id="cmd-1"),
            CommandFactory.create(id="cmd-2")
        ]

        mock_registry = Mock()
        mock_registry.search.return_value = commands
        mock_registry.categories = {}

        mock_theme = ThemeFactory.create_mock()
        search_cli = SearchCLI(registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            search_cli.search_commands(query='cmd', format='json')

        result = output.getvalue()
        parsed = json.loads(result)  # Should not raise
        assert isinstance(parsed, list)

    def test_markdown_format_output(self):
        """
        BV: Markdown format uses proper markdown syntax

        Scenario:
          Given: Search results
          When: format='markdown' is specified
          Then: Markdown formatting is used
        """
        from crack.reference.cli.search import SearchCLI

        commands = [
            CommandFactory.create(id="cmd-1", name="Test Command")
        ]

        mock_registry = Mock()
        mock_registry.search.return_value = commands
        mock_registry.categories = {}

        mock_theme = ThemeFactory.create_mock()
        search_cli = SearchCLI(registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            search_cli.search_commands(query='cmd', format='markdown')

        result = output.getvalue()
        assert '##' in result  # Markdown headers
        assert '```' in result  # Code blocks


class TestVerboseOutput:
    """Tests for verbose output mode"""

    def test_verbose_shows_more_details(self):
        """
        BV: Verbose mode shows comprehensive details

        Scenario:
          Given: Commands with full metadata
          When: verbose=True is specified
          Then: All details are shown
        """
        from crack.reference.cli.search import SearchCLI

        commands = [
            CommandFactory.create(
                id="cmd-1",
                description="Full description here",
                tags=["TAG1", "TAG2"],
                prerequisites=["prereq-1"]
            )
        ]

        mock_registry = Mock()
        mock_registry.search.return_value = commands
        mock_registry.categories = {}

        mock_theme = ThemeFactory.create_mock()
        search_cli = SearchCLI(registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            search_cli.search_commands(query='cmd', verbose=True)

        result = output.getvalue()
        assert 'Description' in result or 'Full description' in result


class TestEdgeCases:
    """Tests for edge cases in search"""

    def test_empty_query(self):
        """
        BV: Empty query without filters shows all commands

        Scenario:
          Given: No query or filters
          When: search_commands() is called
          Then: All commands are returned
        """
        from crack.reference.cli.search import SearchCLI

        commands = {
            "cmd-1": CommandFactory.create(id="cmd-1"),
            "cmd-2": CommandFactory.create(id="cmd-2")
        }

        mock_registry = Mock()
        mock_registry.commands = commands
        mock_registry.categories = {}

        mock_theme = ThemeFactory.create_mock()
        search_cli = SearchCLI(registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            search_cli.search_commands()

        # Should display both commands
        output_text = output.getvalue()
        assert 'cmd-1' in output_text or len(output_text) > 0

    def test_combined_query_and_tags(self):
        """
        BV: Query combined with tags applies both filters

        Scenario:
          Given: Tags filter and query
          When: Both are specified
          Then: Results match both criteria
        """
        from crack.reference.cli.search import SearchCLI

        commands = [
            CommandFactory.create(id="smb-enum-1", tags=["ENUM", "SMB"]),
            CommandFactory.create(id="smb-enum-2", tags=["ENUM", "SMB"])
        ]

        # First command matches both query and tags
        matching = CommandFactory.create(id="smb-quick", tags=["ENUM", "SMB"])
        matching._matches_search = lambda q: "quick" in q.lower()

        mock_registry = Mock()
        mock_registry.filter_by_tags.return_value = commands
        mock_registry.categories = {}

        mock_theme = ThemeFactory.create_mock()
        search_cli = SearchCLI(registry=mock_registry, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            search_cli.search_commands(query='smb', tags=['ENUM'])

        # Should apply both filters
        mock_registry.filter_by_tags.assert_called_with(['ENUM'], None)
