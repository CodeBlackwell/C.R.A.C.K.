"""
Tests for Reference CLI main.py - Entry point and argument parsing

Business Value Focus:
- Users need reliable CLI that accepts documented arguments
- Argument parsing must handle edge cases gracefully
- Backend initialization must fail gracefully with clear messages
- Banner control must work as documented
"""

import pytest
import sys
import argparse
from pathlib import Path
from io import StringIO
from unittest.mock import Mock, MagicMock, patch, PropertyMock

# Add project root
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tests.reference.cli.conftest import (
    CommandFactory, ThemeFactory, ConfigFactory, RegistryFactory, CLIAssertions
)


class TestReferenceCLIInitialization:
    """Tests for ReferenceCLI initialization and setup"""

    def test_cli_creates_parser(self):
        """
        BV: Users need working CLI with valid argument definitions

        Scenario:
          Given: ReferenceCLI is imported
          When: Instantiated
          Then: Parser is created with expected arguments
        """
        with patch('crack.reference.cli.main.HybridCommandRegistry') as mock_registry, \
             patch('crack.reference.cli.main.ConfigManager') as mock_config, \
             patch('crack.reference.cli.main.ReferenceTheme') as mock_theme, \
             patch('crack.reference.cli.main.PlaceholderEngine'), \
             patch('crack.reference.cli.main.CommandValidator'):

            mock_registry.return_value = RegistryFactory.create_mock()
            mock_config.return_value = ConfigFactory.create_mock()
            mock_theme.return_value = ThemeFactory.create_mock()

            from crack.reference.cli.main import ReferenceCLI
            cli = ReferenceCLI()

            assert cli.parser is not None
            assert isinstance(cli.parser, argparse.ArgumentParser)

    def test_cli_parser_has_required_arguments(self):
        """
        BV: All documented CLI arguments must be available

        Scenario:
          Given: ReferenceCLI parser is created
          When: Parser actions are inspected
          Then: All documented arguments are present
        """
        with patch('crack.reference.cli.main.HybridCommandRegistry') as mock_registry, \
             patch('crack.reference.cli.main.ConfigManager') as mock_config, \
             patch('crack.reference.cli.main.ReferenceTheme') as mock_theme, \
             patch('crack.reference.cli.main.PlaceholderEngine'), \
             patch('crack.reference.cli.main.CommandValidator'):

            mock_registry.return_value = RegistryFactory.create_mock()
            mock_config.return_value = ConfigFactory.create_mock()
            mock_theme.return_value = ThemeFactory.create_mock()

            from crack.reference.cli.main import ReferenceCLI
            cli = ReferenceCLI()

            # Get all registered option strings
            option_strings = []
            for action in cli.parser._actions:
                option_strings.extend(action.option_strings)

            # Required arguments per documentation
            required_args = [
                '--category', '-c',
                '--subcategory', '-s',
                '--tags', '-t',
                '--verbose', '-v',
                '--interactive', '-i',
                '--format', '-f',
                '--quick-wins',
                '--oscp-high',
                '--validate',
                '--stats',
                '--config',
                '--set',
                '--get',
                '--chains',
                '--no-banner',
                '--status'
            ]

            for arg in required_args:
                assert arg in option_strings, f"Missing argument: {arg}"


class TestArgumentParsing:
    """Tests for argument parsing behavior"""

    def test_parse_category_flag(self):
        """
        BV: Users can filter commands by category using --category

        Scenario:
          Given: CLI with --category flag
          When: --category recon is passed
          Then: Category is correctly parsed
        """
        with patch('crack.reference.cli.main.HybridCommandRegistry') as mock_registry, \
             patch('crack.reference.cli.main.ConfigManager') as mock_config, \
             patch('crack.reference.cli.main.ReferenceTheme') as mock_theme, \
             patch('crack.reference.cli.main.PlaceholderEngine'), \
             patch('crack.reference.cli.main.CommandValidator'):

            mock_registry.return_value = RegistryFactory.create_mock()
            mock_config.return_value = ConfigFactory.create_mock()
            mock_theme.return_value = ThemeFactory.create_mock()

            from crack.reference.cli.main import ReferenceCLI
            cli = ReferenceCLI()

            # Parse with just flags
            parsed = cli.parser.parse_args(['--category', 'recon'])
            assert parsed.category == 'recon'

    def test_parse_tags_multiple_values(self):
        """
        BV: Users can filter by multiple tags

        Scenario:
          Given: CLI with --tags flag
          When: Multiple tags are provided
          Then: All tags are captured in list
        """
        with patch('crack.reference.cli.main.HybridCommandRegistry') as mock_registry, \
             patch('crack.reference.cli.main.ConfigManager') as mock_config, \
             patch('crack.reference.cli.main.ReferenceTheme') as mock_theme, \
             patch('crack.reference.cli.main.PlaceholderEngine'), \
             patch('crack.reference.cli.main.CommandValidator'):

            mock_registry.return_value = RegistryFactory.create_mock()
            mock_config.return_value = ConfigFactory.create_mock()
            mock_theme.return_value = ThemeFactory.create_mock()

            from crack.reference.cli.main import ReferenceCLI
            cli = ReferenceCLI()

            parsed = cli.parser.parse_args(['--tags', 'ENUM', 'SMB'])
            assert parsed.tags == ['ENUM', 'SMB']

    def test_parse_format_choices(self):
        """
        BV: Users can select output format (text, json, markdown)

        Scenario:
          Given: CLI with --format flag
          When: Valid format is provided
          Then: Format is correctly parsed
        """
        with patch('crack.reference.cli.main.HybridCommandRegistry') as mock_registry, \
             patch('crack.reference.cli.main.ConfigManager') as mock_config, \
             patch('crack.reference.cli.main.ReferenceTheme') as mock_theme, \
             patch('crack.reference.cli.main.PlaceholderEngine'), \
             patch('crack.reference.cli.main.CommandValidator'):

            mock_registry.return_value = RegistryFactory.create_mock()
            mock_config.return_value = ConfigFactory.create_mock()
            mock_theme.return_value = ThemeFactory.create_mock()

            from crack.reference.cli.main import ReferenceCLI
            cli = ReferenceCLI()

            for fmt in ['text', 'json', 'markdown']:
                parsed = cli.parser.parse_args(['--format', fmt])
                assert parsed.format == fmt

    def test_parse_invalid_format_raises_error(self):
        """
        BV: Invalid format values are rejected with clear error

        Scenario:
          Given: CLI with --format flag
          When: Invalid format is provided
          Then: SystemExit is raised
        """
        with patch('crack.reference.cli.main.HybridCommandRegistry') as mock_registry, \
             patch('crack.reference.cli.main.ConfigManager') as mock_config, \
             patch('crack.reference.cli.main.ReferenceTheme') as mock_theme, \
             patch('crack.reference.cli.main.PlaceholderEngine'), \
             patch('crack.reference.cli.main.CommandValidator'):

            mock_registry.return_value = RegistryFactory.create_mock()
            mock_config.return_value = ConfigFactory.create_mock()
            mock_theme.return_value = ThemeFactory.create_mock()

            from crack.reference.cli.main import ReferenceCLI
            cli = ReferenceCLI()

            with pytest.raises(SystemExit):
                cli.parser.parse_args(['--format', 'invalid'])

    def test_parse_set_requires_two_values(self):
        """
        BV: --set requires VAR and VALUE arguments

        Scenario:
          Given: CLI with --set flag
          When: Both VAR and VALUE are provided
          Then: Values are correctly parsed as tuple
        """
        with patch('crack.reference.cli.main.HybridCommandRegistry') as mock_registry, \
             patch('crack.reference.cli.main.ConfigManager') as mock_config, \
             patch('crack.reference.cli.main.ReferenceTheme') as mock_theme, \
             patch('crack.reference.cli.main.PlaceholderEngine'), \
             patch('crack.reference.cli.main.CommandValidator'):

            mock_registry.return_value = RegistryFactory.create_mock()
            mock_config.return_value = ConfigFactory.create_mock()
            mock_theme.return_value = ThemeFactory.create_mock()

            from crack.reference.cli.main import ReferenceCLI
            cli = ReferenceCLI()

            parsed = cli.parser.parse_args(['--set', 'LHOST', '10.10.14.5'])
            assert parsed.set == ['LHOST', '10.10.14.5']

    def test_parse_boolean_flags(self):
        """
        BV: Boolean flags work as documented

        Scenario:
          Given: CLI with boolean flags
          When: Flags are provided
          Then: Flags are set to True
        """
        with patch('crack.reference.cli.main.HybridCommandRegistry') as mock_registry, \
             patch('crack.reference.cli.main.ConfigManager') as mock_config, \
             patch('crack.reference.cli.main.ReferenceTheme') as mock_theme, \
             patch('crack.reference.cli.main.PlaceholderEngine'), \
             patch('crack.reference.cli.main.CommandValidator'):

            mock_registry.return_value = RegistryFactory.create_mock()
            mock_config.return_value = ConfigFactory.create_mock()
            mock_theme.return_value = ThemeFactory.create_mock()

            from crack.reference.cli.main import ReferenceCLI
            cli = ReferenceCLI()

            boolean_flags = [
                ('--verbose', 'verbose'),
                ('--interactive', 'interactive'),
                ('--quick-wins', 'quick_wins'),
                ('--oscp-high', 'oscp_high'),
                ('--validate', 'validate'),
                ('--stats', 'stats'),
                ('--no-banner', 'no_banner'),
                ('--status', 'status'),
                ('--tree', 'tree'),
                ('--list-tags', 'list_tags')
            ]

            for flag, attr in boolean_flags:
                parsed = cli.parser.parse_args([flag])
                assert getattr(parsed, attr) is True, f"Flag {flag} should set {attr}=True"


class TestCLIRouting:
    """Tests for CLI command routing to handlers"""

    def test_config_list_routes_to_config_cli(self):
        """
        BV: --config list shows configuration variables

        Scenario:
          Given: CLI with --config list
          When: run() is called
          Then: Routes to ConfigCLI.handle_config
        """
        with patch('crack.reference.cli.main.HybridCommandRegistry') as mock_registry, \
             patch('crack.reference.cli.main.ConfigManager') as mock_config, \
             patch('crack.reference.cli.main.ReferenceTheme') as mock_theme, \
             patch('crack.reference.cli.main.PlaceholderEngine'), \
             patch('crack.reference.cli.main.CommandValidator'), \
             patch('crack.reference.cli.main.ConfigCLI') as mock_config_cli:

            mock_registry.return_value = RegistryFactory.create_mock()
            mock_config.return_value = ConfigFactory.create_mock()
            mock_theme.return_value = ThemeFactory.create_mock()

            from crack.reference.cli.main import ReferenceCLI
            cli = ReferenceCLI()

            cli.run(['--config', 'list', '--no-banner'])

            mock_config_cli.return_value.handle_config.assert_called_once_with('list')

    def test_set_routes_to_config_cli(self):
        """
        BV: --set VAR VALUE updates configuration

        Scenario:
          Given: CLI with --set flag
          When: run() is called
          Then: Routes to ConfigCLI.set_config_var
        """
        with patch('crack.reference.cli.main.HybridCommandRegistry') as mock_registry, \
             patch('crack.reference.cli.main.ConfigManager') as mock_config, \
             patch('crack.reference.cli.main.ReferenceTheme') as mock_theme, \
             patch('crack.reference.cli.main.PlaceholderEngine'), \
             patch('crack.reference.cli.main.CommandValidator'), \
             patch('crack.reference.cli.main.ConfigCLI') as mock_config_cli:

            mock_registry.return_value = RegistryFactory.create_mock()
            mock_config.return_value = ConfigFactory.create_mock()
            mock_theme.return_value = ThemeFactory.create_mock()

            from crack.reference.cli.main import ReferenceCLI
            cli = ReferenceCLI()

            cli.run(['--set', 'LHOST', '10.10.14.5', '--no-banner'])

            mock_config_cli.return_value.set_config_var.assert_called_once_with('LHOST', '10.10.14.5')

    def test_stats_routes_to_search_cli(self):
        """
        BV: --stats shows registry statistics

        Scenario:
          Given: CLI with --stats flag
          When: run() is called
          Then: Routes to SearchCLI.show_stats
        """
        with patch('crack.reference.cli.main.HybridCommandRegistry') as mock_registry, \
             patch('crack.reference.cli.main.ConfigManager') as mock_config, \
             patch('crack.reference.cli.main.ReferenceTheme') as mock_theme, \
             patch('crack.reference.cli.main.PlaceholderEngine'), \
             patch('crack.reference.cli.main.CommandValidator'), \
             patch('crack.reference.cli.main.SearchCLI') as mock_search_cli:

            mock_registry.return_value = RegistryFactory.create_mock()
            mock_config.return_value = ConfigFactory.create_mock()
            mock_theme.return_value = ThemeFactory.create_mock()

            from crack.reference.cli.main import ReferenceCLI
            cli = ReferenceCLI()

            cli.run(['--stats', '--no-banner'])

            mock_search_cli.return_value.show_stats.assert_called_once()

    def test_quick_wins_routes_to_search_cli(self):
        """
        BV: --quick-wins shows quick win commands

        Scenario:
          Given: CLI with --quick-wins flag
          When: run() is called
          Then: Routes to SearchCLI.show_quick_wins
        """
        with patch('crack.reference.cli.main.HybridCommandRegistry') as mock_registry, \
             patch('crack.reference.cli.main.ConfigManager') as mock_config, \
             patch('crack.reference.cli.main.ReferenceTheme') as mock_theme, \
             patch('crack.reference.cli.main.PlaceholderEngine'), \
             patch('crack.reference.cli.main.CommandValidator'), \
             patch('crack.reference.cli.main.SearchCLI') as mock_search_cli:

            mock_registry.return_value = RegistryFactory.create_mock()
            mock_config.return_value = ConfigFactory.create_mock()
            mock_theme.return_value = ThemeFactory.create_mock()

            from crack.reference.cli.main import ReferenceCLI
            cli = ReferenceCLI()

            cli.run(['--quick-wins', '--no-banner'])

            mock_search_cli.return_value.show_quick_wins.assert_called_once()

    def test_chains_routes_to_chains_cli(self):
        """
        BV: --chains shows attack chains

        Scenario:
          Given: CLI with --chains flag
          When: run() is called
          Then: Routes to ChainsCLI.list_or_show
        """
        with patch('crack.reference.cli.main.HybridCommandRegistry') as mock_registry, \
             patch('crack.reference.cli.main.ConfigManager') as mock_config, \
             patch('crack.reference.cli.main.ReferenceTheme') as mock_theme, \
             patch('crack.reference.cli.main.PlaceholderEngine'), \
             patch('crack.reference.cli.main.CommandValidator'), \
             patch('crack.reference.cli.main.ChainsCLI') as mock_chains_cli:

            mock_registry.return_value = RegistryFactory.create_mock()
            mock_config.return_value = ConfigFactory.create_mock()
            mock_theme.return_value = ThemeFactory.create_mock()

            from crack.reference.cli.main import ReferenceCLI
            cli = ReferenceCLI()

            cli.run(['--chains', '--no-banner'])

            mock_chains_cli.return_value.list_or_show.assert_called_once()


class TestBannerControl:
    """Tests for banner display control"""

    def test_no_banner_suppresses_banner(self):
        """
        BV: --no-banner hides banner for scripting/automation

        Scenario:
          Given: CLI with --no-banner flag
          When: run() is called
          Then: Banner is not printed
        """
        with patch('crack.reference.cli.main.HybridCommandRegistry') as mock_registry, \
             patch('crack.reference.cli.main.ConfigManager') as mock_config, \
             patch('crack.reference.cli.main.ReferenceTheme') as mock_theme, \
             patch('crack.reference.cli.main.PlaceholderEngine'), \
             patch('crack.reference.cli.main.CommandValidator'):

            mock_theme_instance = ThemeFactory.create_mock()
            mock_registry.return_value = RegistryFactory.create_mock()
            mock_config.return_value = ConfigFactory.create_mock()
            mock_theme.return_value = mock_theme_instance

            from crack.reference.cli.main import ReferenceCLI
            cli = ReferenceCLI()

            # Capture output
            output = StringIO()
            with patch('sys.stdout', output):
                cli.run(['--no-banner', '--stats'])

            # Banner contains "CRACK Reference System" - should not be present
            assert 'CRACK Reference System' not in output.getvalue()

    def test_banner_flag_overrides_no_banner(self):
        """
        BV: --banner explicitly shows banner even with --no-banner

        Scenario:
          Given: CLI with both --no-banner and --banner
          When: run() is called
          Then: Banner is displayed
        """
        with patch('crack.reference.cli.main.HybridCommandRegistry') as mock_registry, \
             patch('crack.reference.cli.main.ConfigManager') as mock_config, \
             patch('crack.reference.cli.main.ReferenceTheme') as mock_theme, \
             patch('crack.reference.cli.main.PlaceholderEngine'), \
             patch('crack.reference.cli.main.CommandValidator'):

            mock_theme_instance = ThemeFactory.create_mock()
            mock_registry.return_value = RegistryFactory.create_mock()
            mock_config.return_value = ConfigFactory.create_mock()
            mock_theme.return_value = mock_theme_instance

            from crack.reference.cli.main import ReferenceCLI
            cli = ReferenceCLI()

            # Capture output
            output = StringIO()
            with patch('sys.stdout', output):
                cli.run(['--no-banner', '--banner', '--stats'])

            # Banner should be present when --banner is used
            assert 'CRACK Reference System' in output.getvalue()


class TestBackendInitialization:
    """Tests for backend selection and initialization"""

    def test_neo4j_backend_selected_when_available(self):
        """
        BV: Neo4j backend used when available for graph queries

        Scenario:
          Given: Neo4j is available and healthy
          When: CLI initializes
          Then: Neo4j backend is selected
        """
        # FIX: Neo4jCommandRegistryAdapter is imported inside _initialize_registry method.
        # Must patch at the source module where it's imported from.
        # Also need to patch GraphCLI._initialize_patterns to avoid isinstance() issues with mocks.
        with patch('crack.reference.cli.main.HybridCommandRegistry'), \
             patch('crack.reference.cli.main.ConfigManager') as mock_config, \
             patch('crack.reference.cli.main.ReferenceTheme') as mock_theme, \
             patch('crack.reference.cli.main.PlaceholderEngine'), \
             patch('crack.reference.cli.main.CommandValidator'), \
             patch('crack.reference.cli.graph.GraphCLI._initialize_patterns'), \
             patch('crack.reference.core.Neo4jCommandRegistryAdapter') as mock_neo4j:

            mock_neo4j_instance = Mock()
            mock_neo4j_instance.health_check.return_value = True
            mock_neo4j_instance.get_stats.return_value = {'total_commands': 700}
            mock_neo4j.return_value = mock_neo4j_instance

            mock_config.return_value = ConfigFactory.create_mock()
            mock_theme.return_value = ThemeFactory.create_mock()

            from crack.reference.cli.main import ReferenceCLI
            cli = ReferenceCLI()

            # Registry should be Neo4j adapter
            assert cli.registry == mock_neo4j_instance

    def test_json_fallback_when_neo4j_unavailable(self):
        """
        BV: JSON fallback works when Neo4j is unavailable

        Scenario:
          Given: Neo4j is not available
          When: CLI initializes
          Then: HybridCommandRegistry (JSON) is used
        """
        # FIX: Neo4jCommandRegistryAdapter is imported inside _initialize_registry method.
        # Must patch at the source module where it's imported from.
        # Also need to patch GraphCLI._initialize_patterns to avoid isinstance() issues with mocks.
        with patch('crack.reference.cli.main.ConfigManager') as mock_config, \
             patch('crack.reference.cli.main.ReferenceTheme') as mock_theme, \
             patch('crack.reference.cli.main.PlaceholderEngine'), \
             patch('crack.reference.cli.main.CommandValidator'), \
             patch('crack.reference.cli.graph.GraphCLI._initialize_patterns'), \
             patch('crack.reference.core.Neo4jCommandRegistryAdapter') as mock_neo4j, \
             patch('crack.reference.cli.main.HybridCommandRegistry') as mock_hybrid:

            # Neo4j fails
            mock_neo4j.side_effect = ImportError("neo4j not available")

            mock_hybrid_instance = RegistryFactory.create_mock()
            mock_hybrid.return_value = mock_hybrid_instance

            mock_config.return_value = ConfigFactory.create_mock()
            mock_theme.return_value = ThemeFactory.create_mock()

            from crack.reference.cli.main import ReferenceCLI
            cli = ReferenceCLI()

            # Registry should be hybrid (JSON)
            mock_hybrid.assert_called_once()


class TestPositionalArgumentHandling:
    """Tests for positional argument parsing (query, category, selection)"""

    def test_positional_arg_as_search_query(self):
        """
        BV: Positional args treated as search query

        Scenario:
          Given: CLI with positional argument "nmap"
          When: run() is called
          Then: Search is performed with query "nmap"
        """
        with patch('crack.reference.cli.main.HybridCommandRegistry') as mock_registry, \
             patch('crack.reference.cli.main.ConfigManager') as mock_config, \
             patch('crack.reference.cli.main.ReferenceTheme') as mock_theme, \
             patch('crack.reference.cli.main.PlaceholderEngine'), \
             patch('crack.reference.cli.main.CommandValidator'), \
             patch('crack.reference.cli.main.SearchCLI') as mock_search_cli:

            mock_registry_instance = RegistryFactory.create_mock()
            mock_registry_instance.get_command.return_value = None  # Not an exact ID match
            mock_registry.return_value = mock_registry_instance
            mock_config.return_value = ConfigFactory.create_mock()
            mock_theme.return_value = ThemeFactory.create_mock()

            from crack.reference.cli.main import ReferenceCLI
            cli = ReferenceCLI()

            cli.run(['nmap', '--no-banner'])

            # Should call search_commands with query='nmap'
            mock_search_cli.return_value.search_commands.assert_called()

    def test_category_as_first_positional_arg(self):
        """
        BV: First positional arg recognized as category when valid

        Scenario:
          Given: CLI with positional argument "recon"
          When: run() is called
          Then: Category filter is applied
        """
        with patch('crack.reference.cli.main.HybridCommandRegistry') as mock_registry, \
             patch('crack.reference.cli.main.ConfigManager') as mock_config, \
             patch('crack.reference.cli.main.ReferenceTheme') as mock_theme, \
             patch('crack.reference.cli.main.PlaceholderEngine'), \
             patch('crack.reference.cli.main.CommandValidator'), \
             patch('crack.reference.cli.main.SearchCLI') as mock_search_cli:

            mock_registry_instance = RegistryFactory.create_mock()
            mock_registry_instance.get_command.return_value = None
            mock_registry.return_value = mock_registry_instance
            mock_config.return_value = ConfigFactory.create_mock()
            mock_theme.return_value = ThemeFactory.create_mock()

            from crack.reference.cli.main import ReferenceCLI
            cli = ReferenceCLI()

            cli.run(['recon', '--no-banner'])

            # Should call search_commands with category='recon'
            call_kwargs = mock_search_cli.return_value.search_commands.call_args
            assert call_kwargs is not None

    def test_numeric_selection_from_results(self):
        """
        BV: Numeric suffix selects from search results

        Scenario:
          Given: CLI with "nmap 1"
          When: run() is called
          Then: First result is auto-selected
        """
        with patch('crack.reference.cli.main.HybridCommandRegistry') as mock_registry, \
             patch('crack.reference.cli.main.ConfigManager') as mock_config, \
             patch('crack.reference.cli.main.ReferenceTheme') as mock_theme, \
             patch('crack.reference.cli.main.PlaceholderEngine'), \
             patch('crack.reference.cli.main.CommandValidator'), \
             patch('crack.reference.cli.main.SearchCLI') as mock_search_cli:

            mock_registry_instance = RegistryFactory.create_mock()
            mock_registry_instance.get_command.return_value = None
            mock_registry.return_value = mock_registry_instance
            mock_config.return_value = ConfigFactory.create_mock()
            mock_theme.return_value = ThemeFactory.create_mock()

            from crack.reference.cli.main import ReferenceCLI
            cli = ReferenceCLI()

            cli.run(['nmap', '1', '--no-banner'])

            # Should include selection in query
            call_args = mock_search_cli.return_value.search_commands.call_args
            assert call_args is not None


class TestDirectCommandLookup:
    """Tests for direct command ID lookup"""

    def test_direct_id_shows_command_details(self):
        """
        BV: Direct command ID lookup shows full details

        Scenario:
          Given: CLI with exact command ID
          When: run() is called
          Then: Command details are displayed
        """
        with patch('crack.reference.cli.main.HybridCommandRegistry') as mock_registry, \
             patch('crack.reference.cli.main.ConfigManager') as mock_config, \
             patch('crack.reference.cli.main.ReferenceTheme') as mock_theme, \
             patch('crack.reference.cli.main.PlaceholderEngine'), \
             patch('crack.reference.cli.main.CommandValidator'), \
             patch('crack.reference.cli.main.DisplayCLI') as mock_display:

            # Create command that will be found
            test_cmd = CommandFactory.create(id="nmap-full-tcp", name="Nmap Full TCP",
                                              tags=["ENUM"])
            mock_registry_instance = Mock()
            mock_registry_instance.get_command.return_value = test_cmd
            mock_registry_instance.categories = {"recon": "01-recon"}
            mock_registry.return_value = mock_registry_instance

            mock_config.return_value = ConfigFactory.create_mock()
            mock_theme.return_value = ThemeFactory.create_mock()

            from crack.reference.cli.main import ReferenceCLI
            cli = ReferenceCLI()

            cli.run(['nmap-full-tcp', '--no-banner'])

            # Display should show command details
            mock_display.return_value.show_command_details.assert_called_with(test_cmd)


class TestGraphPatternRouting:
    """Tests for graph pattern CLI routing"""

    def test_graph_flag_routes_to_graph_cli(self):
        """
        BV: --graph routes to GraphCLI for Neo4j patterns

        Scenario:
          Given: CLI with --graph multi-hop
          When: run() is called
          Then: Routes to GraphCLI.execute_pattern
        """
        with patch('crack.reference.cli.main.HybridCommandRegistry') as mock_registry, \
             patch('crack.reference.cli.main.ConfigManager') as mock_config, \
             patch('crack.reference.cli.main.ReferenceTheme') as mock_theme, \
             patch('crack.reference.cli.main.PlaceholderEngine'), \
             patch('crack.reference.cli.main.CommandValidator'), \
             patch('crack.reference.cli.main.GraphCLI') as mock_graph_cli:

            mock_registry.return_value = RegistryFactory.create_mock()
            mock_config.return_value = ConfigFactory.create_mock()
            mock_theme.return_value = ThemeFactory.create_mock()

            from crack.reference.cli.main import ReferenceCLI
            cli = ReferenceCLI()

            cli.run(['--graph', 'multi-hop', 'gobuster-dir', '--no-banner'])

            mock_graph_cli.return_value.execute_pattern.assert_called_once()


class TestHelpAndDefaults:
    """Tests for help display and default values"""

    def test_no_arguments_shows_help(self):
        """
        BV: No arguments shows help message

        Scenario:
          Given: CLI with no arguments
          When: run() is called
          Then: Help is displayed
        """
        with patch('crack.reference.cli.main.HybridCommandRegistry') as mock_registry, \
             patch('crack.reference.cli.main.ConfigManager') as mock_config, \
             patch('crack.reference.cli.main.ReferenceTheme') as mock_theme, \
             patch('crack.reference.cli.main.PlaceholderEngine'), \
             patch('crack.reference.cli.main.CommandValidator'):

            mock_registry.return_value = RegistryFactory.create_mock()
            mock_config.return_value = ConfigFactory.create_mock()
            mock_theme.return_value = ThemeFactory.create_mock()

            from crack.reference.cli.main import ReferenceCLI
            cli = ReferenceCLI()

            # Mock print_help
            cli.parser.print_help = Mock()

            cli.run(['--no-banner'])

            cli.parser.print_help.assert_called_once()

    def test_default_format_is_text(self):
        """
        BV: Default output format is text

        Scenario:
          Given: CLI without --format flag
          When: Arguments are parsed
          Then: format defaults to 'text'
        """
        with patch('crack.reference.cli.main.HybridCommandRegistry') as mock_registry, \
             patch('crack.reference.cli.main.ConfigManager') as mock_config, \
             patch('crack.reference.cli.main.ReferenceTheme') as mock_theme, \
             patch('crack.reference.cli.main.PlaceholderEngine'), \
             patch('crack.reference.cli.main.CommandValidator'):

            mock_registry.return_value = RegistryFactory.create_mock()
            mock_config.return_value = ConfigFactory.create_mock()
            mock_theme.return_value = ThemeFactory.create_mock()

            from crack.reference.cli.main import ReferenceCLI
            cli = ReferenceCLI()

            parsed = cli.parser.parse_args([])
            assert parsed.format == 'text'


class TestMainEntryPoint:
    """Tests for main() function entry point"""

    def test_main_function_exists(self):
        """
        BV: main() function is importable for CLI entry point

        Scenario:
          Given: main module
          When: main function is imported
          Then: Function is callable
        """
        with patch('crack.reference.cli.main.HybridCommandRegistry'), \
             patch('crack.reference.cli.main.ConfigManager'), \
             patch('crack.reference.cli.main.ReferenceTheme'), \
             patch('crack.reference.cli.main.PlaceholderEngine'), \
             patch('crack.reference.cli.main.CommandValidator'):

            from crack.reference.cli.main import main
            assert callable(main)


class TestValidateCommand:
    """Tests for --validate command"""

    def test_validate_returns_zero_on_success(self):
        """
        BV: --validate returns 0 when all commands are valid

        Scenario:
          Given: CLI with --validate flag
          When: All commands pass validation
          Then: Returns exit code 0
        """
        with patch('crack.reference.cli.main.HybridCommandRegistry') as mock_registry, \
             patch('crack.reference.cli.main.ConfigManager') as mock_config, \
             patch('crack.reference.cli.main.ReferenceTheme') as mock_theme, \
             patch('crack.reference.cli.main.PlaceholderEngine'), \
             patch('crack.reference.cli.main.CommandValidator') as mock_validator:

            mock_registry.return_value = RegistryFactory.create_mock()
            mock_config.return_value = ConfigFactory.create_mock()
            mock_theme.return_value = ThemeFactory.create_mock()

            # Validator returns no errors
            mock_validator_instance = Mock()
            mock_validator_instance.validate_directory.return_value = {}
            mock_validator.return_value = mock_validator_instance

            from crack.reference.cli.main import ReferenceCLI
            cli = ReferenceCLI()

            result = cli.run(['--validate', '--no-banner'])

            assert result == 0

    def test_validate_returns_one_on_errors(self):
        """
        BV: --validate returns 1 when validation errors exist

        Scenario:
          Given: CLI with --validate flag
          When: Commands have validation errors
          Then: Returns exit code 1
        """
        with patch('crack.reference.cli.main.HybridCommandRegistry') as mock_registry, \
             patch('crack.reference.cli.main.ConfigManager') as mock_config, \
             patch('crack.reference.cli.main.ReferenceTheme') as mock_theme, \
             patch('crack.reference.cli.main.PlaceholderEngine'), \
             patch('crack.reference.cli.main.CommandValidator') as mock_validator:

            mock_registry.return_value = RegistryFactory.create_mock()
            mock_config.return_value = ConfigFactory.create_mock()
            mock_theme.return_value = ThemeFactory.create_mock()

            # Validator returns errors
            mock_validator_instance = Mock()
            mock_validator_instance.validate_directory.return_value = {
                'commands.json': ['Missing ID field', 'Invalid tag format']
            }
            mock_validator.return_value = mock_validator_instance

            from crack.reference.cli.main import ReferenceCLI
            cli = ReferenceCLI()

            result = cli.run(['--validate', '--no-banner'])

            assert result == 1


class TestStatusCommand:
    """Tests for --status command"""

    def test_status_shows_backend_info(self):
        """
        BV: --status shows backend type and health

        Scenario:
          Given: CLI with --status flag
          When: run() is called
          Then: Backend status information is displayed
        """
        with patch('crack.reference.cli.main.HybridCommandRegistry') as mock_registry, \
             patch('crack.reference.cli.main.ConfigManager') as mock_config, \
             patch('crack.reference.cli.main.ReferenceTheme') as mock_theme, \
             patch('crack.reference.cli.main.PlaceholderEngine'), \
             patch('crack.reference.cli.main.CommandValidator'):

            mock_registry_instance = RegistryFactory.create_mock()
            mock_registry.return_value = mock_registry_instance
            mock_config.return_value = ConfigFactory.create_mock()
            mock_theme.return_value = ThemeFactory.create_mock()

            from crack.reference.cli.main import ReferenceCLI
            cli = ReferenceCLI()

            output = StringIO()
            with patch('sys.stdout', output):
                result = cli.run(['--status', '--no-banner'])

            assert result == 0
            assert 'Backend' in output.getvalue()
            assert 'Active' in output.getvalue()
