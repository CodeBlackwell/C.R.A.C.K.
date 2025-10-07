#!/usr/bin/env python3
"""
Integration tests for Reference CLI
Tests command-line interface, argument parsing, and workflows
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import sys
import json

from crack.reference.cli import ReferenceCLI


class TestReferenceCLI:
    """Test Reference CLI functionality"""

    @pytest.mark.integration
    @pytest.mark.reference
    @pytest.mark.fast
    def test_cli_initialization(self):
        """Test CLI initialization"""
        cli = ReferenceCLI()

        assert cli.config is not None
        assert cli.registry is not None
        assert cli.placeholder_engine is not None
        assert cli.parser is not None

    @pytest.mark.integration
    @pytest.mark.reference
    def test_argument_parser_creation(self):
        """Test argument parser has all expected arguments"""
        cli = ReferenceCLI()
        parser = cli.parser

        # Test that parser accepts key arguments
        args = parser.parse_args(['test', 'query'])
        assert args.args == ['test', 'query']

        args = parser.parse_args(['--stats'])
        assert args.stats is True

        args = parser.parse_args(['--fill', 'command-id'])
        assert args.fill == 'command-id'

    @pytest.mark.integration
    @pytest.mark.reference
    def test_stats_command(self, capsys, temp_output_dir):
        """Test --stats command"""
        with patch.object(ReferenceCLI, '__init__', lambda x: None):
            cli = ReferenceCLI()
            cli.config = Mock()
            cli.registry = Mock()
            cli.registry.get_stats.return_value = {
                'total_commands': 10,
                'by_category': {'test': 5},
                'by_subcategory': {},
                'top_tags': [('OSCP:HIGH', 5)],
                'quick_wins': 3,
                'oscp_high': 7
            }

            cli.show_stats()

            captured = capsys.readouterr()
            assert 'Total Commands: 10' in captured.out
            assert 'test: 5' in captured.out

    @pytest.mark.integration
    @pytest.mark.reference
    def test_search_commands(self, capsys, temp_output_dir):
        """Test search functionality"""
        with patch.object(ReferenceCLI, '__init__', lambda x: None):
            cli = ReferenceCLI()
            cli.registry = Mock()

            mock_cmd = Mock()
            mock_cmd.id = 'test-cmd'
            mock_cmd.name = 'Test Command'
            mock_cmd.command = 'echo test'

            cli.registry.search.return_value = [mock_cmd]
            cli.display_commands = Mock()

            cli.search_commands(query='test')

            cli.registry.search.assert_called_with('test')
            cli.display_commands.assert_called_once()

    @pytest.mark.integration
    @pytest.mark.reference
    def test_category_navigation(self, capsys):
        """Test category-based navigation"""
        with patch.object(ReferenceCLI, '__init__', lambda x: None):
            cli = ReferenceCLI()
            cli.registry = Mock()

            mock_cmd = Mock()
            mock_cmd.id = 'test-cmd'
            mock_cmd.category = 'test'

            cli.registry.filter_by_category.return_value = [mock_cmd]
            cli.registry.get_subcategories.return_value = []
            cli.display_commands = Mock()

            cli.search_commands(category='test')

            cli.registry.filter_by_category.assert_called_with('test', None)

    @pytest.mark.integration
    @pytest.mark.reference
    def test_subcategory_navigation(self, capsys):
        """Test subcategory navigation"""
        with patch.object(ReferenceCLI, '__init__', lambda x: None):
            cli = ReferenceCLI()
            cli.registry = Mock()

            mock_cmd = Mock()
            mock_cmd.id = 'test-subcat-cmd'
            mock_cmd.category = 'test'
            mock_cmd.subcategory = 'subcat'

            cli.registry.filter_by_category.return_value = [mock_cmd]
            cli.display_commands = Mock()

            cli.search_commands(category='test', subcategory='subcat')

            cli.registry.filter_by_category.assert_called_with('test', 'subcat')

    @pytest.mark.integration
    @pytest.mark.reference
    def test_subcategory_listing(self, capsys):
        """Test listing subcategories when category has no root commands"""
        with patch.object(ReferenceCLI, '__init__', lambda x: None):
            cli = ReferenceCLI()
            cli.registry = Mock()

            cli.registry.filter_by_category.return_value = []
            cli.registry.get_subcategories.return_value = ['linux', 'windows']

            cli.search_commands(category='post-exploit', subcategory=None)

            captured = capsys.readouterr()
            assert 'subcategories' in captured.out.lower() or 'linux' in captured.out

    @pytest.mark.integration
    @pytest.mark.reference
    def test_tag_filtering(self):
        """Test filtering by tags"""
        with patch.object(ReferenceCLI, '__init__', lambda x: None):
            cli = ReferenceCLI()
            cli.registry = Mock()

            mock_cmd = Mock()
            mock_cmd.tags = ['OSCP:HIGH', 'QUICK_WIN']

            cli.registry.filter_by_tags.return_value = [mock_cmd]
            cli.display_commands = Mock()

            cli.search_commands(tags=['OSCP:HIGH'])

            cli.registry.filter_by_tags.assert_called_with(['OSCP:HIGH'], None)

    @pytest.mark.integration
    @pytest.mark.reference
    def test_display_text_format(self, capsys):
        """Test displaying commands in text format"""
        with patch.object(ReferenceCLI, '__init__', lambda x: None):
            cli = ReferenceCLI()

            mock_cmd = Mock()
            mock_cmd.id = 'test-cmd'
            mock_cmd.name = 'Test Command'
            mock_cmd.command = 'echo test'
            mock_cmd.description = 'Test description'
            mock_cmd.tags = ['TEST']
            mock_cmd.oscp_relevance = 'high'

            cli.display_commands([mock_cmd], format='text', verbose=True)

            captured = capsys.readouterr()
            assert 'test-cmd' in captured.out
            assert 'Test Command' in captured.out
            assert 'echo test' in captured.out

    @pytest.mark.integration
    @pytest.mark.reference
    def test_display_json_format(self, capsys):
        """Test displaying commands in JSON format"""
        with patch.object(ReferenceCLI, '__init__', lambda x: None):
            cli = ReferenceCLI()

            mock_cmd = Mock()
            mock_cmd.to_dict.return_value = {
                'id': 'test-cmd',
                'name': 'Test Command'
            }

            cli.display_commands([mock_cmd], format='json')

            captured = capsys.readouterr()
            assert 'test-cmd' in captured.out
            # Should be valid JSON
            try:
                json.loads(captured.out)
            except:
                pytest.fail("Output is not valid JSON")

    @pytest.mark.integration
    @pytest.mark.reference
    def test_display_markdown_format(self, capsys):
        """Test displaying commands in markdown format"""
        with patch.object(ReferenceCLI, '__init__', lambda x: None):
            cli = ReferenceCLI()

            mock_cmd = Mock()
            mock_cmd.id = 'test-cmd'
            mock_cmd.name = 'Test Command'
            mock_cmd.command = 'echo test'
            mock_cmd.description = 'Test description'
            mock_cmd.tags = []
            mock_cmd.oscp_relevance = 'high'

            cli.display_commands([mock_cmd], format='markdown', verbose=True)

            captured = capsys.readouterr()
            assert '##' in captured.out  # Markdown header
            assert '```' in captured.out  # Code block

    @pytest.mark.integration
    @pytest.mark.reference
    def test_config_list_command(self, capsys, mock_config_file):
        """Test --config list command"""
        with patch.object(ReferenceCLI, '__init__', lambda x: None):
            from crack.reference.core.config import ConfigManager

            cli = ReferenceCLI()
            cli.config = ConfigManager(config_path=str(mock_config_file))

            cli.list_config()

            captured = capsys.readouterr()
            assert 'LHOST' in captured.out
            assert 'TARGET' in captured.out
            assert '10.10.14.5' in captured.out

    @pytest.mark.integration
    @pytest.mark.reference
    def test_set_config_variable(self, capsys, temp_output_dir):
        """Test --set command"""
        with patch.object(ReferenceCLI, '__init__', lambda x: None):
            from crack.reference.core.config import ConfigManager

            config_path = temp_output_dir / "cli_test.json"
            cli = ReferenceCLI()
            cli.config = ConfigManager(config_path=str(config_path))

            cli.set_config_var('TARGET', '192.168.1.100')

            captured = capsys.readouterr()
            assert 'TARGET' in captured.out
            assert '192.168.1.100' in captured.out

            # Verify variable was set
            assert cli.config.get_variable('TARGET') == '192.168.1.100'

    @pytest.mark.integration
    @pytest.mark.reference
    def test_get_config_variable(self, capsys, mock_config_file):
        """Test --get command"""
        with patch.object(ReferenceCLI, '__init__', lambda x: None):
            from crack.reference.core.config import ConfigManager

            cli = ReferenceCLI()
            cli.config = ConfigManager(config_path=str(mock_config_file))

            cli.get_config_var('LHOST')

            captured = capsys.readouterr()
            assert 'LHOST' in captured.out
            assert '10.10.14.5' in captured.out

    @pytest.mark.integration
    @pytest.mark.reference
    def test_auto_config_command(self, capsys, mock_network_interfaces, mock_ip_detection, temp_output_dir):
        """Test --config auto command"""
        with patch.object(ReferenceCLI, '__init__', lambda x: None):
            from crack.reference.core.config import ConfigManager

            config_path = temp_output_dir / "auto_cli_test.json"
            cli = ReferenceCLI()
            cli.config = ConfigManager(config_path=str(config_path))

            cli.auto_config()

            captured = capsys.readouterr()
            # Should show auto-detected values
            assert 'auto' in captured.out.lower() or 'detect' in captured.out.lower()

    @pytest.mark.integration
    @pytest.mark.reference
    def test_list_tags_command(self, capsys):
        """Test --list-tags command"""
        with patch.object(ReferenceCLI, '__init__', lambda x: None):
            cli = ReferenceCLI()
            cli.registry = Mock()

            mock_cmd1 = Mock()
            mock_cmd1.tags = ['OSCP:HIGH', 'ENUM']

            mock_cmd2 = Mock()
            mock_cmd2.tags = ['OSCP:HIGH', 'QUICK_WIN']

            cli.registry.commands = {
                'cmd1': mock_cmd1,
                'cmd2': mock_cmd2
            }

            cli.list_tags()

            captured = capsys.readouterr()
            assert 'OSCP:HIGH' in captured.out
            assert '2 commands' in captured.out  # OSCP:HIGH appears in 2 commands

    @pytest.mark.integration
    @pytest.mark.reference
    def test_quick_wins_command(self, capsys):
        """Test --quick-wins command"""
        with patch.object(ReferenceCLI, '__init__', lambda x: None):
            cli = ReferenceCLI()
            cli.registry = Mock()

            mock_cmd = Mock()
            mock_cmd.tags = ['QUICK_WIN']
            mock_cmd.id = 'quick-cmd'
            mock_cmd.name = 'Quick Command'

            cli.registry.get_quick_wins.return_value = [mock_cmd]
            cli.display_commands = Mock()

            cli.show_quick_wins('text', False)

            cli.registry.get_quick_wins.assert_called_once()
            cli.display_commands.assert_called_once()

    @pytest.mark.integration
    @pytest.mark.reference
    def test_oscp_high_command(self, capsys):
        """Test --oscp-high command"""
        with patch.object(ReferenceCLI, '__init__', lambda x: None):
            cli = ReferenceCLI()
            cli.registry = Mock()

            mock_cmd = Mock()
            mock_cmd.oscp_relevance = 'high'
            mock_cmd.id = 'oscp-cmd'

            cli.registry.get_oscp_high.return_value = [mock_cmd]
            cli.display_commands = Mock()

            cli.show_oscp_high('text', False)

            cli.registry.get_oscp_high.assert_called_once()

    @pytest.mark.integration
    @pytest.mark.reference
    def test_fill_command(self, capsys, monkeypatch):
        """Test --fill command"""
        with patch.object(ReferenceCLI, '__init__', lambda x: None):
            cli = ReferenceCLI()
            cli.registry = Mock()

            mock_cmd = Mock()
            mock_cmd.id = 'test-cmd'
            mock_cmd.name = 'Test Command'

            cli.registry.get_command.return_value = mock_cmd
            cli.registry.interactive_fill.return_value = "echo filled"

            cli.fill_command('test-cmd')

            captured = capsys.readouterr()
            assert 'filled' in captured.out or 'Copy' in captured.out

    @pytest.mark.integration
    @pytest.mark.reference
    def test_fill_command_with_search(self, capsys):
        """Test --fill with search when exact ID not found"""
        with patch.object(ReferenceCLI, '__init__', lambda x: None):
            cli = ReferenceCLI()
            cli.registry = Mock()

            mock_cmd = Mock()
            mock_cmd.id = 'test-cmd'
            mock_cmd.name = 'Test Command'

            # get_command returns None (not found)
            cli.registry.get_command.return_value = None
            # search returns one match
            cli.registry.search.return_value = [mock_cmd]
            cli.registry.interactive_fill.return_value = "echo filled"

            cli.fill_command('test')

            # Should use the search result
            cli.registry.interactive_fill.assert_called_once()

    @pytest.mark.integration
    @pytest.mark.reference
    def test_positional_args_category_detection(self):
        """Test positional args detect category correctly"""
        cli = ReferenceCLI()

        # Parse category argument
        args = cli.parser.parse_args(['recon'])
        assert args.args == ['recon']

        # Should detect as category in run() method
        # (This would be tested in functional tests with full workflow)

    @pytest.mark.integration
    @pytest.mark.reference
    def test_positional_args_subcategory_detection(self):
        """Test positional args detect category and subcategory"""
        cli = ReferenceCLI()

        args = cli.parser.parse_args(['post-exploit', 'linux'])
        assert args.args == ['post-exploit', 'linux']

        # run() method should parse this as category + subcategory
        # (Full workflow tested in functional tests)

    @pytest.mark.integration
    @pytest.mark.reference
    def test_no_commands_found_message(self, capsys):
        """Test message when no commands match criteria"""
        with patch.object(ReferenceCLI, '__init__', lambda x: None):
            cli = ReferenceCLI()
            cli.registry = Mock()
            cli.registry.filter_by_category.return_value = []
            cli.registry.get_subcategories.return_value = []  # No subcategories

            cli.search_commands(category='nonexistent')

            captured = capsys.readouterr()
            assert 'No commands found' in captured.out or 'subcategories' in captured.out.lower()

    @pytest.mark.integration
    @pytest.mark.reference
    def test_clear_config_confirmation(self, capsys, monkeypatch, temp_output_dir):
        """Test --clear-config with confirmation"""
        with patch.object(ReferenceCLI, '__init__', lambda x: None):
            from crack.reference.core.config import ConfigManager

            config_path = temp_output_dir / "clear_test.json"
            cli = ReferenceCLI()
            cli.config = ConfigManager(config_path=str(config_path))

            # Mock user saying 'y' to confirmation
            monkeypatch.setattr('builtins.input', lambda x: 'y')

            cli.clear_config()

            captured = capsys.readouterr()
            assert 'cleared' in captured.out.lower() or 'Clear' in captured.out
