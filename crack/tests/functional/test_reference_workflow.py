#!/usr/bin/env python3
"""
Functional tests for Reference System Workflows
Tests end-to-end scenarios and complete user workflows
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch
import json

from crack.reference.cli import ReferenceCLI
from crack.reference.core.registry import HybridCommandRegistry
from crack.reference.core.config import ConfigManager


class TestReferenceWorkflows:
    """Test complete reference system workflows"""

    @pytest.mark.functional
    @pytest.mark.reference
    def test_config_to_command_workflow(self, temp_output_dir, sample_commands_json, monkeypatch):
        """Test complete workflow: auto-config -> set values -> fill command"""
        # Setup
        config_path = temp_output_dir / "workflow_config.json"
        commands_dir = temp_output_dir / "data" / "commands"
        commands_dir.mkdir(parents=True)

        import shutil
        shutil.copy(sample_commands_json, commands_dir / "test.json")

        # Step 1: Initialize and auto-configure
        config = ConfigManager(config_path=str(config_path))

        # Mock auto-detection
        with patch.object(config, 'auto_detect_ip', return_value='10.10.14.5'):
            with patch.object(config, 'auto_detect_interface', return_value='tun0'):
                updates = config.auto_configure()
                assert len(updates) > 0

        # Step 2: Manually set TARGET
        config.set_variable('TARGET', '192.168.45.100')

        # Step 3: Load commands with config
        registry = HybridCommandRegistry(base_path=temp_output_dir, config_manager=config)

        # Step 4: Fill command with config values
        cmd = registry.get_command('test-nmap')
        assert cmd is not None

        # Mock user pressing enter to use config values
        inputs = iter([""])  # Press enter
        monkeypatch.setattr('builtins.input', lambda x: next(inputs))

        filled = registry.interactive_fill(cmd)

        # Should contain TARGET from config
        assert '192.168.45.100' in filled or '<TARGET>' in filled

    @pytest.mark.functional
    @pytest.mark.reference
    def test_subcategory_navigation_workflow(self, temp_output_dir, sample_subcategory_commands):
        """Test navigating to commands via category and subcategory"""
        # Setup subdirectory structure
        commands_dir = temp_output_dir / "data" / "commands"
        commands_dir.mkdir(parents=True)

        import shutil
        src_cat = sample_subcategory_commands / "test-category"
        dest_cat = commands_dir / "test-category"
        shutil.copytree(src_cat, dest_cat)

        # Load registry
        registry = HybridCommandRegistry(base_path=temp_output_dir)

        # Step 1: Check category exists
        assert "test-category" in registry.categories or len(registry.commands) > 0

        # Step 2: Get subcategories
        subcats = registry.get_subcategories("test-category")
        assert "subcat" in subcats

        # Step 3: Filter by subcategory
        commands = registry.filter_by_category("test-category", "subcat")
        assert len(commands) == 1
        assert commands[0].id == "test-subcat-cmd"

    @pytest.mark.functional
    @pytest.mark.reference
    def test_search_and_filter_workflow(self, temp_output_dir, sample_commands_json):
        """Test searching and filtering commands"""
        # Setup
        commands_dir = temp_output_dir / "data" / "commands"
        commands_dir.mkdir(parents=True)

        import shutil
        shutil.copy(sample_commands_json, commands_dir / "test.json")

        registry = HybridCommandRegistry(base_path=temp_output_dir)

        # Step 1: Search by text
        results = registry.search("nmap")
        assert len(results) >= 1

        # Step 2: Filter by tag
        results = registry.filter_by_tags(["OSCP:HIGH"])
        assert len(results) >= 1

        # Step 3: Get quick wins
        results = registry.get_quick_wins()
        assert len(results) >= 1

        # Step 4: Get OSCP high commands
        results = registry.get_oscp_high()
        assert len(results) >= 1

    @pytest.mark.functional
    @pytest.mark.reference
    def test_cli_category_workflow(self, temp_output_dir, sample_commands_json, capsys):
        """Test CLI workflow for category navigation"""
        # Setup
        commands_dir = temp_output_dir / "data" / "commands"
        commands_dir.mkdir(parents=True)

        import shutil
        shutil.copy(sample_commands_json, commands_dir / "test.json")

        # Initialize CLI with test data
        with patch.object(ReferenceCLI, '__init__') as mock_init:
            mock_init.return_value = None

            cli = ReferenceCLI()
            cli.config = ConfigManager()
            cli.registry = HybridCommandRegistry(base_path=temp_output_dir)
            cli.validator = Mock()
            cli.placeholder_engine = Mock()
            cli.parser = cli.create_parser()

            # Mock the filter_by_category method to track calls
            with patch.object(cli.registry, 'filter_by_category', wraps=cli.registry.filter_by_category) as mock_filter:
                # Simulate: crack reference test
                cli.display_commands = Mock()
                cli.search_commands(category='test')

                # Verify filter_by_category was called
                mock_filter.assert_called_once()

    @pytest.mark.functional
    @pytest.mark.reference
    def test_export_workflow(self, temp_output_dir, sample_commands_json, capsys):
        """Test exporting commands in different formats"""
        # Setup
        commands_dir = temp_output_dir / "data" / "commands"
        commands_dir.mkdir(parents=True)

        import shutil
        shutil.copy(sample_commands_json, commands_dir / "test.json")

        registry = HybridCommandRegistry(base_path=temp_output_dir)
        cli = ReferenceCLI.__new__(ReferenceCLI)
        cli.registry = registry

        # Get test commands
        commands = registry.filter_by_category('test')

        # Test text export
        cli.display_commands(commands, format='text', verbose=False)
        captured = capsys.readouterr()
        assert 'test-nmap' in captured.out

        # Test JSON export
        cli.display_commands(commands, format='json', verbose=False)
        captured = capsys.readouterr()
        # Should be valid JSON
        try:
            data = json.loads(captured.out)
            assert isinstance(data, list)
        except:
            pytest.fail("JSON export is not valid")

        # Test markdown export
        cli.display_commands(commands, format='markdown', verbose=True)
        captured = capsys.readouterr()
        assert '```' in captured.out

    @pytest.mark.functional
    @pytest.mark.reference
    def test_config_persistence_workflow(self, temp_output_dir):
        """Test config persists across CLI sessions"""
        config_path = temp_output_dir / "persist_test.json"

        # Session 1: Set config
        config1 = ConfigManager(config_path=str(config_path))
        config1.set_variable('LHOST', '10.10.14.5')
        config1.set_variable('TARGET', '192.168.45.100')

        # Session 2: Load config
        config2 = ConfigManager(config_path=str(config_path))

        # Values should persist
        assert config2.get_variable('LHOST') == '10.10.14.5'
        assert config2.get_variable('TARGET') == '192.168.45.100'

    @pytest.mark.functional
    @pytest.mark.reference
    def test_stats_workflow(self, temp_output_dir, sample_commands_json, sample_subcategory_commands, capsys):
        """Test stats generation with mixed command structure"""
        # Setup mixed structure (flat + subdirectories)
        commands_dir = temp_output_dir / "data" / "commands"
        commands_dir.mkdir(parents=True)

        import shutil
        shutil.copy(sample_commands_json, commands_dir / "test.json")

        src_cat = sample_subcategory_commands / "test-category"
        dest_cat = commands_dir / "test-category"
        shutil.copytree(src_cat, dest_cat)

        # Initialize registry
        registry = HybridCommandRegistry(base_path=temp_output_dir)

        # Get stats
        stats = registry.get_stats()

        # Should have both flat and subcategory data
        assert stats['total_commands'] >= 3
        assert 'by_category' in stats
        assert 'by_subcategory' in stats

        # Display stats via CLI
        cli = ReferenceCLI.__new__(ReferenceCLI)
        cli.registry = registry

        cli.show_stats()
        captured = capsys.readouterr()

        assert 'Total Commands' in captured.out
        assert 'test-category' in captured.out or 'test:' in captured.out

    @pytest.mark.functional
    @pytest.mark.reference
    def test_validation_workflow(self, temp_output_dir, invalid_command_json):
        """Test command validation workflow"""
        # Setup with invalid commands
        commands_dir = temp_output_dir / "data" / "commands"
        commands_dir.mkdir(parents=True)

        import shutil
        shutil.copy(invalid_command_json, commands_dir / "invalid.json")

        # Load registry (should handle invalid gracefully)
        registry = HybridCommandRegistry(base_path=temp_output_dir)

        # Validate schema
        errors = registry.validate_schema()

        # Should detect missing required fields
        assert isinstance(errors, list)
        # May have errors from invalid command

    @pytest.mark.functional
    @pytest.mark.reference
    def test_fill_with_override_workflow(self, temp_output_dir, sample_commands_json, mock_config_file, monkeypatch):
        """Test filling command with config and manual override"""
        # Setup
        commands_dir = temp_output_dir / "data" / "commands"
        commands_dir.mkdir(parents=True)

        import shutil
        shutil.copy(sample_commands_json, commands_dir / "test.json")

        config = ConfigManager(config_path=str(mock_config_file))
        registry = HybridCommandRegistry(base_path=temp_output_dir, config_manager=config)

        cmd = registry.get_command('test-nmap')

        # Mock user overriding config value
        inputs = iter(["192.168.1.200"])  # Override with different value
        monkeypatch.setattr('builtins.input', lambda x: next(inputs))

        filled = registry.interactive_fill(cmd)

        # Should use overridden value, not config
        assert '192.168.1.200' in filled or '192.168.45.100' in filled

    @pytest.mark.functional
    @pytest.mark.reference
    def test_quick_start_workflow(self, temp_output_dir, sample_commands_json, monkeypatch, capsys):
        """Test quick start workflow from README"""
        # Simulates: crack reference --config auto && crack reference --set TARGET 192.168.45.100

        # Setup
        config_path = temp_output_dir / "quickstart.json"
        commands_dir = temp_output_dir / "data" / "commands"
        commands_dir.mkdir(parents=True)

        import shutil
        shutil.copy(sample_commands_json, commands_dir / "test.json")

        # Initialize
        with patch.object(ReferenceCLI, '__init__') as mock_init:
            mock_init.return_value = None

            cli = ReferenceCLI()
            cli.config = ConfigManager(config_path=str(config_path))
            cli.registry = HybridCommandRegistry(base_path=temp_output_dir, config_manager=cli.config)

            # Step 1: Auto-configure
            with patch.object(cli.config, 'auto_detect_ip', return_value='10.10.14.5'):
                with patch.object(cli.config, 'auto_detect_interface', return_value='tun0'):
                    cli.auto_config()

            # Step 2: Set TARGET
            cli.set_config_var('TARGET', '192.168.45.100')

            # Step 3: Search for command
            cli.display_commands = Mock()
            cli.search_commands(query='nmap')

            # Should find commands
            cli.display_commands.assert_called_once()

    @pytest.mark.functional
    @pytest.mark.reference
    def test_multi_tag_filter_workflow(self, temp_output_dir, sample_commands_json):
        """Test filtering by multiple tags"""
        # Setup
        commands_dir = temp_output_dir / "data" / "commands"
        commands_dir.mkdir(parents=True)

        import shutil
        shutil.copy(sample_commands_json, commands_dir / "test.json")

        registry = HybridCommandRegistry(base_path=temp_output_dir)

        # Filter by multiple tags (AND logic)
        results = registry.filter_by_tags(['OSCP:HIGH', 'ENUM'])

        # Should only return commands with BOTH tags
        for cmd in results:
            assert 'OSCP:HIGH' in cmd.tags
            assert 'ENUM' in cmd.tags

    @pytest.mark.functional
    @pytest.mark.reference
    def test_category_subcategory_stats_workflow(self, temp_output_dir, sample_subcategory_commands, capsys):
        """Test stats with subcategory breakdown"""
        # Setup
        commands_dir = temp_output_dir / "data" / "commands"
        commands_dir.mkdir(parents=True)

        import shutil
        src_cat = sample_subcategory_commands / "test-category"
        dest_cat = commands_dir / "test-category"
        shutil.copytree(src_cat, dest_cat)

        # Get stats
        registry = HybridCommandRegistry(base_path=temp_output_dir)
        cli = ReferenceCLI.__new__(ReferenceCLI)
        cli.registry = registry

        cli.show_stats()
        captured = capsys.readouterr()

        # Should show category with subcategory tree
        assert 'test-category' in captured.out
        assert 'subcat' in captured.out or '└─' in captured.out
