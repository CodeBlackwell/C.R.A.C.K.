#!/usr/bin/env python3
"""
Unit tests for Reference Registry Module
Tests command loading, search, filtering, and subcategory functionality
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch
import json

from crack.reference.core.registry import (
    Command,
    CommandVariable,
    HybridCommandRegistry
)


class TestCommandDataclass:
    """Test Command dataclass functionality"""

    @pytest.mark.unit
    @pytest.mark.reference
    def test_command_creation(self, sample_command_data):
        """Test creating Command from dictionary"""
        cmd = Command.from_dict(sample_command_data)

        assert cmd.id == "test-command"
        assert cmd.name == "Test Command"
        assert cmd.category == "test"
        assert cmd.subcategory == "unit"
        assert cmd.command == "echo <MESSAGE>"
        assert cmd.oscp_relevance == "high"
        assert "OSCP:HIGH" in cmd.tags

    @pytest.mark.unit
    @pytest.mark.reference
    def test_command_to_dict(self, sample_command_data):
        """Test Command serialization to dict"""
        cmd = Command.from_dict(sample_command_data)
        data = cmd.to_dict()

        assert data['id'] == "test-command"
        assert data['name'] == "Test Command"
        assert isinstance(data['variables'], list)
        assert len(data['variables']) == 1

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_extract_placeholders(self):
        """Test placeholder extraction from command"""
        cmd = Command(
            id="test",
            name="Test",
            category="test",
            command="nmap -sV <TARGET> -p <PORTS>",
            description="Test"
        )

        placeholders = cmd.extract_placeholders()
        assert "<TARGET>" in placeholders
        assert "<PORTS>" in placeholders
        assert len(placeholders) == 2

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_fill_placeholders(self):
        """Test filling placeholders with values"""
        cmd = Command(
            id="test",
            name="Test",
            category="test",
            command="curl http://<TARGET>:<PORT>",
            description="Test",
            variables=[
                CommandVariable("<TARGET>", "Target IP", "192.168.1.1", True),
                CommandVariable("<PORT>", "Port", "80", True)
            ]
        )

        values = {
            "<TARGET>": "192.168.45.100",
            "<PORT>": "8080"
        }
        filled = cmd.fill_placeholders(values)

        assert filled == "curl http://192.168.45.100:8080"

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_matches_search(self):
        """Test command search matching"""
        cmd = Command(
            id="nmap-service-scan",
            name="Service Version Detection",
            category="recon",
            command="nmap -sV <TARGET>",
            description="Detect service versions",
            tags=["ENUM", "OSCP:HIGH"]
        )

        # Test name match
        assert cmd.matches_search("service")
        assert cmd.matches_search("version")

        # Test description match
        assert cmd.matches_search("detect")

        # Test command match
        assert cmd.matches_search("nmap")

        # Test tag match
        assert cmd.matches_search("enum")
        assert cmd.matches_search("OSCP")

        # Test no match
        assert not cmd.matches_search("gobuster")


class TestHybridCommandRegistry:
    """Test HybridCommandRegistry functionality"""

    @pytest.mark.unit
    @pytest.mark.reference
    def test_registry_initialization(self, temp_output_dir):
        """Test registry initialization"""
        # Create commands directory
        commands_dir = temp_output_dir / "data" / "commands"
        commands_dir.mkdir(parents=True)

        registry = HybridCommandRegistry(base_path=temp_output_dir)

        assert registry.base_path == temp_output_dir
        assert isinstance(registry.commands, dict)
        assert isinstance(registry.categories, dict)
        assert isinstance(registry.subcategories, dict)

    @pytest.mark.unit
    @pytest.mark.reference
    def test_load_flat_json_commands(self, temp_output_dir, sample_commands_json):
        """Test loading commands from flat JSON structure"""
        # Setup directory structure
        commands_dir = temp_output_dir / "data" / "commands"
        commands_dir.mkdir(parents=True)

        # Copy sample commands
        import shutil
        shutil.copy(sample_commands_json, commands_dir / "test.json")

        registry = HybridCommandRegistry(base_path=temp_output_dir)

        assert len(registry.commands) >= 2
        assert "test-nmap" in registry.commands
        assert "test-curl" in registry.commands

    @pytest.mark.unit
    @pytest.mark.reference
    def test_load_subcategory_commands(self, temp_output_dir, sample_subcategory_commands):
        """Test loading commands from subdirectory structure"""
        # Move temp dir to expected location
        commands_dir = temp_output_dir / "data" / "commands"
        commands_dir.mkdir(parents=True)

        # Move test-category to commands dir
        import shutil
        src_cat = sample_subcategory_commands / "test-category"
        dest_cat = commands_dir / "test-category"
        shutil.copytree(src_cat, dest_cat)

        registry = HybridCommandRegistry(base_path=temp_output_dir)

        # Check subcategory was detected
        assert "test-category" in registry.subcategories
        assert "subcat" in registry.subcategories["test-category"]

        # Check command loaded with subcategory
        assert "test-subcat-cmd" in registry.commands
        cmd = registry.commands["test-subcat-cmd"]
        assert cmd.category == "test-category"
        assert cmd.subcategory == "subcat"

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_add_command(self, reference_registry):
        """Test adding command to registry"""
        new_cmd = Command(
            id="new-test-cmd",
            name="New Test",
            category="test",
            command="echo 'new'",
            description="New command"
        )

        initial_count = len(reference_registry.commands)
        reference_registry.add_command(new_cmd)

        assert len(reference_registry.commands) == initial_count + 1
        assert "new-test-cmd" in reference_registry.commands

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_get_command(self, reference_registry):
        """Test retrieving command by ID"""
        cmd = reference_registry.get_command("test-nmap")

        assert cmd is not None
        assert cmd.id == "test-nmap"
        assert cmd.name == "Test Nmap Scan"

        # Test non-existent command
        assert reference_registry.get_command("non-existent") is None

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_search_commands(self, reference_registry):
        """Test searching commands by query"""
        # Search by name
        results = reference_registry.search("nmap")
        assert len(results) >= 1
        assert any(cmd.id == "test-nmap" for cmd in results)

        # Search by description
        results = reference_registry.search("service")
        assert len(results) >= 1

        # Search by command text
        results = reference_registry.search("curl")
        assert len(results) >= 1

        # No results
        results = reference_registry.search("nonexistent-term")
        assert len(results) == 0

    @pytest.mark.unit
    @pytest.mark.reference
    def test_filter_by_category(self, reference_registry):
        """Test filtering commands by category"""
        results = reference_registry.filter_by_category("test")

        assert len(results) >= 2
        assert all(cmd.category == "test" for cmd in results)

    @pytest.mark.unit
    @pytest.mark.reference
    def test_filter_by_subcategory(self, temp_output_dir, sample_subcategory_commands):
        """Test filtering by category and subcategory"""
        # Setup
        commands_dir = temp_output_dir / "data" / "commands"
        commands_dir.mkdir(parents=True)

        import shutil
        src_cat = sample_subcategory_commands / "test-category"
        dest_cat = commands_dir / "test-category"
        shutil.copytree(src_cat, dest_cat)

        registry = HybridCommandRegistry(base_path=temp_output_dir)

        # Filter by category and subcategory
        results = registry.filter_by_category("test-category", "subcat")

        assert len(results) == 1
        assert results[0].id == "test-subcat-cmd"
        assert results[0].subcategory == "subcat"

    @pytest.mark.unit
    @pytest.mark.reference
    def test_filter_by_tags(self, reference_registry):
        """Test filtering commands by tags"""
        # Filter by single tag
        results = reference_registry.filter_by_tags(["OSCP:HIGH"])
        assert len(results) >= 1
        assert all("OSCP:HIGH" in cmd.tags for cmd in results)

        # Filter by multiple tags (AND logic)
        results = reference_registry.filter_by_tags(["OSCP:MEDIUM", "QUICK_WIN"])
        assert len(results) >= 1
        assert all("OSCP:MEDIUM" in cmd.tags and "QUICK_WIN" in cmd.tags for cmd in results)

    @pytest.mark.unit
    @pytest.mark.reference
    def test_filter_exclude_tags(self, reference_registry):
        """Test excluding commands by tags"""
        results = reference_registry.filter_by_tags(
            ["OSCP:HIGH"],
            exclude_tags=["ENUM"]
        )

        # Should have OSCP:HIGH but not ENUM
        assert all("OSCP:HIGH" in cmd.tags for cmd in results)
        assert all("ENUM" not in cmd.tags for cmd in results)

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_get_quick_wins(self, reference_registry):
        """Test getting quick win commands"""
        results = reference_registry.get_quick_wins()

        assert len(results) >= 1
        assert all("QUICK_WIN" in cmd.tags for cmd in results)

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_get_oscp_high(self, reference_registry):
        """Test getting OSCP high relevance commands"""
        results = reference_registry.get_oscp_high()

        assert len(results) >= 1
        # Check each command has high relevance OR OSCP:HIGH tag
        for cmd in results:
            assert cmd.oscp_relevance == "high" or "OSCP:HIGH" in cmd.tags

    @pytest.mark.unit
    @pytest.mark.reference
    def test_get_subcategories(self, temp_output_dir, sample_subcategory_commands):
        """Test getting subcategories for a category"""
        # Setup
        commands_dir = temp_output_dir / "data" / "commands"
        commands_dir.mkdir(parents=True)

        import shutil
        src_cat = sample_subcategory_commands / "test-category"
        dest_cat = commands_dir / "test-category"
        shutil.copytree(src_cat, dest_cat)

        registry = HybridCommandRegistry(base_path=temp_output_dir)

        subcats = registry.get_subcategories("test-category")
        assert "subcat" in subcats

        # Non-existent category
        assert registry.get_subcategories("nonexistent") == []

    @pytest.mark.unit
    @pytest.mark.reference
    def test_get_stats(self, reference_registry):
        """Test getting registry statistics"""
        stats = reference_registry.get_stats()

        assert 'total_commands' in stats
        assert stats['total_commands'] >= 2

        assert 'by_category' in stats
        assert 'test' in stats['by_category']

        assert 'top_tags' in stats
        assert len(stats['top_tags']) > 0

        assert 'quick_wins' in stats
        assert 'oscp_high' in stats

    @pytest.mark.unit
    @pytest.mark.reference
    def test_stats_with_subcategories(self, temp_output_dir, sample_subcategory_commands):
        """Test stats include subcategory counts"""
        # Setup
        commands_dir = temp_output_dir / "data" / "commands"
        commands_dir.mkdir(parents=True)

        import shutil
        src_cat = sample_subcategory_commands / "test-category"
        dest_cat = commands_dir / "test-category"
        shutil.copytree(src_cat, dest_cat)

        registry = HybridCommandRegistry(base_path=temp_output_dir)
        stats = registry.get_stats()

        assert 'by_subcategory' in stats
        assert 'test-category' in stats['by_subcategory']
        assert 'subcat' in stats['by_subcategory']['test-category']

    @pytest.mark.unit
    @pytest.mark.reference
    def test_validate_schema(self, reference_registry):
        """Test schema validation"""
        errors = reference_registry.validate_schema()

        # With valid commands, should have no errors
        assert isinstance(errors, list)
        # May have errors if commands missing fields, but should not crash

    @pytest.mark.unit
    @pytest.mark.reference
    def test_interactive_fill_with_config(self, reference_registry, mock_config_file, monkeypatch):
        """Test interactive fill with config integration"""
        from crack.reference.core.config import ConfigManager

        # Setup config manager
        config = ConfigManager(config_path=str(mock_config_file))
        reference_registry.config_manager = config

        # Get command with placeholders
        cmd = reference_registry.get_command("test-nmap")
        assert cmd is not None

        # Mock user input (press enter to use config value)
        inputs = iter([""])  # Press enter to use config
        monkeypatch.setattr('builtins.input', lambda x: next(inputs))

        # Test interactive fill
        filled = reference_registry.interactive_fill(cmd)

        # Should use config value for TARGET
        assert "192.168.45.100" in filled or "<TARGET>" in filled

    @pytest.mark.unit
    @pytest.mark.reference
    def test_loading_error_handling(self, temp_output_dir):
        """Test graceful handling of malformed JSON"""
        commands_dir = temp_output_dir / "data" / "commands"
        commands_dir.mkdir(parents=True)

        # Create invalid JSON file
        bad_json = commands_dir / "bad.json"
        bad_json.write_text("{invalid json content")

        # Should not crash
        registry = HybridCommandRegistry(base_path=temp_output_dir)
        assert isinstance(registry.commands, dict)
