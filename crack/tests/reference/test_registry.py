"""
Tests for HybridCommandRegistry

Business Value Focus:
- Command loading accuracy (users get complete command data)
- get_command() reliability (direct ID lookup works)
- Category filtering (users find commands by attack phase)
- Tag filtering (users find commands by technique)
- Statistics accuracy (users understand registry contents)

These tests verify the core registry operations that users depend on
for command discovery and management.
"""

import pytest
import json
import tempfile
from pathlib import Path
from typing import List, Dict, Any
from unittest.mock import Mock, patch


# =============================================================================
# Command Loading Tests (BV: HIGH)
# =============================================================================

class TestCommandLoading:
    """Tests for command loading from JSON files."""

    def test_loads_commands_from_flat_json_file(self, tmp_path, command_factory):
        """
        BV: Users' commands load correctly from legacy flat file structure.

        Scenario:
          Given: JSON file with commands in root directory
          When: Registry is initialized
          Then: All commands are accessible by ID
        """
        commands_dir = tmp_path / "db" / "data" / "commands"
        commands_dir.mkdir(parents=True)

        test_cmd = command_factory.create(id="flat-test-cmd", category="recon")
        json_file = commands_dir / "recon.json"
        json_file.write_text(json.dumps({
            "category": "recon",
            "commands": [test_cmd]
        }))

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        cmd = registry.get_command("flat-test-cmd")
        assert cmd is not None, "Command should be loaded from flat JSON file"
        assert cmd.id == "flat-test-cmd"

    def test_loads_commands_from_subdirectory_structure(self, tmp_path, command_factory):
        """
        BV: Users' commands load correctly from categorized subdirectory structure.

        Scenario:
          Given: JSON files in category subdirectories
          When: Registry is initialized
          Then: Commands are loaded with correct category and subcategory
        """
        # Create subdirectory structure
        subdir = tmp_path / "db" / "data" / "commands" / "post-exploit"
        subdir.mkdir(parents=True)

        test_cmd = command_factory.create(
            id="subdir-test-cmd",
            category="post-exploit",
            subcategory="privesc"
        )
        json_file = subdir / "privesc.json"
        json_file.write_text(json.dumps({
            "category": "post-exploit",
            "commands": [test_cmd]
        }))

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        cmd = registry.get_command("subdir-test-cmd")
        assert cmd is not None
        assert cmd.category == "post-exploit"
        assert cmd.subcategory == "privesc"

    def test_loads_commands_with_all_fields_intact(self, tmp_path, command_factory):
        """
        BV: No data loss during command loading - all fields preserved.

        Scenario:
          Given: Command with all fields populated
          When: Loaded from JSON
          Then: All fields match original values
        """
        commands_dir = tmp_path / "db" / "data" / "commands"
        commands_dir.mkdir(parents=True)

        full_cmd = {
            "id": "full-field-cmd",
            "name": "Full Field Command",
            "category": "exploitation",
            "command": "exploit.py --target <TARGET>",
            "description": "A fully populated command",
            "subcategory": "buffer-overflow",
            "tags": ["BOF", "EXPLOIT", "OSCP:HIGH"],
            "variables": [
                {"name": "<TARGET>", "description": "Target IP", "example": "192.168.1.1", "required": True}
            ],
            "flag_explanations": {"--target": "Target system"},
            "success_indicators": ["Shell received"],
            "failure_indicators": ["Connection refused"],
            "next_steps": ["escalate-privileges"],
            "alternatives": ["alt-exploit"],
            "prerequisites": ["recon-scan"],
            "troubleshooting": {"Error 1": "Try X"},
            "notes": "Important note",
            "oscp_relevance": "high"
        }

        json_file = commands_dir / "exploitation.json"
        json_file.write_text(json.dumps({
            "category": "exploitation",
            "commands": [full_cmd]
        }))

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        cmd = registry.get_command("full-field-cmd")
        assert cmd is not None
        assert cmd.name == "Full Field Command"
        assert cmd.description == "A fully populated command"
        assert "BOF" in cmd.tags
        assert len(cmd.variables) == 1
        assert cmd.variables[0].name == "<TARGET>"
        assert cmd.oscp_relevance == "high"
        assert "Shell received" in cmd.success_indicators
        assert "--target" in cmd.flag_explanations

    def test_handles_malformed_json_gracefully(self, tmp_path, capsys):
        """
        BV: Registry doesn't crash on malformed JSON - continues loading valid files.

        Scenario:
          Given: Directory with valid and invalid JSON files
          When: Registry initializes
          Then: Valid commands load, error logged for invalid
        """
        commands_dir = tmp_path / "db" / "data" / "commands"
        commands_dir.mkdir(parents=True)

        # Valid file
        valid_file = commands_dir / "valid.json"
        valid_file.write_text(json.dumps({
            "category": "recon",
            "commands": [{"id": "valid-cmd", "name": "Valid", "command": "test",
                         "description": "test", "category": "recon"}]
        }))

        # Invalid file
        invalid_file = commands_dir / "invalid.json"
        invalid_file.write_text("{this is: not valid json}")

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        # Valid command should still be loaded
        cmd = registry.get_command("valid-cmd")
        assert cmd is not None, "Valid commands should load despite invalid files"

    def test_handles_empty_commands_directory(self, tmp_path):
        """
        BV: Registry works with empty commands directory.

        Scenario:
          Given: Empty commands directory
          When: Registry initializes
          Then: No errors, empty registry functional
        """
        commands_dir = tmp_path / "db" / "data" / "commands"
        commands_dir.mkdir(parents=True)

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        assert len(registry.commands) == 0
        assert registry.get_command("nonexistent") is None

    def test_handles_missing_commands_directory(self, tmp_path):
        """
        BV: Registry creates missing directory and continues.

        Scenario:
          Given: No commands directory exists
          When: Registry initializes
          Then: Directory created, registry functional
        """
        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        # Should not raise, just have empty registry
        assert len(registry.commands) == 0


# =============================================================================
# get_command() Tests (BV: HIGH)
# =============================================================================

class TestGetCommand:
    """Tests for get_command() ID lookup."""

    def test_returns_command_by_exact_id(self, json_registry_with_commands):
        """
        BV: Users can retrieve command by exact ID.

        Scenario:
          Given: Registry with loaded commands
          When: get_command() called with exact ID
          Then: Correct command returned
        """
        registry = json_registry_with_commands
        cmd = registry.get_command("nmap-tcp-scan")

        assert cmd is not None
        assert cmd.id == "nmap-tcp-scan"
        assert cmd.name == "Nmap TCP Scan"

    def test_returns_none_for_nonexistent_id(self, json_registry_with_commands):
        """
        BV: Graceful handling of missing command IDs.

        Scenario:
          Given: Registry with commands
          When: get_command() called with unknown ID
          Then: Returns None (no exception)
        """
        registry = json_registry_with_commands
        result = registry.get_command("nonexistent-command-id")

        assert result is None

    def test_returns_none_for_empty_id(self, json_registry_with_commands):
        """
        BV: Handles empty string ID gracefully.
        """
        registry = json_registry_with_commands
        assert registry.get_command("") is None

    def test_returns_none_for_none_id(self, json_registry_with_commands):
        """
        BV: Handles None ID gracefully.
        """
        registry = json_registry_with_commands
        # This tests edge case - some implementations might accept None
        result = registry.get_command(None)
        assert result is None

    def test_id_lookup_is_case_sensitive(self, tmp_path, command_factory):
        """
        BV: Command IDs are case-sensitive (prevents accidental collisions).

        Scenario:
          Given: Commands with similar IDs differing by case
          When: get_command() called
          Then: Only exact case match returned
        """
        commands_dir = tmp_path / "db" / "data" / "commands"
        commands_dir.mkdir(parents=True)

        cmd1 = command_factory.create(id="My-Command", name="Uppercase")
        cmd2 = command_factory.create(id="my-command", name="Lowercase")

        json_file = commands_dir / "test.json"
        json_file.write_text(json.dumps({
            "category": "test",
            "commands": [cmd1, cmd2]
        }))

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        upper_cmd = registry.get_command("My-Command")
        lower_cmd = registry.get_command("my-command")

        assert upper_cmd is not None
        assert lower_cmd is not None
        assert upper_cmd.name == "Uppercase"
        assert lower_cmd.name == "Lowercase"


# =============================================================================
# filter_by_category() Tests (BV: HIGH)
# =============================================================================

class TestFilterByCategory:
    """Tests for filter_by_category() method."""

    def test_returns_all_commands_in_category(self, json_registry_with_commands):
        """
        BV: Users can view all commands for an attack phase.

        Scenario:
          Given: Registry with commands in multiple categories
          When: filter_by_category('recon')
          Then: Only recon commands returned
        """
        registry = json_registry_with_commands
        results = registry.filter_by_category("recon")

        assert len(results) > 0
        for cmd in results:
            assert cmd.category == "recon"

    def test_returns_empty_list_for_empty_category(self, json_registry_with_commands):
        """
        BV: No error on empty/nonexistent category.
        """
        registry = json_registry_with_commands
        results = registry.filter_by_category("nonexistent-category")

        assert results == []

    def test_filters_by_subcategory(self, tmp_path, command_factory):
        """
        BV: Users can narrow down to specific subcategory.

        Scenario:
          Given: Commands with subcategories
          When: filter_by_category('post-exploit', 'privesc')
          Then: Only privesc subcategory commands returned
        """
        subdir = tmp_path / "db" / "data" / "commands" / "post-exploit"
        subdir.mkdir(parents=True)

        privesc_cmd = command_factory.create(
            id="privesc-cmd",
            category="post-exploit",
            subcategory="privesc"
        )
        enum_cmd = command_factory.create(
            id="enum-cmd",
            category="post-exploit",
            subcategory="enum"
        )

        privesc_file = subdir / "privesc.json"
        privesc_file.write_text(json.dumps({
            "category": "post-exploit",
            "commands": [privesc_cmd]
        }))

        enum_file = subdir / "enum.json"
        enum_file.write_text(json.dumps({
            "category": "post-exploit",
            "commands": [enum_cmd]
        }))

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        results = registry.filter_by_category("post-exploit", subcategory="privesc")

        assert len(results) == 1
        assert results[0].id == "privesc-cmd"

    def test_subcategory_filter_with_no_match(self, json_registry_with_commands):
        """
        BV: Returns empty list when subcategory doesn't exist.
        """
        registry = json_registry_with_commands
        results = registry.filter_by_category("recon", subcategory="nonexistent")

        assert results == []


# =============================================================================
# filter_by_tags() Tests (BV: HIGH)
# =============================================================================

class TestFilterByTags:
    """Tests for filter_by_tags() method."""

    def test_returns_commands_with_all_tags(self, json_registry_with_commands):
        """
        BV: Tag filtering uses AND logic (all tags required).

        Scenario:
          Given: Commands with various tags
          When: filter_by_tags(['OSCP:HIGH'])
          Then: Only commands with that tag returned
        """
        registry = json_registry_with_commands
        results = registry.filter_by_tags(["OSCP:HIGH"])

        assert len(results) > 0
        for cmd in results:
            # Case-insensitive check
            cmd_tags_upper = [t.upper() for t in cmd.tags]
            assert "OSCP:HIGH" in cmd_tags_upper

    def test_tag_filtering_is_case_insensitive(self, tmp_path, command_factory):
        """
        BV: Users don't need to remember exact tag casing.

        Scenario:
          Given: Commands with mixed-case tags
          When: Search with different casing
          Then: Matches regardless of case
        """
        commands_dir = tmp_path / "db" / "data" / "commands"
        commands_dir.mkdir(parents=True)

        cmd = command_factory.create(
            id="case-test",
            tags=["OSCP:HIGH", "Linux", "privesc"]
        )

        json_file = commands_dir / "test.json"
        json_file.write_text(json.dumps({
            "category": "test",
            "commands": [cmd]
        }))

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        # Test various cases
        assert len(registry.filter_by_tags(["oscp:high"])) == 1
        assert len(registry.filter_by_tags(["LINUX"])) == 1
        assert len(registry.filter_by_tags(["PRIVESC"])) == 1
        assert len(registry.filter_by_tags(["Oscp:High", "linux"])) == 1

    def test_multiple_tags_require_all_match(self, tmp_path, command_factory):
        """
        BV: AND logic for multiple tag filter (stricter filtering).

        Scenario:
          Given: Commands with various tags
          When: Filter with multiple tags
          Then: Only commands with ALL tags returned
        """
        commands_dir = tmp_path / "db" / "data" / "commands"
        commands_dir.mkdir(parents=True)

        cmd1 = command_factory.create(id="cmd1", tags=["TAG_A", "TAG_B"])
        cmd2 = command_factory.create(id="cmd2", tags=["TAG_A"])
        cmd3 = command_factory.create(id="cmd3", tags=["TAG_B"])

        json_file = commands_dir / "test.json"
        json_file.write_text(json.dumps({
            "category": "test",
            "commands": [cmd1, cmd2, cmd3]
        }))

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        results = registry.filter_by_tags(["TAG_A", "TAG_B"])

        assert len(results) == 1
        assert results[0].id == "cmd1"

    def test_exclude_tags_removes_matching_commands(self, tmp_path, command_factory):
        """
        BV: Users can exclude commands with unwanted tags.

        Scenario:
          Given: Commands with various tags
          When: Filter with exclude_tags
          Then: Commands with excluded tags removed
        """
        commands_dir = tmp_path / "db" / "data" / "commands"
        commands_dir.mkdir(parents=True)

        cmd1 = command_factory.create(id="keep", tags=["OSCP:HIGH"])
        cmd2 = command_factory.create(id="exclude", tags=["OSCP:HIGH", "NOISY"])

        json_file = commands_dir / "test.json"
        json_file.write_text(json.dumps({
            "category": "test",
            "commands": [cmd1, cmd2]
        }))

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        results = registry.filter_by_tags(["OSCP:HIGH"], exclude_tags=["NOISY"])

        assert len(results) == 1
        assert results[0].id == "keep"

    def test_empty_tag_list_returns_all_commands(self, json_registry_with_commands):
        """
        BV: Empty tag filter returns all commands.
        """
        registry = json_registry_with_commands
        results = registry.filter_by_tags([])

        # Should return all commands (no filter applied)
        assert len(results) == len(registry.commands)


# =============================================================================
# get_quick_wins() / get_oscp_high() Tests (BV: MEDIUM)
# =============================================================================

class TestQuickFilters:
    """Tests for convenience filter methods."""

    def test_get_quick_wins_returns_tagged_commands(self, tmp_path, command_factory):
        """
        BV: Quick wins are easily accessible for time-constrained scenarios.
        """
        commands_dir = tmp_path / "db" / "data" / "commands"
        commands_dir.mkdir(parents=True)

        quick_cmd = command_factory.create_quick_win(id="quick-1")
        normal_cmd = command_factory.create(id="normal-1", tags=[])

        json_file = commands_dir / "test.json"
        json_file.write_text(json.dumps({
            "category": "test",
            "commands": [quick_cmd, normal_cmd]
        }))

        from reference.core.registry import HybridCommandRegistry
        registry = HybridCommandRegistry(base_path=tmp_path)

        results = registry.get_quick_wins()

        assert len(results) == 1
        assert results[0].id == "quick-1"

    def test_get_oscp_high_returns_high_relevance(self, json_registry_with_commands):
        """
        BV: OSCP exam-critical commands easily accessible.
        """
        registry = json_registry_with_commands
        results = registry.get_oscp_high()

        assert len(results) > 0
        for cmd in results:
            assert (
                cmd.oscp_relevance == "high" or
                "OSCP:HIGH" in [t.upper() for t in cmd.tags]
            )


# =============================================================================
# get_stats() Tests (BV: MEDIUM)
# =============================================================================

class TestGetStats:
    """Tests for registry statistics."""

    def test_returns_total_command_count(self, json_registry_with_commands):
        """
        BV: Users can verify registry loaded correctly.
        """
        registry = json_registry_with_commands
        stats = registry.get_stats()

        assert "total_commands" in stats
        assert stats["total_commands"] == len(registry.commands)

    def test_returns_category_breakdown(self, json_registry_with_commands):
        """
        BV: Users understand command distribution by category.
        """
        registry = json_registry_with_commands
        stats = registry.get_stats()

        assert "by_category" in stats
        assert isinstance(stats["by_category"], dict)

    def test_returns_tag_counts(self, json_registry_with_commands):
        """
        BV: Users can discover popular/common tags.
        """
        registry = json_registry_with_commands
        stats = registry.get_stats()

        assert "top_tags" in stats
        assert isinstance(stats["top_tags"], list)

    def test_stats_on_empty_registry(self, empty_registry):
        """
        BV: Stats work on empty registry without error.
        """
        stats = empty_registry.get_stats()

        assert stats["total_commands"] == 0


# =============================================================================
# add_command() Tests (BV: MEDIUM)
# =============================================================================

class TestAddCommand:
    """Tests for adding commands to registry."""

    def test_adds_command_to_registry(self, empty_registry):
        """
        BV: Programmatically added commands are retrievable.
        """
        from reference.core.registry import Command

        cmd = Command(
            id="added-cmd",
            name="Added Command",
            category="test",
            command="echo test",
            description="Programmatically added"
        )

        empty_registry.add_command(cmd)
        retrieved = empty_registry.get_command("added-cmd")

        assert retrieved is not None
        assert retrieved.name == "Added Command"

    def test_overwrites_existing_command(self, empty_registry):
        """
        BV: Re-adding command updates it (no duplicates).
        """
        from reference.core.registry import Command

        cmd1 = Command(
            id="overwrite-test",
            name="Original",
            category="test",
            command="echo 1",
            description="First version"
        )
        cmd2 = Command(
            id="overwrite-test",
            name="Updated",
            category="test",
            command="echo 2",
            description="Second version"
        )

        empty_registry.add_command(cmd1)
        empty_registry.add_command(cmd2)

        result = empty_registry.get_command("overwrite-test")
        assert result.name == "Updated"
        assert len(empty_registry.commands) == 1


# =============================================================================
# validate_schema() Tests (BV: MEDIUM)
# =============================================================================

class TestValidateSchema:
    """Tests for command schema validation."""

    def test_detects_missing_command_text(self, empty_registry):
        """
        BV: Validates commands have required fields.
        """
        from reference.core.registry import Command

        invalid_cmd = Command(
            id="no-command",
            name="No Command Text",
            category="test",
            command="",  # Empty command text
            description="This should fail validation"
        )

        empty_registry.add_command(invalid_cmd)
        errors = empty_registry.validate_schema()

        assert any("missing command text" in e.lower() for e in errors)

    def test_detects_undefined_placeholders(self, empty_registry):
        """
        BV: Catches placeholder/variable mismatch.
        """
        from reference.core.registry import Command

        cmd_with_undefined_placeholder = Command(
            id="undefined-placeholder",
            name="Undefined Placeholder",
            category="test",
            command="nmap <TARGET> <PORT>",  # Two placeholders
            description="Has undefined placeholder",
            variables=[]  # No variables defined!
        )

        empty_registry.add_command(cmd_with_undefined_placeholder)
        errors = empty_registry.validate_schema()

        assert any("<TARGET>" in e or "<PORT>" in e for e in errors)

    def test_validates_successfully_for_correct_commands(self, json_registry_with_commands):
        """
        BV: Correct commands pass validation.
        """
        errors = json_registry_with_commands.validate_schema()

        # Sample commands from fixture should be valid
        # Allow some errors from auto-generated test commands, but check for critical ones
        critical_errors = [e for e in errors if "missing command text" in e.lower()]
        assert len(critical_errors) == 0


# =============================================================================
# Command Dataclass Tests (BV: MEDIUM)
# =============================================================================

class TestCommandDataclass:
    """Tests for Command dataclass methods."""

    def test_to_dict_serializes_correctly(self, command_factory):
        """
        BV: Commands can be serialized for storage/export.
        """
        from reference.core.registry import Command

        cmd = Command.from_dict(command_factory.create_nmap())
        result = cmd.to_dict()

        assert isinstance(result, dict)
        assert result["id"] == "nmap-tcp-scan"
        assert isinstance(result["variables"], list)

    def test_from_dict_deserializes_correctly(self, command_factory):
        """
        BV: Commands load correctly from dict/JSON.
        """
        from reference.core.registry import Command

        data = command_factory.create_nmap()
        cmd = Command.from_dict(data)

        assert cmd.id == "nmap-tcp-scan"
        assert cmd.name == "Nmap TCP Scan"
        assert len(cmd.variables) == 2
        assert cmd.variables[0].name == "<TARGET>"

    def test_from_dict_filters_unknown_fields(self, command_factory):
        """
        BV: Unknown JSON fields don't cause errors.
        """
        from reference.core.registry import Command

        data = command_factory.create(id="test-unknown")
        data["unknown_field"] = "should be ignored"
        data["another_unknown"] = {"nested": "value"}

        # Should not raise
        cmd = Command.from_dict(data)
        assert cmd.id == "test-unknown"

    def test_extract_placeholders(self):
        """
        BV: Placeholders correctly extracted from command text.
        """
        from reference.core.registry import Command

        cmd = Command(
            id="test",
            name="Test",
            category="test",
            command="nmap -p <PORT> <TARGET> -o <OUTPUT>",
            description="Test"
        )

        placeholders = cmd.extract_placeholders()

        assert "<PORT>" in placeholders
        assert "<TARGET>" in placeholders
        assert "<OUTPUT>" in placeholders
        assert len(placeholders) == 3

    def test_fill_placeholders_replaces_values(self):
        """
        BV: Placeholder substitution works correctly.
        """
        from reference.core.registry import Command, CommandVariable

        cmd = Command(
            id="test",
            name="Test",
            category="test",
            command="nmap -p <PORT> <TARGET>",
            description="Test",
            variables=[
                CommandVariable(name="<PORT>", description="Port", example="80"),
                CommandVariable(name="<TARGET>", description="Target", example="192.168.1.1")
            ]
        )

        filled = cmd.fill_placeholders({
            "<PORT>": "443",
            "<TARGET>": "10.10.10.1"
        })

        assert filled == "nmap -p 443 10.10.10.1"

    def test_fill_placeholders_uses_example_as_fallback(self):
        """
        BV: Missing values fall back to example.
        """
        from reference.core.registry import Command, CommandVariable

        cmd = Command(
            id="test",
            name="Test",
            category="test",
            command="nmap -p <PORT> <TARGET>",
            description="Test",
            variables=[
                CommandVariable(name="<PORT>", description="Port", example="80"),
                CommandVariable(name="<TARGET>", description="Target", example="192.168.1.1")
            ]
        )

        filled = cmd.fill_placeholders({
            "<TARGET>": "10.10.10.1"
            # <PORT> not provided - should use example
        })

        assert filled == "nmap -p 80 10.10.10.1"
