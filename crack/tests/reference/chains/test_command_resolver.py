"""
Tests for CommandResolver - Command reference resolution for chains.

Business Value Focus:
- Chain steps must resolve to valid commands for execution
- Missing command references are caught before chain execution
- Lazy registry initialization reduces startup overhead
- Reference caching improves repeated resolution performance
"""

import pytest
from unittest.mock import MagicMock, patch

from reference.chains.command_resolver import CommandResolver
from tests.reference.chains.conftest import ChainFactory


# ==============================================================================
# Test: Basic Resolution
# ==============================================================================


class TestBasicResolution:
    """Tests for basic command reference resolution."""

    def test_resolve_known_command(self):
        """
        BV: Commands in the registry are resolved successfully.

        Scenario:
          Given: A resolver with known commands
          When: resolve_command_ref() is called for a known command
          Then: The command object is returned
        """
        mock_cmd = MagicMock(id="test-cmd", name="Test Command")
        resolver = CommandResolver(commands={"test-cmd": mock_cmd})

        result = resolver.resolve_command_ref("test-cmd")

        assert result is not None
        assert result.id == "test-cmd"

    def test_resolve_unknown_command_returns_none(self):
        """
        BV: Unknown commands return None (no exception).

        Scenario:
          Given: A resolver with limited commands
          When: resolve_command_ref() is called for unknown command
          Then: None is returned
        """
        resolver = CommandResolver(commands={"known-cmd": MagicMock()})

        result = resolver.resolve_command_ref("unknown-cmd")

        assert result is None

    def test_resolve_empty_ref_returns_none(self):
        """
        BV: Empty reference string returns None.

        Scenario:
          Given: A resolver
          When: resolve_command_ref("") is called
          Then: None is returned
        """
        resolver = CommandResolver(commands={})

        result = resolver.resolve_command_ref("")

        assert result is None

    def test_resolve_none_ref_returns_none(self):
        """
        BV: None reference returns None (handles malformed steps).

        Scenario:
          Given: A resolver
          When: resolve_command_ref(None) is called (type mismatch)
          Then: None is returned without error
        """
        resolver = CommandResolver(commands={})

        result = resolver.resolve_command_ref(None)

        assert result is None


# ==============================================================================
# Test: Resolution Caching
# ==============================================================================


class TestResolutionCaching:
    """Tests for command resolution caching."""

    def test_resolution_is_cached(self):
        """
        BV: Repeated resolutions use cache (performance).

        Scenario:
          Given: A command is resolved once
          When: Same command is resolved again
          Then: Cache is used (no repeated registry lookup)
        """
        mock_cmd = MagicMock(id="cached-cmd")
        commands = {"cached-cmd": mock_cmd}
        resolver = CommandResolver(commands=commands)

        # First resolution
        result1 = resolver.resolve_command_ref("cached-cmd")

        # Modify the source (cache should still return original)
        del commands["cached-cmd"]

        # Second resolution (should use cache)
        result2 = resolver.resolve_command_ref("cached-cmd")

        assert result1 is result2

    def test_cache_stores_none_for_unknown(self):
        """
        BV: Failed resolutions are also cached.

        Scenario:
          Given: An unknown command is resolved
          When: Same resolution is attempted again
          Then: Cache returns None (no repeated lookup)
        """
        resolver = CommandResolver(commands={})

        # First resolution (miss)
        result1 = resolver.resolve_command_ref("unknown")

        # Add command after first resolution
        resolver._commands["unknown"] = MagicMock()

        # Second resolution (should still return cached None)
        result2 = resolver.resolve_command_ref("unknown")

        assert result1 is None
        assert result2 is None


# ==============================================================================
# Test: Command Reference Extraction
# ==============================================================================


class TestCommandRefExtraction:
    """Tests for extracting command references from chains."""

    def test_extract_command_refs_from_chain(self):
        """
        BV: All command references in a chain are extracted.

        Scenario:
          Given: A chain with multiple steps
          When: extract_command_refs() is called
          Then: All command_ref values are returned
        """
        chain = ChainFactory.create(
            steps=[
                ChainFactory.create_step(command_ref="cmd-a"),
                ChainFactory.create_step(command_ref="cmd-b"),
                ChainFactory.create_step(command_ref="cmd-c"),
            ]
        )
        resolver = CommandResolver(commands={})

        refs = resolver.extract_command_refs(chain)

        assert refs == ["cmd-a", "cmd-b", "cmd-c"]

    def test_extract_refs_empty_chain(self):
        """
        BV: Empty chain returns empty list.

        Scenario:
          Given: A chain with no steps
          When: extract_command_refs() is called
          Then: Empty list is returned
        """
        chain = {"steps": []}
        resolver = CommandResolver(commands={})

        refs = resolver.extract_command_refs(chain)

        assert refs == []

    def test_extract_refs_missing_steps_key(self):
        """
        BV: Chain without steps key returns empty list.

        Scenario:
          Given: A malformed chain without 'steps'
          When: extract_command_refs() is called
          Then: Empty list is returned (no crash)
        """
        chain = {"id": "no-steps"}
        resolver = CommandResolver(commands={})

        refs = resolver.extract_command_refs(chain)

        assert refs == []

    def test_extract_refs_skips_invalid_steps(self):
        """
        BV: Non-dict steps are skipped gracefully.

        Scenario:
          Given: A chain with mixed valid and invalid steps
          When: extract_command_refs() is called
          Then: Only valid refs are extracted
        """
        chain = {
            "steps": [
                {"command_ref": "valid-cmd"},
                "not-a-dict",
                None,
                {"command_ref": "another-valid"},
            ]
        }
        resolver = CommandResolver(commands={})

        refs = resolver.extract_command_refs(chain)

        assert refs == ["valid-cmd", "another-valid"]

    def test_extract_refs_skips_empty_command_ref(self):
        """
        BV: Steps with empty command_ref are skipped.

        Scenario:
          Given: A step with command_ref: ""
          When: extract_command_refs() is called
          Then: Empty string is not included
        """
        chain = {
            "steps": [
                {"command_ref": "valid"},
                {"command_ref": ""},
                {"command_ref": "also-valid"},
            ]
        }
        resolver = CommandResolver(commands={})

        refs = resolver.extract_command_refs(chain)

        assert refs == ["valid", "also-valid"]


# ==============================================================================
# Test: Reference Validation
# ==============================================================================


class TestReferenceValidation:
    """Tests for validating command references."""

    def test_validate_all_references_exist(self):
        """
        BV: Valid references return empty dict (no errors).

        Scenario:
          Given: A resolver with known commands
          When: validate_references() is called with known refs
          Then: Empty dict is returned
        """
        resolver = CommandResolver(
            commands={
                "cmd-a": MagicMock(),
                "cmd-b": MagicMock(),
            }
        )

        missing = resolver.validate_references(["cmd-a", "cmd-b"])

        assert missing == {}

    def test_validate_missing_reference(self):
        """
        BV: Missing references are reported with clear messages.

        Scenario:
          Given: A resolver without certain commands
          When: validate_references() is called with unknown refs
          Then: Dict maps ref to error message
        """
        resolver = CommandResolver(commands={"known": MagicMock()})

        missing = resolver.validate_references(["known", "unknown"])

        assert "unknown" in missing
        assert "could not be resolved" in missing["unknown"]

    def test_validate_multiple_missing_references(self):
        """
        BV: All missing references are reported together.

        Scenario:
          Given: Multiple unknown references
          When: validate_references() is called
          Then: All are reported in the result
        """
        resolver = CommandResolver(commands={})

        missing = resolver.validate_references(["cmd-1", "cmd-2", "cmd-3"])

        assert len(missing) == 3
        assert "cmd-1" in missing
        assert "cmd-2" in missing
        assert "cmd-3" in missing

    def test_validate_skips_duplicates(self):
        """
        BV: Duplicate references are validated only once.

        Scenario:
          Given: References with duplicates
          When: validate_references() is called
          Then: Each unique ref is checked once
        """
        resolver = CommandResolver(commands={})

        missing = resolver.validate_references(
            ["dup-cmd", "dup-cmd", "dup-cmd", "other"]
        )

        assert len(missing) == 2
        assert "dup-cmd" in missing
        assert "other" in missing

    def test_validate_empty_list(self):
        """
        BV: Empty reference list returns empty dict.

        Scenario:
          Given: An empty list of references
          When: validate_references() is called
          Then: Empty dict is returned
        """
        resolver = CommandResolver(commands={})

        missing = resolver.validate_references([])

        assert missing == {}


# ==============================================================================
# Test: Lazy Registry Initialization
# ==============================================================================


class TestLazyRegistryInitialization:
    """Tests for lazy HybridCommandRegistry initialization."""

    def test_no_registry_until_needed(self):
        """
        BV: Registry is not created until first resolution attempt.

        Scenario:
          Given: A resolver created without explicit commands
          When: No resolution is attempted yet
          Then: Internal registry is None
        """
        resolver = CommandResolver()

        # Before any resolution, registry should be None
        assert resolver._registry is None
        assert resolver._commands == {}

    def test_registry_initialized_on_resolution(self):
        """
        BV: Registry is lazily created on first resolution.

        Scenario:
          Given: A resolver without explicit commands
          When: resolve_command_ref() is called
          Then: Registry is initialized

        FIX: The HybridCommandRegistry is imported inside the _init_registry method,
        not at module level. Must patch the source module, not the import location.
        """
        with patch(
            "crack.reference.core.registry.HybridCommandRegistry"
        ) as mock_registry_class:
            mock_registry = MagicMock()
            mock_registry.commands = {"test-cmd": MagicMock()}
            mock_registry.get_command.return_value = None
            mock_registry_class.return_value = mock_registry

            resolver = CommandResolver()
            resolver.resolve_command_ref("test-cmd")

            mock_registry_class.assert_called_once()

    def test_explicit_commands_prevent_registry_init(self):
        """
        BV: Explicit commands mapping prevents registry initialization.

        Scenario:
          Given: A resolver with explicit commands dict
          When: Resolutions are attempted
          Then: No registry is created
        """
        resolver = CommandResolver(commands={"my-cmd": MagicMock()})

        # Resolution should use explicit commands
        resolver.resolve_command_ref("my-cmd")
        resolver.resolve_command_ref("unknown")

        # Registry should never be initialized
        assert resolver._registry is None


# ==============================================================================
# Test: Registry Integration
# ==============================================================================


class TestRegistryIntegration:
    """Tests for integration with HybridCommandRegistry."""

    def test_resolver_with_registry(self):
        """
        BV: Resolver can use an explicit registry instance.

        Scenario:
          Given: A mock HybridCommandRegistry
          When: Resolver is created with that registry
          Then: Commands are resolved via registry
        """
        mock_registry = MagicMock()
        mock_registry.commands = {"reg-cmd": MagicMock()}
        mock_registry.get_command.return_value = MagicMock(id="reg-cmd")

        resolver = CommandResolver(registry=mock_registry)

        # First check explicit commands dict
        result = resolver.resolve_command_ref("reg-cmd")

        assert result is not None

    def test_registry_fallback_on_cache_miss(self):
        """
        BV: Registry is consulted for cache misses.

        Scenario:
          Given: A resolver with registry
          When: Command not in cache or explicit commands
          Then: Registry is consulted
        """
        mock_cmd = MagicMock(id="registry-cmd")
        mock_registry = MagicMock()
        mock_registry.commands = {}
        mock_registry.get_command.return_value = mock_cmd

        resolver = CommandResolver(registry=mock_registry)

        result = resolver.resolve_command_ref("registry-cmd")

        mock_registry.get_command.assert_called_with("registry-cmd")
        assert result is mock_cmd


# ==============================================================================
# Test: Edge Cases
# ==============================================================================


class TestResolverEdgeCases:
    """Edge case tests for command resolver."""

    def test_step_without_command_ref_key(self):
        """
        BV: Steps missing command_ref key are handled.

        Scenario:
          Given: A step dict without 'command_ref' key
          When: extract_command_refs() processes it
          Then: Step is skipped gracefully
        """
        chain = {
            "steps": [
                {"name": "No Command Ref"},
                {"command_ref": "valid-cmd"},
            ]
        }
        resolver = CommandResolver(commands={})

        refs = resolver.extract_command_refs(chain)

        assert refs == ["valid-cmd"]

    def test_step_with_non_string_command_ref(self):
        """
        BV: Non-string command_ref values are skipped.

        Scenario:
          Given: A step with command_ref: 123 (int)
          When: extract_command_refs() processes it
          Then: Non-string is skipped
        """
        chain = {
            "steps": [
                {"command_ref": 123},
                {"command_ref": ["not", "a", "string"]},
                {"command_ref": "valid"},
            ]
        }
        resolver = CommandResolver(commands={})

        refs = resolver.extract_command_refs(chain)

        assert refs == ["valid"]

    def test_chain_with_none_steps(self):
        """
        BV: Chain with steps: None is handled.

        Scenario:
          Given: A chain with steps: None
          When: extract_command_refs() is called
          Then: Empty list is returned
        """
        chain = {"steps": None}
        resolver = CommandResolver(commands={})

        refs = resolver.extract_command_refs(chain)

        assert refs == []


# ==============================================================================
# Test: Complex Chains
# ==============================================================================


class TestComplexChains:
    """Tests for complex multi-step chains."""

    def test_large_chain_extraction(self):
        """
        BV: Large chains with many steps are handled efficiently.

        Scenario:
          Given: A chain with 50 steps
          When: extract_command_refs() is called
          Then: All refs are extracted correctly
        """
        steps = [
            ChainFactory.create_step(command_ref=f"cmd-{i}") for i in range(50)
        ]
        chain = ChainFactory.create(steps=steps)
        resolver = CommandResolver(commands={})

        refs = resolver.extract_command_refs(chain)

        assert len(refs) == 50
        assert "cmd-0" in refs
        assert "cmd-49" in refs

    def test_chain_with_repeated_command_refs(self):
        """
        BV: Chains can reuse the same command in multiple steps.

        Scenario:
          Given: A chain where multiple steps use same command
          When: extract_command_refs() is called
          Then: All refs are returned (including duplicates)
        """
        chain = ChainFactory.create(
            steps=[
                ChainFactory.create_step(step_id="s1", command_ref="shared-cmd"),
                ChainFactory.create_step(step_id="s2", command_ref="shared-cmd"),
                ChainFactory.create_step(step_id="s3", command_ref="other-cmd"),
            ]
        )
        resolver = CommandResolver(commands={})

        refs = resolver.extract_command_refs(chain)

        assert refs == ["shared-cmd", "shared-cmd", "other-cmd"]

    def test_validate_chain_with_repeated_refs(self):
        """
        BV: Validation handles repeated refs efficiently.

        Scenario:
          Given: A chain with repeated command references
          When: validate_references() is called
          Then: Each unique ref is validated once
        """
        resolver = CommandResolver(
            commands={"shared-cmd": MagicMock(), "other-cmd": MagicMock()}
        )

        refs = ["shared-cmd", "shared-cmd", "other-cmd", "missing"]
        missing = resolver.validate_references(refs)

        assert len(missing) == 1
        assert "missing" in missing


# ==============================================================================
# Test: Integration with Chain Validation
# ==============================================================================


class TestChainValidationIntegration:
    """Integration tests for chain validation workflow."""

    def test_full_chain_validation_workflow(self):
        """
        BV: Complete chain can be validated end-to-end.

        Scenario:
          Given: A chain with multiple steps and some missing commands
          When: References are extracted and validated
          Then: All issues are identified
        """
        chain = ChainFactory.create(
            steps=[
                ChainFactory.create_step(step_id="s1", command_ref="known-cmd"),
                ChainFactory.create_step(step_id="s2", command_ref="missing-cmd"),
                ChainFactory.create_step(step_id="s3", command_ref="known-cmd"),
            ]
        )
        resolver = CommandResolver(commands={"known-cmd": MagicMock()})

        refs = resolver.extract_command_refs(chain)
        missing = resolver.validate_references(refs)

        assert len(missing) == 1
        assert "missing-cmd" in missing

    def test_resolve_and_validate_valid_chain(self):
        """
        BV: Valid chains pass both resolution and validation.

        Scenario:
          Given: A chain with all valid command references
          When: References are extracted and validated
          Then: No errors are reported
        """
        chain = ChainFactory.create(
            steps=[
                ChainFactory.create_step(command_ref="cmd-a"),
                ChainFactory.create_step(command_ref="cmd-b"),
            ]
        )
        resolver = CommandResolver(
            commands={
                "cmd-a": MagicMock(id="cmd-a"),
                "cmd-b": MagicMock(id="cmd-b"),
            }
        )

        refs = resolver.extract_command_refs(chain)
        missing = resolver.validate_references(refs)

        # All valid
        assert missing == {}

        # All resolvable
        for ref in refs:
            assert resolver.resolve_command_ref(ref) is not None
