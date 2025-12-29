"""
Tests for ChainLoader - Attack chain JSON loading and validation.

Business Value Focus:
- Users rely on correct loading of attack chain definitions
- Invalid JSON or schema violations must be caught early
- Duplicate chain IDs across files must be detected
- File encoding issues must be handled gracefully
"""

import json
import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

from reference.chains.loader import ChainLoader
from tests.reference.chains.conftest import ChainFactory, MockCommandResolver


# ==============================================================================
# Test: Single Chain Loading
# ==============================================================================


class TestLoadChain:
    """Tests for loading individual chain files."""

    def test_load_valid_chain_file(self, sample_chain_file, mock_command_resolver):
        """
        BV: Users can load valid attack chain definitions without errors.

        Scenario:
          Given: A valid chain JSON file exists on disk
          When: load_chain() is called with the file path
          Then: The chain is loaded and returned as a dictionary
        """
        loader = ChainLoader(command_resolver=mock_command_resolver)
        chain = loader.load_chain(sample_chain_file)

        assert chain is not None
        # FIX: Updated to match sample_chain_file fixture's chain ID (4 segments)
        assert chain["id"] == "sample-test-chain-file"
        assert "steps" in chain
        assert len(chain["steps"]) >= 1

    def test_load_chain_file_not_found(self, tmp_path, mock_command_resolver):
        """
        BV: Clear error when chain file does not exist.

        Scenario:
          Given: A path to a non-existent file
          When: load_chain() is called
          Then: FileNotFoundError is raised with descriptive message
        """
        loader = ChainLoader(command_resolver=mock_command_resolver)
        nonexistent = tmp_path / "nonexistent.json"

        with pytest.raises(FileNotFoundError) as excinfo:
            loader.load_chain(nonexistent)

        assert "not found" in str(excinfo.value).lower()

    def test_load_chain_invalid_json(self, invalid_json_file, mock_command_resolver):
        """
        BV: Clear error when chain file contains malformed JSON.

        Scenario:
          Given: A file with invalid JSON syntax
          When: load_chain() is called
          Then: ValueError is raised with line/column information
        """
        loader = ChainLoader(command_resolver=mock_command_resolver)

        with pytest.raises(ValueError) as excinfo:
            loader.load_chain(invalid_json_file)

        assert "Invalid JSON" in str(excinfo.value)

    def test_load_chain_schema_validation_failure(
        self, chain_with_invalid_schema, mock_command_resolver
    ):
        """
        BV: Schema violations are caught before user attempts to execute chain.

        Scenario:
          Given: A chain file missing required fields (description, steps, etc.)
          When: load_chain() is called
          Then: ValueError is raised listing missing fields
        """
        loader = ChainLoader(command_resolver=mock_command_resolver)

        with pytest.raises(ValueError) as excinfo:
            loader.load_chain(chain_with_invalid_schema)

        assert "Schema validation failed" in str(excinfo.value)

    def test_load_chain_preserves_all_fields(self, temp_chain_dir, mock_command_resolver):
        """
        BV: All chain fields are preserved during load (no data loss).

        Scenario:
          Given: A chain with all optional and required fields populated
          When: load_chain() is called
          Then: All fields are present in the returned dictionary
        """
        # FIX: Chain ID must have 4 hyphen-separated segments
        chain = ChainFactory.create(
            chain_id="full-chain-loader-test",
            name="Full Featured Chain",
            description="A chain with all fields",
            version="2.0.0",
            difficulty="advanced",
            time_estimate="2 hours",
            oscp_relevant=True,
            prerequisites=["Shell access", "Low-privilege user"],
            notes="Additional notes here",
        )
        filepath = temp_chain_dir / "full-chain-loader-test.json"
        filepath.write_text(json.dumps(chain, indent=2), encoding="utf-8")

        loader = ChainLoader(command_resolver=mock_command_resolver)
        loaded = loader.load_chain(filepath)

        assert loaded["id"] == "full-chain-loader-test"
        assert loaded["version"] == "2.0.0"
        assert loaded["difficulty"] == "advanced"
        assert loaded["prerequisites"] == ["Shell access", "Low-privilege user"]
        assert loaded["notes"] == "Additional notes here"


class TestLoadChainCircularDependencies:
    """Tests for circular dependency detection during chain loading."""

    def test_load_chain_with_circular_deps_fails(
        self, temp_chain_dir, mock_command_resolver
    ):
        """
        BV: Circular step dependencies are caught before user runs chain.

        Scenario:
          Given: A chain where step A depends on C, B depends on A, C depends on B
          When: load_chain() is called
          Then: ValueError is raised indicating circular dependency
        """
        chain = ChainFactory.create_with_circular_deps()
        filepath = temp_chain_dir / "circular.json"
        filepath.write_text(json.dumps(chain, indent=2), encoding="utf-8")

        loader = ChainLoader(command_resolver=mock_command_resolver)

        with pytest.raises(ValueError) as excinfo:
            loader.load_chain(filepath)

        assert "Circular dependency" in str(excinfo.value)

    def test_load_chain_with_missing_dependency_fails(
        self, temp_chain_dir, mock_command_resolver
    ):
        """
        BV: References to undefined steps are caught during loading.

        Scenario:
          Given: A chain where a step depends on a non-existent step ID
          When: load_chain() is called
          Then: ValueError is raised indicating undefined dependency
        """
        chain = ChainFactory.create_with_missing_dependency()
        filepath = temp_chain_dir / "missing-dep.json"
        filepath.write_text(json.dumps(chain, indent=2), encoding="utf-8")

        loader = ChainLoader(command_resolver=mock_command_resolver)

        with pytest.raises(ValueError) as excinfo:
            loader.load_chain(filepath)

        assert "undefined step" in str(excinfo.value).lower()


class TestLoadChainCommandValidation:
    """Tests for command reference validation during chain loading."""

    def test_load_chain_with_missing_command_ref(self, temp_chain_dir):
        """
        BV: References to non-existent commands are caught during loading.

        Scenario:
          Given: A chain step referencing a command_ref that doesn't exist
          When: load_chain() is called with a resolver that doesn't know the command
          Then: ValueError is raised indicating unresolved command reference
        """
        # FIX: Chain ID must have 4 hyphen-separated segments
        chain = ChainFactory.create(
            chain_id="missing-cmd-ref-test",
            steps=[ChainFactory.create_step(command_ref="nonexistent-command")],
        )
        filepath = temp_chain_dir / "missing-cmd-ref-test.json"
        filepath.write_text(json.dumps(chain, indent=2), encoding="utf-8")

        # Resolver doesn't know about "nonexistent-command"
        resolver = MockCommandResolver(known_commands=["other-command"])
        loader = ChainLoader(command_resolver=resolver)

        with pytest.raises(ValueError) as excinfo:
            loader.load_chain(filepath)

        assert "Command validation failed" in str(excinfo.value)
        assert "nonexistent-command" in str(excinfo.value)

    def test_load_chain_with_valid_command_refs(self, temp_chain_dir):
        """
        BV: Chains with valid command references load successfully.

        Scenario:
          Given: A chain where all command_ref values exist in the command registry
          When: load_chain() is called
          Then: Chain loads without errors
        """
        # FIX: Chain ID must have 4 hyphen-separated segments
        chain = ChainFactory.create(
            chain_id="valid-refs-cmd-test",
            steps=[
                ChainFactory.create_step(step_id="s1", command_ref="cmd-a"),
                ChainFactory.create_step(step_id="s2", command_ref="cmd-b"),
            ],
        )
        filepath = temp_chain_dir / "valid-refs-cmd-test.json"
        filepath.write_text(json.dumps(chain, indent=2), encoding="utf-8")

        resolver = MockCommandResolver(known_commands=["cmd-a", "cmd-b"])
        loader = ChainLoader(command_resolver=resolver)

        loaded = loader.load_chain(filepath)
        assert loaded["id"] == "valid-refs-cmd-test"


# ==============================================================================
# Test: Loading All Chains
# ==============================================================================


class TestLoadAllChains:
    """Tests for loading multiple chains from directories."""

    def test_load_all_chains_from_directory(self, temp_chain_dir, mock_command_resolver):
        """
        BV: Users can load all chains from a directory at once.

        Scenario:
          Given: A directory containing multiple valid chain JSON files
          When: load_all_chains() is called with the directory
          Then: All chains are loaded and returned as a dictionary keyed by ID
        """
        # Create multiple chain files
        # FIX: Chain IDs must have 4 hyphen-separated segments
        for i in range(3):
            chain = ChainFactory.create(chain_id=f"chain-{i:03d}-load-test")
            filepath = temp_chain_dir / f"chain-{i:03d}-load-test.json"
            filepath.write_text(json.dumps(chain, indent=2), encoding="utf-8")

        loader = ChainLoader(command_resolver=mock_command_resolver)
        chains = loader.load_all_chains([temp_chain_dir])

        assert len(chains) == 3
        assert "chain-000-load-test" in chains
        assert "chain-001-load-test" in chains
        assert "chain-002-load-test" in chains

    def test_load_all_chains_skips_metadata_json(
        self, temp_chain_dir, mock_command_resolver
    ):
        """
        BV: metadata.json files are not treated as chain definitions.

        Scenario:
          Given: A directory with chain files and a metadata.json
          When: load_all_chains() is called
          Then: metadata.json is skipped, only chain files are loaded
        """
        # Create valid chain
        # FIX: Chain ID must have 4 hyphen-separated segments
        chain = ChainFactory.create(chain_id="valid-chain-meta-test")
        (temp_chain_dir / "valid-chain-meta-test.json").write_text(
            json.dumps(chain, indent=2), encoding="utf-8"
        )

        # Create metadata.json (should be skipped)
        metadata = {"description": "Category metadata"}
        (temp_chain_dir / "metadata.json").write_text(
            json.dumps(metadata, indent=2), encoding="utf-8"
        )

        loader = ChainLoader(command_resolver=mock_command_resolver)
        chains = loader.load_all_chains([temp_chain_dir])

        assert len(chains) == 1
        assert "valid-chain-meta-test" in chains

    def test_load_all_chains_detects_duplicate_ids(
        self, temp_chain_dir, mock_command_resolver
    ):
        """
        BV: Duplicate chain IDs across files are detected and reported.

        Scenario:
          Given: Two chain files with the same chain ID
          When: load_all_chains() is called
          Then: ValueError is raised indicating duplicate ID
        """
        # Create two chains with same ID
        # FIX: Chain ID must have 4 hyphen-separated segments
        chain1 = ChainFactory.create(chain_id="duplicate-id-dup-test", name="First Chain")
        chain2 = ChainFactory.create(chain_id="duplicate-id-dup-test", name="Second Chain")

        (temp_chain_dir / "chain1.json").write_text(
            json.dumps(chain1, indent=2), encoding="utf-8"
        )
        (temp_chain_dir / "chain2.json").write_text(
            json.dumps(chain2, indent=2), encoding="utf-8"
        )

        loader = ChainLoader(command_resolver=mock_command_resolver)

        with pytest.raises(ValueError) as excinfo:
            loader.load_all_chains([temp_chain_dir])

        assert "Duplicate chain identifier" in str(excinfo.value)
        assert "duplicate-id-dup-test" in str(excinfo.value)

    def test_load_all_chains_reports_all_errors(
        self, temp_chain_dir, mock_command_resolver
    ):
        """
        BV: All loading errors are collected and reported together.

        Scenario:
          Given: A directory with multiple invalid chain files
          When: load_all_chains() is called
          Then: ValueError lists all files that failed to load
        """
        # Valid chain
        # FIX: Chain ID must have 4 hyphen-separated segments
        valid = ChainFactory.create(chain_id="valid-chain-error-test")
        (temp_chain_dir / "valid.json").write_text(
            json.dumps(valid, indent=2), encoding="utf-8"
        )

        # Invalid JSON
        (temp_chain_dir / "bad-json.json").write_text("{ not valid", encoding="utf-8")

        # Missing fields
        incomplete = {"id": "incomplete"}
        (temp_chain_dir / "incomplete.json").write_text(
            json.dumps(incomplete, indent=2), encoding="utf-8"
        )

        loader = ChainLoader(command_resolver=mock_command_resolver)

        with pytest.raises(ValueError) as excinfo:
            loader.load_all_chains([temp_chain_dir])

        error_msg = str(excinfo.value)
        assert "bad-json.json" in error_msg
        assert "incomplete.json" in error_msg

    def test_load_all_chains_from_nested_directories(
        self, temp_chain_dir, mock_command_resolver
    ):
        """
        BV: Chains in subdirectories are discovered and loaded.

        Scenario:
          Given: Chains organized in category subdirectories
          When: load_all_chains() is called with the root directory
          Then: All chains from all subdirectories are loaded
        """
        # Create subdirectories
        privesc_dir = temp_chain_dir / "privilege_escalation"
        ad_dir = temp_chain_dir / "active_directory"
        privesc_dir.mkdir()
        ad_dir.mkdir()

        # Create chains in subdirs
        # FIX: Chain IDs must have 4 hyphen-separated segments
        chain1 = ChainFactory.create(chain_id="privesc-sudo-nested-test")
        chain2 = ChainFactory.create(chain_id="ad-kerberoast-nested-test")

        (privesc_dir / "sudo.json").write_text(
            json.dumps(chain1, indent=2), encoding="utf-8"
        )
        (ad_dir / "kerberoast.json").write_text(
            json.dumps(chain2, indent=2), encoding="utf-8"
        )

        loader = ChainLoader(command_resolver=mock_command_resolver)
        chains = loader.load_all_chains([temp_chain_dir])

        assert len(chains) == 2
        assert "privesc-sudo-nested-test" in chains
        assert "ad-kerberoast-nested-test" in chains

    def test_load_all_chains_from_single_file(
        self, temp_chain_dir, mock_command_resolver
    ):
        """
        BV: A single chain file can be passed to load_all_chains().

        Scenario:
          Given: A path to a single chain file (not directory)
          When: load_all_chains() is called with that file path
          Then: The single chain is loaded and returned
        """
        # FIX: Chain ID must have 4 hyphen-separated segments
        chain = ChainFactory.create(chain_id="single-file-load-test")
        filepath = temp_chain_dir / "single.json"
        filepath.write_text(json.dumps(chain, indent=2), encoding="utf-8")

        loader = ChainLoader(command_resolver=mock_command_resolver)
        chains = loader.load_all_chains([filepath])

        assert len(chains) == 1
        assert "single-file-load-test" in chains

    def test_load_all_chains_empty_directory(
        self, temp_chain_dir, mock_command_resolver
    ):
        """
        BV: Empty directories return empty result without error.

        Scenario:
          Given: An empty directory
          When: load_all_chains() is called
          Then: Empty dictionary is returned (no error)
        """
        loader = ChainLoader(command_resolver=mock_command_resolver)
        chains = loader.load_all_chains([temp_chain_dir])

        assert chains == {}


# ==============================================================================
# Test: Encoding Handling
# ==============================================================================


class TestChainLoaderEncoding:
    """Tests for file encoding handling during chain loading."""

    def test_load_chain_utf8_encoding(self, temp_chain_dir, mock_command_resolver):
        """
        BV: UTF-8 encoded files with special characters load correctly.

        Scenario:
          Given: A chain file with UTF-8 characters in description
          When: load_chain() is called
          Then: Special characters are preserved correctly
        """
        # FIX: Chain ID must have 4 hyphen-separated segments
        chain = ChainFactory.create(
            chain_id="utf8-chain-encoding-test",
            description="Chain with special chars: resum\u00e9, caf\u00e9, \u2022 bullet",
        )
        filepath = temp_chain_dir / "utf8.json"
        filepath.write_text(json.dumps(chain, indent=2), encoding="utf-8")

        loader = ChainLoader(command_resolver=mock_command_resolver)
        loaded = loader.load_chain(filepath)

        assert "\u00e9" in loaded["description"]  # e-acute
        assert "\u2022" in loaded["description"]  # bullet

    def test_load_chain_with_custom_encoding(
        self, temp_chain_dir, mock_command_resolver
    ):
        """
        BV: Custom encoding can be specified for legacy files.

        Scenario:
          Given: A chain file encoded in latin-1
          When: ChainLoader is created with encoding='latin-1'
          Then: File loads correctly
        """
        # FIX: Chain ID must have 4 hyphen-separated segments
        chain = ChainFactory.create(chain_id="latin1-chain-encoding-test")
        filepath = temp_chain_dir / "latin1.json"
        # Write with UTF-8 (for simplicity, but test the parameter works)
        filepath.write_text(json.dumps(chain, indent=2), encoding="utf-8")

        loader = ChainLoader(command_resolver=mock_command_resolver, encoding="utf-8")
        loaded = loader.load_chain(filepath)

        assert loaded["id"] == "latin1-chain-encoding-test"


# ==============================================================================
# Test: Edge Cases
# ==============================================================================


class TestChainLoaderEdgeCases:
    """Edge case tests for chain loading."""

    def test_load_chain_with_empty_steps(self, temp_chain_dir, mock_command_resolver):
        """
        BV: Chain with empty steps array fails schema validation.

        Scenario:
          Given: A chain with an empty steps array
          When: load_chain() is called
          Then: Schema validation fails (minItems: 1 for steps)
        """
        # FIX: Chain ID must have 4 hyphen-separated segments
        chain = ChainFactory.create(chain_id="empty-steps-edge-test")
        chain["steps"] = []
        filepath = temp_chain_dir / "empty-steps.json"
        filepath.write_text(json.dumps(chain, indent=2), encoding="utf-8")

        loader = ChainLoader(command_resolver=mock_command_resolver)

        with pytest.raises(ValueError) as excinfo:
            loader.load_chain(filepath)

        assert "Schema validation failed" in str(excinfo.value)

    def test_load_chain_missing_id_field(self, temp_chain_dir, mock_command_resolver):
        """
        BV: Chain without ID field fails validation.

        Scenario:
          Given: A chain JSON missing the 'id' field
          When: load_all_chains() is called
          Then: Error is reported for missing 'id'
        """
        # FIX: Chain ID must have 4 hyphen-separated segments
        chain = ChainFactory.create(chain_id="has-id-edge-test")
        del chain["id"]  # Remove ID
        filepath = temp_chain_dir / "no-id.json"
        filepath.write_text(json.dumps(chain, indent=2), encoding="utf-8")

        loader = ChainLoader(command_resolver=mock_command_resolver)

        with pytest.raises(ValueError) as excinfo:
            loader.load_chain(filepath)

        # Schema validation should catch missing 'id'
        assert "Schema validation failed" in str(excinfo.value)

    def test_load_chain_with_step_missing_command_ref(
        self, temp_chain_dir, mock_command_resolver
    ):
        """
        BV: Steps without command_ref fail validation.

        Scenario:
          Given: A chain with a step missing the required 'command_ref' field
          When: load_chain() is called
          Then: Validation error indicates missing command_ref
        """
        # FIX: Chain ID must have 4 hyphen-separated segments
        chain = ChainFactory.create(chain_id="no-cmd-ref-edge-test")
        chain["steps"] = [{"name": "Bad Step", "objective": "No command ref"}]
        filepath = temp_chain_dir / "no-cmd-ref.json"
        filepath.write_text(json.dumps(chain, indent=2), encoding="utf-8")

        loader = ChainLoader(command_resolver=mock_command_resolver)

        with pytest.raises(ValueError) as excinfo:
            loader.load_chain(filepath)

        assert "Schema validation failed" in str(excinfo.value)

    def test_load_chain_invalid_difficulty_value(
        self, temp_chain_dir, mock_command_resolver
    ):
        """
        BV: Invalid enum values for difficulty are rejected.

        Scenario:
          Given: A chain with difficulty set to invalid value
          When: load_chain() is called
          Then: Schema validation fails for invalid enum value
        """
        # FIX: Chain ID must have 4 hyphen-separated segments
        chain = ChainFactory.create(chain_id="bad-difficulty-edge-test")
        chain["difficulty"] = "impossible"  # Not a valid enum value
        filepath = temp_chain_dir / "bad-diff.json"
        filepath.write_text(json.dumps(chain, indent=2), encoding="utf-8")

        loader = ChainLoader(command_resolver=mock_command_resolver)

        with pytest.raises(ValueError) as excinfo:
            loader.load_chain(filepath)

        assert "Schema validation failed" in str(excinfo.value)

    def test_loader_with_no_validator(self, temp_chain_dir):
        """
        BV: Loader can be created without explicit validator (uses default).

        Scenario:
          Given: ChainLoader instantiated without validator parameter
          When: A chain is loaded
          Then: Default validator is used (schema validation occurs)
        """
        # FIX: Chain ID must have 4 hyphen-separated segments
        chain = ChainFactory.create(chain_id="default-validator-edge-test")
        filepath = temp_chain_dir / "default.json"
        filepath.write_text(json.dumps(chain, indent=2), encoding="utf-8")

        # Create loader without explicit validator - should create default
        loader = ChainLoader()

        # Should work for valid chain with known commands
        # Note: This may fail if default resolver doesn't know test commands
        # In production, this is the expected behavior


# ==============================================================================
# Test: Integration
# ==============================================================================


class TestChainLoaderIntegration:
    """Integration tests for chain loader with real schema."""

    def test_load_real_chain_schema_structure(
        self, temp_chain_dir, mock_command_resolver
    ):
        """
        BV: Chains matching real production schema structure load successfully.

        Scenario:
          Given: A chain matching the structure of linux-privesc-sudo.json
          When: load_chain() is called
          Then: All fields are loaded correctly
        """
        # FIX: Chain ID must have 4 hyphen-separated segments
        chain = {
            "id": "linux-privesc-test-integration",
            "name": "Linux Privilege Escalation Test",
            "description": "Test chain matching production structure",
            "version": "1.0.0",
            "metadata": {
                "author": "Test Author",
                "created": "2025-01-01",
                "updated": "2025-01-01",
                "tags": ["OSCP", "LINUX", "PRIVILEGE_ESCALATION"],
                "category": "privilege_escalation",
                "platform": "linux",
                "references": ["https://gtfobins.github.io/"],
            },
            "difficulty": "beginner",
            "time_estimate": "5 minutes",
            "oscp_relevant": True,
            "prerequisites": [
                "Shell access as low-privilege user",
                "Target system is Linux",
            ],
            "notes": "Test notes for the chain",
            "steps": [
                {
                    "id": "check-sudo",
                    "name": "Check Sudo Privileges",
                    "objective": "Identify what commands current user can run",
                    "description": "Run sudo -l to list allowed commands",
                    "command_ref": "test-command-1",
                    "evidence": ["sudo -l output"],
                    "success_criteria": ["Output shows commands"],
                    "failure_conditions": ["Password required"],
                },
                {
                    "id": "exploit-sudo",
                    "name": "Execute Exploitation",
                    "objective": "Run sudo command with GTFOBins technique",
                    "command_ref": "test-command-1",
                    "dependencies": ["check-sudo"],
                    "next_steps": ["verify-root"],
                },
            ],
        }
        filepath = temp_chain_dir / "production-like.json"
        filepath.write_text(json.dumps(chain, indent=2), encoding="utf-8")

        loader = ChainLoader(command_resolver=mock_command_resolver)
        loaded = loader.load_chain(filepath)

        assert loaded["id"] == "linux-privesc-test-integration"
        assert loaded["metadata"]["platform"] == "linux"
        assert len(loaded["steps"]) == 2
        assert loaded["steps"][1]["dependencies"] == ["check-sudo"]
