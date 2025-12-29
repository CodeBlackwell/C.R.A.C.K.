"""
Tests for ChainSession - Session persistence and state management.

Business Value Focus:
- Users can resume multi-step attack chains after interruption
- Progress and variables are preserved across restarts
- Session files are stored safely and don't corrupt
- Cross-chain activation history is tracked
"""

import json
import pytest
from pathlib import Path
from datetime import datetime
from unittest.mock import patch, MagicMock

from reference.chains.session_storage import ChainSession
from tests.reference.chains.conftest import SessionFactory


# ==============================================================================
# Test: Session Creation
# ==============================================================================


class TestSessionCreation:
    """Tests for creating new chain sessions."""

    def test_create_session_with_defaults(self):
        """
        BV: New sessions start with correct initial state.

        Scenario:
          Given: Chain ID and target IP
          When: ChainSession is created
          Then: Session has correct defaults (step 0, empty progress)
        """
        session = ChainSession("linux-privesc-sudo", "192.168.1.100")

        assert session.chain_id == "linux-privesc-sudo"
        assert session.target == "192.168.1.100"
        assert session.current_step_index == 0
        assert session.completed_steps == []
        assert session.variables == {}
        assert session.format_version == "2.0"

    def test_create_session_sets_timestamps(self):
        """
        BV: Sessions track when they were started and last updated.

        Scenario:
          Given: A new session is created
          When: Checking timestamps
          Then: Started and updated are set to current time
        """
        session = ChainSession("test-chain", "10.10.10.1")

        assert session.started is not None
        assert session.updated is not None
        # Started and updated should be equal for new session
        assert session.started == session.updated


# ==============================================================================
# Test: Step Progress
# ==============================================================================


class TestStepProgress:
    """Tests for tracking step completion."""

    def test_mark_step_complete(self, sample_session):
        """
        BV: Completed steps are tracked for resume functionality.

        Scenario:
          Given: A session with no completed steps
          When: mark_step_complete() is called
          Then: Step is added to completed_steps list
        """
        sample_session.mark_step_complete("step-1")

        assert "step-1" in sample_session.completed_steps
        assert len(sample_session.completed_steps) == 1

    def test_mark_step_complete_with_output(self, sample_session):
        """
        BV: Command output is preserved for debugging and reporting.

        Scenario:
          Given: A session
          When: mark_step_complete() is called with output
          Then: Output is stored in step_outputs
        """
        output = "uid=0(root) gid=0(root)"
        sample_session.mark_step_complete("verify-root", output=output)

        assert sample_session.step_outputs["verify-root"] == output

    def test_mark_step_complete_no_duplicates(self, sample_session):
        """
        BV: Marking same step complete twice doesn't duplicate entry.

        Scenario:
          Given: A step already marked complete
          When: mark_step_complete() is called again for same step
          Then: Step appears only once in completed_steps
        """
        sample_session.mark_step_complete("step-1")
        sample_session.mark_step_complete("step-1")

        assert sample_session.completed_steps.count("step-1") == 1

    def test_advance_step(self, sample_session):
        """
        BV: Users can advance to next step in chain.

        Scenario:
          Given: Session at step 0
          When: advance_step() is called
          Then: current_step_index increments to 1
        """
        assert sample_session.current_step_index == 0
        sample_session.advance_step()
        assert sample_session.current_step_index == 1

    def test_advance_step_updates_timestamp(self, sample_session):
        """
        BV: Progress changes update the 'updated' timestamp.

        Scenario:
          Given: A session with a known updated timestamp
          When: advance_step() is called
          Then: Updated timestamp changes
        """
        original_updated = sample_session.updated
        sample_session.advance_step()

        assert sample_session.updated != original_updated


# ==============================================================================
# Test: Variable Management
# ==============================================================================


class TestVariableManagement:
    """Tests for session-scoped variable storage."""

    def test_add_variables(self, sample_session):
        """
        BV: Discovered values can be stored for use in later steps.

        Scenario:
          Given: A session with no variables
          When: add_variables() is called
          Then: Variables are stored and accessible
        """
        sample_session.add_variables({"<TARGET>": "192.168.1.100", "<PORT>": "22"})

        assert sample_session.variables["<TARGET>"] == "192.168.1.100"
        assert sample_session.variables["<PORT>"] == "22"

    def test_add_variables_overwrites_existing(self, sample_session):
        """
        BV: Variable updates overwrite previous values.

        Scenario:
          Given: A session with existing variable
          When: add_variables() is called with same key
          Then: Variable value is updated
        """
        sample_session.add_variables({"<PORT>": "22"})
        sample_session.add_variables({"<PORT>": "443"})

        assert sample_session.variables["<PORT>"] == "443"

    def test_store_step_findings(self, sample_session):
        """
        BV: Parser findings are stored per step for reference.

        Scenario:
          Given: Parser output with findings
          When: store_step_findings() is called
          Then: Findings are retrievable by step ID
        """
        findings = {
            "exploitable_binaries": ["/usr/bin/find", "/usr/bin/vim"],
            "standard_binaries": ["/usr/bin/passwd"],
        }
        sample_session.store_step_findings("suid-scan", findings)

        retrieved = sample_session.get_step_findings("suid-scan")
        assert retrieved == findings

    def test_store_step_variables(self, sample_session):
        """
        BV: Step-specific variables are stored separately from session vars.

        Scenario:
          Given: Variables extracted from a specific step
          When: store_step_variables() is called
          Then: Variables are retrievable by step ID
        """
        step_vars = {"<SUDO_BINARY>": "find", "<SUDO_COMMAND>": "/usr/bin/find"}
        sample_session.store_step_variables("check-sudo", step_vars)

        retrieved = sample_session.get_step_variables("check-sudo")
        assert retrieved == step_vars

    def test_get_step_variables_missing_returns_empty(self, sample_session):
        """
        BV: Missing step variables return empty dict (no error).

        Scenario:
          Given: A session with no variables for a step
          When: get_step_variables() is called for that step
          Then: Empty dictionary is returned
        """
        result = sample_session.get_step_variables("nonexistent-step")
        assert result == {}


# ==============================================================================
# Test: Cross-Chain Activation
# ==============================================================================


class TestCrossChainActivation:
    """Tests for cross-chain activation tracking."""

    def test_add_activation(self, sample_session):
        """
        BV: Chain activations are tracked for workflow debugging.

        Scenario:
          Given: A session for chain-a
          When: add_activation() records transition to chain-b
          Then: Activation is recorded in history
        """
        sample_session.add_activation("chain-a", "chain-b", reason="SUID found")

        assert len(sample_session.activation_history) == 1
        activation = sample_session.activation_history[0]
        assert activation["from_chain"] == "chain-a"
        assert activation["to_chain"] == "chain-b"
        assert activation["reason"] == "SUID found"

    def test_get_activation_chain_empty(self, sample_session):
        """
        BV: Fresh session shows only the initial chain.

        Scenario:
          Given: A session with no activations
          When: get_activation_chain() is called
          Then: Returns list with just the current chain
        """
        chain = sample_session.get_activation_chain()

        assert chain == ["test-chain"]

    def test_get_activation_chain_with_history(self, sample_session):
        """
        BV: Activation path shows full chain traversal.

        Scenario:
          Given: Session with multiple chain activations
          When: get_activation_chain() is called
          Then: Returns ordered list of all chains visited
        """
        sample_session.add_activation("test-chain", "chain-b", "Found SUID")
        sample_session.add_activation("chain-b", "chain-c", "Found sudo")

        chain = sample_session.get_activation_chain()

        assert chain == ["test-chain", "chain-b", "chain-c"]


# ==============================================================================
# Test: Persistence (Save/Load)
# ==============================================================================


class TestSessionPersistence:
    """Tests for saving and loading sessions."""

    def test_save_session(self, temp_session_dir, sample_session):
        """
        BV: Session state is persisted to disk for resume.

        Scenario:
          Given: A session with progress
          When: save() is called
          Then: Session file is created in correct location
        """
        sample_session.mark_step_complete("step-1", output="test output")
        sample_session.add_variables({"<TARGET>": "192.168.1.100"})
        sample_session.save()

        # Check file exists
        expected_file = (
            temp_session_dir / "test-chain-192_168_1_100.json"
        )
        assert expected_file.exists()

        # Verify content
        with open(expected_file) as f:
            data = json.load(f)
        assert data["chain_id"] == "test-chain"
        assert "step-1" in data["completed_steps"]

    def test_load_session(self, temp_session_dir, sample_session):
        """
        BV: Saved sessions can be loaded to resume work.

        Scenario:
          Given: A saved session file
          When: ChainSession.load() is called
          Then: Session state is restored correctly
        """
        # Save session with progress
        sample_session.current_step_index = 2
        sample_session.completed_steps = ["step-1", "step-2"]
        sample_session.variables = {"<USER>": "admin"}
        sample_session.save()

        # Load it back
        loaded = ChainSession.load("test-chain", "192.168.1.100")

        assert loaded is not None
        assert loaded.current_step_index == 2
        assert loaded.completed_steps == ["step-1", "step-2"]
        assert loaded.variables["<USER>"] == "admin"

    def test_load_nonexistent_session_returns_none(self, temp_session_dir):
        """
        BV: Loading non-existent session returns None (no error).

        Scenario:
          Given: No session file exists for chain/target
          When: ChainSession.load() is called
          Then: None is returned
        """
        result = ChainSession.load("nonexistent-chain", "1.2.3.4")
        assert result is None

    def test_session_exists_true(self, temp_session_dir, sample_session):
        """
        BV: Users can check if a session exists before loading.

        Scenario:
          Given: A saved session
          When: ChainSession.exists() is called
          Then: Returns True
        """
        sample_session.save()

        assert ChainSession.exists("test-chain", "192.168.1.100")

    def test_session_exists_false(self, temp_session_dir):
        """
        BV: exists() returns False for non-existent sessions.

        Scenario:
          Given: No session file
          When: ChainSession.exists() is called
          Then: Returns False
        """
        assert not ChainSession.exists("no-such-chain", "1.1.1.1")

    def test_delete_session(self, temp_session_dir, sample_session):
        """
        BV: Users can delete completed sessions to clean up.

        Scenario:
          Given: A saved session
          When: delete() is called
          Then: Session file is removed
        """
        sample_session.save()
        assert ChainSession.exists("test-chain", "192.168.1.100")

        sample_session.delete()
        assert not ChainSession.exists("test-chain", "192.168.1.100")


# ==============================================================================
# Test: Target Sanitization
# ==============================================================================


class TestTargetSanitization:
    """Tests for target name sanitization in filenames."""

    def test_target_with_dots_sanitized(self, temp_session_dir):
        """
        BV: IP addresses are safely converted to valid filenames.

        Scenario:
          Given: A target IP like 192.168.1.100
          When: Session is saved
          Then: Filename uses underscores: 192_168_1_100
        """
        session = ChainSession("test-chain", "192.168.1.100")
        session.save()

        expected_file = temp_session_dir / "test-chain-192_168_1_100.json"
        assert expected_file.exists()

    def test_target_with_colons_sanitized(self, temp_session_dir):
        """
        BV: IPv6 addresses are safely converted to valid filenames.

        Scenario:
          Given: A target with colons (IPv6 or port notation)
          When: Session is saved
          Then: Colons are replaced with underscores
        """
        session = ChainSession("test-chain", "::1")
        session.save()

        expected_file = temp_session_dir / "test-chain-__1.json"
        assert expected_file.exists()


# ==============================================================================
# Test: Version Migration
# ==============================================================================


class TestVersionMigration:
    """Tests for session format version migration."""

    def test_load_v1_session_migrates_to_v2(self, temp_session_dir):
        """
        BV: Old session files are automatically upgraded.

        Scenario:
          Given: A v1.0 format session file (no activation_history)
          When: ChainSession.load() is called
          Then: Session is migrated to v2.0 with empty activation_history
        """
        # Create v1.0 format file manually
        v1_data = {
            "chain_id": "old-chain",
            "target": "10.0.0.1",
            "current_step_index": 1,
            "completed_steps": ["step-1"],
            "variables": {"<TARGET>": "10.0.0.1"},
            "step_outputs": {},
            "step_findings": {},
            "step_variables": {},
            "started": "2025-01-01T00:00:00",
            "updated": "2025-01-01T00:00:00",
            # Note: No activation_history or format_version (v1.0)
        }
        session_file = temp_session_dir / "old-chain-10_0_0_1.json"
        with open(session_file, "w") as f:
            json.dump(v1_data, f)

        # Load should migrate
        loaded = ChainSession.load("old-chain", "10.0.0.1")

        assert loaded is not None
        assert loaded.format_version == "2.0"
        assert loaded.activation_history == []
        assert loaded.completed_steps == ["step-1"]

    def test_migrate_v1_to_v2_preserves_data(self, temp_session_dir):
        """
        BV: Migration preserves all existing session data.

        Scenario:
          Given: A v1.0 session with progress and variables
          When: Loaded and migrated
          Then: All original data is preserved
        """
        v1_data = {
            "chain_id": "migrate-test",
            "target": "1.2.3.4",
            "current_step_index": 3,
            "completed_steps": ["s1", "s2", "s3"],
            "variables": {"<A>": "1", "<B>": "2"},
            "step_outputs": {"s1": "output1"},
            "step_findings": {"s2": {"finding": "value"}},
            "step_variables": {"s3": {"<X>": "y"}},
            "started": "2025-01-01T00:00:00",
            "updated": "2025-01-02T00:00:00",
        }
        session_file = temp_session_dir / "migrate-test-1_2_3_4.json"
        with open(session_file, "w") as f:
            json.dump(v1_data, f)

        loaded = ChainSession.load("migrate-test", "1.2.3.4")

        assert loaded.current_step_index == 3
        assert loaded.completed_steps == ["s1", "s2", "s3"]
        assert loaded.variables == {"<A>": "1", "<B>": "2"}
        assert loaded.step_outputs == {"s1": "output1"}


# ==============================================================================
# Test: Error Handling
# ==============================================================================


class TestSessionErrorHandling:
    """Tests for error handling in session storage."""

    def test_load_corrupted_json_returns_none(self, temp_session_dir):
        """
        BV: Corrupted session files don't crash, return None.

        Scenario:
          Given: A session file with invalid JSON
          When: ChainSession.load() is called
          Then: None is returned (session treated as non-existent)
        """
        session_file = temp_session_dir / "corrupt-chain-1_1_1_1.json"
        session_file.write_text("{ not valid json }", encoding="utf-8")

        result = ChainSession.load("corrupt-chain", "1.1.1.1")
        assert result is None

    def test_load_missing_key_returns_none(self, temp_session_dir):
        """
        BV: Session files missing required keys return None.

        Scenario:
          Given: A session file missing chain_id
          When: ChainSession.load() is called
          Then: None is returned
        """
        incomplete_data = {"target": "1.1.1.1"}  # Missing chain_id
        session_file = temp_session_dir / "incomplete-1_1_1_1.json"
        with open(session_file, "w") as f:
            json.dump(incomplete_data, f)

        result = ChainSession.load("incomplete", "1.1.1.1")
        assert result is None

    def test_delete_nonexistent_session_no_error(self, temp_session_dir):
        """
        BV: Deleting non-existent session doesn't raise error.

        Scenario:
          Given: No session file exists
          When: delete() is called on a session object
          Then: No exception is raised
        """
        session = ChainSession("no-file", "1.2.3.4")
        # Should not raise
        session.delete()


# ==============================================================================
# Test: Full Session Lifecycle
# ==============================================================================


class TestSessionLifecycle:
    """Integration tests for complete session lifecycle."""

    def test_complete_session_workflow(self, temp_session_dir):
        """
        BV: Full workflow from creation to completion works correctly.

        Scenario:
          Given: A new session for a multi-step chain
          When: Steps are completed with outputs and variables
          Then: All state is preserved through save/load cycles
        """
        # 1. Create session
        session = ChainSession("lifecycle-test", "192.168.1.1")

        # 2. Complete first step with output
        session.mark_step_complete("step-1", output="Found NOPASSWD entries")
        session.store_step_findings(
            "step-1", {"nopasswd_commands": ["/usr/bin/find"]}
        )
        session.store_step_variables("step-1", {"<SUDO_BINARY>": "find"})
        session.add_variables({"<TARGET>": "192.168.1.1"})
        session.advance_step()
        session.save()

        # 3. Load and continue
        loaded = ChainSession.load("lifecycle-test", "192.168.1.1")
        assert loaded.current_step_index == 1
        assert "step-1" in loaded.completed_steps
        assert loaded.variables["<TARGET>"] == "192.168.1.1"

        # 4. Complete second step
        loaded.mark_step_complete("step-2", output="Root shell obtained")
        loaded.add_activation("lifecycle-test", "post-exploit", "Got root")
        loaded.advance_step()
        loaded.save()

        # 5. Final verification
        final = ChainSession.load("lifecycle-test", "192.168.1.1")
        assert final.current_step_index == 2
        assert final.completed_steps == ["step-1", "step-2"]
        assert len(final.activation_history) == 1
        assert final.get_activation_chain() == ["lifecycle-test", "post-exploit"]

        # 6. Cleanup
        final.delete()
        assert not ChainSession.exists("lifecycle-test", "192.168.1.1")

    def test_resume_interrupted_session(self, temp_session_dir):
        """
        BV: Users can resume an interrupted session exactly where they left off.

        Scenario:
          Given: A session interrupted mid-chain
          When: Session is loaded
          Then: Current step and all progress is restored
        """
        # Simulate interrupted session
        session = ChainSession("interrupted", "10.0.0.1")
        session.current_step_index = 2
        session.completed_steps = ["enum", "exploit"]
        session.variables = {
            "<TARGET>": "10.0.0.1",
            "<USER>": "admin",
            "<CRED>": "password123",
        }
        session.step_outputs = {
            "enum": "Ports: 22, 80, 443",
            "exploit": "Got user shell",
        }
        session.save()

        # "Resume" session
        resumed = ChainSession.load("interrupted", "10.0.0.1")

        # Verify exact state
        assert resumed.current_step_index == 2
        assert resumed.completed_steps == ["enum", "exploit"]
        assert resumed.variables["<CRED>"] == "password123"
        assert "Got user shell" in resumed.step_outputs["exploit"]
