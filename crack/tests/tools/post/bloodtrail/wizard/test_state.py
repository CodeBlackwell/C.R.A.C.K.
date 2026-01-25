"""
Tests for WizardState persistence and serialization.

Phase 1: State Foundation (TDD)
"""

import json
import pytest
from pathlib import Path
from typing import Dict


class TestWizardStateSerialization:
    """Test WizardState to_dict() and from_dict() methods."""

    def test_wizard_state_serializes_to_dict(
        self, wizard_state_factory, test_wizard_state_data: Dict
    ):
        """
        GIVEN a WizardState with all fields populated
        WHEN to_dict() is called
        THEN it returns a dictionary with all fields correctly serialized
        """
        # Create state with test data
        state = wizard_state_factory(
            target=test_wizard_state_data["target"],
            domain=test_wizard_state_data["domain"],
            current_step=test_wizard_state_data["current_step"],
            detected_services=test_wizard_state_data["detected_services"],
            detected_domain=test_wizard_state_data["detected_domain"],
            detected_dc=test_wizard_state_data["detected_dc"],
            selected_mode=test_wizard_state_data["selected_mode"],
            skip_steps=test_wizard_state_data["skip_steps"],
            completed_steps=test_wizard_state_data["completed_steps"],
            findings=test_wizard_state_data["findings"],
            credentials=test_wizard_state_data["credentials"],
            started_at=test_wizard_state_data["started_at"],
            last_checkpoint=test_wizard_state_data["last_checkpoint"],
        )

        # Serialize to dict
        result = state.to_dict()

        # Verify all fields present
        assert result["target"] == test_wizard_state_data["target"]
        assert result["domain"] == test_wizard_state_data["domain"]
        assert result["current_step"] == test_wizard_state_data["current_step"]
        assert result["detected_services"] == test_wizard_state_data["detected_services"]
        assert result["detected_domain"] == test_wizard_state_data["detected_domain"]
        assert result["detected_dc"] == test_wizard_state_data["detected_dc"]
        assert result["selected_mode"] == test_wizard_state_data["selected_mode"]
        assert result["skip_steps"] == test_wizard_state_data["skip_steps"]
        assert result["completed_steps"] == test_wizard_state_data["completed_steps"]
        assert result["findings"] == test_wizard_state_data["findings"]
        assert result["credentials"] == test_wizard_state_data["credentials"]
        assert result["started_at"] == test_wizard_state_data["started_at"]
        assert result["last_checkpoint"] == test_wizard_state_data["last_checkpoint"]

        # Verify types for collections
        assert isinstance(result["detected_services"], list)
        assert isinstance(result["skip_steps"], list)
        assert isinstance(result["completed_steps"], list)
        assert isinstance(result["findings"], list)
        assert isinstance(result["credentials"], list)

    def test_wizard_state_deserializes_from_dict(
        self, test_wizard_state_data: Dict
    ):
        """
        GIVEN a dictionary with WizardState data
        WHEN from_dict() is called
        THEN it returns a WizardState instance with all fields correctly populated
        """
        from tools.post.bloodtrail.wizard.state import WizardState

        # Deserialize from dict
        state = WizardState.from_dict(test_wizard_state_data)

        # Verify all fields
        assert state.target == test_wizard_state_data["target"]
        assert state.domain == test_wizard_state_data["domain"]
        assert state.current_step == test_wizard_state_data["current_step"]
        assert state.detected_services == test_wizard_state_data["detected_services"]
        assert state.detected_domain == test_wizard_state_data["detected_domain"]
        assert state.detected_dc == test_wizard_state_data["detected_dc"]
        assert state.selected_mode == test_wizard_state_data["selected_mode"]
        assert state.skip_steps == test_wizard_state_data["skip_steps"]
        assert state.completed_steps == test_wizard_state_data["completed_steps"]
        assert state.findings == test_wizard_state_data["findings"]
        assert state.credentials == test_wizard_state_data["credentials"]
        assert state.started_at == test_wizard_state_data["started_at"]
        assert state.last_checkpoint == test_wizard_state_data["last_checkpoint"]

    def test_wizard_state_roundtrip_preserves_data(
        self, wizard_state_factory, test_wizard_state_data: Dict
    ):
        """
        GIVEN a WizardState
        WHEN serialized to dict and deserialized back
        THEN the resulting state is identical to the original
        """
        from tools.post.bloodtrail.wizard.state import WizardState

        # Create original state
        original = wizard_state_factory(
            target=test_wizard_state_data["target"],
            domain=test_wizard_state_data["domain"],
            current_step=test_wizard_state_data["current_step"],
            detected_services=test_wizard_state_data["detected_services"],
            detected_domain=test_wizard_state_data["detected_domain"],
            detected_dc=test_wizard_state_data["detected_dc"],
            selected_mode=test_wizard_state_data["selected_mode"],
            skip_steps=test_wizard_state_data["skip_steps"],
            completed_steps=test_wizard_state_data["completed_steps"],
            findings=test_wizard_state_data["findings"],
            credentials=test_wizard_state_data["credentials"],
            started_at=test_wizard_state_data["started_at"],
            last_checkpoint=test_wizard_state_data["last_checkpoint"],
        )

        # Roundtrip: to_dict → from_dict
        serialized = original.to_dict()
        restored = WizardState.from_dict(serialized)

        # Verify all fields match
        assert restored.target == original.target
        assert restored.domain == original.domain
        assert restored.current_step == original.current_step
        assert restored.detected_services == original.detected_services
        assert restored.detected_domain == original.detected_domain
        assert restored.detected_dc == original.detected_dc
        assert restored.selected_mode == original.selected_mode
        assert restored.skip_steps == original.skip_steps
        assert restored.completed_steps == original.completed_steps
        assert restored.findings == original.findings
        assert restored.credentials == original.credentials
        assert restored.started_at == original.started_at
        assert restored.last_checkpoint == original.last_checkpoint


class TestWizardStatePersistence:
    """Test WizardState save() and load() file operations."""

    def test_wizard_state_saves_to_file(
        self, wizard_state_factory, test_wizard_state_data: Dict
    ):
        """
        GIVEN a WizardState
        WHEN save() is called with a target IP
        THEN a JSON file is created at ~/.crack/wizard_state/<target>.json
        AND the file contains correctly serialized data
        """
        # Create state
        state = wizard_state_factory(
            target=test_wizard_state_data["target"],
            domain=test_wizard_state_data["domain"],
            current_step=test_wizard_state_data["current_step"],
        )

        # Save to file
        saved_path = state.save(test_wizard_state_data["target"])

        # Verify path format
        assert saved_path.exists()
        assert saved_path.name == "10.10.10.182.json"
        assert saved_path.parent.name == "wizard_state"

        # Verify file contents
        with open(saved_path) as f:
            data = json.load(f)

        assert data["target"] == test_wizard_state_data["target"]
        assert data["domain"] == test_wizard_state_data["domain"]
        assert data["current_step"] == test_wizard_state_data["current_step"]

    def test_wizard_state_loads_from_file(
        self, wizard_state_factory, test_wizard_state_data: Dict
    ):
        """
        GIVEN a saved WizardState file
        WHEN load() is called with the target IP
        THEN it returns a WizardState instance with the saved data
        """
        from tools.post.bloodtrail.wizard.state import WizardState

        # Create and save state
        original = wizard_state_factory(
            target=test_wizard_state_data["target"],
            domain=test_wizard_state_data["domain"],
            current_step=test_wizard_state_data["current_step"],
            detected_services=test_wizard_state_data["detected_services"],
            credentials=test_wizard_state_data["credentials"],
        )
        original.save(test_wizard_state_data["target"])

        # Load from file
        loaded = WizardState.load(test_wizard_state_data["target"])

        # Verify loaded state matches original
        assert loaded is not None
        assert loaded.target == original.target
        assert loaded.domain == original.domain
        assert loaded.current_step == original.current_step
        assert loaded.detected_services == original.detected_services
        assert loaded.credentials == original.credentials

    def test_wizard_state_returns_none_for_missing(self):
        """
        GIVEN no saved state file exists for a target
        WHEN load() is called
        THEN it returns None
        """
        from tools.post.bloodtrail.wizard.state import WizardState

        # Try to load non-existent state
        result = WizardState.load("192.168.99.99")

        # Verify None returned (not an exception)
        assert result is None

    def test_wizard_state_handles_invalid_json_gracefully(self, tmp_path: Path):
        """
        GIVEN a corrupted state file with invalid JSON
        WHEN load() is called
        THEN it returns None and doesn't crash
        """
        from tools.post.bloodtrail.wizard.state import WizardState

        # Create corrupted state file
        state_dir = tmp_path / ".crack" / "wizard_state"
        state_dir.mkdir(parents=True, exist_ok=True)
        corrupt_file = state_dir / "10.10.10.100.json"
        corrupt_file.write_text("{invalid json")

        # Try to load corrupted file
        result = WizardState.load("10.10.10.100")

        # Should return None, not crash
        assert result is None

    def test_wizard_state_auto_sets_timestamp(self, wizard_state_factory):
        """
        GIVEN a WizardState created without started_at
        WHEN the instance is created
        THEN started_at is automatically set to current ISO timestamp
        """
        from datetime import datetime

        state = wizard_state_factory(target="10.10.10.1", started_at=None)

        # Verify started_at was auto-set
        assert state.started_at is not None
        assert isinstance(state.started_at, str)

        # Verify it's a valid ISO timestamp
        parsed = datetime.fromisoformat(state.started_at)
        assert parsed is not None

    def test_wizard_state_preserves_manual_timestamp(
        self, wizard_state_factory, test_wizard_state_data: Dict
    ):
        """
        GIVEN a WizardState created with explicit started_at
        WHEN the instance is created
        THEN started_at is preserved as provided
        """
        expected_time = test_wizard_state_data["started_at"]
        state = wizard_state_factory(target="10.10.10.1", started_at=expected_time)

        # Verify started_at matches provided value
        assert state.started_at == expected_time
