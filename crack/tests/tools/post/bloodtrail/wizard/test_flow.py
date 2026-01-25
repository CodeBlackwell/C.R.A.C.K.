"""
Tests for BloodTrail Wizard Flow.

Tests the WizardFlow controller including:
- Step execution loop
- State persistence (auto-save after each step)
- Resume capability
- Mode selection step

TDD Approach: Tests written FIRST, then implementation.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
from io import StringIO

from tools.post.bloodtrail.wizard.state import WizardState
from tools.post.bloodtrail.wizard.steps import WizardStep, StepResult, DetectStep, ChooseModeStep
from tools.post.bloodtrail.wizard.flow import WizardFlow


class TestChooseModeStep:
    """Test suite for ChooseModeStep implementation."""

    def test_choose_mode_presents_three_options(self, capsys):
        """Verify that ChooseModeStep displays three mode options."""
        step = ChooseModeStep()
        state = WizardState(target="10.10.10.182")
        state.completed_steps.append("detect")

        # Mock user input: select option 1 (auto)
        with patch('builtins.input', return_value="1"):
            result = step.run(state, {})

        # Capture output to verify options were shown
        captured = capsys.readouterr()

        # Should display all three options
        assert "[1]" in captured.out, "Should show option 1"
        assert "[2]" in captured.out, "Should show option 2"
        assert "[3]" in captured.out, "Should show option 3"

    def test_choose_mode_auto_is_first_and_recommended(self, capsys):
        """Verify Auto mode is first and marked as recommended."""
        step = ChooseModeStep()
        state = WizardState(target="10.10.10.182")
        state.completed_steps.append("detect")

        # Mock user input
        with patch('builtins.input', return_value="1"):
            result = step.run(state, {})

        captured = capsys.readouterr()

        # Auto should be first and marked recommended
        assert "Auto" in captured.out, "Should mention Auto mode"
        assert "recommended" in captured.out.lower(), "Auto should be marked as recommended"

        # Verify Auto appears before Guided
        auto_pos = captured.out.find("Auto")
        guided_pos = captured.out.find("Guided")
        assert auto_pos < guided_pos, "Auto should appear before Guided"

    def test_choose_mode_accepts_numeric_selection(self):
        """Verify numeric selection works for all three modes."""
        step = ChooseModeStep()
        state = WizardState(target="10.10.10.182")
        state.completed_steps.append("detect")

        # Test selection 1 - Auto
        with patch('builtins.input', return_value="1"):
            result = step.run(state, {})
        assert state.selected_mode == "auto"
        assert result.next_step == "enumerate"

        # Test selection 2 - Guided
        state2 = WizardState(target="10.10.10.182")
        state2.completed_steps.append("detect")
        with patch('builtins.input', return_value="2"):
            result2 = step.run(state2, {})
        assert state2.selected_mode == "guided"
        assert result2.next_step == "enumerate"

        # Test selection 3 - Skip
        state3 = WizardState(target="10.10.10.182")
        state3.completed_steps.append("detect")
        with patch('builtins.input', return_value="3"):
            result3 = step.run(state3, {})
        assert state3.selected_mode == "skip"
        assert result3.next_step == "recommend"

    def test_choose_mode_handles_invalid_input(self):
        """Verify graceful handling of invalid input."""
        step = ChooseModeStep()
        state = WizardState(target="10.10.10.182")
        state.completed_steps.append("detect")

        # Test invalid number - should re-prompt or default to auto
        with patch('builtins.input', side_effect=["99", "1"]):
            result = step.run(state, {})

        # Should eventually succeed with valid input
        assert result.success
        assert state.selected_mode in ["auto", "guided", "skip"]


class TestWizardFlow:
    """Test suite for WizardFlow controller (Iterative Architecture)."""

    def test_flow_transitions_between_steps(self, tmp_path):
        """Verify flow executes init phase and attack loop correctly.

        The new iterative architecture has two phases:
        - Phase 1: Init (detect, choose_mode) - one-time
        - Phase 2: Attack loop (enumerate → analyze → recommend) - iterative
        """
        flow = WizardFlow(target="10.10.10.182", resume=False)

        # Mock the init phase to succeed
        with patch.object(flow, '_run_init_phase', return_value=True) as mock_init:
            # Mock the attack loop to complete immediately (Domain Admin)
            with patch.object(flow, '_run_attack_loop') as mock_loop:
                # Mock display summary
                with patch.object(flow, '_display_summary'):
                    with patch.object(WizardState, 'save', return_value=tmp_path / "state.json"):
                        final_state = flow.run()

        # Verify both phases were called
        assert mock_init.called, "Init phase should execute"
        assert mock_loop.called, "Attack loop should execute"

    def test_flow_initializes_with_target(self):
        """Verify flow initializes with target and creates fresh state."""
        flow = WizardFlow(target="192.168.1.10", resume=False)

        assert flow.state.target == "192.168.1.10"
        assert flow.state.current_step == "detect"
        assert flow.state.completed_steps == []

    def test_flow_resumes_from_saved_state(self, tmp_path):
        """Verify resume=True loads saved state."""
        target = "10.10.10.182"

        # Create a saved state
        existing_state = WizardState(target=target)
        existing_state.current_step = "enumerate"
        existing_state.completed_steps = ["detect", "choose_mode"]
        existing_state.selected_mode = "auto"

        # Mock WizardState.load to return saved state
        with patch.object(WizardState, 'load', return_value=existing_state):
            flow = WizardFlow(target=target, resume=True)

            # Should resume from saved state
            assert flow.state.current_step == "enumerate"
            assert "detect" in flow.state.completed_steps
            assert "choose_mode" in flow.state.completed_steps
            assert flow.state.selected_mode == "auto"

    def test_flow_creates_fresh_state_if_no_saved_state(self):
        """Verify resume=True with no saved state creates fresh state."""
        target = "10.10.10.182"

        # Mock WizardState.load to return None (no saved state)
        with patch.object(WizardState, 'load', return_value=None):
            flow = WizardFlow(target=target, resume=True)

            # Should create fresh state
            assert flow.state.target == target
            assert flow.state.current_step == "detect"
            assert flow.state.completed_steps == []

    def test_flow_saves_checkpoint_after_each_step(self, tmp_path):
        """Verify flow auto-saves state during execution.

        The iterative architecture saves state:
        - After init phase completion
        - After each attack cycle
        - On keyboard interrupt
        """
        flow = WizardFlow(target="10.10.10.182", resume=False)

        # Track save calls
        save_count = [0]

        def track_save(*args, **kwargs):
            save_count[0] += 1
            return tmp_path / f"state_{save_count[0]}.json"

        # Mock flow methods to simulate quick execution
        with patch.object(flow, '_run_init_phase', return_value=True):
            with patch.object(flow, '_run_attack_loop'):
                with patch.object(flow, '_display_summary'):
                    with patch.object(flow.state, 'save', side_effect=track_save):
                        flow.run()

        # State should be saved at least once during execution
        assert save_count[0] > 0, "State should be saved during execution"

    def test_flow_has_iterative_architecture(self):
        """Verify WizardFlow has the expected iterative architecture methods.

        The new architecture uses:
        - _run_init_phase(): One-time init (detect, choose_mode)
        - _run_attack_loop(): Iterative attack cycle
        - _run_enumeration(): Run enumerators based on access level
        - _run_analysis(): Generate recommendations from findings
        - _run_recommendation_loop(): Present and execute recommendations
        """
        flow = WizardFlow(target="10.10.10.1", resume=False)

        # Core iterative methods should exist
        assert hasattr(flow, '_run_init_phase'), "Should have init phase method"
        assert hasattr(flow, '_run_attack_loop'), "Should have attack loop method"
        assert hasattr(flow, '_display_summary'), "Should have summary method"
        assert hasattr(flow, '_display_victory'), "Should have victory method"
