"""
Integration tests for BloodTrail Wizard - Iterative Attack Loop Architecture.

These tests are designed to be SAFE and prevent system hangs:
- No full flow.run() calls except for interrupt handling tests
- Test internal methods directly (_run_init_phase, _display_summary, etc.)
- Pre-configure state to trigger specific exit conditions
- Mock at method level to avoid nested loop issues

Test Categories:
- TestWizardInitPhase: Phase 1 one-time initialization
- TestWizardAttackLoopExit: Loop termination conditions
- TestWizardStateTransitions: Access level and credential tracking
- TestWizardInterruptHandling: Ctrl+C behavior
- TestWizardSummaryDisplay: Final output formatting
- TestWizardResume: State persistence and resume
"""

import pytest
from unittest.mock import patch, MagicMock
from pathlib import Path

from tools.post.bloodtrail.wizard.flow import WizardFlow
from tools.post.bloodtrail.wizard.state import WizardState, AccessLevel
from tools.post.bloodtrail.wizard.steps import StepResult


class TestWizardInitPhase:
    """Test Phase 1: One-time initialization (detect, choose_mode)."""

    @patch("tools.post.bloodtrail.wizard.steps.DetectStep.run")
    @patch("tools.post.bloodtrail.wizard.steps.ChooseModeStep.run")
    def test_init_phase_completes_both_steps(self, mock_choose, mock_detect):
        """Init phase runs detect then choose_mode."""
        mock_detect.return_value = StepResult(True, "choose_mode", "OK", {})
        mock_choose.return_value = StepResult(True, "enumerate", "OK", {})

        flow = WizardFlow(target="10.10.10.1", resume=False)
        result = flow._run_init_phase()

        assert result is True
        assert mock_detect.called
        assert mock_choose.called
        assert "detect" in flow.state.completed_steps
        assert "choose_mode" in flow.state.completed_steps

    @patch("tools.post.bloodtrail.wizard.steps.DetectStep.run")
    def test_init_phase_stops_on_failure(self, mock_detect):
        """Init phase stops if detect fails."""
        mock_detect.return_value = StepResult(False, None, "No services", {})

        flow = WizardFlow(target="10.10.10.1", resume=False)
        result = flow._run_init_phase()

        assert result is False
        assert "detect" not in flow.state.completed_steps

    @patch("tools.post.bloodtrail.wizard.steps.DetectStep.run")
    @patch("tools.post.bloodtrail.wizard.steps.ChooseModeStep.run")
    def test_init_phase_skips_completed_steps(self, mock_choose, mock_detect):
        """Init phase skips already completed steps on resume."""
        mock_detect.return_value = StepResult(True, "choose_mode", "OK", {})
        mock_choose.return_value = StepResult(True, "enumerate", "OK", {})

        flow = WizardFlow(target="10.10.10.1", resume=False)
        # Pre-mark detect as completed
        flow.state.completed_steps = ["detect"]

        result = flow._run_init_phase()

        assert result is True
        assert not mock_detect.called  # Should skip
        assert mock_choose.called  # Should still run


class TestWizardAttackLoopExit:
    """Test attack loop exit conditions - NO full loop execution."""

    def test_loop_exits_on_domain_admin(self):
        """Attack loop exits immediately when Domain Admin achieved."""
        flow = WizardFlow(target="10.10.10.1", resume=False)
        flow.state.access_level = AccessLevel.DOMAIN_ADMIN
        flow.state.completed_steps = ["detect", "choose_mode"]

        # Directly call _run_attack_loop - should exit on first iteration
        with patch.object(flow, '_display_victory') as mock_victory:
            flow._run_attack_loop()

        assert mock_victory.called
        assert flow.state.attack_complete is True

    def test_loop_exits_when_no_actions(self):
        """Attack loop exits when no recommendations and can't re-enumerate."""
        flow = WizardFlow(target="10.10.10.1", resume=False)
        flow.state.completed_steps = ["detect", "choose_mode"]
        flow.state.last_enum_level = AccessLevel.ANONYMOUS
        flow.state.access_level = AccessLevel.ANONYMOUS

        # Mock to return quickly with no actions
        with patch.object(flow, '_run_enumeration', return_value=True):
            with patch.object(flow, '_run_analysis', return_value=True):
                with patch.object(flow, '_run_recommendation_loop', return_value=False):
                    flow._run_attack_loop()

        # Should exit after one cycle with no action
        assert flow.state.current_cycle >= 1

    def test_loop_respects_max_cycles(self):
        """Attack loop exits at max_cycles safety limit."""
        flow = WizardFlow(target="10.10.10.1", resume=False)
        flow.state.completed_steps = ["detect", "choose_mode"]
        flow.state.current_cycle = 49  # Near limit

        # Mock to always return True (would loop forever without limit)
        with patch.object(flow, '_run_enumeration', return_value=True):
            with patch.object(flow, '_run_analysis', return_value=True):
                with patch.object(flow, '_run_recommendation_loop', return_value=True):
                    flow._run_attack_loop()

        # Should have stopped at or before 50
        assert flow.state.current_cycle <= 50


class TestWizardStateTransitions:
    """Test state changes during wizard execution."""

    def test_access_level_update_triggers_reenumerate(self):
        """Changing access level should trigger re-enumeration."""
        state = WizardState(target="10.10.10.1")
        state.access_level = AccessLevel.ANONYMOUS
        state.last_enum_level = AccessLevel.ANONYMOUS

        # Initially should not need re-enumerate
        assert not state.should_reenumerate()

        # Update access level
        state.update_access_level(AccessLevel.USER, "user", "pass")

        # Now should need re-enumerate
        assert state.should_reenumerate()

    def test_add_credential_avoids_duplicates(self):
        """Adding same credential twice should not duplicate."""
        state = WizardState(target="10.10.10.1")
        state.add_credential("user", "pass", "test")
        state.add_credential("user", "pass", "test")

        assert len(state.credentials) == 1

    def test_add_credential_stores_details(self):
        """Credentials store username, password, source, validation status."""
        state = WizardState(target="10.10.10.1")
        state.add_credential("admin", "secret123", "asrep_crack", validated=True)

        assert len(state.credentials) == 1
        cred = state.credentials[0]
        assert cred["username"] == "admin"
        assert cred["password"] == "secret123"
        assert cred["source"] == "asrep_crack"
        assert cred["validated"] is True

    def test_domain_admin_detection(self):
        """is_domain_admin() returns correct value."""
        state = WizardState(target="10.10.10.1")
        assert not state.is_domain_admin()

        state.access_level = AccessLevel.DOMAIN_ADMIN
        assert state.is_domain_admin()

    def test_get_access_level_name(self):
        """Access level names are human-readable."""
        state = WizardState(target="10.10.10.1")

        state.access_level = AccessLevel.ANONYMOUS
        assert state.get_access_level_name() == "Anonymous"

        state.access_level = AccessLevel.USER
        assert state.get_access_level_name() == "Domain User"

        state.access_level = AccessLevel.DOMAIN_ADMIN
        assert state.get_access_level_name() == "Domain Admin"


class TestWizardInterruptHandling:
    """Test Ctrl+C interrupt handling."""

    @patch("tools.post.bloodtrail.wizard.steps.DetectStep.run")
    @patch("tools.post.bloodtrail.wizard.state.WizardState.save")
    @patch("builtins.print")
    def test_interrupt_saves_checkpoint(self, mock_print, mock_save, mock_detect):
        """Keyboard interrupt saves state before re-raising."""
        mock_detect.side_effect = KeyboardInterrupt()
        mock_save.return_value = Path("/tmp/state.json")

        flow = WizardFlow(target="10.10.10.1", resume=False)

        with pytest.raises(KeyboardInterrupt):
            flow.run()

        assert mock_save.called

    @patch("tools.post.bloodtrail.wizard.steps.DetectStep.run")
    @patch("tools.post.bloodtrail.wizard.state.WizardState.save")
    @patch("builtins.print")
    def test_interrupt_prints_resume_instructions(self, mock_print, mock_save, mock_detect):
        """Keyboard interrupt shows resume command."""
        mock_detect.side_effect = KeyboardInterrupt()
        mock_save.return_value = Path("/tmp/state.json")

        flow = WizardFlow(target="10.10.10.182", resume=False)

        with pytest.raises(KeyboardInterrupt):
            flow.run()

        # Check for resume message
        print_calls = [str(c) for c in mock_print.call_args_list]
        resume_calls = [c for c in print_calls if "resume" in c.lower()]
        assert len(resume_calls) > 0

    @patch("tools.post.bloodtrail.wizard.steps.DetectStep.run")
    @patch("tools.post.bloodtrail.wizard.state.WizardState.save")
    @patch("builtins.print")
    def test_interrupt_shows_target_in_resume(self, mock_print, mock_save, mock_detect):
        """Resume instructions include the target IP."""
        mock_detect.side_effect = KeyboardInterrupt()
        mock_save.return_value = Path("/tmp/state.json")

        flow = WizardFlow(target="10.10.10.182", resume=False)

        with pytest.raises(KeyboardInterrupt):
            flow.run()

        print_calls = [str(c) for c in mock_print.call_args_list]
        target_mentions = [c for c in print_calls if "10.10.10.182" in c]
        assert len(target_mentions) > 0


class TestWizardSummaryDisplay:
    """Test final summary display - call _display_summary directly."""

    @patch("builtins.print")
    def test_summary_shows_domain_admin(self, mock_print):
        """Summary indicates Domain Admin achievement."""
        flow = WizardFlow(target="10.10.10.1", resume=False)
        flow.state.access_level = AccessLevel.DOMAIN_ADMIN
        flow.state.attack_complete = True
        flow.state.current_cycle = 3
        flow.state.findings = ["f1", "f2", "f3"]

        flow._display_summary()

        print_calls = "".join([str(c) for c in mock_print.call_args_list])
        assert "DOMAIN ADMIN" in print_calls or "domain admin" in print_calls.lower()

    @patch("builtins.print")
    def test_summary_shows_cycle_count(self, mock_print):
        """Summary shows number of attack cycles."""
        flow = WizardFlow(target="10.10.10.1", resume=False)
        flow.state.current_cycle = 5
        flow.state.findings = []

        flow._display_summary()

        print_calls = "".join([str(c) for c in mock_print.call_args_list])
        assert "5" in print_calls or "cycle" in print_calls.lower()

    @patch("builtins.print")
    def test_summary_shows_findings_count(self, mock_print):
        """Summary shows number of findings."""
        flow = WizardFlow(target="10.10.10.1", resume=False)
        flow.state.findings = ["f1", "f2", "f3", "f4"]
        flow.state.current_cycle = 2

        flow._display_summary()

        print_calls = "".join([str(c) for c in mock_print.call_args_list])
        # Should show 4 or mention findings
        assert "4" in print_calls or "findings" in print_calls.lower()

    @patch("builtins.print")
    def test_summary_shows_credentials(self, mock_print):
        """Summary shows credentials if any found."""
        flow = WizardFlow(target="10.10.10.1", resume=False)
        flow.state.credentials = [
            {"username": "user1", "password": "pass1", "validated": True},
            {"username": "user2", "password": "pass2", "validated": False},
        ]
        flow.state.current_cycle = 2

        flow._display_summary()

        print_calls = "".join([str(c) for c in mock_print.call_args_list])
        # Should mention credentials
        assert "credential" in print_calls.lower() or "user1" in print_calls


class TestWizardResume:
    """Test wizard resume functionality."""

    @patch("tools.post.bloodtrail.wizard.state.WizardState.load")
    def test_resume_loads_saved_state(self, mock_load):
        """Resume flag loads state from disk."""
        saved_state = WizardState(target="10.10.10.1")
        saved_state.current_cycle = 5
        saved_state.access_level = AccessLevel.USER
        mock_load.return_value = saved_state

        flow = WizardFlow(target="10.10.10.1", resume=True)

        assert flow.state.current_cycle == 5
        assert flow.state.access_level == AccessLevel.USER

    @patch("tools.post.bloodtrail.wizard.state.WizardState.load")
    def test_resume_creates_fresh_if_no_saved(self, mock_load):
        """Resume with no saved state creates fresh."""
        mock_load.return_value = None

        flow = WizardFlow(target="10.10.10.1", resume=True)

        assert flow.state.current_cycle == 0
        assert flow.state.access_level == AccessLevel.ANONYMOUS

    @patch("tools.post.bloodtrail.wizard.state.WizardState.load")
    def test_resume_preserves_credentials(self, mock_load):
        """Resumed state preserves credentials from previous run."""
        saved_state = WizardState(target="10.10.10.1")
        saved_state.credentials = [
            {"username": "svc-alfresco", "password": "s3rvice", "validated": True}
        ]
        mock_load.return_value = saved_state

        flow = WizardFlow(target="10.10.10.1", resume=True)

        assert len(flow.state.credentials) == 1
        assert flow.state.credentials[0]["username"] == "svc-alfresco"

    def test_fresh_start_ignores_resume_flag(self):
        """Fresh start (resume=False) always creates new state."""
        flow = WizardFlow(target="10.10.10.1", resume=False)

        assert flow.state.current_cycle == 0
        assert flow.state.access_level == AccessLevel.ANONYMOUS
        assert len(flow.state.credentials) == 0


class TestWizardVictoryDisplay:
    """Test victory banner display."""

    @patch("builtins.print")
    def test_victory_shows_attack_path(self, mock_print):
        """Victory display shows attack path."""
        flow = WizardFlow(target="10.10.10.1", resume=False)
        flow.state.access_level = AccessLevel.DOMAIN_ADMIN
        flow.state.credentials = [
            {"username": "svc-alfresco", "password": "s3rvice", "validated": True},
        ]

        flow._display_victory()

        print_calls = "".join([str(c) for c in mock_print.call_args_list])
        assert "DOMAIN ADMIN" in print_calls
        assert "svc-alfresco" in print_calls
