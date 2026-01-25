"""
Tests for RecommendStep - Recommendation Loop (Phase 5).

Tests the one-at-a-time recommendation presentation loop.
"""

import pytest
from unittest.mock import Mock, patch, call

from tools.post.bloodtrail.wizard.steps import RecommendStep, StepResult
from tools.post.bloodtrail.wizard.state import WizardState
from tools.post.bloodtrail.recommendation.engine import RecommendationEngine
from tools.post.bloodtrail.recommendation.models import Recommendation, RecommendationPriority


@pytest.fixture
def mock_state():
    """Create a basic wizard state."""
    state = WizardState(
        target="10.10.10.182",
        domain="CASCADE.LOCAL",
    )
    state.detected_services = [
        {"port": 88, "service": "kerberos", "state": "open"},
        {"port": 389, "service": "ldap", "state": "open"},
        {"port": 445, "service": "smb", "state": "open"},
    ]
    state.findings = ["finding_asrep_user1", "finding_spn_user2"]
    state.completed_steps = ["detect", "choose_mode", "enumerate", "analyze"]
    return state


@pytest.fixture
def mock_engine():
    """Create a mock recommendation engine with some recommendations."""
    engine = Mock(spec=RecommendationEngine)

    # Create mock recommendations
    rec1 = Recommendation(
        id="rec_asrep_1",
        description="Test AS-REP roastable user",
        command="GetNPUsers.py CASCADE.LOCAL/user1 -no-pass -dc-ip 10.10.10.182",
        priority=RecommendationPriority.HIGH,
        trigger_finding_id="finding_asrep_user1",
        action_type="run_command",
        why="User has Do Not Require Pre-Authentication enabled",
        metadata={"username": "user1"},
    )

    rec2 = Recommendation(
        id="rec_spn_2",
        description="Test Kerberoastable service account",
        command="GetUserSPNs.py CASCADE.LOCAL/user2 -no-pass -dc-ip 10.10.10.182",
        priority=RecommendationPriority.MEDIUM,
        trigger_finding_id="finding_spn_user2",
        action_type="run_command",
        why="User has Service Principal Name (SPN) registered",
        metadata={"username": "user2"},
    )

    # Mock get_next_recommendation to return recommendations then None
    engine.get_next_recommendation.side_effect = [rec1, rec2, None]

    return engine


def test_recommend_step_presents_one_at_a_time(mock_state, mock_engine):
    """
    Test that RecommendStep presents recommendations one at a time.

    Verifies:
    - Calls engine.get_next_recommendation() in a loop
    - Displays each recommendation using box()
    - Prompts user for action
    - Stops when no more recommendations
    """
    step = RecommendStep()
    context = {"engine": mock_engine}

    # Mock user inputs: run first, skip second, then no more
    with patch("tools.post.bloodtrail.interactive.display.prompt_user") as mock_prompt:
        with patch("tools.post.bloodtrail.interactive.display.box") as mock_box:
            with patch("builtins.print"):
                mock_prompt.side_effect = ['r', 's']  # Run, Skip
                mock_box.return_value = "Mock box output"

                result = step.run(mock_state, context)

    # Verify get_next_recommendation called until None
    assert mock_engine.get_next_recommendation.call_count == 3  # rec1, rec2, None

    # Verify box() called twice (once per recommendation)
    assert mock_box.call_count == 2

    # Verify prompt called twice
    assert mock_prompt.call_count == 2

    # Verify success and next step
    assert result.success is True
    assert result.next_step == "done"


def test_recommend_step_handles_run_action(mock_state, mock_engine):
    """
    Test that RecommendStep executes command when user chooses 'r'.

    Verifies:
    - Runs subprocess with command
    - Marks recommendation as complete
    - Continues to next recommendation
    """
    step = RecommendStep()
    context = {"engine": mock_engine}

    with patch("tools.post.bloodtrail.interactive.display.prompt_user") as mock_prompt:
        with patch("tools.post.bloodtrail.interactive.display.box"):
            with patch("subprocess.run") as mock_subprocess:
                with patch("builtins.print"):
                    # User chooses 'r' (run) for first, then quit on second
                    mock_prompt.side_effect = ['r', 'q']

                    # Mock successful subprocess
                    mock_subprocess.return_value = Mock(returncode=0, stdout="", stderr="")

                    result = step.run(mock_state, context)

    # Verify command was executed
    assert mock_subprocess.call_count == 1

    # Verify recommendation marked complete
    assert mock_engine.complete_recommendation.call_count == 1
    assert mock_engine.complete_recommendation.call_args[0][0] == "rec_asrep_1"

    # Verify success
    assert result.success is True


def test_recommend_step_handles_skip_action(mock_state, mock_engine):
    """
    Test that RecommendStep skips recommendation when user chooses 's'.

    Verifies:
    - Does NOT execute command
    - Marks recommendation as skipped
    - Continues to next recommendation
    """
    step = RecommendStep()
    context = {"engine": mock_engine}

    with patch("tools.post.bloodtrail.interactive.display.prompt_user") as mock_prompt:
        with patch("tools.post.bloodtrail.interactive.display.box"):
            with patch("subprocess.run") as mock_subprocess:
                with patch("builtins.print"):
                    # User skips both recommendations
                    mock_prompt.side_effect = ['s', 's']

                    result = step.run(mock_state, context)

    # Verify NO commands executed
    assert mock_subprocess.call_count == 0

    # Verify both skipped
    assert mock_engine.skip_recommendation.call_count == 2
    assert mock_engine.skip_recommendation.call_args_list[0][0][0] == "rec_asrep_1"
    assert mock_engine.skip_recommendation.call_args_list[1][0][0] == "rec_spn_2"

    # Verify success
    assert result.success is True


def test_recommend_step_shows_why_on_help(mock_state, mock_engine):
    """
    Test that RecommendStep shows extended WHY when user chooses '?'.

    Verifies:
    - Displays WHY explanation
    - Re-prompts for action
    - Eventually processes recommendation
    """
    step = RecommendStep()
    context = {"engine": mock_engine}

    with patch("tools.post.bloodtrail.interactive.display.prompt_user") as mock_prompt:
        with patch("tools.post.bloodtrail.interactive.display.box") as mock_box:
            with patch("builtins.print") as mock_print:
                # User asks for help first, then runs
                mock_prompt.side_effect = ['?', 'r', 'q']
                mock_box.return_value = "Mock box"

                result = step.run(mock_state, context)

    # Verify WHY was printed
    # Look for "Why this matters:" or the WHY text itself in print calls
    why_printed = False
    for call_args in mock_print.call_args_list:
        if call_args[0]:
            output = str(call_args[0][0])
            if "Why this matters:" in output or "Do Not Require Pre-Authentication" in output:
                why_printed = True
                break
    assert why_printed, f"Expected WHY explanation to be printed. Print calls: {[str(c) for c in mock_print.call_args_list[:5]]}"

    # Verify recommendation still processed
    assert mock_engine.complete_recommendation.call_count == 1


def test_recommend_step_tracks_completed(mock_state, mock_engine):
    """
    Test that RecommendStep tracks completed/skipped recommendations.

    Verifies:
    - State updated with completed actions
    - Skip count incremented
    - Completed count incremented
    """
    step = RecommendStep()
    context = {"engine": mock_engine}

    with patch("tools.post.bloodtrail.interactive.display.prompt_user") as mock_prompt:
        with patch("tools.post.bloodtrail.interactive.display.box"):
            with patch("subprocess.run") as mock_subprocess:
                with patch("builtins.print"):
                    # Run first, skip second
                    mock_prompt.side_effect = ['r', 's']
                    mock_subprocess.return_value = Mock(returncode=0, stdout="", stderr="")

                    result = step.run(mock_state, context)

    # Verify both complete and skip were called
    assert mock_engine.complete_recommendation.call_count == 1
    assert mock_engine.skip_recommendation.call_count == 1


def test_recommend_step_creates_engine_if_missing(mock_state):
    """
    Test that RecommendStep creates engine if not in context.

    Verifies:
    - Creates fresh RecommendationEngine if context["engine"] missing
    - Uses state.target and state.domain
    """
    step = RecommendStep()
    context = {}  # No engine in context

    with patch("tools.post.bloodtrail.recommendation.engine.RecommendationEngine") as MockEngine:
        with patch("tools.post.bloodtrail.interactive.display.prompt_user"):
            with patch("tools.post.bloodtrail.interactive.display.box"):
                with patch("builtins.print"):
                    # Mock engine with no recommendations
                    mock_instance = Mock()
                    mock_instance.get_next_recommendation.return_value = None
                    MockEngine.return_value = mock_instance

                    result = step.run(mock_state, context)

    # Verify engine was created
    MockEngine.assert_called_once_with(
        target=mock_state.target,
        domain=mock_state.domain,
    )


def test_recommend_step_can_always_run(mock_state):
    """
    Test that RecommendStep can always run (no hard prerequisites).

    Even if no findings/engine, should be able to run (will just have empty queue).
    """
    step = RecommendStep()

    # Empty state should still allow run
    empty_state = WizardState(target="10.10.10.1")
    assert step.can_run(empty_state) is True

    # State with findings should allow run
    assert step.can_run(mock_state) is True


def test_recommend_step_handles_quit_gracefully(mock_state, mock_engine):
    """
    Test that RecommendStep exits loop when user chooses 'q'.

    Verifies:
    - Loop exits immediately
    - No further recommendations processed
    """
    step = RecommendStep()
    context = {"engine": mock_engine}

    with patch("tools.post.bloodtrail.interactive.display.prompt_user") as mock_prompt:
        with patch("tools.post.bloodtrail.interactive.display.box"):
            with patch("builtins.print"):
                # User quits on first recommendation
                mock_prompt.return_value = 'q'

                result = step.run(mock_state, context)

    # Verify only ONE recommendation requested (then quit)
    assert mock_engine.get_next_recommendation.call_count == 1

    # Verify neither complete nor skip called
    assert mock_engine.complete_recommendation.call_count == 0
    assert mock_engine.skip_recommendation.call_count == 0

    # Still successful (quit is graceful exit)
    assert result.success is True
