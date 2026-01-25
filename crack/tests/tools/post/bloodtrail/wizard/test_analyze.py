"""
Tests for AnalyzeStep.

TDD Approach: Tests written FIRST, then implementation.

Test Coverage:
- AnalyzeStep feeds engine with findings from state
- AnalyzeStep generates prioritized recommendations
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from tools.post.bloodtrail.wizard.steps import AnalyzeStep
from tools.post.bloodtrail.wizard.state import WizardState
from tools.post.bloodtrail.recommendation.models import (
    Finding,
    FindingType,
    Recommendation,
    RecommendationPriority,
)


def test_analyze_step_feeds_engine_with_findings():
    """
    AnalyzeStep should feed all findings from state to the recommendation engine.

    Given:
        - State has findings list: ["finding1", "finding2", "finding3"]
        - Context has finding objects stored from enumerate step

    When:
        - AnalyzeStep.run() is called

    Then:
        - RecommendationEngine is created
        - Each finding is fed to engine via add_finding()
        - Engine processes findings through trigger rules
    """
    # Arrange
    state = WizardState(target="10.10.10.182")
    state.findings = ["finding_asrep_pete", "finding_spn_service"]

    # Create mock finding objects
    finding1 = Finding(
        id="finding_asrep_pete",
        finding_type=FindingType.USER_FLAG,
        source="enum4linux",
        target="pete",
        raw_value="asrep",
        tags=["asrep", "enabled"],
        metadata={"username": "pete"},
    )

    finding2 = Finding(
        id="finding_spn_service",
        finding_type=FindingType.USER_FLAG,
        source="ldapsearch",
        target="service",
        raw_value="spn",
        tags=["spn", "enabled"],
        metadata={"username": "service"},
    )

    # Store findings in context (simulate enumerate step output)
    context = {
        "finding_objects": {
            "finding_asrep_pete": finding1,
            "finding_spn_service": finding2,
        }
    }

    step = AnalyzeStep()

    # Mock RecommendationEngine
    mock_engine = Mock()
    mock_engine.add_finding = Mock(return_value=[])  # Returns list of recommendations
    mock_engine.get_pending_count = Mock(return_value=2)

    with patch('tools.post.bloodtrail.recommendation.engine.RecommendationEngine') as MockEngine:
        MockEngine.return_value = mock_engine

        # Act
        result = step.run(state, context)

        # Assert
        assert result.success is True
        assert result.next_step == "recommend"

        # Engine should be created with target and domain
        MockEngine.assert_called_once()
        call_kwargs = MockEngine.call_args[1]
        assert call_kwargs["target"] == "10.10.10.182"

        # Each finding should be added to engine
        assert mock_engine.add_finding.call_count == 2
        mock_engine.add_finding.assert_any_call(finding1)
        mock_engine.add_finding.assert_any_call(finding2)


def test_analyze_step_generates_recommendations():
    """
    AnalyzeStep should generate prioritized recommendations from findings.

    Given:
        - State has findings for AS-REP roastable user
        - RecommendationEngine processes findings

    When:
        - AnalyzeStep.run() is called

    Then:
        - Engine generates recommendations
        - Recommendation count is stored in result.data
        - Engine is stored in context for next step (RecommendStep)
    """
    # Arrange
    state = WizardState(target="10.10.10.182")
    state.findings = ["finding_asrep_pete"]

    finding = Finding(
        id="finding_asrep_pete",
        finding_type=FindingType.USER_FLAG,
        source="enum4linux",
        target="pete",
        raw_value="asrep",
        tags=["asrep", "enabled"],
        metadata={"username": "pete"},
    )

    context = {
        "finding_objects": {
            "finding_asrep_pete": finding,
        }
    }

    step = AnalyzeStep()

    # Mock RecommendationEngine with actual recommendations
    mock_rec1 = Recommendation(
        id="rec_asrep_roast_pete",
        priority=RecommendationPriority.HIGH,
        trigger_finding_id="finding_asrep_pete",
        action_type="run_command",
        description="AS-REP roast user pete",
        why="User pete has preauthentication disabled",
        command="GetNPUsers.py ...",
    )

    mock_engine = Mock()
    mock_engine.add_finding = Mock(return_value=[mock_rec1])
    mock_engine.get_pending_count = Mock(return_value=1)
    mock_engine.state = Mock()
    mock_engine.state.pending_recommendations = [mock_rec1]

    with patch('tools.post.bloodtrail.recommendation.engine.RecommendationEngine') as MockEngine:
        MockEngine.return_value = mock_engine

        # Act
        result = step.run(state, context)

        # Assert
        assert result.success is True
        assert result.next_step == "recommend"

        # Result should include recommendation count
        assert "recommendation_count" in result.data
        assert result.data["recommendation_count"] == 1

        # Engine should be stored in context for RecommendStep
        assert "engine" in context
        assert context["engine"] == mock_engine


def test_analyze_step_cannot_run_without_findings():
    """
    AnalyzeStep.can_run() should return False if no findings exist.

    Given:
        - State has empty findings list

    When:
        - AnalyzeStep.can_run() is called

    Then:
        - Returns False
    """
    # Arrange
    state = WizardState(target="10.10.10.182")
    state.findings = []  # No findings

    step = AnalyzeStep()

    # Act
    can_run = step.can_run(state)

    # Assert
    assert can_run is False


def test_analyze_step_can_run_with_findings():
    """
    AnalyzeStep.can_run() should return True if findings exist.

    Given:
        - State has findings

    When:
        - AnalyzeStep.can_run() is called

    Then:
        - Returns True
    """
    # Arrange
    state = WizardState(target="10.10.10.182")
    state.findings = ["finding1", "finding2"]

    step = AnalyzeStep()

    # Act
    can_run = step.can_run(state)

    # Assert
    assert can_run is True
