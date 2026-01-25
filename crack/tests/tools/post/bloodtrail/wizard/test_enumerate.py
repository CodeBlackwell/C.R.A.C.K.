"""
Tests for EnumerateStep.

TDD Approach: Tests written FIRST, then implementation.

Test Coverage:
- EnumerateStep only runs detected enumerators (not all)
- EnumerateStep aggregates findings and stores in state
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from tools.post.bloodtrail.wizard.steps import EnumerateStep
from tools.post.bloodtrail.wizard.state import WizardState
from tools.post.bloodtrail.enumerators.base import EnumerationResult, AuthLevel
from tools.post.bloodtrail.recommendation.models import Finding, FindingType


def test_enumerate_step_only_runs_detected_enumerators():
    """
    EnumerateStep should only run enumerators for detected services.

    Given:
        - State has detected_services: [{"port": 445, "service": "smb"}]
        - State has detected_dc = True

    When:
        - EnumerateStep.run() is called

    Then:
        - Only SMB-relevant enumerators are run (enum4linux, rpcclient)
        - LDAP enumerators are NOT run (not detected)
        - Results are stored in state.findings
    """
    # Arrange
    state = WizardState(target="10.10.10.182")
    state.detected_services = [
        {"port": 445, "service": "smb", "state": "open"},
    ]
    state.detected_dc = False  # Not a DC, no LDAP

    step = EnumerateStep()
    context = {}

    # Mock enumerator instance
    mock_enum = Mock()
    mock_enum.id = "enum4linux"
    mock_enum.run = Mock(return_value=EnumerationResult(
        enumerator_id="enum4linux",
        success=True,
        auth_level=AuthLevel.ANONYMOUS,
        users=[
            {"name": "pete", "enabled": True, "asrep": True},
        ],
    ))

    # Mock get_available_enumerators to return only SMB enumerators
    with patch('tools.post.bloodtrail.enumerators.get_available_enumerators') as mock_get_enums:
        mock_get_enums.return_value = [mock_enum]

        # Mock aggregate_results
        mock_aggregated = Mock()
        mock_aggregated.asrep_roastable_users = [
            {"name": "pete", "enabled": True, "asrep": True},
        ]
        mock_aggregated.service_accounts = []
        mock_aggregated.password_policy = None

        with patch('tools.post.bloodtrail.enumerators.aggregator.aggregate_results') as mock_agg:
            mock_agg.return_value = mock_aggregated

            # Act
            result = step.run(state, context)

            # Assert
            assert result.success is True
            assert result.next_step == "analyze"

            # Should have called enumerator for SMB
            assert mock_enum.run.call_count == 1

            # State should have findings
            assert len(state.findings) > 0


def test_enumerate_step_aggregates_findings():
    """
    EnumerateStep should aggregate findings from multiple enumerators.

    Given:
        - Multiple enumerators return results (enum4linux, rpcclient)
        - Results contain users, groups, password policies

    When:
        - EnumerateStep.run() is called

    Then:
        - All findings are aggregated and deduplicated
        - Findings are converted to Finding objects
        - Finding IDs are appended to state.findings list
        - Result includes count of findings discovered
    """
    # Arrange
    state = WizardState(target="10.10.10.182")
    state.detected_services = [
        {"port": 445, "service": "smb", "state": "open"},
        {"port": 389, "service": "ldap", "state": "open"},
    ]
    state.detected_dc = True

    step = EnumerateStep()
    context = {}

    # Mock enumerator instances
    mock_enum4linux = Mock()
    mock_enum4linux.id = "enum4linux"
    mock_enum4linux.run = Mock(return_value=EnumerationResult(
        enumerator_id="enum4linux",
        success=True,
        auth_level=AuthLevel.ANONYMOUS,
        users=[
            {"name": "pete", "enabled": True, "asrep": True},
            {"name": "admin", "enabled": True, "asrep": False},
        ],
        password_policy={"lockout_threshold": 5},
    ))

    mock_ldapsearch = Mock()
    mock_ldapsearch.id = "ldapsearch"
    mock_ldapsearch.run = Mock(return_value=EnumerationResult(
        enumerator_id="ldapsearch",
        success=True,
        auth_level=AuthLevel.ANONYMOUS,
        users=[
            {"name": "pete", "enabled": True, "asrep": True},  # Duplicate
            {"name": "service", "enabled": True, "spn": True},  # New
        ],
    ))

    # Mock aggregator to merge results
    mock_aggregated = Mock()
    mock_aggregated.asrep_roastable_users = [
        {"name": "pete", "enabled": True, "asrep": True},
    ]
    mock_aggregated.service_accounts = [
        {"name": "service", "enabled": True, "spn": True},
    ]
    mock_aggregated.password_policy = {"lockout_threshold": 5}

    with patch('tools.post.bloodtrail.enumerators.get_available_enumerators') as mock_get_enums:
        mock_get_enums.return_value = [mock_enum4linux, mock_ldapsearch]

        with patch('tools.post.bloodtrail.enumerators.aggregator.aggregate_results') as mock_agg:
            mock_agg.return_value = mock_aggregated

            # Act
            result = step.run(state, context)

            # Assert
            assert result.success is True
            assert result.next_step == "analyze"

            # Findings should be stored as Finding IDs (strings)
            assert isinstance(state.findings, list)
            # Should have at least AS-REP user finding + service account finding + policy
            assert len(state.findings) >= 3

            # Result data should include counts
            assert "finding_count" in result.data
            assert result.data["finding_count"] >= 3
