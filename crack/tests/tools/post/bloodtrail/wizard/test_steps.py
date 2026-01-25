"""
Tests for BloodTrail Wizard Step Framework.

Phase 2: Step Framework
Tests written FIRST (TDD approach).
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from dataclasses import dataclass, field
from typing import Dict, List, Optional


# Mock WizardState for testing (will be implemented by parallel agent)
@dataclass
class MockWizardState:
    """Mock WizardState for testing."""
    target: str
    domain: Optional[str] = None
    current_step: str = "detect"
    detected_services: List[Dict] = field(default_factory=list)
    detected_domain: Optional[str] = None
    detected_dc: Optional[str] = None
    selected_mode: str = "auto"
    skip_steps: List[str] = field(default_factory=list)
    completed_steps: List[str] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    credentials: List[Dict] = field(default_factory=list)
    started_at: str = "2025-01-10T12:00:00"
    last_checkpoint: Optional[str] = None


class TestStepAttributes:
    """Test that Step classes have required attributes."""

    def test_step_has_required_attributes(self):
        """Verify WizardStep base class enforces required attributes."""
        from tools.post.bloodtrail.wizard.steps import WizardStep

        # Check that WizardStep defines required class attributes
        assert hasattr(WizardStep, 'id')
        assert hasattr(WizardStep, 'title')
        assert hasattr(WizardStep, 'description')
        assert hasattr(WizardStep, 'skippable')

        # Verify abstract methods exist
        assert hasattr(WizardStep, 'can_run')
        assert hasattr(WizardStep, 'run')


class TestStepBehavior:
    """Test step behavior and lifecycle."""

    def test_step_can_run_checks_prerequisites(self):
        """Verify can_run() method checks state prerequisites."""
        from tools.post.bloodtrail.wizard.steps import WizardStep

        # Create a concrete implementation for testing
        class TestStep(WizardStep):
            id = "test_step"
            title = "Test Step"
            description = "Test description"
            skippable = True

            def can_run(self, state):
                # Check prerequisite: requires domain to be set
                return state.domain is not None

            def run(self, state, context):
                pass

        step = TestStep()

        # State without domain - should return False
        state_without_domain = MockWizardState(target="10.10.10.1")
        assert step.can_run(state_without_domain) is False

        # State with domain - should return True
        state_with_domain = MockWizardState(target="10.10.10.1", domain="cascade.local")
        assert step.can_run(state_with_domain) is True

    def test_step_run_returns_step_result(self):
        """Verify run() method returns StepResult dataclass."""
        from tools.post.bloodtrail.wizard.steps import WizardStep, StepResult

        class TestStep(WizardStep):
            id = "test_step"
            title = "Test Step"
            description = "Test description"

            def can_run(self, state):
                return True

            def run(self, state, context):
                return StepResult(
                    success=True,
                    next_step="next_step_id",
                    message="Step completed successfully",
                    data={"key": "value"}
                )

        step = TestStep()
        state = MockWizardState(target="10.10.10.1")
        result = step.run(state, {})

        # Verify StepResult structure
        assert isinstance(result, StepResult)
        assert result.success is True
        assert result.next_step == "next_step_id"
        assert result.message == "Step completed successfully"
        assert result.data == {"key": "value"}


class TestDetectStep:
    """Test DetectStep implementation."""

    @patch('tools.post.bloodtrail.wizard.steps.DetectStep._is_port_open')
    def test_detect_step_probes_common_ports(self, mock_is_port_open):
        """Verify DetectStep probes standard AD ports."""
        from tools.post.bloodtrail.wizard.steps import DetectStep

        # Mock socket probes - simulate open ports: 88 (Kerberos), 389 (LDAP), 445 (SMB)
        def port_open_side_effect(target, port):
            return port in {88, 389, 445}

        mock_is_port_open.side_effect = port_open_side_effect

        step = DetectStep()
        state = MockWizardState(target="10.10.10.182")
        context = {}

        result = step.run(state, context)

        # Verify success
        assert result.success is True

        # Verify detected services stored in state
        assert len(state.detected_services) > 0

        # Verify at least one AD-related service detected
        service_ports = [s.get('port') for s in state.detected_services]
        ad_ports = {88, 389, 445, 3389}
        assert any(port in ad_ports for port in service_ports), \
            f"Expected AD ports in {service_ports}"

        # Verify specific services detected
        assert 88 in service_ports, "Kerberos port should be detected"
        assert 389 in service_ports, "LDAP port should be detected"
        assert 445 in service_ports, "SMB port should be detected"

    @patch('tools.post.bloodtrail.wizard.steps.DetectStep._is_port_open')
    @patch('tools.post.bloodtrail.wizard.steps.DetectStep._detect_domain_via_ldap')
    def test_detect_step_identifies_domain_controller(self, mock_detect_domain, mock_is_port_open):
        """Verify DetectStep sets detected_dc flag when DC ports found."""
        from tools.post.bloodtrail.wizard.steps import DetectStep

        # Simulate DC signature: Kerberos (88) or LDAP (389) open
        def port_open_side_effect(target, port):
            return port in {88, 389}

        mock_is_port_open.side_effect = port_open_side_effect
        mock_detect_domain.return_value = "CASCADE.LOCAL"

        step = DetectStep()
        state = MockWizardState(target="10.10.10.182")
        context = {}

        result = step.run(state, context)

        # Verify DC detection
        assert state.detected_dc is True or state.detected_dc == "10.10.10.182", \
            "DetectStep should mark target as DC when ports 88/389 are open"

        # Verify domain detected
        assert state.detected_domain == "CASCADE.LOCAL"

        # Verify next step is correct
        assert result.next_step == "choose_mode"


class TestStepResultDataclass:
    """Test StepResult dataclass structure."""

    def test_step_result_has_required_fields(self):
        """Verify StepResult has all required fields."""
        from tools.post.bloodtrail.wizard.steps import StepResult

        result = StepResult(
            success=True,
            next_step="test_step"
        )

        assert result.success is True
        assert result.next_step == "test_step"
        assert result.message == ""  # Default value
        assert result.data == {}  # Default value

    def test_step_result_accepts_optional_fields(self):
        """Verify StepResult accepts optional message and data."""
        from tools.post.bloodtrail.wizard.steps import StepResult

        result = StepResult(
            success=False,
            next_step="retry",
            message="Connection timeout",
            data={"error_code": 500}
        )

        assert result.success is False
        assert result.next_step == "retry"
        assert result.message == "Connection timeout"
        assert result.data == {"error_code": 500}
