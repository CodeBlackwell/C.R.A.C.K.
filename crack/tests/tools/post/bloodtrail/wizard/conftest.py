"""
Shared fixtures for BloodTrail Wizard tests.
"""

import pytest
from pathlib import Path
from typing import Dict, List, Optional


@pytest.fixture
def wizard_state_factory():
    """Factory for creating WizardState instances with test data."""
    from tools.post.bloodtrail.wizard.state import WizardState

    def _create(
        target: str = "10.10.10.182",
        domain: Optional[str] = None,
        current_step: str = "detect",
        detected_services: Optional[List[Dict]] = None,
        detected_domain: Optional[str] = None,
        detected_dc: Optional[str] = None,
        selected_mode: str = "auto",
        skip_steps: Optional[List[str]] = None,
        completed_steps: Optional[List[str]] = None,
        findings: Optional[List[str]] = None,
        credentials: Optional[List[Dict]] = None,
        started_at: Optional[str] = None,
        last_checkpoint: Optional[str] = None,
    ) -> WizardState:
        """Create a WizardState with specified or default test data."""
        return WizardState(
            target=target,
            domain=domain,
            current_step=current_step,
            detected_services=detected_services or [],
            detected_domain=detected_domain,
            detected_dc=detected_dc,
            selected_mode=selected_mode,
            skip_steps=skip_steps or [],
            completed_steps=completed_steps or [],
            findings=findings or [],
            credentials=credentials or [],
            started_at=started_at,  # Will auto-set if None
            last_checkpoint=last_checkpoint,
        )

    return _create


@pytest.fixture
def test_wizard_state_data() -> Dict:
    """Complete test data for WizardState serialization tests."""
    return {
        "target": "10.10.10.182",
        "domain": "CASCADE.LOCAL",
        "current_step": "enumerate",
        "detected_services": [
            {"port": 88, "service": "kerberos"},
            {"port": 389, "service": "ldap"},
            {"port": 445, "service": "smb"},
        ],
        "detected_domain": "CASCADE.LOCAL",
        "detected_dc": "DC1.CASCADE.LOCAL",
        "selected_mode": "auto",
        "skip_steps": ["choose_mode"],
        "completed_steps": ["detect"],
        "findings": ["kerberos_detected", "ldap_accessible"],
        "credentials": [
            {"username": "r.thompson", "password": "rY4n5eva"},
        ],
        "started_at": "2025-01-10T10:00:00",
        "last_checkpoint": "2025-01-10T10:05:00",
    }


@pytest.fixture
def temp_wizard_state_dir(tmp_path: Path) -> Path:
    """Create a temporary directory for wizard state files."""
    state_dir = tmp_path / ".crack" / "wizard_state"
    state_dir.mkdir(parents=True, exist_ok=True)
    return state_dir


@pytest.fixture(autouse=True)
def mock_wizard_state_home(monkeypatch, tmp_path: Path):
    """Mock Path.home() to use temp directory for all wizard state tests."""
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
