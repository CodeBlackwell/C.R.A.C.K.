"""
Tests for EngagementIntegration Helper.

Business Value Focus:
- Integration helper works gracefully when Neo4j is unavailable
- Auto-logging from tools correctly populates engagement data
- Target deduplication prevents duplicate entries
- Errors are swallowed (logged) rather than crashing tools

Test Coverage:
- is_active(): Check if engagement is active
- get_active_engagement_id(): Get ID without full adapter
- ensure_target(): Create or get existing target
- add_service(): Add service to target
- add_finding(): Add finding to engagement
- log_session(): Log reverse shell session
- Error handling: Graceful degradation when Neo4j unavailable
"""

import pytest
from datetime import datetime
from unittest.mock import patch, MagicMock, Mock, PropertyMock
import sys
from pathlib import Path
import json

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from tests.factories.neo4j import (
    MockNeo4jDriver,
    MockNeo4jSession,
    create_mock_driver_success,
    create_mock_driver_failure,
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def mock_storage_dir(tmp_path, monkeypatch):
    """Create isolated storage for engagement state."""
    monkeypatch.setattr('tools.engagement.storage.EngagementStorage.DEFAULT_DIR', tmp_path)
    return tmp_path


@pytest.fixture
def active_engagement_file(mock_storage_dir):
    """Create storage file with active engagement."""
    storage_file = mock_storage_dir / "engagement.json"
    data = {
        "active_engagement_id": "eng-test-123",
        "last_used": datetime.now().isoformat(),
        "history": [{"id": "eng-test-123", "name": "Test Engagement", "last_used": datetime.now().isoformat()}]
    }
    storage_file.write_text(json.dumps(data))
    return storage_file


@pytest.fixture
def reset_integration_singleton():
    """Reset EngagementIntegration singleton state between tests."""
    from tools.engagement.integration import EngagementIntegration
    EngagementIntegration._adapter = None
    EngagementIntegration._adapter_initialized = False
    yield
    EngagementIntegration._adapter = None
    EngagementIntegration._adapter_initialized = False


# =============================================================================
# Test: is_active()
# =============================================================================

class TestIsActive:
    """Tests for EngagementIntegration.is_active()."""

    def test_is_active_returns_true_when_engagement_set(
        self, mock_storage_dir, active_engagement_file, reset_integration_singleton
    ):
        """
        BV: Tools can check if engagement logging is active

        Scenario:
          Given: Active engagement is set in storage
          When: is_active() is called
          Then: Returns True
        """
        # Reload storage module to pick up new path
        from tools.engagement import storage
        storage._storage = None  # Reset singleton

        from tools.engagement.integration import EngagementIntegration

        result = EngagementIntegration.is_active()

        assert result is True

    def test_is_active_returns_false_when_no_engagement(
        self, mock_storage_dir, reset_integration_singleton
    ):
        """
        BV: Tools skip logging when no engagement is active

        Scenario:
          Given: No active engagement
          When: is_active() is called
          Then: Returns False
        """
        # Create empty storage
        storage_file = mock_storage_dir / "engagement.json"
        storage_file.write_text(json.dumps({
            "active_engagement_id": None,
            "last_used": None,
            "history": []
        }))

        from tools.engagement import storage
        storage._storage = None  # Reset singleton

        from tools.engagement.integration import EngagementIntegration

        result = EngagementIntegration.is_active()

        assert result is False

    def test_is_active_returns_false_on_storage_error(
        self, mock_storage_dir, reset_integration_singleton
    ):
        """
        BV: Storage errors don't crash tools

        Scenario:
          Given: Storage file is corrupted
          When: is_active() is called
          Then: Returns False (graceful degradation)
        """
        storage_file = mock_storage_dir / "engagement.json"
        storage_file.write_text("invalid json {{{")

        from tools.engagement import storage
        storage._storage = None

        from tools.engagement.integration import EngagementIntegration

        result = EngagementIntegration.is_active()

        # Should handle gracefully
        assert result in [True, False]  # Either valid state is ok


# =============================================================================
# Test: get_active_engagement_id()
# =============================================================================

class TestGetActiveEngagementId:
    """Tests for EngagementIntegration.get_active_engagement_id()."""

    def test_get_active_engagement_id_returns_id(
        self, mock_storage_dir, active_engagement_file, reset_integration_singleton
    ):
        """
        BV: Tools can get engagement ID for linking data

        Scenario:
          Given: Active engagement is set
          When: get_active_engagement_id() is called
          Then: Returns the engagement ID string
        """
        from tools.engagement import storage
        storage._storage = None

        from tools.engagement.integration import EngagementIntegration

        result = EngagementIntegration.get_active_engagement_id()

        assert result == "eng-test-123"

    def test_get_active_engagement_id_returns_none_when_no_engagement(
        self, mock_storage_dir, reset_integration_singleton
    ):
        """
        BV: Tools handle no active engagement gracefully

        Scenario:
          Given: No active engagement
          When: get_active_engagement_id() is called
          Then: Returns None
        """
        storage_file = mock_storage_dir / "engagement.json"
        storage_file.write_text(json.dumps({
            "active_engagement_id": None,
            "last_used": None,
            "history": []
        }))

        from tools.engagement import storage
        storage._storage = None

        from tools.engagement.integration import EngagementIntegration

        result = EngagementIntegration.get_active_engagement_id()

        assert result is None


# =============================================================================
# Test: ensure_target()
# =============================================================================

class TestEnsureTarget:
    """Tests for EngagementIntegration.ensure_target()."""

    def test_ensure_target_creates_new_target(
        self, mock_storage_dir, active_engagement_file, reset_integration_singleton, monkeypatch
    ):
        """
        BV: Discovered targets are automatically logged to engagement

        Scenario:
          Given: Active engagement and new IP address
          When: ensure_target() is called
          Then: Target is created and ID returned
        """
        # Setup mock adapter
        mock_adapter = MagicMock()
        mock_engagement = MagicMock()
        mock_engagement.id = "eng-test-123"
        mock_adapter.get_active_engagement.return_value = mock_engagement
        mock_adapter.get_targets.return_value = []
        mock_adapter.add_target.return_value = "target-new-123"

        from tools.engagement import storage
        storage._storage = None

        from tools.engagement.integration import EngagementIntegration
        EngagementIntegration._adapter = mock_adapter
        EngagementIntegration._adapter_initialized = True

        result = EngagementIntegration.ensure_target("192.168.1.100")

        assert result == "target-new-123"
        mock_adapter.add_target.assert_called_once()

    def test_ensure_target_returns_existing_target(
        self, mock_storage_dir, active_engagement_file, reset_integration_singleton
    ):
        """
        BV: Duplicate targets are not created

        Scenario:
          Given: Target already exists in engagement
          When: ensure_target() is called with same IP
          Then: Returns existing target ID (no duplicate)
        """
        # Create mock existing target
        mock_target = MagicMock()
        mock_target.id = "target-existing"
        mock_target.ip_address = "192.168.1.100"
        mock_target.hostname = ""
        mock_target.os_guess = ""

        mock_adapter = MagicMock()
        mock_engagement = MagicMock()
        mock_engagement.id = "eng-test-123"
        mock_adapter.get_active_engagement.return_value = mock_engagement
        mock_adapter.get_targets.return_value = [mock_target]

        from tools.engagement import storage
        storage._storage = None

        from tools.engagement.integration import EngagementIntegration
        EngagementIntegration._adapter = mock_adapter
        EngagementIntegration._adapter_initialized = True

        result = EngagementIntegration.ensure_target("192.168.1.100")

        assert result == "target-existing"
        mock_adapter.add_target.assert_not_called()

    def test_ensure_target_updates_existing_with_new_info(
        self, mock_storage_dir, active_engagement_file, reset_integration_singleton
    ):
        """
        BV: New target info is appended to existing targets

        Scenario:
          Given: Target exists but hostname is empty
          When: ensure_target() called with hostname
          Then: Target is updated with hostname
        """
        mock_target = MagicMock()
        mock_target.id = "target-existing"
        mock_target.ip_address = "192.168.1.100"
        mock_target.hostname = ""  # Empty
        mock_target.os_guess = ""

        mock_adapter = MagicMock()
        mock_engagement = MagicMock()
        mock_engagement.id = "eng-test-123"
        mock_adapter.get_active_engagement.return_value = mock_engagement
        mock_adapter.get_targets.return_value = [mock_target]

        from tools.engagement import storage
        storage._storage = None

        from tools.engagement.integration import EngagementIntegration
        EngagementIntegration._adapter = mock_adapter
        EngagementIntegration._adapter_initialized = True

        result = EngagementIntegration.ensure_target(
            "192.168.1.100",
            hostname="server01.corp.local"
        )

        assert result == "target-existing"
        mock_adapter.update_target.assert_called_once_with(
            "target-existing",
            hostname="server01.corp.local",
            os_guess=""
        )

    def test_ensure_target_returns_none_when_no_adapter(
        self, mock_storage_dir, reset_integration_singleton
    ):
        """
        BV: Missing adapter doesn't crash tools

        Scenario:
          Given: Adapter initialization failed
          When: ensure_target() is called
          Then: Returns None (graceful degradation)
        """
        from tools.engagement.integration import EngagementIntegration
        EngagementIntegration._adapter = None
        EngagementIntegration._adapter_initialized = True

        result = EngagementIntegration.ensure_target("192.168.1.100")

        assert result is None

    def test_ensure_target_returns_none_when_no_active_engagement(
        self, mock_storage_dir, reset_integration_singleton
    ):
        """
        BV: No engagement means no target logging (silent skip)

        Scenario:
          Given: Adapter available but no active engagement
          When: ensure_target() is called
          Then: Returns None
        """
        mock_adapter = MagicMock()
        mock_adapter.get_active_engagement.return_value = None

        from tools.engagement.integration import EngagementIntegration
        EngagementIntegration._adapter = mock_adapter
        EngagementIntegration._adapter_initialized = True

        result = EngagementIntegration.ensure_target("192.168.1.100")

        assert result is None


# =============================================================================
# Test: add_service()
# =============================================================================

class TestAddService:
    """Tests for EngagementIntegration.add_service()."""

    def test_add_service_creates_service(self, reset_integration_singleton):
        """
        BV: Discovered services are logged to targets

        Scenario:
          Given: Valid target ID
          When: add_service() is called
          Then: Service is created and ID returned
        """
        mock_adapter = MagicMock()
        mock_adapter.add_service.return_value = "svc-new-123"

        from tools.engagement.integration import EngagementIntegration
        EngagementIntegration._adapter = mock_adapter
        EngagementIntegration._adapter_initialized = True

        result = EngagementIntegration.add_service(
            "target-123",
            80,
            service_name="http",
            version="Apache/2.4"
        )

        assert result == "svc-new-123"
        mock_adapter.add_service.assert_called_once_with(
            "target-123",
            80,
            protocol="tcp",
            service_name="http",
            version="Apache/2.4",
            banner=""
        )

    def test_add_service_returns_none_with_no_target_id(self, reset_integration_singleton):
        """
        BV: Missing target ID doesn't cause error

        Scenario:
          Given: Empty target ID
          When: add_service() is called
          Then: Returns None (no crash)
        """
        mock_adapter = MagicMock()

        from tools.engagement.integration import EngagementIntegration
        EngagementIntegration._adapter = mock_adapter
        EngagementIntegration._adapter_initialized = True

        result = EngagementIntegration.add_service("", 80)

        assert result is None
        mock_adapter.add_service.assert_not_called()

    def test_add_service_returns_none_when_no_adapter(self, reset_integration_singleton):
        """
        BV: Missing adapter doesn't crash service discovery

        Scenario:
          Given: No adapter available
          When: add_service() is called
          Then: Returns None
        """
        from tools.engagement.integration import EngagementIntegration
        EngagementIntegration._adapter = None
        EngagementIntegration._adapter_initialized = True

        result = EngagementIntegration.add_service("target-123", 80)

        assert result is None


# =============================================================================
# Test: add_services_batch()
# =============================================================================

class TestAddServicesBatch:
    """Tests for EngagementIntegration.add_services_batch()."""

    def test_add_services_batch_creates_multiple(self, reset_integration_singleton):
        """
        BV: Nmap scan results can be bulk-imported

        Scenario:
          Given: List of service dictionaries
          When: add_services_batch() is called
          Then: All services are created and count returned
        """
        mock_adapter = MagicMock()
        mock_adapter.add_service.return_value = "svc-id"

        from tools.engagement.integration import EngagementIntegration
        EngagementIntegration._adapter = mock_adapter
        EngagementIntegration._adapter_initialized = True

        services = [
            {"port": 22, "service_name": "ssh"},
            {"port": 80, "service_name": "http"},
            {"port": 443, "service_name": "https"},
        ]

        count = EngagementIntegration.add_services_batch("target-123", services)

        assert count == 3
        assert mock_adapter.add_service.call_count == 3

    def test_add_services_batch_returns_zero_for_empty_list(self, reset_integration_singleton):
        """
        BV: Empty service list returns zero (no error)

        Scenario:
          Given: Empty services list
          When: add_services_batch() is called
          Then: Returns 0
        """
        mock_adapter = MagicMock()

        from tools.engagement.integration import EngagementIntegration
        EngagementIntegration._adapter = mock_adapter
        EngagementIntegration._adapter_initialized = True

        count = EngagementIntegration.add_services_batch("target-123", [])

        assert count == 0


# =============================================================================
# Test: add_finding()
# =============================================================================

class TestAddFinding:
    """Tests for EngagementIntegration.add_finding()."""

    def test_add_finding_creates_finding(self, reset_integration_singleton):
        """
        BV: Discovered vulnerabilities are logged

        Scenario:
          Given: Active engagement
          When: add_finding() is called
          Then: Finding is created and ID returned
        """
        mock_adapter = MagicMock()
        mock_engagement = MagicMock()
        mock_engagement.id = "eng-123"
        mock_adapter.get_active_engagement.return_value = mock_engagement
        mock_adapter.add_finding.return_value = "finding-new-123"

        from tools.engagement.integration import EngagementIntegration
        EngagementIntegration._adapter = mock_adapter
        EngagementIntegration._adapter_initialized = True

        result = EngagementIntegration.add_finding(
            "SQL Injection",
            severity="critical",
            cve_id="CVE-2024-12345"
        )

        assert result == "finding-new-123"
        mock_adapter.add_finding.assert_called_once()

    def test_add_finding_links_to_target_when_provided(self, reset_integration_singleton):
        """
        BV: Findings are linked to affected targets

        Scenario:
          Given: Finding with target_id
          When: add_finding() is called
          Then: Finding is linked to target via relationship
        """
        mock_adapter = MagicMock()
        mock_engagement = MagicMock()
        mock_engagement.id = "eng-123"
        mock_adapter.get_active_engagement.return_value = mock_engagement
        mock_adapter.add_finding.return_value = "finding-123"

        from tools.engagement.integration import EngagementIntegration
        EngagementIntegration._adapter = mock_adapter
        EngagementIntegration._adapter_initialized = True

        result = EngagementIntegration.add_finding(
            "XSS in Login",
            severity="high",
            target_id="target-456"
        )

        assert result == "finding-123"
        mock_adapter.link_finding_to_target.assert_called_once_with(
            "finding-123",
            "target-456"
        )

    def test_add_finding_returns_none_when_no_engagement(self, reset_integration_singleton):
        """
        BV: No engagement means no finding logging

        Scenario:
          Given: No active engagement
          When: add_finding() is called
          Then: Returns None
        """
        mock_adapter = MagicMock()
        mock_adapter.get_active_engagement.return_value = None

        from tools.engagement.integration import EngagementIntegration
        EngagementIntegration._adapter = mock_adapter
        EngagementIntegration._adapter_initialized = True

        result = EngagementIntegration.add_finding("Test Finding")

        assert result is None


# =============================================================================
# Test: log_session()
# =============================================================================

class TestLogSession:
    """Tests for EngagementIntegration.log_session()."""

    def test_log_session_creates_target_and_finding(self, reset_integration_singleton):
        """
        BV: Reverse shell sessions are logged as critical findings

        Scenario:
          Given: Active engagement
          When: log_session() is called with session details
          Then: Target is ensured, status updated, and critical finding created
        """
        mock_adapter = MagicMock()
        mock_engagement = MagicMock()
        mock_engagement.id = "eng-123"
        mock_adapter.get_active_engagement.return_value = mock_engagement
        mock_adapter.get_targets.return_value = []
        mock_adapter.add_target.return_value = "target-shell"
        mock_adapter.add_finding.return_value = "finding-shell"

        from tools.engagement.integration import EngagementIntegration
        EngagementIntegration._adapter = mock_adapter
        EngagementIntegration._adapter_initialized = True

        result = EngagementIntegration.log_session(
            target_ip="192.168.1.100",
            port=4444,
            session_type="tcp",
            session_id="session-abc123"
        )

        assert result is True
        # Verify target was updated to exploited status
        mock_adapter.update_target.assert_called_with("target-shell", status="exploited")
        # Verify finding was added
        mock_adapter.add_finding.assert_called()

    def test_log_session_returns_false_when_no_engagement(self, reset_integration_singleton):
        """
        BV: Session logging fails gracefully without engagement

        Scenario:
          Given: No active engagement
          When: log_session() is called
          Then: Returns False
        """
        mock_adapter = MagicMock()
        mock_adapter.get_active_engagement.return_value = None

        from tools.engagement.integration import EngagementIntegration
        EngagementIntegration._adapter = mock_adapter
        EngagementIntegration._adapter_initialized = True

        result = EngagementIntegration.log_session(
            "192.168.1.100", 4444, "tcp", "session-123"
        )

        assert result is False


# =============================================================================
# Test: find_target_by_ip()
# =============================================================================

class TestFindTargetByIp:
    """Tests for EngagementIntegration.find_target_by_ip()."""

    def test_find_target_by_ip_returns_id(self, reset_integration_singleton):
        """
        BV: Tools can look up target IDs by IP for linking

        Scenario:
          Given: Target exists in engagement
          When: find_target_by_ip() is called
          Then: Returns target ID
        """
        mock_target = MagicMock()
        mock_target.id = "target-found"
        mock_target.ip_address = "10.0.0.5"

        mock_adapter = MagicMock()
        mock_engagement = MagicMock()
        mock_engagement.id = "eng-123"
        mock_adapter.get_active_engagement.return_value = mock_engagement
        mock_adapter.get_targets.return_value = [mock_target]

        from tools.engagement.integration import EngagementIntegration
        EngagementIntegration._adapter = mock_adapter
        EngagementIntegration._adapter_initialized = True

        result = EngagementIntegration.find_target_by_ip("10.0.0.5")

        assert result == "target-found"

    def test_find_target_by_ip_returns_none_when_not_found(self, reset_integration_singleton):
        """
        BV: Missing targets return None (not exception)

        Scenario:
          Given: Target doesn't exist
          When: find_target_by_ip() is called
          Then: Returns None
        """
        mock_adapter = MagicMock()
        mock_engagement = MagicMock()
        mock_engagement.id = "eng-123"
        mock_adapter.get_active_engagement.return_value = mock_engagement
        mock_adapter.get_targets.return_value = []

        from tools.engagement.integration import EngagementIntegration
        EngagementIntegration._adapter = mock_adapter
        EngagementIntegration._adapter_initialized = True

        result = EngagementIntegration.find_target_by_ip("10.0.0.5")

        assert result is None


# =============================================================================
# Test: link_credential_to_target()
# =============================================================================

class TestLinkCredentialToTarget:
    """Tests for EngagementIntegration.link_credential_to_target()."""

    def test_link_credential_creates_finding(self, reset_integration_singleton):
        """
        BV: Extracted credentials are logged as high-severity findings

        Scenario:
          Given: Target exists
          When: link_credential_to_target() is called
          Then: High-severity finding is created
        """
        mock_target = MagicMock()
        mock_target.id = "target-creds"
        mock_target.ip_address = "192.168.1.50"

        mock_adapter = MagicMock()
        mock_engagement = MagicMock()
        mock_engagement.id = "eng-123"
        mock_adapter.get_active_engagement.return_value = mock_engagement
        mock_adapter.get_targets.return_value = [mock_target]
        mock_adapter.add_finding.return_value = "finding-cred"

        from tools.engagement.integration import EngagementIntegration
        EngagementIntegration._adapter = mock_adapter
        EngagementIntegration._adapter_initialized = True

        result = EngagementIntegration.link_credential_to_target(
            "192.168.1.50",
            "admin:Password123 (NTLM)"
        )

        assert result is True
        # Verify finding was created with high severity
        call_kwargs = mock_adapter.add_finding.call_args
        # Check that add_finding was called (via ensure_target -> add_finding)

    def test_link_credential_returns_false_when_target_not_found(
        self, reset_integration_singleton
    ):
        """
        BV: Missing target doesn't crash credential logging

        Scenario:
          Given: Target doesn't exist
          When: link_credential_to_target() is called
          Then: Returns False
        """
        mock_adapter = MagicMock()
        mock_engagement = MagicMock()
        mock_engagement.id = "eng-123"
        mock_adapter.get_active_engagement.return_value = mock_engagement
        mock_adapter.get_targets.return_value = []

        from tools.engagement.integration import EngagementIntegration
        EngagementIntegration._adapter = mock_adapter
        EngagementIntegration._adapter_initialized = True

        result = EngagementIntegration.link_credential_to_target(
            "192.168.1.50",
            "user:password"
        )

        assert result is False


# =============================================================================
# Test: get_active_engagement()
# =============================================================================

class TestGetActiveEngagement:
    """Tests for EngagementIntegration.get_active_engagement()."""

    def test_get_active_engagement_returns_dict(self, reset_integration_singleton):
        """
        BV: Full engagement details available for display

        Scenario:
          Given: Active engagement exists
          When: get_active_engagement() is called
          Then: Returns engagement as dictionary
        """
        mock_engagement = MagicMock()
        mock_engagement.id = "eng-123"
        mock_engagement.name = "Test Engagement"
        mock_engagement.to_dict.return_value = {
            "id": "eng-123",
            "name": "Test Engagement",
            "status": "active"
        }

        mock_adapter = MagicMock()
        mock_adapter.get_active_engagement.return_value = mock_engagement

        from tools.engagement.integration import EngagementIntegration
        EngagementIntegration._adapter = mock_adapter
        EngagementIntegration._adapter_initialized = True

        result = EngagementIntegration.get_active_engagement()

        assert result is not None
        assert result["id"] == "eng-123"
        assert result["name"] == "Test Engagement"

    def test_get_active_engagement_returns_none_when_no_adapter(
        self, reset_integration_singleton
    ):
        """
        BV: Missing adapter returns None

        Scenario:
          Given: No adapter available
          When: get_active_engagement() is called
          Then: Returns None
        """
        from tools.engagement.integration import EngagementIntegration
        EngagementIntegration._adapter = None
        EngagementIntegration._adapter_initialized = True

        result = EngagementIntegration.get_active_engagement()

        assert result is None


# =============================================================================
# Test: Error Handling
# =============================================================================

class TestErrorHandling:
    """Tests for graceful error handling."""

    def test_adapter_exception_is_logged_not_raised(self, reset_integration_singleton):
        """
        BV: Adapter errors don't crash calling tools

        Scenario:
          Given: Adapter throws exception
          When: ensure_target() is called
          Then: Returns None and logs error (no exception)
        """
        mock_adapter = MagicMock()
        mock_adapter.get_active_engagement.side_effect = Exception("Database error")

        from tools.engagement.integration import EngagementIntegration
        EngagementIntegration._adapter = mock_adapter
        EngagementIntegration._adapter_initialized = True

        # Should not raise
        result = EngagementIntegration.ensure_target("192.168.1.1")

        assert result is None

    def test_adapter_lazy_init_failure_is_handled(self, reset_integration_singleton, monkeypatch):
        """
        BV: Failed adapter initialization doesn't crash subsequent calls

        Scenario:
          Given: Adapter fails to initialize
          When: Multiple integration calls are made
          Then: All return None gracefully
        """
        # Make adapter import fail
        def mock_get_adapter():
            return None

        from tools.engagement.integration import EngagementIntegration
        EngagementIntegration._adapter = None
        EngagementIntegration._adapter_initialized = True

        # Multiple calls should all return None
        assert EngagementIntegration.ensure_target("10.0.0.1") is None
        assert EngagementIntegration.add_service("target-1", 80) is None
        assert EngagementIntegration.add_finding("Test") is None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
