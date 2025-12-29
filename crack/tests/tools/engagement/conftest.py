"""
Pytest configuration and fixtures for Engagement tests.

Business Value Focus:
- Isolated test state (no leakage between tests)
- Mock Neo4j driver for all adapter tests
- Clean engagement storage for each test
- Factory fixtures for creating test entities

Fixtures:
- mock_neo4j_driver: Pre-configured mock driver
- mock_engagement_storage: Isolated storage directory
- engagement_factory: Factory for creating Engagement objects
- target_factory: Factory for creating Target objects
- client_factory: Factory for creating Client objects
"""

import pytest
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional
from unittest.mock import MagicMock, patch

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from tests.factories.neo4j import (
    MockNeo4jDriver,
    MockNeo4jSession,
    create_mock_driver_success,
    create_mock_driver_failure,
)


# =============================================================================
# Storage Fixtures
# =============================================================================

@pytest.fixture
def mock_engagement_storage(tmp_path, monkeypatch):
    """
    Isolated engagement storage for tests.

    BV: Each test gets its own storage directory to prevent leakage.

    Returns:
        Path to temporary storage directory
    """
    # Patch the storage module to use temp directory
    monkeypatch.setattr(
        'tools.engagement.storage.EngagementStorage.DEFAULT_DIR',
        tmp_path
    )

    # Reset the singleton
    from tools.engagement import storage
    storage._storage = None

    return tmp_path


@pytest.fixture
def active_engagement_storage(mock_engagement_storage):
    """
    Storage with an active engagement pre-configured.

    BV: Tests can start with engagement already active.

    Returns:
        Tuple of (storage_path, engagement_id)
    """
    engagement_id = "eng-fixture-123"
    storage_file = mock_engagement_storage / "engagement.json"
    data = {
        "active_engagement_id": engagement_id,
        "last_used": datetime.now().isoformat(),
        "history": [
            {
                "id": engagement_id,
                "name": "Test Fixture Engagement",
                "last_used": datetime.now().isoformat()
            }
        ]
    }
    storage_file.write_text(json.dumps(data))

    # Reset storage singleton to pick up new file
    from tools.engagement import storage
    storage._storage = None

    return mock_engagement_storage, engagement_id


# =============================================================================
# Neo4j Mock Fixtures
# =============================================================================

@pytest.fixture
def mock_neo4j_driver():
    """
    Fresh mock Neo4j driver for each test.

    BV: Tests don't require live Neo4j database.
    """
    return MockNeo4jDriver(records=[])


@pytest.fixture
def mock_neo4j_driver_with_records():
    """
    Factory for creating driver with specific records.

    BV: Tests can configure expected Neo4j responses.

    Usage:
        def test_something(mock_neo4j_driver_with_records):
            driver = mock_neo4j_driver_with_records([{"id": "test"}])
    """
    def _factory(records: List[Dict[str, Any]]) -> MockNeo4jDriver:
        return MockNeo4jDriver(records=records)
    return _factory


@pytest.fixture
def mock_neo4j_failure():
    """
    Mock driver that simulates connection failure.

    BV: Tests verify graceful error handling.
    """
    return create_mock_driver_failure(
        exception_type=ConnectionError,
        message="Connection refused"
    )


# =============================================================================
# Entity Factories
# =============================================================================

class ClientFactory:
    """Factory for creating test Client objects."""

    _counter = 0

    @classmethod
    def reset(cls):
        """Reset counter for deterministic tests."""
        cls._counter = 0

    @classmethod
    def create(
        cls,
        name: str = None,
        organization: str = "",
        contact_email: str = "",
        industry: str = "",
        notes: str = ""
    ):
        """Create Client with sensible defaults."""
        from tools.engagement.models import Client

        cls._counter += 1
        return Client.create(
            name=name or f"TestClient{cls._counter}",
            organization=organization,
            contact_email=contact_email,
            industry=industry,
            notes=notes
        )


class EngagementFactory:
    """Factory for creating test Engagement objects."""

    _counter = 0

    @classmethod
    def reset(cls):
        """Reset counter for deterministic tests."""
        cls._counter = 0

    @classmethod
    def create(
        cls,
        name: str = None,
        client_id: str = "client-default",
        scope_type: str = "external",
        scope_text: str = "192.168.1.0/24",
        **kwargs
    ):
        """Create Engagement with sensible defaults."""
        from tools.engagement.models import Engagement

        cls._counter += 1
        return Engagement.create(
            name=name or f"TestEngagement{cls._counter}",
            client_id=client_id,
            scope_type=scope_type,
            scope_text=scope_text,
            **kwargs
        )


class TargetFactory:
    """Factory for creating test Target objects."""

    _counter = 0

    @classmethod
    def reset(cls):
        """Reset counter for deterministic tests."""
        cls._counter = 0

    @classmethod
    def create(
        cls,
        ip_or_hostname: str = None,
        hostname: str = "",
        os_guess: str = "",
        **kwargs
    ):
        """Create Target with sensible defaults."""
        from tools.engagement.models import Target

        cls._counter += 1
        if ip_or_hostname is None:
            ip_or_hostname = f"192.168.1.{cls._counter}"

        return Target.create(
            ip_or_hostname,
            hostname=hostname,
            os_guess=os_guess,
            **kwargs
        )

    @classmethod
    def create_with_hostname(cls, hostname: str, **kwargs):
        """Create Target from hostname."""
        return cls.create(hostname, **kwargs)


class ServiceFactory:
    """Factory for creating test Service objects."""

    _counter = 0

    @classmethod
    def reset(cls):
        """Reset counter for deterministic tests."""
        cls._counter = 0

    @classmethod
    def create(
        cls,
        target_id: str = "target-default",
        port: int = None,
        protocol: str = "tcp",
        service_name: str = "",
        **kwargs
    ):
        """Create Service with sensible defaults."""
        from tools.engagement.models import Service

        cls._counter += 1
        return Service.create(
            target_id=target_id,
            port=port or (80 + cls._counter),
            protocol=protocol,
            service_name=service_name,
            **kwargs
        )


class FindingFactory:
    """Factory for creating test Finding objects."""

    _counter = 0

    @classmethod
    def reset(cls):
        """Reset counter for deterministic tests."""
        cls._counter = 0

    @classmethod
    def create(
        cls,
        title: str = None,
        severity: str = "medium",
        cve_id: str = "",
        **kwargs
    ):
        """Create Finding with sensible defaults."""
        from tools.engagement.models import Finding

        cls._counter += 1
        return Finding.create(
            title=title or f"TestFinding{cls._counter}",
            severity=severity,
            cve_id=cve_id,
            **kwargs
        )

    @classmethod
    def create_critical(cls, title: str = None, **kwargs):
        """Create critical severity finding."""
        return cls.create(
            title=title or "Critical Vulnerability",
            severity="critical",
            **kwargs
        )


# =============================================================================
# Factory Fixtures
# =============================================================================

@pytest.fixture
def client_factory():
    """
    Factory for creating test clients.

    BV: Consistent client creation across tests.
    """
    ClientFactory.reset()
    return ClientFactory


@pytest.fixture
def engagement_factory():
    """
    Factory for creating test engagements.

    BV: Consistent engagement creation across tests.
    """
    EngagementFactory.reset()
    return EngagementFactory


@pytest.fixture
def target_factory():
    """
    Factory for creating test targets.

    BV: Consistent target creation across tests.
    """
    TargetFactory.reset()
    return TargetFactory


@pytest.fixture
def service_factory():
    """
    Factory for creating test services.

    BV: Consistent service creation across tests.
    """
    ServiceFactory.reset()
    return ServiceFactory


@pytest.fixture
def finding_factory():
    """
    Factory for creating test findings.

    BV: Consistent finding creation across tests.
    """
    FindingFactory.reset()
    return FindingFactory


# =============================================================================
# Integration Singleton Reset
# =============================================================================

@pytest.fixture(autouse=True)
def reset_integration_singleton():
    """
    Reset EngagementIntegration singleton between tests.

    BV: Tests are isolated from adapter state.
    """
    try:
        from tools.engagement.integration import EngagementIntegration
        EngagementIntegration._adapter = None
        EngagementIntegration._adapter_initialized = False
    except ImportError:
        pass

    yield

    try:
        from tools.engagement.integration import EngagementIntegration
        EngagementIntegration._adapter = None
        EngagementIntegration._adapter_initialized = False
    except ImportError:
        pass


# =============================================================================
# Assertion Helpers
# =============================================================================

class EngagementAssertions:
    """Reusable assertion helpers for engagement tests."""

    @staticmethod
    def assert_entity_has_id(entity, prefix: str = ""):
        """Assert entity has valid ID with optional prefix."""
        assert hasattr(entity, 'id'), f"Entity missing 'id' attribute"
        assert entity.id, "Entity ID is empty"
        if prefix:
            assert entity.id.startswith(prefix), \
                f"Expected ID prefix '{prefix}', got '{entity.id}'"

    @staticmethod
    def assert_roundtrip_preserves_data(original, entity_class):
        """Assert to_dict/from_dict preserves all data."""
        data = original.to_dict()
        restored = entity_class.from_dict(data)

        for key in data.keys():
            original_val = getattr(original, key, None)
            restored_val = getattr(restored, key, None)

            # Handle enum comparison
            if hasattr(original_val, 'value'):
                original_val = original_val.value
            if hasattr(restored_val, 'value'):
                restored_val = restored_val.value

            assert original_val == restored_val, \
                f"Field '{key}' mismatch: {original_val} != {restored_val}"

    @staticmethod
    def assert_query_contains(queries: List[tuple], *keywords: str):
        """Assert at least one query contains all keywords."""
        for query, params in queries:
            if all(kw in query for kw in keywords):
                return
        raise AssertionError(
            f"No query found containing all keywords: {keywords}\n"
            f"Queries run: {[q[0] for q in queries]}"
        )


@pytest.fixture
def engagement_assertions():
    """
    Engagement-specific assertion helpers.

    BV: Consistent assertions with clear error messages.
    """
    return EngagementAssertions


# =============================================================================
# Sample Data Fixtures
# =============================================================================

@pytest.fixture
def sample_engagement_data():
    """
    Pre-built sample data for common test scenarios.

    BV: Reduces test setup boilerplate.

    Returns dict with:
        - client: Sample Client object
        - engagement: Sample Engagement object
        - targets: List of Target objects
        - services: List of Service objects
        - findings: List of Finding objects
    """
    ClientFactory.reset()
    EngagementFactory.reset()
    TargetFactory.reset()
    ServiceFactory.reset()
    FindingFactory.reset()

    client = ClientFactory.create(
        name="ACME Corp",
        organization="ACME Corporation",
        industry="Technology"
    )

    engagement = EngagementFactory.create(
        name="Q4 External Pentest",
        client_id=client.id,
        scope_type="external",
        scope_text="10.0.0.0/8"
    )

    targets = [
        TargetFactory.create("192.168.1.10", hostname="web01.acme.local"),
        TargetFactory.create("192.168.1.20", hostname="db01.acme.local"),
        TargetFactory.create("192.168.1.30", hostname="dc01.acme.local"),
    ]

    services = [
        ServiceFactory.create(targets[0].id, 80, service_name="http"),
        ServiceFactory.create(targets[0].id, 443, service_name="https"),
        ServiceFactory.create(targets[1].id, 3306, service_name="mysql"),
        ServiceFactory.create(targets[2].id, 445, service_name="microsoft-ds"),
    ]

    findings = [
        FindingFactory.create_critical(
            title="SQL Injection in Login",
            cve_id="CVE-2024-1234"
        ),
        FindingFactory.create(
            title="Missing Security Headers",
            severity="low"
        ),
    ]

    return {
        "client": client,
        "engagement": engagement,
        "targets": targets,
        "services": services,
        "findings": findings,
    }
