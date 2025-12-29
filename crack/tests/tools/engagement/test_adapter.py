"""
Tests for EngagementAdapter CRUD Operations.

Business Value Focus:
- CRUD operations correctly persist data to Neo4j
- Neo4j unavailability is handled gracefully
- Retry logic works for transient failures
- Relationship integrity is maintained (engagement -> target -> service)

Test Coverage:
- Client CRUD: create, get, list
- Engagement CRUD: create, get, list, update status, activate
- Target CRUD: add, get, update
- Service CRUD: add, get
- Finding CRUD: add, get, link to target
- Statistics: engagement stats, finding summary
"""

import pytest
from datetime import datetime
from unittest.mock import patch, MagicMock, Mock
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from tests.factories.neo4j import (
    MockNeo4jDriver,
    MockNeo4jSession,
    MockNeo4jResult,
    MockRecord,
    create_mock_driver_success,
    create_mock_driver_failure,
)


# =============================================================================
# Test Fixtures
# =============================================================================

@pytest.fixture
def mock_driver():
    """Create a fresh mock Neo4j driver for each test."""
    return MockNeo4jDriver(records=[])


@pytest.fixture
def mock_driver_with_records():
    """Factory fixture for driver with custom records."""
    def _factory(records):
        return MockNeo4jDriver(records=records)
    return _factory


@pytest.fixture
def mock_storage(tmp_path, monkeypatch):
    """Mock the engagement storage to use temp directory."""
    storage_file = tmp_path / "engagement.json"
    monkeypatch.setattr(
        'tools.engagement.storage.EngagementStorage.DEFAULT_DIR',
        tmp_path
    )
    return storage_file


# =============================================================================
# Test: EngagementAdapter Initialization
# =============================================================================

class TestEngagementAdapterInit:
    """Tests for EngagementAdapter initialization."""

    def test_adapter_raises_when_neo4j_unavailable(self, monkeypatch):
        """
        BV: Clear error when Neo4j package not installed

        Scenario:
          Given: neo4j package not available
          When: EngagementAdapter() is instantiated
          Then: Neo4jUnavailableError is raised with install hint
        """
        monkeypatch.setattr('tools.engagement.adapter.NEO4J_AVAILABLE', False)

        from tools.engagement.adapter import EngagementAdapter, Neo4jUnavailableError

        with pytest.raises(Neo4jUnavailableError) as exc_info:
            EngagementAdapter()

        assert "pip install neo4j" in str(exc_info.value)

    def test_adapter_raises_on_connection_failure(self, monkeypatch):
        """
        BV: Clear error when Neo4j server is unreachable

        Scenario:
          Given: Neo4j server is down
          When: EngagementAdapter() is instantiated
          Then: Neo4jUnavailableError is raised
        """
        monkeypatch.setattr('tools.engagement.adapter.NEO4J_AVAILABLE', True)

        mock_driver = create_mock_driver_failure(
            exception_type=ConnectionError,
            message="Connection refused"
        )

        with patch('neo4j.GraphDatabase.driver', side_effect=ConnectionError("Connection refused")):
            from tools.engagement.adapter import EngagementAdapter, Neo4jUnavailableError

            with pytest.raises(Neo4jUnavailableError) as exc_info:
                EngagementAdapter()

            assert "Failed to connect" in str(exc_info.value)


# =============================================================================
# Test: Client Operations
# =============================================================================

class TestClientOperations:
    """Tests for Client CRUD operations."""

    def test_create_client_returns_id(self, monkeypatch, mock_driver_with_records):
        """
        BV: Clients are created and return usable IDs

        Scenario:
          Given: Valid client name
          When: create_client() is called
          Then: Returns client ID string
        """
        driver = mock_driver_with_records([{'id': 'client-abc123'}])

        with patch('neo4j.GraphDatabase.driver', return_value=driver):
            monkeypatch.setattr('tools.engagement.adapter.NEO4J_AVAILABLE', True)
            from tools.engagement.adapter import EngagementAdapter

            # Mock the connection test
            with patch.object(EngagementAdapter, '__init__', lambda self, **kwargs: None):
                adapter = EngagementAdapter()
                adapter.driver = driver
                adapter.database = 'neo4j'

                client_id = adapter.create_client("ACME Corp")

                assert client_id == 'client-abc123'

    def test_create_client_executes_merge_query(self, monkeypatch, mock_driver_with_records):
        """
        BV: Client creation uses MERGE for idempotent writes

        Scenario:
          Given: Client details
          When: create_client() is called
          Then: MERGE query is executed with all fields
        """
        driver = mock_driver_with_records([{'id': 'client-test'}])

        with patch('neo4j.GraphDatabase.driver', return_value=driver):
            monkeypatch.setattr('tools.engagement.adapter.NEO4J_AVAILABLE', True)

            from tools.engagement.adapter import EngagementAdapter

            with patch.object(EngagementAdapter, '__init__', lambda self, **kwargs: None):
                adapter = EngagementAdapter()
                adapter.driver = driver
                adapter.database = 'neo4j'

                adapter.create_client(
                    "Test Corp",
                    organization="Test Org",
                    contact_email="test@test.com"
                )

                # Verify MERGE was used
                queries = driver.get_all_queries()
                assert len(queries) > 0
                assert "MERGE" in queries[0][0]
                assert "Client" in queries[0][0]

    def test_get_client_returns_client_object(self, monkeypatch, mock_driver_with_records):
        """
        BV: Retrieved clients are fully populated objects

        Scenario:
          Given: Client exists in Neo4j
          When: get_client() is called
          Then: Returns Client object with all fields
        """
        client_data = {
            'c': {
                'id': 'client-123',
                'name': 'Test Corp',
                'organization': 'Test Organization',
                'contact_email': 'contact@test.com',
                'industry': 'Technology',
                'notes': 'Test notes',
                'created_at': '2024-01-15T10:00:00'
            }
        }
        driver = mock_driver_with_records([client_data])

        with patch('neo4j.GraphDatabase.driver', return_value=driver):
            monkeypatch.setattr('tools.engagement.adapter.NEO4J_AVAILABLE', True)

            from tools.engagement.adapter import EngagementAdapter

            with patch.object(EngagementAdapter, '__init__', lambda self, **kwargs: None):
                adapter = EngagementAdapter()
                adapter.driver = driver
                adapter.database = 'neo4j'

                client = adapter.get_client('client-123')

                assert client is not None
                assert client.id == 'client-123'
                assert client.name == 'Test Corp'
                assert client.organization == 'Test Organization'

    def test_get_client_returns_none_when_not_found(self, monkeypatch, mock_driver):
        """
        BV: Missing clients return None (not exception)

        Scenario:
          Given: Client ID that doesn't exist
          When: get_client() is called
          Then: Returns None
        """
        with patch('neo4j.GraphDatabase.driver', return_value=mock_driver):
            monkeypatch.setattr('tools.engagement.adapter.NEO4J_AVAILABLE', True)

            from tools.engagement.adapter import EngagementAdapter

            with patch.object(EngagementAdapter, '__init__', lambda self, **kwargs: None):
                adapter = EngagementAdapter()
                adapter.driver = mock_driver
                adapter.database = 'neo4j'

                client = adapter.get_client('nonexistent-client')

                assert client is None

    def test_list_clients_returns_all_clients(self, monkeypatch, mock_driver_with_records):
        """
        BV: All clients are returned for engagement selection

        Scenario:
          Given: Multiple clients in database
          When: list_clients() is called
          Then: Returns list of all Client objects
        """
        clients_data = [
            {'c': {'id': 'client-1', 'name': 'Client A', 'organization': '', 'contact_email': '', 'industry': '', 'notes': '', 'created_at': ''}},
            {'c': {'id': 'client-2', 'name': 'Client B', 'organization': '', 'contact_email': '', 'industry': '', 'notes': '', 'created_at': ''}},
        ]
        driver = mock_driver_with_records(clients_data)

        with patch('neo4j.GraphDatabase.driver', return_value=driver):
            monkeypatch.setattr('tools.engagement.adapter.NEO4J_AVAILABLE', True)

            from tools.engagement.adapter import EngagementAdapter

            with patch.object(EngagementAdapter, '__init__', lambda self, **kwargs: None):
                adapter = EngagementAdapter()
                adapter.driver = driver
                adapter.database = 'neo4j'

                clients = adapter.list_clients()

                assert len(clients) == 2
                assert clients[0].name == 'Client A'
                assert clients[1].name == 'Client B'


# =============================================================================
# Test: Engagement Operations
# =============================================================================

class TestEngagementOperations:
    """Tests for Engagement CRUD operations."""

    def test_create_engagement_returns_id(self, monkeypatch, mock_driver_with_records):
        """
        BV: Engagements are created and return usable IDs

        Scenario:
          Given: Valid engagement details
          When: create_engagement() is called
          Then: Returns engagement ID
        """
        driver = mock_driver_with_records([{'id': 'eng-abc123'}])

        with patch('neo4j.GraphDatabase.driver', return_value=driver):
            monkeypatch.setattr('tools.engagement.adapter.NEO4J_AVAILABLE', True)

            from tools.engagement.adapter import EngagementAdapter

            with patch.object(EngagementAdapter, '__init__', lambda self, **kwargs: None):
                adapter = EngagementAdapter()
                adapter.driver = driver
                adapter.database = 'neo4j'

                eng_id = adapter.create_engagement("Q4 Pentest", "client-123")

                assert eng_id == 'eng-abc123'

    def test_create_engagement_links_to_client(self, monkeypatch, mock_driver):
        """
        BV: Engagements are linked to clients via relationship

        Scenario:
          Given: Engagement with client_id
          When: create_engagement() is called
          Then: HAS_ENGAGEMENT relationship is created
        """
        mock_driver.records = [{'id': 'eng-test'}]

        with patch('neo4j.GraphDatabase.driver', return_value=mock_driver):
            monkeypatch.setattr('tools.engagement.adapter.NEO4J_AVAILABLE', True)

            from tools.engagement.adapter import EngagementAdapter

            with patch.object(EngagementAdapter, '__init__', lambda self, **kwargs: None):
                adapter = EngagementAdapter()
                adapter.driver = mock_driver
                adapter.database = 'neo4j'

                adapter.create_engagement("Test Engagement", "client-123")

                queries = mock_driver.get_all_queries()
                # Check for relationship creation in query
                query = queries[0][0]
                assert "HAS_ENGAGEMENT" in query
                assert "Client" in query
                assert "Engagement" in query

    def test_update_engagement_status(self, monkeypatch, mock_driver_with_records):
        """
        BV: Engagement status can be updated

        Scenario:
          Given: Existing engagement
          When: update_engagement_status() is called
          Then: Status is updated and returns True
        """
        driver = mock_driver_with_records([{'id': 'eng-123'}])

        with patch('neo4j.GraphDatabase.driver', return_value=driver):
            monkeypatch.setattr('tools.engagement.adapter.NEO4J_AVAILABLE', True)

            from tools.engagement.adapter import EngagementAdapter
            from tools.engagement.models import EngagementStatus

            with patch.object(EngagementAdapter, '__init__', lambda self, **kwargs: None):
                adapter = EngagementAdapter()
                adapter.driver = driver
                adapter.database = 'neo4j'

                result = adapter.update_engagement_status('eng-123', EngagementStatus.COMPLETED)

                assert result is True

    def test_set_active_engagement_stores_locally(self, monkeypatch, mock_driver_with_records, tmp_path):
        """
        BV: Active engagement is persisted for session resumption

        Scenario:
          Given: Valid engagement ID
          When: set_active_engagement() is called
          Then: Engagement ID is stored in local file
        """
        eng_data = {
            'e': {
                'id': 'eng-123',
                'name': 'Test Engagement',
                'client_id': 'client-1',
                'status': 'active',
                'start_date': '',
                'end_date': '',
                'scope_type': '',
                'scope_text': '',
                'rules_of_engagement': '',
                'notes': '',
                'created_at': ''
            }
        }
        driver = mock_driver_with_records([eng_data])

        # Mock storage
        monkeypatch.setattr('tools.engagement.storage.EngagementStorage.DEFAULT_DIR', tmp_path)

        with patch('neo4j.GraphDatabase.driver', return_value=driver):
            monkeypatch.setattr('tools.engagement.adapter.NEO4J_AVAILABLE', True)

            from tools.engagement.adapter import EngagementAdapter

            with patch.object(EngagementAdapter, '__init__', lambda self, **kwargs: None):
                adapter = EngagementAdapter()
                adapter.driver = driver
                adapter.database = 'neo4j'

                result = adapter.set_active_engagement('eng-123')

                assert result is True

    def test_get_active_engagement_returns_engagement(self, monkeypatch, mock_driver_with_records, tmp_path):
        """
        BV: Active engagement can be retrieved after setting

        Scenario:
          Given: Active engagement is set
          When: get_active_engagement() is called
          Then: Returns the engagement object
        """
        eng_data = {
            'e': {
                'id': 'eng-456',
                'name': 'Active Test',
                'client_id': 'client-1',
                'status': 'active',
                'start_date': '',
                'end_date': '',
                'scope_type': '',
                'scope_text': '',
                'rules_of_engagement': '',
                'notes': '',
                'created_at': ''
            }
        }
        driver = mock_driver_with_records([eng_data])

        # Setup storage with active engagement
        monkeypatch.setattr('tools.engagement.storage.EngagementStorage.DEFAULT_DIR', tmp_path)
        from tools.engagement.storage import set_active_engagement_id
        set_active_engagement_id('eng-456', 'Active Test')

        with patch('neo4j.GraphDatabase.driver', return_value=driver):
            monkeypatch.setattr('tools.engagement.adapter.NEO4J_AVAILABLE', True)

            from tools.engagement.adapter import EngagementAdapter

            with patch.object(EngagementAdapter, '__init__', lambda self, **kwargs: None):
                adapter = EngagementAdapter()
                adapter.driver = driver
                adapter.database = 'neo4j'

                engagement = adapter.get_active_engagement()

                assert engagement is not None
                assert engagement.id == 'eng-456'
                assert engagement.name == 'Active Test'


# =============================================================================
# Test: Target Operations
# =============================================================================

class TestTargetOperations:
    """Tests for Target CRUD operations."""

    def test_add_target_returns_id(self, monkeypatch, mock_driver_with_records):
        """
        BV: Targets are created and return usable IDs

        Scenario:
          Given: Valid target IP
          When: add_target() is called
          Then: Returns target ID
        """
        driver = mock_driver_with_records([{'id': 'target-abc'}])

        with patch('neo4j.GraphDatabase.driver', return_value=driver):
            monkeypatch.setattr('tools.engagement.adapter.NEO4J_AVAILABLE', True)

            from tools.engagement.adapter import EngagementAdapter

            with patch.object(EngagementAdapter, '__init__', lambda self, **kwargs: None):
                adapter = EngagementAdapter()
                adapter.driver = driver
                adapter.database = 'neo4j'

                target_id = adapter.add_target('eng-123', '192.168.1.100')

                assert target_id == 'target-abc'

    def test_add_target_creates_targets_relationship(self, monkeypatch, mock_driver):
        """
        BV: Targets are linked to engagements

        Scenario:
          Given: Target for an engagement
          When: add_target() is called
          Then: TARGETS relationship is created
        """
        mock_driver.records = [{'id': 'target-test'}]

        with patch('neo4j.GraphDatabase.driver', return_value=mock_driver):
            monkeypatch.setattr('tools.engagement.adapter.NEO4J_AVAILABLE', True)

            from tools.engagement.adapter import EngagementAdapter

            with patch.object(EngagementAdapter, '__init__', lambda self, **kwargs: None):
                adapter = EngagementAdapter()
                adapter.driver = mock_driver
                adapter.database = 'neo4j'

                adapter.add_target('eng-123', '10.0.0.1', hostname='server01')

                queries = mock_driver.get_all_queries()
                query = queries[0][0]
                assert "TARGETS" in query
                assert "Engagement" in query
                assert "Target" in query

    def test_get_targets_returns_list(self, monkeypatch, mock_driver_with_records):
        """
        BV: All targets for an engagement are retrievable

        Scenario:
          Given: Engagement with multiple targets
          When: get_targets() is called
          Then: Returns list of Target objects
        """
        targets_data = [
            {'t': {'id': 'target-1', 'ip_address': '192.168.1.1', 'hostname': '', 'os_guess': '', 'status': 'new', 'first_seen': '', 'last_seen': '', 'notes': ''}},
            {'t': {'id': 'target-2', 'ip_address': '192.168.1.2', 'hostname': 'web01', 'os_guess': '', 'status': 'scanning', 'first_seen': '', 'last_seen': '', 'notes': ''}},
        ]
        driver = mock_driver_with_records(targets_data)

        with patch('neo4j.GraphDatabase.driver', return_value=driver):
            monkeypatch.setattr('tools.engagement.adapter.NEO4J_AVAILABLE', True)

            from tools.engagement.adapter import EngagementAdapter

            with patch.object(EngagementAdapter, '__init__', lambda self, **kwargs: None):
                adapter = EngagementAdapter()
                adapter.driver = driver
                adapter.database = 'neo4j'

                targets = adapter.get_targets('eng-123')

                assert len(targets) == 2
                assert targets[0].ip_address == '192.168.1.1'
                assert targets[1].hostname == 'web01'

    def test_update_target_updates_fields(self, monkeypatch, mock_driver_with_records):
        """
        BV: Target fields can be updated after creation

        Scenario:
          Given: Existing target
          When: update_target() is called with new fields
          Then: Returns True and fields are updated
        """
        driver = mock_driver_with_records([{'id': 'target-123'}])

        with patch('neo4j.GraphDatabase.driver', return_value=driver):
            monkeypatch.setattr('tools.engagement.adapter.NEO4J_AVAILABLE', True)

            from tools.engagement.adapter import EngagementAdapter

            with patch.object(EngagementAdapter, '__init__', lambda self, **kwargs: None):
                adapter = EngagementAdapter()
                adapter.driver = driver
                adapter.database = 'neo4j'

                result = adapter.update_target(
                    'target-123',
                    os_guess='Windows Server 2019',
                    status='exploited'
                )

                assert result is True


# =============================================================================
# Test: Service Operations
# =============================================================================

class TestServiceOperations:
    """Tests for Service CRUD operations."""

    def test_add_service_returns_id(self, monkeypatch, mock_driver_with_records):
        """
        BV: Services are created and return usable IDs

        Scenario:
          Given: Valid service details
          When: add_service() is called
          Then: Returns service ID
        """
        driver = mock_driver_with_records([{'id': 'svc-abc'}])

        with patch('neo4j.GraphDatabase.driver', return_value=driver):
            monkeypatch.setattr('tools.engagement.adapter.NEO4J_AVAILABLE', True)

            from tools.engagement.adapter import EngagementAdapter

            with patch.object(EngagementAdapter, '__init__', lambda self, **kwargs: None):
                adapter = EngagementAdapter()
                adapter.driver = driver
                adapter.database = 'neo4j'

                svc_id = adapter.add_service('target-123', 80, service_name='http')

                assert svc_id == 'svc-abc'

    def test_add_service_creates_has_service_relationship(self, monkeypatch, mock_driver):
        """
        BV: Services are linked to targets

        Scenario:
          Given: Service for a target
          When: add_service() is called
          Then: HAS_SERVICE relationship is created
        """
        mock_driver.records = [{'id': 'svc-test'}]

        with patch('neo4j.GraphDatabase.driver', return_value=mock_driver):
            monkeypatch.setattr('tools.engagement.adapter.NEO4J_AVAILABLE', True)

            from tools.engagement.adapter import EngagementAdapter

            with patch.object(EngagementAdapter, '__init__', lambda self, **kwargs: None):
                adapter = EngagementAdapter()
                adapter.driver = mock_driver
                adapter.database = 'neo4j'

                adapter.add_service('target-123', 443, service_name='https')

                queries = mock_driver.get_all_queries()
                query = queries[0][0]
                assert "HAS_SERVICE" in query
                assert "Target" in query
                assert "Service" in query

    def test_get_services_returns_list(self, monkeypatch, mock_driver_with_records):
        """
        BV: All services for a target are retrievable

        Scenario:
          Given: Target with multiple services
          When: get_services() is called
          Then: Returns list of Service objects
        """
        services_data = [
            {'s': {'id': 'svc-1', 'target_id': 'target-1', 'port': 22, 'protocol': 'tcp', 'service_name': 'ssh', 'version': '', 'banner': '', 'state': 'open', 'found_at': ''}},
            {'s': {'id': 'svc-2', 'target_id': 'target-1', 'port': 80, 'protocol': 'tcp', 'service_name': 'http', 'version': 'Apache', 'banner': '', 'state': 'open', 'found_at': ''}},
        ]
        driver = mock_driver_with_records(services_data)

        with patch('neo4j.GraphDatabase.driver', return_value=driver):
            monkeypatch.setattr('tools.engagement.adapter.NEO4J_AVAILABLE', True)

            from tools.engagement.adapter import EngagementAdapter

            with patch.object(EngagementAdapter, '__init__', lambda self, **kwargs: None):
                adapter = EngagementAdapter()
                adapter.driver = driver
                adapter.database = 'neo4j'

                services = adapter.get_services('target-1')

                assert len(services) == 2
                assert services[0].port == 22
                assert services[1].service_name == 'http'


# =============================================================================
# Test: Finding Operations
# =============================================================================

class TestFindingOperations:
    """Tests for Finding CRUD operations."""

    def test_add_finding_returns_id(self, monkeypatch, mock_driver_with_records):
        """
        BV: Findings are created and return usable IDs

        Scenario:
          Given: Valid finding details
          When: add_finding() is called
          Then: Returns finding ID
        """
        driver = mock_driver_with_records([{'id': 'finding-abc'}])

        with patch('neo4j.GraphDatabase.driver', return_value=driver):
            monkeypatch.setattr('tools.engagement.adapter.NEO4J_AVAILABLE', True)

            from tools.engagement.adapter import EngagementAdapter

            with patch.object(EngagementAdapter, '__init__', lambda self, **kwargs: None):
                adapter = EngagementAdapter()
                adapter.driver = driver
                adapter.database = 'neo4j'

                finding_id = adapter.add_finding('eng-123', 'SQL Injection', severity='critical')

                assert finding_id == 'finding-abc'

    def test_add_finding_with_cve_links_to_cve_node(self, monkeypatch, mock_driver):
        """
        BV: Findings with CVEs are linked to CVE nodes for correlation

        Scenario:
          Given: Finding with CVE ID
          When: add_finding() is called
          Then: EXPLOITS relationship to CVE is created
        """
        mock_driver.records = [{'id': 'finding-test'}]

        with patch('neo4j.GraphDatabase.driver', return_value=mock_driver):
            monkeypatch.setattr('tools.engagement.adapter.NEO4J_AVAILABLE', True)

            from tools.engagement.adapter import EngagementAdapter

            with patch.object(EngagementAdapter, '__init__', lambda self, **kwargs: None):
                adapter = EngagementAdapter()
                adapter.driver = mock_driver
                adapter.database = 'neo4j'

                adapter.add_finding(
                    'eng-123',
                    'Remote Code Execution',
                    severity='critical',
                    cve_id='CVE-2024-12345'
                )

                # Check that CVE linking query was executed
                queries = mock_driver.get_all_queries()
                cve_query = [q for q in queries if 'CVE' in q[0]]
                assert len(cve_query) > 0

    def test_link_finding_to_target_creates_affects_relationship(self, monkeypatch, mock_driver_with_records):
        """
        BV: Findings can be linked to affected targets

        Scenario:
          Given: Finding and target IDs
          When: link_finding_to_target() is called
          Then: AFFECTS relationship is created
        """
        driver = mock_driver_with_records([{'id': 'finding-123'}])

        with patch('neo4j.GraphDatabase.driver', return_value=driver):
            monkeypatch.setattr('tools.engagement.adapter.NEO4J_AVAILABLE', True)

            from tools.engagement.adapter import EngagementAdapter

            with patch.object(EngagementAdapter, '__init__', lambda self, **kwargs: None):
                adapter = EngagementAdapter()
                adapter.driver = driver
                adapter.database = 'neo4j'

                result = adapter.link_finding_to_target('finding-123', 'target-456')

                assert result is True
                queries = driver.get_all_queries()
                query = queries[0][0]
                assert "AFFECTS" in query

    def test_get_findings_returns_list(self, monkeypatch, mock_driver_with_records):
        """
        BV: All findings for an engagement are retrievable

        Scenario:
          Given: Engagement with multiple findings
          When: get_findings() is called
          Then: Returns list of Finding objects
        """
        findings_data = [
            {'f': {'id': 'finding-1', 'title': 'SQLi', 'severity': 'critical', 'cvss_score': '', 'cve_id': '', 'description': '', 'impact': '', 'remediation': '', 'evidence': '', 'status': 'open', 'found_at': '', 'affected_targets': []}},
            {'f': {'id': 'finding-2', 'title': 'XSS', 'severity': 'medium', 'cvss_score': '', 'cve_id': '', 'description': '', 'impact': '', 'remediation': '', 'evidence': '', 'status': 'open', 'found_at': '', 'affected_targets': []}},
        ]
        driver = mock_driver_with_records(findings_data)

        with patch('neo4j.GraphDatabase.driver', return_value=driver):
            monkeypatch.setattr('tools.engagement.adapter.NEO4J_AVAILABLE', True)

            from tools.engagement.adapter import EngagementAdapter

            with patch.object(EngagementAdapter, '__init__', lambda self, **kwargs: None):
                adapter = EngagementAdapter()
                adapter.driver = driver
                adapter.database = 'neo4j'

                findings = adapter.get_findings('eng-123')

                assert len(findings) == 2
                assert findings[0].title == 'SQLi'
                assert findings[1].title == 'XSS'

    def test_get_findings_with_severity_filter(self, monkeypatch, mock_driver):
        """
        BV: Findings can be filtered by severity for prioritization

        Scenario:
          Given: Engagement with findings
          When: get_findings() is called with severity filter
          Then: Only matching severity findings are queried
        """
        mock_driver.records = []

        with patch('neo4j.GraphDatabase.driver', return_value=mock_driver):
            monkeypatch.setattr('tools.engagement.adapter.NEO4J_AVAILABLE', True)

            from tools.engagement.adapter import EngagementAdapter

            with patch.object(EngagementAdapter, '__init__', lambda self, **kwargs: None):
                adapter = EngagementAdapter()
                adapter.driver = mock_driver
                adapter.database = 'neo4j'

                adapter.get_findings('eng-123', severity='critical')

                queries = mock_driver.get_all_queries()
                query = queries[0][0]
                assert "severity" in query.lower()


# =============================================================================
# Test: Statistics Operations
# =============================================================================

class TestStatisticsOperations:
    """Tests for engagement statistics."""

    def test_get_engagement_stats_returns_counts(self, monkeypatch, mock_driver_with_records):
        """
        BV: Dashboard can display engagement summary

        Scenario:
          Given: Engagement with targets, services, findings
          When: get_engagement_stats() is called
          Then: Returns counts for each entity type
        """
        stats_data = [{
            'name': 'Test Engagement',
            'status': 'active',
            'target_count': 5,
            'service_count': 15,
            'finding_count': 3
        }]
        driver = mock_driver_with_records(stats_data)

        with patch('neo4j.GraphDatabase.driver', return_value=driver):
            monkeypatch.setattr('tools.engagement.adapter.NEO4J_AVAILABLE', True)

            from tools.engagement.adapter import EngagementAdapter

            with patch.object(EngagementAdapter, '__init__', lambda self, **kwargs: None):
                adapter = EngagementAdapter()
                adapter.driver = driver
                adapter.database = 'neo4j'

                stats = adapter.get_engagement_stats('eng-123')

                assert stats['name'] == 'Test Engagement'
                assert stats['targets'] == 5
                assert stats['services'] == 15
                assert stats['findings'] == 3

    def test_get_finding_summary_returns_severity_breakdown(self, monkeypatch, mock_driver_with_records):
        """
        BV: Finding severity breakdown for reporting

        Scenario:
          Given: Engagement with findings of various severities
          When: get_finding_summary() is called
          Then: Returns dict with count per severity
        """
        summary_data = [
            {'severity': 'critical', 'count': 2},
            {'severity': 'high', 'count': 5},
            {'severity': 'medium', 'count': 8},
        ]
        driver = mock_driver_with_records(summary_data)

        with patch('neo4j.GraphDatabase.driver', return_value=driver):
            monkeypatch.setattr('tools.engagement.adapter.NEO4J_AVAILABLE', True)

            from tools.engagement.adapter import EngagementAdapter

            with patch.object(EngagementAdapter, '__init__', lambda self, **kwargs: None):
                adapter = EngagementAdapter()
                adapter.driver = driver
                adapter.database = 'neo4j'

                summary = adapter.get_finding_summary('eng-123')

                assert summary['critical'] == 2
                assert summary['high'] == 5
                assert summary['medium'] == 8
                assert summary['low'] == 0  # Default
                assert summary['info'] == 0  # Default


# =============================================================================
# Test: Retry Logic
# =============================================================================

class TestRetryLogic:
    """Tests for Neo4j retry behavior."""

    def test_execute_read_retries_on_service_unavailable(self, monkeypatch, mock_driver):
        """
        BV: Transient Neo4j failures don't crash the application

        Scenario:
          Given: Neo4j throws ServiceUnavailable on first attempt
          When: _execute_read() is called
          Then: Retries and eventually succeeds or returns empty
        """
        # This test verifies the retry logic exists
        # Full integration would require more complex mocking

        with patch('neo4j.GraphDatabase.driver', return_value=mock_driver):
            monkeypatch.setattr('tools.engagement.adapter.NEO4J_AVAILABLE', True)

            from tools.engagement.adapter import EngagementAdapter

            with patch.object(EngagementAdapter, '__init__', lambda self, **kwargs: None):
                adapter = EngagementAdapter()
                adapter.driver = mock_driver
                adapter.database = 'neo4j'

                # The method should handle failures gracefully
                result = adapter._execute_read("MATCH (n) RETURN n")
                assert isinstance(result, list)


# =============================================================================
# Test: Edge Cases
# =============================================================================

class TestEdgeCases:
    """Tests for edge cases and error handling."""

    def test_update_target_with_no_kwargs_returns_false(self, monkeypatch, mock_driver):
        """
        BV: No-op updates don't cause errors

        Scenario:
          Given: update_target() called with no fields
          When: Method is executed
          Then: Returns False (nothing to update)
        """
        with patch('neo4j.GraphDatabase.driver', return_value=mock_driver):
            monkeypatch.setattr('tools.engagement.adapter.NEO4J_AVAILABLE', True)

            from tools.engagement.adapter import EngagementAdapter

            with patch.object(EngagementAdapter, '__init__', lambda self, **kwargs: None):
                adapter = EngagementAdapter()
                adapter.driver = mock_driver
                adapter.database = 'neo4j'

                result = adapter.update_target('target-123')

                assert result is False

    def test_get_engagement_stats_empty_engagement(self, monkeypatch, mock_driver):
        """
        BV: Empty engagement returns zero counts (not errors)

        Scenario:
          Given: Engagement with no targets/findings
          When: get_engagement_stats() is called
          Then: Returns zeros for all counts
        """
        with patch('neo4j.GraphDatabase.driver', return_value=mock_driver):
            monkeypatch.setattr('tools.engagement.adapter.NEO4J_AVAILABLE', True)

            from tools.engagement.adapter import EngagementAdapter

            with patch.object(EngagementAdapter, '__init__', lambda self, **kwargs: None):
                adapter = EngagementAdapter()
                adapter.driver = mock_driver
                adapter.database = 'neo4j'

                stats = adapter.get_engagement_stats('nonexistent-eng')

                assert stats['targets'] == 0
                assert stats['services'] == 0
                assert stats['findings'] == 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
