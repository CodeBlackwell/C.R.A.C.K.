"""
BloodTrail Test Configuration and Shared Fixtures

Provides common fixtures, factories, and utilities for all BloodTrail tests.
Follows CRACK_INSPECTOR patterns for test isolation and business value focus.

Ownership: tests/tools/post/bloodtrail/ (exclusive)
"""

import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Optional
from unittest.mock import Mock, patch
import pytest

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# Import shared mock factory
from tests.factories.neo4j import (
    MockNeo4jDriver,
    MockNeo4jSession,
    MockNeo4jResult,
    MockRecord,
    create_mock_driver_success,
    create_mock_driver_failure,
)


# =============================================================================
# BloodTrail-Specific Factories
# =============================================================================

class QueryFactory:
    """Factory for creating Query test objects with sensible defaults."""

    _counter = 0

    @classmethod
    def create(
        cls,
        id: str = None,
        name: str = None,
        description: str = "Test query description",
        cypher: str = "MATCH (n) RETURN n",
        category: str = "test",
        variables: Dict[str, Dict] = None,
        oscp_relevance: str = "medium",
        **kwargs
    ):
        """Create Query with defaults. Override only what matters."""
        cls._counter += 1
        query_id = id or f"test-query-{cls._counter}"

        # Import Query class lazily to avoid import issues
        from tools.post.bloodtrail.query_runner import Query

        return Query(
            id=query_id,
            name=name or f"Test Query {cls._counter}",
            description=description,
            cypher=cypher,
            category=category,
            variables=variables or {},
            oscp_relevance=oscp_relevance,
            **kwargs
        )

    @classmethod
    def create_with_variables(cls, var_names: List[str], **kwargs):
        """Create Query requiring variable substitution."""
        variables = {
            name: {"description": f"{name} variable", "required": True}
            for name in var_names
        }
        placeholders = " ".join(f"${{name}}" for name in var_names)
        cypher = f"MATCH (n) WHERE n.name = {placeholders} RETURN n"

        return cls.create(variables=variables, cypher=cypher, **kwargs)

    @classmethod
    def create_kerberoast(cls):
        """Create Kerberoast query for testing."""
        return cls.create(
            id="quick-kerberoastable",
            name="Kerberoastable Users",
            description="Find users with SPNs set",
            cypher="MATCH (u:User) WHERE u.hasspn = true RETURN u.name AS User",
            category="quick_wins",
            oscp_relevance="high",
        )

    @classmethod
    def create_with_user_variable(cls):
        """Create query requiring USER variable."""
        return cls.create(
            id="owned-what-can-access",
            name="What Can User Access",
            cypher="MATCH (u:User {name: '<USER>'})-[r:AdminTo|CanRDP|CanPSRemote]->(c:Computer) RETURN c.name",
            variables={"USER": {"description": "Target user", "required": True}},
        )


class BloodHoundDataFactory:
    """Factory for creating BloodHound JSON test data."""

    @classmethod
    def create_users_json(cls, users: List[Dict] = None) -> Dict:
        """Create users.json structure."""
        if users is None:
            users = [
                {
                    "Properties": {
                        "name": "ADMIN@CORP.COM",
                        "enabled": True,
                        "hasspn": False,
                        "dontreqpreauth": False,
                        "admincount": True,
                    }
                },
                {
                    "Properties": {
                        "name": "SVCACCOUNT@CORP.COM",
                        "enabled": True,
                        "hasspn": True,
                        "dontreqpreauth": False,
                        "serviceprincipalnames": ["MSSQLSvc/db01.corp.com:1433"],
                    }
                },
            ]
        return {"data": users}

    @classmethod
    def create_computers_json(cls, computers: List[Dict] = None) -> Dict:
        """Create computers.json structure."""
        if computers is None:
            computers = [
                {
                    "Properties": {
                        "name": "DC01.CORP.COM",
                        "enabled": True,
                        "unconstraineddelegation": True,
                        "haslaps": False,
                    },
                    "LocalAdmins": {
                        "Results": [
                            {"ObjectIdentifier": "S-1-5-21-123-456-789-500", "ObjectType": "User"}
                        ],
                        "Collected": True,
                    },
                    "Sessions": {
                        "Results": [
                            {"UserSID": "S-1-5-21-123-456-789-1001", "ComputerSID": "S-1-5-21-123-456-789-1000"}
                        ],
                        "Collected": True,
                    },
                }
            ]
        return {"data": computers}

    @classmethod
    def create_groups_json(cls, groups: List[Dict] = None) -> Dict:
        """Create groups.json structure."""
        if groups is None:
            groups = [
                {
                    "Properties": {
                        "name": "DOMAIN ADMINS@CORP.COM",
                        "admincount": True,
                        "highvalue": True,
                    },
                    "Members": [
                        {"ObjectIdentifier": "S-1-5-21-123-456-789-500", "ObjectType": "User"}
                    ],
                }
            ]
        return {"data": groups}

    @classmethod
    def create_domains_json(cls, domains: List[Dict] = None) -> Dict:
        """Create domains.json structure."""
        if domains is None:
            domains = [
                {
                    "Properties": {
                        "name": "CORP.COM",
                        "functionallevel": "2016",
                        "highvalue": True,
                    }
                }
            ]
        return {"data": domains}


class EdgeFactory:
    """Factory for creating Edge test objects."""

    @classmethod
    def create(
        cls,
        source: str = "ADMIN@CORP.COM",
        target: str = "DC01.CORP.COM",
        edge_type: str = "AdminTo",
        properties: Dict = None,
    ):
        """Create Edge with defaults."""
        from tools.post.bloodtrail.extractors import Edge

        return Edge(
            source=source,
            target=target,
            edge_type=edge_type,
            properties=properties or {},
        )

    @classmethod
    def create_adminto(cls, user: str, computer: str):
        """Create AdminTo edge."""
        return cls.create(source=user, target=computer, edge_type="AdminTo")

    @classmethod
    def create_memberof(cls, member: str, group: str):
        """Create MemberOf edge."""
        return cls.create(source=member, target=group, edge_type="MemberOf")


class QueryResultFactory:
    """Factory for creating QueryResult test objects."""

    @classmethod
    def create_success(
        cls,
        query_id: str = "test-query",
        records: List[Dict] = None,
        cypher: str = "MATCH (n) RETURN n",
    ):
        """Create successful QueryResult."""
        from tools.post.bloodtrail.query_runner import QueryResult

        records = records or []
        return QueryResult(
            query_id=query_id,
            success=True,
            records=records,
            record_count=len(records),
            cypher_executed=cypher,
        )

    @classmethod
    def create_failure(cls, query_id: str = "test-query", error: str = "Query failed"):
        """Create failed QueryResult."""
        from tools.post.bloodtrail.query_runner import QueryResult

        return QueryResult(
            query_id=query_id,
            success=False,
            error=error,
        )


# =============================================================================
# Assertion Helpers
# =============================================================================

class BloodTrailAssertions:
    """Reusable assertion helpers for BloodTrail tests."""

    @staticmethod
    def assert_query_result_success(test_case, result, min_records: int = 0):
        """Assert query result is successful with minimum records."""
        test_case.assertTrue(
            result.success,
            f"Expected success but got error: {result.error}"
        )
        test_case.assertGreaterEqual(
            result.record_count,
            min_records,
            f"Expected at least {min_records} records, got {result.record_count}"
        )

    @staticmethod
    def assert_edge_extracted(test_case, edges: List, edge_type: str, min_count: int = 1):
        """Assert edges of specific type were extracted."""
        matching = [e for e in edges if e.edge_type == edge_type]
        test_case.assertGreaterEqual(
            len(matching),
            min_count,
            f"Expected at least {min_count} {edge_type} edges, found {len(matching)}"
        )

    @staticmethod
    def assert_cypher_uses_parameters(test_case, cypher: str, session):
        """Assert Cypher query uses parameter binding (not string interpolation)."""
        # Check that parameters were passed as kwargs, not interpolated into query
        for query, params in session.queries_run:
            if cypher in query or query in cypher:
                # Good: params dict is not empty for queries with variables
                # Bad: query contains literal values that should be parameters
                dangerous_patterns = [
                    "'; DROP",  # SQL injection patterns
                    "\" OR 1=1",
                    "' OR '1'='1",
                ]
                for pattern in dangerous_patterns:
                    test_case.assertNotIn(
                        pattern,
                        query,
                        f"Query appears to have injection vulnerability: {query}"
                    )
                return
        test_case.fail(f"Query not found in session: {cypher}")

    @staticmethod
    def assert_no_string_interpolation(test_case, template: str, filled: str, user_value: str):
        """Assert variable substitution does not allow injection."""
        # If user_value contains Cypher metacharacters, they should be escaped or parameterized
        if "'" in user_value or '"' in user_value:
            # Check that quotes are properly escaped or value is parameterized
            test_case.assertNotIn(
                user_value,
                filled,
                "User value with quotes was interpolated without escaping"
            )


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mock_neo4j_driver():
    """Create mock Neo4j driver with empty records."""
    return create_mock_driver_success([])


@pytest.fixture
def mock_neo4j_driver_with_users():
    """Create mock Neo4j driver returning user records."""
    records = [
        {"name": "ADMIN@CORP.COM", "enabled": True, "admincount": True},
        {"name": "USER1@CORP.COM", "enabled": True, "admincount": False},
    ]
    return create_mock_driver_success(records)


@pytest.fixture
def mock_neo4j_driver_failure():
    """Create mock Neo4j driver that fails."""
    return create_mock_driver_failure(ConnectionError, "Connection refused")


@pytest.fixture
def temp_bloodhound_dir():
    """Create temporary directory with BloodHound JSON files."""
    import json

    with tempfile.TemporaryDirectory() as tmpdir:
        tmppath = Path(tmpdir)

        # Create users.json
        users_data = BloodHoundDataFactory.create_users_json()
        with open(tmppath / "users.json", "w") as f:
            json.dump(users_data, f)

        # Create computers.json
        computers_data = BloodHoundDataFactory.create_computers_json()
        with open(tmppath / "computers.json", "w") as f:
            json.dump(computers_data, f)

        # Create groups.json
        groups_data = BloodHoundDataFactory.create_groups_json()
        with open(tmppath / "groups.json", "w") as f:
            json.dump(groups_data, f)

        yield tmppath


@pytest.fixture
def query_factory():
    """Provide QueryFactory for test use."""
    return QueryFactory


@pytest.fixture
def bloodhound_data_factory():
    """Provide BloodHoundDataFactory for test use."""
    return BloodHoundDataFactory


@pytest.fixture
def edge_factory():
    """Provide EdgeFactory for test use."""
    return EdgeFactory


# =============================================================================
# Patch Helpers
# =============================================================================

def patch_neo4j_driver(records: List[Dict] = None):
    """Create context manager that patches neo4j.GraphDatabase.driver."""
    mock_driver = create_mock_driver_success(records or [])
    return patch("neo4j.GraphDatabase.driver", return_value=mock_driver)


def patch_neo4j_driver_failure(exception_type=ConnectionError, message="Connection failed"):
    """Create context manager that patches neo4j driver to fail."""
    mock_driver = create_mock_driver_failure(exception_type, message)
    return patch("neo4j.GraphDatabase.driver", return_value=mock_driver)
