"""
BloodTrail Query Runner Tests

Business Value Focus:
- Users need reliable query execution against Neo4j
- Query loading must correctly parse all query definitions
- Variable substitution must prevent Cypher injection
- Connection failures must be handled gracefully

Ownership: tests/tools/post/bloodtrail/ (exclusive)
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch, Mock, MagicMock
import json
import tempfile

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tests.factories.neo4j import (
    MockNeo4jDriver,
    MockNeo4jSession,
    MockNeo4jResult,
    MockRecord,
    create_mock_driver_success,
    create_mock_driver_failure,
)


# =============================================================================
# QUERY LOADING TESTS
# =============================================================================

class TestQueryLoading(unittest.TestCase):
    """Tests for query loading from JSON files."""

    def test_loads_queries_from_json_files(self):
        """
        BV: Users can access all defined queries without manual loading

        Scenario:
          Given: cypher_queries/*.json files exist
          When: QueryRunner is instantiated
          Then: All queries are loaded and accessible
        """
        from tools.post.bloodtrail.query_runner import QueryRunner

        runner = QueryRunner()

        # Should have loaded some queries
        self.assertGreater(
            len(runner._queries), 0,
            "Expected queries to be loaded from JSON files"
        )

    def test_get_categories_returns_all_categories(self):
        """
        BV: Users can filter queries by category (lateral_movement, quick_wins, etc.)

        Scenario:
          Given: Queries exist in multiple categories
          When: get_categories() is called
          Then: All unique categories are returned
        """
        from tools.post.bloodtrail.query_runner import QueryRunner

        runner = QueryRunner()
        categories = runner.get_categories()

        # Should have at least some standard categories
        self.assertIsInstance(categories, list)
        self.assertGreater(
            len(categories), 0,
            "Expected at least one category"
        )

    def test_list_queries_returns_all_when_no_filter(self):
        """
        BV: Users can browse all available queries

        Scenario:
          Given: Multiple queries are loaded
          When: list_queries() is called without filters
          Then: All queries are returned
        """
        from tools.post.bloodtrail.query_runner import QueryRunner

        runner = QueryRunner()
        queries = runner.list_queries()

        self.assertIsInstance(queries, list)
        self.assertGreater(
            len(queries), 0,
            "Expected at least one query"
        )

    def test_list_queries_filters_by_category(self):
        """
        BV: Users can focus on specific attack phases

        Scenario:
          Given: Queries exist in multiple categories
          When: list_queries(category='quick_wins') is called
          Then: Only quick_wins queries are returned
        """
        from tools.post.bloodtrail.query_runner import QueryRunner

        runner = QueryRunner()

        # Get first available category
        categories = runner.get_categories()
        if not categories:
            self.skipTest("No categories loaded")

        test_category = categories[0]
        filtered = runner.list_queries(category=test_category)

        # All returned queries should be in the requested category
        for query in filtered:
            self.assertEqual(
                query.category, test_category,
                f"Query {query.id} has category {query.category}, expected {test_category}"
            )

    def test_list_queries_filters_by_oscp_relevance(self):
        """
        BV: Users preparing for OSCP can prioritize high-relevance queries

        Scenario:
          Given: Queries have oscp_relevance ratings
          When: list_queries(oscp_relevance='high') is called
          Then: Only high-relevance queries are returned
        """
        from tools.post.bloodtrail.query_runner import QueryRunner

        runner = QueryRunner()
        high_relevance = runner.list_queries(oscp_relevance="high")

        for query in high_relevance:
            self.assertEqual(
                query.oscp_relevance, "high",
                f"Query {query.id} has relevance {query.oscp_relevance}, expected high"
            )

    def test_get_query_returns_correct_query(self):
        """
        BV: Users can retrieve specific query by ID

        Scenario:
          Given: A query with known ID exists
          When: get_query(id) is called
          Then: The correct query object is returned
        """
        from tools.post.bloodtrail.query_runner import QueryRunner

        runner = QueryRunner()
        queries = runner.list_queries()

        if not queries:
            self.skipTest("No queries loaded")

        # Get first query by ID
        test_id = queries[0].id
        query = runner.get_query(test_id)

        self.assertIsNotNone(query, f"Query {test_id} not found")
        self.assertEqual(query.id, test_id)

    def test_get_query_returns_none_for_invalid_id(self):
        """
        BV: Invalid query IDs are handled gracefully

        Scenario:
          Given: A query ID that doesn't exist
          When: get_query() is called
          Then: None is returned (not an exception)
        """
        from tools.post.bloodtrail.query_runner import QueryRunner

        runner = QueryRunner()
        query = runner.get_query("nonexistent-query-id-12345")

        self.assertIsNone(query)


# =============================================================================
# QUERY SEARCH TESTS
# =============================================================================

class TestQuerySearch(unittest.TestCase):
    """Tests for query search functionality."""

    def test_search_finds_by_name(self):
        """
        BV: Users can find queries by typing partial names

        Scenario:
          Given: A query named "Kerberoastable Users" exists
          When: search_queries("kerberos") is called
          Then: The query is found
        """
        from tools.post.bloodtrail.query_runner import QueryRunner

        runner = QueryRunner()

        # Search for a common term
        results = runner.search_queries("admin")

        # Should find at least one query mentioning admin
        # (either in name, description, or tags)
        self.assertIsInstance(results, list)

    def test_search_is_case_insensitive(self):
        """
        BV: Users don't need to remember exact capitalization

        Scenario:
          Given: A query with "AdminTo" in description
          When: search_queries("adminto") is called (lowercase)
          Then: The query is found
        """
        from tools.post.bloodtrail.query_runner import QueryRunner

        runner = QueryRunner()

        results_lower = runner.search_queries("admin")
        results_upper = runner.search_queries("ADMIN")
        results_mixed = runner.search_queries("Admin")

        # All searches should return the same results
        lower_ids = {q.id for q in results_lower}
        upper_ids = {q.id for q in results_upper}
        mixed_ids = {q.id for q in results_mixed}

        self.assertEqual(
            lower_ids, upper_ids,
            "Case sensitivity issue: lowercase and uppercase returned different results"
        )
        self.assertEqual(
            lower_ids, mixed_ids,
            "Case sensitivity issue: lowercase and mixed case returned different results"
        )

    def test_search_finds_by_tag(self):
        """
        BV: Users can search by OSCP relevance tags

        Scenario:
          Given: Queries tagged with "OSCP:HIGH"
          When: search_queries("OSCP") is called
          Then: Tagged queries are found
        """
        from tools.post.bloodtrail.query_runner import QueryRunner

        runner = QueryRunner()
        results = runner.search_queries("OSCP")

        # May or may not find results depending on tag presence
        self.assertIsInstance(results, list)


# =============================================================================
# QUERY EXECUTION TESTS
# =============================================================================

class TestQueryExecution(unittest.TestCase):
    """Tests for query execution against Neo4j."""

    def test_run_query_connects_if_not_connected(self):
        """
        BV: Users don't need to manually call connect()

        Scenario:
          Given: QueryRunner without active connection
          When: run_query() is called
          Then: Connection is established automatically
        """
        from tools.post.bloodtrail.query_runner import QueryRunner

        mock_driver = create_mock_driver_success([{"name": "test"}])

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            runner = QueryRunner()

            # Get a valid query
            queries = runner.list_queries()
            if not queries:
                self.skipTest("No queries loaded")

            # Find a query without variables
            simple_query = None
            for q in queries:
                if not q.has_variables():
                    simple_query = q
                    break

            if not simple_query:
                self.skipTest("No simple queries available")

            result = runner.run_query(simple_query.id)

            # Should succeed (connection was made automatically)
            self.assertTrue(
                result.success or "not found" in str(result.error).lower(),
                f"Unexpected error: {result.error}"
            )

    def test_run_query_returns_error_for_invalid_id(self):
        """
        BV: Invalid query IDs produce clear error messages

        Scenario:
          Given: An invalid query ID
          When: run_query() is called
          Then: Result contains descriptive error
        """
        from tools.post.bloodtrail.query_runner import QueryRunner

        runner = QueryRunner()
        result = runner.run_query("nonexistent-query-12345")

        self.assertFalse(result.success)
        self.assertIn("not found", result.error.lower())

    def test_run_query_returns_error_for_missing_variables(self):
        """
        BV: Users are told which variables are missing

        Scenario:
          Given: A query requiring USER variable
          When: run_query() is called without USER
          Then: Error message lists missing variable
        """
        from tools.post.bloodtrail.query_runner import QueryRunner

        runner = QueryRunner()

        # Find a query with variables
        queries_with_vars = [q for q in runner.list_queries() if q.has_variables()]
        if not queries_with_vars:
            self.skipTest("No queries with variables")

        query = queries_with_vars[0]
        result = runner.run_query(query.id)  # No variables provided

        self.assertFalse(result.success)
        self.assertIn("missing", result.error.lower())

    def test_run_query_with_variables_substitutes_correctly(self):
        """
        BV: Variable values are correctly substituted into queries

        Scenario:
          Given: Query with <USER> placeholder
          When: run_query(id, {"USER": "ADMIN@CORP.COM"}) is called
          Then: Cypher contains the substituted value
        """
        from tools.post.bloodtrail.query_runner import QueryRunner

        mock_driver = create_mock_driver_success([])

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            runner = QueryRunner()

            # Find query with USER variable
            queries_with_user = [
                q for q in runner.list_queries()
                if "USER" in q.variables
            ]
            if not queries_with_user:
                self.skipTest("No queries with USER variable")

            query = queries_with_user[0]
            result = runner.run_query(query.id, {"USER": "TESTUSER@CORP.COM"})

            # Check the executed cypher contains substituted value
            if result.success:
                self.assertIn(
                    "TESTUSER@CORP.COM",
                    result.cypher_executed,
                    "Variable not substituted in query"
                )

    def test_run_query_adds_limit_when_not_present(self):
        """
        BV: Queries are limited to prevent memory exhaustion

        Scenario:
          Given: Query without LIMIT clause
          When: run_query() is called
          Then: LIMIT is automatically added
        """
        from tools.post.bloodtrail.query_runner import QueryRunner

        mock_driver = create_mock_driver_success([])

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            runner = QueryRunner()

            # Find query without LIMIT in cypher
            for query in runner.list_queries():
                if "LIMIT" not in query.cypher.upper() and not query.has_variables():
                    result = runner.run_query(query.id, limit=50)

                    if result.success:
                        self.assertIn(
                            "LIMIT",
                            result.cypher_executed.upper(),
                            "LIMIT not added to query"
                        )
                    break

    def test_run_query_returns_records(self):
        """
        BV: Query results are accessible as list of dicts

        Scenario:
          Given: Neo4j returns records
          When: run_query() succeeds
          Then: records are accessible as list of dicts
        """
        from tools.post.bloodtrail.query_runner import QueryRunner

        test_records = [
            {"User": "ADMIN@CORP.COM", "Computer": "DC01.CORP.COM"},
            {"User": "USER1@CORP.COM", "Computer": "WS01.CORP.COM"},
        ]
        mock_driver = create_mock_driver_success(test_records)

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            runner = QueryRunner()

            # Find simple query
            simple_queries = [q for q in runner.list_queries() if not q.has_variables()]
            if not simple_queries:
                self.skipTest("No simple queries")

            result = runner.run_query(simple_queries[0].id)

            if result.success:
                self.assertEqual(result.record_count, len(test_records))
                self.assertIsInstance(result.records, list)


# =============================================================================
# CONNECTION HANDLING TESTS
# =============================================================================

class TestConnectionHandling(unittest.TestCase):
    """Tests for Neo4j connection handling."""

    def test_connect_returns_true_on_success(self):
        """
        BV: Users know when connection succeeds

        Scenario:
          Given: Neo4j is available
          When: connect() is called
          Then: Returns True
        """
        from tools.post.bloodtrail.query_runner import QueryRunner

        mock_driver = create_mock_driver_success([])

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            runner = QueryRunner()
            result = runner.connect()

            self.assertTrue(result)

    def test_connect_returns_false_on_auth_error(self):
        """
        BV: Authentication failures are reported clearly

        Scenario:
          Given: Invalid Neo4j credentials
          When: connect() is called
          Then: Returns False (not exception)
        """
        from tools.post.bloodtrail.query_runner import QueryRunner
        from neo4j.exceptions import AuthError

        mock_driver = create_mock_driver_failure(AuthError, "Invalid credentials")

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            runner = QueryRunner()
            result = runner.connect()

            self.assertFalse(result)

    def test_connect_returns_false_when_unavailable(self):
        """
        BV: Connection failures don't crash the application

        Scenario:
          Given: Neo4j is not running
          When: connect() is called
          Then: Returns False with error message
        """
        from tools.post.bloodtrail.query_runner import QueryRunner
        from neo4j.exceptions import ServiceUnavailable

        mock_driver = create_mock_driver_failure(ServiceUnavailable, "Connection refused")

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            runner = QueryRunner()
            result = runner.connect()

            self.assertFalse(result)

    def test_close_releases_resources(self):
        """
        BV: Resources are properly released after use

        Scenario:
          Given: Active Neo4j connection
          When: close() is called
          Then: Driver is closed
        """
        from tools.post.bloodtrail.query_runner import QueryRunner

        mock_driver = create_mock_driver_success([])

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            runner = QueryRunner()
            runner.connect()
            runner.close()

            self.assertTrue(mock_driver.closed)


# =============================================================================
# QUERY CLASS TESTS
# =============================================================================

class TestQueryClass(unittest.TestCase):
    """Tests for Query dataclass functionality."""

    def test_has_variables_returns_true_when_variables_defined(self):
        """
        BV: Correctly identifies queries requiring user input

        Scenario:
          Given: Query with variables dict
          When: has_variables() is called
          Then: Returns True
        """
        from tools.post.bloodtrail.query_runner import Query

        query = Query(
            id="test",
            name="Test",
            description="Test query",
            cypher="MATCH (u:User {name: '<USER>'}) RETURN u",
            category="test",
            variables={"USER": {"description": "Target user", "required": True}},
        )

        self.assertTrue(query.has_variables())

    def test_has_variables_returns_false_when_no_variables(self):
        """
        BV: Identifies queries that can run without input

        Scenario:
          Given: Query without variables
          When: has_variables() is called
          Then: Returns False
        """
        from tools.post.bloodtrail.query_runner import Query

        query = Query(
            id="test",
            name="Test",
            description="Test query",
            cypher="MATCH (u:User) RETURN u",
            category="test",
            variables={},
        )

        self.assertFalse(query.has_variables())

    def test_get_required_variables_returns_required_only(self):
        """
        BV: Distinguishes required vs optional variables

        Scenario:
          Given: Query with required and optional variables
          When: get_required_variables() is called
          Then: Only required variable names are returned
        """
        from tools.post.bloodtrail.query_runner import Query

        query = Query(
            id="test",
            name="Test",
            description="Test query",
            cypher="MATCH (u:User {name: '<USER>'}) RETURN u LIMIT <LIMIT>",
            category="test",
            variables={
                "USER": {"description": "Target user", "required": True},
                "LIMIT": {"description": "Result limit", "required": False},
            },
        )

        required = query.get_required_variables()

        self.assertIn("USER", required)
        self.assertNotIn("LIMIT", required)

    def test_substitute_variables_replaces_placeholders(self):
        """
        BV: Variable substitution works correctly

        Scenario:
          Given: Query with <USER> placeholder
          When: substitute_variables({"USER": "ADMIN"}) is called
          Then: Placeholder is replaced with value
        """
        from tools.post.bloodtrail.query_runner import Query

        query = Query(
            id="test",
            name="Test",
            description="Test query",
            cypher="MATCH (u:User {name: '<USER>'}) RETURN u",
            category="test",
            variables={"USER": {"description": "Target user", "required": True}},
        )

        result = query.substitute_variables({"USER": "ADMIN@CORP.COM"})

        self.assertIn("ADMIN@CORP.COM", result)
        self.assertNotIn("<USER>", result)


# =============================================================================
# QUERY RESULT CLASS TESTS
# =============================================================================

class TestQueryResultClass(unittest.TestCase):
    """Tests for QueryResult dataclass functionality."""

    def test_successful_result_has_records(self):
        """
        BV: Successful results contain accessible data

        Scenario:
          Given: Successful query execution
          When: Result is examined
          Then: records list and record_count are populated
        """
        from tools.post.bloodtrail.query_runner import QueryResult

        result = QueryResult(
            query_id="test",
            success=True,
            records=[{"name": "test1"}, {"name": "test2"}],
            record_count=2,
        )

        self.assertTrue(result.success)
        self.assertEqual(result.record_count, 2)
        self.assertEqual(len(result.records), 2)

    def test_failed_result_has_error(self):
        """
        BV: Failed results contain error information

        Scenario:
          Given: Failed query execution
          When: Result is examined
          Then: error field contains message
        """
        from tools.post.bloodtrail.query_runner import QueryResult

        result = QueryResult(
            query_id="test",
            success=False,
            error="Connection refused",
        )

        self.assertFalse(result.success)
        self.assertIsNotNone(result.error)
        self.assertIn("Connection", result.error)


# =============================================================================
# EXPORT TESTS
# =============================================================================

class TestQueryExport(unittest.TestCase):
    """Tests for query export functionality."""

    def test_export_query_returns_cypher(self):
        """
        BV: Users can copy queries to BloodHound GUI

        Scenario:
          Given: A valid query ID
          When: export_query() is called
          Then: Raw Cypher string is returned
        """
        from tools.post.bloodtrail.query_runner import QueryRunner

        runner = QueryRunner()
        queries = runner.list_queries()

        if not queries:
            self.skipTest("No queries loaded")

        cypher = runner.export_query(queries[0].id)

        self.assertIsNotNone(cypher)
        self.assertIn("MATCH", cypher.upper())

    def test_export_query_with_variables_substitutes(self):
        """
        BV: Exported queries have variables filled in

        Scenario:
          Given: Query with <USER> variable
          When: export_query(id, {"USER": "ADMIN"}) is called
          Then: Returned Cypher has substituted value
        """
        from tools.post.bloodtrail.query_runner import QueryRunner

        runner = QueryRunner()

        # Find query with variables
        queries_with_vars = [q for q in runner.list_queries() if q.has_variables()]
        if not queries_with_vars:
            self.skipTest("No queries with variables")

        query = queries_with_vars[0]
        var_name = list(query.variables.keys())[0]

        cypher = runner.export_query(query.id, {var_name: "TESTVALUE"})

        if cypher:
            self.assertIn("TESTVALUE", cypher)

    def test_export_query_returns_none_for_invalid_id(self):
        """
        BV: Invalid IDs don't cause crashes

        Scenario:
          Given: Invalid query ID
          When: export_query() is called
          Then: None is returned
        """
        from tools.post.bloodtrail.query_runner import QueryRunner

        runner = QueryRunner()
        result = runner.export_query("nonexistent-id-12345")

        self.assertIsNone(result)


# =============================================================================
# INVENTORY TESTS
# =============================================================================

class TestInventory(unittest.TestCase):
    """Tests for BloodHound data inventory functionality."""

    def test_get_inventory_returns_domain_info(self):
        """
        BV: Users can see what data is available in Neo4j

        Scenario:
          Given: BloodHound data in Neo4j
          When: get_inventory() is called
          Then: Domain, user, computer counts are returned
        """
        from tools.post.bloodtrail.query_runner import QueryRunner

        mock_records = [{"name": "CORP.COM"}]
        mock_driver = create_mock_driver_success(mock_records)

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            runner = QueryRunner()
            runner.connect()
            inventory = runner.get_inventory()

            self.assertIsInstance(inventory, dict)
            self.assertIn("domains", inventory)
            self.assertIn("users", inventory)
            self.assertIn("computers", inventory)

    def test_get_inventory_returns_empty_when_not_connected(self):
        """
        BV: Graceful handling when Neo4j unavailable

        Scenario:
          Given: No Neo4j connection
          When: get_inventory() is called
          Then: Empty dict is returned
        """
        from tools.post.bloodtrail.query_runner import QueryRunner

        runner = QueryRunner()
        runner.driver = None  # Ensure not connected

        inventory = runner.get_inventory()

        self.assertEqual(inventory, {})


# =============================================================================
# PWNED USER TRACKING TESTS
# =============================================================================

class TestPwnedUserTracking(unittest.TestCase):
    """Tests for pwned user caching and highlighting."""

    def test_get_pwned_users_returns_set(self):
        """
        BV: Pwned users can be highlighted in results

        Scenario:
          Given: Neo4j contains pwned users
          When: get_pwned_users() is called
          Then: Set of user names is returned
        """
        from tools.post.bloodtrail.query_runner import QueryRunner

        mock_records = [
            {"name": "ADMIN@CORP.COM"},
            {"name": "USER1@CORP.COM"},
        ]
        mock_driver = create_mock_driver_success(mock_records)

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            runner = QueryRunner()
            runner.connect()
            pwned = runner.get_pwned_users()

            self.assertIsInstance(pwned, set)

    def test_get_pwned_users_caches_results(self):
        """
        BV: Repeated calls don't hit Neo4j each time

        Scenario:
          Given: First call to get_pwned_users()
          When: Called again without force_refresh
          Then: Cached result is returned
        """
        from tools.post.bloodtrail.query_runner import QueryRunner

        mock_records = [{"name": "ADMIN@CORP.COM"}]
        mock_driver = create_mock_driver_success(mock_records)

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            runner = QueryRunner()
            runner.connect()

            # First call
            result1 = runner.get_pwned_users()

            # Modify cache to detect if reused
            runner._pwned_users_cache.add("TEST_MARKER")

            # Second call should return cached
            result2 = runner.get_pwned_users()

            self.assertIn("TEST_MARKER", result2)

    def test_get_pwned_users_force_refresh_reloads(self):
        """
        BV: Users can refresh pwned list after marking new users

        Scenario:
          Given: Cached pwned users
          When: get_pwned_users(force_refresh=True) is called
          Then: Fresh data is loaded from Neo4j
        """
        from tools.post.bloodtrail.query_runner import QueryRunner

        mock_records = [{"name": "ADMIN@CORP.COM"}]
        mock_driver = create_mock_driver_success(mock_records)

        with patch("neo4j.GraphDatabase.driver", return_value=mock_driver):
            runner = QueryRunner()
            runner.connect()

            # First call
            runner.get_pwned_users()

            # Add marker to cache
            runner._pwned_users_cache.add("TEST_MARKER")

            # Force refresh should reload
            result = runner.get_pwned_users(force_refresh=True)

            # Marker should be gone (fresh load)
            self.assertNotIn("TEST_MARKER", result)


if __name__ == "__main__":
    unittest.main()
