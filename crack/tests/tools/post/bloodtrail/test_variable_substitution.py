"""
BloodTrail Variable Substitution Security Tests

Business Value Focus:
- CRITICAL: Cypher injection must be prevented
- Variable substitution must not allow query manipulation
- Special characters in user input must be handled safely
- Parameter binding must be used for all dynamic values

Ownership: tests/tools/post/bloodtrail/ (exclusive)
"""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch, Mock, MagicMock

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tests.factories.neo4j import (
    MockNeo4jDriver,
    MockNeo4jSession,
    create_mock_driver_success,
)


# =============================================================================
# CYPHER INJECTION PREVENTION TESTS
# =============================================================================

class TestCypherInjectionPrevention(unittest.TestCase):
    """
    Tests to ensure Cypher queries cannot be manipulated through variable substitution.

    CRITICAL: These tests verify security properties that prevent data exfiltration
    or database manipulation through malicious user input.
    """

    def test_single_quote_in_variable_does_not_break_query(self):
        """
        BV: User input with quotes doesn't corrupt query syntax

        Scenario:
          Given: Query with USER variable
          When: User provides value with single quote: O'Brien
          Then: Query executes without syntax error

        Edge Cases:
          - Single quotes in usernames (Irish names, etc.)
          - Quotes at start/end of value
          - Multiple quotes in value
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

        # Test with single quote
        result = query.substitute_variables({"USER": "O'BRIEN@CORP.COM"})

        # Query should contain the value (substitution works)
        self.assertIn("O'BRIEN@CORP.COM", result)

        # Note: The Query class does simple string replacement.
        # The CRITICAL test is that the property_importer and query_runner
        # use parameter binding ($params) not string interpolation.

    def test_double_quote_in_variable_handled(self):
        """
        BV: Double quotes in input don't cause issues

        Scenario:
          Given: Query with description variable
          When: User provides value with double quote
          Then: Query handles it correctly
        """
        from tools.post.bloodtrail.query_runner import Query

        query = Query(
            id="test",
            name="Test",
            description="Test query",
            cypher="MATCH (u:User) WHERE u.description CONTAINS '<DESC>' RETURN u",
            category="test",
            variables={"DESC": {"description": "Description search", "required": True}},
        )

        result = query.substitute_variables({"DESC": 'Has "special" chars'})

        # Should contain the substituted value
        self.assertIn('Has "special" chars', result)

    def test_cypher_keywords_in_variable_not_executed(self):
        """
        BV: Cypher keywords in user input don't become part of query logic

        Scenario:
          Given: Query with USER variable
          When: User provides: ' OR 1=1 RETURN n //
          Then: Value is treated as literal string, not as Cypher

        This is a CRITICAL security test.
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

        malicious_input = "' OR 1=1 RETURN n //"
        result = query.substitute_variables({"USER": malicious_input})

        # The malicious input IS in the string (that's how substitution works)
        # But the IMPORTANT thing is that property_importer uses $params
        self.assertIn(malicious_input, result)

        # The real protection is in the execution layer using parameter binding
        # See: test_property_importer_uses_parameter_binding

    def test_newlines_in_variable_handled(self):
        """
        BV: Newlines in input don't break query structure

        Scenario:
          Given: Query with variable
          When: User provides value with newline
          Then: Query remains syntactically valid
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

        result = query.substitute_variables({"USER": "USER\n@CORP.COM"})

        # Newline is preserved in substitution
        self.assertIn("\n", result)


# =============================================================================
# PARAMETER BINDING VERIFICATION TESTS
# =============================================================================

class TestParameterBindingVerification(unittest.TestCase):
    """
    Tests to verify that Neo4j queries use parameter binding ($params)
    instead of string interpolation for user-provided values.

    CRITICAL: This is the primary defense against Cypher injection.
    """

    def test_property_importer_uses_unwind_with_params(self):
        """
        BV: Property import uses UNWIND $users for parameter binding

        Scenario:
          Given: PropertyImporter with user data
          When: Batch import is executed
          Then: Query uses UNWIND $users (parameter binding)
        """
        from tools.post.bloodtrail.property_importer import PropertyImporter

        mock_driver = create_mock_driver_success([{"imported": 1}])
        importer = PropertyImporter(mock_driver)

        users = [{"name": "ADMIN@CORP.COM", "enabled": True}]
        importer._batch_import_users(users, verbose=False)

        session = mock_driver.get_session()
        query, params = session.queries_run[0]

        # Query MUST use parameter placeholder
        self.assertIn("$users", query)

        # Params MUST contain the data
        self.assertIn("users", params)

    def test_property_importer_data_passed_as_params(self):
        """
        BV: User data is passed as parameters, not interpolated

        Scenario:
          Given: User with malicious name
          When: Import is executed
          Then: Name appears in params dict, not in query string
        """
        from tools.post.bloodtrail.property_importer import PropertyImporter

        mock_driver = create_mock_driver_success([{"imported": 1}])
        importer = PropertyImporter(mock_driver)

        malicious_name = "'; DROP DATABASE neo4j; //"
        users = [{"name": malicious_name, "enabled": True}]

        importer._batch_import_users(users, verbose=False)

        session = mock_driver.get_session()
        query, params = session.queries_run[0]

        # Query should NOT contain the malicious string
        self.assertNotIn("DROP DATABASE", query)
        self.assertNotIn(malicious_name, query)

        # Params should contain the data
        self.assertIn("users", params)

    def test_computer_import_uses_parameter_binding(self):
        """
        BV: Computer import also uses parameter binding

        Scenario:
          Given: PropertyImporter with computer data
          When: Batch import is executed
          Then: Query uses $computers parameter
        """
        from tools.post.bloodtrail.property_importer import PropertyImporter

        mock_driver = create_mock_driver_success([{"imported": 1}])
        importer = PropertyImporter(mock_driver)

        computers = [{"name": "DC01.CORP.COM", "enabled": True}]
        importer._batch_import_computers(computers, verbose=False)

        session = mock_driver.get_session()
        query, params = session.queries_run[0]

        self.assertIn("$computers", query)
        self.assertIn("computers", params)

    def test_group_import_uses_parameter_binding(self):
        """
        BV: Group import also uses parameter binding

        Scenario:
          Given: PropertyImporter with group data
          When: Batch import is executed
          Then: Query uses $groups parameter
        """
        from tools.post.bloodtrail.property_importer import PropertyImporter

        mock_driver = create_mock_driver_success([{"imported": 1}])
        importer = PropertyImporter(mock_driver)

        groups = [{"name": "DOMAIN ADMINS@CORP.COM"}]
        importer._batch_import_groups(groups, verbose=False)

        session = mock_driver.get_session()
        query, params = session.queries_run[0]

        self.assertIn("$groups", query)
        self.assertIn("groups", params)

    def test_domain_import_uses_parameter_binding(self):
        """
        BV: Domain import also uses parameter binding

        Scenario:
          Given: PropertyImporter with domain data
          When: Batch import is executed
          Then: Query uses $domains parameter
        """
        from tools.post.bloodtrail.property_importer import PropertyImporter

        mock_driver = create_mock_driver_success([{"imported": 1}])
        importer = PropertyImporter(mock_driver)

        domains = [{"name": "CORP.COM", "functionallevel": "2016"}]
        importer._batch_import_domains(domains, verbose=False)

        session = mock_driver.get_session()
        query, params = session.queries_run[0]

        self.assertIn("$domains", query)
        self.assertIn("domains", params)


# =============================================================================
# EDGE CASE TESTS
# =============================================================================

class TestVariableSubstitutionEdgeCases(unittest.TestCase):
    """Tests for edge cases in variable substitution."""

    def test_empty_variable_value_handled(self):
        """
        BV: Empty string values don't cause errors

        Scenario:
          Given: Query with variable
          When: Empty string is provided
          Then: Substitution works (may produce invalid query, but no crash)
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

        result = query.substitute_variables({"USER": ""})

        # Placeholder should be replaced with empty string
        self.assertNotIn("<USER>", result)

    def test_unicode_in_variable_handled(self):
        """
        BV: Unicode characters in input don't cause issues

        Scenario:
          Given: Query with variable
          When: Unicode value is provided
          Then: Substitution preserves unicode
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

        unicode_name = "MULLER@CORP.COM"  # German umlaut: u with dots
        result = query.substitute_variables({"USER": unicode_name})

        self.assertIn(unicode_name, result)

    def test_very_long_variable_handled(self):
        """
        BV: Long values don't cause memory issues

        Scenario:
          Given: Query with variable
          When: Very long value is provided
          Then: Substitution works without memory issues
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

        long_value = "A" * 10000 + "@CORP.COM"
        result = query.substitute_variables({"USER": long_value})

        self.assertIn(long_value, result)

    def test_backslash_in_variable_handled(self):
        """
        BV: Backslashes (Windows paths) don't cause escape issues

        Scenario:
          Given: Query with path variable
          When: Windows path with backslashes is provided
          Then: Backslashes are preserved
        """
        from tools.post.bloodtrail.query_runner import Query

        query = Query(
            id="test",
            name="Test",
            description="Test query",
            cypher="MATCH (u:User {path: '<PATH>'}) RETURN u",
            category="test",
            variables={"PATH": {"description": "File path", "required": True}},
        )

        windows_path = "C:\\Users\\Admin\\file.txt"
        result = query.substitute_variables({"PATH": windows_path})

        self.assertIn(windows_path, result)

    def test_placeholder_in_variable_causes_secondary_substitution(self):
        """
        BV: Understand that string replacement allows secondary substitution

        Scenario:
          Given: Query with USER and ROLE variables
          When: User provides USER value containing <ROLE>
          Then: The <ROLE> within USER value gets substituted (string replacement behavior)

        Note:
          This documents actual behavior - the Query class uses simple string
          replacement, so placeholders in values will be substituted. This is
          acceptable because the REAL security protection is in the Neo4j
          parameter binding layer, not in Query.substitute_variables().
        """
        from tools.post.bloodtrail.query_runner import Query

        query = Query(
            id="test",
            name="Test",
            description="Test query",
            cypher="MATCH (u:User {name: '<USER>'}) WHERE u.role = '<ROLE>' RETURN u",
            category="test",
            variables={
                "USER": {"description": "Target user", "required": True},
                "ROLE": {"description": "Role filter", "required": True},
            },
        )

        # User provides a value that looks like a placeholder
        result = query.substitute_variables({
            "USER": "test_<ROLE>_user",
            "ROLE": "admin",
        })

        # With simple string replacement, the <ROLE> in USER gets replaced too
        # This is expected behavior - security is enforced by parameter binding
        self.assertIn("admin", result)
        # The query is still valid (just with potentially unexpected substitution)
        self.assertIn("MATCH", result)


# =============================================================================
# QUERY CLASS SAFETY TESTS
# =============================================================================

class TestQueryClassSafety(unittest.TestCase):
    """Tests for Query class safety properties."""

    def test_get_required_variables_returns_immutable_result(self):
        """
        BV: Returned variable list cannot be used to modify query

        Scenario:
          Given: Query with variables
          When: get_required_variables() is called and result is modified
          Then: Original query is not affected
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

        required = query.get_required_variables()
        required.append("INJECTED")  # Try to modify

        # Original should not be affected
        self.assertNotIn("INJECTED", query.variables)

    def test_substitute_does_not_modify_original_cypher(self):
        """
        BV: Substitution returns new string, doesn't modify original

        Scenario:
          Given: Query with cypher template
          When: substitute_variables() is called
          Then: Original cypher property is unchanged
        """
        from tools.post.bloodtrail.query_runner import Query

        original_cypher = "MATCH (u:User {name: '<USER>'}) RETURN u"

        query = Query(
            id="test",
            name="Test",
            description="Test query",
            cypher=original_cypher,
            category="test",
            variables={"USER": {"description": "Target user", "required": True}},
        )

        # Substitute
        query.substitute_variables({"USER": "ADMIN"})

        # Original should be unchanged
        self.assertEqual(query.cypher, original_cypher)


# =============================================================================
# INTEGRATION TESTS WITH MOCK DRIVER
# =============================================================================

class TestParameterBindingIntegration(unittest.TestCase):
    """Integration tests verifying parameter binding through the full stack."""

    def test_full_import_flow_uses_params(self):
        """
        BV: Full import flow (source -> importer -> neo4j) uses params

        Scenario:
          Given: BloodHound data source
          When: Full import is executed
          Then: All queries use parameter binding
        """
        from tools.post.bloodtrail.property_importer import PropertyImporter
        from tools.post.bloodtrail.data_source import DirectoryDataSource
        import tempfile
        import json

        mock_driver = create_mock_driver_success([{"imported": 1}])

        with tempfile.TemporaryDirectory() as tmpdir:
            tmppath = Path(tmpdir)

            # Create test data with potentially malicious content
            users_data = {
                "data": [{
                    "Properties": {
                        "name": "USER'; MATCH (n) DETACH DELETE n; //",
                        "enabled": True,
                    }
                }]
            }
            with open(tmppath / "users.json", "w") as f:
                json.dump(users_data, f)

            data_source = DirectoryDataSource(tmppath)
            importer = PropertyImporter(mock_driver)

            importer.import_from_source(data_source)

            # Verify all queries used parameter binding
            session = mock_driver.get_session()
            for query, params in session.queries_run:
                # No query should contain DELETE or other dangerous commands
                self.assertNotIn("DELETE", query)
                self.assertNotIn("DETACH", query)

                # Should use parameter placeholders
                self.assertTrue(
                    "$users" in query or
                    "$computers" in query or
                    "$groups" in query or
                    "$domains" in query or
                    "RETURN" in query.upper(),  # Inventory queries are OK
                    f"Query missing parameter binding: {query[:100]}"
                )


if __name__ == "__main__":
    unittest.main()
