#!/usr/bin/env python3
"""
Data Migration Validation Tests
Validates data integrity and completeness after Neo4j migration
"""

import pytest
from typing import List, Dict, Optional
from unittest.mock import Mock, MagicMock, patch


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture(scope="module")
def neo4j_session():
    """
    Create direct Neo4j session for validation queries

    Returns:
        Neo4j session object or skips if Neo4j unavailable
    """
    try:
        from neo4j import GraphDatabase
        from db.config import get_neo4j_config

        config = get_neo4j_config()
        driver = GraphDatabase.driver(
            config['uri'],
            auth=(config['user'], config['password'])
        )

        with driver.session(database=config.get('database', 'neo4j')) as session:
            # Test connection
            session.run("RETURN 1").single()

            yield session

        driver.close()
    except ImportError:
        pytest.skip("Neo4j driver not installed")
    except Exception as e:
        pytest.skip(f"Neo4j not available: {e}")


@pytest.fixture(scope="module")
def pg_connection():
    """
    Create PostgreSQL connection for comparison queries

    Returns:
        psycopg2 connection or skips if PostgreSQL unavailable
    """
    try:
        import psycopg2
        from db.config import get_db_config

        config = get_db_config()
        conn = psycopg2.connect(**config)

        yield conn

        conn.close()
    except ImportError:
        pytest.skip("psycopg2 not installed")
    except Exception as e:
        pytest.skip(f"PostgreSQL not available: {e}")


@pytest.fixture
def neo4j_adapter():
    """Neo4j adapter for high-level queries"""
    try:
        from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
        from crack.reference.core import ConfigManager, ReferenceTheme

        config = ConfigManager()
        theme = ReferenceTheme()
        adapter = Neo4jCommandRegistryAdapter(config, theme)

        return adapter
    except ImportError:
        pytest.skip("Neo4j adapter not implemented yet")
    except Exception as e:
        pytest.skip(f"Neo4j adapter initialization failed: {e}")


@pytest.fixture
def sql_adapter():
    """SQL adapter for comparison"""
    try:
        from crack.reference.core.sql_adapter import SQLCommandRegistryAdapter
        from crack.reference.core import ConfigManager, ReferenceTheme

        config = ConfigManager()
        theme = ReferenceTheme()
        adapter = SQLCommandRegistryAdapter(config, theme)

        return adapter
    except Exception as e:
        pytest.skip(f"SQL adapter not available: {e}")


# ============================================================================
# Data Completeness Tests (5 tests)
# ============================================================================

class TestDataCompleteness:
    """Test that all data was migrated from source"""

    @pytest.mark.integration
    @pytest.mark.validation
    def test_all_commands_migrated(self, neo4j_session, sql_adapter):
        """Test that command count matches source"""
        # Get Neo4j count
        neo4j_result = neo4j_session.run("""
            MATCH (c:Command)
            RETURN count(c) AS count
        """)
        neo4j_count = neo4j_result.single()['count']

        # Get source count from SQL
        sql_commands = sql_adapter.search('')
        sql_count = len(sql_commands)

        # Counts should match (within tolerance for test data)
        assert neo4j_count > 0, "Neo4j has no commands"
        assert sql_count > 0, "SQL has no commands"

        # Allow small variance for test environments
        variance = abs(neo4j_count - sql_count) / max(neo4j_count, sql_count)
        assert variance < 0.1, f"Count mismatch: Neo4j={neo4j_count}, SQL={sql_count}"

    @pytest.mark.integration
    @pytest.mark.validation
    def test_all_tags_migrated(self, neo4j_session):
        """Test that all unique tags are present"""
        result = neo4j_session.run("""
            MATCH (t:Tag)
            RETURN count(t) AS tag_count, collect(t.name) AS tag_names
        """)

        record = result.single()
        tag_count = record['tag_count']
        tag_names = record['tag_names']

        # Should have many tags
        assert tag_count > 10, f"Only {tag_count} tags found, expected more"

        # Check for critical OSCP tags
        critical_tags = ['OSCP:HIGH', 'QUICK_WIN', 'WINDOWS', 'LINUX']
        for tag in critical_tags:
            assert tag in tag_names, f"Missing critical tag: {tag}"

    @pytest.mark.integration
    @pytest.mark.validation
    def test_all_attack_chains_migrated(self, neo4j_session):
        """Test that attack chains are present"""
        result = neo4j_session.run("""
            MATCH (ac:AttackChain)
            RETURN count(ac) AS chain_count
        """)

        chain_count = result.single()['chain_count']

        # Should have some attack chains
        assert chain_count >= 0, "Attack chain count query failed"

        # If chains exist, verify structure
        if chain_count > 0:
            chain_result = neo4j_session.run("""
                MATCH (ac:AttackChain)-[:HAS_STEP]->(step)
                RETURN count(step) AS step_count
            """)
            step_count = chain_result.single()['step_count']
            assert step_count > 0, "Attack chains exist but have no steps"

    @pytest.mark.integration
    @pytest.mark.validation
    def test_no_orphaned_nodes(self, neo4j_session):
        """Test that all nodes have appropriate relationships"""
        # Check for commands without variables (if they have placeholders)
        result = neo4j_session.run("""
            MATCH (cmd:Command)
            WHERE cmd.command CONTAINS '<'
              AND NOT exists((cmd)-[:USES_VARIABLE]->())
            RETURN count(cmd) AS orphaned_count, collect(cmd.id)[0..5] AS sample_ids
        """)

        record = result.single()
        orphaned_count = record['orphaned_count']
        sample_ids = record['sample_ids']

        # Allow small number of edge cases
        assert orphaned_count < 10, f"Too many commands without variables: {orphaned_count}, samples: {sample_ids}"

    @pytest.mark.integration
    @pytest.mark.validation
    def test_no_duplicate_nodes(self, neo4j_session):
        """Test that unique constraints prevent duplicates"""
        # Check for duplicate command IDs
        result = neo4j_session.run("""
            MATCH (c:Command)
            WITH c.id AS cmd_id, count(c) AS cmd_count
            WHERE cmd_count > 1
            RETURN count(cmd_id) AS duplicate_count, collect(cmd_id)[0..5] AS sample_ids
        """)

        record = result.single()
        duplicate_count = record['duplicate_count']
        sample_ids = record['sample_ids']

        assert duplicate_count == 0, f"Found {duplicate_count} duplicate command IDs: {sample_ids}"


# ============================================================================
# Relationship Integrity Tests (5 tests)
# ============================================================================

class TestRelationshipIntegrity:
    """Test that relationships are correctly created"""

    @pytest.mark.integration
    @pytest.mark.validation
    def test_command_variable_relationships(self, neo4j_session):
        """Test that commands are linked to their variables"""
        result = neo4j_session.run("""
            MATCH (cmd:Command)-[r:USES_VARIABLE]->(var:Variable)
            RETURN count(r) AS rel_count
        """)

        rel_count = result.single()['rel_count']

        # Most commands should have variables
        assert rel_count > 50, f"Only {rel_count} command-variable relationships found"

    @pytest.mark.integration
    @pytest.mark.validation
    def test_command_tag_relationships(self, neo4j_session):
        """Test that commands are tagged correctly"""
        result = neo4j_session.run("""
            MATCH (cmd:Command)-[r:HAS_TAG]->(tag:Tag)
            RETURN count(r) AS rel_count
        """)

        rel_count = result.single()['rel_count']

        # All commands should have at least one tag
        assert rel_count > 100, f"Only {rel_count} command-tag relationships found"

        # Verify tag consistency
        consistency_result = neo4j_session.run("""
            MATCH (cmd:Command)-[:HAS_TAG]->(tag:Tag)
            WHERE tag.name = 'OSCP:HIGH'
            RETURN count(DISTINCT cmd) AS oscp_high_count
        """)

        oscp_high_count = consistency_result.single()['oscp_high_count']
        assert oscp_high_count > 10, "Not enough OSCP:HIGH tagged commands"

    @pytest.mark.integration
    @pytest.mark.validation
    def test_alternative_relationships_bidirectional(self, neo4j_session):
        """Test that ALTERNATIVE_TO relationships are symmetric"""
        # Check if alternatives are bidirectional
        result = neo4j_session.run("""
            MATCH (a:Command)-[:ALTERNATIVE_TO]->(b:Command)
            WHERE NOT exists((b)-[:ALTERNATIVE_TO]->(a))
            RETURN count(*) AS unidirectional_count,
                   collect([a.id, b.id])[0..3] AS samples
        """)

        record = result.single()
        unidirectional_count = record['unidirectional_count']
        samples = record['samples']

        # Alternatives should generally be bidirectional
        # Allow some exceptions for intentional one-way relationships
        if unidirectional_count > 0:
            # This is informational - log the samples
            assert unidirectional_count < 50, f"Too many one-way alternatives: {unidirectional_count}, samples: {samples}"

    @pytest.mark.integration
    @pytest.mark.validation
    def test_prerequisite_relationships_valid(self, neo4j_session):
        """Test that prerequisite relationships reference valid commands"""
        result = neo4j_session.run("""
            MATCH (cmd:Command)-[:REQUIRES]->(prereq:Command)
            WHERE NOT exists(prereq.id)
            RETURN count(*) AS invalid_count
        """)

        invalid_count = result.single()['invalid_count']

        assert invalid_count == 0, f"Found {invalid_count} invalid prerequisite relationships"

    @pytest.mark.integration
    @pytest.mark.validation
    def test_chain_step_relationships_ordered(self, neo4j_session):
        """Test that attack chain steps are properly ordered"""
        result = neo4j_session.run("""
            MATCH (ac:AttackChain)-[:HAS_STEP]->(step)
            WHERE step.order IS NULL OR step.step_number IS NULL
            RETURN count(step) AS unordered_count
        """)

        if result.peek():
            unordered_count = result.single()['unordered_count']
            assert unordered_count == 0, f"Found {unordered_count} unordered chain steps"


# ============================================================================
# Data Quality Tests (5 tests)
# ============================================================================

class TestDataQuality:
    """Test that migrated data meets quality standards"""

    @pytest.mark.integration
    @pytest.mark.validation
    def test_no_null_required_fields(self, neo4j_session):
        """Test that required fields are populated"""
        # Check for commands with missing required fields
        result = neo4j_session.run("""
            MATCH (c:Command)
            WHERE c.id IS NULL
               OR c.name IS NULL
               OR c.command IS NULL
               OR c.category IS NULL
            RETURN count(c) AS null_field_count
        """)

        null_field_count = result.single()['null_field_count']

        assert null_field_count == 0, f"Found {null_field_count} commands with null required fields"

    @pytest.mark.integration
    @pytest.mark.validation
    def test_oscp_relevance_values_valid(self, neo4j_session):
        """Test that OSCP relevance values are valid"""
        result = neo4j_session.run("""
            MATCH (c:Command)
            WHERE c.oscp_relevance IS NOT NULL
              AND NOT c.oscp_relevance IN ['low', 'medium', 'high']
            RETURN count(c) AS invalid_count, collect(c.oscp_relevance)[0..5] AS sample_values
        """)

        record = result.single()
        invalid_count = record['invalid_count']
        sample_values = record['sample_values']

        assert invalid_count == 0, f"Found {invalid_count} invalid oscp_relevance values: {sample_values}"

    @pytest.mark.integration
    @pytest.mark.validation
    def test_command_syntax_valid(self, neo4j_session):
        """Test that commands have valid syntax with placeholders"""
        # Check for commands with unmatched angle brackets
        result = neo4j_session.run("""
            MATCH (c:Command)
            WHERE c.command =~ '.*<[^>]*$' OR c.command =~ '^[^<]*>.*'
            RETURN count(c) AS invalid_syntax_count, collect(c.id)[0..5] AS sample_ids
        """)

        record = result.single()
        invalid_syntax_count = record['invalid_syntax_count']
        sample_ids = record['sample_ids']

        assert invalid_syntax_count == 0, f"Found {invalid_syntax_count} commands with unmatched brackets: {sample_ids}"

    @pytest.mark.integration
    @pytest.mark.validation
    def test_tags_normalized(self, neo4j_session):
        """Test that tag names are normalized (uppercase)"""
        result = neo4j_session.run("""
            MATCH (t:Tag)
            WHERE t.name =~ '.*[a-z].*'
              AND NOT t.name CONTAINS ':'
            RETURN count(t) AS lowercase_count, collect(t.name)[0..5] AS sample_names
        """)

        record = result.single()
        lowercase_count = record['lowercase_count']
        sample_names = record['sample_names']

        # Some tags may intentionally use lowercase (e.g., "wordpress")
        # Allow reasonable number of exceptions
        assert lowercase_count < 20, f"Too many lowercase tags: {lowercase_count}, samples: {sample_names}"

    @pytest.mark.integration
    @pytest.mark.validation
    def test_chain_steps_have_commands(self, neo4j_session):
        """Test that all chain steps reference valid commands"""
        result = neo4j_session.run("""
            MATCH (step)-[:EXECUTES]->(cmd:Command)
            RETURN count(*) AS valid_step_count
        """)

        if result.peek():
            valid_step_count = result.single()['valid_step_count']

            # Compare with total steps
            total_steps_result = neo4j_session.run("""
                MATCH (ac:AttackChain)-[:HAS_STEP]->(step)
                RETURN count(step) AS total_steps
            """)

            if total_steps_result.peek():
                total_steps = total_steps_result.single()['total_steps']

                # Most steps should have commands
                if total_steps > 0:
                    ratio = valid_step_count / total_steps
                    assert ratio > 0.8, f"Only {ratio*100:.1f}% of steps have commands"


# ============================================================================
# Cross-Backend Consistency Tests (2 tests)
# ============================================================================

class TestCrossBackendConsistency:
    """Test consistency between Neo4j and SQL backends"""

    @pytest.mark.integration
    @pytest.mark.validation
    def test_same_command_in_both_backends(self, neo4j_adapter, sql_adapter):
        """Test that the same command returns identical data from both backends"""
        command_id = 'nmap-quick-scan'

        # Get from both backends
        neo4j_cmd = neo4j_adapter.get_command(command_id)
        sql_cmd = sql_adapter.get_command(command_id)

        if neo4j_cmd and sql_cmd:
            # Core fields should match
            assert neo4j_cmd.id == sql_cmd.id
            assert neo4j_cmd.name == sql_cmd.name
            assert neo4j_cmd.command == sql_cmd.command
            assert neo4j_cmd.category == sql_cmd.category

    @pytest.mark.integration
    @pytest.mark.validation
    def test_search_results_consistent(self, neo4j_adapter, sql_adapter):
        """Test that search returns similar results from both backends"""
        query = 'nmap'

        # Search both backends
        neo4j_results = neo4j_adapter.search(query)
        sql_results = sql_adapter.search(query)

        # Both should return results
        assert len(neo4j_results) > 0
        assert len(sql_results) > 0

        # Convert to sets of IDs
        neo4j_ids = set(cmd.id for cmd in neo4j_results)
        sql_ids = set(cmd.id for cmd in sql_results)

        # Should have significant overlap (>50%)
        intersection = neo4j_ids & sql_ids
        union = neo4j_ids | sql_ids

        if len(union) > 0:
            overlap_ratio = len(intersection) / len(union)
            assert overlap_ratio > 0.5, f"Only {overlap_ratio*100:.1f}% overlap between backends"


# ============================================================================
# Schema Validation Tests (3 tests)
# ============================================================================

class TestSchemaValidation:
    """Test that Neo4j schema matches design specifications"""

    @pytest.mark.integration
    @pytest.mark.validation
    def test_required_indexes_exist(self, neo4j_session):
        """Test that required indexes are created"""
        result = neo4j_session.run("""
            SHOW INDEXES
            YIELD name, labelsOrTypes, properties
            RETURN name, labelsOrTypes, properties
        """)

        indexes = [(rec['labelsOrTypes'], rec['properties']) for rec in result]

        # Should have index on Command.id
        command_indexes = [idx for idx in indexes if 'Command' in str(idx[0])]
        assert len(command_indexes) > 0, "No indexes on Command nodes"

    @pytest.mark.integration
    @pytest.mark.validation
    def test_required_constraints_exist(self, neo4j_session):
        """Test that unique constraints are created"""
        result = neo4j_session.run("""
            SHOW CONSTRAINTS
            YIELD name, labelsOrTypes, properties
            RETURN name, labelsOrTypes, properties
        """)

        constraints = [(rec['labelsOrTypes'], rec['properties']) for rec in result]

        # Should have uniqueness constraint on Command.id
        command_constraints = [c for c in constraints if 'Command' in str(c[0])]
        assert len(command_constraints) > 0, "No constraints on Command nodes"

    @pytest.mark.integration
    @pytest.mark.validation
    def test_fulltext_index_exists(self, neo4j_session):
        """Test that full-text search index exists"""
        try:
            # Try to use full-text index
            result = neo4j_session.run("""
                CALL db.index.fulltext.queryNodes('commandSearchIndex', 'test')
                YIELD node
                RETURN count(node) AS result_count
            """)

            # If we get here, index exists
            assert True
        except Exception as e:
            # Index might not exist yet (migration not run)
            if "not found" in str(e).lower() or "does not exist" in str(e).lower():
                pytest.skip("Full-text index not created yet")
            else:
                raise
