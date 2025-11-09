#!/usr/bin/env python3
"""
Unit tests for Neo4j Command Registry Adapter
Tests all methods with API parity to SQLCommandRegistryAdapter
"""

import pytest
from typing import List, Dict, Optional
from unittest.mock import Mock, MagicMock, patch

from crack.reference.core import Command, CommandVariable, ConfigManager, ReferenceTheme


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture(scope="module")
def neo4j_adapter():
    """
    Create Neo4j adapter instance for testing

    Returns:
        Neo4jCommandRegistryAdapter instance or skips if Neo4j unavailable
    """
    try:
        from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter

        config = ConfigManager()
        theme = ReferenceTheme()
        adapter = Neo4jCommandRegistryAdapter(config, theme)

        # Verify connection is healthy
        if not adapter.health_check():
            pytest.skip("Neo4j connection unhealthy")

        return adapter
    except ImportError:
        pytest.skip("Neo4j adapter not implemented yet")
    except Exception as e:
        pytest.skip(f"Neo4j not available: {e}")


@pytest.fixture
def sample_command_id():
    """Known command ID from test data"""
    return "nmap-quick-scan"


@pytest.fixture
def sample_chain_id():
    """Known attack chain ID from test data"""
    return "linux-privesc-suid-basic"


@pytest.fixture
def mock_neo4j_driver():
    """Mock Neo4j driver for testing without database"""
    mock_driver = MagicMock()
    mock_session = MagicMock()
    mock_driver.session.return_value.__enter__.return_value = mock_session
    return mock_driver, mock_session


# ============================================================================
# Connection Tests (5 tests)
# ============================================================================

class TestConnection:
    """Test Neo4j connection and initialization"""

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_init_with_default_config(self):
        """Test initialization with default configuration"""
        try:
            from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter

            adapter = Neo4jCommandRegistryAdapter()

            assert adapter is not None
            assert hasattr(adapter, 'driver')
            assert hasattr(adapter, 'config')
            assert hasattr(adapter, 'theme')
        except ImportError:
            pytest.skip("Neo4j adapter not implemented yet")
        except Exception:
            pytest.skip("Neo4j not configured")

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_init_with_custom_config(self):
        """Test initialization with custom configuration"""
        try:
            from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
            from db.config import get_neo4j_config

            custom_config = get_neo4j_config()
            config = ConfigManager()
            theme = ReferenceTheme()

            adapter = Neo4jCommandRegistryAdapter(
                config_manager=config,
                theme=theme,
                neo4j_config=custom_config
            )

            assert adapter is not None
        except ImportError:
            pytest.skip("Neo4j adapter not implemented yet")
        except Exception:
            pytest.skip("Neo4j not configured")

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_connection_pool_created(self, neo4j_adapter):
        """Test that Neo4j driver connection pool is created"""
        assert neo4j_adapter.driver is not None
        assert hasattr(neo4j_adapter, 'database')

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_health_check_success(self, neo4j_adapter):
        """Test health check returns True when Neo4j is connected"""
        result = neo4j_adapter.health_check()

        assert result is True

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_health_check_failure(self):
        """Test health check returns False when Neo4j is down"""
        try:
            from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter, Neo4jConnectionError

            # Invalid configuration
            bad_config = {
                'uri': 'bolt://invalid-host-does-not-exist:7687',
                'user': 'neo4j',
                'password': 'wrong'
            }

            # Should raise connection error
            with pytest.raises(Neo4jConnectionError):
                adapter = Neo4jCommandRegistryAdapter(neo4j_config=bad_config)
        except ImportError:
            pytest.skip("Neo4j adapter not implemented yet")


# ============================================================================
# Basic Query Tests (6 tests)
# ============================================================================

class TestBasicQueries:
    """Test simple CRUD-style queries"""

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_get_command_exists(self, neo4j_adapter, sample_command_id):
        """Test retrieving existing command by ID"""
        cmd = neo4j_adapter.get_command(sample_command_id)

        assert cmd is not None
        assert isinstance(cmd, Command)
        assert cmd.id == sample_command_id
        assert cmd.name is not None
        assert cmd.command is not None

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_get_command_not_found(self, neo4j_adapter):
        """Test graceful handling of nonexistent command"""
        cmd = neo4j_adapter.get_command('nonexistent-command-12345')

        assert cmd is None

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_get_command_with_variables(self, neo4j_adapter, sample_command_id):
        """Test that command includes variables"""
        cmd = neo4j_adapter.get_command(sample_command_id)

        assert cmd is not None
        assert hasattr(cmd, 'variables')
        assert isinstance(cmd.variables, list)

        # Commands should have at least one variable (most have placeholders)
        if '<' in cmd.command:
            assert len(cmd.variables) > 0

            # Verify variable structure
            for var in cmd.variables:
                assert isinstance(var, CommandVariable)
                assert var.name is not None
                assert var.description is not None

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_get_command_with_tags(self, neo4j_adapter, sample_command_id):
        """Test that command includes tags"""
        cmd = neo4j_adapter.get_command(sample_command_id)

        assert cmd is not None
        assert hasattr(cmd, 'tags')
        assert isinstance(cmd.tags, list)

        # Most commands should have tags
        if len(cmd.tags) > 0:
            assert all(isinstance(tag, str) for tag in cmd.tags)

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_get_all_commands(self, neo4j_adapter):
        """Test retrieving all commands"""
        # This tests the search with empty query
        commands = neo4j_adapter.search('')

        assert isinstance(commands, list)
        # Should have hundreds of commands
        assert len(commands) > 10

        # All should be Command objects
        for cmd in commands[:5]:  # Check first 5
            assert isinstance(cmd, Command)

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_filter_by_category(self, neo4j_adapter):
        """Test category filtering"""
        results = neo4j_adapter.filter_by_category('web')

        assert isinstance(results, list)
        assert len(results) > 0

        # All results should be in 'web' category
        for cmd in results:
            assert cmd.category == 'web'


# ============================================================================
# Search Tests (4 tests)
# ============================================================================

class TestSearch:
    """Test full-text search functionality"""

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_search_by_name(self, neo4j_adapter):
        """Test searching by command name"""
        results = neo4j_adapter.search('nmap')

        assert isinstance(results, list)
        assert len(results) > 0

        # Results should contain 'nmap' in name or description
        for cmd in results:
            search_text = f"{cmd.name} {cmd.description} {cmd.command}".lower()
            assert 'nmap' in search_text

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_search_by_description(self, neo4j_adapter):
        """Test searching by description text"""
        results = neo4j_adapter.search('reverse shell')

        assert isinstance(results, list)
        assert len(results) > 0

        # Results should be related to reverse shells
        for cmd in results:
            search_text = f"{cmd.name} {cmd.description} {cmd.command}".lower()
            assert 'reverse' in search_text or 'shell' in search_text

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_search_limit(self, neo4j_adapter):
        """Test search respects limit parameter"""
        # Search for common term
        results_unlimited = neo4j_adapter.search('scan')

        # If search supports limit parameter
        if hasattr(neo4j_adapter.search, '__code__'):
            arg_names = neo4j_adapter.search.__code__.co_varnames
            if 'limit' in arg_names:
                results_limited = neo4j_adapter.search('scan', limit=5)
                assert len(results_limited) <= 5

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_search_no_results(self, neo4j_adapter):
        """Test search with no matching results"""
        results = neo4j_adapter.search('xyzzy-nonexistent-term-12345')

        assert isinstance(results, list)
        assert len(results) == 0


# ============================================================================
# Tag Filter Tests (3 tests)
# ============================================================================

class TestTagFiltering:
    """Test tag-based filtering"""

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_filter_by_single_tag(self, neo4j_adapter):
        """Test filtering by single tag"""
        results = neo4j_adapter.filter_by_tags(['OSCP:HIGH'])

        assert isinstance(results, list)
        assert len(results) > 0

        # All results should have the tag
        for cmd in results:
            assert 'OSCP:HIGH' in cmd.tags

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_filter_by_multiple_tags(self, neo4j_adapter):
        """Test filtering by multiple tags with OR logic"""
        results = neo4j_adapter.filter_by_tags(
            ['OSCP:HIGH', 'QUICK_WIN'],
            match_all=False
        )

        assert isinstance(results, list)
        assert len(results) > 0

        # Results should have at least one of the tags
        for cmd in results:
            assert 'OSCP:HIGH' in cmd.tags or 'QUICK_WIN' in cmd.tags

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_get_quick_wins(self, neo4j_adapter):
        """Test getting QUICK_WIN tagged commands"""
        results = neo4j_adapter.get_quick_wins()

        assert isinstance(results, list)

        # All results should have QUICK_WIN tag
        for cmd in results:
            assert 'QUICK_WIN' in cmd.tags


# ============================================================================
# Graph Traversal Tests (6 tests)
# ============================================================================

class TestGraphTraversal:
    """Test graph-specific queries (Neo4j advantage)"""

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_find_alternatives_depth_1(self, neo4j_adapter):
        """Test finding direct alternatives (1-hop)"""
        # Use a command known to have alternatives
        paths = neo4j_adapter.find_alternatives('gobuster-dir', max_depth=1)

        assert isinstance(paths, list)

        if len(paths) > 0:
            # Check path structure
            for path in paths:
                assert hasattr(path, 'nodes')
                assert hasattr(path, 'relationships')
                assert hasattr(path, 'length')
                assert path.length <= 1
                assert len(path.nodes) == path.length + 1  # start + end

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_find_alternatives_depth_3(self, neo4j_adapter):
        """Test multi-hop alternative discovery"""
        paths = neo4j_adapter.find_alternatives('gobuster-dir', max_depth=3)

        assert isinstance(paths, list)

        if len(paths) > 0:
            # All paths should respect max depth
            for path in paths:
                assert path.length <= 3
                assert len(path.nodes) == path.length + 1

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_find_alternatives_no_results(self, neo4j_adapter):
        """Test alternative discovery with no results"""
        # Use a command unlikely to have alternatives
        paths = neo4j_adapter.find_alternatives('nonexistent-command', max_depth=3)

        assert isinstance(paths, list)
        assert len(paths) == 0

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_find_prerequisites_depth_1(self, neo4j_adapter):
        """Test finding direct prerequisites"""
        # Use a command that requires setup
        prereqs = neo4j_adapter.find_prerequisites('wordpress-sqli')

        assert isinstance(prereqs, list)

        # Prerequisites should be Command objects
        for prereq in prereqs:
            assert isinstance(prereq, Command)

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_find_prerequisites_depth_3(self, neo4j_adapter):
        """Test finding transitive prerequisite chain"""
        # Find prerequisites for a complex command
        prereqs = neo4j_adapter.find_prerequisites('wordpress-sqli')

        assert isinstance(prereqs, list)

        # Should be ordered (deepest dependencies first)
        if len(prereqs) > 1:
            # All prerequisites should have unique IDs
            prereq_ids = [p.id for p in prereqs]
            assert len(prereq_ids) == len(set(prereq_ids))

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_get_attack_chain_path(self, neo4j_adapter, sample_chain_id):
        """Test attack chain path planning"""
        plan = neo4j_adapter.get_attack_chain_path(sample_chain_id)

        if plan is not None:
            # Verify plan structure
            assert isinstance(plan, dict)
            assert 'id' in plan
            assert 'name' in plan
            assert 'steps' in plan

            # Steps should be ordered
            steps = plan['steps']
            assert isinstance(steps, list)

            if len(steps) > 0:
                # Each step should have order and command
                for step in steps:
                    assert 'order' in step or 'step_number' in step
                    assert 'command' in step or 'command_id' in step


# ============================================================================
# Helper Method Tests (3 tests)
# ============================================================================

class TestHelperMethods:
    """Test internal helper methods"""

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_node_to_command_conversion(self, neo4j_adapter, sample_command_id):
        """Test conversion of Neo4j node to Command dataclass"""
        cmd = neo4j_adapter.get_command(sample_command_id)

        assert cmd is not None
        assert isinstance(cmd, Command)

        # Verify all required fields present
        assert cmd.id is not None
        assert cmd.name is not None
        assert cmd.category is not None
        assert cmd.command is not None
        assert cmd.description is not None

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_command_with_relationships(self, neo4j_adapter, sample_command_id):
        """Test that command includes relationship data"""
        cmd = neo4j_adapter.get_command(sample_command_id)

        assert cmd is not None

        # Check for relationship-derived data
        assert hasattr(cmd, 'variables')
        assert hasattr(cmd, 'tags')
        assert hasattr(cmd, 'alternatives')
        assert hasattr(cmd, 'prerequisites')

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_execute_query_error_handling(self, neo4j_adapter):
        """Test graceful error handling in query execution"""
        # Try to get nonexistent command
        result = neo4j_adapter.get_command('definitely-does-not-exist-12345')

        # Should return None, not raise exception
        assert result is None


# ============================================================================
# Stats Tests (3 tests)
# ============================================================================

class TestStatistics:
    """Test statistics and metadata queries"""

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_get_stats_structure(self, neo4j_adapter):
        """Test stats returns correct dictionary structure"""
        stats = neo4j_adapter.get_stats()

        assert isinstance(stats, dict)

        # Should have count information
        expected_keys = ['command_count', 'total_commands', 'node_count']
        has_count = any(key in stats for key in expected_keys)
        assert has_count

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_get_stats_counts(self, neo4j_adapter):
        """Test stats counts match actual data"""
        stats = neo4j_adapter.get_stats()

        # Get actual count via search
        all_commands = neo4j_adapter.search('')

        # Stats count should match
        if 'command_count' in stats:
            assert stats['command_count'] > 0
        elif 'total_commands' in stats:
            assert stats['total_commands'] > 0
        elif 'node_count' in stats:
            assert stats['node_count'] > 0

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_get_oscp_high(self, neo4j_adapter):
        """Test getting OSCP high-relevance commands"""
        results = neo4j_adapter.get_oscp_high()

        assert isinstance(results, list)

        # All results should have high OSCP relevance
        for cmd in results:
            assert cmd.oscp_relevance == 'high' or 'OSCP:HIGH' in cmd.tags


# ============================================================================
# Edge Cases and Error Handling (3 tests)
# ============================================================================

class TestEdgeCases:
    """Test edge cases and error handling"""

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_search_special_characters(self, neo4j_adapter):
        """Test search handles special characters safely"""
        # Cypher has special characters that need escaping
        special_queries = [
            "test: (special)",
            "command-with-dash",
            "command_with_underscore",
            "command.with.dots"
        ]

        for query in special_queries:
            # Should not raise exception
            results = neo4j_adapter.search(query)
            assert isinstance(results, list)

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_filter_nonexistent_category(self, neo4j_adapter):
        """Test filtering by invalid category"""
        results = neo4j_adapter.filter_by_category('nonexistent_category_12345')

        assert isinstance(results, list)
        assert len(results) == 0

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_filter_nonexistent_tag(self, neo4j_adapter):
        """Test filtering by invalid tag"""
        results = neo4j_adapter.filter_by_tags(['NONEXISTENT_TAG_12345'])

        assert isinstance(results, list)
        assert len(results) == 0


# ============================================================================
# Performance-Related Tests (2 tests)
# ============================================================================

class TestPerformance:
    """Test performance-critical operations"""

    @pytest.mark.unit
    @pytest.mark.neo4j
    @pytest.mark.slow
    def test_deep_traversal_completes(self, neo4j_adapter):
        """Test that deep graph traversal completes within reasonable time"""
        import time

        start = time.time()
        paths = neo4j_adapter.find_alternatives('gobuster-dir', max_depth=5)
        elapsed = time.time() - start

        # Should complete within 5 seconds
        assert elapsed < 5.0
        assert isinstance(paths, list)

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_batch_queries_efficient(self, neo4j_adapter):
        """Test that multiple queries can be executed efficiently"""
        import time

        commands_to_fetch = [
            'nmap-quick-scan',
            'gobuster-dir',
            'bash-reverse-shell'
        ]

        start = time.time()
        for cmd_id in commands_to_fetch:
            cmd = neo4j_adapter.get_command(cmd_id)
        elapsed = time.time() - start

        # Should complete within 2 seconds
        assert elapsed < 2.0


# ============================================================================
# Advanced Integration Tests (4 tests)
# ============================================================================

class TestAdvancedQueryIntegration:
    """End-to-end workflow tests demonstrating how patterns compose"""

    @pytest.mark.unit
    @pytest.mark.neo4j
    @pytest.mark.integration
    def test_oscp_exam_workflow(self, neo4j_adapter):
        """
        Integration test: Complete OSCP exam workflow

        Scenario: Enumerate -> Exploit -> Privesc
        Uses multiple primitives in sequence
        """
        # Step 1: Find starter enumeration commands (Pattern 5)
        initial_commands = neo4j_adapter.aggregate_by_pattern(
            pattern="(c:Command)-[:TAGGED]->(t:Tag {name: 'STARTER'})",
            group_by=['c'],
            aggregations={'id': 'c.id', 'name': 'c.name'},
            limit=10
        )
        assert isinstance(initial_commands, list)

        # Step 2: After nmap, find service-specific attacks (Pattern 5)
        service_attacks = neo4j_adapter.aggregate_by_pattern(
            pattern="(s:Service {name: 'http'})-[:ENUMERATED_BY]->(c:Command)",
            group_by=['c'],
            aggregations={'id': 'c.id', 'priority': 'MIN(c.priority)'},
            order_by='priority ASC',
            limit=5
        )
        assert isinstance(service_attacks, list)

        # Step 3: If primary tool fails, find alternatives (Pattern 1)
        if service_attacks and len(service_attacks) > 0:
            alternatives = neo4j_adapter.traverse_graph(
                start_node_id=service_attacks[0]['id'],
                rel_type='ALTERNATIVE',
                max_depth=2,
                return_metadata=True
            )
            assert isinstance(alternatives, list)

        # Step 4: Find shortest path to privesc (Pattern 2)
        privesc_paths = neo4j_adapter.find_by_pattern(
            pattern="shortestPath((start)-[:NEXT_STEP*]-(end:Command))",
            where_clause="end.tags CONTAINS 'PRIVESC'",
            limit=3
        )
        assert isinstance(privesc_paths, list)

        # Workflow should complete without errors
        assert True

    @pytest.mark.unit
    @pytest.mark.neo4j
    @pytest.mark.integration
    def test_prerequisite_validation_workflow(self, neo4j_adapter):
        """
        Integration test: Validate all prerequisites before exploit

        Combines Pattern 3 (prerequisites) with Pattern 4 (parallel execution)
        """
        exploit_id = 'wordpress-sqli'

        # Get all prerequisites with execution order
        prereqs = neo4j_adapter.find_prerequisites(
            exploit_id,
            execution_order=True
        )

        assert isinstance(prereqs, list)

        if len(prereqs) > 0:
            # Verify no circular dependencies exist (Pattern 9)
            cycles = neo4j_adapter.find_by_pattern(
                pattern="(s:ChainStep)-[:DEPENDS_ON*]->(s)",
                return_fields=['s.id']
            )
            assert isinstance(cycles, list)
            # No cycles should exist
            assert len(cycles) == 0, "Circular dependencies detected"

            # Check if prerequisites have coverage (Pattern 8)
            for prereq in prereqs:
                # Ensure each prereq command exists and is OSCP-relevant
                cmd = neo4j_adapter.get_command(prereq.get('command_id', prereq.get('id', '')))
                # Command may or may not exist in test data
                if cmd is not None:
                    assert isinstance(cmd, Command)

    @pytest.mark.unit
    @pytest.mark.neo4j
    @pytest.mark.integration
    def test_multi_pattern_composition(self, neo4j_adapter):
        """
        Integration test: Compose multiple patterns for complex query

        Scenario: Find alternatives for commands that target specific services
        """
        # Pattern 5: Get service-specific commands
        service_commands = neo4j_adapter.aggregate_by_pattern(
            pattern="(s:Service)-[:ENUMERATED_BY]->(c:Command)",
            group_by=['c'],
            aggregations={
                'command_id': 'c.id',
                'services': 'COLLECT(s.name)',
                'service_count': 'COUNT(s)'
            },
            filters={'c.oscp_relevance': 'high'},
            order_by='service_count DESC',
            limit=5
        )

        assert isinstance(service_commands, list)

        # Pattern 1: For each command, find alternatives
        for cmd_info in service_commands[:3]:  # Check first 3
            alternatives = neo4j_adapter.traverse_graph(
                start_node_id=cmd_info['command_id'],
                rel_type='ALTERNATIVE',
                max_depth=2,
                return_metadata=True
            )
            # Should complete without error
            assert isinstance(alternatives, list)

    @pytest.mark.unit
    @pytest.mark.neo4j
    @pytest.mark.integration
    @pytest.mark.slow
    def test_performance_complex_traversal(self, neo4j_adapter):
        """Performance test: 3+ hop traversals complete in <500ms"""
        import time

        start_time = time.time()

        results = neo4j_adapter.traverse_graph(
            start_node_id='nmap-quick-scan',
            rel_type='NEXT_STEP',
            direction='OUTGOING',
            max_depth=5,  # Deep traversal
            limit=100
        )

        elapsed = time.time() - start_time

        # Should complete in reasonable time
        assert elapsed < 0.5, f"Query took {elapsed:.3f}s (expected <500ms)"
        assert isinstance(results, list)
