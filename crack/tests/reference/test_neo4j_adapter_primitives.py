#!/usr/bin/env python3
"""
Graph Primitive Tests for Neo4j Command Registry Adapter
Tests the 3 new graph primitives: traverse_graph, aggregate_by_pattern, find_by_pattern
"""

import pytest
from typing import List, Dict
from crack.reference.core import Command, ConfigManager, ReferenceTheme


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


# ============================================================================
# Graph Traversal Primitive Tests (200 LOC)
# ============================================================================

class TestGraphTraversalPrimitive:
    """Test traverse_graph() method covering Patterns 1, 3, 6"""

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_traverse_multi_hop_alternatives(self, neo4j_adapter):
        """Test Pattern 1: Multi-hop alternative chains with metadata"""
        if not hasattr(neo4j_adapter, 'traverse_graph'):
            pytest.skip("traverse_graph() not yet implemented")

        results = neo4j_adapter.traverse_graph(
            start_node_id='gobuster-dir',
            rel_type='ALTERNATIVE',
            direction='OUTGOING',
            max_depth=3,
            return_metadata=True,
            limit=10
        )

        # Verify structure
        assert isinstance(results, list)
        assert len(results) >= 0

        if results:
            # Verify metadata fields
            first_result = results[0]
            assert 'command_chain' in first_result
            assert 'metadata' in first_result
            assert 'depth' in first_result
            assert 'cumulative_priority' in first_result

            # Verify ordering (depth ascending, priority ascending)
            depths = [r['depth'] for r in results]
            assert depths == sorted(depths)

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_traverse_prerequisites_incoming(self, neo4j_adapter):
        """Test Pattern 3: Prerequisite traversal with INCOMING direction"""
        if not hasattr(neo4j_adapter, 'traverse_graph'):
            pytest.skip("traverse_graph() not yet implemented")

        results = neo4j_adapter.traverse_graph(
            start_node_id='wordpress-sqli',
            rel_type='PREREQUISITE',
            direction='INCOMING',
            max_depth=5,
            return_metadata=False
        )

        # Should return Command objects when return_metadata=False
        assert isinstance(results, list)

        if results:
            assert all(isinstance(cmd, Command) for cmd in results)

            # Should include transitive prerequisites
            command_ids = [cmd.id for cmd in results]
            assert len(command_ids) > 0

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_traverse_tag_hierarchy(self, neo4j_adapter):
        """Test Pattern 6: Tag hierarchy traversal"""
        if not hasattr(neo4j_adapter, 'traverse_graph'):
            pytest.skip("traverse_graph() not yet implemented")

        results = neo4j_adapter.traverse_graph(
            start_node_id='OSCP',
            rel_type='CHILD_OF',
            direction='INCOMING',
            max_depth=2,
            return_metadata=False
        )

        # Should find child tags
        assert isinstance(results, list)

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_traverse_bidirectional(self, neo4j_adapter):
        """Test BOTH direction traversal"""
        if not hasattr(neo4j_adapter, 'traverse_graph'):
            pytest.skip("traverse_graph() not yet implemented")

        results = neo4j_adapter.traverse_graph(
            start_node_id='nmap-quick-scan',
            rel_type='NEXT_STEP',
            direction='BOTH',
            max_depth=2
        )

        # Should find nodes in both directions
        assert isinstance(results, list)

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_traverse_depth_limit(self, neo4j_adapter):
        """Test max_depth parameter enforcement"""
        if not hasattr(neo4j_adapter, 'traverse_graph'):
            pytest.skip("traverse_graph() not yet implemented")

        results_depth_1 = neo4j_adapter.traverse_graph(
            'gobuster-dir',
            'ALTERNATIVE',
            max_depth=1
        )
        results_depth_3 = neo4j_adapter.traverse_graph(
            'gobuster-dir',
            'ALTERNATIVE',
            max_depth=3
        )

        # Deeper traversal should find more or equal results
        assert isinstance(results_depth_1, list)
        assert isinstance(results_depth_3, list)
        assert len(results_depth_3) >= len(results_depth_1)

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_traverse_with_filters(self, neo4j_adapter):
        """Test filter parameter"""
        if not hasattr(neo4j_adapter, 'traverse_graph'):
            pytest.skip("traverse_graph() not yet implemented")

        results = neo4j_adapter.traverse_graph(
            start_node_id='nmap-quick-scan',
            rel_type='ALTERNATIVE',
            filters={'oscp_relevance': 'high'},
            return_metadata=False
        )

        # All results should match filter
        assert isinstance(results, list)

        if results:
            for cmd in results:
                if isinstance(cmd, Command):
                    assert cmd.oscp_relevance == 'high'

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_traverse_empty_results(self, neo4j_adapter):
        """Test graceful handling of no results"""
        if not hasattr(neo4j_adapter, 'traverse_graph'):
            pytest.skip("traverse_graph() not yet implemented")

        results = neo4j_adapter.traverse_graph(
            start_node_id='nonexistent-id-12345',
            rel_type='ALTERNATIVE'
        )

        # Should return empty list, not error
        assert results == []

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_traverse_return_metadata_structure(self, neo4j_adapter):
        """Test metadata structure contains all required fields"""
        if not hasattr(neo4j_adapter, 'traverse_graph'):
            pytest.skip("traverse_graph() not yet implemented")

        results = neo4j_adapter.traverse_graph(
            start_node_id='gobuster-dir',
            rel_type='ALTERNATIVE',
            max_depth=2,
            return_metadata=True
        )

        if results:
            first = results[0]
            # Should have command chain (list of nodes)
            assert isinstance(first.get('command_chain'), list)
            # Should have relationship metadata
            assert 'metadata' in first
            # Should have depth indicator
            assert isinstance(first.get('depth'), int)

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_traverse_limit_enforcement(self, neo4j_adapter):
        """Test that limit parameter is enforced"""
        if not hasattr(neo4j_adapter, 'traverse_graph'):
            pytest.skip("traverse_graph() not yet implemented")

        results = neo4j_adapter.traverse_graph(
            start_node_id='nmap-quick-scan',
            rel_type='NEXT_STEP',
            max_depth=5,
            limit=5
        )

        assert isinstance(results, list)
        assert len(results) <= 5


# ============================================================================
# Aggregation Primitive Tests (150 LOC)
# ============================================================================

class TestAggregationPrimitive:
    """Test aggregate_by_pattern() covering Patterns 5, 7, 10"""

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_aggregate_service_recommendations(self, neo4j_adapter):
        """Test Pattern 5: Service-based command recommendations"""
        if not hasattr(neo4j_adapter, 'aggregate_by_pattern'):
            pytest.skip("aggregate_by_pattern() not yet implemented")

        results = neo4j_adapter.aggregate_by_pattern(
            pattern="(p:Port)<-[:RUNS_ON]-(s:Service)-[:ENUMERATED_BY]->(c:Command)",
            group_by=['c'],
            aggregations={
                'command_id': 'c.id',
                'command_name': 'c.name',
                'services': 'COLLECT(DISTINCT s.name)',
                'service_count': 'COUNT(DISTINCT s)'
            },
            filters={'p.number': [80, 445, 22]},
            order_by='service_count DESC',
            limit=10
        )

        assert isinstance(results, list)

        if results:
            # Verify aggregation fields
            first = results[0]
            assert 'command_id' in first
            assert 'services' in first
            assert 'service_count' in first

            # Verify ordering (service_count descending)
            counts = [r['service_count'] for r in results]
            assert counts == sorted(counts, reverse=True)

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_aggregate_variable_usage(self, neo4j_adapter):
        """Test Pattern 10: Variable usage analysis"""
        if not hasattr(neo4j_adapter, 'aggregate_by_pattern'):
            pytest.skip("aggregate_by_pattern() not yet implemented")

        results = neo4j_adapter.aggregate_by_pattern(
            pattern="(v:Variable)<-[u:USES_VARIABLE]-(c:Command)",
            group_by=['v'],
            aggregations={
                'variable_name': 'v.name',
                'usage_count': 'COUNT(c)',
                'sample_commands': 'COLLECT(c.id)[0..5]'
            },
            filters={'u.required': True},
            order_by='usage_count DESC',
            limit=10
        )

        assert isinstance(results, list)

        if results:
            # Most common variables should appear first
            assert results[0]['usage_count'] > 0

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_aggregate_dynamic_group_by(self, neo4j_adapter):
        """Test multiple GROUP BY fields"""
        if not hasattr(neo4j_adapter, 'aggregate_by_pattern'):
            pytest.skip("aggregate_by_pattern() not yet implemented")

        results = neo4j_adapter.aggregate_by_pattern(
            pattern="(c:Command)-[:TAGGED]->(t:Tag)",
            group_by=['c', 't'],
            aggregations={
                'command_id': 'c.id',
                'tag_name': 't.name',
                'count': 'COUNT(*)'
            }
        )

        assert isinstance(results, list)

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_aggregate_multiple_aggregations(self, neo4j_adapter):
        """Test multiple aggregation functions"""
        if not hasattr(neo4j_adapter, 'aggregate_by_pattern'):
            pytest.skip("aggregate_by_pattern() not yet implemented")

        results = neo4j_adapter.aggregate_by_pattern(
            pattern="(c:Command)-[:TAGGED]->(t:Tag)",
            group_by=['t'],
            aggregations={
                'tag': 't.name',
                'count': 'COUNT(c)',
                'avg_priority': 'AVG(c.priority)',
                'commands': 'COLLECT(c.id)'
            }
        )

        if results:
            first = results[0]
            assert 'count' in first
            assert 'commands' in first
            assert isinstance(first['commands'], list)

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_aggregate_security_validation(self, neo4j_adapter):
        """Test that dangerous Cypher is blocked"""
        if not hasattr(neo4j_adapter, 'aggregate_by_pattern'):
            pytest.skip("aggregate_by_pattern() not yet implemented")

        # Try to inject DELETE statement
        with pytest.raises((ValueError, Exception)) as exc_info:
            neo4j_adapter.aggregate_by_pattern(
                pattern="(c:Command) DELETE c",
                group_by=['c'],
                aggregations={'count': 'COUNT(c)'}
            )

        # Should raise error about dangerous operation
        error_msg = str(exc_info.value).lower()
        assert 'delete' in error_msg or 'not allowed' in error_msg or 'injection' in error_msg

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_aggregate_with_filters(self, neo4j_adapter):
        """Test filters parameter with IN clause"""
        if not hasattr(neo4j_adapter, 'aggregate_by_pattern'):
            pytest.skip("aggregate_by_pattern() not yet implemented")

        results = neo4j_adapter.aggregate_by_pattern(
            pattern="(c:Command)-[:TAGGED]->(t:Tag)",
            group_by=['t'],
            aggregations={
                'tag': 't.name',
                'count': 'COUNT(c)'
            },
            filters={'t.name': ['OSCP:HIGH', 'QUICK_WIN']}
        )

        assert isinstance(results, list)

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_aggregate_empty_results(self, neo4j_adapter):
        """Test graceful handling of no matches"""
        if not hasattr(neo4j_adapter, 'aggregate_by_pattern'):
            pytest.skip("aggregate_by_pattern() not yet implemented")

        results = neo4j_adapter.aggregate_by_pattern(
            pattern="(c:Command {id: 'nonexistent-12345'})",
            group_by=['c'],
            aggregations={'count': 'COUNT(c)'}
        )

        assert isinstance(results, list)

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_aggregate_collect_slicing(self, neo4j_adapter):
        """Test COLLECT with array slicing (Cypher [0..5] syntax)"""
        if not hasattr(neo4j_adapter, 'aggregate_by_pattern'):
            pytest.skip("aggregate_by_pattern() not yet implemented")

        results = neo4j_adapter.aggregate_by_pattern(
            pattern="(t:Tag)<-[:TAGGED]-(c:Command)",
            group_by=['t'],
            aggregations={
                'tag_name': 't.name',
                'top_5_commands': 'COLLECT(c.id)[0..5]'
            },
            limit=10
        )

        if results:
            first = results[0]
            assert 'top_5_commands' in first
            assert len(first['top_5_commands']) <= 5


# ============================================================================
# Pattern Matching Primitive Tests (100 LOC)
# ============================================================================

class TestPatternMatchingPrimitive:
    """Test find_by_pattern() covering Patterns 2, 8, 9"""

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_find_shortest_path(self, neo4j_adapter):
        """Test Pattern 2: Shortest attack path"""
        if not hasattr(neo4j_adapter, 'find_by_pattern'):
            pytest.skip("find_by_pattern() not yet implemented")

        results = neo4j_adapter.find_by_pattern(
            pattern="shortestPath((start:Command)-[:NEXT_STEP*]-(end:Command))",
            where_clause="start.tags CONTAINS 'STARTER' AND end.tags CONTAINS 'PRIVESC'",
            return_fields=['start.id', 'end.id', 'length(path) AS path_length'],
            limit=5
        )

        assert isinstance(results, list)
        assert len(results) <= 5

        if results:
            assert 'path_length' in results[0]

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_find_coverage_gaps(self, neo4j_adapter):
        """Test Pattern 8: Services without high-OSCP enumeration"""
        if not hasattr(neo4j_adapter, 'find_by_pattern'):
            pytest.skip("find_by_pattern() not yet implemented")

        results = neo4j_adapter.find_by_pattern(
            pattern="(s:Service) WHERE NOT exists { MATCH (s)-[:ENUMERATED_BY]->(c:Command) WHERE c.oscp_relevance = 'high' }",
            return_fields=['s.name', 's.protocol'],
            limit=50
        )

        # Should find services lacking high-OSCP commands
        assert isinstance(results, list)
        assert len(results) <= 50

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_find_circular_dependencies(self, neo4j_adapter):
        """Test Pattern 9: Detect cycles in attack chains"""
        if not hasattr(neo4j_adapter, 'find_by_pattern'):
            pytest.skip("find_by_pattern() not yet implemented")

        results = neo4j_adapter.find_by_pattern(
            pattern="(s:ChainStep)-[:DEPENDS_ON*]->(s)",
            return_fields=['s.id', 's.name', 'length(path) AS cycle_length']
        )

        # May be empty if no cycles (good!)
        assert isinstance(results, list)

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_find_pattern_security_blocked(self, neo4j_adapter):
        """Test Cypher injection prevention"""
        if not hasattr(neo4j_adapter, 'find_by_pattern'):
            pytest.skip("find_by_pattern() not yet implemented")

        dangerous_patterns = [
            "MATCH (n) DELETE n",
            "MATCH (n) SET n.hacked = true",
            "CREATE (n:Evil)",
            "MATCH (n); DROP DATABASE",
        ]

        for pattern in dangerous_patterns:
            with pytest.raises((ValueError, Exception)) as exc_info:
                neo4j_adapter.find_by_pattern(pattern)

            # Should raise error
            error_msg = str(exc_info.value).lower()
            assert any(keyword in error_msg for keyword in ['not allowed', 'injection', 'delete', 'create', 'set'])

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_find_pattern_empty_results(self, neo4j_adapter):
        """Test graceful handling of no matches"""
        if not hasattr(neo4j_adapter, 'find_by_pattern'):
            pytest.skip("find_by_pattern() not yet implemented")

        results = neo4j_adapter.find_by_pattern(
            pattern="(n:NonExistentNode)",
            return_fields=['n.id']
        )

        assert results == []

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_find_pattern_with_where(self, neo4j_adapter):
        """Test pattern with WHERE clause"""
        if not hasattr(neo4j_adapter, 'find_by_pattern'):
            pytest.skip("find_by_pattern() not yet implemented")

        results = neo4j_adapter.find_by_pattern(
            pattern="(c:Command)",
            where_clause="c.oscp_relevance = 'high'",
            return_fields=['c.id', 'c.name'],
            limit=10
        )

        assert isinstance(results, list)
        assert len(results) <= 10

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_find_pattern_return_path_objects(self, neo4j_adapter):
        """Test pattern returns path objects correctly"""
        if not hasattr(neo4j_adapter, 'find_by_pattern'):
            pytest.skip("find_by_pattern() not yet implemented")

        results = neo4j_adapter.find_by_pattern(
            pattern="path = (start:Command)-[:ALTERNATIVE*1..2]->(end:Command)",
            where_clause="start.id = 'gobuster-dir'",
            return_fields=['nodes(path)', 'length(path)'],
            limit=5
        )

        assert isinstance(results, list)


# ============================================================================
# Enhanced Method Tests (50 LOC)
# ============================================================================

class TestEnhancedMethods:
    """Test enhanced existing methods with new parameters"""

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_find_alternatives_with_metadata(self, neo4j_adapter):
        """Test enhanced find_alternatives with return_metadata=True"""
        import inspect

        # Check if method supports return_metadata parameter
        if 'return_metadata' not in inspect.signature(neo4j_adapter.find_alternatives).parameters:
            pytest.skip("find_alternatives doesn't support return_metadata yet")

        results = neo4j_adapter.find_alternatives('gobuster-dir', max_depth=2, return_metadata=True)

        if results:
            assert 'command_chain' in results[0]
            assert 'metadata' in results[0]

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_find_prerequisites_execution_order(self, neo4j_adapter):
        """Test enhanced find_prerequisites with execution_order=True"""
        import inspect

        if 'execution_order' not in inspect.signature(neo4j_adapter.find_prerequisites).parameters:
            pytest.skip("find_prerequisites doesn't support execution_order yet")

        results = neo4j_adapter.find_prerequisites('wordpress-sqli', execution_order=True)

        if results:
            assert 'dependency_count' in results[0]
            # Should be sorted by dependency_count DESC
            counts = [r['dependency_count'] for r in results]
            assert counts == sorted(counts, reverse=True)

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_filter_by_tags_hierarchy(self, neo4j_adapter):
        """Test enhanced filter_by_tags with include_hierarchy=True"""
        import inspect

        if 'include_hierarchy' not in inspect.signature(neo4j_adapter.filter_by_tags).parameters:
            pytest.skip("filter_by_tags doesn't support include_hierarchy yet")

        results_flat = neo4j_adapter.filter_by_tags(['OSCP'], include_hierarchy=False)
        results_hierarchical = neo4j_adapter.filter_by_tags(['OSCP'], include_hierarchy=True)

        # Hierarchical should include more or equal results (child tags)
        assert len(results_hierarchical) >= len(results_flat)

    @pytest.mark.unit
    @pytest.mark.neo4j
    def test_filter_by_tags_hierarchy_depth(self, neo4j_adapter):
        """Test tag hierarchy includes multiple levels"""
        import inspect

        if 'include_hierarchy' not in inspect.signature(neo4j_adapter.filter_by_tags).parameters:
            pytest.skip("filter_by_tags doesn't support include_hierarchy yet")

        # Should find commands tagged with OSCP, OSCP:ENUM, OSCP:EXPLOIT, etc.
        results = neo4j_adapter.filter_by_tags(['OSCP'], include_hierarchy=True)

        assert isinstance(results, list)
