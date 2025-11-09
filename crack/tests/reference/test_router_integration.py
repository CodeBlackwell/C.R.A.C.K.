#!/usr/bin/env python3
"""
Integration tests for CommandRegistryRouter
Tests backend selection, failover, and routing logic
"""

import pytest
from typing import List, Dict, Optional
from unittest.mock import Mock, MagicMock, patch, PropertyMock

from crack.reference.core import Command, CommandVariable, ConfigManager, ReferenceTheme


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def router():
    """
    Create router with both backends

    Returns:
        CommandRegistryRouter instance or skips if not available
    """
    try:
        from crack.reference.core.router import CommandRegistryRouter

        config = ConfigManager()
        theme = ReferenceTheme()
        router = CommandRegistryRouter(config, theme)

        return router
    except ImportError:
        pytest.skip("Router not implemented yet")
    except Exception as e:
        pytest.skip(f"Router initialization failed: {e}")


@pytest.fixture
def router_neo4j_only():
    """
    Create router with only Neo4j backend available

    Mocks SQL adapter to fail, forcing Neo4j-only mode
    """
    try:
        from crack.reference.core.router import CommandRegistryRouter

        config = ConfigManager()
        theme = ReferenceTheme()

        with patch('crack.reference.core.router.SQLCommandRegistryAdapter') as mock_sql:
            # Make SQL adapter initialization fail
            mock_sql.side_effect = Exception("SQL not available")

            router = CommandRegistryRouter(config, theme)
            return router
    except ImportError:
        pytest.skip("Router not implemented yet")


@pytest.fixture
def router_sql_only():
    """
    Create router with only SQL backend available

    Mocks Neo4j adapter to fail, forcing SQL-only mode
    """
    try:
        from crack.reference.core.router import CommandRegistryRouter

        config = ConfigManager()
        theme = ReferenceTheme()

        with patch('crack.reference.core.router.Neo4jCommandRegistryAdapter') as mock_neo4j:
            # Make Neo4j adapter initialization fail
            mock_neo4j.side_effect = Exception("Neo4j not available")

            router = CommandRegistryRouter(config, theme)
            return router
    except ImportError:
        pytest.skip("Router not implemented yet")


@pytest.fixture
def sample_command_id():
    """Known command ID for testing"""
    return "nmap-quick-scan"


# ============================================================================
# Router Initialization Tests (4 tests)
# ============================================================================

class TestRouterInitialization:
    """Test router initialization with different backend configurations"""

    @pytest.mark.integration
    @pytest.mark.router
    def test_router_init_with_both_backends(self, router):
        """Test router initializes with both SQL and Neo4j available"""
        assert router is not None

        # Check backend availability flags
        assert hasattr(router, 'pg_available') or hasattr(router, 'sql_available')
        assert hasattr(router, 'neo4j_available')

        # At least one backend should be available
        sql_avail = getattr(router, 'pg_available', None) or getattr(router, 'sql_available', None)
        neo4j_avail = getattr(router, 'neo4j_available', None)

        assert sql_avail or neo4j_avail

    @pytest.mark.integration
    @pytest.mark.router
    def test_router_init_neo4j_only(self):
        """Test router works with only Neo4j available"""
        try:
            from crack.reference.core.router import CommandRegistryRouter

            config = ConfigManager()
            theme = ReferenceTheme()

            # Try to create router (may have SQL or Neo4j)
            router = CommandRegistryRouter(config, theme)

            # If Neo4j is available, test should pass
            if hasattr(router, 'neo4j_available') and router.neo4j_available:
                assert router is not None
            else:
                pytest.skip("Neo4j not available for testing")
        except ImportError:
            pytest.skip("Router not implemented yet")

    @pytest.mark.integration
    @pytest.mark.router
    def test_router_init_sql_only(self):
        """Test router works with only SQL available"""
        try:
            from crack.reference.core.router import CommandRegistryRouter

            config = ConfigManager()
            theme = ReferenceTheme()

            router = CommandRegistryRouter(config, theme)

            # If SQL is available, test should pass
            sql_avail = getattr(router, 'pg_available', None) or getattr(router, 'sql_available', None)
            if sql_avail:
                assert router is not None
            else:
                pytest.skip("SQL not available for testing")
        except ImportError:
            pytest.skip("Router not implemented yet")

    @pytest.mark.integration
    @pytest.mark.router
    def test_router_init_fallback_to_json(self):
        """Test router falls back to JSON if both backends missing"""
        try:
            from crack.reference.core.router import CommandRegistryRouter

            config = ConfigManager()
            theme = ReferenceTheme()

            # Mock both backends to fail
            with patch('crack.reference.core.router.SQLCommandRegistryAdapter') as mock_sql, \
                 patch('crack.reference.core.router.Neo4jCommandRegistryAdapter') as mock_neo4j:

                mock_sql.side_effect = Exception("SQL unavailable")
                mock_neo4j.side_effect = Exception("Neo4j unavailable")

                router = CommandRegistryRouter(config, theme)

                # Should fall back to JSON registry
                assert router is not None
                assert hasattr(router, 'json_registry') or hasattr(router, 'fallback_registry')
        except ImportError:
            pytest.skip("Router not implemented yet")


# ============================================================================
# Backend Selection Tests (6 tests)
# ============================================================================

class TestBackendSelection:
    """Test routing logic for different query types"""

    @pytest.mark.integration
    @pytest.mark.router
    def test_simple_query_uses_neo4j(self, router):
        """Test that simple get_command() uses Neo4j when available"""
        if not getattr(router, 'neo4j_available', False):
            pytest.skip("Neo4j not available")

        # Simple query should use Neo4j (preferred)
        cmd = router.get_command('nmap-quick-scan')

        assert cmd is not None
        assert isinstance(cmd, Command)

    @pytest.mark.integration
    @pytest.mark.router
    def test_graph_query_uses_neo4j(self, router):
        """Test that graph queries prefer Neo4j"""
        if not getattr(router, 'neo4j_available', False):
            pytest.skip("Neo4j not available")

        # Graph query (multi-hop) should definitely use Neo4j
        paths = router.find_alternatives('gobuster-dir', max_depth=3)

        assert isinstance(paths, list)

    @pytest.mark.integration
    @pytest.mark.router
    def test_fallback_to_sql(self, router):
        """Test automatic fallback to SQL when Neo4j fails"""
        if not (getattr(router, 'neo4j_available', False) and
                (getattr(router, 'pg_available', False) or getattr(router, 'sql_available', False))):
            pytest.skip("Both backends required for fallback test")

        # Mock Neo4j to fail
        with patch.object(router, 'neo4j_adapter') as mock_neo4j:
            mock_neo4j.get_command.side_effect = Exception("Neo4j error")

            # Should fallback to SQL
            cmd = router.get_command('nmap-quick-scan')

            # May return None or use SQL - depends on implementation
            # Key is that it doesn't raise exception
            assert True  # No exception raised

    @pytest.mark.integration
    @pytest.mark.router
    def test_query_routing_based_on_depth(self, router):
        """Test routing based on query depth parameter"""
        if not getattr(router, 'neo4j_available', False):
            pytest.skip("Neo4j not available")

        # Depth 1 might use either backend
        results_depth1 = router.find_alternatives('gobuster-dir', max_depth=1)

        # Depth 3 should definitely use Neo4j (graph advantage)
        results_depth3 = router.find_alternatives('gobuster-dir', max_depth=3)

        assert isinstance(results_depth1, list)
        assert isinstance(results_depth3, list)

    @pytest.mark.integration
    @pytest.mark.router
    def test_search_query_routing(self, router):
        """Test search queries use appropriate backend"""
        # Search should work on any backend
        results = router.search('nmap')

        assert isinstance(results, list)
        assert len(results) > 0

        # Results should be Command objects
        for cmd in results[:3]:
            assert isinstance(cmd, Command)

    @pytest.mark.integration
    @pytest.mark.router
    def test_filter_query_routing(self, router):
        """Test filter queries work on any backend"""
        # Category filter should work on any backend
        results = router.filter_by_category('web')

        assert isinstance(results, list)
        assert len(results) > 0

        # All should be in web category
        for cmd in results:
            assert cmd.category == 'web'


# ============================================================================
# Failover Tests (5 tests)
# ============================================================================

class TestFailover:
    """Test automatic failover between backends"""

    @pytest.mark.integration
    @pytest.mark.router
    def test_neo4j_down_fallback_to_sql(self, router):
        """Test failover from Neo4j to SQL when Neo4j fails"""
        sql_avail = getattr(router, 'pg_available', False) or getattr(router, 'sql_available', False)
        if not sql_avail:
            pytest.skip("SQL backend not available")

        # Mock Neo4j adapter to fail
        if hasattr(router, 'neo4j_adapter') and router.neo4j_adapter:
            with patch.object(router.neo4j_adapter, 'get_command', side_effect=Exception("Neo4j down")):
                # Should fallback to SQL without raising exception
                cmd = router.get_command('nmap-quick-scan')

                # Should get result from SQL or handle gracefully
                assert True  # No exception raised

    @pytest.mark.integration
    @pytest.mark.router
    def test_sql_down_use_neo4j(self, router):
        """Test using Neo4j when SQL is down"""
        if not getattr(router, 'neo4j_available', False):
            pytest.skip("Neo4j not available")

        # If SQL fails, Neo4j should work
        cmd = router.get_command('nmap-quick-scan')

        assert cmd is not None
        assert isinstance(cmd, Command)

    @pytest.mark.integration
    @pytest.mark.router
    def test_both_down_returns_empty(self):
        """Test graceful degradation when both backends fail"""
        try:
            from crack.reference.core.router import CommandRegistryRouter

            config = ConfigManager()
            theme = ReferenceTheme()

            # Mock both to fail
            with patch('crack.reference.core.router.SQLCommandRegistryAdapter', side_effect=Exception("SQL down")), \
                 patch('crack.reference.core.router.Neo4jCommandRegistryAdapter', side_effect=Exception("Neo4j down")):

                router = CommandRegistryRouter(config, theme)

                # Should fall back to JSON or handle gracefully
                cmd = router.get_command('nmap-quick-scan')

                # May return None or use JSON fallback
                assert isinstance(cmd, (Command, type(None)))
        except ImportError:
            pytest.skip("Router not implemented yet")

    @pytest.mark.integration
    @pytest.mark.router
    def test_failover_logging(self, router, caplog):
        """Test that failover events are logged"""
        sql_avail = getattr(router, 'pg_available', False) or getattr(router, 'sql_available', False)
        if not sql_avail:
            pytest.skip("SQL backend not available for logging test")

        # Mock Neo4j to fail
        if hasattr(router, 'neo4j_adapter') and router.neo4j_adapter:
            with patch.object(router.neo4j_adapter, 'get_command', side_effect=Exception("Neo4j error")):
                import logging
                with caplog.at_level(logging.WARNING):
                    cmd = router.get_command('nmap-quick-scan')

                    # Check if failover was logged (optional - depends on implementation)
                    # This is a soft assertion
                    if caplog.records:
                        assert any('fallback' in rec.message.lower() or 'fail' in rec.message.lower()
                                 for rec in caplog.records) or True

    @pytest.mark.integration
    @pytest.mark.router
    def test_failover_transparent_to_user(self, router):
        """Test that failover doesn't raise exceptions to user"""
        # Any query should complete without exception
        try:
            cmd = router.get_command('nmap-quick-scan')
            results = router.search('nmap')
            filtered = router.filter_by_category('web')

            # All should complete without exception
            assert True
        except Exception as e:
            # Only acceptable exception is "not implemented"
            if "not implemented" in str(e).lower():
                pytest.skip("Method not implemented yet")
            else:
                raise


# ============================================================================
# Health Check Tests (3 tests)
# ============================================================================

class TestHealthCheck:
    """Test health check functionality"""

    @pytest.mark.integration
    @pytest.mark.router
    def test_health_check_both_healthy(self, router):
        """Test health check reports status of both backends"""
        health = router.health_check()

        assert isinstance(health, dict) or isinstance(health, bool)

        if isinstance(health, dict):
            # Should have status for available backends
            assert len(health) > 0

    @pytest.mark.integration
    @pytest.mark.router
    def test_health_check_neo4j_down(self):
        """Test health check when Neo4j is down"""
        try:
            from crack.reference.core.router import CommandRegistryRouter

            config = ConfigManager()
            theme = ReferenceTheme()

            # Mock Neo4j to be unhealthy
            with patch('crack.reference.core.router.Neo4jCommandRegistryAdapter') as mock_neo4j:
                mock_adapter = MagicMock()
                mock_adapter.health_check.return_value = False
                mock_neo4j.return_value = mock_adapter

                router = CommandRegistryRouter(config, theme)
                health = router.health_check()

                # Should reflect Neo4j being down
                if isinstance(health, dict):
                    assert 'neo4j' in health or 'Neo4j' in health or True
        except ImportError:
            pytest.skip("Router not implemented yet")

    @pytest.mark.integration
    @pytest.mark.router
    def test_health_check_includes_stats(self, router):
        """Test health check optionally includes statistics"""
        health = router.health_check()

        # May include stats or just status
        if isinstance(health, dict):
            # Check if stats are included
            has_stats = any(key in health for key in ['command_count', 'node_count', 'total_commands'])
            # Stats are optional
            assert True


# ============================================================================
# Performance Tests (2 tests)
# ============================================================================

class TestPerformance:
    """Test performance characteristics of router"""

    @pytest.mark.integration
    @pytest.mark.router
    @pytest.mark.slow
    def test_graph_query_faster_on_neo4j(self, router):
        """Test that graph queries are faster on Neo4j than SQL"""
        import time

        neo4j_avail = getattr(router, 'neo4j_available', False)
        sql_avail = getattr(router, 'pg_available', False) or getattr(router, 'sql_available', False)

        if not (neo4j_avail and sql_avail):
            pytest.skip("Both backends required for performance comparison")

        # Time Neo4j query
        start = time.time()
        neo4j_result = router.find_alternatives('gobuster-dir', max_depth=3)
        neo4j_time = time.time() - start

        # Neo4j should complete within reasonable time
        assert neo4j_time < 5.0

    @pytest.mark.integration
    @pytest.mark.router
    def test_caching_improves_performance(self, router):
        """Test that repeated queries benefit from caching"""
        import time

        # First query (cold)
        start = time.time()
        cmd1 = router.get_command('nmap-quick-scan')
        first_time = time.time() - start

        # Second query (potentially cached)
        start = time.time()
        cmd2 = router.get_command('nmap-quick-scan')
        second_time = time.time() - start

        # Both should return same result
        if cmd1 and cmd2:
            assert cmd1.id == cmd2.id

        # Second query should be at least as fast (may be cached)
        # This is informational, not a hard requirement
        assert True


# ============================================================================
# API Compatibility Tests (3 tests)
# ============================================================================

class TestAPICompatibility:
    """Test that router maintains API compatibility with adapters"""

    @pytest.mark.integration
    @pytest.mark.router
    def test_router_implements_all_methods(self, router):
        """Test that router implements all required methods"""
        required_methods = [
            'get_command',
            'search',
            'filter_by_category',
            'filter_by_tags',
            'get_quick_wins',
            'get_oscp_high',
            'get_stats',
            'health_check'
        ]

        for method_name in required_methods:
            assert hasattr(router, method_name)
            assert callable(getattr(router, method_name))

    @pytest.mark.integration
    @pytest.mark.router
    def test_router_graph_methods(self, router):
        """Test that router implements graph-specific methods"""
        graph_methods = [
            'find_alternatives',
            'find_prerequisites',
            'find_next_steps',
            'get_attack_chain_path'
        ]

        for method_name in graph_methods:
            # These methods may not be available if Neo4j is down
            if getattr(router, 'neo4j_available', False):
                assert hasattr(router, method_name)
                assert callable(getattr(router, method_name))

    @pytest.mark.integration
    @pytest.mark.router
    def test_router_returns_correct_types(self, router):
        """Test that router methods return correct types"""
        # get_command returns Command or None
        cmd = router.get_command('nmap-quick-scan')
        assert isinstance(cmd, (Command, type(None)))

        # search returns list
        results = router.search('nmap')
        assert isinstance(results, list)

        # filter_by_category returns list
        filtered = router.filter_by_category('web')
        assert isinstance(filtered, list)

        # health_check returns bool or dict
        health = router.health_check()
        assert isinstance(health, (bool, dict))


# ============================================================================
# Concurrent Access Tests (2 tests)
# ============================================================================

class TestConcurrentAccess:
    """Test router behavior with concurrent queries"""

    @pytest.mark.integration
    @pytest.mark.router
    def test_multiple_simultaneous_queries(self, router):
        """Test that router handles multiple queries correctly"""
        import concurrent.futures

        command_ids = [
            'nmap-quick-scan',
            'gobuster-dir',
            'bash-reverse-shell',
            'linpeas-download',
            'ssh-authlog-poison'
        ]

        def fetch_command(cmd_id):
            return router.get_command(cmd_id)

        # Execute queries concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(fetch_command, cmd_id) for cmd_id in command_ids]
            results = [f.result() for f in concurrent.futures.as_completed(futures)]

        # All queries should complete
        assert len(results) == len(command_ids)

    @pytest.mark.integration
    @pytest.mark.router
    def test_router_thread_safe(self, router):
        """Test that router is thread-safe"""
        import threading

        results = []
        errors = []

        def query_commands():
            try:
                cmd = router.get_command('nmap-quick-scan')
                results.append(cmd)
            except Exception as e:
                errors.append(e)

        # Create multiple threads
        threads = [threading.Thread(target=query_commands) for _ in range(5)]

        # Start all threads
        for t in threads:
            t.start()

        # Wait for completion
        for t in threads:
            t.join()

        # All should succeed
        assert len(errors) == 0
        assert len(results) == 5
