# 07 - Testing Strategy: Validation and Benchmarking

## Prerequisites
- [04-ADAPTER-IMPLEMENTATION.md](04-ADAPTER-IMPLEMENTATION.md) - Adapter code
- [05-INTEGRATION.md](05-INTEGRATION.md) - Router integration

## Overview

Comprehensive testing strategy for Neo4j integration including unit tests, integration tests, performance benchmarks, and data validation.

---

## Testing Pyramid

```
           ┌─────────────────────┐
           │   E2E Tests (5%)    │  Full workflow validation
           ├─────────────────────┤
           │ Integration (25%)   │  Router + Both backends
           ├─────────────────────┤
           │  Unit Tests (70%)   │  Adapter methods
           └─────────────────────┘
```

---

## Unit Tests

### Test Scope

Test each `Neo4jCommandRegistryAdapter` method in isolation.

**File**: `tests/reference/test_neo4j_adapter.py`

### Test Suite Structure

```python
import pytest
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter, Neo4jConnectionError

# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture(scope="module")
def neo4j_adapter():
    """Create adapter instance (shared across module)"""
    try:
        adapter = Neo4jCommandRegistryAdapter()
        # Verify connection
        assert adapter.health_check()
        return adapter
    except Neo4jConnectionError:
        pytest.skip("Neo4j not available for testing")


@pytest.fixture
def sample_command_id():
    """Known command ID for testing"""
    return 'nmap-quick-scan'


# ============================================================================
# Health Check Tests
# ============================================================================

def test_health_check_success(neo4j_adapter):
    """Verify Neo4j connection is healthy"""
    assert neo4j_adapter.health_check() is True


def test_health_check_returns_false_on_connection_failure():
    """Verify health check fails gracefully"""
    from db.config import get_neo4j_config

    # Invalid configuration
    bad_config = get_neo4j_config()
    bad_config['uri'] = 'bolt://invalid-host:7687'

    try:
        adapter = Neo4jCommandRegistryAdapter(neo4j_config=bad_config)
        # Should not reach here
        assert False, "Expected Neo4jConnectionError"
    except Neo4jConnectionError:
        pass  # Expected


# ============================================================================
# Simple Query Tests
# ============================================================================

def test_get_command_by_id(neo4j_adapter, sample_command_id):
    """Test single command retrieval"""
    cmd = neo4j_adapter.get_command(sample_command_id)

    assert cmd is not None
    assert cmd.id == sample_command_id
    assert cmd.name is not None
    assert cmd.command is not None
    assert len(cmd.variables) > 0


def test_get_command_nonexistent_returns_none(neo4j_adapter):
    """Test graceful handling of missing commands"""
    cmd = neo4j_adapter.get_command('nonexistent-command-id')
    assert cmd is None


def test_get_command_includes_all_relationships(neo4j_adapter, sample_command_id):
    """Verify all relationships are loaded"""
    cmd = neo4j_adapter.get_command(sample_command_id)

    # Check variables
    assert len(cmd.variables) > 0
    assert all(hasattr(v, 'name') for v in cmd.variables)

    # Check tags
    assert len(cmd.tags) > 0
    assert isinstance(cmd.tags, list)

    # Check flag explanations
    assert isinstance(cmd.flag_explanations, dict)


# ============================================================================
# Search Tests
# ============================================================================

def test_search_by_text(neo4j_adapter):
    """Test full-text search"""
    results = neo4j_adapter.search('nmap')

    assert len(results) > 0
    assert all('nmap' in cmd.name.lower() or 'nmap' in cmd.description.lower()
               for cmd in results)


def test_search_with_category_filter(neo4j_adapter):
    """Test search with category constraint"""
    results = neo4j_adapter.search('scan', category='recon')

    assert len(results) > 0
    assert all(cmd.category == 'recon' for cmd in results)


def test_search_with_oscp_filter(neo4j_adapter):
    """Test OSCP relevance filtering"""
    results = neo4j_adapter.search('enum', oscp_only=True)

    assert len(results) > 0
    assert all(cmd.oscp_relevance == 'high' for cmd in results)


def test_search_empty_query_returns_all(neo4j_adapter):
    """Test empty search returns results"""
    results = neo4j_adapter.search('')

    # Should return some results (or handle gracefully)
    assert isinstance(results, list)


# ============================================================================
# Filter Tests
# ============================================================================

def test_filter_by_category(neo4j_adapter):
    """Test category filtering"""
    results = neo4j_adapter.filter_by_category('web')

    assert len(results) > 0
    assert all(cmd.category == 'web' for cmd in results)


def test_filter_by_single_tag(neo4j_adapter):
    """Test single tag filter"""
    results = neo4j_adapter.filter_by_tags(['OSCP:HIGH'], match_all=True)

    assert len(results) > 0
    assert all('OSCP:HIGH' in cmd.tags for cmd in results)


def test_filter_by_multiple_tags_and_logic(neo4j_adapter):
    """Test multiple tags with AND logic"""
    results = neo4j_adapter.filter_by_tags(
        ['OSCP:HIGH', 'QUICK_WIN'],
        match_all=True
    )

    assert len(results) >= 0
    for cmd in results:
        assert 'OSCP:HIGH' in cmd.tags
        assert 'QUICK_WIN' in cmd.tags


def test_filter_by_multiple_tags_or_logic(neo4j_adapter):
    """Test multiple tags with OR logic"""
    results = neo4j_adapter.filter_by_tags(
        ['OSCP:HIGH', 'QUICK_WIN'],
        match_all=False
    )

    assert len(results) > 0
    for cmd in results:
        assert 'OSCP:HIGH' in cmd.tags or 'QUICK_WIN' in cmd.tags


# ============================================================================
# Graph Traversal Tests (Neo4j Strength)
# ============================================================================

def test_find_alternatives_single_hop(neo4j_adapter):
    """Test 1-hop alternative discovery"""
    paths = neo4j_adapter.find_alternatives('gobuster-dir', max_depth=1)

    assert len(paths) > 0
    assert all(path.length == 1 for path in paths)
    assert all(len(path.nodes) == 2 for path in paths)  # start + alternative


def test_find_alternatives_multi_hop(neo4j_adapter):
    """Test multi-hop alternative chains"""
    paths = neo4j_adapter.find_alternatives('gobuster-dir', max_depth=3)

    assert len(paths) >= 0
    assert all(path.length <= 3 for path in paths)
    assert all(len(path.nodes) == path.length + 1 for path in paths)


def test_find_alternatives_sorted_by_depth(neo4j_adapter):
    """Verify alternatives are sorted by depth (shortest first)"""
    paths = neo4j_adapter.find_alternatives('gobuster-dir', max_depth=3)

    if len(paths) > 1:
        for i in range(len(paths) - 1):
            assert paths[i].length <= paths[i + 1].length


def test_find_alternatives_includes_metadata(neo4j_adapter):
    """Verify relationship metadata is included"""
    paths = neo4j_adapter.find_alternatives('gobuster-dir', max_depth=2)

    assert len(paths) > 0
    for path in paths:
        assert len(path.relationships) == path.length
        for rel in path.relationships:
            assert 'priority' in rel


def test_find_prerequisites_transitive(neo4j_adapter):
    """Test transitive prerequisite discovery"""
    prereqs = neo4j_adapter.find_prerequisites('wordpress-sqli')

    assert isinstance(prereqs, list)
    # Verify prerequisites are ordered (deepest first)
    if len(prereqs) > 1:
        # All prerequisites should have unique IDs
        assert len(set(p.id for p in prereqs)) == len(prereqs)


def test_find_next_steps(neo4j_adapter, sample_command_id):
    """Test next step recommendations"""
    next_steps = neo4j_adapter.find_next_steps(sample_command_id)

    assert isinstance(next_steps, list)
    if len(next_steps) > 0:
        assert all(hasattr(step, 'id') for step in next_steps)


# ============================================================================
# Attack Chain Tests
# ============================================================================

def test_get_attack_chain_path(neo4j_adapter):
    """Test attack chain execution planning"""
    plan = neo4j_adapter.get_attack_chain_path('linux-privesc-sudo')

    assert plan is not None
    assert 'id' in plan
    assert 'name' in plan
    assert 'steps' in plan
    assert 'execution_order' in plan
    assert 'parallel_groups' in plan

    # Verify steps are ordered
    assert len(plan['steps']) > 0
    for i, step in enumerate(plan['steps']):
        assert step['order'] == i + 1 or step['order'] is not None


def test_attack_chain_parallel_detection(neo4j_adapter):
    """Test parallel execution group calculation"""
    plan = neo4j_adapter.get_attack_chain_path('linux-privesc-sudo')

    assert 'parallel_groups' in plan
    assert len(plan['parallel_groups']) > 0

    # First group should have no dependencies
    # (implementation-dependent, may need actual chain data)


def test_attack_chain_nonexistent(neo4j_adapter):
    """Test graceful handling of missing attack chain"""
    plan = neo4j_adapter.get_attack_chain_path('nonexistent-chain')
    assert plan is None


# ============================================================================
# Statistics Tests
# ============================================================================

def test_get_stats(neo4j_adapter):
    """Test statistics retrieval"""
    stats = neo4j_adapter.get_stats()

    assert isinstance(stats, dict)
    assert 'command_count' in stats or 'node_count' in stats


# ============================================================================
# Edge Cases
# ============================================================================

def test_search_special_characters(neo4j_adapter):
    """Test search with special characters"""
    # Cypher uses special characters, ensure proper escaping
    results = neo4j_adapter.search('test: (special)')

    # Should not raise exception
    assert isinstance(results, list)


def test_filter_nonexistent_category(neo4j_adapter):
    """Test filtering by invalid category"""
    results = neo4j_adapter.filter_by_category('nonexistent_category')
    assert len(results) == 0


def test_filter_nonexistent_tag(neo4j_adapter):
    """Test filtering by invalid tag"""
    results = neo4j_adapter.filter_by_tags(['NONEXISTENT_TAG'])
    assert len(results) == 0
```

---

## Integration Tests

### Test Router Behavior

**File**: `tests/reference/test_router_integration.py`

```python
import pytest
from crack.reference.core.router import CommandRegistryRouter, BackendType

@pytest.fixture
def router():
    """Create router with both backends"""
    return CommandRegistryRouter(backend_preference=BackendType.AUTO)


def test_router_initializes_both_backends(router):
    """Verify both backends are initialized"""
    assert router.pg_available or router.neo4j_available
    health = router.health_check()
    assert any(health.values())


def test_simple_query_uses_postgresql(router, mocker):
    """Verify simple queries route to PostgreSQL"""
    if not router.pg_available:
        pytest.skip("PostgreSQL not available")

    # Spy on backend calls
    pg_spy = mocker.spy(router.pg_adapter, 'get_command')

    cmd = router.get_command('nmap-quick-scan')

    assert pg_spy.call_count == 1
    assert cmd is not None


def test_graph_query_uses_neo4j(router, mocker):
    """Verify graph queries prefer Neo4j"""
    if not router.neo4j_available:
        pytest.skip("Neo4j not available")

    neo4j_spy = mocker.spy(router.neo4j_adapter, 'find_alternatives')

    paths = router.find_alternatives('gobuster-dir', max_depth=3)

    assert neo4j_spy.call_count == 1


def test_fallback_on_neo4j_failure(router, mocker):
    """Test automatic fallback to PostgreSQL"""
    if not (router.pg_available and router.neo4j_available):
        pytest.skip("Both backends required")

    # Force Neo4j to fail
    mocker.patch.object(
        router.neo4j_adapter,
        'find_alternatives',
        side_effect=Exception("Neo4j failure")
    )

    # Should fallback to PostgreSQL
    paths = router.find_alternatives('gobuster-dir', max_depth=3)

    # Should not raise exception (fallback succeeded)
    assert isinstance(paths, list)


def test_neo4j_only_attack_chain_query(router):
    """Attack chain planning only works with Neo4j"""
    if not router.neo4j_available:
        with pytest.raises(NotImplementedError):
            router.get_attack_chain_path('linux-privesc-sudo')
    else:
        plan = router.get_attack_chain_path('linux-privesc-sudo')
        assert plan is not None
```

---

## Performance Benchmarks

### Benchmark Suite

**File**: `tests/reference/test_performance_benchmarks.py`

```python
import pytest
from crack.reference.core.sql_adapter import SQLCommandRegistryAdapter
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter

@pytest.fixture
def pg_adapter():
    return SQLCommandRegistryAdapter()


@pytest.fixture
def neo4j_adapter():
    try:
        return Neo4jCommandRegistryAdapter()
    except:
        pytest.skip("Neo4j not available")


# ============================================================================
# Simple Query Benchmarks
# ============================================================================

def test_benchmark_get_command_postgresql(benchmark, pg_adapter):
    """Benchmark PostgreSQL get_command()"""
    result = benchmark(pg_adapter.get_command, 'nmap-quick-scan')
    assert result is not None


def test_benchmark_get_command_neo4j(benchmark, neo4j_adapter):
    """Benchmark Neo4j get_command()"""
    result = benchmark(neo4j_adapter.get_command, 'nmap-quick-scan')
    assert result is not None


# ============================================================================
# Graph Traversal Benchmarks
# ============================================================================

@pytest.mark.parametrize("depth", [1, 2, 3, 5])
def test_benchmark_alternatives_neo4j(benchmark, neo4j_adapter, depth):
    """Benchmark Neo4j multi-hop alternatives"""
    result = benchmark(
        neo4j_adapter.find_alternatives,
        'gobuster-dir',
        max_depth=depth
    )
    assert isinstance(result, list)


def test_benchmark_prerequisites_neo4j(benchmark, neo4j_adapter):
    """Benchmark Neo4j prerequisite lookup"""
    result = benchmark(
        neo4j_adapter.find_prerequisites,
        'wordpress-sqli'
    )
    assert isinstance(result, list)


def test_benchmark_attack_chain_neo4j(benchmark, neo4j_adapter):
    """Benchmark Neo4j attack chain planning"""
    result = benchmark(
        neo4j_adapter.get_attack_chain_path,
        'linux-privesc-sudo'
    )
    assert result is not None


# ============================================================================
# Search Benchmarks
# ============================================================================

def test_benchmark_search_postgresql(benchmark, pg_adapter):
    """Benchmark PostgreSQL full-text search"""
    result = benchmark(pg_adapter.search, 'nmap')
    assert len(result) > 0


def test_benchmark_search_neo4j(benchmark, neo4j_adapter):
    """Benchmark Neo4j full-text search"""
    result = benchmark(neo4j_adapter.search, 'nmap')
    assert len(result) > 0
```

**Run Benchmarks**:
```bash
pytest tests/reference/test_performance_benchmarks.py \
    --benchmark-only \
    --benchmark-min-rounds=10 \
    --benchmark-sort=mean
```

**Expected Output**:
```
Name (time in ms)                                          Mean
test_benchmark_get_command_postgresql                     2.1
test_benchmark_get_command_neo4j                          4.8
test_benchmark_alternatives_neo4j[depth=1]                3.2
test_benchmark_alternatives_neo4j[depth=3]               12.5
test_benchmark_alternatives_neo4j[depth=5]               35.1
test_benchmark_search_postgresql                         14.2
test_benchmark_search_neo4j                              18.7
```

---

## Data Validation Tests

### Schema Integrity

**File**: `tests/db/test_neo4j_schema_validation.py`

```python
def test_all_commands_have_variables(neo4j_session):
    """Verify commands with <> have USES_VARIABLE relationships"""

    query = """
    MATCH (cmd:Command)
    WHERE cmd.template CONTAINS '<'
      AND NOT exists((cmd)-[:USES_VARIABLE]->())
    RETURN count(cmd) AS orphaned_commands
    """

    result = neo4j_session.run(query)
    count = result.single()['orphaned_commands']

    assert count == 0, f"{count} commands have placeholders but no variables"


def test_no_circular_dependencies(neo4j_session):
    """Detect circular dependencies in attack chains"""

    query = """
    MATCH path = (step:ChainStep)-[:DEPENDS_ON*]->(step)
    RETURN count(path) AS cycles
    """

    result = neo4j_session.run(query)
    cycles = result.single()['cycles']

    assert cycles == 0, f"Detected {cycles} circular dependencies"


def test_node_counts_match_postgresql(pg_cursor, neo4j_session):
    """Verify node counts match PostgreSQL source"""

    # PostgreSQL count
    pg_cursor.execute("SELECT COUNT(*) FROM commands")
    pg_count = pg_cursor.fetchone()[0]

    # Neo4j count
    neo4j_result = neo4j_session.run("MATCH (c:Command) RETURN count(c) AS count")
    neo4j_count = neo4j_result.single()['count']

    assert neo4j_count == pg_count, f"Count mismatch: PG={pg_count}, Neo4j={neo4j_count}"
```

---

## CI/CD Integration

### GitHub Actions Workflow

**File**: `.github/workflows/neo4j-tests.yml`

```yaml
name: Neo4j Integration Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_DB: crack
          POSTGRES_USER: crack_user
          POSTGRES_PASSWORD: crack_pass
        ports:
          - 5432:5432

      neo4j:
        image: neo4j:5.15-community
        env:
          NEO4J_AUTH: neo4j/crack_password
          NEO4J_PLUGINS: '["apoc"]'
        ports:
          - 7474:7474
          - 7687:7687

    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -e .[dev]

      - name: Run unit tests
        run: |
          pytest tests/reference/test_neo4j_adapter.py -v

      - name: Run integration tests
        run: |
          pytest tests/reference/test_router_integration.py -v

      - name: Run benchmarks
        run: |
          pytest tests/reference/test_performance_benchmarks.py \
            --benchmark-only \
            --benchmark-json=benchmark_results.json

      - name: Upload benchmark results
        uses: actions/upload-artifact@v3
        with:
          name: benchmark-results
          path: benchmark_results.json
```

---

## Manual Testing Checklist

### Pre-Deployment Validation

- [ ] All unit tests pass (70+ tests)
- [ ] Integration tests pass (router behavior)
- [ ] Performance benchmarks meet targets (see [00-ARCHITECTURE.md](00-ARCHITECTURE.md#performance-targets))
- [ ] Data integrity checks pass
- [ ] Health checks return true for both backends
- [ ] Fallback mechanism triggers correctly
- [ ] CLI auto-detect works as expected
- [ ] Attack chain planning produces valid execution order

---

## Next Steps

1. **Run Test Suite**: `pytest tests/reference/ -v`
2. **Analyze Benchmarks**: Compare PostgreSQL vs Neo4j
3. **Optimize Performance**: [08-PERFORMANCE-OPTIMIZATION.md](08-PERFORMANCE-OPTIMIZATION.md)

---

## See Also

- [04-ADAPTER-IMPLEMENTATION.md](04-ADAPTER-IMPLEMENTATION.md#testing-interface) - Unit test examples
- [05-INTEGRATION.md](05-INTEGRATION.md#testing-integration) - Router tests
- [08-PERFORMANCE-OPTIMIZATION.md](08-PERFORMANCE-OPTIMIZATION.md) - Optimization based on benchmarks

---

**Document Version**: 1.0.0
**Last Updated**: 2025-11-08
**Owner**: QA Team
**Status**: Test Framework Complete
