# Phase 5: Neo4j Migration Test Suite

Comprehensive test suites for validating the Neo4j dual-backend integration.

## Test Files Created

### 1. `test_neo4j_adapter.py` - Unit Tests (35 tests)

Tests the `Neo4jCommandRegistryAdapter` implementation with API parity to `SQLCommandRegistryAdapter`.

**Test Classes:**
- `TestConnection` (5 tests) - Connection, initialization, health checks
- `TestBasicQueries` (6 tests) - CRUD operations, get_command, filters
- `TestSearch` (4 tests) - Full-text search functionality
- `TestTagFiltering` (3 tests) - Tag-based filtering
- `TestGraphTraversal` (6 tests) - Graph queries (Neo4j advantage)
- `TestHelperMethods` (3 tests) - Internal helper functions
- `TestStatistics` (3 tests) - Stats and metadata queries
- `TestEdgeCases` (3 tests) - Error handling, special characters
- `TestPerformance` (2 tests) - Performance benchmarks

**Key Features:**
- All methods from SQL adapter tested
- Graph traversal tests (find_alternatives, find_prerequisites)
- Attack chain path planning tests
- Graceful failure handling
- Performance validation

### 2. `test_router_integration.py` - Integration Tests (25 tests)

Tests the `CommandRegistryRouter` for backend selection, failover, and routing logic.

**Test Classes:**
- `TestRouterInitialization` (4 tests) - Router setup with different backends
- `TestBackendSelection` (6 tests) - Query routing logic
- `TestFailover` (5 tests) - Automatic failover between backends
- `TestHealthCheck` (3 tests) - Health monitoring
- `TestPerformance` (2 tests) - Performance comparison
- `TestAPICompatibility` (3 tests) - API parity validation
- `TestConcurrentAccess` (2 tests) - Thread safety

**Key Features:**
- Tests routing: simple queries → PostgreSQL, graph queries → Neo4j
- Validates fallback mechanism when backends fail
- Verifies transparent failover (no exceptions to user)
- Thread safety and concurrent access
- Health check reporting

### 3. `test_migration_validation.py` - Data Validation Tests (20 tests)

Validates data integrity and completeness after Neo4j migration.

**Test Classes:**
- `TestDataCompleteness` (5 tests) - All data migrated
- `TestRelationshipIntegrity` (5 tests) - Relationships correct
- `TestDataQuality` (5 tests) - Data meets quality standards
- `TestCrossBackendConsistency` (2 tests) - Neo4j ↔ SQL consistency
- `TestSchemaValidation` (3 tests) - Schema matches design

**Key Features:**
- Compares Neo4j vs SQL command counts
- Validates relationship integrity
- Checks for orphaned nodes
- Ensures no duplicate data
- Validates OSCP relevance values
- Cross-backend consistency checks

### 4. `conftest.py` - Shared Fixtures

Provides reusable fixtures for all test suites.

**Fixtures:**
- `neo4j_driver`, `neo4j_test_session` - Neo4j connections
- `sql_connection` - SQL database connections
- `config_manager`, `reference_theme` - Configuration objects
- `sample_command_data` - Test data samples
- `known_command_ids`, `known_categories`, `known_tags` - Expected data
- `mock_neo4j_adapter`, `mock_sql_adapter` - Mock objects for testing

## Running the Tests

### Prerequisites

```bash
# Install test dependencies
pip install pytest pytest-mock pytest-benchmark

# Ensure Neo4j is running
docker-compose up -d neo4j

# Ensure PostgreSQL is running
docker-compose up -d postgres
```

### Run All Phase 5 Tests

```bash
# Run all Neo4j-related tests
pytest tests/reference/test_neo4j_adapter.py \
       tests/reference/test_router_integration.py \
       tests/reference/test_migration_validation.py -v

# Total: 80 tests
```

### Run Specific Test Suites

```bash
# Unit tests only (Neo4j adapter)
pytest tests/reference/test_neo4j_adapter.py -v

# Integration tests only (Router)
pytest tests/reference/test_router_integration.py -v

# Validation tests only (Migration)
pytest tests/reference/test_migration_validation.py -v
```

### Run by Test Marker

```bash
# Run only Neo4j tests
pytest tests/reference/ -m neo4j -v

# Run only router tests
pytest tests/reference/ -m router -v

# Run only validation tests
pytest tests/reference/ -m validation -v

# Skip slow tests
pytest tests/reference/ -m "not slow" -v
```

### Run Specific Test Classes

```bash
# Test connection handling
pytest tests/reference/test_neo4j_adapter.py::TestConnection -v

# Test graph traversal (Neo4j advantage)
pytest tests/reference/test_neo4j_adapter.py::TestGraphTraversal -v

# Test failover mechanism
pytest tests/reference/test_router_integration.py::TestFailover -v

# Test data completeness
pytest tests/reference/test_migration_validation.py::TestDataCompleteness -v
```

### Run with Coverage

```bash
# Generate coverage report
pytest tests/reference/ --cov=crack.reference.core.neo4j_adapter \
                         --cov=crack.reference.core.router \
                         --cov-report=html \
                         --cov-report=term

# View coverage report
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
```

### Run Performance Benchmarks

```bash
# Run benchmark tests only
pytest tests/reference/ -m slow --benchmark-only

# Compare Neo4j vs SQL performance
pytest tests/reference/test_router_integration.py::TestPerformance::test_graph_query_faster_on_neo4j -v
```

## Expected Test Behavior

### When Neo4j is NOT Available

Tests that require Neo4j will automatically skip with message:
```
SKIPPED [1] Neo4j not available: connection refused
```

The router should fall back to SQL gracefully (failover tests).

### When SQL is NOT Available

Tests that require SQL will skip, but Neo4j-only tests will pass.
Router should use Neo4j exclusively.

### When Both Backends Are Available

All tests should pass. Router tests will validate:
- Simple queries routed to PostgreSQL
- Graph queries routed to Neo4j
- Failover works correctly

## Test Output Example

```
tests/reference/test_neo4j_adapter.py::TestConnection::test_health_check_success PASSED [1%]
tests/reference/test_neo4j_adapter.py::TestBasicQueries::test_get_command_exists PASSED [2%]
tests/reference/test_neo4j_adapter.py::TestGraphTraversal::test_find_alternatives_depth_3 PASSED [15%]
tests/reference/test_router_integration.py::TestBackendSelection::test_graph_query_uses_neo4j PASSED [45%]
tests/reference/test_migration_validation.py::TestDataCompleteness::test_all_commands_migrated PASSED [82%]

================================ 80 passed in 12.34s =================================
```

## Continuous Integration

These tests are designed to run in CI/CD pipelines:

```yaml
# .github/workflows/neo4j-tests.yml
- name: Run Phase 5 Tests
  run: |
    pytest tests/reference/test_neo4j_adapter.py \
           tests/reference/test_router_integration.py \
           tests/reference/test_migration_validation.py \
           --junitxml=test-results.xml \
           --cov-report=xml
```

## Debugging Failed Tests

### Enable Verbose Logging

```bash
pytest tests/reference/ -v -s --log-cli-level=DEBUG
```

### Run Single Test

```bash
pytest tests/reference/test_neo4j_adapter.py::TestConnection::test_health_check_success -v -s
```

### Inspect Test Fixtures

```bash
# Show fixtures available
pytest tests/reference/ --fixtures

# Show fixture setup/teardown
pytest tests/reference/ -v --setup-show
```

## Test Coverage Goals

- **Unit Tests (Neo4j Adapter)**: 95% code coverage
- **Integration Tests (Router)**: 90% code coverage
- **Validation Tests**: 100% of critical data checks

## Next Steps After Tests Pass

1. **Phase 3**: Implement `neo4j_adapter.py` based on test specifications
2. **Phase 4**: Implement `router.py` for backend selection
3. **Re-run tests**: Validate implementation against test suite
4. **Performance tuning**: Use benchmark results to optimize queries
5. **Documentation**: Update based on test results

## Test Maintenance

As the Neo4j implementation evolves:

1. Update test fixtures with new sample data
2. Add tests for new features (e.g., new graph queries)
3. Update expected values if schema changes
4. Keep cross-backend consistency tests aligned

## Known Issues / Expected Skips

- Full-text search index tests may skip if index not created yet
- Attack chain tests may skip if no chains migrated yet
- Performance tests are informational, not strict pass/fail

## Summary

- **Total Tests**: 80
- **Unit Tests**: 35 (Neo4j Adapter)
- **Integration Tests**: 25 (Router)
- **Validation Tests**: 20 (Migration)
- **Fixtures**: 20+ shared fixtures
- **Test Classes**: 21 classes
- **Status**: Ready to run (will skip if implementation not complete)
