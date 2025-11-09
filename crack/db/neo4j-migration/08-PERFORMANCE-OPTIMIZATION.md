# 08 - Performance Optimization: Tuning and Best Practices

## Prerequisites
- [02-SCHEMA-DESIGN.md](02-SCHEMA-DESIGN.md) - Schema structure
- [07-TESTING-STRATEGY.md](07-TESTING-STRATEGY.md) - Performance benchmarks

## Overview

Performance tuning guide for Neo4j integration including indexing strategies, query optimization, caching, and resource management.

---

## Indexing Strategy

### Essential Indexes

**Purpose**: Speed up node lookups and relationship traversals

#### 1. Unique Constraints (Enforce + Index)

```cypher
// Command ID (primary key)
CREATE CONSTRAINT command_id_unique IF NOT EXISTS
  FOR (c:Command) REQUIRE c.id IS UNIQUE;

// Creates implicit index on id property
// Lookup time: O(1) instead of O(n)
```

**Performance Impact**:
- Before: Full node scan (1247 nodes = ~500ms)
- After: Index lookup (~2ms)

---

#### 2. Property Indexes

```cypher
// Category filtering
CREATE INDEX command_category IF NOT EXISTS
  FOR (c:Command) ON (c.category);

// OSCP relevance (frequently queried)
CREATE INDEX command_oscp IF NOT EXISTS
  FOR (c:Command) ON (c.oscp_relevance);

// Tag category
CREATE INDEX tag_category IF NOT EXISTS
  FOR (t:Tag) ON (t.category);

// Attack chain category
CREATE INDEX chain_category IF NOT EXISTS
  FOR (ac:AttackChain) ON (ac.category);
```

**Usage**:
```cypher
// Query automatically uses index
MATCH (c:Command)
WHERE c.category = 'web' AND c.oscp_relevance = 'high'
RETURN c
// Index hit rate: 100%
```

---

#### 3. Full-Text Search Indexes

```cypher
// Command name and description search
CREATE FULLTEXT INDEX command_search IF NOT EXISTS
  FOR (c:Command)
  ON EACH [c.name, c.description, c.notes];

// Tag search
CREATE FULLTEXT INDEX tag_search IF NOT EXISTS
  FOR (t:Tag)
  ON EACH [t.name, t.description];
```

**Usage**:
```cypher
// Full-text search
CALL db.index.fulltext.queryNodes("command_search", "nmap port scan")
YIELD node, score
RETURN node.name, score
ORDER BY score DESC
LIMIT 10
```

**Performance Comparison**:
| Search Method | Time (1247 commands) | Accuracy |
|--------------|---------------------|----------|
| CONTAINS filter | 250ms | Exact match only |
| Regex match | 450ms | Flexible, slow |
| Full-text index | **15ms** | Ranked by relevance |

---

#### 4. Composite Indexes

```cypher
// Multi-property queries
CREATE INDEX command_category_oscp IF NOT EXISTS
  FOR (c:Command) ON (c.category, c.oscp_relevance);
```

**Use Case**:
```cypher
// Both properties in WHERE clause
MATCH (c:Command)
WHERE c.category = 'web' AND c.oscp_relevance = 'high'
RETURN c
// Uses composite index (faster than single-property)
```

---

### Index Maintenance

#### Check Index Usage

```cypher
// View all indexes
SHOW INDEXES

// Get index statistics
CALL db.indexes() YIELD name, type, state, populationPercent
RETURN name, type, state, populationPercent
ORDER BY name
```

#### Rebuild Stale Indexes

```cypher
// Drop and recreate if population < 100%
DROP INDEX command_name_fulltext
CREATE FULLTEXT INDEX command_name_fulltext
  FOR (c:Command) ON EACH [c.name, c.description]
```

---

## Query Optimization

### Pattern 1: Use LIMIT Early

```cypher
// BAD: Filter after traversal
MATCH path = (start:Command)-[:NEXT_STEP*1..5]->(end)
WHERE end.oscp_relevance = 'high'
RETURN path
LIMIT 10
// Traverses ALL paths, then limits

// GOOD: Limit during traversal
MATCH path = (start:Command)-[:NEXT_STEP*1..5]->(end)
WHERE end.oscp_relevance = 'high'
WITH path LIMIT 10
RETURN path
// Stops after finding 10 paths
```

**Performance**: 10x+ faster for large graphs

---

### Pattern 2: Index Hints

```cypher
// Force index usage when planner doesn't auto-select
MATCH (c:Command)
USING INDEX c:Command(oscp_relevance)
WHERE c.oscp_relevance = 'high'
  AND c.category IN ['web', 'exploitation']
RETURN c
```

---

### Pattern 3: Profile Queries

```cypher
// Analyze query execution plan
PROFILE
MATCH (cmd:Command)-[:TAGGED]->(tag:Tag {name: 'OSCP:HIGH'})
RETURN cmd.name
```

**Output Analysis**:
- `DbHits`: Lower = better (index usage)
- `Rows`: Check cardinality estimates
- `EstimatedRows` vs `Rows`: Large mismatch = poor planner decision

---

### Pattern 4: Avoid Cartesian Products

```cypher
// BAD: Creates cartesian product (N * M rows)
MATCH (cmd:Command)
MATCH (tag:Tag)
WHERE cmd.id = 'nmap-quick-scan' AND tag.name = 'OSCP:HIGH'
CREATE (cmd)-[:TAGGED]->(tag)

// GOOD: Single MATCH pattern
MATCH (cmd:Command {id: 'nmap-quick-scan'})
MATCH (tag:Tag {name: 'OSCP:HIGH'})
CREATE (cmd)-[:TAGGED]->(tag)
// Or even better: single MATCH with relationship
MATCH (cmd:Command {id: 'nmap-quick-scan'})
MATCH (tag:Tag {name: 'OSCP:HIGH'})
MERGE (cmd)-[:TAGGED]->(tag)
```

---

### Pattern 5: Use DISTINCT Carefully

```cypher
// BAD: DISTINCT on large result set
MATCH (cmd:Command)-[:TAGGED]->(tag:Tag)
RETURN DISTINCT cmd.id, tag.name
// Must track all unique combinations in memory

// GOOD: Aggregate instead
MATCH (cmd:Command)-[:TAGGED]->(tag:Tag)
RETURN cmd.id, collect(tag.name) AS tags
// Single row per command
```

---

## Caching Strategy

### Level 1: Application-Level Cache (In-Memory)

**Implementation**: LRU cache in Python

```python
from functools import lru_cache

@lru_cache(maxsize=256)
def get_command_cached(command_id: str) -> Optional[Command]:
    """Cached command lookup"""
    return neo4j_adapter.get_command(command_id)

# Cache hit: ~0.1ms (vs 5ms Neo4j query)
```

**Cache Statistics**:
```python
get_command_cached.cache_info()
# CacheInfo(hits=1847, misses=123, maxsize=256, currsize=123)
# Hit rate: 93.7%
```

---

### Level 2: Redis Distributed Cache

**Configuration**:
```python
import redis
import pickle
from datetime import timedelta

class CachedNeo4jAdapter:
    def __init__(self):
        self.redis = redis.Redis(host='localhost', port=6379, db=0)
        self.neo4j = Neo4jCommandRegistryAdapter()

    def get_command(self, command_id: str) -> Optional[Command]:
        # Try cache
        cache_key = f"cmd:{command_id}"
        cached = self.redis.get(cache_key)

        if cached:
            return pickle.loads(cached)

        # Cache miss - query Neo4j
        command = self.neo4j.get_command(command_id)

        if command:
            # Cache for 1 hour
            self.redis.setex(
                cache_key,
                timedelta(hours=1),
                pickle.dumps(command)
            )

        return command
```

**Cache Invalidation**:
```python
def invalidate_command_cache(command_id: str):
    """Clear cache when command is updated"""
    redis_client.delete(f"cmd:{command_id}")
```

---

### Level 3: Neo4j Query Result Cache

**Enable in neo4j.conf**:
```properties
# Query result caching (enterprise feature)
dbms.query_cache_size=1000
```

**Alternative (Community Edition)**: Use `CALL apoc.periodic.iterate()`

```cypher
// Pre-warm cache with common queries
CALL apoc.periodic.iterate(
  "MATCH (c:Command) WHERE c.oscp_relevance = 'high' RETURN c",
  "WITH c RETURN c",
  {batchSize:100}
)
```

---

## Connection Pooling

### Driver Configuration

```python
from neo4j import GraphDatabase

driver = GraphDatabase.driver(
    "bolt://localhost:7687",
    auth=("neo4j", "crack_password"),

    # Connection pool settings
    max_connection_lifetime=3600,      # Close connections after 1 hour
    max_connection_pool_size=50,       # Max 50 concurrent connections
    connection_acquisition_timeout=60, # Wait up to 60s for connection
    connection_timeout=30,             # TCP connection timeout

    # Performance tuning
    fetch_size=1000,                   # Fetch 1000 records at a time
    encrypted=False,                   # Disable encryption for local (faster)
)
```

**Pooling Benefits**:
- Reuse connections (avoid TCP handshake overhead)
- Limit concurrent connections (prevent resource exhaustion)

---

## Memory Management

### Heap Size Configuration

**Docker Compose**:
```yaml
environment:
  # Initial heap: 512MB (start small)
  - NEO4J_dbms_memory_heap_initial__size=512m

  # Max heap: 2GB (for 1200+ commands)
  - NEO4J_dbms_memory_heap_max__size=2g

  # Page cache: 512MB (for relationship traversals)
  - NEO4J_dbms_memory_pagecache_size=512m
```

**Sizing Guidelines**:
| Node Count | Heap Min | Heap Max | Page Cache |
|------------|----------|----------|------------|
| <1,000 | 256MB | 512MB | 256MB |
| 1,000-10,000 | 512MB | 2GB | 512MB |
| 10,000-100,000 | 1GB | 4GB | 1GB |

---

### Batch Operations

**Avoid**:
```cypher
// BAD: 1000 individual transactions
UNWIND range(1, 1000) AS i
CREATE (c:Command {id: 'cmd-' + i})
// Creates 1000 separate write transactions
```

**Prefer**:
```cypher
// GOOD: Single transaction with batching
CALL apoc.periodic.iterate(
  "UNWIND range(1, 1000) AS i RETURN i",
  "CREATE (c:Command {id: 'cmd-' + i})",
  {batchSize: 100}
)
// Creates 10 transactions (100 nodes each)
```

---

## Monitoring and Profiling

### Query Logging

**Enable slow query log**:
```properties
# neo4j.conf
dbms.logs.query.enabled=true
dbms.logs.query.threshold=100ms
dbms.logs.query.parameter_logging_enabled=true
```

**Check logs**:
```bash
tail -f /var/lib/neo4j/logs/query.log
```

---

### Metrics Collection

**Cypher Query**:
```cypher
// Database statistics
CALL dbms.queryJmx("org.neo4j:*")
YIELD name, attributes
WHERE name CONTAINS "Primitive"
RETURN name, attributes.value AS value
```

**Python Monitoring**:
```python
def collect_metrics(driver):
    """Collect Neo4j performance metrics"""

    with driver.session() as session:
        # Node count by label
        result = session.run("""
            CALL db.labels() YIELD label
            CALL apoc.cypher.run('MATCH (n:' + label + ') RETURN count(n) AS count', {})
            YIELD value
            RETURN label, value.count AS count
        """)

        # Relationship count by type
        result = session.run("""
            CALL db.relationshipTypes() YIELD relationshipType
            CALL apoc.cypher.run('MATCH ()-[r:' + relationshipType + ']->() RETURN count(r) AS count', {})
            YIELD value
            RETURN relationshipType, value.count AS count
        """)

        return metrics
```

---

## Performance Targets

### Acceptance Criteria (from 00-ARCHITECTURE.md)

| Query Type | Target Time | Measurement |
|-----------|------------|-------------|
| get_command() | <5ms | 95th percentile |
| search() | <20ms | 95th percentile |
| find_alternatives(depth=1) | <5ms | Mean |
| find_alternatives(depth=3) | <15ms | Mean |
| find_alternatives(depth=5) | <40ms | Mean |
| find_prerequisites() | <10ms | Mean |
| get_attack_chain_path() | <30ms | Mean |

### Current Performance (Example)

**From benchmarks** (see 07-TESTING-STRATEGY.md):
```
Query                              | PostgreSQL | Neo4j | Improvement
-----------------------------------|------------|-------|-------------
get_command()                      | 2.1ms      | 4.8ms | -56% (acceptable)
search('nmap')                     | 14.2ms     | 18.7ms| -24% (acceptable)
find_alternatives(depth=1)         | 5.3ms      | 3.2ms | +40%
find_alternatives(depth=3)         | 487ms      | 12.5ms| +97% ⭐
find_alternatives(depth=5)         | 3.2s       | 35.1ms| +99% ⭐
get_attack_chain_path()            | N/A        | 28ms  | ∞ (new feature)
```

**Analysis**:
- ✅ Neo4j meets targets for graph queries
- ✅ PostgreSQL still faster for simple lookups (expected)
- ✅ Overall system latency <100ms (target: 95th percentile)

---

## Optimization Workflow

### 1. Identify Slow Queries

**Enable profiling**:
```cypher
PROFILE
MATCH (cmd:Command)-[:ALTERNATIVE*3]->(alt)
WHERE cmd.id = 'gobuster-dir'
RETURN alt
```

**Check metrics**:
- `db_hits`: >10,000 = inefficient
- `time`: >100ms = slow

---

### 2. Add Missing Indexes

```cypher
// If PROFILE shows NodeByLabelScan instead of NodeIndexSeek
CREATE INDEX missing_index IF NOT EXISTS
  FOR (c:Command) ON (c.property_name);
```

---

### 3. Rewrite Query

**Before**:
```cypher
MATCH (cmd:Command)
WHERE cmd.name =~ '.*nmap.*'  // Regex scan
RETURN cmd
```

**After**:
```cypher
CALL db.index.fulltext.queryNodes("command_search", "nmap")  // Index search
YIELD node
RETURN node
```

---

### 4. Validate Improvement

```bash
pytest tests/reference/test_performance_benchmarks.py::test_benchmark_search_neo4j \
    --benchmark-compare=before.json
```

---

## Troubleshooting

### Issue: Queries Timeout

**Symptoms**: Queries fail after 30 seconds

**Solution 1**: Increase transaction timeout
```python
driver = GraphDatabase.driver(
    uri,
    auth=auth,
    max_transaction_retry_time=300  # 5 minutes
)
```

**Solution 2**: Add `LIMIT` to query
```cypher
MATCH path = (start)-[:NEXT_STEP*1..10]->(end)
WITH path LIMIT 100  // Stop after 100 paths
RETURN path
```

---

### Issue: High Memory Usage

**Symptoms**: Java heap OutOfMemoryError

**Solution**: Reduce batch size or increase heap
```yaml
# docker-compose.yml
environment:
  - NEO4J_dbms_memory_heap_max__size=4g  # Increased from 2g
```

---

### Issue: Slow Writes

**Symptoms**: Import takes >5 minutes

**Solution**: Use `neo4j-admin import` instead of Cypher LOAD CSV
```bash
# 10x+ faster for bulk imports
neo4j-admin database import full \
    --nodes=Command=commands.csv \
    --relationships=PREREQUISITE=prerequisite.csv
```

---

## Best Practices Summary

### DO ✅

- Use indexes for all frequently queried properties
- Profile queries before optimization
- Batch write operations (100-1000 rows)
- Cache frequently accessed commands
- Use LIMIT early in traversals
- Monitor slow query logs

### DON'T ❌

- Create indexes on every property (overhead)
- Use regex when full-text index available
- Scan all nodes with `MATCH (n)`
- Create cartesian products
- Use DISTINCT on large result sets
- Ignore query execution plans

---

## Next Steps

1. **Apply Indexes**: Run index creation script
2. **Benchmark**: Compare before/after performance
3. **Monitor**: Enable slow query logging
4. **Iterate**: Profile → Optimize → Validate

---

## See Also

- [02-SCHEMA-DESIGN.md](02-SCHEMA-DESIGN.md#schema-creation-script) - Index definitions
- [07-TESTING-STRATEGY.md](07-TESTING-STRATEGY.md#performance-benchmarks) - Benchmark suite
- [Neo4j Performance Guide](https://neo4j.com/docs/operations-manual/current/performance/)

---

**Document Version**: 1.0.0
**Last Updated**: 2025-11-08
**Owner**: Performance Team
**Status**: Optimization Guide Complete
