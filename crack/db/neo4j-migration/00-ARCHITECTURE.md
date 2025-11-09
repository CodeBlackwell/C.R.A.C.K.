# 00 - Architecture: Dual Backend System Design

## Prerequisites
None - This is a foundational document

## Overview

This document defines the architectural approach for integrating Neo4j as a complementary graph database alongside PostgreSQL in the CRACK pentesting toolkit.

## Executive Summary

**Architecture Pattern**: Polyglot Persistence with Intelligent Routing
**Timeline**: 4-6 weeks
**Risk Level**: Medium (dual backend complexity, offset by fallback safety)

### Success Criteria
- [ ] Neo4j handles complex graph traversals (3+ hop relationships) 10x+ faster than PostgreSQL recursive CTEs
- [ ] PostgreSQL maintains role for CRUD operations and session history
- [ ] Zero breaking changes to existing `HybridCommandRegistry` API
- [ ] Graceful degradation: Neo4j unavailable → automatic PostgreSQL fallback

---

## Current Architecture Analysis

### Existing Database Stack

**PostgreSQL Schema** (db/schema.sql:1-424):
- 17 tables organized into 5 domains
- Normalized design optimized for data integrity
- Foreign key constraints enforce referential integrity

**Critical Tables**:
```
commands (1200+ rows)
  ├── command_flags (many-to-one)
  ├── command_vars (many-to-one)
  ├── command_tags (many-to-many)
  ├── command_relations (self-referential) ← GRAPH CANDIDATE
  └── command_indicators (one-to-many)

attack_chains (50+ chains)
  ├── chain_steps (300+ steps)
  └── step_dependencies (self-referential) ← GRAPH CANDIDATE

services (30+ services)
  ├── service_ports (many-to-many)
  └── service_commands (many-to-many) ← GRAPH CANDIDATE
```

**Reference**: [Current Schema](../schema.sql)

### Performance Bottlenecks Identified

1. **Command Relationship Traversal** (db/repositories/command_repository.py:156-238)
   - Current: 1-level JOIN queries only
   - Missing: Multi-hop alternative chains (if A fails → try B → try C)
   - PostgreSQL solution: Recursive CTEs (complex, slow at depth >5)

2. **Attack Chain Dependency Resolution**
   - Current: NOT IMPLEMENTED (AttackChainRepository is stub)
   - Required: Topological sort for execution order
   - Required: Parallel step detection (steps with no shared dependencies)

3. **Service-Based Attack Paths**
   - Current: Simple `services → service_commands → commands` (2 JOINs)
   - Needed: Multi-service conditional paths ("if HTTP + SMB both open → recommend attack chain X")
   - Needed: "Shortest path from nmap to root shell" queries

---

## Proposed Dual Backend Architecture

### Design Principles

1. **Separation of Concerns**
   - PostgreSQL: Data of Record (commands, sessions, history)
   - Neo4j: Relationship Intelligence (graph traversal, path finding)

2. **Backend Selection Strategy**

| Query Pattern | Backend | Rationale |
|--------------|---------|-----------|
| Get command by ID | PostgreSQL | Indexed lookup, O(1) |
| Search commands (text) | PostgreSQL | Full-text search mature |
| Filter by category/tags | PostgreSQL | Simple WHERE clauses |
| Session CRUD operations | PostgreSQL | ACID guarantees, backup maturity |
| **Find 3+ hop alternatives** | **Neo4j** | Graph traversal native |
| **Attack chain execution order** | **Neo4j** | Topological sort |
| **Shortest path queries** | **Neo4j** | Dijkstra/A* algorithms |
| **Find similar past sessions** | **Neo4j** | Pattern matching |

3. **Data Consistency Model**
   - **Command Data**: Single source of truth in PostgreSQL
   - **Graph Projections**: Materialized view in Neo4j (eventual consistency)
   - **Sync Strategy**: Daily batch sync (commands change infrequently)
   - **Session Data**: PostgreSQL only (Neo4j reads via queries, no writes)

---

## Component Architecture

### Layer Diagram

```
┌─────────────────────────────────────────────────────────┐
│              CLI / Track Module / Reference             │
│                  (User Interface Layer)                 │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│             CommandRegistryRouter                       │
│         (Intelligent Backend Selection)                 │
│                                                          │
│  route(query_type) →                                   │
│    if simple_lookup: PostgreSQL                        │
│    if graph_traversal: Neo4j (fallback → PostgreSQL)  │
└────────┬────────────────────────────────┬──────────────┘
         │                                 │
         ▼                                 ▼
┌──────────────────────┐      ┌──────────────────────────┐
│ SQLCommandRegistry   │      │ Neo4jCommandRegistry     │
│     Adapter          │      │     Adapter              │
│                      │      │                          │
│  - get_command()     │      │  - find_attack_path()    │
│  - search()          │      │  - get_alternatives()    │
│  - filter_*()        │      │  - resolve_dependencies()│
│  - CRUD operations   │      │  - find_similar_sessions()│
└──────────┬───────────┘      └───────────┬──────────────┘
           │                              │
           ▼                              ▼
    ┌─────────────┐              ┌──────────────┐
    │ PostgreSQL  │              │   Neo4j      │
    │   (CRUD)    │              │  (Graph)     │
    └─────────────┘              └──────────────┘
```

### Adapter Interface (API Parity Required)

**Base Interface** (must be implemented by both adapters):

```python
class CommandRegistryInterface:
    """Shared interface for all backend adapters"""

    # Simple Queries (PostgreSQL optimized)
    def get_command(self, command_id: str) -> Optional[Command]
    def search(self, query: str, **filters) -> List[Command]
    def filter_by_category(self, category: str) -> List[Command]
    def filter_by_tags(self, tags: List[str], match_all: bool) -> List[Command]
    def get_quick_wins(self) -> List[Command]
    def get_oscp_high(self) -> List[Command]

    # Graph Queries (Neo4j optimized)
    def find_alternatives(self, command_id: str, depth: int = 3) -> List[Path]
    def find_prerequisites(self, command_id: str) -> List[Command]
    def get_attack_chain_path(self, chain_id: str) -> ExecutionPlan
    def find_similar_sessions(self, session_id: int) -> List[Session]

    # Metadata
    def get_stats(self) -> Dict[str, Any]
    def health_check(self) -> bool
```

**Reference**: See [04-ADAPTER-IMPLEMENTATION.md](04-ADAPTER-IMPLEMENTATION.md#interface-design)

---

## Router Implementation Strategy

### Intelligent Query Routing

**File**: `reference/core/router.py` (NEW)

```python
class CommandRegistryRouter(CommandRegistryInterface):
    """Routes queries to optimal backend with fallback"""

    def __init__(self):
        self.pg_adapter = SQLCommandRegistryAdapter()
        try:
            self.neo4j_adapter = Neo4jCommandRegistryAdapter()
            self.neo4j_available = True
        except ConnectionError:
            self.neo4j_adapter = None
            self.neo4j_available = False

    def get_command(self, command_id: str) -> Optional[Command]:
        """Simple lookup → always PostgreSQL"""
        return self.pg_adapter.get_command(command_id)

    def find_alternatives(self, command_id: str, depth: int = 3) -> List[Path]:
        """Graph traversal → Neo4j with PostgreSQL fallback"""
        if self.neo4j_available and depth > 1:
            try:
                return self.neo4j_adapter.find_alternatives(command_id, depth)
            except Exception as e:
                logger.warning(f"Neo4j query failed: {e}, falling back to PostgreSQL")

        # Fallback: PostgreSQL with recursive CTE (slower)
        return self.pg_adapter.find_alternatives(command_id, depth)
```

**Reference**: See [05-INTEGRATION.md](05-INTEGRATION.md#router-implementation)

---

## Data Synchronization Strategy

### Command Data Sync (PostgreSQL → Neo4j)

**Trigger**: Daily cron job or manual `crack db sync-neo4j`

**Process**:
1. Export commands from PostgreSQL (JSON format)
2. Transform to Neo4j import format (CSV or Cypher)
3. Batch import nodes and relationships
4. Validate counts match

**Script**: `db/neo4j-migration/scripts/sync_to_neo4j.py`

```python
def sync_commands():
    """One-way sync: PostgreSQL → Neo4j"""

    # 1. Export from PostgreSQL
    commands = pg_repo.get_all_commands()

    # 2. Batch create/update nodes in Neo4j
    with neo4j_session() as session:
        session.write_transaction(batch_upsert_commands, commands)

    # 3. Rebuild relationships
    with neo4j_session() as session:
        session.write_transaction(rebuild_command_relations)

    # 4. Validate
    assert neo4j_count() == pg_count()
```

**Frequency**:
- Development: On-demand (after schema changes)
- Production: Daily at 2 AM UTC
- Exam Mode: Disabled (read-only Neo4j, no sync)

**Reference**: See [03-MIGRATION-SCRIPTS.md](03-MIGRATION-SCRIPTS.md#sync-strategy)

---

## Fallback and Fault Tolerance

### Graceful Degradation

**Scenario 1: Neo4j Unavailable at Startup**
```python
# reference/cli/main.py initialization
try:
    registry = CommandRegistryRouter()  # Tries Neo4j
except Neo4jConnectionError:
    logger.warning("Neo4j unavailable, using PostgreSQL only")
    registry = SQLCommandRegistryAdapter()  # Fallback
```

**Scenario 2: Neo4j Query Timeout**
```python
def find_alternatives(self, cmd_id, depth=3):
    try:
        result = self.neo4j_adapter.find_alternatives(cmd_id, depth)
        if not result:  # Empty result
            raise EmptyResultError()
        return result
    except (Timeout, Neo4jError, EmptyResultError):
        # Fallback to PostgreSQL recursive query
        return self.pg_adapter.find_alternatives_recursive(cmd_id, depth)
```

**Scenario 3: Data Inconsistency Detection**
```python
def get_command(self, cmd_id):
    pg_cmd = self.pg_adapter.get_command(cmd_id)

    if self.neo4j_available:
        neo4j_cmd = self.neo4j_adapter.get_command(cmd_id)
        if pg_cmd.updated_at > neo4j_cmd.updated_at:
            logger.warning(f"Neo4j stale for {cmd_id}, using PostgreSQL")

    return pg_cmd  # PostgreSQL is always source of truth
```

---

## Performance Targets

### Benchmark Goals

| Query Type | PostgreSQL (Current) | Neo4j (Target) | Improvement |
|-----------|---------------------|----------------|-------------|
| Get command by ID | 2ms | 5ms | -60% (acceptable) |
| Search by text | 15ms | 20ms | -25% (acceptable) |
| Filter by 2 tags | 8ms | 10ms | -20% (acceptable) |
| **1-hop alternatives** | 5ms | 3ms | +40% |
| **3-hop alternatives** | 450ms (recursive) | 12ms | **+97%** ⭐ |
| **5-hop alternatives** | 3200ms | 35ms | **+99%** ⭐ |
| **Attack chain deps** | Not implemented | 8ms | ∞ (new feature) |
| **Shortest attack path** | Not feasible | 25ms | ∞ (new feature) |

**Acceptance Criteria**:
- Neo4j must be 10x+ faster for depth ≥3 graph queries
- Neo4j must NOT be 2x+ slower for simple queries (caching mitigates)
- Overall system latency <100ms for 95th percentile

**Reference**: See [08-PERFORMANCE-OPTIMIZATION.md](08-PERFORMANCE-OPTIMIZATION.md#benchmarks)

---

## Implementation Phases

### Phase 1: Foundation (Week 1)
- [ ] Set up Neo4j Docker container
- [ ] Design graph schema (nodes, relationships)
- [ ] Create initial Cypher constraints/indexes
- [ ] Write data export script (PostgreSQL → JSON)

**Deliverables**:
- `docker-compose.yml` with Neo4j service
- `02-SCHEMA-DESIGN.md` completed
- `scripts/export_postgresql.py` working

**Reference**: [01-ENVIRONMENT.md](01-ENVIRONMENT.md), [02-SCHEMA-DESIGN.md](02-SCHEMA-DESIGN.md)

---

### Phase 2: Data Migration (Week 2)
- [ ] Transform PostgreSQL data to Neo4j import format
- [ ] Batch import 1200+ command nodes
- [ ] Create 3000+ relationship edges
- [ ] Validate data integrity (count checks)

**Deliverables**:
- `scripts/transform_to_neo4j.py`
- `scripts/import_to_neo4j.py`
- Migration validation report

**Reference**: [03-MIGRATION-SCRIPTS.md](03-MIGRATION-SCRIPTS.md)

---

### Phase 3: Adapter Development (Week 3)
- [ ] Create `Neo4jCommandRegistryAdapter` class
- [ ] Implement 14 core interface methods
- [ ] Add connection pooling and error handling
- [ ] Implement caching layer (Redis or in-memory)

**Deliverables**:
- `reference/core/neo4j_adapter.py` (400+ lines)
- Unit tests (14 test cases)

**Reference**: [04-ADAPTER-IMPLEMENTATION.md](04-ADAPTER-IMPLEMENTATION.md)

---

### Phase 4: Router Integration (Week 4)
- [ ] Create `CommandRegistryRouter` class
- [ ] Implement intelligent backend selection
- [ ] Update CLI auto-detect logic
- [ ] Add fallback mechanisms

**Deliverables**:
- `reference/core/router.py` (200+ lines)
- `reference/cli/main.py` updated
- Integration tests

**Reference**: [05-INTEGRATION.md](05-INTEGRATION.md)

---

### Phase 5: Advanced Features (Week 5)
- [ ] Implement recursive attack chain planning
- [ ] Add multi-hop alternative lookup
- [ ] Create service-based attack path finder
- [ ] Build tag taxonomy hierarchy

**Deliverables**:
- Advanced Cypher queries
- Attack path visualizer
- Feature documentation

**Reference**: [06-ADVANCED-QUERIES.md](06-ADVANCED-QUERIES.md)

---

### Phase 6: Testing & Optimization (Week 6)
- [ ] Performance benchmarks (Neo4j vs PostgreSQL)
- [ ] Load testing (1000+ concurrent queries)
- [ ] Index optimization
- [ ] Documentation finalization

**Deliverables**:
- Benchmark report
- Performance tuning guide
- Complete documentation

**Reference**: [07-TESTING-STRATEGY.md](07-TESTING-STRATEGY.md), [08-PERFORMANCE-OPTIMIZATION.md](08-PERFORMANCE-OPTIMIZATION.md)

---

## Risk Assessment

### High Risk Items

**1. API Compatibility Breaking Changes**
- **Risk**: Neo4j adapter doesn't match SQLCommandRegistryAdapter interface
- **Mitigation**: Unit tests enforcing interface parity, adapter base class
- **Owner**: Week 3 (Adapter Development)

**2. Performance Regression on Simple Queries**
- **Risk**: Router overhead slows down get_command() calls
- **Mitigation**: Benchmark-driven routing, direct PostgreSQL for simple queries
- **Owner**: Week 4 (Integration)

**3. Data Sync Failures**
- **Risk**: Neo4j graph becomes stale, inconsistent with PostgreSQL
- **Mitigation**: Health checks, version timestamps, fallback to PostgreSQL
- **Owner**: Week 2 (Migration Scripts)

### Medium Risk Items

**4. Neo4j Operational Complexity**
- **Risk**: Team unfamiliar with Cypher, deployment complexity
- **Mitigation**: Comprehensive docs, Docker Compose for easy setup
- **Owner**: Week 1 (Environment)

**5. Query Timeout on Large Graphs**
- **Risk**: 5-hop traversals timeout on 10,000+ node graphs
- **Mitigation**: Query complexity limits, pagination, index optimization
- **Owner**: Week 6 (Performance)

---

## Success Metrics

### Quantitative KPIs
- ✅ 10x+ speedup on 3+ hop graph queries
- ✅ Zero breaking changes to existing API
- ✅ 99.9% uptime with PostgreSQL fallback
- ✅ <5% performance regression on simple queries

### Qualitative Goals
- ✅ Enable new features (attack path finding, parallel step detection)
- ✅ Improve code maintainability (no complex recursive CTEs)
- ✅ Provide foundation for ML features (session similarity, technique correlation)

---

## See Also

- [01-ENVIRONMENT.md](01-ENVIRONMENT.md) - Docker setup, dependencies
- [02-SCHEMA-DESIGN.md](02-SCHEMA-DESIGN.md) - Neo4j graph model
- [04-ADAPTER-IMPLEMENTATION.md](04-ADAPTER-IMPLEMENTATION.md) - Python adapter code
- [05-INTEGRATION.md](05-INTEGRATION.md) - CLI integration
- [../schema.sql](../schema.sql) - Current PostgreSQL schema
- [../repositories/command_repository.py](../repositories/command_repository.py) - Current query patterns

---

## Implementation References

**Code Files** (to be created/modified):
- `reference/core/neo4j_adapter.py` - Neo4j adapter (NEW)
- `reference/core/router.py` - Routing logic (NEW)
- `reference/cli/main.py:52-114` - Auto-detect (MODIFY)
- `db/config.py` - Add Neo4j connection (MODIFY)
- `pyproject.toml:35` - Add neo4j dependency (MODIFY)

**Migration Files**:
- `db/neo4j-migration/scripts/export_postgresql.py`
- `db/neo4j-migration/scripts/transform_to_neo4j.py`
- `db/neo4j-migration/scripts/import_to_neo4j.py`
- `db/neo4j-migration/scripts/sync_to_neo4j.py`

---

**Document Version**: 1.0.0
**Last Updated**: 2025-11-08
**Owner**: Architecture Team
**Status**: Design Phase
