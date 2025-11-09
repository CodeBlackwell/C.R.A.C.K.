# 04 - Adapter Implementation: Neo4jCommandRegistryAdapter

## Prerequisites
- [00-ARCHITECTURE.md](00-ARCHITECTURE.md#adapter-interface) - Interface requirements
- [02-SCHEMA-DESIGN.md](02-SCHEMA-DESIGN.md) - Graph schema
- [03-MIGRATION-SCRIPTS.md](03-MIGRATION-SCRIPTS.md) - Data imported

## Overview

Complete specification for `Neo4jCommandRegistryAdapter` - the Python class that provides unified access to Neo4j graph database with API parity to `SQLCommandRegistryAdapter`.

---

## Interface Requirements

### API Compatibility Matrix

Must implement ALL methods from `reference/core/sql_adapter.py:152-325`:

| Method | PostgreSQL | Neo4j | Priority | Complexity |
|--------|-----------|-------|----------|------------|
| `get_command(id)` | ✅ Direct SELECT | ✅ MATCH by id | HIGH | Low |
| `search(query, **filters)` | ✅ Full-text | ✅ Fulltext index | HIGH | Medium |
| `filter_by_category(cat)` | ✅ WHERE clause | ✅ Label filter | HIGH | Low |
| `filter_by_tags(tags)` | ✅ JOIN + HAVING | ✅ Relationship pattern | HIGH | Medium |
| `get_quick_wins()` | ✅ Tag filter | ✅ Tag relationship | MEDIUM | Low |
| `get_oscp_high()` | ✅ Property filter | ✅ Property match | MEDIUM | Low |
| `find_alternatives(id, depth)` | ⚠️ Recursive CTE | ✅ **Graph traversal** | **CRITICAL** | **High** |
| `find_prerequisites(id)` | ⚠️ Recursive CTE | ✅ **Graph traversal** | **CRITICAL** | **High** |
| `find_next_steps(id)` | ✅ Single JOIN | ✅ Relationship match | MEDIUM | Low |
| `get_attack_chain_path(id)` | ❌ Not implemented | ✅ **NEW FEATURE** | **CRITICAL** | **High** |
| `interactive_fill(cmd)` | ✅ Prompt loop | ✅ Same | LOW | None (reuse) |
| `get_stats()` | ✅ COUNT queries | ✅ COUNT nodes | LOW | Low |
| `health_check()` | ✅ SELECT 1 | ✅ RETURN 1 | HIGH | Low |
| `add_command()` | ✅ INSERT | ❌ **Not supported** | N/A | N/A |

**Legend**:
- ✅ Fully supported
- ⚠️ Slow/complex
- ❌ Not implemented
- **Bold** = Neo4j advantage

---

## Class Structure

### File Location

**File**: `reference/core/neo4j_adapter.py` (NEW)

### Skeleton Implementation

```python
"""Neo4j adapter for command registry"""

from typing import List, Dict, Optional, Any
from dataclasses import dataclass
from neo4j import GraphDatabase, Session
from neo4j.exceptions import ServiceUnavailable, SessionExpired

from crack.reference.core import Command, CommandVariable, ConfigManager, ReferenceTheme
from db.config import get_neo4j_config


class Neo4jConnectionError(Exception):
    """Raised when Neo4j is unavailable"""
    pass


@dataclass
class Path:
    """Represents a graph path between commands"""
    nodes: List[Command]
    relationships: List[Dict[str, Any]]
    length: int


class Neo4jCommandRegistryAdapter:
    """
    Neo4j-backed implementation of CommandRegistryInterface

    Optimized for graph queries:
    - Multi-hop relationship traversal
    - Attack chain path finding
    - Alternative command discovery
    """

    def __init__(
        self,
        config_manager: Optional[ConfigManager] = None,
        theme: Optional[ReferenceTheme] = None,
        neo4j_config: Optional[Dict] = None
    ):
        self.config = config_manager or ConfigManager()
        self.theme = theme or ReferenceTheme()

        # Neo4j connection
        neo4j_cfg = neo4j_config or get_neo4j_config()
        try:
            self.driver = GraphDatabase.driver(
                neo4j_cfg['uri'],
                auth=(neo4j_cfg['user'], neo4j_cfg['password']),
                max_connection_lifetime=neo4j_cfg.get('max_connection_lifetime', 3600),
                max_connection_pool_size=neo4j_cfg.get('max_connection_pool_size', 50)
            )
            self.database = neo4j_cfg.get('database', 'neo4j')

            # Test connection
            with self.driver.session(database=self.database) as session:
                session.run("RETURN 1")

        except Exception as e:
            raise Neo4jConnectionError(f"Failed to connect to Neo4j: {e}")

    def __del__(self):
        """Close driver on cleanup"""
        if hasattr(self, 'driver'):
            self.driver.close()

    # ========================================================================
    # Core Query Methods
    # ========================================================================

    def get_command(self, command_id: str) -> Optional[Command]:
        """Get single command by ID"""
        # Implementation in next section
        pass

    def search(
        self,
        query: str,
        category: Optional[str] = None,
        tags: Optional[List[str]] = None,
        oscp_only: bool = False
    ) -> List[Command]:
        """Full-text search with filters"""
        # Implementation in next section
        pass

    def filter_by_category(self, category: str) -> List[Command]:
        """Get all commands in category"""
        # Implementation in next section
        pass

    def filter_by_tags(
        self,
        tags: List[str],
        match_all: bool = True
    ) -> List[Command]:
        """Filter by tags (AND or OR logic)"""
        # Implementation in next section
        pass

    # ========================================================================
    # Graph Traversal Methods (Neo4j Advantage)
    # ========================================================================

    def find_alternatives(
        self,
        command_id: str,
        max_depth: int = 3
    ) -> List[Path]:
        """Find multi-hop alternative command chains"""
        # Implementation in next section
        pass

    def find_prerequisites(self, command_id: str) -> List[Command]:
        """Get all prerequisite commands (transitive closure)"""
        # Implementation in next section
        pass

    def find_next_steps(self, command_id: str) -> List[Command]:
        """Get recommended next commands"""
        # Implementation in next section
        pass

    def get_attack_chain_path(self, chain_id: str) -> Dict[str, Any]:
        """Get attack chain execution plan with dependencies"""
        # Implementation in next section
        pass

    # ========================================================================
    # Helper Methods
    # ========================================================================

    def _record_to_command(self, record) -> Command:
        """Convert Neo4j record to Command dataclass"""
        # Implementation in next section
        pass

    def _execute_read(self, query: str, **params) -> List:
        """Execute read query with error handling"""
        with self.driver.session(database=self.database) as session:
            return session.read_transaction(
                lambda tx: list(tx.run(query, **params))
            )

    def health_check(self) -> bool:
        """Test Neo4j connectivity"""
        try:
            with self.driver.session(database=self.database) as session:
                result = session.run("RETURN 1 AS test")
                return result.single()['test'] == 1
        except:
            return False
```

---

## Method Implementations

### 1. get_command() - Simple Node Lookup

**Cypher Query**:
```cypher
MATCH (cmd:Command {id: $command_id})
OPTIONAL MATCH (cmd)-[:USES_VARIABLE]->(var:Variable)
OPTIONAL MATCH (cmd)-[:TAGGED]->(tag:Tag)
OPTIONAL MATCH (cmd)-[:HAS_FLAG]->(flag:Flag)
RETURN
    cmd,
    collect(DISTINCT var) AS variables,
    collect(DISTINCT tag.name) AS tags,
    collect(DISTINCT {flag: flag.flag, explanation: flag.explanation}) AS flags
```

**Python Implementation**:
```python
def get_command(self, command_id: str) -> Optional[Command]:
    """Get single command with all relationships"""

    query = """
    MATCH (cmd:Command {id: $command_id})
    OPTIONAL MATCH (cmd)-[uv:USES_VARIABLE]->(var:Variable)
    OPTIONAL MATCH (cmd)-[:TAGGED]->(tag:Tag)
    OPTIONAL MATCH (cmd)-[:HAS_FLAG]->(flag:Flag)
    OPTIONAL MATCH (cmd)-[sp:SUCCESS_PATTERN]->(success:Indicator)
    OPTIONAL MATCH (cmd)-[fp:FAILURE_PATTERN]->(failure:Indicator)
    RETURN
        cmd,
        collect(DISTINCT {
            name: var.name,
            description: var.description,
            example: COALESCE(uv.example, var.default_value),
            required: uv.required
        }) AS variables,
        collect(DISTINCT tag.name) AS tags,
        collect(DISTINCT {flag: flag.flag, explanation: flag.explanation}) AS flags,
        collect(DISTINCT success.pattern) AS success_indicators,
        collect(DISTINCT failure.pattern) AS failure_indicators
    """

    result = self._execute_read(query, command_id=command_id)

    if not result:
        return None

    record = result[0]
    return self._record_to_command(record)


def _record_to_command(self, record) -> Command:
    """Convert Neo4j record to Command dataclass"""

    cmd_node = record['cmd']
    variables = [
        CommandVariable(
            name=v['name'],
            description=v['description'],
            example=v['example'],
            required=v['required']
        )
        for v in record['variables']
        if v['name']  # Filter out null variables from OPTIONAL MATCH
    ]

    flag_explanations = {
        f['flag']: f['explanation']
        for f in record['flags']
        if f['flag']
    }

    return Command(
        id=cmd_node['id'],
        name=cmd_node['name'],
        command=cmd_node['template'],
        description=cmd_node['description'],
        category=cmd_node['category'],
        subcategory=cmd_node.get('subcategory', ''),
        tags=[t for t in record['tags'] if t],
        variables=variables,
        flag_explanations=flag_explanations,
        success_indicators=[s for s in record['success_indicators'] if s],
        failure_indicators=[f for f in record['failure_indicators'] if f],
        oscp_relevance=cmd_node.get('oscp_relevance', 'medium'),
        notes=cmd_node.get('notes', '')
    )
```

---

### 2. search() - Full-Text Search

**Cypher Query** (uses fulltext index):
```cypher
CALL db.index.fulltext.queryNodes("command_search", $search_query)
YIELD node, score
WHERE ($category IS NULL OR node.category = $category)
  AND ($oscp_only = false OR node.oscp_relevance = 'high')
RETURN node
ORDER BY score DESC
LIMIT 50
```

**Python Implementation**:
```python
def search(
    self,
    query: str,
    category: Optional[str] = None,
    tags: Optional[List[str]] = None,
    oscp_only: bool = False
) -> List[Command]:
    """Full-text search with optional filters"""

    # Escape special characters for Lucene query syntax
    escaped_query = query.replace(':', '\\:').replace('(', '\\(')

    cypher = """
    CALL db.index.fulltext.queryNodes("command_search", $search_query)
    YIELD node AS cmd, score
    WHERE ($category IS NULL OR cmd.category = $category)
      AND ($oscp_only = false OR cmd.oscp_relevance = 'high')
    """

    # Add tag filter if specified
    if tags:
        cypher += """
        AND ALL(tag IN $tags WHERE EXISTS {
            MATCH (cmd)-[:TAGGED]->(t:Tag {name: tag})
        })
        """

    cypher += """
    RETURN cmd
    ORDER BY score DESC
    LIMIT 50
    """

    results = self._execute_read(
        cypher,
        search_query=escaped_query,
        category=category,
        oscp_only=oscp_only,
        tags=tags or []
    )

    # For each result, fetch full command details
    commands = []
    for record in results:
        cmd_id = record['cmd']['id']
        cmd = self.get_command(cmd_id)
        if cmd:
            commands.append(cmd)

    return commands
```

---

### 3. find_alternatives() - Multi-Hop Graph Traversal

**Cypher Query** (variable-length path):
```cypher
MATCH path = (start:Command {id: $command_id})-[:ALTERNATIVE*1..$max_depth]->(alt:Command)
WITH path, alt, relationships(path) AS rels
RETURN
    alt,
    [rel IN rels | {priority: rel.priority, reason: rel.reason}] AS path_metadata,
    length(path) AS depth
ORDER BY depth ASC, rels[0].priority ASC
LIMIT 10
```

**Python Implementation**:
```python
def find_alternatives(
    self,
    command_id: str,
    max_depth: int = 3
) -> List[Path]:
    """
    Find alternative command chains

    Returns paths ordered by:
    1. Shortest path first (depth 1, then 2, then 3)
    2. Highest priority alternatives first
    """

    query = """
    MATCH path = (start:Command {id: $command_id})-[:ALTERNATIVE*1..$max_depth]->(alt:Command)
    WITH path, alt, relationships(path) AS rels
    RETURN
        [node IN nodes(path) | node.id] AS node_ids,
        [node IN nodes(path) | node.name] AS node_names,
        [rel IN rels | {priority: rel.priority, reason: rel.reason, condition: rel.condition}] AS edge_data,
        length(path) AS depth
    ORDER BY depth ASC, rels[0].priority ASC
    LIMIT 20
    """

    results = self._execute_read(
        query,
        command_id=command_id,
        max_depth=max_depth
    )

    paths = []
    for record in results:
        # Fetch full command objects for each node in path
        commands = [
            self.get_command(cmd_id)
            for cmd_id in record['node_ids']
        ]

        paths.append(Path(
            nodes=commands,
            relationships=record['edge_data'],
            length=record['depth']
        ))

    return paths
```

**Output Example**:
```python
paths = adapter.find_alternatives('gobuster-dir', max_depth=3)

# Path 1 (depth 1): gobuster-dir → ffuf-dir
# Path 2 (depth 2): gobuster-dir → ffuf-dir → wfuzz-dir
# Path 3 (depth 1): gobuster-dir → dirbuster-gui

for path in paths:
    print(f"Depth {path.length}: {' → '.join([c.name for c in path.nodes])}")
    for i, rel in enumerate(path.relationships):
        print(f"  Step {i+1}: Priority {rel['priority']}, Reason: {rel['reason']}")
```

---

### 4. find_prerequisites() - Transitive Closure

**Cypher Query**:
```cypher
MATCH (cmd:Command {id: $command_id})<-[:PREREQUISITE*]-(prereq:Command)
RETURN DISTINCT prereq, length(path) AS depth
ORDER BY depth DESC
```

**Python Implementation**:
```python
def find_prerequisites(self, command_id: str) -> List[Command]:
    """
    Get ALL prerequisites (transitive closure)

    Returns commands ordered by dependency depth (deepest first)
    Example:
        C requires B requires A
        Returns: [A, B] (run A first, then B, then C)
    """

    query = """
    MATCH path = (cmd:Command {id: $command_id})<-[:PREREQUISITE*]-(prereq:Command)
    WITH prereq, length(path) AS depth
    ORDER BY depth DESC
    RETURN DISTINCT prereq.id AS id, depth
    """

    results = self._execute_read(query, command_id=command_id)

    # Fetch full command objects
    prerequisites = []
    for record in results:
        cmd = self.get_command(record['id'])
        if cmd:
            prerequisites.append(cmd)

    return prerequisites
```

---

### 5. get_attack_chain_path() - Dependency Resolution

**Cypher Query** (complex topological sort):
```cypher
MATCH (chain:AttackChain {id: $chain_id})-[:HAS_STEP]->(step:ChainStep)
OPTIONAL MATCH (step)-[:DEPENDS_ON]->(dep:ChainStep)
OPTIONAL MATCH (step)-[:EXECUTES]->(cmd:Command)
WITH step, collect(dep.id) AS dependencies, cmd
RETURN
    step.id AS step_id,
    step.name AS step_name,
    step.step_order AS order,
    dependencies,
    cmd.id AS command_id,
    cmd.name AS command_name
ORDER BY step.step_order
```

**Python Implementation**:
```python
def get_attack_chain_path(self, chain_id: str) -> Dict[str, Any]:
    """
    Get attack chain execution plan

    Returns:
    {
        'id': 'linux-privesc-sudo',
        'name': 'Linux Privilege Escalation via Sudo',
        'steps': [
            {
                'id': 'check-sudo-privs',
                'name': 'Check Sudo Privileges',
                'order': 1,
                'command': Command(...),
                'dependencies': [],
                'can_run_parallel': False
            },
            ...
        ],
        'execution_order': ['check-sudo-privs', 'exploit-sudo', 'verify-root'],
        'parallel_groups': [[step1], [step2, step3], [step4]]
    }
    """

    query = """
    MATCH (chain:AttackChain {id: $chain_id})
    MATCH (chain)-[:HAS_STEP]->(step:ChainStep)
    OPTIONAL MATCH (step)-[:DEPENDS_ON]->(dep:ChainStep)
    OPTIONAL MATCH (step)-[:EXECUTES]->(cmd:Command)
    WITH chain, step, collect(DISTINCT dep.id) AS dependencies, cmd
    RETURN
        chain.name AS chain_name,
        chain.description AS chain_description,
        collect({
            id: step.id,
            name: step.name,
            order: step.step_order,
            objective: step.objective,
            command_id: cmd.id,
            dependencies: dependencies
        }) AS steps
    """

    result = self._execute_read(query, chain_id=chain_id)

    if not result:
        return None

    record = result[0]
    steps_data = record['steps']

    # Enrich with full command objects
    steps = []
    for step_data in steps_data:
        command = None
        if step_data['command_id']:
            command = self.get_command(step_data['command_id'])

        steps.append({
            'id': step_data['id'],
            'name': step_data['name'],
            'order': step_data['order'],
            'objective': step_data['objective'],
            'command': command,
            'dependencies': step_data['dependencies']
        })

    # Calculate parallel execution groups
    parallel_groups = self._calculate_parallel_groups(steps)

    return {
        'id': chain_id,
        'name': record['chain_name'],
        'description': record['chain_description'],
        'steps': sorted(steps, key=lambda s: s['order']),
        'execution_order': [s['id'] for s in sorted(steps, key=lambda s: s['order'])],
        'parallel_groups': parallel_groups
    }


def _calculate_parallel_groups(self, steps: List[Dict]) -> List[List[str]]:
    """
    Detect which steps can run in parallel

    Steps with no shared dependencies can run concurrently
    """

    # Build dependency graph
    step_deps = {s['id']: set(s['dependencies']) for s in steps}

    groups = []
    remaining = set(s['id'] for s in steps)

    while remaining:
        # Find steps with all dependencies satisfied
        ready = set()
        for step_id in remaining:
            deps = step_deps[step_id]
            if all(d not in remaining for d in deps):
                ready.add(step_id)

        if not ready:
            # Circular dependency detected
            break

        groups.append(sorted(ready))
        remaining -= ready

    return groups
```

**Output Example**:
```python
plan = adapter.get_attack_chain_path('linux-privesc-sudo')

print(f"Attack Chain: {plan['name']}")
print(f"Steps: {len(plan['steps'])}")
print("\nExecution Plan:")

for i, group in enumerate(plan['parallel_groups']):
    if len(group) == 1:
        print(f"  Step {i+1}: {group[0]}")
    else:
        print(f"  Step {i+1} (parallel): {', '.join(group)}")
```

---

## Caching Strategy

### In-Memory LRU Cache

**Decorator**:
```python
from functools import lru_cache, wraps
from hashlib import sha256
import json

def cache_command(maxsize=128):
    """Cache command lookups to reduce Neo4j queries"""

    def decorator(func):
        # Use LRU cache with serialized args as key
        cache = {}

        @wraps(func)
        def wrapper(self, *args, **kwargs):
            # Create cache key from arguments
            cache_key = sha256(
                json.dumps([args, sorted(kwargs.items())]).encode()
            ).hexdigest()[:16]

            if cache_key in cache:
                return cache[cache_key]

            result = func(self, *args, **kwargs)
            cache[cache_key] = result

            # Limit cache size
            if len(cache) > maxsize:
                cache.pop(next(iter(cache)))

            return result

        wrapper.cache_clear = lambda: cache.clear()
        return wrapper

    return decorator


# Apply to expensive methods
@cache_command(maxsize=256)
def get_command(self, command_id: str) -> Optional[Command]:
    # ... implementation ...
    pass
```

---

### Redis-Based Distributed Cache (Optional)

**Configuration**:
```python
import redis
import pickle

class Neo4jCommandRegistryAdapter:
    def __init__(self, ..., use_redis=False):
        # ... existing init ...

        if use_redis:
            from db.config import get_redis_config
            redis_cfg = get_redis_config()
            self.redis = redis.Redis(**redis_cfg)
        else:
            self.redis = None

    def get_command(self, command_id: str) -> Optional[Command]:
        # Check Redis cache
        if self.redis:
            cached = self.redis.get(f"cmd:{command_id}")
            if cached:
                return pickle.loads(cached)

        # Query Neo4j
        command = self._fetch_command_from_neo4j(command_id)

        # Cache result
        if self.redis and command:
            self.redis.setex(
                f"cmd:{command_id}",
                3600,  # 1 hour TTL
                pickle.dumps(command)
            )

        return command
```

---

## Error Handling

### Connection Failures

```python
from neo4j.exceptions import ServiceUnavailable, SessionExpired

def _execute_read(self, query: str, **params) -> List:
    """Execute with automatic retry on transient failures"""

    max_retries = 3
    for attempt in range(max_retries):
        try:
            with self.driver.session(database=self.database) as session:
                return session.read_transaction(
                    lambda tx: list(tx.run(query, **params))
                )

        except (ServiceUnavailable, SessionExpired) as e:
            if attempt == max_retries - 1:
                raise Neo4jConnectionError(f"Neo4j unavailable after {max_retries} retries: {e}")

            # Exponential backoff
            time.sleep(2 ** attempt)

        except Exception as e:
            # Non-retryable error
            raise
```

---

## Testing Interface

### Unit Test Template

**File**: `tests/reference/test_neo4j_adapter.py`

```python
import pytest
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter

@pytest.fixture
def neo4j_adapter():
    """Create adapter instance for testing"""
    return Neo4jCommandRegistryAdapter()


def test_get_command(neo4j_adapter):
    """Test single command retrieval"""
    cmd = neo4j_adapter.get_command('nmap-quick-scan')

    assert cmd is not None
    assert cmd.id == 'nmap-quick-scan'
    assert cmd.name == 'Quick Full Port Scan'
    assert '<TARGET>' in cmd.command
    assert len(cmd.variables) > 0


def test_find_alternatives_multi_hop(neo4j_adapter):
    """Test multi-hop alternative discovery"""
    paths = neo4j_adapter.find_alternatives('gobuster-dir', max_depth=3)

    assert len(paths) > 0
    assert all(path.length <= 3 for path in paths)
    assert paths[0].length <= paths[-1].length  # Sorted by depth


def test_get_attack_chain_parallel_detection(neo4j_adapter):
    """Test parallel step detection in attack chains"""
    plan = neo4j_adapter.get_attack_chain_path('linux-privesc-sudo')

    assert plan is not None
    assert 'parallel_groups' in plan
    assert len(plan['parallel_groups']) > 0
```

---

## Next Steps

1. **Implement Adapter**: Create `reference/core/neo4j_adapter.py`
2. **Write Unit Tests**: Test each method independently
3. **Integrate Router**: [05-INTEGRATION.md](05-INTEGRATION.md)

---

## See Also

- [00-ARCHITECTURE.md](00-ARCHITECTURE.md#component-architecture) - System design
- [05-INTEGRATION.md](05-INTEGRATION.md) - Routing logic
- [06-ADVANCED-QUERIES.md](06-ADVANCED-QUERIES.md) - Complex Cypher patterns
- [reference/core/sql_adapter.py](../../reference/core/sql_adapter.py) - PostgreSQL adapter (reference implementation)

---

**Document Version**: 1.0.0
**Last Updated**: 2025-11-08
**Owner**: Adapter Development Team
**Status**: Specification Complete (Code TBD)
