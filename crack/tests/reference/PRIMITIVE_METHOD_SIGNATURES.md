# Graph Primitive Method Signatures

## Reference for Neo4j Adapter Implementation

Based on test requirements from `test_neo4j_adapter_primitives.py`.

---

## 1. traverse_graph()

### Signature
```python
def traverse_graph(
    self,
    start_node_id: str,
    rel_type: str,
    direction: str = 'OUTGOING',
    max_depth: int = 3,
    return_metadata: bool = False,
    filters: Optional[Dict[str, Any]] = None,
    limit: Optional[int] = None
) -> Union[List[Command], List[Dict[str, Any]]]:
    """
    Generic graph traversal primitive

    Args:
        start_node_id: ID of starting node (command or tag)
        rel_type: Relationship type to traverse (ALTERNATIVE, PREREQUISITE, NEXT_STEP, CHILD_OF)
        direction: OUTGOING, INCOMING, or BOTH
        max_depth: Maximum traversal depth (default 3)
        return_metadata: If True, return dict with metadata; if False, return Command objects
        filters: Optional property filters (e.g., {'oscp_relevance': 'high'})
        limit: Maximum number of results

    Returns:
        If return_metadata=False: List[Command]
        If return_metadata=True: List[Dict] with structure:
            {
                'command_chain': List[Dict[str, str]],  # [{id, name}, ...]
                'metadata': List[Dict[str, Any]],       # Relationship properties
                'depth': int,
                'cumulative_priority': int
            }
    """
```

### Example Usage
```python
# Pattern 1: Multi-hop alternatives with metadata
results = adapter.traverse_graph(
    start_node_id='gobuster-dir',
    rel_type='ALTERNATIVE',
    direction='OUTGOING',
    max_depth=3,
    return_metadata=True,
    limit=10
)

# Pattern 3: Prerequisites (incoming)
prereqs = adapter.traverse_graph(
    start_node_id='wordpress-sqli',
    rel_type='PREREQUISITE',
    direction='INCOMING',
    max_depth=5,
    return_metadata=False  # Returns Command objects
)

# Pattern 6: Tag hierarchy
tags = adapter.traverse_graph(
    start_node_id='OSCP',
    rel_type='CHILD_OF',
    direction='INCOMING',
    max_depth=2
)
```

### Cypher Implementation Pattern
```cypher
MATCH path = (start {id: $start_node_id})-[:REL_TYPE*1..max_depth]->(end)
WHERE $filters (if provided)
WITH path, relationships(path) AS rels
RETURN
    [node IN nodes(path) | {id: node.id, name: node.name}] AS command_chain,
    [rel IN rels | {priority: rel.priority, reason: rel.reason}] AS metadata,
    length(path) AS depth,
    reduce(total = 0, rel IN rels | total + rel.priority) AS cumulative_priority
ORDER BY depth ASC, cumulative_priority ASC
LIMIT $limit
```

---

## 2. aggregate_by_pattern()

### Signature
```python
def aggregate_by_pattern(
    self,
    pattern: str,
    group_by: List[str],
    aggregations: Dict[str, str],
    filters: Optional[Dict[str, Any]] = None,
    order_by: Optional[str] = None,
    limit: Optional[int] = None
) -> List[Dict[str, Any]]:
    """
    Pattern-based aggregation primitive

    Args:
        pattern: Cypher MATCH pattern (e.g., "(c:Command)-[:TAGGED]->(t:Tag)")
        group_by: List of variables to group by (e.g., ['c', 't'])
        aggregations: Dict of {field_name: cypher_expression}
            Examples:
                {'count': 'COUNT(c)'}
                {'services': 'COLLECT(DISTINCT s.name)'}
                {'avg_priority': 'AVG(c.priority)'}
                {'top_5': 'COLLECT(c.id)[0..5]'}
        filters: Optional property filters (converted to WHERE clause)
            Examples:
                {'p.number': [80, 445, 22]}  # IN clause
                {'c.oscp_relevance': 'high'}  # Equality
                {'u.required': True}          # Boolean
        order_by: Optional ORDER BY clause (e.g., "service_count DESC")
        limit: Maximum number of results

    Returns:
        List of dicts with aggregated data

    Raises:
        ValueError: If pattern contains dangerous Cypher (DELETE, CREATE, SET, DROP)
    """
```

### Example Usage
```python
# Pattern 5: Service-based recommendations
results = adapter.aggregate_by_pattern(
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

# Pattern 10: Variable usage analysis
results = adapter.aggregate_by_pattern(
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
```

### Cypher Implementation Pattern
```cypher
MATCH <pattern>
WHERE <filters converted to WHERE clauses>
WITH <group_by variables>
RETURN
    <aggregations>
ORDER BY <order_by>
LIMIT <limit>
```

### Security Validation
Must reject patterns containing:
- `DELETE`
- `CREATE`
- `SET`
- `DROP`
- `DETACH DELETE`
- `MERGE` (optional - can be dangerous)

---

## 3. find_by_pattern()

### Signature
```python
def find_by_pattern(
    self,
    pattern: str,
    where_clause: Optional[str] = None,
    return_fields: Optional[List[str]] = None,
    limit: Optional[int] = None
) -> List[Dict[str, Any]]:
    """
    Flexible pattern matching primitive for complex queries

    Args:
        pattern: Full Cypher MATCH pattern
            Examples:
                "shortestPath((start:Command)-[:NEXT_STEP*]-(end:Command))"
                "(s:Service) WHERE NOT exists { ... }"
                "(s:ChainStep)-[:DEPENDS_ON*]->(s)"
        where_clause: Optional WHERE clause (appended to query)
        return_fields: List of fields to return
            Examples:
                ['start.id', 'end.id', 'length(path) AS path_length']
                ['s.name', 's.protocol']
                ['nodes(path)', 'length(path)']
        limit: Maximum number of results

    Returns:
        List of dicts with specified return fields

    Raises:
        ValueError: If pattern contains dangerous Cypher
    """
```

### Example Usage
```python
# Pattern 2: Shortest attack path
results = adapter.find_by_pattern(
    pattern="shortestPath((start:Command)-[:NEXT_STEP*]-(end:Command))",
    where_clause="start.tags CONTAINS 'STARTER' AND end.tags CONTAINS 'PRIVESC'",
    return_fields=['start.id', 'end.id', 'length(path) AS path_length'],
    limit=5
)

# Pattern 8: Coverage gaps
results = adapter.find_by_pattern(
    pattern="(s:Service) WHERE NOT exists { MATCH (s)-[:ENUMERATED_BY]->(c:Command) WHERE c.oscp_relevance = 'high' }",
    return_fields=['s.name', 's.protocol'],
    limit=50
)

# Pattern 9: Circular dependencies
results = adapter.find_by_pattern(
    pattern="(s:ChainStep)-[:DEPENDS_ON*]->(s)",
    return_fields=['s.id', 's.name', 'length(path) AS cycle_length']
)
```

### Cypher Implementation Pattern
```cypher
MATCH <pattern>
WHERE <where_clause>
RETURN <return_fields or *>
LIMIT <limit>
```

---

## 4. Enhanced Existing Methods

### find_alternatives() Enhancement
```python
def find_alternatives(
    self,
    command_id: str,
    max_depth: int = 3,
    return_metadata: bool = False  # NEW PARAMETER
) -> Union[List[Command], List[Dict[str, Any]]]:
    """
    Find alternative commands with optional metadata

    NEW: return_metadata parameter
        If False: Returns List[Command] (backward compatible)
        If True: Returns List[Dict] with metadata structure
    """
```

### find_prerequisites() Enhancement
```python
def find_prerequisites(
    self,
    command_id: str,
    depth: int = 3,
    execution_order: bool = False  # NEW PARAMETER
) -> Union[List[Command], List[Dict[str, Any]]]:
    """
    Get prerequisite commands with optional execution ordering

    NEW: execution_order parameter
        If False: Returns List[Command] (backward compatible)
        If True: Returns List[Dict] with dependency_count for topological sort
            [
                {
                    'command_id': str,
                    'command_name': str,
                    'dependency_count': int,  # 0 = run first
                    'command': Command
                }
            ]
            Sorted by dependency_count DESC
    """
```

### filter_by_tags() Enhancement
```python
def filter_by_tags(
    self,
    tags: List[str],
    match_all: bool = True,
    exclude_tags: List[str] = None,
    include_hierarchy: bool = False  # NEW PARAMETER
) -> List[Command]:
    """
    Filter commands by tags with optional hierarchy traversal

    NEW: include_hierarchy parameter
        If False: Only match exact tags (backward compatible)
        If True: Include child tags via CHILD_OF relationships
            Example: tags=['OSCP'] matches OSCP, OSCP:ENUM, OSCP:EXPLOIT, etc.
    """
```

---

## Implementation Notes

### Common Patterns

#### Direction Mapping
```python
DIRECTION_MAP = {
    'OUTGOING': '->',
    'INCOMING': '<-',
    'BOTH': '-'
}
```

#### Filter to WHERE Clause
```python
def build_where_clause(filters: Dict[str, Any]) -> str:
    """
    Convert filters dict to Cypher WHERE clause

    Examples:
        {'p.number': [80, 445, 22]} → "p.number IN [80, 445, 22]"
        {'c.oscp_relevance': 'high'} → "c.oscp_relevance = 'high'"
        {'u.required': True} → "u.required = true"
    """
```

#### Security Validation
```python
DANGEROUS_KEYWORDS = ['DELETE', 'CREATE', 'SET', 'DROP', 'DETACH DELETE']

def validate_cypher(query: str) -> None:
    """Raise ValueError if query contains dangerous operations"""
    upper_query = query.upper()
    for keyword in DANGEROUS_KEYWORDS:
        if keyword in upper_query:
            raise ValueError(f"Dangerous Cypher keyword not allowed: {keyword}")
```

---

## Error Handling

All primitives should:
1. Return `[]` for empty results (not `None`)
2. Skip if method not implemented (`pytest.skip()` in tests)
3. Validate Cypher for security before execution
4. Handle Neo4j connection errors gracefully
5. Use parameterized queries (never string interpolation for values)

---

## Performance Considerations

1. **Index Usage**: Patterns should leverage indexes
   - `(c:Command {id: $id})` uses Command.id index
   - `(c:Command)-[:TAGGED]->(:Tag {name: $tag})` uses Tag.name index

2. **Limit Early**: Apply LIMIT in Cypher, not Python
   ```cypher
   MATCH path = ...
   WITH path LIMIT 100  -- Good
   RETURN path
   ```

3. **Avoid Cartesian Products**: Use WHERE, not multiple MATCH
   ```cypher
   -- Good
   MATCH (c:Command)
   WHERE c.category = $cat AND c.oscp_relevance = 'high'

   -- Bad
   MATCH (c:Command)
   MATCH (c2:Command)  -- Creates cartesian product
   WHERE c.id = c2.id
   ```

---

## Testing

All primitives tested with:
- Happy path (valid data)
- Empty results
- Invalid inputs
- Security violations
- Performance benchmarks (deep traversals <500ms)
- Edge cases (nonexistent IDs, special characters)

See `/home/kali/Desktop/OSCP/crack/tests/reference/test_neo4j_adapter_primitives.py` for complete test suite.
