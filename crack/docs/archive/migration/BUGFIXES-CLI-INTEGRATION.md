# Bug Fixes - Neo4j CLI Integration

**Date**: 2025-11-08
**Context**: Fixed Cypher syntax errors discovered during CLI testing

---

## Bugs Fixed

### 1. **Parameter Sanitization in `aggregate_by_pattern()`**

**File**: `reference/core/neo4j_adapter.py:973-982`

**Issue**: Parameter names containing dots (e.g., `p.number`, `c.oscp_relevance`) caused Neo4j parameter binding errors.

**Error**:
```
Neo.ClientError.Statement.ParameterMissing: Expected parameter(s): p, c
```

**Cause**: Neo4j interprets dots as property access, not parameter names.

**Fix**: Sanitize parameter names to simple identifiers:
```python
# Before:
params = filters or {}
where_clauses = [f"{key} = ${key}" for key in filters.keys()]

# After:
params = {}
for i, (key, value) in enumerate(filters.items()):
    param_name = f"filter_{i}"  # Simple name without dots
    where_clauses.append(f"{key} = ${param_name}")
    params[param_name] = value
```

**Impact**: Fixed Pattern 5 (service-rec), Pattern 7 (success-corr), Pattern 10 (var-usage)

---

### 2. **Missing Path Variable in `detect_circular_dependencies()`**

**File**: `reference/patterns/advanced_queries.py:320`

**Issue**: Pattern used `path` variable in return fields without defining it in the MATCH clause.

**Error**:
```
Neo.ClientError.Statement.SyntaxError: Variable `path` not defined
```

**Cause**: Cypher pattern didn't assign the path to a variable.

**Fix**:
```python
# Before:
pattern=f"(step:ChainStep)-[:DEPENDS_ON*]->(step) {chain_filter}"

# After:
pattern=f"path = (step:ChainStep)-[:DEPENDS_ON*]->(step) {chain_filter}"
```

**Impact**: Fixed Pattern 9 (circular-deps)

---

### 3. **Missing Path Variable in `shortest_attack_path()`**

**File**: `reference/patterns/advanced_queries.py:93`

**Issue**: Same as Bug #2 - path variable not defined.

**Error**:
```
Neo.ClientError.Statement.SyntaxError: Variable `path` not defined
```

**Fix**:
```python
# Before:
pattern="shortestPath((start:Command)-[:NEXT_STEP*]-(end:Command))"

# After:
pattern="path = shortestPath((start:Command)-[:NEXT_STEP*]-(end:Command))"
```

**Impact**: Fixed Pattern 2 (shortest-path)

---

### 4. **Neo4j 5.x Syntax in 4.x Environment**

**File**: `reference/core/neo4j_adapter.py:374-378`

**Issue**: Used Neo4j 5.x `EXISTS { MATCH ... }` syntax in Neo4j 4.4.26 environment.

**Error**:
```
Neo.ClientError.Statement.SyntaxError: EXISTS is only valid in a WHERE clause as a standalone predicate
```

**Cause**: Neo4j 4.x doesn't support `EXISTS { ... }` subquery syntax.

**Fix**:
```python
# Before (Neo4j 5.x):
WHERE ALL(parent_tag IN $tags WHERE EXISTS {
    MATCH (cmd)-[:TAGGED]->(tag:Tag)-[:CHILD_OF*0..]->(parent:Tag {name: parent_tag})
})

# After (Neo4j 4.x compatible):
WHERE ALL(parent_tag IN $tags WHERE
    EXISTS((cmd)-[:TAGGED]->(:Tag)-[:CHILD_OF*0..]->(:Tag {name: parent_tag}))
)
```

**Impact**: Fixed Pattern 6 (tag-hierarchy)

---

## Testing Results

**All 10 patterns now working:**

| Pattern | Status | Test Command |
|---------|--------|-------------|
| 1. Multi-hop alternatives | ✅ PASS | `crack reference --graph multi-hop gobuster-dir` |
| 2. Shortest path | ✅ PASS | `crack reference --graph shortest-path STARTER PRIVESC` |
| 3. Prerequisites | ✅ PASS | `crack reference --graph prereqs wordpress-sqli` |
| 4. Parallel execution | ✅ PASS | `crack reference --graph parallel web-to-root` |
| 5. Service recommendations | ✅ PASS | `crack reference --graph service-rec 80 445` |
| 6. Tag hierarchy | ✅ PASS | `crack reference --graph tag-hierarchy OSCP` |
| 7. Success correlation | ✅ PASS | `crack reference --graph success-corr` |
| 8. Coverage gaps | ✅ PASS | `crack reference --graph coverage-gaps` |
| 9. Circular dependencies | ✅ PASS | `crack reference --graph circular-deps` |
| 10. Variable usage | ✅ PASS | `crack reference --graph var-usage` |

**Success Rate**: 10/10 (100%)

---

## Key Learnings

### 1. **Neo4j Version Compatibility**

Neo4j 4.x and 5.x have different Cypher syntax:

**Neo4j 4.x** (current environment):
```cypher
# Use EXISTS with pattern directly
WHERE EXISTS((node)-[:REL]->(other))

# NOT this (Neo4j 5.x):
WHERE EXISTS { MATCH (node)-[:REL]->(other) }
```

**Reference**: Neo4j 4.4 running in test environment

### 2. **Parameter Naming Best Practices**

- Avoid dots in parameter names
- Use simple alphanumeric identifiers
- Sanitize user-provided keys when building queries

**Example**:
```python
# Bad: params = {'p.number': 80}  # Neo4j thinks 'p' is object
# Good: params = {'filter_0': 80}  # Clean parameter name
```

### 3. **Path Variables Must Be Explicit**

When using path functions like `shortestPath()` or variable-length patterns:

```cypher
# Always assign to variable if you'll reference it:
MATCH path = shortestPath((a)-[:REL*]->(b))
RETURN nodes(path)  # ✅ Works

# Don't do this:
MATCH shortestPath((a)-[:REL*]->(b))
RETURN nodes(path)  # ❌ path undefined
```

---

## Files Modified

1. **`reference/core/neo4j_adapter.py`**
   - Line 973-982: Parameter sanitization
   - Line 374-378: Neo4j 4.x compatibility for EXISTS

2. **`reference/patterns/advanced_queries.py`**
   - Line 93: Added path variable to shortest_attack_path
   - Line 320: Added path variable to detect_circular_dependencies

---

## Validation Commands

```bash
# Test all patterns
/tmp/test_all_patterns.sh

# Individual pattern tests
crack reference --graph multi-hop gobuster-dir
crack reference --graph shortest-path STARTER PRIVESC
crack reference --graph prereqs wordpress-sqli
crack reference --graph parallel web-to-root
crack reference --graph service-rec 80 445
crack reference --graph tag-hierarchy OSCP
crack reference --graph success-corr
crack reference --graph coverage-gaps
crack reference --graph circular-deps
crack reference --graph var-usage
```

---

## Production Readiness

✅ All patterns tested and working
✅ Neo4j 4.x compatibility confirmed
✅ Error handling graceful (empty results, no crashes)
✅ CLI integration complete
✅ Zero breaking changes

**Status**: Production Ready
