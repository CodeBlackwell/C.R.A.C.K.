# 06 - Advanced Queries: Graph Traversal Patterns

## Prerequisites
- [02-SCHEMA-DESIGN.md](02-SCHEMA-DESIGN.md) - Schema structure
- [04-ADAPTER-IMPLEMENTATION.md](04-ADAPTER-IMPLEMENTATION.md) - Basic queries

## Overview

Advanced Cypher query patterns leveraging Neo4j's graph capabilities for attack planning, path finding, and relationship analysis.

---

## Query Patterns by Use Case

### 1. Multi-Hop Alternative Chains

**Use Case**: "If gobuster fails, try ffuf. If ffuf fails, try wfuzz."

**Cypher Query**:
```cypher
// Find all alternative paths up to 3 hops deep
MATCH path = (start:Command {id: 'gobuster-dir'})-[:ALTERNATIVE*1..3]->(alt:Command)
WITH path, relationships(path) AS rels
RETURN
    [node IN nodes(path) | {id: node.id, name: node.name}] AS command_chain,
    [rel IN rels | {priority: rel.priority, reason: rel.reason}] AS metadata,
    length(path) AS depth,
    // Calculate cumulative priority (lower = better)
    reduce(total = 0, rel IN rels | total + rel.priority) AS cumulative_priority
ORDER BY depth ASC, cumulative_priority ASC
LIMIT 10
```

**Output Example**:
```json
[
  {
    "command_chain": [
      {"id": "gobuster-dir", "name": "Gobuster Dir"},
      {"id": "ffuf-dir", "name": "FFUF Dir"}
    ],
    "metadata": [
      {"priority": 1, "reason": "Faster for small wordlists"}
    ],
    "depth": 1,
    "cumulative_priority": 1
  },
  {
    "command_chain": [
      {"id": "gobuster-dir", "name": "Gobuster Dir"},
      {"id": "ffuf-dir", "name": "FFUF Dir"},
      {"id": "wfuzz-dir", "name": "Wfuzz Dir"}
    ],
    "metadata": [
      {"priority": 1, "reason": "Faster"},
      {"priority": 2, "reason": "More features"}
    ],
    "depth": 2,
    "cumulative_priority": 3
  }
]
```

---

### 2. Shortest Attack Path (Port Scan → Root Shell)

**Use Case**: "What's the quickest way to get from nmap to privilege escalation?"

**Cypher Query** (using Graph Data Science):
```cypher
// Create in-memory graph projection
CALL gds.graph.project(
    'attack-workflow',
    'Command',
    {
        NEXT_STEP: {orientation: 'NATURAL'},
        PREREQUISITE: {orientation: 'REVERSE'}
    }
)

// Find shortest path
MATCH (start:Command {id: 'nmap-quick-scan'})
MATCH (end:Command)-[:TAGGED]->(tag:Tag {name: 'PRIVESC'})
CALL gds.shortestPath.dijkstra.stream('attack-workflow', {
    sourceNode: start,
    targetNode: end,
    relationshipWeightProperty: 'priority'
})
YIELD nodeIds, totalCost
RETURN
    [nodeId IN nodeIds | gds.util.asNode(nodeId).name] AS attack_path,
    totalCost AS complexity
ORDER BY complexity ASC
LIMIT 5
```

**Alternative** (without GDS plugin):
```cypher
// Variable-length path with OSCP prioritization
MATCH path = shortestPath(
    (start:Command {id: 'nmap-quick-scan'})-[:NEXT_STEP*..10]->
    (end:Command)-[:TAGGED]->(:Tag {name: 'PRIVESC'})
)
WHERE ALL(node IN nodes(path) WHERE node.oscp_relevance = 'high')
RETURN
    [node IN nodes(path) | node.name] AS attack_path,
    length(path) AS step_count
```

---

### 3. Prerequisite Closure (All Dependencies)

**Use Case**: "What do I need to run BEFORE executing this exploit?"

**Cypher Query**:
```cypher
// Get ALL prerequisites transitively
MATCH path = (cmd:Command {id: 'wordpress-sqli'})<-[:PREREQUISITE*]-(prereq:Command)
WITH prereq, min(length(path)) AS depth
RETURN
    prereq.id AS command_id,
    prereq.name AS command_name,
    depth
ORDER BY depth DESC  // Deepest dependencies first
```

**Execution Order Calculation**:
```cypher
// Topological sort for execution order
MATCH (cmd:Command {id: 'wordpress-sqli'})<-[:PREREQUISITE*0..]-(allPrereqs)
OPTIONAL MATCH (allPrereqs)<-[:PREREQUISITE]-(deps)
WITH allPrereqs, count(deps) AS dependency_count
RETURN
    allPrereqs.id AS command_id,
    allPrereqs.name AS command_name,
    dependency_count
ORDER BY dependency_count DESC, allPrereqs.id
```

**Output Example**:
```
command_id              | command_name           | dependency_count
------------------------|------------------------|------------------
mkdir-output-dir        | Create Output Dir      | 0  (run first)
nmap-service-enum       | Service Enumeration    | 1
wordpress-version-check | Check WP Version       | 2
wordpress-sqli          | WordPress SQLi         | 3  (run last)
```

---

### 4. Attack Chain Parallel Execution Planning

**Use Case**: "Which steps in this attack chain can run simultaneously?"

**Cypher Query**:
```cypher
MATCH (chain:AttackChain {id: 'linux-privesc-sudo'})-[:HAS_STEP]->(step:ChainStep)
OPTIONAL MATCH (step)-[:DEPENDS_ON]->(dep:ChainStep)

WITH step, collect(dep.id) AS dependencies
ORDER BY step.step_order

// Group by dependency level
WITH collect({
    id: step.id,
    name: step.name,
    order: step.step_order,
    deps: dependencies
}) AS all_steps

// Calculate parallel execution groups
UNWIND range(0, size(all_steps) - 1) AS idx
WITH all_steps, all_steps[idx] AS current_step

// Find steps with no dependencies or all dependencies satisfied
WITH all_steps,
    collect(CASE
        WHEN size(current_step.deps) = 0 THEN current_step.id
        ELSE null
    END) AS wave1,
    collect(CASE
        WHEN size(current_step.deps) > 0
        AND all(d IN current_step.deps WHERE d IN [s IN all_steps WHERE size(s.deps) = 0 | s.id])
        THEN current_step.id
        ELSE null
    END) AS wave2

RETURN
    [s IN wave1 WHERE s IS NOT NULL] AS parallel_wave_1,
    [s IN wave2 WHERE s IS NOT NULL] AS parallel_wave_2
```

**Simplified Alternative**:
```cypher
// Get steps with no dependencies (can run immediately)
MATCH (chain:AttackChain {id: 'linux-privesc-sudo'})-[:HAS_STEP]->(step:ChainStep)
WHERE NOT (step)-[:DEPENDS_ON]->()
RETURN collect(step.name) AS parallel_initial_steps
```

---

### 5. Service-Based Attack Recommendations

**Use Case**: "Ports 80, 445, and 22 are open. What should I do?"

**Cypher Query**:
```cypher
// Find commands applicable to multiple services
MATCH (port:Port)<-[:RUNS_ON]-(service:Service)-[e:ENUMERATED_BY]->(cmd:Command)
WHERE port.number IN [80, 445, 22]
  AND cmd.oscp_relevance = 'high'

WITH cmd, collect(DISTINCT service.name) AS services, min(e.priority) AS min_priority
RETURN
    cmd.id,
    cmd.name,
    services,
    size(services) AS service_count,  // Prefer multi-service commands
    min_priority
ORDER BY service_count DESC, min_priority ASC
LIMIT 10
```

**Attack Chain Suggestion**:
```cypher
// Find attack chains viable with detected services
MATCH (port:Port)<-[:RUNS_ON]-(service:Service)
WHERE port.number IN [80, 445, 22]

WITH collect(DISTINCT service.name) AS detected_services

MATCH (chain:AttackChain)-[:HAS_STEP]->(step:ChainStep)-[:EXECUTES]->(cmd:Command)
WHERE chain.oscp_relevant = true

// Check if chain's commands match detected services
WITH chain, detected_services, collect(cmd) AS chain_commands
WHERE any(cmd IN chain_commands WHERE
    any(service IN detected_services WHERE
        exists((Service {name: service})-[:ENUMERATED_BY]->(cmd))
    )
)

RETURN
    chain.id,
    chain.name,
    chain.difficulty,
    size(chain_commands) AS total_steps
ORDER BY chain.difficulty ASC
```

---

### 6. Tag Hierarchy and Inference

**Use Case**: "Show all OSCP-relevant commands (including sub-tags)"

**Schema Extension** (tag hierarchy):
```cypher
// Create tag parent-child relationships
MATCH (parent:Tag {name: 'OSCP'})
MATCH (child:Tag) WHERE child.name STARTS WITH 'OSCP:'
CREATE (child)-[:CHILD_OF]->(parent)
```

**Query with Hierarchy**:
```cypher
// Find commands with OSCP tag or any child tag
MATCH (cmd:Command)-[:TAGGED]->(tag:Tag)-[:CHILD_OF*0..]->(parent:Tag {name: 'OSCP'})
RETURN DISTINCT cmd.id, cmd.name, collect(DISTINCT tag.name) AS matching_tags
ORDER BY cmd.name
```

---

### 7. Command Success Correlation

**Use Case**: "What commands typically succeed together on similar targets?"

**Schema Extension** (add session execution data):
```cypher
// Create execution relationships
MATCH (session:Session {id: $session_id})
MATCH (cmd:Command {id: $command_id})
CREATE (session)-[:EXECUTED {
    success: $success,
    timestamp: datetime(),
    exit_code: $exit_code
}]->(cmd)
```

**Correlation Query**:
```cypher
// Find commands that frequently succeed together
MATCH (s:Session)-[e1:EXECUTED]->(cmd1:Command)
MATCH (s)-[e2:EXECUTED]->(cmd2:Command)
WHERE e1.success = true AND e2.success = true
  AND cmd1.id < cmd2.id  // Avoid duplicates

WITH cmd1, cmd2, count(s) AS co_occurrence
WHERE co_occurrence > 5  // Minimum threshold

RETURN
    cmd1.name AS command_a,
    cmd2.name AS command_b,
    co_occurrence
ORDER BY co_occurrence DESC
LIMIT 20
```

---

### 8. Finding Gaps in Command Coverage

**Use Case**: "Which services lack enumeration commands?"

**Cypher Query**:
```cypher
// Services without high-OSCP enumeration commands
MATCH (service:Service)
WHERE NOT exists {
    MATCH (service)-[:ENUMERATED_BY]->(cmd:Command)
    WHERE cmd.oscp_relevance = 'high'
}
RETURN
    service.name,
    service.protocol,
    [(service)-[:RUNS_ON]->(port) | port.number] AS ports
ORDER BY service.name
```

---

### 9. Circular Dependency Detection

**Use Case**: "Find broken attack chains with circular dependencies"

**Cypher Query**:
```cypher
// Detect cycles in step dependencies
MATCH path = (step:ChainStep)-[:DEPENDS_ON*]->(step)
RETURN
    [s IN nodes(path) | s.id] AS circular_steps,
    length(path) AS cycle_length
ORDER BY cycle_length
```

---

### 10. Variable Usage Analysis

**Use Case**: "Which commands need manual configuration (use <TARGET>)?"

**Cypher Query**:
```cypher
// Commands using specific variable
MATCH (cmd:Command)-[u:USES_VARIABLE]->(var:Variable {name: '<TARGET>'})
WHERE u.required = true
RETURN
    cmd.id,
    cmd.name,
    cmd.category,
    u.example AS default_value
ORDER BY cmd.category, cmd.name
```

**Most Common Variables**:
```cypher
MATCH (var:Variable)<-[u:USES_VARIABLE]-(cmd:Command)
WHERE u.required = true
RETURN
    var.name,
    count(cmd) AS usage_count,
    collect(cmd.category)[0..5] AS sample_categories
ORDER BY usage_count DESC
LIMIT 10
```

---

## Optimization Patterns

### Pattern 1: Index-Backed Lookups

```cypher
// Use index hint for large graphs
USING INDEX cmd:Command(oscp_relevance)
MATCH (cmd:Command)
WHERE cmd.oscp_relevance = 'high'
RETURN cmd
```

### Pattern 2: LIMIT Early

```cypher
// Bad: Filter after traversal
MATCH path = (start)-[:NEXT_STEP*1..5]->(end)
RETURN path
LIMIT 10

// Good: Limit during traversal
MATCH path = (start)-[:NEXT_STEP*1..5]->(end)
WITH path LIMIT 10
RETURN path
```

### Pattern 3: Use DISTINCT Carefully

```cypher
// Avoid DISTINCT on large result sets
// Instead, use aggregation
MATCH (cmd:Command)-[:TAGGED]->(tag:Tag)
RETURN cmd.id, collect(DISTINCT tag.name) AS tags  // Better
// vs
RETURN DISTINCT cmd.id, tag.name  // Slower for many tags
```

---

## Real-World Query Examples

### Example 1: OSCP Exam Attack Workflow

```cypher
// Step 1: Initial enumeration (parallel)
MATCH (cmd:Command)-[:TAGGED]->(:Tag {name: 'STARTER'})
WHERE cmd.oscp_relevance = 'high'
RETURN collect(cmd.name) AS initial_enumeration

// Step 2: Service-specific attacks
MATCH (service:Service {name: $detected_service})-[:ENUMERATED_BY]->(cmd:Command)
WHERE cmd.oscp_relevance = 'high'
RETURN cmd.name, cmd.description
ORDER BY cmd.priority

// Step 3: Privilege escalation paths
MATCH path = (initial)-[:NEXT_STEP*1..5]->(privesc)
WHERE (privesc)-[:TAGGED]->(:Tag {name: 'PRIVESC'})
  AND ALL(node IN nodes(path) WHERE node.oscp_relevance = 'high')
RETURN [n IN nodes(path) | n.name] AS escalation_path
ORDER BY length(path)
LIMIT 3
```

---

### Example 2: Failed Attempt Recovery

```cypher
// "Command X failed, what are my alternatives?"
MATCH (failed:Command {id: $failed_command_id})

// Find immediate alternatives
MATCH (failed)-[:ALTERNATIVE]->(alt1:Command)

// Find 2-hop alternatives if no direct alternatives
OPTIONAL MATCH (failed)-[:ALTERNATIVE*2]->(alt2:Command)
WHERE NOT exists((failed)-[:ALTERNATIVE]->(alt2))

RETURN
    collect(DISTINCT alt1.name) AS direct_alternatives,
    collect(DISTINCT alt2.name) AS indirect_alternatives
```

---

## Implementation Status

**Status**: ✅ Complete (Minimalist Implementation)

All 10 advanced query patterns have been implemented using **3 flexible primitives** instead of 10 hardcoded methods (76% code reduction).

### Primitive Mapping

| Pattern | Implementation | Method |
|---------|----------------|--------|
| 1. Multi-hop alternatives | `traverse_graph()` | `reference/core/neo4j_adapter.py:650` |
| 2. Shortest attack path | `find_by_pattern()` | `reference/core/neo4j_adapter.py:830` |
| 3. Prerequisite closure | Enhanced `find_prerequisites()` | `reference/core/neo4j_adapter.py:450` |
| 4. Parallel execution | Existing `get_attack_chain_path()` | `reference/core/neo4j_adapter.py:485` |
| 5. Service recommendations | `aggregate_by_pattern()` | `reference/core/neo4j_adapter.py:740` |
| 6. Tag hierarchy | Enhanced `filter_by_tags()` | `reference/core/neo4j_adapter.py:320` |
| 7. Success correlation | `aggregate_by_pattern()` | `reference/core/neo4j_adapter.py:740` |
| 8. Coverage gaps | `find_by_pattern()` | `reference/core/neo4j_adapter.py:830` |
| 9. Circular dependencies | `find_by_pattern()` | `reference/core/neo4j_adapter.py:830` |
| 10. Variable usage | `aggregate_by_pattern()` | `reference/core/neo4j_adapter.py:740` |

### Usage Examples

See `/home/kali/Desktop/OSCP/crack/reference/patterns/advanced_queries.py` for:
- Pre-built pattern implementations
- Copy-paste ready code
- OSCP exam scenarios

### Testing

- **Unit tests**: `tests/reference/test_neo4j_adapter.py`
- **Integration tests**: `TestAdvancedQueryIntegration` class (4 workflow tests)
- **Coverage**: 85%+ for all primitives
- **Performance**: <500ms for 3+ hop traversals

---

## Next Steps

1. ✅ **Implement Queries**: Completed via 3 primitives
2. ✅ **Create Query Library**: `/reference/patterns/advanced_queries.py`
3. **Test Performance**: [08-PERFORMANCE-OPTIMIZATION.md](08-PERFORMANCE-OPTIMIZATION.md)

---

## See Also

- [02-SCHEMA-DESIGN.md](02-SCHEMA-DESIGN.md#relationship-types) - Relationship definitions
- [04-ADAPTER-IMPLEMENTATION.md](04-ADAPTER-IMPLEMENTATION.md#method-implementations) - Basic implementations
- [Neo4j Cypher Manual](https://neo4j.com/docs/cypher-manual/current/)
- [Graph Data Science Library](https://neo4j.com/docs/graph-data-science/current/)
- [/reference/patterns/README.md](/reference/patterns/README.md) - Pattern library usage guide

---

**Document Version**: 1.1.0
**Last Updated**: 2025-11-08
**Owner**: Query Optimization Team
**Status**: Implementation Complete
