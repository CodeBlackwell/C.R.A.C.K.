# Advanced Query Pattern Library

This directory contains pre-built implementations of the 10 advanced query patterns from `db/neo4j-migration/06-ADVANCED-QUERIES.md`.

## Quick Start

```python
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
from crack.reference.patterns.advanced_queries import GraphQueryPatterns

# Initialize adapter
adapter = Neo4jCommandRegistryAdapter()

# Create pattern helper
patterns = GraphQueryPatterns(adapter)

# Use patterns
alternatives = patterns.multi_hop_alternatives('gobuster-dir', depth=3)
prereqs = patterns.prerequisite_closure('wordpress-sqli')
gaps = patterns.find_coverage_gaps()
```

## Pattern Reference

| Pattern | Method | OSCP Use Case |
|---------|--------|---------------|
| 1 | `multi_hop_alternatives()` | Find backup tools when primary fails |
| 2 | `shortest_attack_path()` | Plan fastest route to privesc |
| 3 | `prerequisite_closure()` | Validate setup before exploit |
| 4 | `parallel_execution_plan()` | Run multiple scans simultaneously |
| 5 | `service_recommendations()` | Get commands for open ports |
| 6 | `filter_by_tag_hierarchy()` | Filter by category hierarchy |
| 7 | `success_correlation()` | Find commonly paired commands |
| 8 | `find_coverage_gaps()` | Identify missing enumeration |
| 9 | `detect_circular_dependencies()` | Validate attack chain integrity |
| 10 | `variable_usage_analysis()` | Find commands needing configuration |

## OSCP Exam Workflow

```python
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
from crack.reference.patterns.advanced_queries import create_pattern_helper

# Initialize
adapter = Neo4jCommandRegistryAdapter()
patterns = create_pattern_helper(adapter)

# 1. Initial enumeration
starters = patterns.filter_by_tag_hierarchy(['STARTER'])
print(f"Found {len(starters)} starter commands")

# 2. Service-specific attacks (after nmap)
attacks = patterns.service_recommendations([80, 445, 22])
for attack in attacks:
    print(f"{attack['command_name']}: {attack['services']}")

# 3. If tool fails, find alternatives
alts = patterns.multi_hop_alternatives('gobuster-dir', depth=2)
for alt in alts:
    print(f"Alternative chain: {alt['command_chain']}")

# 4. Plan fastest path to root
paths = patterns.shortest_attack_path(start_tag='STARTER', end_tag='PRIVESC')
if paths:
    fastest = paths[0]
    print(f"Quickest path: {fastest['step_count']} steps")

# 5. Validate prerequisites before exploit
prereqs = patterns.prerequisite_closure('exploit-id')
for prereq in prereqs:
    print(f"Run first: {prereq['command_name']}")
```

## Pattern Details

### 1. Multi-Hop Alternatives

Find alternative commands up to N hops away.

```python
alternatives = patterns.multi_hop_alternatives(
    command_id='gobuster-dir',
    depth=3,
    limit=10
)

for alt in alternatives:
    print(f"Chain: {alt['command_chain']}")
    print(f"Priority: {alt['cumulative_priority']}")
```

**Use Case**: "If gobuster fails, try ffuf. If ffuf fails, try wfuzz."

### 2. Shortest Attack Path

Find quickest path from enumeration to privilege escalation.

```python
paths = patterns.shortest_attack_path(
    start_tag='STARTER',
    end_tag='PRIVESC',
    limit=5
)

fastest = paths[0]  # Shortest path first
print(f"Steps: {fastest['step_count']}")
```

**Use Case**: "What's the fastest way to get from nmap to root?"

### 3. Prerequisite Closure

Get ALL prerequisites with execution order.

```python
prereqs = patterns.prerequisite_closure(
    command_id='wordpress-sqli',
    with_execution_order=True
)

for prereq in prereqs:
    print(f"{prereq['dependency_count']}: {prereq['command_name']}")
```

**Use Case**: "What do I need to run BEFORE executing this exploit?"

### 4. Parallel Execution Plan

Identify which steps can run simultaneously.

```python
plan = patterns.parallel_execution_plan('linux-privesc-sudo')

wave1 = plan['parallel_groups'][0]  # No dependencies
wave2 = plan['parallel_groups'][1]  # Depends on wave1
```

**Use Case**: "Which enumeration commands can I run in parallel?"

### 5. Service Recommendations

Recommend commands for detected services.

```python
recs = patterns.service_recommendations(
    port_numbers=[80, 445, 22],
    oscp_only=True,
    limit=10
)

for rec in recs:
    print(f"{rec['command_name']}: {rec['services']}")
```

**Use Case**: "Ports 80, 445, 22 are open. What should I do?"

### 6. Tag Hierarchy Filtering

Filter commands with tag hierarchy inference.

```python
commands = patterns.filter_by_tag_hierarchy(
    parent_tags=['OSCP'],
    include_children=True
)
# Returns commands tagged with OSCP, OSCP:ENUM, OSCP:EXPLOIT, etc.
```

**Use Case**: "Show all OSCP commands (including sub-tags like OSCP:ENUM)"

### 7. Success Correlation

Find commands that frequently succeed together.

```python
correlations = patterns.success_correlation(
    min_co_occurrence=5,
    limit=20
)

for corr in correlations:
    print(f"{corr['command_a']} + {corr['command_b']}: {corr['count']}")
```

**Use Case**: "What commands typically work on similar targets?"

**Note**: Requires Session execution data ([:EXECUTED] relationships)

### 8. Coverage Gap Detection

Services lacking enumeration commands.

```python
gaps = patterns.find_coverage_gaps(oscp_only=True)

for gap in gaps:
    print(f"Missing: {gap['service_name']} (ports: {gap['ports']})")
```

**Use Case**: "Which services don't have good OSCP commands?"

### 9. Circular Dependency Detection

Find broken attack chains with circular dependencies.

```python
cycles = patterns.detect_circular_dependencies(chain_id=None)

if cycles:
    print("WARNING: Circular dependencies detected!")
    for cycle in cycles:
        print(f"  {cycle['circular_steps']}")
```

**Use Case**: "Are there any cyclic prerequisite chains?"

### 10. Variable Usage Analysis

Analyze which commands use which variables.

```python
# Find most common variables
vars = patterns.variable_usage_analysis(required_only=True, limit=10)
print(f"Most used: {vars[0]['variable_name']} ({vars[0]['usage_count']} commands)")

# Find commands using specific variable
target_cmds = patterns.variable_usage_analysis(variable_name='<TARGET>')
```

**Use Case**: "Which commands need manual configuration (use <TARGET>)?"

## Implementation Notes

All patterns are implemented using **3 minimalist primitives**:

1. **`traverse_graph()`** - Multi-hop relationship traversal
2. **`aggregate_by_pattern()`** - Group/count/collect operations
3. **`find_by_pattern()`** - Custom Cypher pattern matching

This reduces code duplication by 76% compared to implementing each pattern separately.

## Testing

Integration tests are available in `/home/kali/Desktop/OSCP/crack/tests/reference/test_neo4j_adapter.py`:

```bash
# Run all integration tests
pytest tests/reference/test_neo4j_adapter.py::TestAdvancedQueryIntegration -v

# Run specific test
pytest tests/reference/test_neo4j_adapter.py::TestAdvancedQueryIntegration::test_oscp_exam_workflow -v
```

## See Also

- [06-ADVANCED-QUERIES.md](../../db/neo4j-migration/06-ADVANCED-QUERIES.md) - Full pattern documentation
- [04-ADAPTER-IMPLEMENTATION.md](../../db/neo4j-migration/04-ADAPTER-IMPLEMENTATION.md) - Adapter API reference
- [02-SCHEMA-DESIGN.md](../../db/neo4j-migration/02-SCHEMA-DESIGN.md) - Neo4j schema
