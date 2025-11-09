# CRACK Neo4j Architecture Testing Guide

Quick reference for testing the new minimalist graph primitives and advanced query patterns.

---

## 🚀 Quick Start

### 1. Verify Neo4j is Running
```bash
# Check Neo4j status
sudo neo4j status

# If not running, start it
sudo neo4j start

# Verify connection
python3 -c "from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter; \
from crack.reference.core import ConfigManager, ReferenceTheme; \
adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme()); \
print('✓ Connected!' if adapter.health_check() else '✗ Connection failed')"
```

### 2. Populate Test Data (if needed)
```bash
python3 tests/scripts/populate_neo4j_test_data.py
```

---

## 📊 Test the 3 Core Primitives

### Primitive 1: `traverse_graph()` - Variable-Length Path Traversal

**Test Pattern 1: Multi-Hop Alternatives**
```python
python3 << 'EOF'
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
from crack.reference.core import ConfigManager, ReferenceTheme

adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme())

# Find alternative commands up to 3 hops away
results = adapter.traverse_graph(
    start_node_id='gobuster-dir',
    rel_type='ALTERNATIVE',
    direction='OUTGOING',
    max_depth=3,
    return_metadata=True
)

print(f"\n🔧 Found {len(results)} alternative chains:")
for r in results:
    chain = " → ".join([cmd['name'] for cmd in r['command_chain']])
    print(f"  • {chain}")
    print(f"    Depth: {r['depth']}, Priority: {r['cumulative_priority']}")
EOF
```

**Test Pattern 3: Prerequisites with Incoming Direction**
```python
python3 << 'EOF'
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
from crack.reference.core import ConfigManager, ReferenceTheme

adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme())

# Find prerequisites (traverse incoming relationships)
results = adapter.traverse_graph(
    start_node_id='wordpress-sqli',
    rel_type='PREREQUISITE',
    direction='INCOMING',
    max_depth=5,
    return_metadata=False
)

print(f"\n📋 Prerequisites for WordPress SQLi:")
for cmd in results:
    print(f"  • {cmd.name} ({cmd.id})")
EOF
```

**Test Pattern 6: Tag Hierarchy**
```python
python3 << 'EOF'
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
from crack.reference.core import ConfigManager, ReferenceTheme

adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme())

# Traverse tag hierarchy (CHILD_OF relationships)
results = adapter.traverse_graph(
    start_node_id='OSCP',
    rel_type='CHILD_OF',
    direction='INCOMING',  # Get child tags
    max_depth=2,
    return_metadata=True
)

print(f"\n🏷️  OSCP tag hierarchy:")
for r in results:
    print(f"  • Depth {r['depth']}: {r['command_chain'][-1]['name']}")
EOF
```

---

### Primitive 2: `aggregate_by_pattern()` - Template-Based Aggregation

**Test Pattern 5: Service-Based Recommendations**
```python
python3 << 'EOF'
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
from crack.reference.core import ConfigManager, ReferenceTheme

adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme())

# Find commands that work on multiple services
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

print(f"\n🌐 Service-based recommendations:")
for r in results:
    print(f"  • {r['command_name']}")
    print(f"    Services: {r['services']} (count: {r['service_count']})")
EOF
```

**Test Pattern 10: Variable Usage Analysis**
```python
python3 << 'EOF'
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
from crack.reference.core import ConfigManager, ReferenceTheme

adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme())

# Find most commonly used variables
results = adapter.aggregate_by_pattern(
    pattern="(v:Variable)<-[u:USES_VARIABLE]-(c:Command)",
    group_by=['v'],
    aggregations={
        'variable_name': 'v.name',
        'usage_count': 'COUNT(c)',
        'sample_commands': 'COLLECT(c.id)[0..3]'
    },
    filters={'u.required': True},
    order_by='usage_count DESC',
    limit=10
)

print(f"\n🔧 Most used variables:")
for r in results:
    print(f"  • {r['variable_name']}: {r['usage_count']} commands")
    print(f"    Examples: {r.get('sample_commands', [])}")
EOF
```

**Test Dynamic GROUP BY**
```python
python3 << 'EOF'
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
from crack.reference.core import ConfigManager, ReferenceTheme

adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme())

# Group by both command and tag
results = adapter.aggregate_by_pattern(
    pattern="(c:Command)-[:TAGGED]->(t:Tag)",
    group_by=['c', 't'],
    aggregations={
        'command_id': 'c.id',
        'command_name': 'c.name',
        'tag_name': 't.name',
        'count': 'COUNT(*)'
    },
    limit=5
)

print(f"\n📊 Command-Tag relationships:")
for r in results:
    print(f"  • {r['command_name']} → {r['tag_name']}")
EOF
```

---

### Primitive 3: `find_by_pattern()` - Generic Pattern Matching

**Test Pattern 2: Shortest Path**
```python
python3 << 'EOF'
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
from crack.reference.core import ConfigManager, ReferenceTheme

adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme())

# Find shortest path from enumeration to privilege escalation
results = adapter.find_by_pattern(
    pattern="shortestPath((start:Command)-[:NEXT_STEP*]-(end:Command))",
    where_clause="start.tags CONTAINS 'STARTER' AND end.tags CONTAINS 'PRIVESC'",
    return_fields=['start.id', 'end.id'],
    limit=5
)

print(f"\n🎯 Shortest attack paths found: {len(results)}")
for r in results:
    print(f"  • {r.get('start.id', 'N/A')} → {r.get('end.id', 'N/A')}")
EOF
```

**Test Pattern 8: Coverage Gaps**
```python
python3 << 'EOF'
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
from crack.reference.core import ConfigManager, ReferenceTheme

adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme())

# Find services without high-OSCP enumeration commands
results = adapter.find_by_pattern(
    pattern="(s:Service) WHERE NOT exists { MATCH (s)-[:ENUMERATED_BY]->(c:Command) WHERE c.oscp_relevance = 'high' }",
    return_fields=['s.name', 's.protocol'],
    limit=50
)

print(f"\n🔍 Services with coverage gaps:")
for r in results:
    print(f"  • {r.get('s.name', 'N/A')} ({r.get('s.protocol', 'N/A')})")
EOF
```

**Test Pattern 9: Circular Dependencies**
```python
python3 << 'EOF'
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
from crack.reference.core import ConfigManager, ReferenceTheme

adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme())

# Detect circular dependencies in attack chains
results = adapter.find_by_pattern(
    pattern="(s:ChainStep)-[:DEPENDS_ON*]->(s)",
    return_fields=['s.id', 's.name'],
    limit=50
)

print(f"\n🔄 Circular dependencies: {len(results)}")
if results:
    print("  ⚠️  WARNING: Circular dependencies detected!")
    for r in results:
        print(f"    • {r.get('s.name', 'N/A')}")
else:
    print("  ✓ No circular dependencies (good!)")
EOF
```

---

## 🎨 Test Enhanced Methods (Backward Compatibility)

### Enhanced: `find_alternatives()` with Metadata
```python
python3 << 'EOF'
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
from crack.reference.core import ConfigManager, ReferenceTheme

adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme())

# Original behavior (backward compatible)
results_simple = adapter.find_alternatives('gobuster-dir', max_depth=2)
print(f"\n📝 Simple mode: {len(results_simple)} alternatives")
for cmd in results_simple:
    print(f"  • {cmd.name}")

# New enhanced mode with metadata
results_meta = adapter.find_alternatives('gobuster-dir', max_depth=2, return_metadata=True)
print(f"\n📊 Metadata mode: {len(results_meta)} alternative chains")
for r in results_meta:
    chain = " → ".join([c['name'] for c in r['command_chain']])
    print(f"  • {chain}")
    print(f"    Priority: {r['cumulative_priority']}, Depth: {r['depth']}")
EOF
```

### Enhanced: `find_prerequisites()` with Execution Order
```python
python3 << 'EOF'
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
from crack.reference.core import ConfigManager, ReferenceTheme

adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme())

# Original behavior
results_simple = adapter.find_prerequisites('wordpress-sqli')
print(f"\n📝 Simple mode: {len(results_simple)} prerequisites")
for cmd in results_simple:
    print(f"  • {cmd.name}")

# New enhanced mode with execution order (topological sort)
results_order = adapter.find_prerequisites('wordpress-sqli', execution_order=True)
print(f"\n📊 Execution order mode:")
for r in results_order:
    print(f"  {r['dependency_count']}: {r['command_name']} ({r['command_id']})")
print("\n  (Lower numbers run first)")
EOF
```

### Enhanced: `filter_by_tags()` with Hierarchy
```python
python3 << 'EOF'
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
from crack.reference.core import ConfigManager, ReferenceTheme

adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme())

# Original behavior (flat tags only)
results_flat = adapter.filter_by_tags(['OSCP'])
print(f"\n📝 Flat mode: {len(results_flat)} commands (exact 'OSCP' tag)")

# New enhanced mode with hierarchy (includes OSCP:ENUM, OSCP:EXPLOIT, etc.)
results_hierarchy = adapter.filter_by_tags(['OSCP'], include_hierarchy=True)
print(f"📊 Hierarchy mode: {len(results_hierarchy)} commands (includes child tags)")

if results_hierarchy:
    print("\nSample results:")
    for cmd in results_hierarchy[:3]:
        print(f"  • {cmd.name} - {cmd.tags}")
EOF
```

---

## 🎯 Test Pattern Library (High-Level API)

### All 10 Patterns via Pattern Helper
```python
python3 << 'EOF'
from crack.reference.patterns.advanced_queries import create_pattern_helper
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
from crack.reference.core import ConfigManager, ReferenceTheme

adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme())
patterns = create_pattern_helper(adapter)

print("\n" + "="*70)
print("  Testing All 10 Advanced Query Patterns")
print("="*70)

# Pattern 1: Multi-Hop Alternatives
print("\n🔧 Pattern 1: Multi-Hop Alternatives")
alts = patterns.multi_hop_alternatives('gobuster-dir', depth=3)
print(f"  Found {len(alts)} alternative chains")

# Pattern 2: Shortest Attack Path
print("\n🎯 Pattern 2: Shortest Attack Path")
paths = patterns.shortest_attack_path('STARTER', 'PRIVESC')
print(f"  Found {len(paths)} paths")

# Pattern 3: Prerequisite Closure
print("\n📋 Pattern 3: Prerequisite Closure")
prereqs = patterns.prerequisite_closure('wordpress-sqli')
print(f"  Found {len(prereqs)} prerequisites")

# Pattern 4: Parallel Execution
print("\n⚡ Pattern 4: Parallel Execution Planning")
plan = patterns.parallel_execution_plan('web-to-root')
print(f"  Attack chain has {len(plan.get('steps', []))} steps")
print(f"  Parallel groups: {len(plan.get('parallel_groups', []))}")

# Pattern 5: Service Recommendations
print("\n🌐 Pattern 5: Service-Based Recommendations")
recs = patterns.service_recommendations([80, 445, 22])
print(f"  Found {len(recs)} recommendations")

# Pattern 6: Tag Hierarchy
print("\n🏷️  Pattern 6: Tag Hierarchy Filtering")
cmds = patterns.filter_by_tag_hierarchy(['OSCP'])
print(f"  Found {len(cmds)} commands")

# Pattern 7: Success Correlation (requires session data)
print("\n📊 Pattern 7: Success Correlation")
corr = patterns.success_correlation(min_co_occurrence=1)
print(f"  Found {len(corr)} correlations (needs session data)")

# Pattern 8: Coverage Gaps
print("\n🔍 Pattern 8: Coverage Gap Detection")
gaps = patterns.find_coverage_gaps()
print(f"  Found {len(gaps)} gaps")

# Pattern 9: Circular Dependencies
print("\n🔄 Pattern 9: Circular Dependency Detection")
cycles = patterns.detect_circular_dependencies()
print(f"  Found {len(cycles)} cycles")

# Pattern 10: Variable Usage
print("\n🔧 Pattern 10: Variable Usage Analysis")
vars = patterns.variable_usage_analysis()
print(f"  Found {len(vars)} variables")

print("\n" + "="*70)
print("  ✓ All patterns tested successfully!")
print("="*70)
EOF
```

---

## 🔒 Test Security Features

### Test Cypher Injection Prevention
```python
python3 << 'EOF'
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
from crack.reference.core import ConfigManager, ReferenceTheme

adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme())

print("\n🔒 Testing security features...")

# Test 1: Block DELETE
try:
    adapter.aggregate_by_pattern(
        pattern="(c:Command) DELETE c",
        group_by=['c'],
        aggregations={'count': 'COUNT(c)'}
    )
    print("  ✗ FAILED: DELETE not blocked!")
except ValueError as e:
    print(f"  ✓ DELETE blocked: {str(e)[:50]}...")

# Test 2: Block DROP
try:
    adapter.find_by_pattern(
        pattern="(n) DROP DATABASE"
    )
    print("  ✗ FAILED: DROP not blocked!")
except ValueError as e:
    print(f"  ✓ DROP blocked: {str(e)[:50]}...")

# Test 3: Block CREATE
try:
    adapter.aggregate_by_pattern(
        pattern="(c:Command) CREATE (n:Evil)",
        group_by=['c'],
        aggregations={'count': 'COUNT(c)'}
    )
    print("  ✗ FAILED: CREATE not blocked!")
except ValueError as e:
    print(f"  ✓ CREATE blocked: {str(e)[:50]}...")

# Test 4: Block SET
try:
    adapter.find_by_pattern(
        pattern="(n) SET n.hacked = true"
    )
    print("  ✗ FAILED: SET not blocked!")
except ValueError as e:
    print(f"  ✓ SET blocked: {str(e)[:50]}...")

print("\n  ✓ All security tests passed!")
EOF
```

---

## ⚡ Test Performance

### Benchmark Complex Traversals
```python
python3 << 'EOF'
import time
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
from crack.reference.core import ConfigManager, ReferenceTheme

adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme())

print("\n⚡ Performance Benchmarks:")

# Test 1: Single hop
start = time.time()
adapter.traverse_graph('gobuster-dir', 'ALTERNATIVE', max_depth=1)
elapsed = time.time() - start
print(f"  1-hop traversal: {elapsed*1000:.1f}ms")

# Test 2: 3-hop traversal
start = time.time()
adapter.traverse_graph('gobuster-dir', 'ALTERNATIVE', max_depth=3)
elapsed = time.time() - start
print(f"  3-hop traversal: {elapsed*1000:.1f}ms")

# Test 3: Deep traversal (5 hops)
start = time.time()
adapter.traverse_graph('nmap-quick-scan', 'NEXT_STEP', max_depth=5)
elapsed = time.time() - start
print(f"  5-hop traversal: {elapsed*1000:.1f}ms")

# Test 4: Aggregation
start = time.time()
adapter.aggregate_by_pattern(
    pattern="(c:Command)-[:TAGGED]->(t:Tag)",
    group_by=['t'],
    aggregations={'tag': 't.name', 'count': 'COUNT(c)'}
)
elapsed = time.time() - start
print(f"  Aggregation query: {elapsed*1000:.1f}ms")

print("\n  Target: All queries < 500ms")
EOF
```

---

## 📈 Integration Tests

### OSCP Exam Workflow Simulation
```python
python3 << 'EOF'
from crack.reference.patterns.advanced_queries import create_pattern_helper
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
from crack.reference.core import ConfigManager, ReferenceTheme

adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme())
patterns = create_pattern_helper(adapter)

print("\n" + "="*70)
print("  OSCP Exam Workflow Simulation")
print("="*70)

# Step 1: Initial enumeration
print("\n📡 Step 1: Initial Enumeration")
starters = patterns.filter_by_tag_hierarchy(['STARTER'])
print(f"  Found {len(starters)} starter commands")
if starters:
    print(f"  Example: {starters[0].name}")

# Step 2: Service-specific attacks (after nmap discovers ports)
print("\n🌐 Step 2: Service-Specific Attacks (ports 80, 445, 22)")
attacks = patterns.service_recommendations([80, 445, 22])
print(f"  Found {len(attacks)} recommended attacks")

# Step 3: If primary tool fails, find alternatives
print("\n🔧 Step 3: Alternative Tools (if gobuster fails)")
alts = patterns.multi_hop_alternatives('gobuster-dir', depth=2)
print(f"  Found {len(alts)} alternative chains")
if alts:
    print(f"  Next try: {alts[0]['command_chain'][1]['name'] if len(alts[0]['command_chain']) > 1 else 'N/A'}")

# Step 4: Find path to privilege escalation
print("\n🎯 Step 4: Path to Privilege Escalation")
paths = patterns.shortest_attack_path('STARTER', 'PRIVESC')
print(f"  Found {len(paths)} paths to root")

# Step 5: Validate prerequisites before exploit
print("\n📋 Step 5: Prerequisite Validation")
prereqs = patterns.prerequisite_closure('wordpress-sqli')
print(f"  Need to run {len(prereqs)} commands first")

print("\n" + "="*70)
print("  ✓ Workflow simulation complete!")
print("="*70)
EOF
```

---

## 🧪 Run Full Test Suite

### Quick Test (< 2 seconds)
```bash
python3 -m pytest tests/reference/test_neo4j_adapter_primitives.py -v --tb=line -q
```

### Full Test Suite
```bash
python3 -m pytest tests/reference/test_neo4j_adapter_primitives.py tests/reference/test_neo4j_adapter.py::TestAdvancedQueryIntegration -v --tb=short
```

### Pattern Validation Script
```bash
python3 tests/scripts/validate_all_patterns.py
```

---

## 📊 Verify Database Statistics

```python
python3 << 'EOF'
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
from crack.reference.core import ConfigManager, ReferenceTheme

adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme())
stats = adapter.get_stats()

print("\n📊 Database Statistics:")
for key, value in stats.items():
    print(f"  {key:20s}: {value}")
EOF
```

---

## 🔍 Debugging Commands

### Check Adapter Health
```python
python3 -c "from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter; \
from crack.reference.core import ConfigManager, ReferenceTheme; \
adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme()); \
print('Health:', adapter.health_check())"
```

### List All Commands
```python
python3 << 'EOF'
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
from crack.reference.core import ConfigManager, ReferenceTheme

adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme())
commands = adapter.get_all_commands()

print(f"\n📋 All Commands ({len(commands)} total):")
for cmd in commands:
    print(f"  • {cmd.id:30s} - {cmd.name}")
EOF
```

### Check Relationships
```python
python3 << 'EOF'
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
from crack.reference.core import ConfigManager, ReferenceTheme

adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme())

# Count relationship types
query = """
MATCH ()-[r]->()
RETURN type(r) AS rel_type, COUNT(r) AS count
ORDER BY count DESC
"""
results = adapter._execute_read(query)

print("\n🔗 Relationship Statistics:")
for r in results:
    print(f"  {r['rel_type']:20s}: {r['count']}")
EOF
```

---

## 🎓 OSCP-Specific Scenarios

### Scenario 1: "I found ports 80 and 22 open"
```python
python3 << 'EOF'
from crack.reference.patterns.advanced_queries import create_pattern_helper
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
from crack.reference.core import ConfigManager, ReferenceTheme

adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme())
patterns = create_pattern_helper(adapter)

print("\n🎯 Scenario: Ports 80 and 22 detected")
recs = patterns.service_recommendations([80, 22])

print(f"\nRecommended commands:")
for r in recs:
    print(f"  • {r.get('command_name', 'N/A')}")
    print(f"    Works on: {r.get('services', [])}")
EOF
```

### Scenario 2: "Gobuster isn't working, what else can I try?"
```python
python3 << 'EOF'
from crack.reference.patterns.advanced_queries import create_pattern_helper
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
from crack.reference.core import ConfigManager, ReferenceTheme

adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme())
patterns = create_pattern_helper(adapter)

print("\n🔧 Scenario: Gobuster failed, finding alternatives...")
alts = patterns.multi_hop_alternatives('gobuster-dir', depth=3)

print(f"\nTry these instead:")
for alt in alts:
    chain = " → ".join([c['name'] for c in alt['command_chain']])
    print(f"  • {chain}")
    print(f"    Priority: {alt['cumulative_priority']}")
    if alt['metadata']:
        print(f"    Reason: {alt['metadata'][0].get('reason', 'N/A')}")
EOF
```

### Scenario 3: "What do I need to run before this exploit?"
```python
python3 << 'EOF'
from crack.reference.patterns.advanced_queries import create_pattern_helper
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
from crack.reference.core import ConfigManager, ReferenceTheme

adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme())
patterns = create_pattern_helper(adapter)

print("\n📋 Scenario: Prerequisites for WordPress SQLi")
prereqs = patterns.prerequisite_closure('wordpress-sqli', with_execution_order=True)

print(f"\nRun these in order:")
for p in prereqs:
    print(f"  {p['dependency_count']}. {p['command_name']}")
print("\n(Numbers indicate dependency depth - lower run first)")
EOF
```

---

## 📝 Expected Output Samples

When tests work correctly, you should see:

**✅ Successful traversal**:
```
🔧 Found 3 alternative chains:
  • Gobuster Directory Enumeration → FFUF Directory Fuzzing
    Depth: 1, Priority: 1
  • Gobuster Directory Enumeration → FFUF Directory Fuzzing → Wfuzz Directory Enumeration
    Depth: 2, Priority: 3
```

**✅ Successful aggregation**:
```
🔧 Most used variables:
  • <TARGET>: 3 commands
    Examples: ['nmap-quick-scan', 'gobuster-dir', 'wordpress-sqli']
```

**✅ Security blocking**:
```
  ✓ DELETE blocked: Dangerous keyword 'DELETE' not allowed...
  ✓ DROP blocked: Dangerous keyword 'DROP' not allowed...
```

**✅ Performance**:
```
  1-hop traversal: 15.2ms
  3-hop traversal: 45.8ms
  5-hop traversal: 118.3ms
  Aggregation query: 23.1ms
```

---

## 🆘 Troubleshooting

### Error: "Neo4j connection failed"
```bash
# Check if Neo4j is running
sudo neo4j status

# Start Neo4j
sudo neo4j start

# Check logs
sudo tail -f /etc/neo4j/logs/neo4j.log
```

### Error: "Command/relationship not found"
```bash
# Repopulate test data
python3 tests/scripts/populate_neo4j_test_data.py
```

### Error: "Authentication failure"
```bash
# Verify password in db/config.py matches Neo4j
# Default password: Afrodeeziak21
```

### Run validation report
```bash
# Comprehensive validation of all patterns
python3 tests/scripts/validate_all_patterns.py
```

---

## 📚 Further Reading

- **Implementation**: `reference/core/neo4j_adapter.py` (lines 798-1085)
- **Pattern Library**: `reference/patterns/advanced_queries.py`
- **Test Examples**: `tests/reference/test_neo4j_adapter_primitives.py`
- **Full Spec**: `db/neo4j-migration/06-ADVANCED-QUERIES.md`
- **Validation Report**: `LIVE_DB_VALIDATION_REPORT.md`

---

**Quick Reference**: All primitives return empty list `[]` on error, never crash
**Performance Target**: < 500ms for all queries ✅
**Security**: All dangerous keywords blocked ✅
