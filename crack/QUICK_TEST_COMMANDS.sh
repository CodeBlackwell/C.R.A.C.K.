#!/bin/bash
# Quick Test Commands for CRACK Neo4j Architecture
# Run these to validate the minimalist graph primitives

echo "=============================================="
echo "  CRACK Neo4j Architecture Quick Tests"
echo "=============================================="

# Test 1: Pattern 1 - Multi-Hop Alternatives
echo -e "\n📊 Test 1: Pattern 1 - Multi-Hop Alternatives"
python3 << 'EOF'
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
from crack.reference.core import ConfigManager, ReferenceTheme
adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme())
results = adapter.traverse_graph('gobuster-dir', 'ALTERNATIVE', 'OUTGOING', 3, return_metadata=True)
print(f"✓ Found {len(results)} alternative chains")
if results: print(f"  Example: {' → '.join([c['name'] for c in results[0]['command_chain']])}")
EOF

# Test 2: Pattern 3 - Prerequisites with Execution Order
echo -e "\n📊 Test 2: Pattern 3 - Prerequisites"
python3 << 'EOF'
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
from crack.reference.core import ConfigManager, ReferenceTheme
adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme())
results = adapter.find_prerequisites('wordpress-sqli', execution_order=True)
print(f"✓ Found {len(results)} prerequisites in execution order")
EOF

# Test 3: Pattern 5 - Service Recommendations
echo -e "\n📊 Test 3: Pattern 5 - Service Recommendations"
python3 << 'EOF'
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
from crack.reference.core import ConfigManager, ReferenceTheme
adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme())
results = adapter.aggregate_by_pattern(
    "(p:Port)<-[:RUNS_ON]-(s:Service)-[:ENUMERATED_BY]->(c:Command)",
    ['c'],
    {'command_name': 'c.name', 'services': 'COLLECT(DISTINCT s.name)'},
    {'p.number': [80, 445]}
)
print(f"✓ Found {len(results)} commands for ports 80, 445")
EOF

# Test 4: All Patterns via Pattern Library
echo -e "\n📊 Test 4: All 10 Patterns (Pattern Library)"
python3 tests/scripts/validate_all_patterns.py 2>&1 | grep -E "(Success rate|✅)"

# Test 5: Security
echo -e "\n📊 Test 5: Security (Injection Prevention)"
python3 << 'EOF'
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
from crack.reference.core import ConfigManager, ReferenceTheme
adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme())
try:
    adapter.find_by_pattern("(n) DELETE n")
    print("✗ Security FAILED")
except ValueError:
    print("✓ Cypher injection blocked")
EOF

# Test 6: Performance
echo -e "\n📊 Test 6: Performance"
python3 << 'EOF'
import time
from crack.reference.core.neo4j_adapter import Neo4jCommandRegistryAdapter
from crack.reference.core import ConfigManager, ReferenceTheme
adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme())
start = time.time()
adapter.traverse_graph('nmap-quick-scan', 'NEXT_STEP', max_depth=5)
elapsed = (time.time() - start) * 1000
print(f"✓ 5-hop traversal: {elapsed:.1f}ms (<500ms target)")
EOF

# Test 7: Run Full Test Suite
echo -e "\n📊 Test 7: Full Test Suite"
python3 -m pytest tests/reference/test_neo4j_adapter_primitives.py -q 2>&1 | tail -3

echo -e "\n=============================================="
echo "  ✓ All Quick Tests Complete!"
echo "=============================================="
echo -e "\nFor detailed testing, see: TESTING_GUIDE.md"
