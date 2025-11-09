# Neo4j CLI Integration Proposal

**Status**: Proposal
**Date**: 2025-11-08
**Context**: Neo4j Phase 5 primitives are implemented but not directly accessible from CLI

---

## Current State ✅

### What's Working

**Router Integration** (`reference/cli/main.py:55-153`):
- ✅ Auto-detection: Tries Neo4j → PostgreSQL → JSON
- ✅ Health checking displays Neo4j status
- ✅ Intelligent routing based on query complexity
- ✅ Automatic fallback on errors

**Query Routing** (`reference/core/router.py:174-249`):
```python
# These automatically use Neo4j when appropriate:
find_alternatives(depth≥2)    # Multi-hop graph traversal
find_prerequisites()          # Dependency chains
get_attack_chain_path()       # Attack sequences
```

**CLI Commands** (Transparent Neo4j Usage):
```bash
crack reference --status              # Shows Neo4j connection
crack reference gobuster-dir          # Uses Neo4j for alternatives
crack reference --chains web-to-root  # Uses Neo4j for path
```

---

## Gaps Identified ❌

### 1. No Direct Access to Graph Primitives

Users **cannot** directly invoke:
- `traverse_graph()` - Variable-length path traversal
- `aggregate_by_pattern()` - Template-based aggregation
- `find_by_pattern()` - Generic Cypher pattern matching

### 2. No Access to Pattern Library

10 OSCP-focused patterns exist but require Python code:
- Pattern 1: Multi-hop alternatives
- Pattern 2: Shortest attack path
- Pattern 3: Prerequisite closure
- Pattern 4: Parallel execution planning
- Pattern 5: Service recommendations
- Pattern 6: Tag hierarchy filtering
- Pattern 7: Success correlation
- Pattern 8: Coverage gap detection
- Pattern 9: Circular dependency detection
- Pattern 10: Variable usage analysis

### 3. Missing Exports

`reference/core/__init__.py` doesn't export:
- `Neo4jCommandRegistryAdapter`
- `reference.patterns.advanced_queries`

---

## Proposed CLI Enhancements

### Option A: Minimalist Approach ⭐ RECOMMENDED

**Add 2 new flags to existing CLI:**

```bash
# 1. Pattern library access
crack reference --pattern <pattern_name> [args]

# Examples:
crack reference --pattern multi-hop gobuster-dir --depth 3
crack reference --pattern service-rec --ports 80 445 22
crack reference --pattern prereqs wordpress-sqli --ordered
crack reference --pattern shortest-path STARTER PRIVESC
crack reference --pattern tag-hierarchy OSCP
crack reference --pattern coverage-gaps --oscp-only
crack reference --pattern circular-deps
crack reference --pattern var-usage

# 2. Force Neo4j backend (override router)
crack reference --backend neo4j gobuster-dir
crack reference --backend sql nmap
crack reference --backend json rdp
```

**Implementation:**
- Add `--pattern` flag to argparse (lines 295-300)
- Add `--backend` flag to argparse (lines 301-305)
- Create `GraphCLI` handler in `reference/cli/graph.py` (new file, ~150 LOC)
- Update `main.py` routing logic (lines 415-425)

**LOC Estimate**: ~200 LOC total

---

### Option B: Dedicated Graph Subcommand

**Add new subcommand structure:**

```bash
crack reference graph <operation> [args]

# Pattern operations
crack reference graph pattern multi-hop gobuster-dir --depth 3
crack reference graph pattern service-rec --ports 80 445

# Primitive operations
crack reference graph traverse gobuster-dir ALTERNATIVE --depth 3
crack reference graph aggregate "(p:Port)<-[:RUNS_ON]-(s:Service)" --group-by c
crack reference graph find "shortestPath((a)-[:NEXT_STEP*]->(b))"

# Status
crack reference graph status
crack reference graph health
```

**Implementation:**
- Add subparser for `graph` command
- Create `GraphCLI` with method handlers
- More flexible but more complex

**LOC Estimate**: ~400 LOC total

---

### Option C: Separate CLI Tool

**Create standalone `crack graph` command:**

```bash
crack graph traverse gobuster-dir ALTERNATIVE --depth 3
crack graph pattern multi-hop gobuster-dir
crack graph service-rec --ports 80 445 22
```

**Implementation:**
- New entry point in `setup.py` console_scripts
- Separate CLI module
- More isolated but requires separate installation

**LOC Estimate**: ~300 LOC total

---

## Recommendation: Option A (Minimalist)

**Rationale:**
- ✅ Minimal code additions (~200 LOC)
- ✅ Consistent with existing CLI patterns
- ✅ Most useful patterns accessible
- ✅ No breaking changes
- ✅ Follows "German Engineering" principle

**Implementation Plan:**

### Phase 1: Export Adapters (5 minutes)
```python
# reference/core/__init__.py
from .neo4j_adapter import Neo4jCommandRegistryAdapter
from reference.patterns.advanced_queries import create_pattern_helper, GraphQueryPatterns

__all__ = [
    # ... existing exports ...
    'Neo4jCommandRegistryAdapter',
    'create_pattern_helper',
    'GraphQueryPatterns'
]
```

### Phase 2: Add Flags (10 minutes)
```python
# reference/cli/main.py (after line 295)
parser.add_argument(
    '--pattern',
    choices=[
        'multi-hop', 'shortest-path', 'prereqs', 'parallel',
        'service-rec', 'tag-hierarchy', 'success-corr',
        'coverage-gaps', 'circular-deps', 'var-usage'
    ],
    help='Execute Neo4j graph pattern (requires Neo4j backend)'
)

parser.add_argument(
    '--backend',
    choices=['auto', 'neo4j', 'sql', 'json'],
    default='auto',
    help='Force specific backend (default: auto)'
)
```

### Phase 3: Create GraphCLI Handler (30 minutes)
```python
# reference/cli/graph.py (NEW FILE)
class GraphCLI:
    """Handler for Neo4j graph pattern operations"""

    def __init__(self, registry, theme):
        self.registry = registry
        self.theme = theme

        # Initialize pattern helper if Neo4j available
        if hasattr(registry, 'neo4j_adapter') and registry.neo4j_adapter:
            from reference.patterns.advanced_queries import create_pattern_helper
            self.patterns = create_pattern_helper(registry.neo4j_adapter)
        else:
            self.patterns = None

    def execute_pattern(self, pattern_name: str, args):
        """Execute named pattern with arguments"""
        if not self.patterns:
            print(self.theme.error("Neo4j backend not available"))
            print(self.theme.hint("Patterns require Neo4j. Check: crack reference --status"))
            return 1

        # Map pattern names to methods
        pattern_map = {
            'multi-hop': self._multi_hop,
            'shortest-path': self._shortest_path,
            'prereqs': self._prerequisites,
            'service-rec': self._service_recommendations,
            # ... etc
        }

        handler = pattern_map.get(pattern_name)
        if not handler:
            print(self.theme.error(f"Unknown pattern: {pattern_name}"))
            return 1

        return handler(args)

    def _multi_hop(self, args):
        """Pattern 1: Multi-hop alternatives"""
        if not args.args:
            print(self.theme.error("Usage: crack reference --pattern multi-hop <command_id> [--depth N]"))
            return 1

        command_id = args.args[0]
        depth = getattr(args, 'depth', 3)

        results = self.patterns.multi_hop_alternatives(command_id, depth=depth)

        # Display results
        if not results:
            print(self.theme.hint(f"No alternatives found for {command_id}"))
            return 0

        print(f"\n{self.theme.command_name('Alternative Command Chains:')}\n")
        for i, alt in enumerate(results, 1):
            chain = ' → '.join([c['name'] for c in alt['command_chain']])
            print(f"{i}. {chain}")
            print(f"   Depth: {alt['depth']}, Priority: {alt.get('cumulative_priority', 'N/A')}")
            if alt.get('metadata'):
                reason = alt['metadata'][0].get('reason', 'N/A')
                print(f"   Reason: {self.theme.hint(reason)}")
            print()

        return 0
```

### Phase 4: Update Main Routing (10 minutes)
```python
# reference/cli/main.py (after line 415)
# Handle pattern flag
if args.pattern:
    graph_cli = GraphCLI(registry=self.registry, theme=self.theme)
    return graph_cli.execute_pattern(args.pattern, args)

# Handle backend override
if args.backend and args.backend != 'auto':
    # Force specific backend (advanced users)
    if args.backend == 'neo4j':
        if hasattr(self.registry, 'neo4j_adapter') and self.registry.neo4j_adapter:
            self.registry = self.registry.neo4j_adapter
        else:
            print(self.theme.error("Neo4j backend not available"))
            return 1
    # ... etc
```

---

## Usage Examples (After Implementation)

### OSCP Exam Scenarios

**Scenario 1: "Gobuster isn't working"**
```bash
crack reference --pattern multi-hop gobuster-dir --depth 3

# Output:
Alternative Command Chains:

1. Gobuster → FFUF
   Depth: 1, Priority: 1
   Reason: Faster for small wordlists

2. Gobuster → FFUF → Wfuzz
   Depth: 2, Priority: 3
   Reason: More features
```

**Scenario 2: "Ports 80, 445 open - what to enumerate?"**
```bash
crack reference --pattern service-rec --ports 80 445 22

# Output:
Service Recommendations:

1. Nmap NSE Scripts
   Works on: http, smb, ssh
   Service count: 3

2. Enum4linux
   Works on: smb
   Service count: 1
```

**Scenario 3: "What prerequisites does this exploit need?"**
```bash
crack reference --pattern prereqs wordpress-sqli --ordered

# Output:
Prerequisites (Execution Order):

1. Create Output Dir (0 dependencies)
2. Nmap Service Scan (1 dependency)
3. Gobuster Dir Enum (2 dependencies)
4. WordPress SQLi (3 dependencies)
```

---

## Testing Plan

### 1. Unit Tests (`tests/reference/cli/test_graph_cli.py`)
```python
def test_multi_hop_pattern(mock_registry):
    """Test multi-hop pattern execution"""
    graph_cli = GraphCLI(registry=mock_registry, theme=ReferenceTheme())
    result = graph_cli.execute_pattern('multi-hop', args)
    assert result == 0

def test_pattern_no_neo4j(json_registry):
    """Test graceful failure when Neo4j unavailable"""
    graph_cli = GraphCLI(registry=json_registry, theme=ReferenceTheme())
    result = graph_cli.execute_pattern('multi-hop', args)
    assert result == 1  # Error code
```

### 2. Integration Tests
```bash
# Test with live database
python3 -m pytest tests/reference/cli/test_graph_cli_integration.py -v
```

### 3. Manual Validation
```bash
# Run all pattern examples from TESTING_GUIDE.md via CLI
./tests/scripts/validate_cli_patterns.sh
```

---

## Timeline

| Phase | LOC | Time | Blocking |
|-------|-----|------|----------|
| 1. Export adapters | 5 | 5 min | No |
| 2. Add flags | 20 | 10 min | Phase 1 |
| 3. Create GraphCLI | 150 | 30 min | Phase 1 |
| 4. Update routing | 25 | 10 min | Phase 3 |
| 5. Unit tests | 100 | 20 min | Phase 3 |
| 6. Documentation | 50 | 15 min | All |
| **Total** | **350** | **90 min** | |

---

## Success Criteria

- ✅ All 10 patterns accessible via `--pattern` flag
- ✅ Graceful error when Neo4j unavailable
- ✅ Consistent output formatting with existing CLI
- ✅ 100% test coverage for GraphCLI
- ✅ Documentation updated (CLAUDE.md, --help text)
- ✅ Zero breaking changes to existing CLI

---

## Alternative: Python API Only

**If CLI integration is too complex, users can access patterns via Python:**

```python
from crack.reference.core import Neo4jCommandRegistryAdapter, ConfigManager, ReferenceTheme
from crack.reference.patterns.advanced_queries import create_pattern_helper

adapter = Neo4jCommandRegistryAdapter(ConfigManager(), ReferenceTheme())
patterns = create_pattern_helper(adapter)

# Use patterns
alternatives = patterns.multi_hop_alternatives('gobuster-dir', depth=3)
recommendations = patterns.service_recommendations([80, 445, 22])
```

**Pros:**
- Zero implementation cost
- More flexible for scripting
- All features already available

**Cons:**
- Requires Python knowledge
- Not accessible from pure CLI workflow
- Extra step for OSCP exam scenarios

---

## Decision Required

Which option should we implement?

- [ ] **Option A**: Minimalist (`--pattern` flag) - 200 LOC, 60 min
- [ ] **Option B**: Subcommand (`crack reference graph`) - 400 LOC, 120 min
- [ ] **Option C**: Separate tool (`crack graph`) - 300 LOC, 90 min
- [ ] **No CLI**: Python API only (current state)

**Recommendation**: **Option A** (Minimalist) for best ROI and minimal code bloat.
