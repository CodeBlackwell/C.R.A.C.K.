# JSON to Neo4j Migration Blueprint

**Date**: 2025-11-08
**Status**: Investigation Complete - Schema Violations Identified
**Scope**: 795 commands across 100+ JSON files

---

## Executive Summary

### Current State
- ✅ **10 commands** in Neo4j (test data only)
- ✅ **795 commands** in JSON files
- ❌ **JSON schema violations** prevent direct migration
- ❌ **73% of alternatives use text instead of IDs**
- ❌ **57% of prerequisites use text instead of IDs**

### Required Actions
1. **Fix JSON schema violations** (574 violations across 575 commands)
2. **Create mapping rules** for text → ID conversion
3. **Build migration script** with validation
4. **Verify graph relationships** in Neo4j

---

## Schema Analysis Results

### By the Numbers

| Metric | Count | Percentage | Status |
|--------|-------|------------|--------|
| **Total Commands** | 795 | 100% | ✅ Counted |
| **Commands with alternatives** | 526 | 66.2% | ⚠️ Mixed |
| **  ✓ Using IDs (correct)** | 140 | 26.6% | ✅ Compliant |
| **  ✗ Using text (violation)** | 386 | 73.4% | ❌ Must fix |
| **Commands with prerequisites** | 332 | 41.8% | ⚠️ Mixed |
| **  ✓ Using IDs (correct)** | 143 | 43.1% | ✅ Compliant |
| **  ✗ Using text (violation)** | 189 | 56.9% | ❌ Must fix |
| **Commands with next_steps** | 646 | 81.3% | ⚠️ Unknown |

**Total Violations**: ~575 commands need fixing

---

## Schema Violations Detailed

### Violation Type 1: Alternatives as Text

**What CLAUDE.md says:**
```json
"alternatives": ["smb-server", "scp-transfer"]  // ✓ Command IDs
```

**What JSON files actually have:**
```json
"alternatives": [
  "dirb <URL>",                               // ✗ Command text
  "ffuf -u <URL>/FUZZ -w <WORDLIST>",        // ✗ Command text
  "wfuzz -u <URL>/FUZZ -w <WORDLIST>"        // ✗ Command text
]
```

**Examples Found:**
```
nmap-ping-sweep:
  - "fping -a -g <TARGET_SUBNET>"           ← Should be: "fping-sweep"
  - "arp-scan -l"                            ← Should be: "arp-scan-local"

gobuster-dir:
  - "dirb <URL>"                             ← Should be: "dirb-scan"
  - "ffuf -u <URL>/FUZZ -w <WORDLIST>"      ← Should be: "ffuf-dir"
  - "wfuzz -u <URL>/FUZZ -w <WORDLIST>"     ← Should be: "wfuzz-dir"
```

**Impact**: Cannot create Neo4j `[:ALTERNATIVE]` relationships without command IDs

---

### Violation Type 2: Prerequisites as Text

**What CLAUDE.md says:**
```json
"prerequisites": ["mkdir-output-dir", "start-listener"]  // ✓ Command IDs
```

**What JSON files actually have:**
```json
"prerequisites": [
  "mkdir -p <LOCAL_PATH>",                    // ✗ Command text
  "sudo nmap -p <PORT> -Pn -v <TARGET>"      // ✗ Command text
]
```

**Examples Found:**
```
iptables-allow-port:
  - "sudo iptables -L -v -n"                 ← Should be: "iptables-list-rules"

rdesktop-disk-share:
  - "mkdir -p <LOCAL_PATH>"                  ← Should be: "mkdir-directory"
  - "sudo nmap -p <PORT> -Pn -v <TARGET>"   ← Should be: "nmap-port-check"
```

**Impact**: Cannot create Neo4j `[:PREREQUISITE]` relationships without command IDs

---

### Violation Type 3: Next Steps as Text (Unknown)

**Current format** (assumed):
```json
"next_steps": [
  "Investigate found directories: curl <URL>/<FOUND_DIR>",
  "Scan subdirectories: gobuster dir -u <URL>/<DIR> -w <WORDLIST>"
]
```

**Neo4j expects** (from schema):
```cypher
(cmd1)-[:NEXT_STEP]->(cmd2)
```

**Question**: Should `next_steps` be:
1. **Converted to IDs** like alternatives/prerequisites?
2. **Kept as text** (guidance notes, not executable commands)?
3. **Split** into executable commands (IDs) vs notes (text)?

**Recommendation**: Keep as text (they're workflow guidance, not strict prerequisites)

---

## Required JSON Changes

### Approach 1: Manual Correction ❌
- **Effort**: 575 commands × 2-5 violations each = 1,500+ edits
- **Time**: 40-60 hours
- **Error Rate**: High (manual typing)
- **Scalability**: None

### Approach 2: Automated Mapping ✅ RECOMMENDED
- **Effort**: Build smart mapping rules (~8 hours)
- **Time**: 2-4 hours to run + validate
- **Error Rate**: Low (algorithmic)
- **Scalability**: Reusable for future commands

---

## Automated Mapping Strategy

### Phase 1: Build Command Registry Index

Create searchable index of all command IDs:
```python
registry = {
    'fping-sweep': {
        'name': 'Fping Network Sweep',
        'command': 'fping -a -g <TARGET_SUBNET>',
        'keywords': ['fping', 'sweep', 'network']
    },
    'gobuster-dir': {
        'name': 'Directory Bruteforce',
        'command': 'gobuster dir -u <URL> -w <WORDLIST>',
        'keywords': ['gobuster', 'dir', 'directory', 'bruteforce']
    },
    # ... 795 total
}
```

### Phase 2: Text → ID Mapping Rules

**Rule 1: Exact Command Match**
```python
# If alternative text matches a command template exactly
"fping -a -g <TARGET_SUBNET>" → "fping-sweep"  # ✓ Found exact match
```

**Rule 2: Primary Tool Name Match**
```python
# Extract primary tool from text
"dirb <URL>" → extract "dirb" → search for "dirb-*" → "dirb-scan"
"ffuf -u <URL>/FUZZ" → extract "ffuf" → "ffuf-dir"
```

**Rule 3: Fuzzy Semantic Match**
```python
# Match by keywords in description
"masscan -p1-65535 <TARGET>" → keywords: ["masscan", "port", "scan"]
                             → search registry for "masscan"
                             → "masscan-full-scan"
```

**Rule 4: Create New Command ID**
```python
# If no match found, generate ID from text
"sudo iptables -L -v -n" → generate: "iptables-list-verbose"
                         → add to registry (new command)
```

### Phase 3: Validation Rules

**Rule V1: Verify Target Exists**
```python
# After mapping, ensure all IDs reference real commands
for cmd in commands:
    for alt_id in cmd['alternatives']:
        assert alt_id in registry, f"Alternative '{alt_id}' not found"
```

**Rule V2: No Self-References**
```python
# Command can't be alternative/prerequisite to itself
assert cmd['id'] not in cmd['alternatives']
assert cmd['id'] not in cmd['prerequisites']
```

**Rule V3: No Circular Dependencies**
```python
# A → B → A is invalid for prerequisites
detect_cycles(prerequisite_graph)
```

---

## Migration Script Architecture

```
scripts/
└── neo4j_migration/
    ├── 01_analyze_json_schema.py      (DONE - analysis complete)
    ├── 02_build_command_index.py       (Build registry index)
    ├── 03_map_text_to_ids.py          (Apply mapping rules)
    ├── 04_validate_mappings.py        (Run validation checks)
    ├── 05_fix_json_files.py           (Update JSON in-place)
    ├── 06_migrate_to_neo4j.py         (Load into Neo4j)
    └── 07_verify_graph.py             (Run Neo4j queries to verify)
```

### Script 02: Build Command Index

**Input**: All JSON files
**Output**: `command_index.json`

```json
{
  "fping-sweep": {
    "id": "fping-sweep",
    "name": "Fping Network Sweep",
    "command": "fping -a -g <TARGET_SUBNET>",
    "primary_tool": "fping",
    "keywords": ["fping", "sweep", "network", "icmp"],
    "file": "reference/data/commands/enumeration/network.json"
  }
}
```

### Script 03: Map Text to IDs

**Input**:
- JSON files with violations
- `command_index.json`

**Output**: `mapping_report.json`

```json
{
  "successful_mappings": [
    {
      "command_id": "nmap-ping-sweep",
      "field": "alternatives",
      "old_value": "fping -a -g <TARGET_SUBNET>",
      "new_value": "fping-sweep",
      "confidence": "exact_match"
    }
  ],
  "failed_mappings": [
    {
      "command_id": "some-command",
      "field": "alternatives",
      "old_value": "custom bash script",
      "reason": "no_match_found",
      "suggestion": "create new command: bash-custom-script"
    }
  ],
  "stats": {
    "total_violations": 575,
    "auto_mapped": 450,
    "needs_review": 125
  }
}
```

### Script 04: Validate Mappings

**Checks**:
1. All mapped IDs exist in registry
2. No self-references
3. No circular prerequisites
4. Graph is acyclic (for prerequisites)
5. Alternative chains don't loop

**Output**: `validation_report.json`

### Script 05: Fix JSON Files

**Action**: Update JSON files in-place with corrected IDs

**Backup**: Create `.backup` files before modifying

**Example diff**:
```diff
  "alternatives": [
-   "dirb <URL>",
-   "ffuf -u <URL>/FUZZ -w <WORDLIST>"
+   "dirb-scan",
+   "ffuf-dir"
  ]
```

### Script 06: Migrate to Neo4j

**Input**: Corrected JSON files
**Output**: Neo4j graph with 795 commands

**Creates**:
- 795 `(:Command)` nodes
- ~2,500 `[:TAGGED]` relationships (avg 3 tags per command)
- ~800 `[:ALTERNATIVE]` relationships
- ~450 `[:PREREQUISITE]` relationships
- ~600 `[:NEXT_STEP]` relationships (if implemented)

### Script 07: Verify Graph

**Runs queries**:
```cypher
// Check node counts
MATCH (c:Command) RETURN count(c) AS commands
// Should return: 795

// Check for orphaned alternatives
MATCH (c1:Command)-[:ALTERNATIVE]->(c2:Command)
WHERE NOT exists(c2)
RETURN count(*) AS orphans
// Should return: 0

// Test multi-hop alternatives
MATCH path = (start:Command {id: 'gobuster-dir'})-[:ALTERNATIVE*1..3]->(alt)
RETURN alt.name, length(path) AS depth
// Should return: 2-3 alternatives
```

---

## Decision Points

### 1. Handle Text-Only Alternatives/Prerequisites?

**Option A**: Create generic commands for common patterns
```json
// Before:
"prerequisites": ["mkdir -p <OUTPUT_DIR>"]

// After: Create new command
{
  "id": "mkdir-directory",
  "name": "Create Directory",
  "command": "mkdir -p <DIRECTORY>",
  "category": "utility"
}

// Then reference it:
"prerequisites": ["mkdir-directory"]
```

**Option B**: Keep text-only in separate field
```json
{
  "prerequisites_commands": ["some-command-id"],
  "prerequisites_text": ["mkdir -p <OUTPUT_DIR>"]
}
```

**Recommendation**: **Option A** - create generic utility commands

---

### 2. Next Steps: IDs or Text?

**Option A**: Convert to IDs (strict graph)
- Pros: Full graph traversal support
- Cons: 646 commands × 3-5 next steps = 2,000+ mappings

**Option B**: Keep as text (guidance only)
- Pros: No mapping needed, preserves workflow notes
- Cons: Can't query next-step relationships

**Recommendation**: **Option B** - keep next_steps as text (they're guidance, not strict prerequisites)

---

### 3. Confidence Thresholds for Auto-Mapping

**High Confidence** (auto-apply):
- Exact command template match
- Primary tool name + category match

**Medium Confidence** (manual review):
- Fuzzy keyword match
- Similar description

**Low Confidence** (flag for creation):
- No match found
- Generic text like "manual testing"

**Recommendation**: Auto-apply high confidence (80%+), flag rest for review

---

## Estimated Effort

| Phase | Task | Effort | Owner |
|-------|------|--------|-------|
| 1 | Build command index | 2 hours | Script |
| 2 | Implement mapping rules | 4 hours | Dev |
| 3 | Run auto-mapping | 30 min | Script |
| 4 | Review failed mappings | 2 hours | Human |
| 5 | Create missing commands | 1 hour | Human |
| 6 | Validate mappings | 30 min | Script |
| 7 | Fix JSON files | 15 min | Script |
| 8 | Migrate to Neo4j | 30 min | Script |
| 9 | Verify graph | 1 hour | Human |
| **TOTAL** | | **~12 hours** | |

---

## Risks and Mitigation

### Risk 1: Data Loss During JSON Updates

**Mitigation**:
- Create backups before modification
- Use atomic file operations
- Git commit before running scripts
- Validate JSON after updates

### Risk 2: Incorrect Mappings

**Mitigation**:
- Human review for medium/low confidence matches
- Require minimum confidence threshold (80%)
- Generate detailed mapping reports
- Allow rollback via backups

### Risk 3: Circular Dependencies

**Mitigation**:
- Run cycle detection before Neo4j migration
- Flag circular chains for manual review
- Implement topological sort validation

### Risk 4: Missing Commands

**Mitigation**:
- Track all "no match found" cases
- Generate command creation templates
- Batch-create utility commands (mkdir, cd, etc.)

---

## Success Criteria

1. ✅ **All 795 commands** loaded into Neo4j
2. ✅ **Zero schema violations** in JSON files
3. ✅ **95%+ auto-mapping** success rate
4. ✅ **All graph queries** from patterns working
5. ✅ **No orphaned relationships** in Neo4j
6. ✅ **Circular dependencies** = 0
7. ✅ **CLI shows "795 commands"** not "10 commands"

---

## Recommended Execution Order

```bash
# Phase 1: Prepare (1 hour)
python3 scripts/neo4j_migration/02_build_command_index.py
# Output: command_index.json (795 entries)

# Phase 2: Auto-map (30 min)
python3 scripts/neo4j_migration/03_map_text_to_ids.py
# Output: mapping_report.json (450 auto-mapped, 125 need review)

# Phase 3: Manual review (2 hours)
# Review mapping_report.json
# Fix low-confidence mappings manually

# Phase 4: Validate (30 min)
python3 scripts/neo4j_migration/04_validate_mappings.py
# Checks: no orphans, no cycles, all IDs valid

# Phase 5: Apply fixes (15 min)
git commit -am "Backup before JSON migration"
python3 scripts/neo4j_migration/05_fix_json_files.py
# Updates all JSON files in-place

# Phase 6: Migrate (30 min)
python3 scripts/neo4j_migration/06_migrate_to_neo4j.py
# Loads 795 commands into Neo4j

# Phase 7: Verify (1 hour)
python3 scripts/neo4j_migration/07_verify_graph.py
crack reference --status  # Should show 795 commands
crack reference --graph multi-hop gobuster-dir  # Test patterns
```

---

## Next Steps

**Immediate**:
1. ✅ Review this blueprint
2. ✅ Approve/reject approach
3. ⏳ Implement Script 02 (command index)

**Short-term**:
4. ⏳ Implement Scripts 03-05 (mapping + fixing)
5. ⏳ Manual review of failed mappings

**Medium-term**:
6. ⏳ Implement Scripts 06-07 (migration + verification)
7. ⏳ Update CLI to show correct count

---

## Open Questions

1. **Should we create generic utility commands?** (mkdir, cd, curl basic, etc.)
   - Recommendation: Yes, ~20 common utilities

2. **Should next_steps become IDs or stay as text?**
   - Recommendation: Stay as text (guidance, not strict relationships)

3. **What confidence threshold for auto-mapping?**
   - Recommendation: 80% (exact match + tool name match)

4. **Should we update CLAUDE.md to reflect reality?**
   - Recommendation: Yes, after migration completes

5. **Backup strategy for JSON files?**
   - Recommendation: Git commit + `.backup` suffix files

---

**Status**: ✅ Investigation Complete - Awaiting Approval to Proceed
**Next Action**: Review blueprint → Implement Script 02 (command index)
