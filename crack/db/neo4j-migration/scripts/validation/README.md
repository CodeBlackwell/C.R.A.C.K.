# Database Diagnostic Utilities

**Fast debugging tools for JSON and Neo4j data validation**

---

## Quick Start

```bash
# Run comprehensive diagnostic report (fastest)
./quick_report.sh

# With detailed violation examples
./quick_report.sh --verbose

# Save output to timestamped file
./quick_report.sh --save

# All options
./quick_report.sh --verbose --save
```

---

## Individual Utilities

### 1. JSON Statistics (`json_stats.py`)

**Purpose**: Analyze JSON command files for schema compliance and statistics

**Usage**:
```bash
python3 json_stats.py             # Quick stats
python3 json_stats.py --verbose   # Include violation examples
```

**Output**:
- Total commands and files
- Category breakdown with percentages
- OSCP relevance distribution
- Top 10 tags
- Field presence (alternatives, prerequisites, etc.)
- **Schema violations** (alternatives/prerequisites using text vs IDs)
- Duplicate ID detection
- Missing required fields

**Example Output**:
```
JSON COMMAND FILES - QUICK STATS
======================================================================

Basic Statistics:
  Files scanned:      42
  Total commands:     795

Commands by Category:
  web                   245 (30.8%) ████████████████
  enumeration           198 (24.9%) ████████████
  exploitation          156 (19.6%) ██████████
  ...

Schema Compliance:
  Alternatives:
    ✓ Using IDs (correct):   140 (26.6%)
    ✗ Using text (wrong):    386 (73.4%)
  Prerequisites:
    ✓ Using IDs (correct):   143 (43.1%)
    ✗ Using text (wrong):    189 (56.9%)
```

**When to Use**:
- Before running migration (check for violations)
- After fixing JSON files (verify corrections)
- General data quality checks

---

### 2. Neo4j Statistics (`neo4j_stats.py`)

**Purpose**: Analyze Neo4j graph database for integrity and statistics

**Usage**:
```bash
python3 neo4j_stats.py             # Quick stats
python3 neo4j_stats.py --verbose   # Include issue details
```

**Requirements**:
- Neo4j must be running (`sudo neo4j status`)
- Database accessible on default port

**Output**:
- Node counts (Command, Tag, Service, etc.)
- Relationship counts (TAGGED, ALTERNATIVE, etc.)
- Commands by category
- OSCP relevance distribution
- Top 10 tags
- **Graph integrity checks**:
  - Orphaned alternatives
  - Self-referencing relationships
  - Circular dependencies
  - Untagged commands
- **Graph pattern support tests**:
  - Multi-hop alternatives
  - Tag hierarchy depth
  - Attack chains

**Example Output**:
```
NEO4J DATABASE - QUICK STATS
======================================================================

✓ Connected to Neo4j

Node Counts:
  Command           795
  Tag                45
  Service            12
  Port              100
  Total             952

Relationship Counts:
  TAGGED          2,385
  ALTERNATIVE       850
  PREREQUISITE      450
  Total           3,685

Graph Integrity Checks:
  ✓ No orphaned alternatives
  ✓ No self-referencing alternatives
  ✓ No circular prerequisites
  ✓ All commands have tags

✓ Database healthy - 795 commands loaded
```

**When to Use**:
- After migration (verify data loaded correctly)
- Debug graph queries (check integrity)
- Monitor database health

---

### 3. Backend Comparison (`compare_backends.py`)

**Purpose**: Compare JSON and Neo4j data to find discrepancies

**Usage**:
```bash
python3 compare_backends.py
```

**Requirements**:
- Neo4j running
- JSON files present

**Output**:
- Command count comparison
- Category distribution diff
- OSCP relevance diff
- **Command ID differences**:
  - Common IDs (in both)
  - Only in JSON (not migrated)
  - Only in Neo4j (extra data)
- Migration status summary

**Example Output**:
```
JSON vs NEO4J - COMPARISON REPORT
======================================================================

Command Counts:
  JSON:      795
  Neo4j:      10
  Missing in Neo4j:  785 (98.7%)

Categories Comparison:
  Category              JSON   Neo4j    Diff
  --------------------------------------------------
  web                    245      3    +242
  enumeration            198      2    +196
  exploitation           156      2    +154

Command ID Comparison:
  Common IDs:              10
  Only in JSON:           785
  Only in Neo4j:            0

⚠ Migration incomplete (1.3% migrated)
  785 commands still need migration
```

**When to Use**:
- Check migration progress
- Identify missing commands
- Verify data consistency
- Debug discrepancies

---

### 4. Quick Report (`quick_report.sh`)

**Purpose**: Run all diagnostics and generate comprehensive report

**Usage**:
```bash
./quick_report.sh                    # Standard report
./quick_report.sh --verbose          # Detailed violations
./quick_report.sh --save             # Save to /tmp/crack_db_report_*.txt
./quick_report.sh --verbose --save   # All options
```

**Features**:
- Runs all 3 utilities in sequence
- Color-coded output
- Summary with recommendations
- Optional file save with timestamp
- Neo4j status check (skips if not running)

**Output Structure**:
```
╔════════════════════════════════════════════════════════╗
║  CRACK DATABASE DIAGNOSTIC REPORT                      ║
╚════════════════════════════════════════════════════════╝

1. JSON FILE ANALYSIS
   [json_stats.py output]

2. NEO4J DATABASE ANALYSIS
   [neo4j_stats.py output]

3. BACKEND COMPARISON
   [compare_backends.py output]

╔════════════════════════════════════════════════════════╗
║  DIAGNOSTIC SUMMARY                                    ║
╚════════════════════════════════════════════════════════╝

✓ JSON files analyzed successfully
✓ Neo4j database analyzed successfully
✓ Backend comparison completed

Recommendations:
  ℹ Run with --verbose for detailed violation examples
  ℹ Run with --save to save output to file
```

**When to Use**:
- Daily health checks
- Before/after migrations
- Debugging sessions
- Generating reports for review

---

## Use Cases

### Use Case 1: Pre-Migration Check

**Goal**: Verify JSON files are ready for migration

```bash
# Check for violations
python3 json_stats.py

# If violations found, get details
python3 json_stats.py --verbose > violations.txt

# Review violations.txt and fix JSON files
```

**Success Criteria**:
- ✓ No schema violations
- ✓ All alternatives/prerequisites are IDs
- ✓ No duplicate command IDs

---

### Use Case 2: Post-Migration Verification

**Goal**: Verify migration completed successfully

```bash
# Run comprehensive check
./quick_report.sh --verbose --save

# Check specific issues
python3 neo4j_stats.py --verbose

# Verify counts match
python3 compare_backends.py
```

**Success Criteria**:
- ✓ JSON count == Neo4j count
- ✓ No orphaned relationships
- ✓ No circular dependencies
- ✓ All graph patterns working

---

### Use Case 3: Debugging Graph Queries

**Goal**: Find why graph pattern returns unexpected results

```bash
# Check graph integrity
python3 neo4j_stats.py --verbose

# Look for:
# - Orphaned alternatives (broken relationships)
# - Circular prerequisites (infinite loops)
# - Self-references (invalid edges)
```

**Common Issues**:
- Missing commands referenced in alternatives
- Circular prerequisite chains
- Commands without tags (can't filter)

---

### Use Case 4: Daily Health Check

**Goal**: Quick validation before working with database

```bash
# Fast check (< 5 seconds)
./quick_report.sh

# If Neo4j not running:
sudo neo4j start
./quick_report.sh
```

**Alerts**:
- Database empty → Run migration
- Count mismatch → Check for partial migration
- Integrity issues → Review errors

---

## Performance

| Utility | Execution Time | Lines of Output |
|---------|---------------|-----------------|
| `json_stats.py` | ~2 seconds | ~50 lines |
| `neo4j_stats.py` | ~3 seconds | ~60 lines |
| `compare_backends.py` | ~2 seconds | ~40 lines |
| `quick_report.sh` | ~7 seconds | ~150 lines |

**Optimized for**:
- Fast execution (< 10 seconds total)
- Clear, actionable output
- Minimal dependencies (Python stdlib + Neo4j driver)

---

## Output Interpretation

### Colors

- **🟢 Green**: Success, healthy state
- **🟡 Yellow**: Warning, needs attention
- **🔴 Red**: Error, critical issue
- **🔵 Blue**: Info, headers
- **⚫ Dim**: Normal, no action needed

### Key Metrics

**JSON Files**:
- `alternatives_text > 0` → ❌ **Must fix before migration**
- `prerequisites_text > 0` → ❌ **Must fix before migration**
- `duplicate_ids > 0` → ❌ **Critical error**
- `orphaned_references > 0` → ⚠️ **Fix recommended**

**Neo4j Database**:
- `command_count < 795` → ⚠️ **Incomplete migration**
- `orphaned_alternatives > 0` → ❌ **Data corruption**
- `circular_prerequisites > 0` → ❌ **Invalid graph**
- `untagged_commands > 0` → ⚠️ **Missing metadata**

**Backend Comparison**:
- `json_count - neo4j_count > 0` → ⚠️ **Migration needed**
- `neo4j_count - json_count > 0` → ⚠️ **Extra data in Neo4j**
- `json_only.length > 0` → 📝 **Commands to migrate**
- `neo4j_only.length > 0` → ⚠️ **Unexpected data**

---

## Troubleshooting

### "Neo4j connection failed"

**Cause**: Neo4j not running or wrong credentials

**Fix**:
```bash
# Check status
sudo neo4j status

# Start if stopped
sudo neo4j start

# Check password
export NEO4J_PASSWORD='Afrodeeziak21'  # Development default
python3 neo4j_stats.py
```

---

### "JSON file parse error"

**Cause**: Invalid JSON syntax

**Fix**:
```bash
# Find invalid files
python3 json_stats.py --verbose | grep "parse_errors"

# Validate JSON
jq . path/to/file.json
```

---

### "Orphaned alternatives detected"

**Cause**: Alternative points to non-existent command ID

**Fix**:
```bash
# Find orphaned references
python3 neo4j_stats.py --verbose

# Either:
# 1. Add missing command to JSON
# 2. Remove invalid reference
# 3. Fix typo in command ID
```

---

### "Circular dependencies detected"

**Cause**: A → B → A prerequisite loop

**Fix**:
```bash
# View cycles
python3 neo4j_stats.py --verbose

# Break cycle by removing one prerequisite relationship
```

---

## Integration with CRACK CLI

These utilities are designed to work alongside the CRACK CLI:

```bash
# Check database before using CLI
./quick_report.sh

# Use CLI
crack reference --status
crack reference --graph multi-hop gobuster-dir

# If CLI shows wrong count, debug:
python3 compare_backends.py
```

---

## Development Workflow

**1. Before migration**:
```bash
python3 json_stats.py --verbose > pre_migration.txt
```

**2. Run migration**:
```bash
python3 ../migrate_json_to_neo4j.py  # (when created)
```

**3. Verify migration**:
```bash
./quick_report.sh --verbose --save
python3 compare_backends.py
```

**4. If issues found**:
```bash
# Check integrity
python3 neo4j_stats.py --verbose

# Fix and re-verify
./quick_report.sh
```

---

## Files

```
db/neo4j-migration/scripts/utils/
├── json_stats.py           (12K) - JSON analysis
├── neo4j_stats.py          (11K) - Neo4j analysis
├── compare_backends.py     (7K)  - Backend comparison
├── quick_report.sh         (7K)  - All-in-one report
└── README.md              (this file)
```

---

## Dependencies

**Python**:
- `json` (stdlib)
- `pathlib` (stdlib)
- `collections` (stdlib)
- `neo4j` (for neo4j_stats.py only)

**System**:
- Neo4j 4.4+ (for Neo4j utilities)
- Bash 4+ (for quick_report.sh)

---

## Tips

**Speed up checks**:
```bash
# Skip verbose output for quick validation
./quick_report.sh | grep "✗\|⚠"
```

**Focus on specific issues**:
```bash
# Only JSON violations
python3 json_stats.py --verbose | grep -A 3 "Alternatives using text"

# Only Neo4j integrity
python3 neo4j_stats.py --verbose | grep -A 5 "Integrity"
```

**Monitor during migration**:
```bash
# Run in background, check periodically
watch -n 10 'python3 neo4j_stats.py | grep "Command"'
```

**Save reports for comparison**:
```bash
# Before migration
./quick_report.sh --save  # Saves to /tmp/crack_db_report_TIMESTAMP.txt

# After migration
./quick_report.sh --save

# Compare
diff /tmp/crack_db_report_*.txt
```

---

**Created**: 2025-11-08
**Purpose**: Fast debugging and validation for Neo4j migration
**Maintainer**: See `db/neo4j-migration/JSON-MIGRATION-BLUEPRINT.md`
