# Migration Fixes Checklist - Usage Guide

**Last Updated**: 2025-11-08

---

## Overview

The diagnostic scripts now output violations in **checklist format** with locations and IDs for easy tracking and fixing.

### Available Outputs

1. **Terminal Checklist** (`json_stats.py --verbose`)
   - Real-time checklist in terminal
   - First 10 violations per type
   - Color-coded with emojis

2. **Detailed Markdown** (`FIXES_CHECKLIST_DETAILED.md`)
   - Complete checklist with ALL violations
   - Organized by violation type
   - Progress tracking sections

3. **Summary Report** (`MIGRATION_FIXES_CHECKLIST.md`)
   - Executive overview
   - Execution plan
   - Success criteria

---

## Quick Start

### Generate All Reports

```bash
# 1. Terminal checklist (quick view)
python3 db/neo4j-migration/scripts/utils/json_stats.py --verbose

# 2. Generate detailed checklist document
python3 db/neo4j-migration/scripts/utils/generate_fixes_checklist.py

# 3. View comprehensive migration plan
cat db/neo4j-migration/MIGRATION_FIXES_CHECKLIST.md
```

### Run Complete Diagnostic

```bash
# Run all diagnostics with checklist output
./db/neo4j-migration/scripts/utils/quick_report.sh --verbose --save
```

---

## Checklist Format

### Terminal Output

```
📋 VIOLATIONS CHECKLIST
======================================================================

🔴 DUPLICATE IDs (14)

[ ] Fix #1: john-test-rules
    📍 Location 1: data/commands/enumeration/password-attacks-john.json
    📍 Location 2: data/commands/enumeration/password-attacks-wordlist-rules.json
    ✏️  Action: Rename or remove duplicate

🟡 ALTERNATIVES USING TEXT (387)
  Showing first 10 violations:

[ ] Fix #1: net-user-domain-list
    📁 File: enumeration/ad-legacy-enumeration.json
    ❌ Current alternatives (text):
       - Get-NetUser
       - ldapsearch -x -H ldap://<DC> -b 'DC=corp,DC=com' '(objectClass=user)'
    ✏️  Action: Replace with command IDs or create missing commands
```

### Markdown Output

```markdown
## 🔴 Duplicate IDs

### 1. `john-test-rules`

- [ ] **ID**: `john-test-rules`
- [ ] **Location 1**: `data/commands/enumeration/password-attacks-john.json`
- [ ] **Location 2**: `data/commands/enumeration/password-attacks-wordlist-rules.json`
- [ ] **Action**: Rename or remove duplicate
```

---

## Violation Types

### 🔴 Critical: Duplicate IDs (14)

**Symbol**: 🔴
**Blocks Migration**: YES
**Info Provided**:
- Command ID
- Location 1 (full path)
- Location 2 (full path)
- Action to take

**Example Fix**:
```bash
# Option 1: Remove duplicate (if identical)
# Edit file and remove duplicate entry

# Option 2: Rename (if different context)
# Change ID: verify-root-access → verify-root-access-sudo
```

### 🟡 High: Alternatives Using Text (387)

**Symbol**: 🟡
**Blocks Migration**: YES
**Info Provided**:
- Command ID (where violation occurs)
- File location
- List of text alternatives
- Action to take

**Example Fix**:
```json
// Before (WRONG):
"alternatives": [
  "dirb <URL>",
  "ffuf -u <URL>/FUZZ -w <WORDLIST>"
]

// After (CORRECT):
"alternatives": [
  "dirb-scan",
  "ffuf-dir"
]
```

### 🟡 High: Prerequisites Using Text (189)

**Symbol**: 🟡
**Blocks Migration**: YES
**Info Provided**:
- Command ID
- File location
- List of text prerequisites
- Action to take

**Example Fix**:
```json
// Before (WRONG):
"prerequisites": [
  "mkdir -p <OUTPUT_DIR>",
  "sudo nmap -p <PORT> -Pn -v <TARGET>"
]

// After (CORRECT):
"prerequisites": [
  "mkdir-directory",
  "nmap-port-check"
]
```

### 🟡 High: Orphaned References (53)

**Symbol**: 🟡
**Blocks Migration**: YES
**Info Provided**:
- Referenced ID (that doesn't exist)
- Status message
- Action to take

**Example Fix**:
```bash
# Option 1: Create missing command
# Add command with ID "dirb-scan" to appropriate JSON file

# Option 2: Fix typo
# Change "dirb-scan" → "dirb-directory-scan" (if typo)
```

---

## Workflow

### Step 1: Generate Reports

```bash
# Terminal view (quick)
python3 db/neo4j-migration/scripts/utils/json_stats.py --verbose | less

# Detailed markdown (complete)
python3 db/neo4j-migration/scripts/utils/generate_fixes_checklist.py
```

### Step 2: Track Progress

Open `FIXES_CHECKLIST_DETAILED.md` and check off items as you fix them:

```markdown
- [x] **ID**: `john-test-rules`  ← Mark as done
- [x] **Location 1**: `data/commands/enumeration/password-attacks-john.json`
- [x] **Location 2**: `data/commands/enumeration/password-attacks-wordlist-rules.json`
- [x] **Action**: Renamed to `john-test-rules-basic`
```

### Step 3: Re-Validate

After fixing violations:

```bash
# Check if fixed
python3 db/neo4j-migration/scripts/utils/json_stats.py

# Should show reduced violation count
# Repeat until: "✓ No schema violations found!"
```

---

## File Locations

```
db/neo4j-migration/
├── MIGRATION_FIXES_CHECKLIST.md      # Summary & execution plan
├── FIXES_CHECKLIST_DETAILED.md       # Complete checklist (auto-generated)
├── scripts/
│   └── utils/
│       ├── json_stats.py             # Terminal checklist output
│       ├── generate_fixes_checklist.py  # Markdown generator
│       └── quick_report.sh           # Comprehensive diagnostics
```

---

## Tips

### Filter Specific Violations

```bash
# Show only duplicate IDs
python3 db/neo4j-migration/scripts/utils/json_stats.py --verbose | grep -A 5 "DUPLICATE"

# Show only alternatives violations
python3 db/neo4j-migration/scripts/utils/json_stats.py --verbose | grep -A 10 "ALTERNATIVES"
```

### Track Progress

```bash
# Count remaining violations
python3 db/neo4j-migration/scripts/utils/json_stats.py | grep "Schema Violations Found"

# Before: Schema Violations Found: 644
# After fix: Schema Violations Found: 630  ← Progress!
```

### Save Checklist to File

```bash
# Save terminal output
python3 db/neo4j-migration/scripts/utils/json_stats.py --verbose > checklist_$(date +%Y%m%d).txt

# Or use quick_report with --save
./db/neo4j-migration/scripts/utils/quick_report.sh --verbose --save
```

---

## Success Criteria

When ready for migration, you should see:

```
✓ No schema violations found!
✓ JSON files ready for Neo4j migration
```

And the checklist should show:

```
Progress Tracking

Phase 1: Duplicate IDs
- [x] Fixed: 14 / 14
- [ ] Remaining: 0

Phase 2: Alternatives
- [x] Fixed: 387 / 387
- [ ] Remaining: 0

Phase 3: Prerequisites
- [x] Fixed: 189 / 189
- [ ] Remaining: 0

Phase 4: Orphaned References
- [x] Fixed: 53 / 53
- [ ] Remaining: 0
```

---

## Next Steps

After all violations are fixed:

1. **Validate**: Run `json_stats.py` → should show 0 violations
2. **Build Index**: Run `02_build_command_index.py`
3. **Map Text to IDs**: Run `03_map_text_to_ids.py`
4. **Migrate**: Run `06_migrate_to_neo4j.py`
5. **Verify**: Run `compare_backends.py` → should show 791 commands in both backends

---

**Need Help?**

- See `MIGRATION_FIXES_CHECKLIST.md` for execution plan
- See `README.md` for detailed utility documentation
- See `JSON-MIGRATION-BLUEPRINT.md` for migration strategy
