# Schema Validation - Actionable Fix Checklist

**Date**: 2025-11-09
**Goal**: Fix 583 BLOCKING violations to enable Neo4j migration
**Current Compliance**: 11.7% → **Target**: 95%+

---

## CRITICAL FIXES (BLOCKING MIGRATION)

### ✅ Fix #1: Duplicate IDs (52 violations) - ALREADY IDENTIFIED

**Status**: Duplicate IDs identified in Phase 2D.1
**Location**: `/db/neo4j-migration/data/duplicate_ids_report.json`
**Action**: Run deduplication script from Phase 2D.1

**Commands**:
```bash
# Already completed in Phase 2D.1
# Reference: duplicate_ids_report.json
```

---

### ❌ Fix #2: Missing Required Fields (464 violations)

**Files Affected**:
- `auto-generated-enumeration-stubs.json` (most violations)
- `auto-generated-exploitation-stubs.json`
- `auto-generated-utilities-stubs.json`

**Issue**: Commands missing `name` field

**Auto-Fix Script**:
```python
#!/usr/bin/env python3
import json
from pathlib import Path

def fix_missing_names(json_file):
    """Add name field derived from ID"""
    with open(json_file, 'r') as f:
        data = json.load(f)

    fixed = 0
    for cmd in data.get('commands', []):
        if 'name' not in cmd and 'id' in cmd:
            # Convert kebab-case to Title Case
            cmd['name'] = cmd['id'].replace('-', ' ').title()
            fixed += 1

    with open(json_file, 'w') as f:
        json.dump(data, f, indent=2)

    return fixed

# Run on all stub files
stub_files = [
    'reference/data/commands/enumeration/auto-generated-enumeration-stubs.json',
    'reference/data/commands/exploitation/auto-generated-exploitation-stubs.json',
    'reference/data/commands/utilities/auto-generated-utilities-stubs.json',
    'reference/data/commands/post-exploitation/auto-generated-post-exploitation-stubs.json',
]

total_fixed = 0
for file in stub_files:
    if Path(file).exists():
        count = fix_missing_names(file)
        print(f"Fixed {count} missing names in {Path(file).name}")
        total_fixed += count

print(f"\nTotal fixed: {total_fixed}/464")
```

**Manual Review Required**: 0 (fully automated)
**Estimated Time**: 15 minutes

---

### ❌ Fix #3: Invalid ID Formats (67 violations)

**Examples of Invalid IDs**:
```
powerup.ps1 → import-powerup
cmd/unix/reverse → msfvenom-unix-reverse
cmd/windows/reverse_powershell → msfvenom-windows-reverse-powershell
java/meterpreter/reverse_tcp → msfvenom-java-meterpreter-tcp
#-list → comment-list
```

**ID Format Rules**:
- Lowercase only
- Hyphens (not underscores or slashes)
- No special characters (#, /, .)
- Pattern: `^[a-z0-9]+(-[a-z0-9]+)*$`

**Manual Fix Required**: YES (67 commands)
**File**: `auto-generated-exploitation-stubs.json` (majority)

**Checklist**:
- [ ] Review 67 invalid IDs in validation report
- [ ] Rename to kebab-case format
- [ ] Update all references in alternatives/prerequisites
- [ ] Re-run validation

**Estimated Time**: 2-3 hours

---

## HIGH PRIORITY FIXES (GRAPH DATABASE QUALITY)

### ❌ Fix #4: Alternatives Using Text (609 violations)

**Pattern**: Alternatives field contains full commands instead of command IDs

**Wrong**:
```json
"alternatives": [
  "Get-NetUser",
  "ldapsearch -x -H ldap://<DC> -b 'DC=corp,DC=com' '(objectClass=user)'"
]
```

**Correct**:
```json
"alternatives": [
  "powerview-get-netuser",
  "ldapsearch-domain-users"
]
```

**Auto-Fix Strategy**:
1. Create text-to-ID mapping (100+ common patterns)
2. Auto-replace known patterns
3. Manual review of unmapped text

**Common Mappings**:
```python
TEXT_TO_ID_MAP = {
    "Get-NetUser": "powerview-get-netuser",
    "Get-ADUser": "get-aduser",
    "Get-NetGroup": "powerview-get-netgroup",
    "Get-ADGroup": "get-adgroup",
    "Get-NetComputer": "powerview-get-netcomputer",
    "Get-ADComputer": "get-adcomputer",
    "Import-Module PowerView.ps1": "import-powerview",
    "Import-Module ActiveDirectory": "import-module-activedirectory",
    # ... add 100+ more
}
```

**Checklist**:
- [ ] Create text-to-ID mapping script
- [ ] Auto-replace 70% of patterns
- [ ] Manual review remaining 30%
- [ ] Create missing commands for unmapped text
- [ ] Re-run validation

**Estimated Time**: 6-8 hours

---

### ❌ Fix #5: Prerequisites Using Text (244 violations)

**Pattern**: Prerequisites contain installation instructions instead of command IDs

**Wrong**:
```json
"prerequisites": [
  "# Install Frida\npip install frida frida-tools"
]
```

**Correct**:
```json
"prerequisites": ["install-frida-tools"]
```

**Strategy**:
1. Create utility commands for installations
2. Replace text with command IDs
3. Remove non-command prerequisites (e.g., "Requires admin access")

**New Utility Commands Needed**:
- `install-frida-tools`
- `install-clamav-windows`
- `check-uac-integrity-level`
- `verify-doc-format`

**Checklist**:
- [ ] Identify unique prerequisite patterns
- [ ] Create 20-30 new utility commands
- [ ] Replace text with new command IDs
- [ ] Remove state-based prerequisites
- [ ] Re-run validation

**Estimated Time**: 4-6 hours

---

### ❌ Fix #6: Missing Variable Definitions (6 violations)

**Issue**: Command has `<PLACEHOLDER>` but no matching entry in variables array

**Example**:
```json
{
  "command": "crackmapexec smb <TARGET> -u <USER> -p <PASS>",
  "variables": []  // WRONG: Missing TARGET, USER, PASS definitions
}
```

**Fix**:
```json
{
  "command": "crackmapexec smb <TARGET> -u <USER> -p <PASS>",
  "variables": [
    {"name": "<TARGET>", "description": "Target IP or hostname", "required": true},
    {"name": "<USER>", "description": "Username", "required": true},
    {"name": "<PASS>", "description": "Password", "required": true}
  ]
}
```

**Checklist**:
- [ ] Fix 6 missing variable definitions (file: `ad-lateral-movement-helpers.json`)
- [ ] Re-run validation

**Estimated Time**: 30 minutes

---

## MEDIUM PRIORITY FIXES (OPTIONAL)

### ⚠️ Fix #7: Orphaned References (385 violations)

**Issue**: Command references non-existent command ID in alternatives/prerequisites/next_steps

**Examples**:
- `powershell-access` → doesn't exist (should be `verify-powershell-access`)
- `bloodhound-python` → doesn't exist (should be `bloodhound-py-ingest`)
- `get-addomain` → doesn't exist (should be `get-addomain-ps`)

**Strategy**:
1. Auto-detect similar existing IDs (fuzzy matching)
2. Create missing high-value commands
3. Remove low-value orphaned refs

**Checklist**:
- [ ] Run fuzzy match script to suggest replacements
- [ ] Create 50-100 missing utility commands
- [ ] Remove unmapped references
- [ ] Re-run validation

**Estimated Time**: 6-8 hours

---

### ⚠️ Fix #8: Next Steps Using Text (1,623 violations)

**Issue**: Next_steps contains notes/instructions instead of command IDs

**Examples** (should be removed or converted):
- "If user in Domain Admins: prioritize as high-value target"
- "Check Password last set - old passwords may be weaker"
- "Look for custom groups (Development, IT, Management)"

**Strategy**:
1. Remove non-actionable text (notes/observations)
2. Keep only command IDs
3. Move notes to `notes` field

**Checklist**:
- [ ] Filter next_steps to remove text entries
- [ ] Move observations to notes field
- [ ] Keep only valid command IDs
- [ ] Re-run validation

**Estimated Time**: 8-10 hours

---

## AUTOMATED FIX SCRIPTS

### Script 1: Fix Missing Names

**File**: `/db/neo4j-migration/scripts/utils/fix_missing_names.py`

```bash
python3 db/neo4j-migration/scripts/utils/fix_missing_names.py
# Fixes: 464 violations (100% automated)
# Time: 5 minutes
```

### Script 2: Fix Text Relationships

**File**: `/db/neo4j-migration/scripts/utils/fix_text_relationships.py`

```bash
python3 db/neo4j-migration/scripts/utils/fix_text_relationships.py
# Fixes: ~400-500 violations (70% automated)
# Time: 30 minutes automated + 4 hours manual review
```

### Script 3: Remove Orphaned References

**File**: `/db/neo4j-migration/scripts/utils/fix_orphaned_refs.py`

```bash
python3 db/neo4j-migration/scripts/utils/fix_orphaned_refs.py --auto-remove
# Fixes: 385 violations (optional - removes invalid refs)
# Time: 5 minutes
```

---

## RECOMMENDED WORKFLOW

### Day 1: Critical Fixes (6 hours)

**Morning (3 hours)**:
1. Run fix_missing_names.py (15 min)
2. Fix 67 invalid ID formats (2h 45m)

**Afternoon (3 hours)**:
3. Verify duplicate IDs fixed (Phase 2D.1)
4. Run validation: `python3 db/neo4j-migration/scripts/utils/validate_schema_compliance.py`
5. **Target**: Zero CRITICAL violations

### Day 2: High Priority Fixes (8 hours)

**Morning (4 hours)**:
1. Create text-to-ID mapping (1h)
2. Run fix_text_relationships.py (30m)
3. Manual review unmapped text (2h 30m)

**Afternoon (4 hours)**:
4. Create 30 new utility commands for prerequisites (2h)
5. Fix 6 missing variable definitions (30m)
6. Run validation (30m)
7. **Target**: <5% HIGH violations

### Day 3: Polish & Validate (4 hours)

**Morning (2 hours)**:
1. Fix orphaned references (fuzzy matching + create missing commands)
2. Run fix_orphaned_refs.py

**Afternoon (2 hours)**:
3. Final validation run
4. Manual spot-check 20 random commands
5. **Target**: 95%+ compliance rate

---

## SUCCESS CRITERIA

### Minimum (BLOCKING Fixed)

- [ ] Zero duplicate IDs (52)
- [ ] Zero missing required fields (464)
- [ ] Zero invalid ID formats (67)
- [ ] Compliance rate: >80%

### Recommended (BLOCKING + HIGH Fixed)

- [ ] Zero duplicate IDs
- [ ] Zero missing required fields
- [ ] Zero invalid ID formats
- [ ] <5% text in alternatives (30/609)
- [ ] <5% text in prerequisites (12/244)
- [ ] <10% orphaned references (38/385)
- [ ] Compliance rate: >95%

### Ideal (100% Compliant)

- [ ] All violations fixed
- [ ] Compliance rate: 100%

---

## VALIDATION COMMANDS

### Run Full Validation
```bash
python3 db/neo4j-migration/scripts/utils/validate_schema_compliance.py
```

### Check Specific Violation Type
```bash
python3 db/neo4j-migration/scripts/utils/json_stats.py --verbose | grep "alternatives_text"
```

### Count Remaining Violations
```bash
python3 db/neo4j-migration/scripts/utils/validate_schema_compliance.py 2>&1 | grep "Compliance Rate"
```

---

## FILES TO REVIEW

**Detailed Report**: `/db/neo4j-migration/data/SCHEMA_VALIDATION_REPORT.md`
**Summary**: `/db/neo4j-migration/PHASE_2D3_VALIDATION_SUMMARY.md`
**This Checklist**: `/db/neo4j-migration/VALIDATION_FIX_CHECKLIST.md`
