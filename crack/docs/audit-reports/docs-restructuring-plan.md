# Documentation Restructuring Plan - `/home/kali/OSCP/crack/docs/`

**Created:** 2025-10-10
**Agent:** 2 (Docs Folder Restructuring Specialist)
**Status:** Ready for Implementation

---

## Executive Summary

**Problem:** The `/home/kali/OSCP/crack/docs/` root directory currently contains 10 markdown files when it should only contain 2 (master index + README). This creates clutter and makes documentation navigation confusing.

**Solution:** Reorganize docs/ into a clean structure with only essential files in root, moving all other documentation to descriptive subdirectories with consistent naming conventions.

**Impact:**
- Cleaner, more scannable documentation structure
- Easier navigation for users
- Consistent naming conventions across categories
- Better separation between user-facing and internal documentation

---

## Current State Analysis

### Files in docs/ Root (10 total)

**Should Stay (2 files):**
1. `MASTER_INDEX.md` - Comprehensive documentation catalog (7,754 lines)
2. `QUICK_REFERENCE.md` - One-page quick reference card (377 lines)

**Should Move (8 files):**
1. `CMS_MADE_SIMPLE_AUTHENTICATED_RCE_ADAPTATION.md` - Educational writeup (target-specific)
2. `CMS_MADE_SIMPLE_EXPLOIT_ADAPTATION.md` - Educational writeup (target-specific)
3. `PARAM_DISCOVERY_GUIDE.md` - Tool-specific guide (web enumeration)
4. `PIPELINE_SQLI_FU.md` - Tool-specific guide (SQLi)
5. `SCAN_ANALYZER.md` - Tool-specific guide (network enumeration)
6. `TIME_SQLI_METHODOLOGY.md` - Tool-specific guide (SQLi)
7. `scanner_validation_report.md` - Internal validation/audit report
8. `sqli_scanner_postgresql_improvements.md` - Internal analysis/audit report

### Existing Subdirectories

**Current subdirectories:**
- `audit-reports/` - Internal audit reports (13 files)
- `guides/` - User guides (1 file: GETTING_STARTED.md)
- `roadmaps/` - Project roadmaps (1 file: HTB_HARD_UPGRADE.md)
- `archive/` - Historical documentation (MANIFEST.md + date-stamped folders)

---

## Problems with Current Structure

### Issue 1: Cluttered Root Directory
- 10 files in root when only 2 should exist
- Mix of user guides, internal reports, and target-specific writeups
- Difficult to scan for essential documentation

### Issue 2: Inconsistent Naming
- Mix of `SCREAMING_CASE.md` and `snake_case.md`
- No clear pattern for user vs internal docs
- Tool-specific guides mixed with reports

### Issue 3: Poor Categorization
- Target-specific writeups in root (CMS Made Simple docs)
- Internal validation reports in root (scanner validation)
- Tool guides scattered (SQLi, web, network tools)

### Issue 4: Confusing Navigation
- Users looking for guides find audit reports
- Developers looking for analysis find user guides
- No clear separation of concerns

---

## Proposed Structure

```
docs/
├── README.md                          # Introduction, points to master-index.md
├── master-index.md                    # Comprehensive catalog (RENAMED from MASTER_INDEX.md)
├── audit-reports/                     # Internal analysis & validation (RENAMED from audit-reports/)
│   ├── scanner-validation-report.md  # MOVED + RENAMED from docs/
│   ├── sqli-postgresql-analysis.md   # MOVED + RENAMED from docs/
│   ├── ARCHIVE_ORGANIZATION_REPORT.md
│   ├── DEV_HISTORY_ARCHIVAL_PLAN.md
│   ├── FINAL_CONSOLIDATION_REPORT.md
│   ├── INDEX.md
│   ├── MASTER_INDEX_CREATION_REPORT.md
│   ├── MINING_REPORT_AUDIT.md
│   ├── MINING_REPORT_CONSOLIDATION_REPORT.md
│   ├── README_CONSOLIDATION_PLAN.md
│   ├── README_CONSOLIDATION_SUMMARY.md
│   ├── README_STRUCTURE_VISUALIZATION.md
│   ├── README_UNIFICATION_REPORT.md
│   ├── ROOT_CLEANUP_PLAN.md
│   ├── VERBOSITY_REDUCTION_REPORT.md
│   └── docs-restructuring-plan.md    # THIS FILE (RENAMED)
├── guides/                            # User-facing guides
│   ├── getting-started.md             # RENAMED from GETTING_STARTED.md
│   ├── web-param-discovery.md         # MOVED + RENAMED from docs/PARAM_DISCOVERY_GUIDE.md
│   ├── network-scan-analyzer.md       # MOVED + RENAMED from docs/SCAN_ANALYZER.md
│   └── sqli/                          # SQLi-specific guides (NEW SUBDIR)
│       ├── pipeline-methodology.md    # MOVED + RENAMED from docs/PIPELINE_SQLI_FU.md
│       └── time-based-methodology.md  # MOVED + RENAMED from docs/TIME_SQLI_METHODOLOGY.md
├── roadmaps/                          # Project roadmaps
│   └── htb-hard-upgrade.md            # RENAMED from HTB_HARD_UPGRADE.md
├── writeups/                          # Target-specific educational writeups (NEW)
│   └── cms-made-simple/               # Grouped by target/vulnerability (NEW SUBDIR)
│       ├── sqli-exploit-adaptation.md # MOVED + RENAMED from CMS_MADE_SIMPLE_EXPLOIT_ADAPTATION.md
│       └── authenticated-rce.md       # MOVED + RENAMED from CMS_MADE_SIMPLE_AUTHENTICATED_RCE_ADAPTATION.md
└── archive/                           # Historical documentation
    ├── MANIFEST.md
    ├── 2025-10-09/
    └── 2025-10-10/
```

---

## Naming Convention Standards

### Root Files (2 only)
- **Convention:** `lowercase-with-dashes.md` (kebab-case)
- **Rationale:** Easy to type, scannable, consistent with web standards
- **Examples:**
  - `master-index.md` (comprehensive catalog)
  - `README.md` (project overview, standard GitHub convention)

### User-Facing Guides (`guides/`)
- **Convention:** `lowercase-with-dashes.md` (kebab-case)
- **Pattern:** `<tool-or-topic>-<purpose>.md`
- **Rationale:** User-friendly, easy to read, descriptive
- **Examples:**
  - `getting-started.md`
  - `web-param-discovery.md`
  - `network-scan-analyzer.md`
  - `sqli/pipeline-methodology.md`
  - `sqli/time-based-methodology.md`

### Internal Audit Reports (`audit-reports/`)
- **Convention:** `lowercase-with-dashes.md` (kebab-case) for NEW reports
- **Convention:** `SCREAMING_SNAKE_CASE.md` for EXISTING historical reports
- **Rationale:** Don't break existing cross-references; new reports use modern convention
- **Examples (new):**
  - `scanner-validation-report.md`
  - `sqli-postgresql-analysis.md`
  - `docs-restructuring-plan.md`
- **Examples (existing - keep as-is):**
  - `ARCHIVE_ORGANIZATION_REPORT.md`
  - `FINAL_CONSOLIDATION_REPORT.md`
  - `MASTER_INDEX_CREATION_REPORT.md`

### Roadmaps (`roadmaps/`)
- **Convention:** `lowercase-with-dashes.md` (kebab-case)
- **Pattern:** `<project-or-goal>-<version-or-date>.md`
- **Examples:**
  - `htb-hard-upgrade.md`

### Writeups (`writeups/`)
- **Convention:** `lowercase-with-dashes.md` (kebab-case)
- **Structure:** Group by target/vulnerability in subdirectories
- **Pattern:** `<vulnerability-or-technique>.md` inside `<target>/` folder
- **Examples:**
  - `cms-made-simple/sqli-exploit-adaptation.md`
  - `cms-made-simple/authenticated-rce.md`

### Archive (`archive/`)
- **Convention:** Keep existing names unchanged (historical preservation)
- **Rationale:** Archive is reference-only, no need to rename

---

## File Migration Plan

### Stay in Root (2 files)

| Current Path | New Path | Action | Reason |
|--------------|----------|--------|--------|
| `MASTER_INDEX.md` | `master-index.md` | RENAME | Consistent kebab-case, primary navigation doc |
| `QUICK_REFERENCE.md` | DELETE | REMOVE | Redundant - master-index.md has quick navigation section |

**Decision:** Remove `QUICK_REFERENCE.md` entirely
- **Rationale:** `MASTER_INDEX.md` already contains:
  - "Quick Navigation" section (lines 5-24)
  - "Top 10 Most-Used Guides" (lines 48-89)
  - "File Locations Cheatsheet" (lines 92-131)
  - "Common Task Workflows" (lines 215-277)
  - Same quick-access content, better integrated
- **Impact:** Reduces redundancy, single source of truth

### Move to audit-reports/ (3 files)

| Current Path | New Path | Reason |
|--------------|----------|--------|
| `scanner_validation_report.md` | `audit-reports/scanner-validation-report.md` | Internal validation/QA report |
| `sqli_scanner_postgresql_improvements.md` | `audit-reports/sqli-postgresql-analysis.md` | Internal analysis/improvement doc |
| *(this file)* | `audit-reports/docs-restructuring-plan.md` | Internal audit report |

### Move to guides/ (4 files → 5 files with subdir)

| Current Path | New Path | Reason |
|--------------|----------|--------|
| `PARAM_DISCOVERY_GUIDE.md` | `guides/web-param-discovery.md` | User-facing web enumeration guide |
| `SCAN_ANALYZER.md` | `guides/network-scan-analyzer.md` | User-facing network analysis guide |
| `PIPELINE_SQLI_FU.md` | `guides/sqli/pipeline-methodology.md` | User-facing SQLi technique guide |
| `TIME_SQLI_METHODOLOGY.md` | `guides/sqli/time-based-methodology.md` | User-facing SQLi technique guide |

**New Subdirectory:** `guides/sqli/` - Groups SQLi-specific methodologies

### Move to writeups/ (2 files → NEW category)

| Current Path | New Path | Reason |
|--------------|----------|--------|
| `CMS_MADE_SIMPLE_EXPLOIT_ADAPTATION.md` | `writeups/cms-made-simple/sqli-exploit-adaptation.md` | Target-specific educational writeup |
| `CMS_MADE_SIMPLE_AUTHENTICATED_RCE_ADAPTATION.md` | `writeups/cms-made-simple/authenticated-rce.md` | Target-specific educational writeup |

**New Category:** `writeups/` - Educational attack narratives grouped by target
**New Subdirectory:** `writeups/cms-made-simple/` - Groups related exploits

### Rename in roadmaps/ (1 file)

| Current Path | New Path | Reason |
|--------------|----------|--------|
| `roadmaps/HTB_HARD_UPGRADE.md` | `roadmaps/htb-hard-upgrade.md` | Consistent kebab-case naming |

### Rename in guides/ (1 existing file)

| Current Path | New Path | Reason |
|--------------|----------|--------|
| `guides/GETTING_STARTED.md` | `guides/getting-started.md` | Consistent kebab-case naming |

---

## Implementation Commands

### Phase 1: Create New Directories

```bash
# Create new writeups structure
mkdir -p /home/kali/OSCP/crack/docs/writeups/cms-made-simple

# Create new guides subdirectory
mkdir -p /home/kali/OSCP/crack/docs/guides/sqli

# Verify directories exist
ls -ld /home/kali/OSCP/crack/docs/{writeups,guides/sqli,audit-reports}
```

### Phase 2: Move and Rename Files (Use git mv to preserve history)

```bash
cd /home/kali/OSCP/crack/docs

# Move audit reports
git mv scanner_validation_report.md audit-reports/scanner-validation-report.md
git mv sqli_scanner_postgresql_improvements.md audit-reports/sqli-postgresql-analysis.md

# Move user guides
git mv PARAM_DISCOVERY_GUIDE.md guides/web-param-discovery.md
git mv SCAN_ANALYZER.md guides/network-scan-analyzer.md

# Move SQLi guides to subdir
git mv PIPELINE_SQLI_FU.md guides/sqli/pipeline-methodology.md
git mv TIME_SQLI_METHODOLOGY.md guides/sqli/time-based-methodology.md

# Move writeups
git mv CMS_MADE_SIMPLE_EXPLOIT_ADAPTATION.md writeups/cms-made-simple/sqli-exploit-adaptation.md
git mv CMS_MADE_SIMPLE_AUTHENTICATED_RCE_ADAPTATION.md writeups/cms-made-simple/authenticated-rce.md

# Rename existing files
git mv MASTER_INDEX.md master-index.md
git mv guides/GETTING_STARTED.md guides/getting-started.md
git mv roadmaps/HTB_HARD_UPGRADE.md roadmaps/htb-hard-upgrade.md

# Remove redundant quick reference
git rm QUICK_REFERENCE.md
```

### Phase 3: Update Cross-References

**Files that likely reference moved docs:**
- `/home/kali/OSCP/crack/README.md` - Main project README
- `/home/kali/OSCP/crack/docs/master-index.md` - Master documentation index
- `/home/kali/OSCP/crack/CLAUDE.md` - Development guide
- `/home/kali/OSCP/crack/track/README.md` - Track module README

**Search for references:**
```bash
# Find all references to moved files
cd /home/kali/OSCP/crack

# Check for MASTER_INDEX.md references
grep -r "MASTER_INDEX.md" --include="*.md" | grep -v ".git"

# Check for QUICK_REFERENCE.md references
grep -r "QUICK_REFERENCE.md" --include="*.md" | grep -v ".git"

# Check for CMS_MADE_SIMPLE references
grep -r "CMS_MADE_SIMPLE" --include="*.md" | grep -v ".git"

# Check for PARAM_DISCOVERY_GUIDE.md references
grep -r "PARAM_DISCOVERY_GUIDE.md" --include="*.md" | grep -v ".git"

# Check for SCAN_ANALYZER.md references
grep -r "SCAN_ANALYZER.md" --include="*.md" | grep -v ".git"

# Check for PIPELINE_SQLI_FU.md references
grep -r "PIPELINE_SQLI_FU.md" --include="*.md" | grep -v ".git"

# Check for TIME_SQLI_METHODOLOGY.md references
grep -r "TIME_SQLI_METHODOLOGY.md" --include="*.md" | grep -v ".git"

# Check for scanner_validation_report.md references
grep -r "scanner_validation_report.md" --include="*.md" | grep -v ".git"

# Check for sqli_scanner_postgresql_improvements.md references
grep -r "sqli_scanner_postgresql_improvements.md" --include="*.md" | grep -v ".git"

# Check for GETTING_STARTED.md references
grep -r "GETTING_STARTED.md" --include="*.md" | grep -v ".git"

# Check for HTB_HARD_UPGRADE.md references
grep -r "HTB_HARD_UPGRADE.md" --include="*.md" | grep -v ".git"
```

**Update patterns (examples):**
```bash
# Example: Update MASTER_INDEX.md → master-index.md
sed -i 's|MASTER_INDEX\.md|master-index.md|g' /home/kali/OSCP/crack/README.md

# Example: Update PARAM_DISCOVERY_GUIDE.md → guides/web-param-discovery.md
sed -i 's|docs/PARAM_DISCOVERY_GUIDE\.md|docs/guides/web-param-discovery.md|g' /home/kali/OSCP/crack/docs/master-index.md

# Will need to run similar sed commands for all moved files
```

### Phase 4: Update master-index.md

**Sections to update in `/home/kali/OSCP/crack/docs/master-index.md`:**

1. **Line 104-107** - Tool-Specific Guides section:
   ```markdown
   **Tool-Specific Guides**
   - [`/home/kali/OSCP/crack/docs/guides/web-param-discovery.md`] - Parameter discovery
   - [`/home/kali/OSCP/crack/docs/guides/network-scan-analyzer.md`] - Scan analyzer
   - [`/home/kali/OSCP/crack/docs/guides/sqli/pipeline-methodology.md`] - SQLi pipeline
   - [`/home/kali/OSCP/crack/docs/guides/sqli/time-based-methodology.md`] - Time-based SQLi
   ```

2. **Remove QUICK_REFERENCE.md references** (if any)

3. **Add new Writeups section** (after Tool-Specific Guides):
   ```markdown
   **Educational Writeups**
   - [`/home/kali/OSCP/crack/docs/writeups/cms-made-simple/sqli-exploit-adaptation.md`] - CMS Made Simple SQLi
   - [`/home/kali/OSCP/crack/docs/writeups/cms-made-simple/authenticated-rce.md`] - CMS Made Simple RCE
   ```

### Phase 5: Create README.md (NEW)

**Path:** `/home/kali/OSCP/crack/docs/README.md`

**Content:**
```markdown
# CRACK Toolkit Documentation

**Comprehensive documentation for the CRACK pentesting toolkit.**

## Quick Links

- **[Master Index](master-index.md)** - Complete documentation catalog
- **[Getting Started](guides/getting-started.md)** - Quick start guide
- **[Main README](../README.md)** - Project overview

## Documentation Categories

### User Guides
- **[Getting Started](guides/getting-started.md)** - First-time setup
- **[Web Parameter Discovery](guides/web-param-discovery.md)** - Web enumeration
- **[Network Scan Analyzer](guides/network-scan-analyzer.md)** - Network analysis
- **SQLi Methodologies:**
  - [Pipeline Methodology](guides/sqli/pipeline-methodology.md)
  - [Time-Based Methodology](guides/sqli/time-based-methodology.md)

### Educational Writeups
- **CMS Made Simple:**
  - [SQLi Exploit Adaptation](writeups/cms-made-simple/sqli-exploit-adaptation.md)
  - [Authenticated RCE](writeups/cms-made-simple/authenticated-rce.md)

### Project Roadmaps
- **[HTB Hard Upgrade](roadmaps/htb-hard-upgrade.md)** - Capability expansion plan

### Internal Documentation
- **[Audit Reports](audit-reports/)** - Internal analysis and validation
- **[Archive](archive/)** - Historical documentation

## Navigation Tips

**Finding Specific Content:**
```bash
# Search all documentation
grep -r "keyword" /home/kali/OSCP/crack/docs/ --include="*.md"

# Browse by category
ls /home/kali/OSCP/crack/docs/guides/
ls /home/kali/OSCP/crack/docs/writeups/
```

**See Also:**
- [Track Module Documentation](../track/README.md)
- [Reference System Documentation](../reference/README.md)
- [Development Guide](../CLAUDE.md)

---

*For comprehensive documentation catalog, see [master-index.md](master-index.md)*
```

### Phase 6: Verify Structure

```bash
# Verify final docs/ structure
tree /home/kali/OSCP/crack/docs/ -I '.git'

# Expected output:
# docs/
# ├── README.md
# ├── master-index.md
# ├── audit-reports/
# │   ├── scanner-validation-report.md
# │   ├── sqli-postgresql-analysis.md
# │   ├── docs-restructuring-plan.md
# │   └── [13 other existing reports]
# ├── guides/
# │   ├── getting-started.md
# │   ├── web-param-discovery.md
# │   ├── network-scan-analyzer.md
# │   └── sqli/
# │       ├── pipeline-methodology.md
# │       └── time-based-methodology.md
# ├── roadmaps/
# │   └── htb-hard-upgrade.md
# ├── writeups/
# │   └── cms-made-simple/
# │       ├── sqli-exploit-adaptation.md
# │       └── authenticated-rce.md
# └── archive/
#     ├── MANIFEST.md
#     ├── 2025-10-09/
#     └── 2025-10-10/

# Count files in docs/ root (should be 2)
ls -1 /home/kali/OSCP/crack/docs/*.md 2>/dev/null | wc -l
# Expected: 2 (README.md, master-index.md)
```

---

## Cross-Reference Update Strategy

### Priority 1: Core Documentation (CRITICAL)

**Files to update first:**
1. `/home/kali/OSCP/crack/README.md` - Main project entry point
2. `/home/kali/OSCP/crack/docs/master-index.md` - Primary navigation
3. `/home/kali/OSCP/crack/CLAUDE.md` - Development guide

**Update method:**
```bash
# Automated sed replacements for common references
cd /home/kali/OSCP/crack

# Update MASTER_INDEX.md → master-index.md
find . -name "*.md" -type f -exec sed -i 's|MASTER_INDEX\.md|master-index.md|g' {} \;

# Update moved file paths (example pattern)
find . -name "*.md" -type f -exec sed -i 's|docs/PARAM_DISCOVERY_GUIDE\.md|docs/guides/web-param-discovery.md|g' {} \;
```

### Priority 2: Module Documentation (IMPORTANT)

**Files likely to reference moved docs:**
- `/home/kali/OSCP/crack/track/README.md`
- `/home/kali/OSCP/crack/reference/README.md`
- `/home/kali/OSCP/crack/sqli/README.md` (if exists)
- `/home/kali/OSCP/crack/web/README.md` (if exists)

### Priority 3: Audit Reports (LOW)

**Internal docs referencing moved files:**
- Files in `docs/audit-reports/` may reference each other
- Archive MANIFEST.md may reference old paths
- **Decision:** Update if found during grep, but not critical

### Automated Update Script

```bash
#!/bin/bash
# File: /home/kali/OSCP/crack/docs/update_references.sh

cd /home/kali/OSCP/crack

# Define replacements (old_path → new_path)
declare -A replacements=(
    ["MASTER_INDEX.md"]="master-index.md"
    ["docs/QUICK_REFERENCE.md"]="docs/master-index.md#quick-navigation"
    ["docs/PARAM_DISCOVERY_GUIDE.md"]="docs/guides/web-param-discovery.md"
    ["docs/SCAN_ANALYZER.md"]="docs/guides/network-scan-analyzer.md"
    ["docs/PIPELINE_SQLI_FU.md"]="docs/guides/sqli/pipeline-methodology.md"
    ["docs/TIME_SQLI_METHODOLOGY.md"]="docs/guides/sqli/time-based-methodology.md"
    ["docs/CMS_MADE_SIMPLE_EXPLOIT_ADAPTATION.md"]="docs/writeups/cms-made-simple/sqli-exploit-adaptation.md"
    ["docs/CMS_MADE_SIMPLE_AUTHENTICATED_RCE_ADAPTATION.md"]="docs/writeups/cms-made-simple/authenticated-rce.md"
    ["docs/scanner_validation_report.md"]="docs/audit-reports/scanner-validation-report.md"
    ["docs/sqli_scanner_postgresql_improvements.md"]="docs/audit-reports/sqli-postgresql-analysis.md"
    ["guides/GETTING_STARTED.md"]="guides/getting-started.md"
    ["roadmaps/HTB_HARD_UPGRADE.md"]="roadmaps/htb-hard-upgrade.md"
)

# Update all markdown files
for old_path in "${!replacements[@]}"; do
    new_path="${replacements[$old_path]}"
    echo "Updating: $old_path → $new_path"

    find . -name "*.md" -type f -not -path "./.git/*" -exec \
        sed -i "s|${old_path}|${new_path}|g" {} \;
done

echo "✓ Cross-reference update complete"
```

---

## Benefits of New Structure

### For Users

**Before:**
```
docs/
├── MASTER_INDEX.md
├── QUICK_REFERENCE.md
├── CMS_MADE_SIMPLE_EXPLOIT_ADAPTATION.md
├── CMS_MADE_SIMPLE_AUTHENTICATED_RCE_ADAPTATION.md
├── PARAM_DISCOVERY_GUIDE.md
├── PIPELINE_SQLI_FU.md
├── SCAN_ANALYZER.md
├── TIME_SQLI_METHODOLOGY.md
├── scanner_validation_report.md
├── sqli_scanner_postgresql_improvements.md
└── ... (subdirectories)
```
- 10 files to scan in root
- Mix of user guides, internal reports, target writeups
- Unclear naming (SCREAMING_CASE vs snake_case)
- Hard to find relevant documentation

**After:**
```
docs/
├── README.md                  # Clear entry point
├── master-index.md            # Comprehensive catalog
├── guides/                    # User-facing guides (organized)
├── writeups/                  # Educational attack narratives
├── roadmaps/                  # Project roadmaps
├── audit-reports/             # Internal analysis (separated)
└── archive/                   # Historical docs (preserved)
```
- 2 files in root (clear navigation)
- Logical categorization by purpose
- Consistent kebab-case naming
- Easy to find documentation by type

### For Developers

**Benefits:**
1. **Clearer Separation:** User docs vs internal docs vs writeups
2. **Easier Maintenance:** Know where new docs belong
3. **Better Discoverability:** Scannable directory structure
4. **Consistent Naming:** Predictable file naming patterns
5. **Preserved History:** Git mv maintains file history

### For OSCP Students

**Benefits:**
1. **Quick Access:** Master index provides fast navigation
2. **Categorized Guides:** Web, network, SQLi guides separated
3. **Educational Writeups:** Target-specific attack narratives grouped
4. **Clean Structure:** Less clutter, more focus on learning content

---

## Risks and Mitigation

### Risk 1: Broken Cross-References

**Impact:** High - Links to moved files will 404
**Likelihood:** High - Many files reference docs/

**Mitigation:**
1. Comprehensive grep search before moving files
2. Automated sed replacements for common patterns
3. Manual verification of critical files (README.md, master-index.md)
4. Test all links in master-index.md after migration

### Risk 2: Git History Loss

**Impact:** Medium - Harder to track file evolution
**Likelihood:** Low - Using git mv preserves history

**Mitigation:**
1. **Always use `git mv`** instead of `mv` command
2. Verify git log shows file history after move:
   ```bash
   git log --follow docs/guides/web-param-discovery.md
   ```
3. Git mv maintains linkage to original file

### Risk 3: External Tool References

**Impact:** Low - External scripts may hardcode paths
**Likelihood:** Low - Most references are relative

**Mitigation:**
1. Search for hardcoded paths in Python/shell scripts:
   ```bash
   grep -r "docs/PARAM_DISCOVERY_GUIDE" --include="*.py" --include="*.sh"
   ```
2. Update any found references
3. Test tools after migration

### Risk 4: User Confusion During Transition

**Impact:** Low - Temporary disorientation
**Likelihood:** Medium - Users may have bookmarked old paths

**Mitigation:**
1. Update master-index.md immediately after migration
2. Create clear README.md in docs/ root
3. Document migration in git commit message
4. Consider adding deprecation notes in moved locations (if keeping old structure temporarily)

---

## Success Criteria

### Phase Completion Checklist

**Phase 1: Directory Creation**
- [ ] `docs/writeups/cms-made-simple/` created
- [ ] `docs/guides/sqli/` created
- [ ] Verified with `ls -ld` command

**Phase 2: File Migration**
- [ ] All 10 files moved to correct locations
- [ ] All files renamed to kebab-case
- [ ] Git history preserved (verified with `git log --follow`)
- [ ] Only 2 files remain in docs/ root

**Phase 3: Cross-Reference Updates**
- [ ] All references found with grep commands
- [ ] Critical files updated (README.md, master-index.md, CLAUDE.md)
- [ ] Module documentation updated
- [ ] Automated update script run

**Phase 4: Documentation Updates**
- [ ] master-index.md updated with new paths
- [ ] README.md created in docs/ root
- [ ] audit-reports/INDEX.md updated (if exists)

**Phase 5: Verification**
- [ ] `tree` output matches expected structure
- [ ] File count in docs/ root = 2
- [ ] All links in master-index.md work
- [ ] Grep searches return no old references
- [ ] Git status shows clean renames

**Phase 6: Testing**
- [ ] Navigate through documentation from README.md
- [ ] Verify all category subdirectories accessible
- [ ] Test master-index.md navigation links
- [ ] Confirm no broken references in CLAUDE.md

---

## Rollback Plan

**If issues arise during migration:**

```bash
# Rollback using git
cd /home/kali/OSCP/crack

# Option 1: Soft rollback (keep working directory changes)
git reset --soft HEAD^

# Option 2: Hard rollback (discard all changes)
git reset --hard HEAD^

# Option 3: Revert specific commit
git revert <commit-hash>

# Verify rollback
git log --oneline -5
ls -la docs/
```

**Manual rollback (if git doesn't work):**
1. Restore files from git history:
   ```bash
   git checkout HEAD~1 docs/
   ```
2. Verify original structure restored
3. Identify what went wrong
4. Fix issue and retry migration

---

## Implementation Timeline

**Estimated Time: 45-60 minutes**

| Phase | Task | Time | Dependencies |
|-------|------|------|--------------|
| 1 | Create new directories | 2 min | None |
| 2 | Move and rename files (git mv) | 10 min | Phase 1 |
| 3 | Search for cross-references (grep) | 5 min | None (parallel with Phase 2) |
| 4 | Update critical files (README, master-index, CLAUDE) | 15 min | Phase 2, 3 |
| 5 | Update module documentation | 10 min | Phase 4 |
| 6 | Create docs/README.md | 5 min | Phase 2 |
| 7 | Run automated update script | 3 min | Phase 4, 5 |
| 8 | Verify structure and test links | 10 min | All phases |

**Total:** 60 minutes (with buffer for troubleshooting)

---

## Post-Migration Actions

### Immediate Actions (Same Day)

1. **Commit Changes:**
   ```bash
   cd /home/kali/OSCP/crack
   git add -A
   git commit -m "docs: restructure documentation with clean root and categorized subdirs

   - Moved 8 files from docs/ root to categorized subdirectories
   - Renamed all files to kebab-case for consistency
   - Created docs/README.md as entry point
   - Renamed MASTER_INDEX.md → master-index.md
   - Removed redundant QUICK_REFERENCE.md
   - Created writeups/ category for educational attack narratives
   - Grouped SQLi guides under guides/sqli/
   - Updated all cross-references in master-index.md, README.md, CLAUDE.md

   Structure: 2 files in root, rest in guides/, writeups/, roadmaps/, audit-reports/"
   ```

2. **Test Navigation:**
   - Open `/home/kali/OSCP/crack/docs/README.md` and verify links
   - Open `/home/kali/OSCP/crack/docs/master-index.md` and test quick navigation
   - Verify moved files accessible from new paths

3. **Update Documentation Stats:**
   - Update file counts in master-index.md if needed
   - Verify "Last Updated" date is current

### Follow-Up Actions (Next Session)

1. **Monitor for Broken Links:**
   - Run link checker if available
   - Ask users to report broken references

2. **Update External References:**
   - Check if any external tools reference old paths
   - Update any scripts or configs

3. **Archive Old Structure (Optional):**
   - Create snapshot of old structure in archive/2025-10-10/
   - Include mapping file showing old → new paths

---

## Appendix: File Content Analysis

### Files Being Moved (Summary)

**User Guides (4 files):**
1. `PARAM_DISCOVERY_GUIDE.md` (8.6KB) - Web parameter fuzzing techniques
2. `SCAN_ANALYZER.md` (6.2KB) - Network scan result analysis
3. `PIPELINE_SQLI_FU.md` (11KB) - SQLi pipeline methodology
4. `TIME_SQLI_METHODOLOGY.md` (11KB) - Time-based blind SQLi techniques

**Writeups (2 files):**
1. `CMS_MADE_SIMPLE_EXPLOIT_ADAPTATION.md` (18KB) - CVE-2019-9053 SQLi exploit adaptation
2. `CMS_MADE_SIMPLE_AUTHENTICATED_RCE_ADAPTATION.md` (20KB) - Authenticated RCE exploitation

**Audit Reports (2 files):**
1. `scanner_validation_report.md` (15KB) - SQLi scanner validation results
2. `sqli_scanner_postgresql_improvements.md` (23KB) - PostgreSQL SQLi enhancement analysis

**Total files moved:** 8 files (~102KB of documentation)
**Total files renamed:** 3 existing files (MASTER_INDEX.md, guides/GETTING_STARTED.md, roadmaps/HTB_HARD_UPGRADE.md)
**Total files removed:** 1 file (QUICK_REFERENCE.md - redundant)

---

## Conclusion

This restructuring plan provides a **clean, organized, and maintainable** documentation structure for the CRACK toolkit. By reducing docs/ root to just 2 essential files and categorizing everything else into logical subdirectories with consistent naming, we improve:

- **User Experience:** Clear navigation, easy to find guides
- **Developer Experience:** Obvious where new docs belong
- **Maintainability:** Consistent naming, logical structure
- **Professionalism:** Clean root directory, descriptive organization

**Next Steps:**
1. Review this plan with user
2. Execute Phase 1-2 (directory creation + file migration)
3. Execute Phase 3-5 (cross-reference updates)
4. Execute Phase 6 (verification)
5. Commit changes with descriptive message
6. Monitor for issues in next session

---

**Document Status:** Ready for Review
**Recommended Action:** Proceed with implementation
**Risk Level:** Low (with proper git mv usage and cross-reference updates)
