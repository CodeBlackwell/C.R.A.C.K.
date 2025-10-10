# Filename Normalization Audit

**Generated:** 2025-10-10
**Scope:** `/home/kali/OSCP/crack/`
**Total Files Analyzed:** 309 markdown files

---

## Executive Summary

### Key Findings

- **Total Files:** 309 markdown files across project
- **SCREAMING_SNAKE_CASE:** 124 files (40.1%)
- **kebab-case:** 45 files (14.6%)
- **snake_case:** 65 files (21.0%)
- **Mixed/PascalCase:** 19 files (6.1%)
- **README.md:** 56 files (18.1%)

### Critical Issues

1. **Root documentation inconsistency** - Mix of SCREAMING_SNAKE_CASE and snake_case in highly visible `/docs/` directory
2. **Mining reports chaos** - Wildly inconsistent naming across 200+ service plugin mining reports
3. **User-facing confusion** - Key guides use different conventions (GETTING_STARTED.md vs quick-reference.md)
4. **Non-descriptive names** - CR4CK-DEV.md, CrackPot.md, CR4KSMITH.md in agent directory
5. **Redundant patterns** - "MINING_REPORT" suffix appears in filenames already in `mining_reports/` directory

### Health Metrics

- **Consistent Directories:** `reference/docs/` (100% kebab-case), `roadmap/` (100% kebab-case)
- **Inconsistent Directories:** `/docs/` (50/50 split), `track/services/plugin_docs/mining_reports/*` (complete chaos)
- **Non-Descriptive Rate:** ~8% of files have unclear purpose from filename alone

---

## Detailed Analysis by Naming Convention

### SCREAMING_SNAKE_CASE Files (124 files, 40.1%)

#### Root Documentation (`/docs/`)
```
CMS_MADE_SIMPLE_AUTHENTICATED_RCE_ADAPTATION.md
CMS_MADE_SIMPLE_EXPLOIT_ADAPTATION.md
MASTER_INDEX.md
PARAM_DISCOVERY_GUIDE.md
PIPELINE_SQLI_FU.md
QUICK_REFERENCE.md
SCAN_ANALYZER.md
TIME_SQLI_METHODOLOGY.md
```

**Analysis:** High-visibility user-facing documentation using all caps. Makes sense for major guides, but inconsistent with some subdirectories.

#### Audit Reports (`/docs/audit-reports/`)
```
ARCHIVE_ORGANIZATION_REPORT.md
DEV_HISTORY_ARCHIVAL_PLAN.md
FINAL_CONSOLIDATION_REPORT.md
INDEX.md
MASTER_INDEX_CREATION_REPORT.md
MINING_REPORT_AUDIT.md
MINING_REPORT_CONSOLIDATION_REPORT.md
README_CONSOLIDATION_PLAN.md
README_CONSOLIDATION_SUMMARY.md
README_STRUCTURE_VISUALIZATION.md
README_UNIFICATION_REPORT.md
ROOT_CLEANUP_PLAN.md
VERBOSITY_REDUCTION_REPORT.md
```

**Analysis:** 100% SCREAMING_SNAKE_CASE. Consistent convention within directory. Appropriate for formal audit documentation.

#### Track Documentation (`/track/docs/`)
```
ALTERNATIVE_COMMANDS_INTEGRATION_PLAN.md
ARCHITECTURE.md
CHANGELOG.md
DEBUG_LOGGING_CHEATSHEET.md
FUZZY_SEARCH.md
INDEX.md
INTERACTIVE_MODE_GUIDE.md
INTERACTIVE_MODE_TOOLS_GUIDE.md
INTERACTIVE_TOOLS_API.md
NSE_QUICK_REFERENCE.md
NSE_SCRIPTS_OSCP_REFERENCE.md
PANEL_DEVELOPER_GUIDE.md
QUICKSTART_INTERACTIVE_TOOLS.md
SCAN_PROFILES.md
SCREENED_MODE.md
TEMPLATES.md
TOOL_INTEGRATION_MATRIX.md
TUI_ARCHITECTURE.md
USAGE_GUIDE.md
VALUE_METRICS.md
WINDOWS_PRIVESC_FIX.md
```

**Analysis:** Mostly SCREAMING_SNAKE_CASE (21 files), signaling these are primary documentation. Good for developer-facing guides.

#### Track Components (`/track/docs/components/`)
```
INPUT_VALIDATOR.md
```

**Analysis:** Single file, SCREAMING_SNAKE_CASE. Sets precedent for component documentation.

#### Track Panels (`/track/docs/panels/`)
```
CREDENTIAL_FORM.md
CREDENTIAL_FORM_QUICKREF.md
FINDING_FORM_QUICKREF.md
```

**Analysis:** 100% SCREAMING_SNAKE_CASE for panel documentation.

#### Sessions Documentation (`/sessions/`)
```
DNS_TUNNEL_GUIDE.md
HTTP_BEACON_USAGE.md
ICMP_TUNNEL_GUIDE.md
SHELL_ENHANCEMENT_GUIDE.md
TCP_USAGE.md
TUNNEL_GUIDE.md
```

**Analysis:** 100% SCREAMING_SNAKE_CASE. Consistent user-facing guides.

#### Track Services (`/track/services/`)
```
PLUGIN_CONTRIBUTION_GUIDE.md
```

**Analysis:** Main guide uses SCREAMING_SNAKE_CASE.

#### Track Archives (`/track/docs/archive/`)
**Development Reports:** 37 files in SCREAMING_SNAKE_CASE format
```
AGENT_F0_B_REPORT.md
ALTERNATIVES_PHASE2_SUMMARY.md
ALTERNATIVE_COMMANDS_IMPLEMENTATION_SUMMARY.md
CHANGELOG_CHAPTER8_ENHANCEMENTS.md
... (33 more)
```

**Planning:** 3 files
```
IMPROVEMENTS.md
PRODUCTION_CHECKLIST.md
ROADMAP.md
```

**QA:** 4 files
```
DOCUMENTATION_VERIFICATION_REPORT.md
ERROR_HANDLING_REPORT.md
FINAL_QA_REPORT.md
VALIDATION_REPORT.md
```

**Testing:** 4 files
```
INTEGRATION_QUICK_FIX.md
INTEGRATION_SUMMARY.md
INTEGRATION_TEST_REPORT.md
```

**Analysis:** Archived development history maintains SCREAMING_SNAKE_CASE consistently. Appropriate for formal historical records.

#### Agent Reports (`/track/services/plugin_docs/agent_reports/`)
```
AGENT5_CLEANUP_REPORT.md
AGENT6_ANDROID_MOBILE_CLEANUP_REPORT.md
AGENT8_CLEANUP_REPORT.md
```

**Analysis:** Agent-generated cleanup reports use SCREAMING_SNAKE_CASE.

#### Service Plugin Summaries (`/track/services/plugin_docs/summaries/`)
```
ANTI_FORENSICS_DELIVERY.md
ANTI_FORENSICS_PLUGIN_SUMMARY.md
BINARY_EXPLOIT_PLUGIN.md
C2_ANALYSIS_PLUGIN_SUMMARY.md
HEAP_EXPLOIT_README.md
LUA_EXPLOIT_PLUGIN_SUMMARY.md
NETWORK_ATTACK_PLUGINS_SUMMARY.md
OSINT_WIFI_PLUGIN_SUMMARY.md
PHISHING_PLUGIN_SUMMARY.md
PYTHON_WEB_PLUGIN_SUMMARY.md
```

**Analysis:** 100% SCREAMING_SNAKE_CASE for plugin summaries. Consistent within directory.

#### Mining Reports (Partial List - Major Examples)
```
AD_INFRASTRUCTURE_MINING_REPORT.md
CAPABILITIES_MINING_REPORT.md
DEV_TOOLS_MINING_REPORT.md
FILE_TRANSFER_MINING_REPORT.md
FILE_UPLOAD_MINING_REPORT.md
GENERIC_ATTACKS_MINING_REPORT.md
IOS_PROTOCOLS_MINING_REPORT.md
LEGACY_PROTOCOLS_MINING_REPORT.md
LINUX_KERNEL_EXPLOIT_MINING_REPORT.md
LINUX_PERSISTENCE_MINING_REPORT.md
LINUX_PRIVESC_BASICS_MINING_REPORT.md
MACOS_IPC_MINING_REPORT.md
MACOS_NETWORK_MINING_REPORT.md
MACOS_PROCESS_ABUSE_MINING_REPORT.md
MINING_REPORT_MACOS_MDM.md
MINING_REPORT_MACOS_MISC.md
MSSQL_MINING_REPORT.md
NETWORK_SERVICES_MINING_REPORT.md
REDIRECT_ATTACKS_MINING_REPORT.md
REVERSE_SHELLS_MINING_REPORT.md
RUBY_RAILS_MINING_REPORT.md
SSRF_ATTACKS_MINING_REPORT.md
```

**Analysis:** 50+ mining reports use SCREAMING_SNAKE_CASE with "MINING_REPORT" suffix, creating verbose filenames in already categorized directories.

---

### kebab-case Files (45 files, 14.6%)

#### Reference Documentation (`/reference/docs/`)
```
config.md
placeholders.md
quick-reference.md
quick-wins.md
tags.md
```

**Analysis:** 100% kebab-case (5/5 files). Most consistent directory in project. Excellent for scanability.

#### Roadmap Directory (`/roadmap/`)
```
service-relationship-mapper.md
```

**Analysis:** Single file using kebab-case.

#### Agent Names (`.claude/agents/`)
```
00-cve-researcher.md
01-recon-scout.md
02-content-architect.md
03-scenario-enricher.md
04-reference-integrator.md
05-document-beautifier.md
alternative-command-dev.md
command-expander.md
context-fetcher.md
date-checker.md
file-creator.md
git-workflow.md
pentest-toolsmith.md
project-manager.md
test-runner.md
tui-dev.md
```

**Analysis:** 16/21 agent files use kebab-case. Clean, professional naming. Numbered prefixes provide ordering.

#### Commands (`.claude/commands/`)
```
analyze-product.md
create-spec.md
create-tasks.md
execute-tasks.md
plan-product.md
```

**Analysis:** 100% kebab-case. Consistent with modern CLI conventions.

#### Track Implementation Docs (`/track/docs/implementation/`)
```
batch_execute.md
quick_execute.md
quick_export.md
smart_suggest.md
task_filter.md
workflow_recorder.md
```

**Analysis:** 100% snake_case (not kebab). Inconsistent with reference/ directory which uses kebab-case for similar technical docs.

#### Nmap Cookbook (`/track/docs/nmap_cookbook/`)
```
chapter_03_enhancements.md
chapter_03_scan_profiles.md
chapter_04_integration.md
chapter_08_quickstart.md
chapter_08_summary.md
chapter_09_nse_advanced.md
```

**Analysis:** 100% snake_case for chapter-based documentation.

---

### snake_case Files (65 files, 21.0%)

#### Root Docs (Technical Reports)
```
scanner_validation_report.md
sqli_scanner_postgresql_improvements.md
```

**Analysis:** Lowercase for technical implementation reports. Contrast with SCREAMING_SNAKE_CASE guides in same directory creates inconsistency.

#### Track Interactive (`/track/interactive/`)
```
CATEGORY_REFERENCE.md (SCREAMING)
DEBUG_LOGGING_GUIDE.md (SCREAMING)
```

**Analysis:** Main directory uses SCREAMING_SNAKE_CASE.

#### Track Interactive Components (`/track/interactive/components/`)
```
ERROR_HANDLER_README.md (SCREAMING)
```

#### Track Interactive State (`/track/interactive/state/`)
```
README.md
```

#### Plugin Docs - Implementation (`/track/services/plugin_docs/implementations/`)
```
anti_forensics_implementation.md
hacktricks_ch02_implementation.md
nmap_ch5_database_implementation.md
```

**Analysis:** 100% snake_case for implementation details. Makes sense to distinguish from high-level guides.

#### Plugin Docs - Plugin READMEs (`/track/services/plugin_docs/plugin_readmes/`)
```
anti_forensics_plugin_readme.md
binary_exploit_plugin_readme.md
c2_analysis_plugin_readme.md
heap_exploit_plugin_readme.md
lua_exploit_plugin_readme.md
network_attack_plugins_readme.md
osint_wifi_plugin_readme.md
phishing_plugin_readme.md
python_web_plugin_readme.md
```

**Analysis:** 100% snake_case for plugin-specific READMEs. Distinguishes from summaries/ directory which uses SCREAMING_SNAKE_CASE.

#### Mining Reports - Mixed Convention
```
linux_enumeration_mining_report.md
linux_shell_escaping_mining_report.md
linux_shell_escaping_summary.md
network_services_mining_report.md
rop_mining_report.md
stack_overflow_mining_report.md
steganography_mining_report.md
cryptography_mining_report.md
cryptography_remine_report.md
macos_enumeration_mining_report.md
macos_filesystem_mining_report.md
macos_kernel_security_mining_report.md
macos_programming_mining_report.md
reversing_remine_report.md
android_mining_report.md
mobile_pentesting_misc_mining_report.md
ai_security_mining_report.md
arm64_mining_report.md
blockchain_mining_report.md
blockchain_remine_report.md
browser_exploit_mining_report.md
hardware_remine_report.md
llm_attacks_mining_report.md
radio_hacking_mining_report.md
ios_app_analysis.md
ios_binary_exploit_mining_report.md
ios_hooking_mining_report.md
ios_pentesting_mining_report.md
```

**Analysis:** 28 mining reports use snake_case vs 50+ using SCREAMING_SNAKE_CASE. Major inconsistency within same category of documents.

---

### Mixed/PascalCase Files (19 files, 6.1%)

#### Agent Names (`.claude/agents/`)
```
CR4CK-DEV.md
CR4KSMITH.md
CrackPot.md
TRACKER.md
```

**Analysis:** Non-descriptive "clever" names that don't convey agent purpose. Should follow numbered convention like other agents.

---

### README.md Files (56 files, 18.1%)

**Distribution:**
- Root: 1
- .pytest_cache: 1 (auto-generated)
- reference/: 1
- sessions/: 1
- tests/: 1
- tests/reference/: 1
- tests/track/: 1
- track/: 1
- track/alternatives/: 1
- track/alternatives/commands/: 1
- track/docs/archive: 1
- track/interactive/state/: 1
- track/services/plugin_docs/: 1
- track/services/plugin_docs/agent_reports/: 1
- track/services/plugin_docs/archive/: 1
- track/services/plugin_docs/implementations/: 1
- track/services/plugin_docs/plugin_readmes/: 1
- track/services/plugin_docs/summaries/: 1
- track/wordlists/: 1
- Mining report categories: 37 READMEs

**Analysis:** Heavy use of README.md as directory index. Appropriate convention, but many lack INDEX.md alternatives for formal documentation directories.

---

## Non-Descriptive Filenames

### Critical Issues (User-Facing)

| File | Location | Issue | Suggested Name |
|------|----------|-------|----------------|
| `CR4CK-DEV.md` | `.claude/agents/` | L33t speak, unclear purpose | `06-crack-developer.md` |
| `CR4KSMITH.md` | `.claude/agents/` | L33t speak, unclear purpose | `07-service-plugin-generator.md` |
| `CrackPot.md` | `.claude/agents/` | Joke name, unclear purpose | `08-documentation-validator.md` |
| `TRACKER.md` | `.claude/agents/` | Generic name | `09-task-tracker-specialist.md` |
| `MANIFEST.md` | `/docs/archive/` | Generic, redundant with INDEX.md | Consider merging with INDEX.md |

### Moderate Issues (Technical Docs)

| File | Location | Issue | Improvement |
|------|----------|-------|-------------|
| `IMPROVEMENTS.md` | `track/docs/archive/planning/` | Too generic | `track_improvements_backlog.md` |
| `ROADMAP.md` | Multiple locations | Ambiguous scope | Prefix with module (e.g., `track_roadmap.md`) |
| `CHANGELOG.md` | Multiple locations | Which component? | Prefix with module |
| `INDEX.md` | Multiple locations | What's being indexed? | More specific (e.g., `DOCUMENTATION_INDEX.md`) |

### Low Priority (Archives)

| File | Location | Issue |
|------|----------|-------|
| `PHASE_*.md` | `track/docs/archive/development/` | Numbered phases hard to track without context |
| `F0-A_*.md`, `F1-A_*.md` | `track/docs/archive/development/` | Unclear phase naming convention |

---

## Directory-by-Directory Analysis

### `/docs/` (Root Documentation)

**Current State:** Mixed (5 SCREAMING, 2 snake_case)

**Files:**
- SCREAMING: `CMS_MADE_SIMPLE_*.md`, `MASTER_INDEX.md`, `PARAM_DISCOVERY_GUIDE.md`, `PIPELINE_SQLI_FU.md`, `QUICK_REFERENCE.md`, `SCAN_ANALYZER.md`, `TIME_SQLI_METHODOLOGY.md`
- snake_case: `scanner_validation_report.md`, `sqli_scanner_postgresql_improvements.md`

**Issue:** Technical reports use snake_case while user guides use SCREAMING_SNAKE_CASE. Same directory, different audiences.

**Recommendation:** SCREAMING_SNAKE_CASE for all user-facing guides. Move technical implementation reports to `/docs/reports/` subdirectory with snake_case.

**Scannability:** Poor (mixed conventions confuse hierarchy)

---

### `/docs/audit-reports/`

**Current State:** 100% SCREAMING_SNAKE_CASE (13 files)

**Consistency:** Excellent

**Recommendation:** Keep as-is. Formal audit documentation benefits from visual distinction.

**Scannability:** Excellent

---

### `/docs/guides/`

**Current State:** 100% SCREAMING_SNAKE_CASE (1 file: `GETTING_STARTED.md`)

**Consistency:** Good (single file)

**Recommendation:** Keep convention for future guides

**Scannability:** Good

---

### `/docs/roadmaps/`

**Current State:** 100% SCREAMING_SNAKE_CASE (1 file: `HTB_HARD_UPGRADE.md`)

**Consistency:** Good

**Recommendation:** Keep convention

**Scannability:** Good

---

### `/reference/docs/`

**Current State:** 100% kebab-case (5 files)

**Consistency:** Excellent - Most consistent directory in project

**Files:** `config.md`, `placeholders.md`, `quick-reference.md`, `quick-wins.md`, `tags.md`

**Recommendation:** Keep as gold standard. Consider adopting kebab-case for all technical API documentation.

**Scannability:** Excellent (clean, modern, scannable)

---

### `/sessions/`

**Current State:** 100% SCREAMING_SNAKE_CASE (6 guides + 1 README)

**Consistency:** Excellent

**Files:** `DNS_TUNNEL_GUIDE.md`, `HTTP_BEACON_USAGE.md`, `ICMP_TUNNEL_GUIDE.md`, `SHELL_ENHANCEMENT_GUIDE.md`, `TCP_USAGE.md`, `TUNNEL_GUIDE.md`

**Recommendation:** Keep as-is. User-facing operational guides.

**Scannability:** Good

---

### `/track/docs/`

**Current State:** Mostly SCREAMING_SNAKE_CASE (21 files)

**Consistency:** Good (95% consistent)

**Files:** Primary developer documentation for track module

**Recommendation:** Keep SCREAMING_SNAKE_CASE for main guides. Consider kebab-case for new API reference docs.

**Scannability:** Good

---

### `/track/docs/components/`

**Current State:** 100% SCREAMING_SNAKE_CASE (1 file)

**Consistency:** Good (establishes pattern)

**Recommendation:** Keep for component documentation

**Scannability:** Good

---

### `/track/docs/panels/`

**Current State:** 100% SCREAMING_SNAKE_CASE (3 files)

**Consistency:** Excellent

**Recommendation:** Keep for panel documentation

**Scannability:** Good

---

### `/track/docs/implementation/`

**Current State:** 100% snake_case (6 files)

**Consistency:** Excellent within directory

**Files:** `batch_execute.md`, `quick_execute.md`, `quick_export.md`, `smart_suggest.md`, `task_filter.md`, `workflow_recorder.md`

**Issue:** Different from `/reference/docs/` (kebab-case) for similar technical documentation

**Recommendation:** Consider standardizing with `/reference/docs/` style (kebab-case) OR keep snake_case to signal "internal implementation details"

**Scannability:** Good

---

### `/track/docs/nmap_cookbook/`

**Current State:** 100% snake_case (6 files)

**Consistency:** Excellent

**Files:** Chapter-based documentation (`chapter_03_*.md`)

**Recommendation:** Keep snake_case for chapter-numbered series

**Scannability:** Good

---

### `/track/services/plugin_docs/mining_reports/`

**Current State:** CHAOS - 50+ SCREAMING_SNAKE_CASE, 28 snake_case

**Consistency:** POOR (worst in project)

**Examples of Inconsistency:**
- `LINUX_KERNEL_EXPLOIT_MINING_REPORT.md` (SCREAMING)
- `linux_enumeration_mining_report.md` (snake_case)
- Both in same category!

**Issue:** "MINING_REPORT" suffix redundant (files already in `mining_reports/` directory)

**Recommendation:**
1. Standardize to snake_case
2. Remove redundant `_mining_report` suffix
3. Result: `linux_kernel_exploit.md`, `linux_enumeration.md`

**Scannability:** POOR (inconsistency causes cognitive load)

---

### `/track/services/plugin_docs/summaries/`

**Current State:** 100% SCREAMING_SNAKE_CASE (10 files)

**Consistency:** Excellent

**Recommendation:** Keep as-is (summaries are user-facing)

**Scannability:** Good

---

### `/track/services/plugin_docs/plugin_readmes/`

**Current State:** 100% snake_case (9 files)

**Consistency:** Excellent

**Recommendation:** Keep snake_case to distinguish from SCREAMING summaries

**Scannability:** Good

---

### `/track/services/plugin_docs/implementations/`

**Current State:** 100% snake_case (3 files)

**Consistency:** Excellent

**Recommendation:** Keep snake_case for implementation details

**Scannability:** Good

---

### `.claude/agents/`

**Current State:** Mixed (16 kebab-case, 5 SCREAMING/PascalCase)

**Consistency:** Poor

**Files:**
- Good: `00-cve-researcher.md` through `05-document-beautifier.md`, plus descriptive names
- Bad: `CR4CK-DEV.md`, `CR4KSMITH.md`, `CrackPot.md`, `TRACKER.md`

**Recommendation:** Standardize all to kebab-case with optional numeric prefix. Rename "clever" names to descriptive ones.

**Scannability:** Poor (inconsistent patterns)

---

### `.claude/commands/`

**Current State:** 100% kebab-case (5 files)

**Consistency:** Excellent

**Recommendation:** Keep as-is

**Scannability:** Excellent

---

## Naming Standard Recommendations

### Proposed Conventions by Document Type

| Document Type | Convention | Rationale | Example |
|---------------|-----------|-----------|---------|
| **User Guides** | SCREAMING_SNAKE_CASE | High visibility, command-like authority | `GETTING_STARTED.md` |
| **Developer Guides** | SCREAMING_SNAKE_CASE | Primary developer documentation | `ARCHITECTURE.md` |
| **API Reference** | kebab-case | Modern, scannable, web-friendly | `quick-reference.md` |
| **Technical Reports** | snake_case | Distinguishes from guides, signals detailed content | `scanner_validation_report.md` |
| **Implementation Details** | snake_case | Internal technical documentation | `batch_execute.md` |
| **Audit/QA Reports** | SCREAMING_SNAKE_CASE | Formal documentation, historical record | `FINAL_QA_REPORT.md` |
| **Mining Reports** | snake_case (no suffix) | Reduce verbosity, directory context provides categorization | `linux_kernel_exploit.md` |
| **Plugin Documentation** | snake_case | Technical integration docs | `anti_forensics_implementation.md` |
| **Agent Definitions** | kebab-case (numbered) | CLI convention, scannable | `06-crack-developer.md` |
| **Command Definitions** | kebab-case | CLI convention | `create-tasks.md` |
| **Chapter-based Docs** | snake_case | Ordered series | `chapter_03_enhancements.md` |

### Migration Strategy

#### Phase 1: High Priority (User-Facing)

**Target:** Root `/docs/`, `.claude/agents/`

**Actions:**
1. Rename agents to descriptive kebab-case:
   - `CR4CK-DEV.md` → `06-crack-developer.md`
   - `CR4KSMITH.md` → `07-service-plugin-generator.md`
   - `CrackPot.md` → `08-documentation-validator.md`
   - `TRACKER.md` → `09-task-tracker-specialist.md`

2. Move technical reports from `/docs/` to `/docs/reports/`:
   - `scanner_validation_report.md` → `/docs/reports/scanner_validation_report.md`
   - `sqli_scanner_postgresql_improvements.md` → `/docs/reports/sqli_scanner_postgresql_improvements.md`

3. Keep all root `/docs/*.md` as SCREAMING_SNAKE_CASE user guides

**Files Affected:** 6 files
**Risk:** Low (agent names in `.claude/` are internal, report moves are organizational)

---

#### Phase 2: Medium Priority (Mining Reports)

**Target:** `/track/services/plugin_docs/mining_reports/*`

**Actions:**
1. Standardize all to snake_case
2. Remove redundant `_mining_report` suffix
3. Update any internal references

**Example Transformations:**
- `LINUX_KERNEL_EXPLOIT_MINING_REPORT.md` → `linux_kernel_exploit.md`
- `AD_INFRASTRUCTURE_MINING_REPORT.md` → `ad_infrastructure.md`
- `PEN300_AMSI_DEFENSES_REMINE_REPORT.md` → `pen300_amsi_defenses_remine.md`

**Files Affected:** ~78 mining report files
**Risk:** Medium (many files, potential internal references)

**Testing Required:**
- Grep for any hardcoded filename references
- Check service plugins for mining report imports
- Verify no broken documentation links

---

#### Phase 3: Low Priority (Archives & Deep Directories)

**Target:** `/track/docs/archive/`, `/track/services/plugin_docs/archive/`

**Actions:**
- Leave archived development history as-is (SCREAMING_SNAKE_CASE)
- These are historical records, not active documentation
- Renaming provides minimal value vs. risk of breaking references

**Files Affected:** 0 (no changes)
**Risk:** None

---

### Rationale for Each Decision

#### Why SCREAMING_SNAKE_CASE for User Guides?

**Pros:**
- High visibility in `ls` output
- Command-like authority ("READ THIS")
- Consistent with existing OSCP mentor voice (imperative, clear)
- Already established pattern in project

**Cons:**
- Less modern than kebab-case
- Can feel "shouty"

**Decision:** Keep for guides. Users expect authoritative documentation to stand out.

---

#### Why kebab-case for API Reference?

**Pros:**
- Modern web convention
- Excellent scannability
- URL-friendly (if docs ever hosted)
- Easier to type (no SHIFT key)
- Already gold standard in `/reference/docs/`

**Cons:**
- Different from guide convention
- Hyphen sometimes harder to type than underscore

**Decision:** Use for technical reference documentation. Signals "look-up docs" vs "read-through guides".

---

#### Why snake_case for Technical Reports?

**Pros:**
- Distinguishes from guides (not user-facing tutorials)
- Common in scientific/technical writing
- Python community convention (relevant for Python project)
- Already used for implementation docs

**Cons:**
- Less scannable than kebab-case

**Decision:** Use for detailed technical reports and implementation docs. Signals "deep dive, not tutorial".

---

#### Why Remove "_mining_report" Suffix?

**Pros:**
- Directory context already says "mining_reports/"
- Reduces filename length by ~14 characters
- Easier to scan and reference
- Example: `linux_kernel_exploit.md` vs `LINUX_KERNEL_EXPLOIT_MINING_REPORT.md` (21 vs 39 chars)

**Cons:**
- Breaking change requires reference updates
- Loss of explicit categorization in filename

**Decision:** Remove suffix. Directory structure provides categorization. Shorter names improve scannability and command-line usability.

---

## Priority Categorization

### High Priority (User Impact)

**Timeline:** Before next release

**Files:** 6-10 files

**Changes:**
1. Rename `.claude/agents/` non-descriptive files
2. Move `/docs/` technical reports to `/docs/reports/`
3. Update CLAUDE.md if it references renamed files
4. Update README.md if it references renamed files

**Reason:** User-facing confusion, onboarding friction

**Effort:** 1-2 hours

---

### Medium Priority (Developer Experience)

**Timeline:** Next development cycle

**Files:** ~78 mining report files

**Changes:**
1. Standardize mining reports to snake_case
2. Remove redundant suffixes
3. Update any internal references
4. Run full test suite to catch broken imports

**Reason:** Inconsistency causes cognitive load during development

**Effort:** 4-6 hours (grep for references, batch rename, testing)

---

### Low Priority (Nice-to-Have)

**Timeline:** Backlog / Never

**Files:** Archived development history

**Changes:** None

**Reason:** Historical documents, low ROI for renaming

**Effort:** N/A

---

## Impact Assessment

### Files to Rename (High + Medium Priority)

**Total:** 84-88 files

**Breakdown:**
- Agents: 4 files
- Root docs: 2 files (move, not rename)
- Mining reports: 78 files

### Potential Broken References

**Risk Areas:**
1. Service plugins importing mining reports
2. Documentation internal links
3. CLAUDE.md agent references
4. README.md guide references
5. Test fixtures referencing specific filenames

### Testing Requirements

**Pre-Migration:**
```bash
# Find all hardcoded filename references
grep -r "MINING_REPORT\.md" /home/kali/OSCP/crack/
grep -r "CR4CK-DEV" /home/kali/OSCP/crack/
grep -r "scanner_validation_report" /home/kali/OSCP/crack/

# Find Python imports referencing docs
grep -r "mining_reports" /home/kali/OSCP/crack/**/*.py
```

**Post-Migration:**
```bash
# Verify no broken imports
python3 -m pytest tests/ --collect-only

# Verify no broken doc links
grep -r "\.md" /home/kali/OSCP/crack/docs/ | grep -o '\[.*\](.*\.md)' | grep -v "^README"

# Full test suite
./run_tests.sh all
```

### Rollback Plan

**Git workflow:**
```bash
# Before changes
git checkout -b feature/filename-normalization

# Make changes
# ... rename files ...

# Commit with detailed log
git add .
git commit -m "refactor: normalize markdown filenames per audit

- Rename agents to descriptive kebab-case
- Move technical reports to /docs/reports/
- Standardize mining reports to snake_case
- Remove redundant _mining_report suffix

Ref: docs/audit-reports/filename_normalization_audit.md"

# If issues found
git revert HEAD
# Or
git reset --hard origin/main
```

---

## Excluded Patterns (Keep As-Is)

### README.md Files

**Decision:** Keep standard `README.md` naming

**Reason:** Universal convention, expected by Git platforms, tools, and developers

**Count:** 56 files

---

### `.pytest_cache/README.md`

**Decision:** Leave auto-generated files alone

**Reason:** Managed by pytest, not project-specific

**Count:** 1 file

---

### Archived Development History

**Decision:** No changes to `/track/docs/archive/development/`

**Reason:** Historical record, renaming provides minimal value

**Count:** 48 files

---

### PEN-300 Reference Material

**Decision:** Keep original naming from `.references/pen-300-chapters/`

**Reason:** External reference material, preserve as sourced

**Count:** 1 file (`table_of_contents.md`)

---

## Recommendations Summary

### Adopt These Standards Going Forward

| Location | Convention | When to Use |
|----------|-----------|-------------|
| `/docs/` (guides) | SCREAMING_SNAKE_CASE | User-facing tutorials and guides |
| `/docs/reports/` | snake_case | Technical implementation reports |
| `/docs/audit-reports/` | SCREAMING_SNAKE_CASE | Formal audit documentation |
| `/reference/docs/` | kebab-case | API reference, quick-reference docs |
| `/sessions/` | SCREAMING_SNAKE_CASE | User-facing operational guides |
| `/track/docs/` | SCREAMING_SNAKE_CASE | Primary developer guides |
| `/track/docs/implementation/` | snake_case | Implementation details |
| `/track/docs/nmap_cookbook/` | snake_case | Chapter-based series |
| `/track/services/plugin_docs/mining_reports/` | snake_case (no suffix) | Mining reports |
| `/track/services/plugin_docs/summaries/` | SCREAMING_SNAKE_CASE | Plugin summaries |
| `/track/services/plugin_docs/plugin_readmes/` | snake_case | Plugin technical docs |
| `.claude/agents/` | kebab-case | Agent definitions |
| `.claude/commands/` | kebab-case | Command definitions |

### Key Principles

1. **User-facing guides:** SCREAMING_SNAKE_CASE (visibility, authority)
2. **Technical references:** kebab-case (modern, scannable, web-friendly)
3. **Implementation details:** snake_case (Python convention, technical signal)
4. **Consistency within directory:** More important than global convention
5. **Remove redundant information:** Directory provides context
6. **Descriptive over clever:** `06-crack-developer.md` not `CR4CK-DEV.md`

### Migration Priorities

**Now:** Rename 4 agent files, move 2 technical reports

**Next Sprint:** Standardize 78 mining reports

**Never:** Rename archived history

---

## Appendix: Full File Inventory

### Complete List of SCREAMING_SNAKE_CASE Files (124)

```
./docs/CMS_MADE_SIMPLE_AUTHENTICATED_RCE_ADAPTATION.md
./docs/CMS_MADE_SIMPLE_EXPLOIT_ADAPTATION.md
./docs/MASTER_INDEX.md
./docs/PARAM_DISCOVERY_GUIDE.md
./docs/PIPELINE_SQLI_FU.md
./docs/QUICK_REFERENCE.md
./docs/SCAN_ANALYZER.md
./docs/TIME_SQLI_METHODOLOGY.md
./docs/audit-reports/ARCHIVE_ORGANIZATION_REPORT.md
./docs/audit-reports/DEV_HISTORY_ARCHIVAL_PLAN.md
./docs/audit-reports/FINAL_CONSOLIDATION_REPORT.md
./docs/audit-reports/INDEX.md
./docs/audit-reports/MASTER_INDEX_CREATION_REPORT.md
./docs/audit-reports/MINING_REPORT_AUDIT.md
./docs/audit-reports/MINING_REPORT_CONSOLIDATION_REPORT.md
./docs/audit-reports/README_CONSOLIDATION_PLAN.md
./docs/audit-reports/README_CONSOLIDATION_SUMMARY.md
./docs/audit-reports/README_STRUCTURE_VISUALIZATION.md
./docs/audit-reports/README_UNIFICATION_REPORT.md
./docs/audit-reports/ROOT_CLEANUP_PLAN.md
./docs/audit-reports/VERBOSITY_REDUCTION_REPORT.md
./docs/guides/GETTING_STARTED.md
./docs/roadmaps/HTB_HARD_UPGRADE.md
./docs/archive/MANIFEST.md
./docs/archive/2025-10-09/FREEZE_ANALYSIS.md
./docs/archive/2025-10-09/HTTP_PLUGIN_FIX_REPORT.md
./docs/archive/2025-10-10/INPUT_VALIDATOR_QUICKREF.md
./docs/archive/2025-10-10/INTEGRATION_CHECKLIST.md
./sessions/DNS_TUNNEL_GUIDE.md
./sessions/HTTP_BEACON_USAGE.md
./sessions/ICMP_TUNNEL_GUIDE.md
./sessions/SHELL_ENHANCEMENT_GUIDE.md
./sessions/TCP_USAGE.md
./sessions/TUNNEL_GUIDE.md
./track/docs/ALTERNATIVE_COMMANDS_INTEGRATION_PLAN.md
./track/docs/ARCHITECTURE.md
./track/docs/CHANGELOG.md
./track/docs/DEBUG_LOGGING_CHEATSHEET.md
./track/docs/FUZZY_SEARCH.md
./track/docs/INDEX.md
./track/docs/INTERACTIVE_MODE_GUIDE.md
./track/docs/INTERACTIVE_MODE_TOOLS_GUIDE.md
./track/docs/INTERACTIVE_TOOLS_API.md
./track/docs/NSE_QUICK_REFERENCE.md
./track/docs/NSE_SCRIPTS_OSCP_REFERENCE.md
./track/docs/PANEL_DEVELOPER_GUIDE.md
./track/docs/QUICKSTART_INTERACTIVE_TOOLS.md
./track/docs/SCAN_PROFILES.md
./track/docs/SCREENED_MODE.md
./track/docs/TEMPLATES.md
./track/docs/TOOL_INTEGRATION_MATRIX.md
./track/docs/TUI_ARCHITECTURE.md
./track/docs/USAGE_GUIDE.md
./track/docs/VALUE_METRICS.md
./track/docs/WINDOWS_PRIVESC_FIX.md
./track/docs/components/INPUT_VALIDATOR.md
./track/docs/panels/CREDENTIAL_FORM.md
./track/docs/panels/CREDENTIAL_FORM_QUICKREF.md
./track/docs/panels/FINDING_FORM_QUICKREF.md
./track/docs/archive/development/AGENT_F0_B_REPORT.md
./track/docs/archive/development/ALTERNATIVES_PHASE2_SUMMARY.md
./track/docs/archive/development/ALTERNATIVE_COMMANDS_IMPLEMENTATION_SUMMARY.md
./track/docs/archive/development/CHANGELOG_CHAPTER8_ENHANCEMENTS.md
./track/docs/archive/development/CHANGELOG_COMMAND_HISTORY.md
./track/docs/archive/development/CHANGELOG_FUZZY_SEARCH.md
./track/docs/archive/development/CHANGELOG_PORT_LOOKUP.md
./track/docs/archive/development/CHANGELOG_SCAN_PROFILES.md
./track/docs/archive/development/CHANGELOG_SCAN_PROFILES_CH01.md
./track/docs/archive/development/CHANGELOG_TEMPLATES.md
./track/docs/archive/development/CHAPTER_09_NSE_IMPLEMENTATION_SUMMARY.md
./track/docs/archive/development/CLEANUP_SUMMARY.md
./track/docs/archive/development/F0-A_FOUNDATION_REPORT.md
./track/docs/archive/development/F1-A_TCP_IMPLEMENTATION_REPORT.md
./track/docs/archive/development/F1-C_SHELL_ENHANCEMENT_REPORT.md
./track/docs/archive/development/F2-B_DNS_ICMP_IMPLEMENTATION_REPORT.md
./track/docs/archive/development/FINAL_INTEGRATION_REPORT.md
./track/docs/archive/development/HTTP_BEACON_SUMMARY.md
./track/docs/archive/development/IMPLEMENTATION_SUMMARY_CH02.md
./track/docs/archive/development/P2_FIX_SUMMARY.md
./track/docs/archive/development/PHASE4_5_DOCUMENTATION_COMPLETE.md
./track/docs/archive/development/PHASE4_IMPROVEMENTS.md
./track/docs/archive/development/PHASE4_ISSUES.md
./track/docs/archive/development/PHASE4_TEST_COVERAGE_REPORT.md
./track/docs/archive/development/PHASE4_VERIFICATION_SUMMARY.md
./track/docs/archive/development/PHASE5_BENCHMARKS.md
./track/docs/archive/development/PHASE5_IMPROVEMENTS.md
./track/docs/archive/development/PHASE5_TEST_COVERAGE_REPORT.md
./track/docs/archive/development/PHASE7_IMPLEMENTATION_SUMMARY.md
./track/docs/archive/development/PHASE_2_IMPLEMENTATION_REPORT.md
./track/docs/archive/development/PHASE_4_COMPLETION_REPORT.md
./track/docs/archive/development/PHASE_4_STAGE1_COMPLETION.md
./track/docs/archive/development/PHASE_5_6_COMPLETION_REPORT.md
./track/docs/archive/development/PHASE_6.4_6.5_COMPLETION_REPORT.md
./track/docs/archive/development/PHASE_6_1_6_2_IMPLEMENTATION_SUMMARY.md
./track/docs/archive/development/PHASE_6_3_COMPLETION_REPORT.md
./track/docs/archive/development/TUNNEL_IMPLEMENTATION_REPORT.md
./track/docs/archive/development/WORDLIST_PHASE1_SUMMARY.md
./track/docs/archive/development/WORDLIST_RESOLUTION_FIX_SUMMARY.md
./track/docs/archive/development/WORDLIST_SELECTION_IMPLEMENTATION.md
./track/docs/archive/planning/IMPROVEMENTS.md
./track/docs/archive/planning/PHASE_5_6_EXECUTION_CHECKLIST.md
./track/docs/archive/planning/PRODUCTION_CHECKLIST.md
./track/docs/archive/planning/ROADMAP.md
./track/docs/archive/qa/DOCUMENTATION_VERIFICATION_REPORT.md
./track/docs/archive/qa/ERROR_HANDLING_REPORT.md
./track/docs/archive/qa/FINAL_QA_REPORT.md
./track/docs/archive/qa/VALIDATION_REPORT.md
./track/docs/archive/scripts/VIDEO_TUTORIAL_SCRIPT.md
./track/docs/archive/testing/INTEGRATION_QUICK_FIX.md
./track/docs/archive/testing/INTEGRATION_SUMMARY.md
./track/docs/archive/testing/INTEGRATION_TEST_REPORT.md
./track/docs/archive/testing/VERIFICATION_AGENT5_SUMMARY.md
./track/docs/archive/testing/VERIFICATION_AGENT6_SUMMARY.md
./track/interactive/CATEGORY_REFERENCE.md
./track/interactive/DEBUG_LOGGING_GUIDE.md
./track/interactive/components/ERROR_HANDLER_README.md
./track/services/PLUGIN_CONTRIBUTION_GUIDE.md
./track/services/plugin_docs/agent_reports/AGENT5_CLEANUP_REPORT.md
./track/services/plugin_docs/agent_reports/AGENT6_ANDROID_MOBILE_CLEANUP_REPORT.md
./track/services/plugin_docs/agent_reports/AGENT8_CLEANUP_REPORT.md
./track/services/plugin_docs/archive/ARCHIVE_MANIFEST.md
./track/services/plugin_docs/archive/EDGE_CASES_RESOLUTION.md
./track/services/plugin_docs/summaries/ANTI_FORENSICS_DELIVERY.md
./track/services/plugin_docs/summaries/ANTI_FORENSICS_PLUGIN_SUMMARY.md
./track/services/plugin_docs/summaries/BINARY_EXPLOIT_PLUGIN.md
./track/services/plugin_docs/summaries/C2_ANALYSIS_PLUGIN_SUMMARY.md
./track/services/plugin_docs/summaries/HEAP_EXPLOIT_README.md
./track/services/plugin_docs/summaries/LUA_EXPLOIT_PLUGIN_SUMMARY.md
./track/services/plugin_docs/summaries/NETWORK_ATTACK_PLUGINS_SUMMARY.md
./track/services/plugin_docs/summaries/OSINT_WIFI_PLUGIN_SUMMARY.md
./track/services/plugin_docs/summaries/PHISHING_PLUGIN_SUMMARY.md
./track/services/plugin_docs/summaries/PYTHON_WEB_PLUGIN_SUMMARY.md
[Plus 50+ mining reports - see main analysis]
```

### Complete List of kebab-case Files (45)

```
./.claude/agents/00-cve-researcher.md
./.claude/agents/01-recon-scout.md
./.claude/agents/02-content-architect.md
./.claude/agents/03-scenario-enricher.md
./.claude/agents/04-reference-integrator.md
./.claude/agents/05-document-beautifier.md
./.claude/agents/alternative-command-dev.md
./.claude/agents/command-expander.md
./.claude/agents/context-fetcher.md
./.claude/agents/date-checker.md
./.claude/agents/file-creator.md
./.claude/agents/git-workflow.md
./.claude/agents/pentest-toolsmith.md
./.claude/agents/project-manager.md
./.claude/agents/test-runner.md
./.claude/agents/tui-dev.md
./.claude/commands/analyze-product.md
./.claude/commands/create-spec.md
./.claude/commands/create-tasks.md
./.claude/commands/execute-tasks.md
./.claude/commands/plan-product.md
./reference/docs/config.md
./reference/docs/placeholders.md
./reference/docs/quick-reference.md
./reference/docs/quick-wins.md
./reference/docs/tags.md
./roadmap/service-relationship-mapper.md
```

### Complete List of snake_case Files (65)

[See main analysis for full list - includes implementation docs, plugin readmes, chapter docs, and snake_case mining reports]

---

## Conclusion

The crack project has 309 markdown files with 3 primary naming conventions in use. The inconsistency is most pronounced in mining reports (78 files affected) and agent definitions (4 files with non-descriptive names).

Key recommendations:
1. **High priority:** Rename 4 agent files to descriptive kebab-case
2. **High priority:** Move 2 technical reports from `/docs/` to `/docs/reports/`
3. **Medium priority:** Standardize 78 mining reports to snake_case and remove redundant suffixes
4. **Going forward:** Follow directory-specific conventions outlined in "Naming Standard Recommendations"

The most consistent directories (`/reference/docs/` and `/docs/audit-reports/`) should serve as models for their respective document types.

**Estimated effort:**
- High priority changes: 1-2 hours
- Medium priority changes: 4-6 hours
- Total impact: 84-88 files renamed/moved
- Testing required: Full test suite + reference grep

**End of Report**
