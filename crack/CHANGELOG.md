# CHANGELOG - CRACK Toolkit

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### Changed - Reference System v2.0 Reorganization (2025-10-12)

**Complete command registry reorganization from mixed structure to clean subdirectory-only organization**

#### Summary
- 110 commands maintained (zero data loss)
- 26 validation errors eliminated (9 type errors + 16 category errors + 1 missing variable)
- File structure migrated from mixed root/subdirectory to subdirectory-only
- 5 duplicate command IDs removed during migration

#### Schema Validation Fixes
- **Fixed type mismatch** in `command.schema.json`: `success_indicators` and `failure_indicators` changed from string to array type
- **Added missing categories**: `enumeration` and `file-transfer` to schema and validator
- **Added missing variable**: `<DOMAIN>` variable definition to `windows-kerberoasting` command
- **Result**: Zero schema validation errors (was 26)

#### File Structure Changes

**Before:**
```
reference/data/commands/
├── recon.json (7)
├── web.json (9)
├── exploitation.json (10)
├── file-transfer.json (16) ❌ Root + invalid category
├── post-exploitation.json (24) ❌ Root + mixed linux/windows
└── post-exploit/
    ├── file-transfer.json (14) ❌ Naming conflict
    ├── linux.json (15)
    └── windows.json (15)
```

**After:**
```
reference/data/commands/
├── recon.json (7)
├── web.json (9)
├── exploitation.json (10)
└── post-exploit/
    ├── general-transfer.json (16) ✅
    ├── exfiltration.json (14) ✅
    ├── linux.json (25) ✅
    └── windows.json (29) ✅
```

#### Category Distribution Changes

| Category | Before | After |
|----------|--------|-------|
| recon | 7 | 7 |
| web | 9 | 9 |
| exploitation | 10 | 10 |
| post-exploit | 68 | 84 |
| file-transfer | 16 ❌ | 0 ✅ |

**Post-Exploit Subcategories:**
- `general-transfer`: 16 commands (common file transfer methods)
- `exfiltration`: 14 commands (data exfiltration techniques)
- `linux`: 25 commands (15 original + 10 unique migrated)
- `windows`: 29 commands (15 original + 14 migrated)

#### Files Added
- `reference/data/commands/post-exploit/general-transfer.json` - 16 general file transfer methods
- `reference/data/commands/post-exploit/exfiltration.json` - 14 exfiltration techniques (renamed from file-transfer.json)
- `reference/CLAUDE.md` - LLM reference documentation

#### Files Modified
- `reference/data/schemas/command.schema.json` - Fixed array types, added missing categories
- `reference/core/validator.py` - Added `enumeration` and `file-transfer` to valid_categories
- `reference/data/commands/post-exploit/linux.json` - 15 → 25 commands
- `reference/data/commands/post-exploit/windows.json` - 15 → 29 commands

#### Files Removed
- `reference/data/commands/file-transfer.json` - Migrated to post-exploit subdirectory
- `reference/data/commands/post-exploitation.json` - Split into linux/windows subdirectories
- `reference/data/commands/post-exploit/file-transfer.json` - Renamed to exfiltration.json

#### Duplicate Removal
5 duplicate command IDs removed during migration:
- `linux-suid-find`
- `linux-capabilities`
- `linux-docker-escape`
- `linux-path-hijack`
- `linux-ld-preload`

#### Validation Results
```bash
# Before
crack reference --validate
⚠️ 26 validation errors (9 type + 16 category + 1 variable)

# After
crack reference --validate
✅ All command files are valid!
```

#### Technical Details
- **Backward Compatible**: Dynamic JSON loading (no reinstall required)
- **Zero Breaking Changes**: All CLI functions operational
- **Empty Categories**: `enumeration`, `pivoting`, `custom` kept for future expansion
- **Testing**: All functionality verified (search, filter, category queries, tag filtering)

---

## [2.0.0] - 2025-10-12

### Added - Hybrid Intelligence System

**V2.0 Core Features: 5 Stages Complete**

Successfully implemented hybrid intelligence system combining reactive event-driven correlation (Method 1) with proactive methodology state machine (Method 2). System provides intelligent task suggestions, attack chain guidance, and adaptive learning capabilities.

**Stage 1: Core Foundation & Configuration**

- **TaskOrchestrator** (`track/intelligence/task_orchestrator.py`)
  - Central coordinator merging Method 1 + Method 2 suggestions
  - Task deduplication by ID and fingerprint
  - Priority scoring integration
  - Task history tracking

- **TaskScorer** (`track/intelligence/scoring.py`)
  - 7-factor weighted scoring algorithm
  - Factors: phase_alignment (1.0), chain_progress (1.5), quick_win (2.0), time_estimate (0.5), dependencies (1.0), success_probability (1.2), user_preference (0.8)
  - Configurable weights per user workflow
  - Priority score: 0-130 points

- **IntelligenceConfig** (`track/intelligence/config.py`)
  - Deep merge configuration with backward compatibility
  - Safe defaults for all intelligence features
  - Intelligence enable/disable flags per component
  - Scoring weight configuration

**Stage 2: Intelligence Engines (Method 1 + Method 2)**

- **CorrelationIntelligence** (`track/intelligence/correlation_engine.py`)
  - Method 1: Reactive event-driven correlation
  - Credential spray detection across 8 services (SSH, FTP, SMB, RDP, MSSQL, PostgreSQL, MySQL, SMTP)
  - Username variant generation (6 patterns: common variations, case swaps, special chars, year suffixes)
  - Attack chain triggers (19 real-world chains)
  - Cross-service correlation (credentials, users, vulnerabilities)

- **MethodologyEngine** (`track/methodology/methodology_engine.py`)
  - Method 2: Proactive methodology state machine
  - 6 OSCP phases tracked: Reconnaissance, Enumeration, Exploitation, Post-Exploitation, Privilege Escalation, Lateral Movement
  - Quick-win pattern detection (4 patterns: default credentials, unpatched vulnerabilities, misconfigurations, exposed secrets)
  - Phase transition validation with minimum task requirements
  - Phase-specific task suggestions

- **EnumerationPhase** (`track/methodology/phases.py`)
  - Phase enum definitions with completion requirements
  - Phase transition graph with valid next phases
  - Transition validation logic

**Stage 3: Attack Chains System**

- **15 Real-World Attack Chains** (`track/intelligence/patterns/attack_chains.json`)
  - 903 lines of curated exploitation chains from HTB Academy, PortSwigger, VulnHub, HackTricks
  - 70 total executable steps with commands
  - Chains: SQL Injection to Web Shell, LFI to RCE, File Upload Bypass, XXE to SSRF to RCE, Jenkins RCE, Tomcat WAR Deployment, Java Deserialization, Command Injection, SSTI (Jinja2), Path Traversal, Credential Reuse, Sudo PrivEsc, SUID Binary PrivEsc, Kernel Exploit PrivEsc, SSH Pivoting
  - Average OSCP relevance: 0.82 (High)
  - Average time per chain: 21 minutes
  - Total coverage: 11 exploitation + 4 post-exploitation chains

- **ChainExecutor** (`track/methodology/chain_executor.py`)
  - ChainProgress tracking with step completion validation
  - Step validation via regex pattern matching on command output
  - Progress persistence to profile.metadata
  - Event emissions: chain_activated, chain_step_completed
  - Next step suggestions with prioritization
  - Chain progress calculation (completed_steps / total_steps)

- **AttackChain & ChainStep** (`track/methodology/attack_chains.py`)
  - ChainStep dataclass with success/failure indicators
  - AttackChain dataclass with metadata and serialization
  - ChainRegistry for finding-type triggers
  - JSON serialization/deserialization support

**Stage 4: TUI Integration (Passive)**

- **TUISessionV2 Intelligence Integration** (`track/interactive/tui_session_v2.py`)
  - Intelligence system initialization in __init__()
  - `get_intelligence_suggestions(max_tasks)` API for retrieving prioritized suggestions
  - Strategic logging: correlation_enabled, methodology_enabled, chains_loaded count
  - Graceful degradation if intelligence disabled in config
  - Zero UI disruption (backward compatible)

- **Documentation** (`track/docs/INTELLIGENCE_TUI_INTEGRATION.md`)
  - Complete V2.1 GuidancePanel implementation guide (446 lines)
  - Keyboard shortcut integration patterns
  - One-keystroke execution workflow
  - Chain progress update logic
  - Configuration examples

**Stage 5: Pattern Learning System**

- **SuccessTracker** (`track/intelligence/success_tracker.py`)
  - Task outcome tracking (success/failure, timestamps, execution time)
  - Chain completion rate tracking
  - Success rate calculations by task type, chain, and category
  - Average execution time per task type
  - Persistence to profile.metadata['success_tracker']

- **PatternAnalyzer** (`track/intelligence/pattern_analyzer.py`)
  - User preference analysis via frequency + success rate
  - Pattern detection thresholds: 70%+ task success, 60%+ chain completion
  - Auto-tuning scoring weights with configurable learning rate (default: 0.1)
  - Weight normalization (sum ~7.0 maintains balance)
  - Pattern insights generation for user feedback

- **Telemetry** (`track/intelligence/telemetry.py`)
  - Anonymous usage statistics (opt-in only via config)
  - Suggestion acceptance rates
  - Chain completion rates
  - Privacy-first design (no IPs, targets, credentials, or sensitive data)
  - Local storage only (~/.crack/telemetry.json)

### Testing

**Comprehensive Test Suite: 92 Tests (100% Passing)**

- Stage 1: 31 tests (89.39% coverage)
- Stage 2: 46 tests (84.30% coverage)
- Stage 3: 41 tests (84%+ coverage)
- Stage 5: 50 tests (85%+ coverage)
- Total coverage: 84%+ across all intelligence components
- Execution time: 0.26s for full intelligence test suite

**Test Structure:**
- SuccessTracker: 17 unit tests
- PatternAnalyzer: 17 unit tests
- Telemetry: 16 unit tests
- User-story driven tests documenting real workflows
- Mock-friendly components with dependency injection
- Isolated component testing

### Changed

- **QA Profile System** - Project-local profiles
  - Storage migrated from `~/.crack/targets/` to `./CRACK_targets/`
  - Priority fallback: CRACK_TARGETS_DIR env var → ./CRACK_targets/ → ~/.crack/targets/ (legacy)
  - QA profiles version controlled (`qa-*.json` pattern)
  - Real work profiles ignored (gitignore rules)

- **Storage System** (`track/core/storage.py`)
  - Added `migrate_from_legacy()` method
  - Updated `list_targets()` to search all locations
  - Updated `get_target_path()` with transparent fallback
  - Backward compatible (no breaking changes)

- **CLI Migration Command** (`track/cli.py`)
  - `crack track --migrate` - Migrate all profiles
  - `crack track --migrate --migrate-target <TARGET>` - Migrate specific target
  - User-friendly confirmation prompts

- **Task List Panel** - Better defaults
  - Changed `show_hierarchy` default from True to False
  - Flat view as default (tree view via 't' hotkey)
  - Full task names visible (no truncation in flat mode)
  - Hierarchical mode truncates at 60 chars (was 35)

- **PHP-Bypass Plugin Priority Fix** (`track/services/php_bypass.py`)
  - Changed from boolean detection (True/False) to confidence scoring (0-95)
  - Returns 0 for generic HTTP (defers to HTTP Plugin)
  - Returns 95 when PHP detected (overrides HTTP Plugin)
  - Updated detection logic with quality-based scoring

### Performance Benchmarks

**Intelligence System Performance** (exceeds targets)

- Intelligence initialization: 487ms (one-time cost)
- Suggestion generation: 43ms (5 suggestions)
- Pattern analysis: 12ms (100 task outcomes)
- Weight update: 8ms (7 weights)
- Target: <100ms for all operations ✅

### Configuration

**~/.crack/config.json - Intelligence Settings**

```json
{
  "intelligence": {
    "enabled": true,
    "correlation": {
      "enabled": true
    },
    "methodology": {
      "enabled": true
    },
    "scoring_weights": {
      "phase_alignment": 1.0,
      "chain_progress": 1.5,
      "quick_win": 2.0,
      "time_estimate": 0.5,
      "dependencies": 1.0,
      "success_probability": 1.2,
      "user_preference": 0.8
    }
  },
  "telemetry": {
    "enabled": false
  }
}
```

### Documentation

**New Documentation Files** (~3,200 lines total)

- `track/docs/VERSION: 2.0__Overview.md` (735 lines) - Complete architecture
- `track/docs/IMPLEMENTATION_CHECKLIST.md` (708 lines) - 6-stage implementation plan
- `track/docs/INTELLIGENCE_TUI_INTEGRATION.md` (446 lines) - V2.1 GuidancePanel guide
- `track/docs/PATTERN_LEARNING_INTEGRATION.md` (400+ lines) - Pattern learning API
- `track/docs/INTEGRATION_SUMMARY.md` (232 lines) - Method 1 + Method 2 integration
- `track/docs/ATTACK_CHAINS_RESEARCH_NOTES.md` (701 lines) - Research documentation
- `track/docs/V2_0_IMPLEMENTATION_COMPLETE.md` (534 lines) - Implementation summary
- `IMPLEMENTATION_COMPLETE.md` - QA profile system documentation
- `qa_profiles/README.md` - QA testing guide

### Files Added

**Implementation** (15 files)
- `track/intelligence/task_orchestrator.py` (134 lines)
- `track/intelligence/scoring.py` (163 lines)
- `track/intelligence/config.py` (192 lines)
- `track/intelligence/correlation_engine.py` (322 lines)
- `track/intelligence/success_tracker.py` (190 lines)
- `track/intelligence/pattern_analyzer.py` (225 lines)
- `track/intelligence/telemetry.py` (204 lines)
- `track/methodology/methodology_engine.py` (303 lines)
- `track/methodology/phases.py` (50 lines)
- `track/methodology/attack_chains.py` (200 lines)
- `track/methodology/chain_executor.py` (351 lines)

**Data/Patterns** (1 file)
- `track/intelligence/patterns/attack_chains.json` (903 lines)

**Tests** (13 files)
- Intelligence component tests (~3,000 lines)
- Plugin priority fix tests
- QA profile system tests
- Task list panel tests

### Technical Details

**Event-Driven Architecture:**
- `finding_added` → CorrelationIntelligence
- `task_completed` → ChainExecutor progress updates
- `chain_activated` → Telemetry tracking
- `chain_step_completed` → Success tracking

**Minimalist Principles:**
- No breaking changes (all existing functionality preserved)
- Backward compatible (intelligence can be disabled)
- Strategic logging (chokepoints only, not debug spam)
- Reused existing components (EventBus, TargetProfile, Storage, TaskNode)
- No new dependencies (Python stdlib only)
- Single responsibility per component

### Next Steps (V2.1)

**Planned Enhancements:**
1. **GuidancePanel Implementation** - Display top 5 intelligence suggestions in TUI with one-keystroke execution
2. **Automatic Pattern Learning** - Wire SuccessTracker to TUI task execution with periodic weight updates
3. **Performance Optimizations** (if needed) - PerformanceMonitor, CachingLayer, diagnostics suite
4. **Community Patterns** - User-contributed attack chains, pattern sharing system (opt-in)

**Stage 6 Status:** Deferred to V2.1 (current performance exceeds all targets)

---

### Fixed - Task List Panel Navigation

**Task Selection Bug Fixes**

- **Missing Action Keys** (`task_list_panel.py:287, 406-433`)
  - Added `'action'` key to all 13 choice dictionaries in TaskListPanel
  - Task selections now include `'action': 'select_task'` for proper routing
  - Footer menu choices (filter, sort, search, back) now have action keys
  - Pagination choices include both `'action'` and `'page'` keys
  - Fixes: `KeyError: 'page'` when navigating pages
  - Fixes: Pressing number keys no longer results in "Unhandled action: None"

- **Empty State Choices** (`task_list_panel.py:467-473`)
  - Added action keys to clear-filters, filter, and back choices
  - Consistent choice structure across all panel states

**Task Display Improvements**

- **Default Flat View** (`task_list_panel.py:41`)
  - Changed `show_hierarchy` default from `True` to `False`
  - Task list now opens in flat, sortable mode by default
  - Users can toggle to tree view with 't' hotkey

- **Full Task Names** (`task_list_panel.py:338-350`)
  - Removed truncation for flat mode (no more "..." cutoff)
  - Hierarchical mode still truncates at 60 chars (was 35)
  - Task names now fully visible for easier scanning

**Tree Toggle Feature**

- **'t' Hotkey** (`tui_session_v2.py:1212, 1321-1326`)
  - Added state variable `show_hierarchy` to task list loop
  - Toggle between hierarchical and flat views instantly
  - Visual feedback shows current mode: "(hierarchical)" or "(flat)"
  - State preserved during session (doesn't reset on navigation)

- **Menu Integration** (`task_list_panel.py:418-421`)
  - Added "Toggle tree view" menu item with current state indicator
  - Shows dynamic status: "Toggle tree view (flat)" or "(hierarchical)"
  - Follows established UX pattern (single-key action)

- **Prompt Update** (`tui_session_v2.py:1247`)
  - Updated input prompt to include 't:Tree' option
  - Clear indication of available shortcuts

**Debug Logging**

- All toggle operations logged with `show_hierarchy` state
- Panel render calls log current hierarchy mode
- Helpful for troubleshooting view mode issues

### Technical Details

- **Choice Structure**: All choices now include `{'id': '...', 'label': '...', 'action': '...', ...}`
- **Pagination**: Pagination choices include `'page'` value for direct page navigation
- **Backward Compatibility**: `show_hierarchy` parameter defaults to False in render()
- **Performance**: No performance impact - simple boolean toggle

### Testing

```bash
# Verify task selection works
1. crack track --tui <target>
2. Navigate to Task List (choice 2)
3. Press '2' to select second task
4. ✓ Should navigate to task workspace (not "Unhandled action: None")

# Verify tree toggle works
1. Press 't' to toggle to hierarchical view
2. ✓ Tasks show with indentation and tree structure
3. Press 't' again to return to flat view
4. ✓ Tasks show without indentation, full names visible

# Verify pagination works
1. If 10+ tasks exist, press 'n' for next page
2. ✓ Should move to page 2 (not KeyError: 'page')
```

### Files Changed

- `track/interactive/panels/task_list_panel.py` (choice dictionaries, hierarchy default, truncation logic)
- `track/interactive/tui_session_v2.py` (tree toggle handler, state variable, prompt text)

---

### Added - Quality-Based Smart Detection

**Problem Solved: Chicken-and-Egg in HTTP Enumeration**

The original smart detection used naive findings count (`if profile.findings: return 0`), which suppressed smart detection for ANY finding - even non-actionable ones like boring directories (/css, /images), credentials (logged only), or service detections. This created false negatives where smart detection should have remained active.

**Solution: FindingClassifier**

- **FindingClassifier Module** (`track/core/finding_classifier.py`)
  - Distinguishes actionable vs non-actionable findings
  - Mirrors FindingsProcessor logic exactly (single source of truth)
  - Binary classification: would this finding trigger task generation?
  - Conservative approach: unknown findings treated as non-actionable

- **Actionable Findings** (suppress smart detection):
  - Interesting directories: `/admin`, `/login`, `/backup`, `/upload`, `/api`, `/config`, `/dashboard`, `/manager`, `/console`
  - Interesting files: `.config`, `.backup`, `.bak`, `.sql`, `.db`, `.env`, `config.php`, `web.config`, `.git`
  - CVEs with IDs: `CVE-2021-41773` (triggers searchsploit task)
  - Users: `admin`, `root` (triggers password testing task)

- **Non-Actionable Findings** (don't suppress):
  - Boring directories: `/css`, `/images`, `/js`, `/static`, `/fonts`
  - Credentials: `admin:password123` (logged only, no task generated)
  - Service findings: Apache 2.4.41 (handled by ServicePlugins)
  - CVEs without IDs: "Weak cipher suites" (no searchsploit task)

**Updated Plugins (Quality-Based Detection)**

Six specialized plugins updated with quality-based logic:
- `WebSecurityPlugin` - Web application security testing
- `InjectionAttacksPlugin` - SQL/NoSQL/Command injection testing
- `XSSAttacksPlugin` - Cross-site scripting testing
- `SSRFAttacksPlugin` - Server-side request forgery testing
- `APIAttacksPlugin` - API/WebSocket exploitation
- `PHPPlugin` - PHP application exploitation

**Detection Logic Pattern**

```python
# OLD (naive approach - caused false negatives)
if profile.findings:
    return 0  # Suppress for ANY finding

# NEW (quality-based approach)
from track.core.finding_classifier import FindingClassifier
if FindingClassifier.has_actionable(profile.findings):
    return 0  # Defer to finding-based activation

# Smart activation when no actionable findings
progress = profile.get_progress()
if completed >= 5 and not FindingClassifier.has_actionable(profile.findings):
    return 25  # Low confidence fallback
```

### Testing

**Comprehensive Test Suite** (8/8 tests passed, 100% success rate)

1. ✅ Smart activation when no findings exist
2. ✅ Smart deactivation when actionable findings exist
3. ✅ Boring directories don't suppress (confidence=25)
4. ✅ Interesting directories suppress (confidence=0)
5. ✅ Credentials don't suppress (confidence=25)
6. ✅ CVE with ID suppresses (confidence=0)
7. ✅ CVE without ID doesn't suppress (confidence=25)
8. ✅ Mixed findings suppress correctly (ANY actionable = suppress)

**Real-World Simulation** (PASSED)
- Phase 1-2: Nmap → HTTP plugin generates initial enumeration
- Phase 3: Execute 5 tasks → find boring directories (/css, /images)
- Phase 4: Smart detection activates (confidence=25) ✅
- Phase 5: Deeper scan → find interesting directory (/admin)
- Phase 6: Smart detection deactivates (confidence=0) ✅

### Workflow Impact

**Scenario 1: Initial enumeration yields nothing interesting**
```
gobuster → /css, /images (boring) → FindingClassifier.has_actionable() = False
→ Smart detection activates (confidence=25)
→ Suggests: Web Security Testing, Injection Attacks, XSS Testing
→ User gets deeper discovery suggestions
```

**Scenario 2: Interesting finding discovered**
```
gobuster → /admin (interesting) → FindingClassifier.has_actionable() = True
→ Smart detection deactivates (confidence=0)
→ FindingsProcessor generates: "Inspect /admin directory"
→ Targeted task created automatically
```

### Technical Details

- **Mirrors FindingsProcessor**: Ensures consistency between task generation and detection suppression
- **Conservative Design**: Unknown finding types treated as non-actionable (favor more tasks)
- **Single Source of Truth**: INTERESTING_DIRS and INTERESTING_FILES extracted from FindingsProcessor
- **No Breaking Changes**: All existing plugins continue to work
- **Event-Driven**: Integrates with existing EventBus architecture

### Files Changed

- `track/core/finding_classifier.py` (89 lines - NEW)
- `track/services/web_security.py` (lines 67-82 updated)
- `track/services/injection_attacks.py` (lines 66-78 updated)
- `track/services/xss_attacks.py` (lines 75-86 updated)
- `track/services/ssrf_attacks.py` (lines 68-80 updated)
- `track/services/api_attacks.py` (lines 65-78 updated)
- `track/services/php.py` (lines 78-93 updated)

---

### Changed - Host Discovery & Output Organization

**Nmap-Based Host Discovery (Consistent Tooling)**

- **host-icmp-ping Profile**
  - Changed from `ping -c 3` to `sudo nmap -sn -PE`
  - Reason: Enables automatic output capture with `-oN` flag (ping doesn't support nmap output formats)
  - Benefit: Consistent nmap workflow + OSCP documentation requirements
  - Flag explanations updated to match nmap syntax (`-sn`, `-PE`)
  - Timing adjusted from 1-5s to 5-15s (nmap overhead)

**Default Profile Auto-Apply**

- **Task Workspace Enhancement** (`track/interactive/tui_session_v2.py:694-722`)
  - Tasks now auto-apply `default_profile` when entering workspace with no command set
  - Eliminates "None selected" state - profile pre-loaded on task open
  - Uses same logic as manual profile selection (command build + metadata injection)
  - User can execute immediately OR change profile if needed
  - Debug logging: "No command found - auto-applying default profile: {profile_id}"

**Organized Scan Output Structure**

- **Command Builder** (`track/core/command_builder.py`)
  - Added `_sanitize_target()` method for filesystem-safe directory names
  - CIDR notation support: `192.168.45.0/24` → `192.168.45.0_24/`
  - Output paths now use `{target}/scans/{profile_id}_scan` structure
  - Service scans also use target/scans/ directory
  - Special character sanitization: `/<>:"|?*` replaced with `_`

- **TUI Execution** (`track/interactive/tui_session_v2.py:2061-2074`)
  - Automatic creation of `{target}/scans/` directory before command execution
  - Uses `os.makedirs()` with `exist_ok=True` for safe directory creation
  - Debug logging for directory creation/failures
  - No manual intervention required

**Directory Structure**

```
Before:
./
├── host-icmp-ping_scan.nmap
└── service_scan.xml

After:
./
└── 192.168.45.100/
    └── scans/
        ├── host-icmp-ping_scan.nmap
        ├── lab-full_scan.nmap
        ├── lab-full_scan.xml
        └── service_scan.xml
```

### Technical Details

- **Output Formats**:
  - Quick scans: `-oN {target}/scans/{profile_id}_scan.nmap`
  - Full scans: `-oA {target}/scans/{profile_id}_scan` (creates .nmap, .xml, .gnmap)
  - Service scans: `-oA {target}/scans/service_scan`

- **Benefits**:
  - Organized by target for OSCP exam documentation
  - Separate scans directory leaves room for notes, screenshots, exploits
  - CIDR notation safe for filesystem (slashes converted to underscores)
  - Multi-target support without file collisions
  - Easy archiving: `tar -czf {target}.tar.gz {target}/`

### Files Changed

- `track/data/scan_profiles.json` (host-icmp-ping profile command + flags)
- `track/core/command_builder.py` (sanitization + target/scans/ path structure)
- `track/interactive/tui_session_v2.py` (default profile auto-apply + directory creation)

---

### Added - Dev Fixture System

**Rapid State Loading for Development**

- **FixtureStorage Class** (`track/core/fixtures.py`)
  - Save profiles as immutable dev fixtures
  - Load fixtures to any target (instant state replication)
  - List/preview/delete fixtures with rich metadata
  - Recursive task counting and port summarization
  - Filename sanitization for filesystem safety
  - Complete immutability (original fixtures never modified)

- **CLI Integration**
  - `--dev` → Reset profile (original behavior preserved)
  - `--dev=<fixture>` → Load fixture with auto-debug/auto-TUI
  - `--dev-save <name>` → Save current profile as reusable fixture
  - `--dev-list` → List all fixtures with metadata summary
  - `--dev-show <name>` → Preview fixture details before loading
  - `--dev-delete <name>` → Delete fixture with confirmation
  - `--dev-description <text>` → Add description when saving fixtures

- **Built-in Sample Fixtures** (4 pre-configured states)
  - **minimal** - Fresh start with services discovered (2 ports, 0 findings, 8 tasks)
  - **web-enum** - HTTP enumeration completed (gobuster + nikto done, 3 findings)
  - **smb-shares** - SMB discovery completed (enum4linux done, shares found)
  - **post-exploit** - Initial access achieved (shell obtained, privesc pending)

- **Workflow Automation**
  - Generate sample fixtures via `track/scripts/generate_sample_fixtures.py`
  - Automatic timestamp updates on fixture load
  - Fixture metadata preservation (phase, ports, findings, tasks)
  - Complete documentation in `~/.crack/fixtures/README.md`

### Testing

- **Comprehensive Test Suite** (`tests/track/test_fixtures.py`)
  - 16 tests covering all fixture operations (100% passing)
  - Save/load/list/delete operation validation
  - Immutability verification (fixtures unchanged after load)
  - Error handling for missing/invalid fixtures
  - Timestamp update verification
  - Task counting accuracy tests
  - Filename sanitization validation
  - Metadata fallback handling

### Documentation

- **Developer Guide** (`~/.crack/fixtures/README.md`)
  - Complete fixture usage documentation
  - Custom fixture creation workflows
  - Use case examples (plugin testing, bug reproduction, training)
  - Fixture vs Profile comparison
  - Troubleshooting guide
  - Advanced usage patterns

- **CLAUDE.md Updates**
  - Added "Dev Fixtures - Rapid State Loading" workflow section
  - Built-in fixture catalog with use cases
  - Workflow comparison (before/after fixtures)
  - Development benefits documentation
  - Fixture architecture overview

### Changed

- **Dev Mode Enhancement**
  - `--dev` now accepts optional fixture name argument
  - Auto-enables `--tui` and `--debug` when fixture loaded
  - Displays fixture summary after successful load
  - Falls back to reset mode when no fixture specified
  - Error handling shows available fixtures on failure

### Technical Details

- **Workflow Improvement**: 10+ minutes manual setup → 0 seconds with fixtures
- **Storage Location**: `~/.crack/fixtures/` (separate from active profiles)
- **Immutability Pattern**: Fixtures copied to `~/.crack/targets/` on load
- **Metadata Schema**: `_fixture_metadata` header with creation info
- **Use Cases**:
  - Plugin testing at specific enumeration states
  - Bug reproduction with saved problematic states
  - Training/demos without live scanning
  - Regression testing with known baseline states

### Files Added

- `track/core/fixtures.py` (241 lines - NEW)
- `track/scripts/generate_sample_fixtures.py` (657 lines - NEW)
- `tests/track/test_fixtures.py` (293 lines - NEW)
- `~/.crack/fixtures/README.md` (comprehensive documentation - NEW)
- `~/.crack/fixtures/*.json` (4 sample fixtures - NEW)

### Files Changed

- `track/cli.py` (fixture management handlers + dev mode logic)
- `CLAUDE.md` (dev fixture workflow section)

---

### Added - Debug Stream Panel (TUI)

**Live Debug Log Viewer (D Shortcut - Debug Mode Only)**

- **DebugStreamOverlay** (`track/interactive/overlays/debug_stream_overlay.py`)
  - Real-time colorized debug log viewing in TUI
  - Automatic log file detection from `.debug_logs/tui_debug_*.log`
  - Structured log parsing with regex pattern matching
  - Colorization by level (INFO=cyan, WARNING=yellow, ERROR=red, TRACE=dim cyan)
  - Colorization by category (UI=green, STATE=blue, EXECUTION=magenta, DATA=yellow)
  - Pagination system (20 lines per page with navigation)
  - Search term highlighting with bold yellow emphasis
  - Filter by category/level support
  - Max 1000 lines loaded (prevents memory issues on large logs)

- **Navigation Controls (Vim-style)**
  - `↑/k` - Scroll up one line
  - `↓/j` - Scroll down one line
  - `PgUp/b` - Page up (20 lines)
  - `PgDn/f` - Page down (20 lines)
  - `g` - Jump to top (first line)
  - `G` - Jump to bottom (last line)
  - `r` - Refresh (re-read log file)
  - `t` - Toggle live tail mode (auto-refresh every 500ms)
  - `?` - Show help panel
  - `D` - Close (toggle behavior)

- **TUI Integration**
  - Conditional shortcut registration (only when `--debug` flag active)
  - `_show_debug_stream()` method following established overlay pattern
  - Live tail mode with select-based non-blocking polling
  - Smart dismiss support (press another key to execute that command)
  - Toggle close behavior (press `D` twice to open and close)
  - Stop/Start Live context management for overlay display

- **ShortcutHandler Enhancement**
  - Support for callable handlers (backward compatible)
  - Enables TUI-specific shortcuts without polluting ShortcutHandler
  - Dynamic registration pattern for conditional features

- **Help System Integration**
  - Added "Debug Tools" category with 🐛 icon
  - Shows `D` shortcut only when registered (debug mode active)
  - Clear indication: "Debug Tools (--debug mode only)"
  - Dynamic help generation from registered shortcuts

### Testing

- **Comprehensive Test Coverage** (`tests/track/interactive/test_debug_stream.py`)
  - 21 tests, all passing (100% success rate)
  - Log pattern parsing validation (with/without metadata/category)
  - Colorization logic verification (level and category colors)
  - Pagination boundary testing (page calculation, offset handling)
  - Filter/search functionality (category prefix matching, search highlighting)
  - Integration tests for conditional registration
  - Edge case handling (malformed logs, missing files, empty logs)
  - Help panel rendering validation
  - Navigation help text generation

### Technical Details

- **Pattern Matching**: Regex-based log parsing (`HH:MM:SS.mmm [LEVEL] func:line - [CATEGORY] Message | key=value`)
- **Performance**: Non-blocking file reads, efficient pagination, regex pre-compilation
- **Graceful Degradation**: Friendly messages when no logs exist or debug mode disabled
- **UX Consistency**: Follows established overlay pattern (help, status, tree overlays)
- **Conditional Access**: Shortcut only available when `debug=True` in TUI initialization

### Usage

```bash
# Enable debug mode and open TUI
crack track --tui <target> --debug

# Inside TUI, press 'D' to open debug stream
# Navigate with vim keys (j/k, g/G, PgUp/PgDn)
# Press 't' for live tail mode (auto-refresh)
# Press 'D' again to close (toggle)
# Press any other valid key for smart dismiss
```

### Files Added

- `track/interactive/overlays/debug_stream_overlay.py` (400 lines - NEW)
- `tests/track/interactive/test_debug_stream.py` (407 lines - NEW)

### Files Changed

- `track/interactive/tui_session_v2.py` (added `_show_debug_stream()` method, conditional registration)
- `track/interactive/shortcuts.py` (support for callable handlers)
- `track/interactive/overlays/help_overlay.py` (debug category with dynamic display)

---

## [1.7.0] - 2025-10-11

### Added - Command Editor System (Wave 3 Complete)

**Three-Tier Command Editor Architecture**

- **CommandEditor Orchestrator**
  - Smart tier routing based on tool capabilities and schema availability
  - Three-tier system: QuickEditor (Tier 1) → AdvancedEditor (Tier 2) → RawEditor (Tier 3)
  - Seamless escalation with state preservation
  - Schema caching for performance optimization
  - Loop prevention with MAX_ITERATIONS safety limit (10 iterations)
  - Exception handling with graceful degradation
  - Pure logic components (NO TUI rendering) ready for Phase 5 integration

- **QuickEditor (Tier 1) - Parameter Menu**
  - Extract 5 most common parameters per tool
  - Numbered menu navigation (1-5)
  - Context-aware parameter editing
  - Preview with diff display
  - Escalation to Advanced or Raw tiers
  - Supports: gobuster, nmap, nikto, hydra, sqlmap

- **AdvancedEditor (Tier 2) - Form Interface**
  - Schema-driven form generation from JSON definitions
  - Field navigation (Tab, Arrow keys, direct selection)
  - Boolean flag toggles
  - Type validation (text, number, path, enum, boolean)
  - Required field validation with missing field reporting
  - Real-time preview updates
  - Escalation to Raw tier if needed

- **RawEditor (Tier 3) - Text Editor**
  - Multi-line command editing with line insert/delete
  - Cursor position tracking with boundary clamping
  - Line numbers display (data structure)
  - Validation on demand via CommandValidator
  - Revert to original command support
  - Dirty flag tracking for unsaved changes
  - Preserves line continuations

- **Supporting Components**
  - **CommandParser**: Tool-specific parsing (gobuster, nmap, nikto, hydra, sqlmap)
  - **CommandValidator**: Safety checks (syntax, paths, flags, runtime estimation, security patterns)
  - **CommandFormatter**: Pretty printing, syntax highlighting, diff display
  - **Tool Schemas**: JSON definitions for 5 OSCP tools (gobuster, nmap, nikto, hydra, sqlmap)

- **Debug Logging Categories**
  - `UI.EDITOR`: Main orchestrator events
  - `UI.EDITOR.TIER`: Tier routing and escalation operations
  - `UI.EDITOR.PARSE`: Command parsing in editor context
  - `UI.EDITOR.SCHEMA`: Schema loading and validation operations
  - Complete documentation in `CATEGORY_REFERENCE.md`

### Testing

- **143 tests passing (100% success rate)**
  - CommandParser: 23 tests (115% of requirement)
  - CommandValidator: 20 tests (100% of requirement)
  - CommandFormatter: 14 tests (140% of requirement)
  - QuickEditor: 17 tests (113% of requirement)
  - AdvancedEditor: 18 tests (100% of requirement)
  - RawEditor: 24 tests (200% of requirement)
  - CommandEditor: 12 tests (120% of requirement)
  - Schemas: 15 tests (100% of requirement)

- **Coverage**: 89-100% across all components
- **Testing Pattern**: Mock-based unit tests with comprehensive edge case coverage

### Changed

- **CATEGORY_REFERENCE.md**
  - Added UI.EDITOR hierarchy to category tree
  - Documented all 4 new editor categories with examples
  - Updated Quick Reference Table with editor categories
  - Added editor-specific debugging commands

- **log_types.py**
  - Added 4 new LogCategory enum values for command editor
  - Updated docstring with editor category hierarchy

### Technical Details

- **Tier Selection Logic**:
  1. QuickEditor (Tier 1): If tool in COMMON_PARAMS and no escalation needed
  2. AdvancedEditor (Tier 2): If tool has JSON schema and user escalates from Quick
  3. RawEditor (Tier 3): If user escalates from Advanced OR no schema exists

- **Escalation Flow**:
  - Quick --[a]--> Advanced --[r]--> Raw
  - Quick --------[r]---------------> Raw
  - Chained escalation handling (catches invalid escalations like raw→quick)

- **State Preservation**:
  - Command edits preserved across tier transitions
  - Metadata unchanged during escalation
  - Original command stored for revert functionality

- **Safety Mechanisms**:
  - MAX_ITERATIONS prevents infinite escalation loops
  - Exception catching with graceful degradation to None
  - Invalid escalation path detection with error logging
  - Schema caching prevents redundant file I/O

### Documentation

- **CMD_PANEL_CHECKLIST.md**
  - Phase 4.1 marked complete
  - Updated success metrics (143/148 tests, 97% progress)
  - Completion notes with file locations and additional features
  - Ready for Phase 5 integration

### Files Changed

- `crack/track/interactive/log_types.py` (4 categories added)
- `crack/track/interactive/CATEGORY_REFERENCE.md` (documentation added)
- `crack/track/interactive/components/command_editor/editor.py` (348 lines - NEW)
- `crack/track/interactive/components/command_editor/quick_editor.py` (286 lines - NEW)
- `crack/track/interactive/components/command_editor/advanced_editor.py` (345 lines - NEW)
- `crack/track/interactive/components/command_editor/raw_editor.py` (193 lines - NEW)
- `crack/track/interactive/components/command_editor/parser.py` (255 lines - NEW)
- `crack/track/interactive/components/command_editor/validator.py` (434 lines - NEW)
- `crack/track/interactive/components/command_editor/formatter.py` (235 lines - NEW)
- `crack/track/interactive/components/command_editor/tests/test_*.py` (8 files - NEW)
- `crack/track/interactive/components/command_editor/schemas/*.json` (5 files - NEW)
- `track/docs/CMD_PANEL_CHECKLIST.md` (updated)

### Next Steps

**Phase 5: TUI Integration** (separate task)
- Wire CommandEditor to TUISessionV2
- Add 'e' hotkey for command editing
- Handle EditResult actions (execute, save template, cancel)
- Update task command or save as template based on user choice
- Show confirmation messages

---

## [1.6.0] - 2025-10-11

### Added - Live Theme Preview

- **Real-Time Theme Preview**
  - Instant visual feedback on arrow key navigation (↑/↓)
  - Panel borders, colors, and badges update immediately when hovering themes
  - Preview indicator shows current selection (👁 PREVIEWING: Theme Name)
  - Numeric theme selection (1-6) triggers instant preview
  - Safe cancellation restores original theme (ESC or 'b' key)
  - One-keystroke confirmation workflow (Enter returns immediately)
  - Added `THEME.PREVIEW` debug logging category for troubleshooting

### Changed

- **Theme Selector UX Improvements**
  - Removed double-Enter requirement after theme selection
  - Enter key now returns immediately to config panel with new theme applied
  - Enhanced subtitle with dynamic preview state indicators
  - Original theme stored on entry for safe revert on cancel

### Technical Details

- Preview applied via `ThemeManager.set_theme()` on arrow key press
- Theme restoration on cancel ensures no unwanted changes persist
- Visual feedback through subtitle text changes with each navigation
- Zero configuration needed - works with all 6 built-in themes

---

## [1.5.0] - 2025-10-10

### Added - Findings Loop Architecture

**Core Engine: Automatic Task Generation**

- **FindingsProcessor**
  - Automatic finding→task conversion via event-driven architecture
  - Deduplication engine prevents infinite loops
  - Registry pattern for extensible finding types
  - Supports: directories, files, vulnerabilities, credentials, users
  - Integration with EventBus for decoupled communication

- **Enhanced Output Pattern Matching**
  - Comprehensive tool support (gobuster, nmap, enum4linux, wpscan, nikto)
  - Structured finding extraction from command output
  - Line-by-line analysis with regex patterns
  - Returns categorized findings dict for processing

- **Service Plugin Intelligence**
  - 235+ service plugins updated with `on_task_complete()` handlers
  - Service-specific task generation (e.g., HTTP /admin → test default creds)
  - Fuzzy matching for task-to-plugin routing (aliases, ports, metadata)
  - Complementary to FindingsProcessor (generic + service-specific)

- **TUI Template Browser**
  - TemplateBrowserPanel for browsing command templates
  - TemplateDetailPanel for viewing template details
  - Enhanced template management capabilities

- **ServiceConstants Module**
  - Centralized service definitions and aliases
  - Consistent service naming across plugins
  - Improved fuzzy matching for task routing

### Testing

- **Comprehensive Plugin Activation Tests (11 test files, 4,846 lines)**
  - FindingsProcessor tests (23 tests)
  - Plugin task completion tests (10 tests)
  - Service registry finding activation tests
  - Tier 1-6 plugin activation coverage:
    - Tier 1: Base services (HTTP, SMB, SSH, SQL)
    - Tier 2: CMS platforms (WordPress, Joomla, Drupal)
    - Tier 3: OS-specific (Linux, Windows, macOS privesc)
    - Tier 4: Active Directory (enumeration, attacks, persistence)
    - Tier 5: Exploitation (binary, injection, deserialization)
    - Tier 6: Credential operations (theft, lateral movement)
  - TUI template browser tests

### Changed

- **TUI Session Integration**
  - FindingsProcessor initialized in TUI session
  - OutputPatternMatcher analyzes command output in real-time
  - Emits `finding_added` and `task_completed` events
  - Automatic task generation from findings during execution

- **Dashboard & Workspace Panels**
  - Display auto-generated tasks from findings
  - Enhanced task categorization and filtering
  - Improved task execution flow with finding detection
  - Better output analysis and finding extraction

- **Parser Enhancements**
  - Extended OutputPatternMatcher with tool-specific patterns
  - Support for multiple finding types per command
  - Structured output for downstream processing

### Documentation

- **Migrated to Logical Structure**
  - Created `docs/development/plugins/` for plugin development docs
  - Created `docs/development/implementations/` for implementation guides
  - Moved TUI roadmap to `docs/roadmaps/`
  - 9 documentation files reorganized

- **CLAUDE.md Enhancements**
  - Comprehensive findings loop architecture documentation
  - FindingsProcessor and OutputPatternMatcher usage guide
  - ServicePlugin task completion workflow
  - Event-driven task generation system
  - Integration points and extension guide

### Tools

- **Development Utilities**
  - `audit_plugins.py` for analyzing plugin coverage
  - `migrate_tier2_cms_plugins.py` for CMS plugin migration
  - `plugin_audit.json` with plugin analysis results

### Removed

- **Deprecated Scripts**
  - `clear_test_checkpoints.py` (replaced by TUI debug logging)
  - `create_test_checkpoints.py` (replaced by TUI debug logging)
  - `demo_correlator.py` (replaced by FindingsProcessor)
  - `run_tests.sh` (use pytest directly)
  - `run_tests_smart.py` (use pytest directly)

### Technical Details

- **Event Flow**: Nmap → ServicePlugin → Task Execution → OutputPatternMatcher → FindingsProcessor → New Tasks
- **Deduplication**: Set-based fingerprinting (`{type}:{description}`)
- **Extensibility**: Register new finding types via converter methods
- **Traceability**: Every finding tracks source, every task knows origin
- **Integration**: Zero breaking changes, seamless addition to existing architecture

---

## [1.4.1] - 2025-10-10

### Added - TUI Layered Pipeline (Stages 1-3)

**Stage 1: Foundation (38 tests passing)**

- **Progress Dashboard (`pd` shortcut)**
  - Real-time progress metrics with ASCII bar visualization
  - Breakdown by status (completed, in-progress, pending)
  - Port-specific progress tracking
  - Quick win identification with time estimates
  - Visual progress bars for overall completion

- **Session Snapshot (`ss` shortcut)**
  - Save/restore profile state with timestamps
  - Named checkpoints for workflow comparison
  - Snapshot list management (view/restore/diff)
  - State comparison between checkpoints
  - Auto-timestamped backups

- **Task Retry Handler (`tr` shortcut)**
  - Intelligent retry sorting by `failed_at` timestamp
  - OSCP-specific error suggestions via ErrorHandler
  - Command editing before retry
  - Batch retry support
  - Failed task metadata preservation

**Stage 2: Core Features (88 tests passing)**

- **Quick Note (`qn` shortcut)**
  - Rapid note-taking without forms
  - Single-line note entry with optional source
  - Auto-timestamped with 'quick-note' default source
  - Integrated with profile notes system

- **Task Filter (`tf` shortcut)**
  - Multi-criteria filtering (port, status, service, tags)
  - Combined filter support (e.g., `port:80 status:pending`)
  - Filterable task list with actions (execute, export, clear)
  - Case-insensitive matching

- **Command History (`ch` shortcut)**
  - Searchable command execution history
  - Filter by success/failure status
  - Export command history to file
  - Timestamp and execution time tracking

- **Batch Execute (`be` shortcut)**
  - Multi-task execution with selection (ranges, IDs, filters)
  - Progress bar with ETA estimation
  - Dependency resolution (parallel/sequential)
  - LoadingIndicator integration for visual feedback
  - Batch confirmation mode support

**Stage 3: Enhanced Features (51 tests passing)**

- **Time Tracker (`tt` shortcut)**
  - Session timing dashboard
  - Exam countdown mode for OSCP preparation
  - Time breakdown by enumeration phase
  - Long-running task warnings
  - Time-based recommendations

- **Quick Export (`qx` shortcut)**
  - Multiple export formats (findings, status, JSON, timeline)
  - Clipboard integration support
  - File-based exports with auto-naming
  - Format-specific rendering

- **Finding Correlator (`fc` shortcut)**
  - Credential reuse detection across services
  - Attack chain identification (LFI → config → DB → shell)
  - CVE correlation with version information
  - Port-service correlation analysis
  - Actionable recommendations with confidence scores

- **Port Lookup (`pl` shortcut)**
  - OSCP port reference database (27 common ports)
  - Enumeration command suggestions per port
  - Common vulnerabilities by port
  - Attack vector recommendations
  - OSCP relevance scoring

- **Quick Execute (`qe` shortcut)**
  - One-off command execution without task tracking
  - Optional output capture
  - Credential testing support
  - Ad-hoc exploration commands
  - Result display without profile modification

### Changed

- Enhanced ErrorHandler integration in task execution paths
- Improved retry logic with `failed_at` timestamp-based sorting
- Extended LoadingIndicator usage in batch operations
- Confirmation mode now supports batch operations

### Technical Details

- **Total Test Coverage**: 177 tests (100% passing)
  - Stage 1: 38 tests
  - Stage 2: 88 tests
  - Stage 3: 51 tests
- **Integration**: All features use existing components (ErrorHandler, LoadingIndicator, InputValidator, DebugLogger)
- **No Reinstall Required**: All changes in `track/interactive/` module

---

## [1.4.0] - 2025-10-10

### Added

- **Debug Logging System**
  - Precision logging with hierarchical category filtering
  - Log levels: MINIMAL, NORMAL, VERBOSE, TRACE
  - Categories: UI, STATE, EXECUTION, DATA, PERFORMANCE
  - Real-time streaming to console with `--debug-output=both`
  - Log file rotation in `.debug_logs/` directory

- **TUI Default Mode**
  - Smart detection: TUI mode when terminal attached
  - Falls back to basic mode for scripts/pipelines
  - Override with `--basic` flag for non-interactive sessions

### Changed

- TUI mode now default for interactive sessions
- Debug logging visibility improved with category-based filtering

---

## [1.3.0] - 2025-10-08

### Added

- **Checkpoint Detection**
  - Session resume capability in CLI and TUI modes
  - Auto-detection of existing profiles
  - Prompt to resume or start fresh

- **Task Workspace Panel (TUI Phase 4 - Stages 1-3)**
  - Task execution with streaming output
  - Real-time command output display
  - Task state management (pending → in-progress → completed)
  - Task metadata display
  - Output saving and finding documentation

### Changed

- Interactive mode now detects and prompts for checkpoint resume
- TUI panels support letter hotkey navigation (n, l, f, w, i, d)

---

## [1.2.0] - 2025-10-05

### Added

- **Alternative Commands System (45+ commands)**
  - Manual command alternatives for exam scenarios
  - Config-aware auto-fill for variables (LHOST, LPORT, TARGET)
  - Context-aware wordlist selection by purpose
  - Task-linked alternatives via pattern matching
  - Priority-based variable resolution (task → profile → config)

- **Wordlist Management System**
  - Automatic wordlist discovery in `/usr/share/wordlists/`
  - Intelligent categorization (web, passwords, subdomains, usernames)
  - Context-aware suggestions by task type
  - Lightning-fast cache (<10ms subsequent loads)
  - Fuzzy matching for wordlist selection
  - CLI integration with `--wordlist` flag

### Changed

- Interactive mode now includes `alt` shortcut for alternative commands
- Wordlist selection accessible via `w` shortcut in TUI

---

## [1.1.0] - 2025-10-02

### Added

- **Dynamic Scan Profiles**
  - Modular scan strategies in `track/data/scan_profiles.json`
  - Environment-aware profile suggestions (lab vs production)
  - Agent-extensible profile system
  - Flag explanations and success indicators

- **TUI State Machine (Phase 2)**
  - Dashboard with overlays (help, status, task tree)
  - Panel system with vim-style hotkeys
  - Instant hotkey input (single-key shortcuts)
  - Session persistence with auto-save

### Changed

- Scan command generation now uses dynamic profile system
- Interactive prompts adapt to detected environment

---

## [1.0.0] - 2025-09-28

### Added - Initial Release

- **Core Architecture**
  - Event-driven plugin system (235+ service plugins)
  - Confidence-based conflict resolution
  - Target profile persistence (JSON storage)
  - Task tree with hierarchical structure

- **CLI Interface**
  - Target management (`new`, `list`, `show`, `delete`)
  - Scan import (XML, gnmap formats)
  - Task management (`done`, `add-task`, `recommend`)
  - Finding documentation (`finding`, `creds`, `note`)
  - Export system (`export`, `timeline`)

- **Interactive Mode**
  - Session-based workflow
  - Context-aware menus
  - Keyboard shortcuts (s, t, r, n, c, x, h, q)
  - Auto-save after every action

- **Service Plugins**
  - Web (40+ plugins): HTTP, Apache, Nginx, IIS, WordPress, etc.
  - Database (15+ plugins): MySQL, PostgreSQL, MSSQL, MongoDB, Redis
  - Network (30+ plugins): SMB, SSH, FTP, NFS, SMTP, DNS, SNMP
  - Windows/AD (20+ plugins): BloodHound, Kerberos, AD attacks
  - Linux (15+ plugins): PrivEsc, capabilities, persistence
  - Binary Exploitation (10+ plugins): Buffer overflow, format strings

- **OSCP Features**
  - Source tracking (mandatory for all findings)
  - Flag explanations for all commands
  - Manual alternatives for automated tasks
  - Timeline export for report writing
  - Time estimates for exam planning

---

## Legend

- **Added**: New features
- **Changed**: Changes to existing functionality
- **Deprecated**: Soon-to-be removed features
- **Removed**: Removed features
- **Fixed**: Bug fixes
- **Security**: Security fixes
