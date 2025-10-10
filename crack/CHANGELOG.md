# CHANGELOG - CRACK Toolkit

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

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
