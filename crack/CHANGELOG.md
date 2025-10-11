# CHANGELOG - CRACK Toolkit

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

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
