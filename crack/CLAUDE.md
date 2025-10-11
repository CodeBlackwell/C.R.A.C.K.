# CLAUDE.md

## Project Overview

**C.R.A.C.K.** - **C**omprehensive **R**econ & **A**ttack **C**reation **K**it

Modular penetration testing toolkit for OSCP preparation. Standalone tools unified under single CLI.

## Quick Start

```bash
./reinstall.sh                    # After changes to __init__.py, cli.py, pyproject.toml
./run_tests.sh all                # Run all tests with coverage (70%+ target)
./run_tests.sh module <name>      # Test specific module
```

## Architecture

```
crack/
├── network/        # Port scanning, service enumeration, CVE lookup
├── web/            # HTML enumeration, parameter discovery
├── sqli/           # SQL injection detection and exploitation
├── exploit/        # CVE research and exploit lookup
├── track/          # Enumeration tracking & task management (235+ service plugins)
│   ├── core/              # TargetProfile, TaskNode, EventBus, Storage
│   ├── parsers/           # Nmap XML/greppable parsers
│   ├── services/          # Service plugins (auto-generate tasks)
│   ├── alternatives/      # Manual command alternatives (45+ commands)
│   ├── interactive/       # TUI mode (state machine, panels, shortcuts)
│   └── visualizer/        # Task tree visualization
├── reference/      # Command reference system (70+ OSCP commands)
└── utils/          # Shared utilities (colors, parsers)

Storage: ~/.crack/targets/<TARGET>.json
Config:  ~/.crack/config.json
Logs:    .debug_logs/tui_debug_*.log
```

## Development Workflows

### 1. TUI Debug-Validation Test Pattern (PRIMARY)

**Pattern:** Mock Input → Run TUI → Parse Logs → Assert

**Use Case:** Testing interactive TUI features without visual verification

**Quick Template:**
```python
import pytest
from pathlib import Path
from unittest.mock import patch
from crack.track.interactive.debug_logger import DebugLogger
from crack.track.interactive.log_types import LogConfig

def test_import_invalid_file_shows_validation_error(
    temp_crack_home,
    simulated_input,
    tmp_path
):
    """
    PROVES: Import form validates file paths and shows errors

    User Actions:
    1. Navigate to import panel
    2. Enter invalid file path
    3. See validation error

    Expected Logs:
    - "Validating file path: /nonexistent/file"
    - "✗ File validation failed: Path does not exist"
    """
    # 1. Mock user input sequence
    simulated_input([
        '4',                    # Choice: Import scan results
        '1',                    # Choice: Enter custom file path
        '/nonexistent/file',    # Input: Invalid file path
        'b'                     # Choice: Back to dashboard
    ])

    # 2. Setup debug logging
    debug_log = tmp_path / 'test_debug.log'
    debug_config = LogConfig(enabled=True, level='NORMAL')

    # 3. Run TUI session (mocked input will auto-execute)
    from crack.track.interactive.tui_session_v2 import TUISessionV2
    with patch('crack.track.interactive.tui_session_v2.get_debug_logger') as mock_logger:
        logger = DebugLogger(str(debug_log), debug_config)
        mock_logger.return_value = logger

        try:
            session = TUISessionV2(
                "192.168.45.100",
                debug=True,
                debug_config=debug_config
            )
            session.run()  # Will exit when inputs exhausted
        except StopIteration:
            pass  # Expected when input queue empty

    # 4. Parse debug log
    log_content = debug_log.read_text()

    # 5. Assert expected validations
    assert "Validating file path: /nonexistent/file" in log_content
    assert "✗ File validation failed:" in log_content
    assert "Path does not exist" in log_content
```

**Common Input Keys:**
```python
simulated_input([
    '4',                    # Dashboard: Select import panel
    '1',                    # Import: Enter custom path
    '/path/to/file',        # Input: File path
    'n',                    # Wizard: Next stage
    'b',                    # Any: Back/Cancel
    'c',                    # Wizard: Confirm action
    'x'                     # Any: Cancel/Exit
])
```

**Log Assertion Patterns:**
```python
# Validation attempt
assert "Validating file path:" in log_content

# Success
assert "✓ File path valid:" in log_content
assert "✓ Parse successful: 3 ports found" in log_content

# Failure
assert "✗ File validation failed:" in log_content
assert "✗ Parse exception:" in log_content

# State transitions
assert "[STATE.TRANSITION]" in log_content
assert "Panel changed: dashboard -> import" in log_content
```

**Debug Log Analysis:**
```bash
# View real-time
tail -f .debug_logs/tui_debug_*.log

# Filter by category
grep "\[UI.INPUT\]" .debug_logs/tui_debug_*.log

# Find errors with context
grep -C 5 "ERROR" .debug_logs/tui_debug_*.log

# Performance analysis
grep "elapsed=" .debug_logs/tui_debug_*.log | awk -F'=' '$2 > 1.0'
```

**Outcome:** Dev writes TUI features → Tests validate via logs → User validates visuals separately

### 2. Adding CLI Tools

```python
# 1. Create crack/network/new_tool.py
def main():
    parser = argparse.ArgumentParser(description='New Tool')
    parser.add_argument('target', help='Target IP')
    args = parser.parse_args()
    # ... tool logic ...

# 2. Update crack/network/__init__.py
from .new_tool import new_tool
__all__ = ['new_tool', ...]

# 3. Add to crack/cli.py
def new_tool_command(args):
    from crack.network import new_tool
    sys.argv = ['new_tool'] + args
    new_tool.main()

new_tool_parser = subparsers.add_parser('new-tool', help='Description', add_help=False)
new_tool_parser.set_defaults(func=new_tool_command)

# 4. Run ./reinstall.sh
```

### 3. Adding Service Plugins

```python
# Create track/services/new_service.py
from .base import ServicePlugin

@ServiceRegistry.register
class NewServicePlugin(ServicePlugin):
    @property
    def name(self) -> str:
        return "new-service"

    def detect(self, port_info: Dict[str, Any]) -> bool:
        service = port_info.get('service', '').lower()
        return service in ['new-service', 'new-svc']

    def get_task_tree(self, target: str, port: int, service_info: Dict) -> Dict:
        return {
            'id': f'new-service-{port}',
            'name': f'NewService Enumeration (Port {port})',
            'type': 'parent',
            'children': [...]
        }

# No reinstall needed - auto-discovered via @ServiceRegistry.register
```

### 4. Debugging TUI Issues (Log-Driven Workflow)

**Pattern:** Add logging → User tests → Check logs together → Fix → Retest

1. **Add Debug Logging** - Timestamped logs in `.debug_logs/`
2. **User Reproduces** - `crack track --tui -D <target>`
3. **Analyze Logs** - Find last entry before freeze/error
4. **Fix Issue** - Address root cause from logs
5. **User Retests** - Verify fix with same steps

**Example:** TUI freeze diagnosed via logs showing choice ID mismatch (`'next'` vs `'execute-next'`)

### 5. Dev Fixtures - Rapid State Loading

**Pattern:** Save state once → Load instantly → Test immediately

**Use Case:** Testing plugins/features at specific enumeration states without manual setup

#### Quick Start
```bash
# List available fixtures
crack track --dev-list

# Load fixture (auto-enables --tui and --debug)
crack track --dev=web-enum 192.168.45.100

# Create custom fixture from current state
crack track --dev-save my-state 192.168.45.100 \
  --dev-description "SQLi discovered, exploitation pending"
```

#### Built-in Fixtures

**minimal** - Fresh start with services discovered
- Ports: 22 (SSH), 80 (HTTP)
- Findings: None
- Tasks: Initial enumeration pending
- Use: Test service plugin initialization

**web-enum** - HTTP enumeration completed
- Ports: 22 (SSH), 80 (HTTP)
- Findings: 2 directories, 1 vulnerability
- Tasks: gobuster/nikto done, inspection pending
- Use: Test finding-to-task conversion

**smb-shares** - SMB discovery completed
- Ports: 22 (SSH), 139/445 (SMB)
- Findings: 3 shares, anonymous access
- Tasks: enum4linux done, mounting pending
- Use: Test SMB plugin logic

**post-exploit** - Initial access achieved
- Ports: 22 (SSH), 80 (HTTP)
- Findings: RCE, reverse shell
- Credentials: www-data shell
- Tasks: Privesc enumeration pending
- Use: Test post-exploit plugins

#### Fixture Management
```bash
# View fixture details
crack track --dev-show web-enum

# Delete fixture
crack track --dev-delete old-fixture

# Regenerate sample fixtures (if corrupted)
python3 track/scripts/generate_sample_fixtures.py
```

#### Workflow Comparison

**Before Fixtures (10+ minutes):**
```bash
crack track --dev 192.168.45.100
# ... import nmap scan
# ... run gobuster
# ... document findings
# ... finally test feature
```

**With Fixtures (0 minutes):**
```bash
crack track --dev=web-enum 192.168.45.100
# Loads instantly - start testing immediately
```

#### Development Benefits

**Plugin Testing:** Load exact state needed to trigger plugin logic
```bash
crack track --dev=smb-shares 192.168.45.100
# Test SMB plugin's share mounting tasks immediately
```

**Bug Reproduction:** Save problematic states
```bash
crack track --dev-save bug-123 192.168.45.100
# Later: crack track --dev=bug-123 192.168.45.100
```

**Training/Demos:** Show different phases without live scanning
```bash
crack track --dev=minimal 192.168.45.100        # Demo 1
crack track --dev=web-enum 192.168.45.100       # Demo 2
crack track --dev=post-exploit 192.168.45.100   # Demo 3
```

#### Fixture Architecture

**Location:** `~/.crack/fixtures/` (immutable)
**Format:** Standard profile JSON + metadata
**Loading:** Copies fixture to `~/.crack/targets/<TARGET>.json`
**Immutability:** Original fixture never modified

**Storage:**
- `track/core/fixtures.py` - FixtureStorage class
- `track/scripts/generate_sample_fixtures.py` - Sample generator
- `~/.crack/fixtures/README.md` - Complete documentation
- `tests/track/test_fixtures.py` - Comprehensive tests

**See Also:** `~/.crack/fixtures/README.md` for advanced usage

### Debug Logging Quick Reference

**Quick Start Commands:**
```bash
# Most common use case
crack track --tui <target> --debug --debug-categories=UI:VERBOSE,STATE:VERBOSE

# Debug by problem type
crack track --tui <target> --debug --debug-categories=UI:TRACE,STATE.TRANSITION:VERBOSE  # UI freezes
crack track --tui <target> --debug --debug-categories=UI.INPUT:TRACE                     # Input issues
crack track --tui <target> --debug --debug-categories=STATE.TRANSITION:VERBOSE,UI.MENU:VERBOSE  # Navigation
crack track --tui <target> --debug --debug-categories=EXECUTION:VERBOSE                  # Task execution
crack track --tui <target> --debug --debug-categories=PERFORMANCE:TRACE --debug-timing   # Performance
crack track --tui <target> --debug --debug-categories=STATE:TRACE,DATA:VERBOSE          # State management
```

**Log Categories:**
- `UI.*` - UI.INPUT, UI.MENU, UI.RENDER, UI.PANEL
- `STATE.*` - STATE.TRANSITION, STATE.VALIDATION, STATE.PERSISTENCE
- `EXECUTION.*` - EXECUTION.COMMAND, EXECUTION.TASK
- `DATA.*` - DATA.READ, DATA.WRITE, DATA.PARSE
- `PERFORMANCE.*` - PERFORMANCE.TIMING, PERFORMANCE.MEMORY

**Verbosity Levels:** MINIMAL, NORMAL, VERBOSE, TRACE

**Log Analysis Commands:**
```bash
# View real-time
tail -f .debug_logs/tui_debug_*.log

# Filter by category
grep "\[UI.INPUT\]" .debug_logs/tui_debug_*.log

# Find errors with context
grep -C 5 "ERROR" .debug_logs/tui_debug_*.log

# Performance analysis
grep "elapsed=" .debug_logs/tui_debug_*.log | awk -F'=' '$2 > 1.0'

# State transitions
grep "\[STATE.TRANSITION\]" .debug_logs/tui_debug_*.log

# Input processing
grep "\[UI.INPUT\]" .debug_logs/tui_debug_*.log | tail -20
```

**Common Debug Combinations:**
```bash
# General panel development
crack track --tui <target> --debug --debug-categories=UI:VERBOSE,STATE:VERBOSE

# Debugging specific panel
crack track --tui <target> --debug --debug-categories=UI.PANEL:TRACE,STATE:VERBOSE

# Production troubleshooting
crack track --tui <target> --debug --debug-categories=ERROR:VERBOSE,STATE.TRANSITION:NORMAL

# Full diagnostic dump
crack track --tui <target> --debug --debug-categories=*:TRACE --debug-timing
```

**5-Step Troubleshooting Workflow:**
1. Enable comprehensive logging with appropriate categories
2. Reproduce issue with exact steps
3. Analyze logs to find last entry before failure
4. Identify root cause from execution flow
5. Fix and retest with same logging enabled

**Full Reference:** `track/docs/DEBUG_LOGGING_CHEATSHEET.md`

## Testing Philosophy

**Coverage Target:** 70%+ for core functionality

**Test Types:**
- **Unit:** Individual functions/classes
- **Integration:** CLI routing, module interactions
- **TUI Validation:** Mock input + log assertion (PRIMARY for interactive features)
- **User-Story:** BDD format validating OSCP workflows

**Mock Strategy:**
```python
# External commands
mock_subprocess_run

# HTTP requests
mock_requests_session

# TUI input
simulated_input(['4', '1', '/path', 'b'])
```

**TUI Test Fixtures** (in `tests/conftest.py`):
- `temp_crack_home` - Isolated ~/.crack directory
- `simulated_input` - Queue-based input mocker
- `tmp_path` - Temporary directory (pytest built-in)

## Module Quick Reference

### Track (`crack track`)
- **Purpose:** Enumeration tracking, task management, interactive TUI
- **Key Classes:** TargetProfile, TaskNode, EventBus, ServicePlugin
- **Event Flow:** Nmap Parser → Emit service_detected → ServicePlugin → Generate tasks
- **Interactive:** State machine with panels, shortcuts, session persistence
- **No reinstall:** Changes to `track/interactive/`, `track/services/`, `track/alternatives/commands/`

### Alternatives (`track/alternatives/`)
- **Purpose:** Manual command alternatives when tools fail (OSCP requirement)
- **Flow:** User presses `alt` → Auto-fill variables → Execute → Log result
- **Priority:** Task Metadata → Profile State → Config → User Prompt
- **Status:** Production (83/83 tests passing)

### Reference (`crack/reference/`)
- **Purpose:** Command lookup with JSON definitions
- **Usage:** `crack reference --fill bash-reverse-shell`
- **Config:** Auto-fills `<LHOST>`, `<LPORT>`, `<TARGET>` from `~/.crack/config.json`
- **No reinstall:** JSON changes load dynamically

### SQLi (`crack/sqli/`)
- **Structure:** scanner.py (main) → techniques.py → databases.py → reporter.py
- **Entry Point:** `sqli_scanner.py` for CLI, `SQLiScanner` class for library

## When to Reinstall

**Reinstall Required:**
- `__init__.py` (module structure)
- `cli.py` (CLI command registration)
- `pyproject.toml` (entry points, dependencies)
- `track/cli.py` (Track CLI routing)
- `reference/core/*.py` (Reference core logic)

**No Reinstall Needed:**
- Tool logic changes (library usage)
- `track/interactive/` modules
- `track/services/` plugins
- `track/alternatives/commands/` JSON
- `reference/data/commands/` JSON
- Test file changes

## Key Design Patterns

1. **Standalone + Integrated**
   - Standalone: `python3 crack/network/port_scanner.py 192.168.1.1`
   - Via CLI: `crack port-scan 192.168.1.1`
   - Achieved via `sys.argv` reassignment + `add_help=False`

2. **Event-Driven Task Generation**
   - Parsers emit events → ServiceRegistry matches plugins → Plugins generate tasks

3. **TUI State Machine**
   - Display Context → Build Menu → Get Input → Process Choice → Execute Action → Save Checkpoint → Repeat

4. **Log-Driven Development**
   - All TUI state transitions logged → Tests assert log entries → Visual testing separate

5. **Findings→Tasks→Findings Loop** (Core Enumeration Engine)
   - Task execution → Output analysis → Finding extraction → Task generation → Repeat
   - FindingsProcessor converts findings to actionable tasks automatically
   - Deduplication prevents infinite loops
   - Event-driven architecture enables extensibility

## Findings Workflow Architecture

**The Core Loop:** This is the foundation that enables infinite enumeration depth.

```
1. Initial Scan (Nmap)
   ↓
2. Service Detection (ServicePlugins)
   ↓
3. Task Generation (get_task_tree)
   ↓
4. Task Execution (TUI/CLI)
   ↓
5. Output Analysis (OutputPatternMatcher)
   ↓
6. Finding Extraction (directories, credentials, vulns, etc.)
   ↓
7. Finding Persistence (profile.add_finding)
   ↓
8. Event Emission (finding_added)
   ↓
9. Finding→Task Conversion (FindingsProcessor)
   ↓
10. New Task Generation → LOOP BACK TO STEP 4
```

### Key Components

**1. OutputPatternMatcher** (`track/parsers/output_patterns.py`)
- Analyzes command output line-by-line
- Tool-specific matchers (gobuster, nmap, enum4linux, etc.)
- Returns structured findings dict: `{'directories': [...], 'credentials': [...], 'vulnerabilities': [...]}`

**2. TargetProfile.add_finding()** (`track/core/state.py:162`)
- Persists findings to profile JSON
- Emits `finding_added` event to EventBus
- Tracks source for documentation/reporting

**3. FindingsProcessor** (`track/services/findings_processor.py`)
- Listens for `finding_added` events
- Converts findings to tasks using registry pattern
- Handles deduplication (same finding won't trigger multiple tasks)
- Emits `plugin_tasks_generated` events

**4. EventBus** (`track/core/events.py`)
- Decoupled communication system
- Events: `finding_added`, `task_completed`, `plugin_tasks_generated`, `service_detected`
- Subscribe with `EventBus.on('event_name', handler)`
- Emit with `EventBus.emit('event_name', {'key': 'value'})`

### Finding Types & Converters

| Finding Type | Example | Generated Task |
|--------------|---------|----------------|
| `directory` | `/admin` | Inspect directory, check for login forms |
| `file` | `/.env`, `/config.php` | Download and analyze file |
| `vulnerability` | `CVE-2021-44228` | Research exploit with searchsploit |
| `credential` | `admin:password123` | Logged for manual verification (no auto-task) |
| `user` | `admin` | Test common passwords |
| `service` | `Apache 2.4.41` | (Handled by ServicePlugins, not FindingsProcessor) |

### Example Flow

```
# User imports nmap scan
1. Nmap detects HTTP on port 80
2. HTTPPlugin generates gobuster task
3. User executes gobuster
4. OutputPatternMatcher extracts: "/admin" directory
5. profile.add_finding(type='directory', description='/admin', source='gobuster')
6. EventBus emits finding_added event
7. FindingsProcessor receives event
8. Checks deduplication (not seen before)
9. Converts to task: "Inspect /admin"
10. Emits plugin_tasks_generated event
11. Task added to profile automatically
12. User sees new task in TUI
```

### Deduplication Strategy

**Fingerprint:** `{finding_type}:{description}`
- Example: `"directory:/admin"`
- Same directory found by gobuster AND dirb = only 1 task generated
- Clear history: `processor.clear_history()` (for testing/reset)

### Event Flow Diagram

```
[Nmap Parser] ─service_detected→ [ServiceRegistry]
                                        ↓
                                  [ServicePlugin]
                                        ↓
                              plugin_tasks_generated
                                        ↓
                                  [TargetProfile]
                                        ↓
                                  [Task Execution]
                                        ↓
                                  [OutputPatternMatcher] ─findings_dict→ [TUI]
                                        ↓                                    ↓
                                  [profile.add_finding] ←───────────────────┘
                                        ↓
                                  finding_added
                                        ↓
                                  [FindingsProcessor]
                                        ↓
                              plugin_tasks_generated
                                        ↓
                                  [TargetProfile] ← LOOP CLOSES
```

### Integration Points

**TUI Integration** (`track/interactive/tui_session_v2.py`):
1. Line 1720-1741: OutputPatternMatcher analyzes output, findings saved to profile
2. Line 1764-1778: task_completed event emitted after execution
3. Line 74-76: FindingsProcessor initialized in __init__

**Testing** (`tests/track/test_findings_processor.py`):
- 23 unit tests covering all finding types
- Deduplication logic validation
- Error handling for malformed findings
- Task structure validation

### Extending the System

**Add New Finding Type:**
```python
# In track/services/findings_processor.py
def _convert_new_type_finding(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convert new_type finding to tasks"""
    description = finding.get('description', '')

    # Generate task based on finding
    return [{
        'id': f'new-type-{description}',
        'name': f'Handle {description}',
        'type': 'executable',
        'status': 'pending',
        'metadata': {
            'command': f'custom-command {description}',
            'finding_source': finding.get('source', 'Unknown')
        }
    }]

# Register in __init__
self.converters['new_type'] = self._convert_new_type_finding
```

**Listen for Custom Events:**
```python
from crack.track.core.events import EventBus

def my_handler(data):
    finding = data['finding']
    print(f"New finding: {finding['type']}")

EventBus.on('finding_added', my_handler)
```

### Why This Architecture?

**Event-Driven Benefits:**
- Decoupled components (parsers, processors, plugins)
- Easy to add new finding types without modifying existing code
- Testable in isolation (mock events)

**Automatic Task Generation:**
- No manual intervention required
- Infinite enumeration depth
- Findings beget tasks beget findings (exponential discovery)

**Deduplication:**
- Prevents infinite loops
- Efficient (set-based lookups)
- Allows multiple tools to find same thing

**Traceability:**
- Every finding tracks its source
- Every task knows its origin finding
- Complete chain for reporting

### ServicePlugin Task Completion (Service-Specific Intelligence)

**Complementary System:** While FindingsProcessor handles generic finding→task conversion, ServicePlugins provide **service-specific intelligence** via `on_task_complete()` methods.

**Key Difference:**
- FindingsProcessor: "You found a directory → Inspect it" (generic)
- HTTP Plugin: "Gobuster found /admin → Test default admin credentials" (service-specific)

**Implementation** (`track/services/registry.py:183-288`):
1. Task completes → EventBus emits `task_completed`
2. ServiceRegistry._handle_task_completed receives event
3. Fuzzy matching identifies which plugin owns the task
4. Plugin's on_task_complete(task_id, output, target) called
5. Plugin returns service-specific follow-up tasks
6. Tasks emitted via plugin_tasks_generated event

**Fuzzy Matching Logic** (flexible to avoid false negatives):
- Direct match: `http-enum-80` → HTTP Plugin
- Alias match: `gobuster-80` → HTTP Plugin (alias: "gobuster")
- Port match: `custom-scan-80` → HTTP Plugin (default port: 80)
- Metadata match: `{service: 'http'}` → HTTP Plugin

**Service Aliases:**
```python
'http': ['web', 'https', 'whatweb', 'gobuster', 'nikto', 'wpscan'],
'smb': ['smbclient', 'enum4linux', 'smbmap', 'crackmapexec'],
'ssh': ['openssh', 'ssh-audit'],
'sql': ['mysql', 'postgresql', 'mssql', 'oracle']
```

**Real-World Examples:**

**Example 1: HTTP Admin Panel Detection**
```
Gobuster → Finds /admin → HTTP Plugin sees "gobuster" + "/admin"
  → Generates: "Test Admin Panel Authentication (try admin:admin, admin:password)"
```

**Example 2: WordPress Detection**
```
WhatWeb → Detects WordPress → HTTP Plugin sees "whatweb" + "wordpress"
  → Generates: "wpscan --url http://target:80 --enumerate u,vp"
```

**Example 3: SMB Share Discovery**
```
Enum4linux → Finds shares → SMB Plugin sees "enum4linux" + "share"
  → Generates: "Mount SMB Share (smbclient //target/Share)"
```

**Active Plugins with on_task_complete (18+):**
- HTTP Plugin (admin panels, CMS detection)
- SMB Plugin (share mounting, null sessions)
- SSH Plugin (exploit research based on version)
- SQL Plugin (database enumeration)
- Post-Exploit Plugin (privilege escalation)
- Binary Exploit Plugin (shellcode generation)
- Network Poisoning Plugin (MitM attacks)
- Lua Exploit Plugin (command execution)
- Linux Capabilities Plugin (capability exploitation)
- AD Enumeration Plugin (Kerberoasting)
- ... and 8 more

**Testing** (`tests/track/test_plugin_task_completion.py`):
- 10 comprehensive tests
- Fuzzy matching validation
- Multi-plugin coordination
- Task generation verification

**Integration Points:**
- ServiceRegistry: Lines 60 (event handler), 183-221 (handler impl), 224-288 (fuzzy matching)
- TUI: Line 1772 (emits task_completed event)

**Why Both Systems?**

| System | Strength | Example |
|--------|----------|---------|
| **FindingsProcessor** | Universal patterns | Any directory → Inspect |
| **ServicePlugin** | Service optimization | HTTP /admin → Test defaults |

Together they provide **comprehensive automatic enumeration** with both breadth (generic) and depth (service-specific).

## TUI UX Philosophy (Established Patterns)

**Core Principle:** Every keystroke has purpose. Minimize friction in high-pressure OSCP scenarios.

### 1. One-Keystroke Transitions

**Philosophy:** No Enter key required. Single keypress executes actions immediately.

**Implementation:**
- All overlays (`h`, `s`, `t`, `p`) - Single key opens, single key dismisses
- All menu choices - Press number, action executes
- All panel navigation - Press letter, panel switches
- Command mode (`:`) - Only multi-char shortcuts require Enter

**Example Flow:**
```
User presses: h
Result: Help overlay appears (no Enter needed)

User presses: s
Result: Help dismisses AND status overlay appears (no Enter needed)

User presses: s again
Result: Status overlay closes, back to dashboard (no Enter needed)
```

**Code Pattern:**
```python
# ✓ Correct - Single keypress
key = self.hotkey_handler.read_key()
if key == 'h':
    self._show_help()

# ✗ Wrong - Requires Enter
user_input = input("Press key: ")
if user_input == 'h':
    self._show_help()
```

### 2. Smart Dismissal

**Philosophy:** Dismissal key can trigger next action. User's intent is clear from context.

**Implementation:**
- Overlay A is open
- User presses key for Overlay B
- Overlay A dismisses AND Overlay B opens (single keystroke)

**Exception:** Pressing same key twice just closes (toggle behavior)

**Code Pattern:**
```python
def _show_help(self):
    # Show help overlay
    dismiss_key = self.hotkey_handler.read_key()

    # Toggle: pressing 'h' again just closes
    if dismiss_key == 'h':
        return  # Just close, don't re-execute

    # Smart dismiss: any other valid command executes
    if dismiss_key not in ['\r', '\n', ' ']:
        self._process_input(dismiss_key)  # Execute the command
```

**Example Flow:**
```
Dashboard → Press 'h' → Help opens
Help → Press 's' → Help closes + Status opens (smart dismiss)
Status → Press 's' → Status closes (toggle)
Dashboard → Press 't' → Tree opens
Tree → Press 'h' → Tree closes + Help opens (smart dismiss)
```

### 3. Toggle Behavior

**Philosophy:** Same key twice = close overlay. Prevents accidental re-triggering.

**Implementation:**
- `h` + `h` = Help opens, then closes
- `s` + `s` = Status opens, then closes
- `t` + `t` = Tree opens, then closes
- `p` + `p` = Progress opens, then closes

**Why:** Prevents infinite toggle loops. User has quick escape route.

**Code Pattern:**
```python
# Prompt hints at toggle behavior
self.console.print("[dim]Press any key to dismiss (or 'h' to toggle off)...[/]")

# Toggle check happens BEFORE smart dismiss
if dismiss_key == 'h':
    return  # Just close, no smart dismiss

# Smart dismiss only if NOT same key
if dismiss_key not in ['\r', '\n', ' ']:
    self._process_input(dismiss_key)
```

### 4. Vim-Inspired Navigation

**Philosophy:** Modal interaction. `:` enters command mode for multi-char shortcuts.

**Implementation:**
- Single chars (`h`, `s`, `t`, `n`, `l`, `f`) = Instant action
- Multi-char (`qn`, `ch`, `alt`, `pl`) = Require `:` prefix
- Digits = Smart buffering (500ms timeout for multi-digit numbers)

**Example:**
```
User: h      → Help opens instantly
User: s      → Status opens instantly
User: :qn    → Quick note form opens
User: :ch    → Command history opens
User: 12     → Selects choice #12 (buffered)
User: 1      → After 500ms, selects choice #1
```

### 5. Consistent Prompts

**Philosophy:** User always knows what keys are valid. Prompts guide next action.

**Implementation:**
```python
# Dashboard
"Press key (or : for command):"

# Overlays with toggle hint
"Press any key to dismiss (or 'h' to toggle off)..."

# Panels with shortcuts
"Press key (1-10:Select, f:Filter, s:Sort, b:Back):"
```

**Why:** Reduces cognitive load. User doesn't have to remember all shortcuts.

### 6. Minimize Multi-Char Shortcuts

**Philosophy:** Single-char shortcuts only. Multi-char shortcuts are a last resort when all single chars are exhausted.

**Rule:** If we must use multi-char because single-char namespace is full, we must - but otherwise just doesn't make sense.

**Implementation:**
- **Preferred:** Single char (`n`, `l`, `f`, `o`, `p`, `h`, `s`, `t`, `q`)
- **Acceptable:** Two chars only when functionally necessary (`qn`, `ch`, `alt`, `pl`)
- **Avoid:** Three+ chars unless absolutely critical

**Decision Criteria - Use Multi-Char Only When:**
1. **All relevant single chars are taken** (e.g., `h` for help, so command history becomes `ch`)
2. **Function is namespaced** (e.g., `qn` = quick note, `qx` = quick export - the `q` prefix groups "quick" actions)
3. **Mnemonic is stronger** (e.g., `alt` for alternatives is clearer than `a`)
4. **Collision would confuse** (e.g., `f` for findings vs filter)

**Current Single-Char Allocations:**
- `n` - Next task
- `l` - List tasks
- `f` - Findings
- `o` - Output overlay
- `p` - Progress dashboard
- `h` - Help
- `s` - Status
- `t` - Tree
- `q` - Quit
- `b` - Back
- `w` - Quick wins (Wordlist in basic mode)
- `i` - Import scans
- `d` - Document finding
- `r` - Recommendations (basic mode)
- `c` - Change confirmation (basic mode)
- `x` - Command templates (basic mode)

**Multi-Char Audit - Consolidation Opportunities:**
- `pd` → Already aliased to `p` ✓
- `qn`, `qx`, `qe` → Keep (quick-prefix namespace)
- `ch` → Keep (`c` taken, `h` taken, command history is essential)
- `pl` → Keep (`p` taken for progress, port lookup is OSCP-critical)
- `tt`, `tf`, `tr` → Consider future consolidation if features prove low-value
- `ss`, `sa`, `sg`, `wr`, `be` → Review usage metrics before OSCP exam

**Footer Strategy:**
- Display ALL single-letter shortcuts with short names
- User sees available keys at all times
- No need to memorize or press `h` for common actions
- **Dynamic Generation:** Extracted from `ShortcutHandler.shortcuts` (single source of truth)
- **Auto-Updates:** Footer automatically reflects added/removed shortcuts

**Footer Code Pattern:**
```python
def _render_footer(self) -> Panel:
    """Dynamically extract single-char shortcuts from ShortcutHandler"""
    single_char_shortcuts = []

    # Priority order for common actions
    priority_keys = ['n', 'l', 'f', 'w', 'i', 'd', 'o', 'p', 'h', 's', 't', 'q', 'b']

    for key in priority_keys:
        if key in self.shortcut_handler.shortcuts and len(key) == 1:
            description, _ = self.shortcut_handler.shortcuts[key]
            short_desc = description.split()[0][:5].capitalize()
            single_char_shortcuts.append(f"[cyan]{key}[/]:{short_desc}")

    shortcuts_text = " | ".join(single_char_shortcuts)
    return Panel(shortcuts_text, border_style="cyan")
```

### UX Decision Matrix

**When designing new TUI features, ask:**

1. **Can it be 1 keystroke?** → If yes, make it so
2. **Can it use a single char?** → If yes, use single char (not multi-char)
3. **If multi-char is required, why?** → Must justify: namespace full, namespaced feature, or stronger mnemonic
4. **Does dismissal key have obvious next action?** → If yes, implement smart dismiss
5. **Should same key twice close it?** → If overlay, yes (toggle)
6. **Does user need guidance?** → If yes, add to prompt and footer

**Anti-Patterns to Avoid:**

- ✗ Requiring Enter after single-key shortcuts
- ✗ Using multi-char shortcuts when single-char is available
- ✗ Creating 3+ char shortcuts (max 2 chars, prefer 1)
- ✗ Not hinting toggle behavior in prompts
- ✗ Dismissing overlay and losing user's next intent
- ✗ Inconsistent key behavior across panels
- ✗ Silent key presses (always provide feedback)
- ✗ Footer showing only subset of shortcuts (show ALL single-char)

**Testing Checklist:**

- [ ] Single keypress opens feature (no Enter)
- [ ] Same key twice closes feature (toggle)
- [ ] Different key closes + opens new feature (smart dismiss)
- [ ] Prompt hints at available keys
- [ ] Feedback on every keypress (visual or state change)
- [ ] Debug logs capture dismiss key for troubleshooting

## Theme System Usage

**Always use ThemeManager for TUI colors** - Never hardcode color strings.

**Quick Start:**
```python
# In __init__ or panel initialization
from .themes import ThemeManager
self.theme = ThemeManager(debug_logger=self.debug_logger)

# Semantic colors (automatic theme switching)
self.theme.primary("Text")      # Panel borders, hotkeys
self.theme.success("Text")      # Completed tasks, success messages
self.theme.warning("Text")      # Pending tasks, warnings
self.theme.danger("Text")       # Failed tasks, errors
self.theme.muted("Text")        # Dim text, subtitles

# Component-specific colors
self.theme.panel_border()       # Get color name for Panel(border_style=...)
self.theme.task_state_color("completed")
self.theme.finding_type_color("vulnerability")
self.theme.port_state_color("open")

# Helper functions (track/interactive/themes/helpers.py)
from .themes.helpers import format_menu_number, format_hotkey, format_task_status
format_menu_number(self.theme, 1)     # "[bold bright_white]1.[/]"
format_hotkey(self.theme, 'h')        # "[cyan]h[/]"
```

**Why:**
- User can switch themes instantly (6 built-in: oscp, dark, light, nord, dracula, mono)
- Live preview shows changes immediately
- Accessibility support (monochrome mode for screenreaders)
- Centralized color management (one place to update)

**Built-in Themes:**
- `oscp` - Cyan-heavy, OSCP workflow optimized (default)
- `dark` - Dark terminal with bright colors
- `light` - Light terminal with darker colors for contrast
- `nord` - Arctic blue color scheme
- `dracula` - Dark with purple accents
- `mono` - No colors, exam-safe, accessible

**Location:** `track/interactive/themes/` (manager.py, presets.py, helpers.py)

## Educational Philosophy (OSCP Focus)

Every tool includes:
1. **Manual alternatives** - For exam scenarios where tools fail
2. **Flag explanations** - Teach methodology, not memorization
3. **Time estimates** - Exam time management
4. **Success/failure indicators** - Verify results
5. **Next steps** - Guide attack chain
6. **Source tracking** - Required for OSCP reports

## Documentation Deep Dives

- **Track Module:** `track/README.md` (comprehensive usage + architecture)
- **Alternative Commands:** `track/alternatives/README.md` (developer guide)
- **Reference System:** `reference/docs/` (config, placeholders, tags)
- **Debug Logging:** `track/docs/DEBUG_LOGGING_CHEATSHEET.md` (categories, filters, patterns)
- **Test Philosophy:** `tests/track/README.md` (user stories, value validation)
- **Panel Development:** `track/docs/PANEL_DEVELOPER_GUIDE.md` (TUI extension patterns)

## Package Info

- **PyPI Name:** `crack-toolkit`
- **Import Name:** `crack`
- **Entry Point:** `crack` command → `crack.cli:main`
- **Platform:** Kali Linux (OSCP preparation)
- **Python:** 3.8+
- **Dependencies:** requests, beautifulsoup4, urllib3
- **External Tools:** nmap, searchsploit, nikto (subprocess calls)

## Module Imports

```python
# ✓ Correct
from .utils.colors import Colors              # Relative import
from crack.utils.colors import Colors         # Absolute import

# ✗ Wrong
from crack.network import port_scanner        # Circular import in __init__.py
```

## Development Checkpoints

**At checkpoints, provide user with:**
1. Step-by-step testing instructions
2. Log analysis command: `grep "<KEY_PATTERN>" .debug_logs/tui_debug_*.log`
3. Expected log entries for success/failure
4. Visual verification checklist (separate from automated tests)

**Note:** Logs can be large - use `grep` to avoid wasting context/tokens
