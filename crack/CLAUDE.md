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
