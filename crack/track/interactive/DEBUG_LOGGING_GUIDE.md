# Precision Debug Logging - Usage Guide

Comprehensive guide to using the precision debug logging system for TUI/GUI/CLI development in CRACK Track.

## Table of Contents

- [Quick Start](#quick-start)
- [Core Concepts](#core-concepts)
- [CLI Integration](#cli-integration)
- [Programmatic Usage](#programmatic-usage)
- [Advanced Features](#advanced-features)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)

---

## Quick Start

### Basic Usage (CLI)

```bash
# Enable debug logging to file
crack track --tui --debug 192.168.1.1

# Log only UI events
crack track --tui --debug --debug-categories=UI 192.168.1.1

# Log UI and STATE with verbose output
crack track --tui --debug --debug-categories="UI:VERBOSE,STATE:VERBOSE" 192.168.1.1

# Log everything to console
crack track --tui --debug --debug-categories=all --debug-output=console 192.168.1.1
```

### Basic Usage (Python)

```python
from crack.track.interactive.log_config import LogConfig
from crack.track.interactive.debug_logger import init_debug_logger, log_info
from crack.track.interactive.log_types import LogCategory

# Initialize logger
config = LogConfig.from_string("UI.INPUT:VERBOSE,STATE:NORMAL")
logger = init_debug_logger(config=config, target="192.168.1.1")

# Log messages
log_info("Application started", category=LogCategory.SYSTEM_INIT)
log_info("User pressed 'n'", category=LogCategory.UI_INPUT, key="n")
```

---

## Core Concepts

### 1. Categories

Logs are organized into **hierarchical categories** using dot notation:

```
UI                          # Parent category
├── UI.RENDER              # Screen rendering
├── UI.INPUT               # User input handling
├── UI.MENU                # Menu generation
├── UI.PANEL               # Panel management
├── UI.FORM                # Form handling
└── UI.LIVE                # Live display updates

STATE
├── STATE.TRANSITION       # State machine changes
├── STATE.CHECKPOINT       # Save operations
├── STATE.LOAD             # Load operations
└── STATE.SAVE             # Save operations

EXECUTION
├── EXECUTION.START        # Task start
├── EXECUTION.OUTPUT       # Command output
├── EXECUTION.END          # Task completion
└── EXECUTION.ERROR        # Execution errors

... (see CATEGORY_REFERENCE.md for full list)
```

**Hierarchy Matching:**
- Enable `UI` → logs all `UI.*` categories
- Enable `UI.INPUT` → logs only that specific category
- Enable `UI.*` → same as enabling `UI`

### 2. Log Levels

Control verbosity with four levels (least to most verbose):

- **MINIMAL**: Critical information, errors only
- **NORMAL**: Standard debug information (default)
- **VERBOSE**: Detailed debug information
- **TRACE**: Everything including internal details

### 3. Filters

Three dimensions of filtering:

1. **Category Filters**: Which types of events to log
2. **Module Filters**: Which Python modules to log from
3. **Level Filters**: How much detail to include

**Example: Combined Filtering**
```bash
# Log VERBOSE UI events from session.py module only
--debug --debug-categories=UI:VERBOSE --debug-modules=session
```

---

## CLI Integration

### Adding Debug Options to Your CLI

```python
import argparse
from crack.track.interactive.debug_cli import add_debug_arguments, create_logger_from_args

# Create parser
parser = argparse.ArgumentParser(description='My Tool')
parser.add_argument('target', help='Target IP')

# Add debug arguments
add_debug_arguments(parser)

# Parse and create logger
args = parser.parse_args()
logger = create_logger_from_args(args, target=args.target)

# Your code here
```

### Available CLI Arguments

```bash
--debug, -D                         Enable debug logging
--debug-categories SPECS            Category filters (e.g., "UI:VERBOSE,STATE")
--debug-modules MODULES             Module filters (e.g., "session,prompts")
--debug-level LEVEL                 Global level (MINIMAL|NORMAL|VERBOSE|TRACE)
--debug-output TARGET               Output (file|console|both|json)
--debug-format FORMAT               Format (text|json|compact)
--debug-config PATH                 Load config from JSON file
--debug-timing                      Include performance timing
```

### CLI Examples

```bash
# 1. Debug UI freezes
crack track --tui --debug --debug-categories=UI:TRACE --debug-output=both 192.168.1.1

# 2. Debug state machine
crack track --tui --debug --debug-categories=STATE.TRANSITION:VERBOSE 192.168.1.1

# 3. Track performance
crack track --tui --debug --debug-categories=PERFORMANCE --debug-timing 192.168.1.1

# 4. Debug specific module
crack track --tui --debug --debug-modules=session --debug-level=TRACE 192.168.1.1

# 5. Minimal logging
crack track --tui --debug --debug-level=MINIMAL 192.168.1.1

# 6. Use config file
crack track --tui --debug --debug-config=~/.crack/my_debug.json 192.168.1.1
```

---

## Programmatic Usage

### Basic Logging

```python
from crack.track.interactive.debug_logger import log_info, log_debug, log_error
from crack.track.interactive.log_types import LogCategory

# Simple logging
log_info("Task started")

# With category
log_info("Rendering menu", category=LogCategory.UI_MENU)

# With additional data
log_debug("Parsed nmap output", category=LogCategory.DATA_PARSE, ports=42, services=12)

# Error logging
log_error("Failed to connect", category=LogCategory.NETWORK_ERROR, host="192.168.1.1")
```

### Category-Specific Methods

```python
from crack.track.interactive.debug_logger import get_debug_logger
from crack.track.interactive.log_types import LogCategory

logger = get_debug_logger()

# UI logging
logger.log_render("main menu", details="5 choices")
logger.log_user_input("n", context="main menu")
logger.log_menu("task selection", choices=10)

# State logging
logger.log_state_transition("IDLE", "EXECUTING", reason="user selected task")
logger.log_checkpoint("save", details="profile saved to disk")

# Execution logging
logger.log_execution_start("nmap scan", task_id="scan-tcp-22")
logger.log_execution_end("nmap scan", success=True, exit_code=0)

# Data logging
logger.log_parse("nmap", items=42, details="parsed 42 ports")
logger.log_validation("port", valid=True)
```

### Configuration in Code

```python
from crack.track.interactive.log_config import LogConfig
from crack.track.interactive.debug_logger import init_debug_logger
from crack.track.interactive.log_types import LogCategory, LogLevel

# Create config from string
config = LogConfig.from_string("UI.INPUT:VERBOSE,STATE:NORMAL")

# Create config programmatically
config = LogConfig(enabled=True)
config.enable_category(LogCategory.UI_INPUT, LogLevel.VERBOSE)
config.enable_category(LogCategory.STATE, LogLevel.NORMAL)
config.enable_module("session")

# Initialize logger
logger = init_debug_logger(config=config, target="192.168.1.1")
```

### Runtime Configuration Changes

```python
logger = get_debug_logger()

# Enable/disable categories
logger.enable_category(LogCategory.UI_RENDER, LogLevel.TRACE)
logger.disable_category(LogCategory.UI_INPUT)

# Change verbosity
logger.set_category_level(LogCategory.STATE, LogLevel.VERBOSE)

# Update entire config
new_config = LogConfig.from_string("EXECUTION:TRACE")
logger.update_config(new_config)
```

---

## Advanced Features

### 1. Performance Tracking

#### Context Manager

```python
from crack.track.interactive.debug_logger import log_timing

with log_timing("Parse Nmap XML"):
    parse_nmap_file("scan.xml")

# Output: TIMING START: Parse Nmap XML
#         TIMING END: Parse Nmap XML | duration=0.125s
```

#### Manual Timing

```python
logger = get_debug_logger()

logger.start_timer("complex_operation")
# ... do work ...
duration = logger.end_timer("complex_operation")
```

#### Timer Method

```python
logger = get_debug_logger()

with logger.timer("database_query"):
    execute_query()
```

### 2. Function Decorators

#### Basic Decorator

```python
from crack.track.interactive.debug_logger import log_function
from crack.track.interactive.log_types import LogCategory

@log_function(category=LogCategory.UI_RENDER)
def render_menu():
    # ... implementation ...
    pass

# Output: ENTER: render_menu()
#         ... function execution ...
#         EXIT: render_menu()
```

#### Decorator with Timing

```python
@log_function(category=LogCategory.DATA_PARSE, log_timing=True)
def parse_large_file():
    pass

# Output: ENTER: parse_large_file()
#         EXIT: parse_large_file() | duration=2.341s
```

#### Decorator with Arguments

```python
@log_function(category=LogCategory.NETWORK_REQUEST, log_args=True, log_result=True)
def fetch_url(url):
    return requests.get(url)

# Output: ENTER: fetch_url() | args=('http://example.com',)
#         EXIT: fetch_url() | result=<Response [200]>
```

### 3. Context Managers

#### Logging Context

```python
from crack.track.interactive.debug_logger import log_context
from crack.track.interactive.log_types import LogCategory

with log_context("Task Execution", category=LogCategory.EXECUTION):
    execute_task()
    process_results()

# Output: ============================================================
#           Task Execution
#         ============================================================
#         BEGIN: Task Execution
#         ... logs during execution ...
#         END: Task Execution
```

#### Exception Logging

```python
from crack.track.interactive.debug_logger import log_exception_context

@log_exception_context
def risky_operation():
    raise ValueError("Something went wrong")

# Logs full exception with traceback
```

### 4. Conditional Logging

```python
from crack.track.interactive.debug_logger import log_if

log_if(task.failed, "Task failed", category=LogCategory.EXECUTION_ERROR, task_id=task.id)
```

### 5. Dictionary Logging

```python
from crack.track.interactive.debug_logger import log_dict

data = {"host": "192.168.1.1", "ports": [22, 80, 443], "services": ["ssh", "http", "https"]}
log_dict(data, title="Scan Results", category=LogCategory.DATA_PARSE)

# Output: ============================================================
#           Scan Results
#         ============================================================
#           host: 192.168.1.1
#           ports: [22, 80, 443]
#           services: ['ssh', 'http', 'https']
```

### 6. Module-Level Filtering

Module filters are automatically determined from the calling code.

```python
# In session.py
log_info("Session started")  # Logged as module="session"

# With module filter --debug-modules=session
# Only logs from session.py will appear
```

Disable specific modules:

```bash
--debug-modules="!test,!debug"  # Don't log from test or debug modules
```

### 7. Multiple Output Targets

```python
config = LogConfig(enabled=True)
config.output_target = OutputTarget.BOTH  # File + Console

logger = init_debug_logger(config=config)
```

### 8. JSON Structured Logging

```python
config = LogConfig(enabled=True)
config.log_format = LogFormat.JSON

# Logs written as JSON lines:
# {"timestamp": "2025-10-10T14:30:15.123", "level": "INFO", "category": "UI.INPUT", "message": "User pressed 'n'"}
```

---

## Best Practices

### 1. Category Selection

**✓ DO:**
- Use specific categories: `UI.INPUT`, `STATE.TRANSITION`
- Use parent categories during development: `UI`
- Use hierarchical filtering: `UI.*`

**✗ DON'T:**
- Log everything in production
- Mix unrelated events in same category

### 2. Verbosity Levels

**Use MINIMAL for:**
- Errors and critical failures
- Production logging

**Use NORMAL for:**
- Important state changes
- User actions
- Task execution start/end

**Use VERBOSE for:**
- Detailed function execution
- Intermediate calculations
- Resource access

**Use TRACE for:**
- Everything
- Temporary debugging
- Deep troubleshooting

### 3. Message Format

**✓ Good:**
```python
log_info("User selected task", category=LogCategory.UI_INPUT, task_id="scan-tcp-22", action="execute")
```

**✗ Bad:**
```python
log_info("The user clicked on the task with ID scan-tcp-22 and wants to execute it")
```

**Why:** Key-value pairs are easier to parse and filter.

### 4. Performance

**✓ DO:**
- Use decorators for automatic timing
- Enable timing only when needed (`--debug-timing`)
- Use module filters to reduce overhead

**✗ DON'T:**
- Log in tight loops at TRACE level
- Log large data structures without truncation
- Leave TRACE logging enabled in production

### 5. Development Workflow

1. **Start Broad** → `--debug --debug-categories=all`
2. **Identify Area** → `--debug --debug-categories=UI`
3. **Focus Narrow** → `--debug --debug-categories=UI.INPUT:TRACE`
4. **Add Targeted Logs** → Add more logs in problem area
5. **Retest** → Verify fix with same filters
6. **Clean Up** → Remove temporary logs, keep useful ones

---

## Troubleshooting

### No Log Output

**Check:**
1. Is debug enabled? `--debug` or `config.enabled = True`
2. Are categories enabled? `--debug-categories=...`
3. Is level high enough? Try `--debug-level=TRACE`
4. Is module filtered out? Remove module filters to test

### Too Much Output

**Solutions:**
1. Use specific categories: `UI.INPUT` instead of `UI`
2. Increase level threshold: `--debug-level=MINIMAL`
3. Filter by module: `--debug-modules=session`
4. Use compact format: `--debug-format=compact`

### Can't Find Log File

**Check:**
```bash
ls -la .debug_logs/
```

Log files are named: `tui_debug_<target>_<timestamp>.log`

Example: `.debug_logs/tui_debug_192_168_1_1_20251010_143015.log`

### Performance Impact

If logging slows down your application:
1. Reduce level: `--debug-level=NORMAL` or `MINIMAL`
2. Disable timing: Don't use `--debug-timing`
3. Filter modules: `--debug-modules=session`
4. Use file output: `--debug-output=file` (console is slower)

### Module Not Logging

Module detection uses `inspect.getmodule()`. If not working:
1. Check module import structure
2. Verify module name: Look at `__name__` attribute
3. Use explicit filtering: Don't filter by module

---

## Configuration File Format

Create `~/.crack/debug_config.json`:

```json
{
  "enabled": true,
  "global_level": "NORMAL",
  "categories": {
    "UI.INPUT": "VERBOSE",
    "UI.RENDER": "NORMAL",
    "STATE": "VERBOSE",
    "EXECUTION": "NORMAL"
  },
  "modules": ["session", "prompts"],
  "disabled_modules": ["test"],
  "output_target": "file",
  "log_format": "text",
  "buffer_size": 100,
  "include_timing": false
}
```

Load with:
```bash
crack track --tui --debug --debug-config=~/.crack/debug_config.json
```

---

## Environment Variables

Alternative to CLI arguments:

```bash
export CRACK_DEBUG_ENABLED=1
export CRACK_DEBUG_CATEGORIES="UI.INPUT:VERBOSE,STATE:NORMAL"
export CRACK_DEBUG_MODULES="session,prompts"
export CRACK_DEBUG_LEVEL="VERBOSE"
export CRACK_DEBUG_OUTPUT="both"
export CRACK_DEBUG_FORMAT="text"

crack track --tui 192.168.1.1
```

---

## Next Steps

- See [CATEGORY_REFERENCE.md](./CATEGORY_REFERENCE.md) for complete category list
- See [examples/](./examples/) for more code examples
- Check existing TUI code for logging patterns

---

**Happy Debugging!** 🐛🔍
