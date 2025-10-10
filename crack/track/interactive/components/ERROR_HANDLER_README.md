# Error Handler Component - Complete Guide

## Overview

The **ErrorHandler** is a standalone TUI component that provides clear, actionable error messages with recovery suggestions. It automatically categorizes errors, detects OSCP-specific patterns, and displays formatted error panels using Rich.

**Status**: Production Ready (39/39 tests passing)

**File**: `/home/kali/OSCP/crack/track/interactive/components/error_handler.py`

---

## Features

### 1. Automatic Error Categorization

Maps Python exceptions to error types:

```python
handler = ErrorHandler()

# Automatically categorizes to ErrorType.FILE
try:
    open('/nonexistent/file.txt')
except Exception as e:
    error_type = handler.categorize_error(e)  # -> ErrorType.FILE
```

**Error Types**:
- `FILE` - File I/O errors (FileNotFoundError, IsADirectoryError, etc.)
- `PERMISSION` - Permission denied errors (PermissionError, errno 13)
- `NETWORK` - Network connectivity issues (ConnectionError, TimeoutError)
- `EXECUTION` - Command execution failures (subprocess errors)
- `CONFIG` - Configuration errors (JSON parsing, missing keys)
- `INPUT` - User input validation errors (ValueError, TypeError)

### 2. OSCP-Specific Error Patterns

Detects common OSCP exam errors and provides targeted suggestions:

**Pattern: nmap not found**
```python
handler.show_error(
    ErrorType.EXECUTION,
    "nmap: command not found"
)
# Suggests: sudo apt install nmap, check PATH, notes OSCP pre-install
```

**Pattern: VPN connection lost**
```python
handler.show_error(
    ErrorType.NETWORK,
    "Network is unreachable: no route to host"
)
# Suggests: ifconfig tun0, check OVPN connection, verify subnet
```

**Pattern: Raw socket permission**
```python
handler.show_error(
    ErrorType.PERMISSION,
    "raw socket operation not permitted"
)
# Suggests: sudo usage, notes OSCP scan tool requirements
```

**Pattern: Wordlist not found**
```python
handler.show_error(
    ErrorType.FILE,
    "/usr/share/wordlists/rockyou.txt not found"
)
# Suggests: extract rockyou.txt.gz, check /usr/share/wordlists/
```

**Pattern: Timeout**
```python
handler.show_error(
    ErrorType.NETWORK,
    "Operation timed out"
)
# Suggests: increase timeout (-T flag), OSCP slow services (-T2)
```

### 3. Context-Aware Suggestions

Generates actionable recovery steps based on error type and message content:

```python
# FILE error with "config.json" -> suggests crack track --init
# PERMISSION error -> suggests chmod/sudo
# NETWORK error -> suggests ping/traceroute/VPN check
# EXECUTION error with "command not found" -> suggests apt install
```

### 4. Rich Panel Formatting

Displays errors with color-coded severity and structured layout:

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ ERROR ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ 📁 FILE ERROR                                                    ┃
┃ ──────────────────────────────────────────────────────────────── ┃
┃                                                                   ┃
┃ Error Details:                                                    ┃
┃   Config file not found: /home/kali/.crack/config.json          ┃
┃                                                                   ┃
┃ Suggested Fixes:                                                  ┃
┃   1. Check if file exists: ls -la ~/.crack/config.json          ┃
┃   2. Initialize config: crack track --init                       ┃
┃   3. Verify file permissions: chmod 644 ~/.crack/config.json    ┃
┃                                                                   ┃
┃ Press Enter to continue...                                        ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

### 5. Error History Tracking

Keeps last N errors (configurable, default 10):

```python
handler = ErrorHandler(max_history=5)

# Generate errors...
handler.show_error(ErrorType.FILE, "Error 1")
handler.show_error(ErrorType.NETWORK, "Error 2")

# Retrieve history
history = handler.get_error_history()
for error in history:
    print(f"[{error['type']}] {error['message']}")
```

### 6. Debug Logger Integration

Automatically logs to debug logger if provided:

```python
from track.interactive.debug_logger import init_debug_logger

debug_logger = init_debug_logger(debug_enabled=True, target="192.168.45.100")
handler = ErrorHandler(debug_logger=debug_logger)

# All errors automatically logged to .debug_logs/
handler.show_error(ErrorType.FILE, "test")
# Logs: "[ERROR] FILE error: test | suggestions_count=3"
```

---

## Usage Patterns

### Pattern 1: Simple Error Display

```python
from crack.track.interactive.components import ErrorHandler, ErrorType

handler = ErrorHandler()

handler.show_error(
    ErrorType.FILE,
    "Config not found",
    ["Run 'crack track --init'", "Check file path"]
)
```

### Pattern 2: Auto-Categorization

```python
handler = ErrorHandler()

try:
    open('/etc/shadow', 'w')
except Exception as e:
    error_type = handler.categorize_error(e)  # -> ErrorType.PERMISSION
    handler.show_error(error_type, str(e))
```

### Pattern 3: Complete Exception Handling

```python
handler = ErrorHandler()

try:
    run_nmap(target)
except Exception as e:
    handler.handle_exception(e, context="nmap scan")
    # Automatically categorizes, logs, and displays with suggestions
```

### Pattern 4: Custom Suggestions

```python
handler = ErrorHandler()

try:
    dangerous_operation()
except Exception as e:
    handler.handle_exception(
        e,
        context="privilege escalation",
        custom_suggestions=[
            "Verify file permissions: ls -la /etc/shadow",
            "Try alternative method: exploit DB",
            "OSCP: Check for SUID binaries: find / -perm -4000 2>/dev/null"
        ]
    )
```

### Pattern 5: CommonErrors Helpers

```python
from crack.track.interactive.components import ErrorHandler, CommonErrors

handler = ErrorHandler()

# Pre-defined helpers for typical scenarios
CommonErrors.file_not_found(handler, "/etc/test.conf")
CommonErrors.permission_denied(handler, "/etc/shadow")
CommonErrors.config_corrupted(handler)
CommonErrors.network_unreachable(handler, "192.168.45.100")
CommonErrors.command_not_found(handler, "gobuster")
```

---

## Integration with TUI Session

### Example: Task Execution Error Handling

```python
from crack.track.interactive.components import ErrorHandler
from crack.track.interactive.debug_logger import get_debug_logger

class TUISessionV2:
    def __init__(self, target: str, debug: bool = False):
        self.debug_logger = get_debug_logger()
        self.error_handler = ErrorHandler(
            debug_logger=self.debug_logger,
            max_history=10
        )

    def _execute_task(self, task):
        try:
            # Execute task command
            result = subprocess.run(
                task.metadata['command'],
                shell=True,
                capture_output=True,
                timeout=300
            )

            if result.returncode != 0:
                raise subprocess.CalledProcessError(
                    result.returncode,
                    task.metadata['command'],
                    output=result.stdout
                )

        except subprocess.TimeoutExpired as e:
            # Auto-categorizes to NETWORK, suggests timeout flags
            self.error_handler.handle_exception(
                e,
                context=f"executing task: {task.name}"
            )

        except PermissionError as e:
            # Auto-categorizes to PERMISSION, suggests sudo
            self.error_handler.handle_exception(
                e,
                context=f"executing task: {task.name}"
            )

        except Exception as e:
            # Generic error handling
            self.error_handler.handle_exception(
                e,
                context=f"executing task: {task.name}"
            )
```

---

## API Reference

### ErrorHandler Class

#### Constructor

```python
ErrorHandler(
    debug_logger=None,        # Optional TUIDebugLogger instance
    console: Console = None,  # Optional Rich Console (creates if None)
    max_history: int = 10     # Maximum error history size
)
```

#### Methods

**categorize_error(exception: Exception) -> ErrorType**
- Auto-detect error category from exception type and message
- Returns: ErrorType enum

**get_suggestions(error_type: ErrorType, message: str = "") -> List[str]**
- Get context-aware recovery suggestions
- Checks OSCP patterns first, falls back to generic suggestions
- Returns: List of actionable suggestion strings

**show_error(error_type: ErrorType, message: str, suggestions: List[str] = None)**
- Display formatted error panel in TUI
- Auto-generates suggestions if None provided
- Adds to error history
- Logs to debug logger if available

**handle_exception(exception: Exception, context: str = "", custom_suggestions: List[str] = None)**
- Complete exception handling workflow
- Categorizes, logs, and displays error with suggestions
- Includes context in error message

**log_error(error: Exception, context: str = "")**
- Log error to debug log without displaying
- Useful for silent logging

**get_error_history() -> List[Dict[str, Any]]**
- Retrieve error history (most recent first)
- Returns: List of error dictionaries

**clear_error_history()**
- Clear all error history

**format_error_panel(error_type: ErrorType, message: str, suggestions: List[str]) -> Panel**
- Create Rich Panel for error display
- Returns: Rich Panel instance

---

## Testing

### Run Tests

```bash
# All tests
python3 -m pytest tests/interactive/test_error_handler.py -v

# Specific test class
python3 -m pytest tests/interactive/test_error_handler.py::TestErrorCategorization -v

# With coverage
python3 -m pytest tests/interactive/test_error_handler.py --cov=track.interactive.components.error_handler
```

**Test Coverage**: 39/39 tests passing (100%)

### Test Categories

1. **Error Categorization** (12 tests)
   - File, permission, network, config, input, execution errors
   - OSError special cases
   - subprocess errors
   - Unknown exceptions

2. **OSCP Patterns** (5 tests)
   - nmap, permission, network, timeout, wordlist patterns

3. **Suggestion Generation** (6 tests)
   - File, permission, network, config, input, execution suggestions

4. **Error History** (3 tests)
   - Add entry, respect max_history, clear history

5. **CommonErrors Helpers** (5 tests)
   - file_not_found, permission_denied, config_corrupted, network_unreachable, command_not_found

6. **Exception Handling** (3 tests)
   - Auto-categorization, context inclusion, custom suggestions

7. **Debug Logger Integration** (2 tests)
   - Logging to debug logger, log_error method

8. **Error Display** (3 tests)
   - Panel formatting, custom/auto-generated suggestions

---

## Demo Scripts

### Quick Demo (30 seconds)

```bash
cd /home/kali/OSCP/crack/track/interactive/components
python3 error_handler_quickdemo.py
```

Shows:
- Auto-categorization
- OSCP patterns
- CommonErrors helpers
- Error history

### Full Interactive Demo

```bash
cd /home/kali/OSCP/crack/track/interactive/components
python3 error_handler_demo.py
```

Interactive menu with 9 demos:
1. File not found
2. Permission denied
3. Network unreachable
4. OSCP nmap error
5. OSCP raw socket permission
6. OSCP VPN connection
7. CommonErrors helpers
8. Error history tracking
9. Auto-categorization

---

## Design Decisions

### 1. Standalone Component
- **NOT** integrated into main TUI session
- Can be used independently in any Python script
- No dependencies on TUI session state

### 2. OSCP-First Design
- Pattern detection prioritizes OSCP exam scenarios
- Suggestions reference common Kali tools and paths
- VPN connectivity checks emphasized

### 3. Rich Formatting
- Uses Rich Panel for consistent TUI appearance
- Color-coded severity (red for critical, yellow for warnings)
- Emojis for quick error type recognition

### 4. Error History FIFO
- Keeps last N errors (configurable)
- Automatically trims to max_history
- Useful for debugging repeated failures

### 5. Exception Hierarchy Awareness
- TimeoutError and ConnectionError checked before OSError
- OSError inspected for errno to distinguish permission/file errors
- subprocess errors mapped to EXECUTION type

---

## Future Enhancements

Potential additions (NOT implemented):

1. **Error Metrics**
   - Track error frequency by type
   - Identify most common error patterns
   - Report generation

2. **Remediation Automation**
   - Execute suggested fixes automatically
   - Prompt user before running commands
   - Log remediation attempts

3. **Multi-Language Suggestions**
   - Detect system language
   - Provide suggestions in multiple languages

4. **Interactive Recovery**
   - Let user select suggestion to execute
   - Show command output inline
   - Chain multiple recovery steps

5. **Error Correlation**
   - Link related errors (e.g., VPN -> network unreachable)
   - Suggest root cause analysis
   - Dependency graph visualization

---

## Troubleshooting

### Issue: Suggestions not OSCP-specific

**Cause**: Error message doesn't match OSCP patterns

**Solution**:
```python
# Check pattern keywords
handler = ErrorHandler()
message = "your error message"
for pattern_name, pattern_info in handler.OSCP_PATTERNS.items():
    if any(kw in message.lower() for kw in pattern_info['keywords']):
        print(f"Matched: {pattern_name}")
```

### Issue: Error history growing unbounded

**Cause**: max_history not set or too large

**Solution**:
```python
# Set explicit limit
handler = ErrorHandler(max_history=5)

# Or clear periodically
handler.clear_error_history()
```

### Issue: Errors not logged to debug file

**Cause**: debug_logger not provided or debug mode disabled

**Solution**:
```python
from track.interactive.debug_logger import init_debug_logger

debug_logger = init_debug_logger(debug_enabled=True, target="192.168.45.100")
handler = ErrorHandler(debug_logger=debug_logger)
```

---

## Files

- **Component**: `track/interactive/components/error_handler.py` (429 lines)
- **Tests**: `tests/interactive/test_error_handler.py` (39 tests)
- **Quick Demo**: `track/interactive/components/error_handler_quickdemo.py`
- **Full Demo**: `track/interactive/components/error_handler_demo.py`
- **README**: `track/interactive/components/ERROR_HANDLER_README.md` (this file)

---

## Summary

The ErrorHandler component provides production-ready error handling for the CRACK Track TUI with:

- **Automatic categorization** of 6 error types
- **5 OSCP-specific patterns** with targeted suggestions
- **Rich Panel formatting** with color-coded severity
- **Error history tracking** (configurable FIFO)
- **Debug logger integration** for troubleshooting
- **CommonErrors helpers** for typical scenarios
- **39/39 tests passing** (100% coverage)

Use it anywhere in the TUI for clear, actionable error messages that help users recover quickly during OSCP enumeration workflows.
