# Debug Logging Cheatsheet

**Quick reference for CRACK Track precision debug logging**

---

## Quick Start

```bash
# Enable debug logging (basic)
crack track --tui <target> --debug

# Enable with specific categories
crack track --tui <target> --debug --debug-categories=UI:VERBOSE,STATE:VERBOSE

# Output to console (for real-time viewing)
crack track --tui <target> --debug --debug-output=console

# Full verbose with timing
crack track --tui <target> --debug --debug-level=VERBOSE --debug-timing
```

---

## Debug by Problem Type

### UI Freezes / Hangs
```bash
crack track --tui <target> --debug \
  --debug-categories=UI:TRACE,STATE.TRANSITION:VERBOSE \
  --debug-timing
```
**Look for:** Last log entry before freeze shows where execution stopped

### Input Not Working
```bash
crack track --tui <target> --debug \
  --debug-categories=UI.INPUT:TRACE \
  --debug-output=console
```
**Look for:** Input processing logs, invalid input warnings

### Panel Navigation Issues
```bash
crack track --tui <target> --debug \
  --debug-categories=STATE.TRANSITION:VERBOSE,UI.MENU:VERBOSE
```
**Look for:** Panel transition logs, navigation stack updates

### Task Execution Problems
```bash
crack track --tui <target> --debug \
  --debug-categories=EXECUTION:VERBOSE \
  --debug-timing
```
**Look for:** Task start/end logs, exit codes, error messages

### Performance Issues
```bash
crack track --tui <target> --debug \
  --debug-categories=PERFORMANCE:TRACE \
  --debug-timing \
  --debug-output=both
```
**Look for:** Timing information, slow operations

### State Management Issues
```bash
crack track --tui <target> --debug \
  --debug-categories=STATE:TRACE,DATA:VERBOSE
```
**Look for:** State load/save operations, checkpoint logs

---

## Log Categories Reference

### UI Categories
| Category | Use When |
|----------|----------|
| `UI.RENDER` | Panel display issues |
| `UI.INPUT` | Keyboard/input problems |
| `UI.MENU` | Menu generation/display |
| `UI.PANEL` | Panel-specific operations |
| `UI.FORM` | Form field interactions |
| `UI.LIVE` | Live display updates |
| `UI` (parent) | All UI operations |

### State Categories
| Category | Use When |
|----------|----------|
| `STATE.TRANSITION` | Panel navigation issues |
| `STATE.CHECKPOINT` | Checkpoint save/restore |
| `STATE.LOAD` | Profile loading problems |
| `STATE.SAVE` | Profile saving issues |
| `STATE` (parent) | All state operations |

### Execution Categories
| Category | Use When |
|----------|----------|
| `EXECUTION.START` | Task won't start |
| `EXECUTION.OUTPUT` | Output not showing |
| `EXECUTION.END` | Task won't complete |
| `EXECUTION.ERROR` | Execution failures |
| `EXECUTION` (parent) | All task execution |

### Other Categories
| Category | Use When |
|----------|----------|
| `DATA.*` | Parsing/validation issues |
| `NETWORK.*` | Network operations |
| `PERFORMANCE.*` | Performance analysis |
| `SYSTEM.*` | Initialization/shutdown |

---

## Verbosity Levels

| Level | Use When | Output |
|-------|----------|--------|
| `MINIMAL` | Production | Errors only |
| `NORMAL` | Default debugging | Standard info |
| `VERBOSE` | Detailed debugging | Extra details |
| `TRACE` | Deep debugging | Everything |

---

## Output Targets

```bash
# File only (default)
--debug-output=file

# Console only (real-time viewing)
--debug-output=console

# Both file and console
--debug-output=both

# JSON format (for parsing)
--debug-output=json
```

---

## Common Combinations

### General Panel Development
```bash
crack track --tui <target> --debug \
  --debug-categories=UI:VERBOSE,STATE:VERBOSE \
  --debug-output=both
```

### Debugging Specific Panel
```bash
crack track --tui <target> --debug \
  --debug-modules=findings_panel \
  --debug-level=TRACE \
  --debug-output=console
```

### Production Troubleshooting
```bash
crack track --tui <target> --debug \
  --debug-level=MINIMAL \
  --debug-categories=EXECUTION.ERROR:NORMAL,STATE.TRANSITION:NORMAL
```

### Full Diagnostic Dump
```bash
crack track --tui <target> --debug \
  --debug-level=TRACE \
  --debug-categories=all \
  --debug-timing \
  --debug-output=both
```

---

## Log File Commands

### View Logs
```bash
# Latest log file
cat .debug_logs/tui_debug_<target>_*.log

# Real-time viewing
tail -f .debug_logs/tui_debug_<target>_*.log

# View all logs for target
cat .debug_logs/tui_debug_<target>_*.log | less
```

### Filter Logs
```bash
# By category
grep "\[UI.INPUT\]" .debug_logs/tui_debug_*.log

# Errors only
grep "\[ERROR\]" .debug_logs/tui_debug_*.log

# Warnings and errors
grep "\[ERROR\]\|\[WARNING\]" .debug_logs/tui_debug_*.log

# Specific panel
grep "findings_panel" .debug_logs/tui_debug_*.log

# State transitions
grep "\[STATE.TRANSITION\]" .debug_logs/tui_debug_*.log

# With context (5 lines before/after)
grep -C 5 "ERROR" .debug_logs/tui_debug_*.log
```

### Analyze Logs
```bash
# Count errors
grep -c "\[ERROR\]" .debug_logs/tui_debug_*.log

# Count by category
grep -o "\[UI\.[A-Z]*\]" .debug_logs/tui_debug_*.log | sort | uniq -c

# Find last entry before crash
tail -20 .debug_logs/tui_debug_*.log

# Performance analysis (with --debug-timing)
grep "elapsed=" .debug_logs/tui_debug_*.log | awk '{print $NF}'

# Find slow operations (>1 second)
grep "elapsed=" .debug_logs/tui_debug_*.log | awk -F'=' '$2 > 1.0'
```

---

## Configuration File

Create `~/.crack/debug_config.json`:

```json
{
  "enabled": true,
  "global_level": "VERBOSE",
  "categories": {
    "UI.INPUT": "TRACE",
    "UI.RENDER": "NORMAL",
    "STATE.TRANSITION": "VERBOSE",
    "EXECUTION": "NORMAL"
  },
  "modules": ["findings_panel", "dashboard_panel"],
  "output_target": "both",
  "log_format": "text",
  "include_timing": true
}
```

Use it:
```bash
crack track --tui <target> --debug --debug-config=~/.crack/debug_config.json
```

---

## In-Code Logging

### Import
```python
from ..debug_logger import get_debug_logger
from ..log_types import LogCategory, LogLevel
```

### Initialization
```python
def __init__(self, session):
    self.debug_logger = session.debug_logger

    self.debug_logger.log("Panel initialized",
                         category=LogCategory.SYSTEM_INIT,
                         level=LogLevel.INFO,
                         panel_name=self.__class__.__name__)
```

### Common Patterns
```python
# Input processing
self.debug_logger.log("Processing input",
                     category=LogCategory.UI_INPUT,
                     level=LogLevel.TRACE,
                     input=user_input)

# Panel rendering
self.debug_logger.log("Rendering panel",
                     category=LogCategory.UI_RENDER,
                     level=LogLevel.DEBUG,
                     panel_state=self.current_state)

# State transition
self.debug_logger.log("State changed",
                     category=LogCategory.STATE_TRANSITION,
                     level=LogLevel.INFO,
                     from_state=old_state,
                     to_state=new_state)

# Error
self.debug_logger.log("Operation failed",
                     category=LogCategory.EXECUTION_ERROR,
                     level=LogLevel.ERROR,
                     error=str(e),
                     error_type=type(e).__name__)
```

---

## Troubleshooting Workflow

1. **Enable comprehensive logging**
   ```bash
   crack track --tui <target> --debug \
     --debug-categories=UI:VERBOSE,STATE:VERBOSE,EXECUTION:VERBOSE \
     --debug-timing
   ```

2. **Reproduce the issue**
   - Note exact steps
   - Note when freeze/crash occurs

3. **Analyze logs**
   ```bash
   # Find last entry
   tail -20 .debug_logs/tui_debug_<target>_*.log

   # Find errors
   grep "\[ERROR\]" .debug_logs/tui_debug_<target>_*.log

   # Track state transitions
   grep "\[STATE.TRANSITION\]" .debug_logs/tui_debug_<target>_*.log
   ```

4. **Identify root cause**
   - Last log entry before freeze = failure point
   - Error logs = exception details
   - State transitions = navigation path

5. **Fix and retest**
   - Add more logging if needed
   - Verify fix with same debug flags

---

## Environment Variables

```bash
# Alternative to CLI flags
export CRACK_DEBUG_ENABLED=1
export CRACK_DEBUG_CATEGORIES="UI:VERBOSE,STATE:VERBOSE"
export CRACK_DEBUG_MODULES="findings_panel"
export CRACK_DEBUG_LEVEL="VERBOSE"
export CRACK_DEBUG_OUTPUT="console"
export CRACK_DEBUG_FORMAT="text"

crack track --tui <target>
```

---

## Quick Tips

✅ **DO:**
- Start with `UI:VERBOSE,STATE:VERBOSE` for general debugging
- Use `--debug-output=console` for real-time feedback
- Enable `--debug-timing` for performance issues
- Filter logs with grep for specific categories
- Keep debug config file for common scenarios

❌ **DON'T:**
- Use `TRACE` level unless necessary (too verbose)
- Log in tight loops without throttling
- Forget to check logs when issues occur
- Leave debug logging enabled in production
- Log sensitive data (passwords, tokens)

---

## See Also

- **Full Guide**: `track/docs/PANEL_DEVELOPER_GUIDE.md` (Section 7)
- **Integration Summary**: `PRECISION_DEBUG_INTEGRATION_SUMMARY.md`
- **Log Config Tests**: `tests/track/interactive/test_log_config.py`

---

**Last Updated:** 2025-10-10
