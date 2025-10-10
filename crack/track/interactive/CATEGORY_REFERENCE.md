# Log Category Reference

Complete reference of all available log categories in the precision debug logging system.

## Category Hierarchy

```
UI
├── UI.RENDER
├── UI.INPUT
├── UI.MENU
├── UI.PANEL
├── UI.FORM
└── UI.LIVE

STATE
├── STATE.TRANSITION
├── STATE.CHECKPOINT
├── STATE.LOAD
└── STATE.SAVE

EXECUTION
├── EXECUTION.START
├── EXECUTION.OUTPUT
├── EXECUTION.END
└── EXECUTION.ERROR

DATA
├── DATA.PARSE
├── DATA.VALIDATION
└── DATA.TRANSFORMATION

NETWORK
├── NETWORK.REQUEST
├── NETWORK.RESPONSE
└── NETWORK.ERROR

PERFORMANCE
├── PERFORMANCE.TIMING
└── PERFORMANCE.MEMORY

SYSTEM
├── SYSTEM.INIT
├── SYSTEM.SHUTDOWN
└── SYSTEM.ERROR
```

---

## UI Categories

### UI
**Parent category for all user interface events**

**When to use:** Enable all UI logging during UI development

**Example:**
```bash
--debug-categories=UI:VERBOSE
```

### UI.RENDER
**Screen rendering and display updates**

**Logs when:**
- Screen is refreshed
- Components are rendered
- Layout calculations occur
- Display state changes

**Common log messages:**
- "RENDER: main menu | details=5 choices"
- "RENDER: task panel | items=42"
- "RENDER: progress bar | percentage=75"

**Use for:**
- Debugging display issues
- Tracking render performance
- Understanding screen update flow

**Example:**
```python
logger.log_render("main menu", details="5 choices")
```

### UI.INPUT
**User input handling and keyboard events**

**Logs when:**
- Key is pressed
- Input is received
- Input is processed
- Input validation occurs

**Common log messages:**
- "USER INPUT: 'n' | context=main menu"
- "USER INPUT: 'q' | context=task details"
- "INPUT: hotkey pressed | key=e | action=execute"

**Use for:**
- Debugging input handling
- Understanding user action flow
- Tracking keyboard shortcuts

**Example:**
```python
logger.log_user_input("n", context="main menu")
```

### UI.MENU
**Menu generation and navigation**

**Logs when:**
- Menu is built
- Menu choices are calculated
- Navigation occurs
- Menu state changes

**Common log messages:**
- "MENU: task selection | choices=10"
- "MENU: context menu | items=5 | context=service details"
- "MENU: navigation | from=main | to=tasks"

**Use for:**
- Debugging menu generation
- Understanding navigation flow
- Tracking menu state

**Example:**
```python
logger.log_menu("task selection", choices=10)
```

### UI.PANEL
**Panel management and updates**

**Logs when:**
- Panel is created
- Panel content updates
- Panel is shown/hidden
- Panel layout changes

**Common log messages:**
- "PANEL: create | panel=task_list"
- "PANEL: update | panel=findings | items=3"
- "PANEL: show | panel=credentials"
- "PANEL: hide | panel=notes"

**Use for:**
- Debugging panel behavior
- Understanding panel lifecycle
- Tracking panel state changes

### UI.FORM
**Form rendering and data entry**

**Logs when:**
- Form is rendered
- Field is validated
- Form is submitted
- Form errors occur

**Common log messages:**
- "FORM: render | form=credential_form | fields=5"
- "FORM: validate | field=username | valid=true"
- "FORM: submit | form=finding_form | success=true"

**Use for:**
- Debugging form issues
- Understanding validation flow
- Tracking form submissions

### UI.LIVE
**Rich Live display management**

**Logs when:**
- Live display starts
- Live display updates
- Live display stops
- Live display errors

**Common log messages:**
- "LIVE DISPLAY: start | component=task_execution"
- "LIVE DISPLAY: update | component=progress | status=running"
- "LIVE DISPLAY: stop | component=task_execution"

**Use for:**
- Debugging Live display issues
- Understanding update frequency
- Tracking display lifecycle

**Example:**
```python
logger.log_live_action("start", details="task execution")
```

---

## STATE Categories

### STATE
**Parent category for all state management events**

**When to use:** Debug state machine issues

**Example:**
```bash
--debug-categories=STATE:VERBOSE
```

### STATE.TRANSITION
**State machine transitions**

**Logs when:**
- State changes occur
- State machine processes events
- State validation happens
- Invalid transitions attempted

**Common log messages:**
- "STATE TRANSITION: IDLE → EXECUTING | reason=user selected task"
- "STATE TRANSITION: EXECUTING → COMPLETED | reason=task finished"
- "STATE TRANSITION: VIEWING → EDITING | reason=user pressed 'e'"

**Use for:**
- Debugging state machine behavior
- Understanding application flow
- Tracking state history

**Example:**
```python
logger.log_state_transition("IDLE", "EXECUTING", reason="user selected task")
```

### STATE.CHECKPOINT
**Save/restore operations**

**Logs when:**
- Profile is saved
- Checkpoint is created
- Auto-save occurs
- Save errors happen

**Common log messages:**
- "CHECKPOINT: save | details=profile saved to disk"
- "CHECKPOINT: auto-save | interval=60s"
- "CHECKPOINT: save error | reason=permission denied"

**Use for:**
- Debugging save issues
- Understanding checkpoint timing
- Tracking data persistence

**Example:**
```python
logger.log_checkpoint("save", details="profile saved to disk")
```

### STATE.LOAD
**Profile and state loading**

**Logs when:**
- Profile is loaded
- State is restored
- Load errors occur
- Migration happens

**Common log messages:**
- "STATE: load profile | target=192.168.1.1 | success=true"
- "STATE: restore checkpoint | timestamp=2025-10-10T14:30:00"
- "STATE: load error | reason=file not found"

**Use for:**
- Debugging load failures
- Understanding state restoration
- Tracking migrations

### STATE.SAVE
**Explicit save operations**

**Logs when:**
- User initiates save
- Explicit save completes
- Save validation occurs

**Common log messages:**
- "STATE: save initiated | source=user"
- "STATE: save complete | duration=0.05s"

**Use for:**
- Distinguishing from auto-save
- Tracking user-initiated saves

---

## EXECUTION Categories

### EXECUTION
**Parent category for task/command execution**

**When to use:** Debug task execution issues

**Example:**
```bash
--debug-categories=EXECUTION:VERBOSE
```

### EXECUTION.START
**Task and command execution start**

**Logs when:**
- Task starts executing
- Command is launched
- Process begins
- Resources allocated

**Common log messages:**
- "TASK EXECUTION START: nmap scan | task_id=scan-tcp-22"
- "EXECUTION: start command | cmd=nmap -p22 192.168.1.1"
- "EXECUTION: start alternative | alt=manual_telnet_22"

**Use for:**
- Verifying tasks start
- Understanding execution sequence
- Tracking resource allocation

**Example:**
```python
logger.log_execution_start("nmap scan", task_id="scan-tcp-22")
```

### EXECUTION.OUTPUT
**Command output streaming**

**Logs when:**
- Process produces output
- Output is captured
- Output is processed
- Streaming occurs

**Common log messages:**
- "EXECUTION: output received | bytes=1024"
- "EXECUTION: stdout | lines=42"
- "EXECUTION: stderr | warning detected"

**Use for:**
- Debugging output capture
- Understanding output flow
- Tracking streaming behavior

### EXECUTION.END
**Task and command completion**

**Logs when:**
- Task completes
- Command exits
- Process terminates
- Results are returned

**Common log messages:**
- "TASK EXECUTION END: nmap scan | status=SUCCESS | exit_code=0"
- "EXECUTION: complete | duration=5.2s | success=true"
- "EXECUTION: failed | exit_code=1 | reason=timeout"

**Use for:**
- Verifying completion
- Tracking success/failure
- Understanding execution time

**Example:**
```python
logger.log_execution_end("nmap scan", success=True, exit_code=0)
```

### EXECUTION.ERROR
**Execution failures and errors**

**Logs when:**
- Command fails
- Process crashes
- Timeout occurs
- Resource errors happen

**Common log messages:**
- "EXECUTION: error | command=nmap | reason=timeout after 30s"
- "EXECUTION: failed | exit_code=127 | reason=command not found"
- "EXECUTION: crashed | signal=SIGKILL"

**Use for:**
- Debugging execution failures
- Understanding error conditions
- Tracking failure patterns

---

## DATA Categories

### DATA
**Parent category for data processing**

**When to use:** Debug parsing and validation

**Example:**
```bash
--debug-categories=DATA:VERBOSE
```

### DATA.PARSE
**Data parsing operations**

**Logs when:**
- Files are parsed
- Data is extracted
- Format conversion occurs
- Parsing completes

**Common log messages:**
- "PARSE: nmap | items=42 | duration=0.15s"
- "PARSE: json | records=128"
- "PARSE: error | format=xml | reason=invalid syntax"

**Use for:**
- Debugging parsing issues
- Understanding data flow
- Tracking parse performance

**Example:**
```python
logger.log_parse("nmap", items=42, details="parsed 42 ports")
```

### DATA.VALIDATION
**Input and data validation**

**Logs when:**
- Input is validated
- Constraints are checked
- Validation passes/fails
- Sanitization occurs

**Common log messages:**
- "VALIDATION: port | status=VALID | value=22"
- "VALIDATION: ip_address | status=INVALID | reason=malformed"
- "VALIDATION: field | field=username | valid=true"

**Use for:**
- Debugging validation logic
- Understanding validation rules
- Tracking invalid inputs

**Example:**
```python
logger.log_validation("port", valid=True)
```

### DATA.TRANSFORMATION
**Data transformation operations**

**Logs when:**
- Data is converted
- Format changes
- Enrichment occurs
- Aggregation happens

**Common log messages:**
- "TRANSFORMATION: normalize | records=100"
- "TRANSFORMATION: enrich | added_fields=5"
- "TRANSFORMATION: aggregate | groups=10"

**Use for:**
- Debugging transformations
- Understanding data pipeline
- Tracking data changes

---

## NETWORK Categories

### NETWORK
**Parent category for network operations**

**When to use:** Debug network communication

**Example:**
```bash
--debug-categories=NETWORK:VERBOSE
```

### NETWORK.REQUEST
**Network requests**

**Logs when:**
- HTTP request is made
- Socket connects
- Request is sent
- Request completes

**Common log messages:**
- "NETWORK: request | url=http://192.168.1.1 | method=GET"
- "NETWORK: connect | host=192.168.1.1 | port=80"
- "NETWORK: send | bytes=512"

**Use for:**
- Debugging network issues
- Understanding request flow
- Tracking network activity

### NETWORK.RESPONSE
**Network responses**

**Logs when:**
- Response received
- Data downloaded
- Response parsed
- Response completes

**Common log messages:**
- "NETWORK: response | status=200 | size=4096"
- "NETWORK: download | bytes=102400 | duration=1.5s"
- "NETWORK: headers | count=12"

**Use for:**
- Debugging response issues
- Understanding response data
- Tracking download progress

### NETWORK.ERROR
**Network failures**

**Logs when:**
- Connection fails
- Timeout occurs
- Network error happens
- Retry needed

**Common log messages:**
- "NETWORK: error | reason=connection refused"
- "NETWORK: timeout | duration=30s"
- "NETWORK: retry | attempt=2 | max=3"

**Use for:**
- Debugging connection issues
- Understanding failure modes
- Tracking retry behavior

---

## PERFORMANCE Categories

### PERFORMANCE
**Parent category for performance tracking**

**When to use:** Track performance metrics

**Example:**
```bash
--debug-categories=PERFORMANCE --debug-timing
```

### PERFORMANCE.TIMING
**Execution timing measurements**

**Logs when:**
- Timer starts
- Timer ends
- Duration calculated
- Timing tracked

**Common log messages:**
- "TIMER START: parse_nmap_file"
- "TIMER END: parse_nmap_file | duration=0.125s"
- "TIMING: function=render_menu | duration=0.003s"

**Use for:**
- Identifying bottlenecks
- Measuring performance
- Tracking execution time

**Example:**
```python
with log_timing("Parse Nmap XML"):
    parse_file()
```

### PERFORMANCE.MEMORY
**Memory usage tracking**

**Logs when:**
- Memory allocated
- Memory released
- Memory usage checked
- Memory limits approached

**Common log messages:**
- "MEMORY: allocate | size=1024KB"
- "MEMORY: current | usage=45MB"
- "MEMORY: warning | usage approaching limit"

**Use for:**
- Debugging memory leaks
- Understanding memory usage
- Tracking resource consumption

---

## SYSTEM Categories

### SYSTEM
**Parent category for system-level events**

**When to use:** Debug initialization/shutdown

**Example:**
```bash
--debug-categories=SYSTEM:NORMAL
```

### SYSTEM.INIT
**System initialization**

**Logs when:**
- Application starts
- Components initialize
- Resources load
- Setup completes

**Common log messages:**
- "SYSTEM: init | version=1.0.0"
- "SYSTEM: load config | path=~/.crack/config.json"
- "SYSTEM: initialize components | count=5"

**Use for:**
- Debugging startup issues
- Understanding init sequence
- Tracking resource loading

### SYSTEM.SHUTDOWN
**System shutdown**

**Logs when:**
- Application exits
- Cleanup occurs
- Resources released
- Shutdown completes

**Common log messages:**
- "SYSTEM: shutdown initiated"
- "SYSTEM: cleanup | resources released"
- "SYSTEM: exit | code=0"

**Use for:**
- Debugging shutdown issues
- Ensuring clean exit
- Tracking cleanup

### SYSTEM.ERROR
**System-level errors**

**Logs when:**
- Critical errors occur
- System failures happen
- Recovery attempted
- Fatal errors

**Common log messages:**
- "SYSTEM: critical error | reason=out of memory"
- "SYSTEM: fatal | reason=unrecoverable error"
- "SYSTEM: recovery attempt | action=restart component"

**Use for:**
- Debugging critical failures
- Understanding system errors
- Tracking recovery

---

## Category Selection Guide

### By Development Phase

**Initial Development:**
```bash
--debug-categories=all --debug-level=VERBOSE
```

**UI Development:**
```bash
--debug-categories=UI:VERBOSE
```

**State Machine Development:**
```bash
--debug-categories=STATE:TRACE
```

**Execution Engine:**
```bash
--debug-categories=EXECUTION:VERBOSE
```

### By Issue Type

**UI Freezes:**
```bash
--debug-categories=UI.INPUT:TRACE,UI.RENDER:VERBOSE,STATE.TRANSITION:VERBOSE
```

**State Issues:**
```bash
--debug-categories=STATE:TRACE
```

**Task Execution Failures:**
```bash
--debug-categories=EXECUTION:VERBOSE,DATA.PARSE:VERBOSE
```

**Performance Problems:**
```bash
--debug-categories=PERFORMANCE --debug-timing
```

**Network Issues:**
```bash
--debug-categories=NETWORK:VERBOSE
```

### By Verbosity Needs

**Minimal (Production):**
```bash
--debug-categories=SYSTEM,EXECUTION.ERROR --debug-level=MINIMAL
```

**Normal (Development):**
```bash
--debug-categories=UI,STATE,EXECUTION --debug-level=NORMAL
```

**Verbose (Debugging):**
```bash
--debug-categories=UI,STATE --debug-level=VERBOSE
```

**Trace (Deep Debugging):**
```bash
--debug-categories=UI.INPUT:TRACE,STATE:TRACE
```

---

## Quick Reference Table

| Category | Use For | Common Issues | Recommended Level |
|----------|---------|---------------|-------------------|
| UI.RENDER | Display issues | Screen not updating | VERBOSE |
| UI.INPUT | Input problems | Keys not working | TRACE |
| UI.MENU | Menu bugs | Wrong choices shown | VERBOSE |
| STATE.TRANSITION | State bugs | Wrong state reached | TRACE |
| STATE.CHECKPOINT | Save issues | Data not persisting | NORMAL |
| EXECUTION.START | Task not starting | Nothing happens | NORMAL |
| EXECUTION.END | Task not completing | Hangs forever | NORMAL |
| EXECUTION.ERROR | Task failures | Exit code errors | MINIMAL |
| DATA.PARSE | Parsing failures | Can't read file | VERBOSE |
| DATA.VALIDATION | Invalid data | Wrong data accepted | VERBOSE |
| NETWORK.REQUEST | Connection issues | Can't connect | VERBOSE |
| NETWORK.ERROR | Network failures | Timeouts | NORMAL |
| PERFORMANCE.TIMING | Slow performance | What's slow? | TRACE |
| SYSTEM.ERROR | Critical failures | App crashes | MINIMAL |

---

## See Also

- [DEBUG_LOGGING_GUIDE.md](./DEBUG_LOGGING_GUIDE.md) - Complete usage guide
- [debug_logger.py](./debug_logger.py) - Implementation
- [log_types.py](./log_types.py) - Category definitions
