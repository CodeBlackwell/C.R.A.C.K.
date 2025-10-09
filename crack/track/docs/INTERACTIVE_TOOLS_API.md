# Interactive Tools API Reference

**Developer documentation for CRACK Track Interactive Mode**

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Session Class API](#session-class-api)
3. [Tool Handler Methods](#tool-handler-methods)
4. [Helper Methods](#helper-methods)
5. [Data Structures](#data-structures)
6. [Extension Guide](#extension-guide)

---

## Architecture Overview

### Component Hierarchy

```
InteractiveSession (session.py)
├── ShortcutHandler (shortcuts.py)          # Keyboard shortcuts
├── PromptBuilder (prompts.py)              # Menu generation
├── InputProcessor (input_handler.py)       # Input parsing
├── DisplayManager (display.py)             # Terminal UI
├── TemplateRegistry (templates.py)         # Command templates
├── TimeTrackerDashboard (time_tracker.py)  # Time tracking
└── SmartSuggestHandler (smart_suggest_handler.py)  # Pattern matching
```

### State Management

**Profile Storage**: `~/.crack/targets/TARGET.json`
- TargetProfile instance (core/state.py)
- Persisted after every modification

**Session Checkpoints**: `~/.crack/sessions/TARGET.json`
- Lightweight session state
- Last action, current phase, preferences

**Snapshots**: `~/.crack/snapshots/TARGET/NAME.json`
- Full profile backups
- Rollback capability

---

## Session Class API

### Core Methods

#### `__init__(target: str, profile: TargetProfile = None)`

Initialize interactive session.

**Parameters**:
- `target` (str): Target IP/hostname
- `profile` (TargetProfile, optional): Existing profile (auto-loads if None)

**Side Effects**:
- Creates session checkpoint directory
- Loads existing checkpoint if available
- Initializes shortcut handler

**Example**:
```python
from crack.track.interactive.session import InteractiveSession

session = InteractiveSession("192.168.45.100")
# Auto-loads profile from ~/.crack/targets/192.168.45.100.json
```

---

#### `run()`

Main session loop - displays menus, processes input, executes actions.

**Returns**: None

**Side Effects**:
- Enters infinite loop (exits on 'q' shortcut or error)
- Saves checkpoint after each action
- Updates profile state

**Flow**:
```
1. Load checkpoint
2. Display context (target, phase, last action)
3. Build menu (context-aware)
4. Get user input
5. Process input → Execute action
6. Save checkpoint
7. Repeat
```

**Example**:
```python
session = InteractiveSession("192.168.45.100")
session.run()  # Enters interactive mode
```

---

#### `process_input(user_input: str, choices: List[Dict], recommendations: Dict) -> bool`

Process user input and execute corresponding action.

**Parameters**:
- `user_input` (str): Raw user input
- `choices` (List[Dict]): Available menu choices
- `recommendations` (Dict): Current recommendations

**Returns**:
- `True`: Continue session
- `False`: Exit session

**Side Effects**:
- Executes matched action
- Updates `self.last_action`
- May modify profile state

**Example**:
```python
choices = [
    {'id': 'import', 'label': 'Import scan', 'description': '...'},
    {'id': 'status', 'label': 'Show status', 'description': '...'}
]
recommendations = {'next': some_task, 'quick_wins': [...]}

continue_session = session.process_input('1', choices, recommendations)
```

---

### Tool Handler Methods

#### `handle_batch_execute()`

Execute multiple tasks with dependency resolution.

**Returns**: None

**Side Effects**:
- Displays task selection menu
- Resolves task dependencies
- Executes tasks (parallel/sequential)
- Updates task statuses
- Saves profile

**Internal Flow**:
```
1. Get all pending tasks
2. Display selection menu
3. Parse user selection (_parse_batch_selection)
4. Resolve dependencies (_resolve_dependencies)
5. Execute batch (_execute_batch)
6. Update task tree
7. Save profile
```

**Example**:
```python
session.handle_batch_execute()
# User selects 'all' → executes all pending tasks
```

---

#### `handle_command_history()`

Browse/search command execution history.

**Returns**: None

**Side Effects**:
- Displays command history menu
- May execute selected command
- May add to profile notes

**Data Source**: `self.profile.command_history`

**Example**:
```python
session.handle_command_history()
# Displays interactive history browser
```

---

#### `handle_finding_correlator()`

Analyze findings for attack chain correlations.

**Returns**: None

**Side Effects**:
- Analyzes profile findings
- Displays correlations (service+cred, vuln chain, etc.)
- May add correlation notes to profile

**Correlation Types**:
- `service_credential`: Service + discovered credentials
- `vulnerability_chain`: Multi-step exploit path
- `file_path_disclosure`: File disclosure + path info

**Example**:
```python
session.handle_finding_correlator()
# Outputs:
# 🔗 HIGH: SMB (445) + admin/password123 found on HTTP
```

---

#### `handle_progress_dashboard()`

Display visual progress overview.

**Returns**: None

**Side Effects**: None (read-only display)

**Metrics Displayed**:
- Overall task completion percentage
- Status breakdown (completed/pending/failed)
- Progress by service
- Attention-needed alerts

**Example**:
```python
session.handle_progress_dashboard()
# Outputs progress bars and service breakdown
```

---

#### `handle_port_lookup()`

Interactive port reference lookup.

**Returns**: None

**Side Effects**:
- Displays port information
- Shows enumeration checklist
- May add commands to task tree

**Data Source**: `interactive/port_reference.py`

**Example**:
```python
session.handle_port_lookup()
# User enters: 445
# Displays: SMB enumeration guide
```

---

#### `handle_quick_execute()`

Execute shell command without task tracking.

**Returns**: None

**Side Effects**:
- Executes command via subprocess
- Displays real-time output
- Optionally logs to profile notes

**Safety Features**:
- Validates against destructive patterns
- Requires confirmation for dangerous commands

**Example**:
```python
session.handle_quick_execute()
# User enters: nc -nv 192.168.45.100 80
# Executes immediately, streams output
```

---

#### `handle_quick_note(note: str = None, source: str = None)`

Add timestamped note to profile.

**Parameters**:
- `note` (str, optional): Note text (prompts if None)
- `source` (str, optional): Source attribution (prompts if None)

**Returns**: None

**Side Effects**:
- Adds note to `profile.notes`
- Saves profile

**Example**:
```python
# Interactive prompt
session.handle_quick_note()

# Programmatic
session.handle_quick_note(
    note="Found admin panel at /admin",
    source="gobuster scan"
)
```

---

#### `handle_quick_export()`

Export profile data to file.

**Returns**: None

**Side Effects**:
- Writes file to `~/.crack/exports/TARGET/`
- Displays export path

**Export Options**:
- Findings only (markdown/JSON/CSV)
- Task list (markdown/JSON/CSV)
- Timeline (markdown)
- Full report (markdown)

**Example**:
```python
session.handle_quick_export()
# User selects: findings → markdown
# Exports to: ~/.crack/exports/192.168.45.100/findings_TIMESTAMP.md
```

---

#### `handle_session_snapshot(action: str = None, name: str = None)`

Save/restore profile snapshots.

**Parameters**:
- `action` (str, optional): 'create', 'restore', 'delete', 'list'
- `name` (str, optional): Snapshot name

**Returns**: None

**Side Effects**:
- Creates/restores/deletes snapshot files
- May overwrite current profile (restore)

**Storage**: `~/.crack/snapshots/TARGET/NAME.json`

**Example**:
```python
# Create snapshot
session.handle_session_snapshot('create', 'before-exploit')

# Restore snapshot
session.handle_session_snapshot('restore', 'before-exploit')
```

---

#### `handle_task_filter()`

Filter tasks by criteria.

**Returns**: None

**Side Effects**:
- Displays filtered task list
- May execute filtered tasks

**Filter Criteria**:
- Port number
- Service type
- Tag (QUICK_WIN, OSCP:HIGH, etc.)
- Status (pending/completed/failed)

**Example**:
```python
session.handle_task_filter()
# User selects: port → 80
# Displays all port 80 tasks
```

---

#### `handle_task_retry()`

Retry failed tasks with command editing.

**Returns**: None

**Side Effects**:
- Displays failed/skipped tasks
- Allows command editing
- Re-executes task
- Updates task status

**Example**:
```python
session.handle_task_retry()
# User selects failed task
# Edits command (fix typo)
# Re-executes
```

---

#### `handle_time_tracker()`

Display time tracking dashboard.

**Returns**: None

**Side Effects**:
- Displays time metrics
- May set time limits/alerts

**Metrics**:
- Overall time spent
- Time by phase
- Time by service
- Time alerts (approaching limit)

**Example**:
```python
session.handle_time_tracker()
# Displays time breakdown and alerts
```

---

#### `handle_success_analyzer()`

Analyze task success rates.

**Returns**: None

**Side Effects**:
- Analyzes task history across targets
- Displays success rate metrics
- Provides optimization recommendations

**Example**:
```python
session.handle_success_analyzer()
# Outputs:
# whatweb: 95% success (19/20)
# gobuster: 90% success (18/20)
```

---

#### `handle_workflow_recorder(action: str = None)`

Record/replay command workflows.

**Parameters**:
- `action` (str, optional): 'record', 'play', 'list', 'delete'

**Returns**: None

**Side Effects**:
- Creates workflow definition
- Executes workflow tasks
- Saves workflow to profile

**Example**:
```python
# Record workflow
session.handle_workflow_recorder('record')
# User selects tasks → saves as workflow

# Play workflow
session.handle_workflow_recorder('play')
# User selects workflow → executes tasks
```

---

#### `handle_smart_suggest()`

Pattern-based next-step suggestions.

**Returns**: None

**Side Effects**:
- Analyzes current profile state
- Displays suggestions with confidence scores
- May execute suggested action

**Suggestion Types**:
- Credential reuse (service correlation)
- Directory enumeration depth
- Version-based exploits
- Blind spot identification

**Example**:
```python
session.handle_smart_suggest()
# Outputs:
# 🎯 HIGH (95%): Test HTTP creds on SMB
```

---

### Helper Methods

#### `_parse_batch_selection(user_input: str, tasks: List[TaskNode]) -> List[TaskNode]`

Parse batch execution selection syntax.

**Parameters**:
- `user_input` (str): Selection string
- `tasks` (List[TaskNode]): Available tasks

**Returns**: List[TaskNode] - Selected tasks

**Selection Syntax**:
- `'all'` - All tasks
- `'quick'` - QUICK_WIN tagged tasks
- `'1,3,5'` - Tasks 1, 3, 5
- `'1-5'` - Tasks 1 through 5
- `'port:80'` - All port 80 tasks

**Example**:
```python
tasks = session.profile.task_tree.get_all_pending()
selected = session._parse_batch_selection('1,3,5', tasks)
# Returns tasks at indices 0, 2, 4
```

---

#### `_resolve_dependencies(tasks: List[TaskNode]) -> Tuple[List[TaskNode], List[TaskNode]]`

Resolve task dependencies for execution order.

**Parameters**:
- `tasks` (List[TaskNode]): Tasks to execute

**Returns**: Tuple[List[TaskNode], List[TaskNode]]
- `parallel_tasks`: Tasks safe to execute in parallel
- `sequential_tasks`: Tasks requiring sequential execution

**Side Effects**: None (pure function)

**Example**:
```python
parallel, sequential = session._resolve_dependencies(tasks)
# parallel: [whatweb, enum4linux] (no dependencies)
# sequential: [gobuster, nikto] (nikto depends on gobuster)
```

---

#### `_execute_batch(tasks: List[TaskNode], parallel: bool = False) -> Dict[str, Any]`

Execute batch of tasks.

**Parameters**:
- `tasks` (List[TaskNode]): Tasks to execute
- `parallel` (bool): Execute in parallel (default: False)

**Returns**: Dict with execution results
```python
{
    'success': 5,
    'failed': 0,
    'duration': 120  # seconds
}
```

**Side Effects**:
- Executes task commands
- Updates task statuses
- Logs output

**Example**:
```python
results = session._execute_batch(tasks, parallel=True)
print(f"Completed {results['success']}/{len(tasks)}")
```

---

#### `_execute_single_task(task: TaskNode) -> bool`

Execute single task command.

**Parameters**:
- `task` (TaskNode): Task to execute

**Returns**: bool - Success/failure

**Side Effects**:
- Executes task command via subprocess
- Updates task status
- Logs output to profile

**Example**:
```python
task = session.profile.task_tree.get_task('whatweb-80')
success = session._execute_single_task(task)
```

---

## Data Structures

### Checkpoint Format

**File**: `~/.crack/sessions/TARGET.json`

```json
{
  "target": "192.168.45.100",
  "phase": "service-specific",
  "last_action": "Executed batch: 5 tasks",
  "start_time": 1699564800,
  "timestamp": 1699564900,
  "preferences": {
    "confirmation_mode": "smart",
    "auto_save": true
  }
}
```

---

### Snapshot Format

**File**: `~/.crack/snapshots/TARGET/NAME.json`

```json
{
  "snapshot_metadata": {
    "name": "before-exploit",
    "created": "2025-10-08T14:30:00",
    "description": "Pre-exploitation checkpoint"
  },
  "profile_data": {
    "target": "192.168.45.100",
    "ports": {...},
    "findings": [...],
    "task_tree": {...}
  }
}
```

---

### Correlation Structure

**Returned by Finding Correlator**:

```python
{
    'type': 'service_credential',
    'priority': 'high',
    'title': 'SMB + Credentials',
    'elements': [
        {
            'type': 'service',
            'port': 445,
            'service': 'smb',
            'version': 'Samba 4.13.2'
        },
        {
            'type': 'credential',
            'username': 'admin',
            'password': 'password123',
            'source': 'HTTP login form'
        }
    ],
    'recommendation': 'crackmapexec smb 192.168.45.100 -u admin -p password123',
    'rationale': 'Credential reuse across services (87% success rate)'
}
```

---

### Task Node Structure

**From task_tree.py**:

```python
{
    'id': 'gobuster-80',
    'name': 'Directory Brute-force (Port 80)',
    'type': 'command',
    'status': 'pending',  # pending/in-progress/completed/failed/skipped
    'metadata': {
        'command': 'gobuster dir -u http://192.168.45.100 -w /usr/share/wordlists/dirb/common.txt',
        'description': 'Enumerate web directories',
        'tags': ['OSCP:HIGH', 'QUICK_WIN', 'HTTP'],
        'estimated_time': '45s',
        'flag_explanations': {
            'dir': 'Directory/file brute-force mode',
            '-u': 'Target URL',
            '-w': 'Wordlist path'
        },
        'success_indicators': [
            'Directories found (200, 301, 302)',
            'No connection errors'
        ],
        'failure_indicators': [
            'Connection refused',
            'Empty results (may need different wordlist)'
        ],
        'alternatives': [
            'Manual: curl -s http://192.168.45.100/FUZZ',
            'Manual: dirb http://192.168.45.100'
        ]
    },
    'output': {
        'stdout': '...',
        'stderr': '...',
        'exit_code': 0,
        'duration': 45
    }
}
```

---

### Workflow Definition

**Stored in profile.workflows**:

```python
{
    'id': 'web-enum-full',
    'name': 'Full Web Enumeration',
    'description': 'Complete HTTP/HTTPS enumeration workflow',
    'tasks': [
        'whatweb-{PORT}',
        'gobuster-{PORT}',
        'nikto-{PORT}',
        'manual-http-{PORT}'
    ],
    'placeholders': {
        'PORT': 'Port number (e.g., 80, 443)',
        'TARGET': 'Target IP/hostname'
    },
    'estimated_time': 150,  # seconds
    'success_rate': 0.95,   # historical success rate
    'created': '2025-10-08T12:00:00'
}
```

---

## Extension Guide

### Adding a New Tool

**Step 1: Add Handler Method to Session**

Edit `/home/kali/OSCP/crack/track/interactive/session.py`:

```python
def handle_new_tool(self):
    """
    New tool description

    Side effects:
    - What this tool modifies

    Example usage:
    - When to use this tool
    """
    from .display import DisplayManager

    print(DisplayManager.format_info("New Tool"))

    # Tool implementation
    # ...

    # Save changes if profile modified
    self.profile.save()
    self.last_action = "Used new tool"
```

**Step 2: Register Shortcut**

Edit `/home/kali/OSCP/crack/track/interactive/shortcuts.py`:

```python
def __init__(self, session):
    self.session = session
    self.shortcuts: Dict[str, Tuple[str, str]] = {
        # ... existing shortcuts ...
        'nt': ('New tool description', 'new_tool'),  # NEW
    }

def new_tool(self):
    """New tool shortcut handler"""
    self.session.handle_new_tool()
```

**Step 3: Add to Input Handler**

Edit `/home/kali/OSCP/crack/track/interactive/input_handler.py`:

```python
class InputProcessor:
    SHORTCUTS = [
        's', 't', 'r', 'n', 'c', 'x',
        'ch', 'pl', 'tf', 'qn', 'tt', 'pd', 'qx',
        'fc', 'qe', 'ss', 'tr', 'be', 'sa', 'wr', 'sg',
        'nt',  # NEW
        'b', 'h', 'q'
    ]
```

**Step 4: Update Help Text**

Edit `/home/kali/OSCP/crack/track/interactive/prompts.py`:

```python
@classmethod
def build_help_text(cls) -> str:
    help_text = f"""
Interactive Mode Help
{'=' * 50}

KEYBOARD SHORTCUTS:
  ...
  nt - New tool description  # NEW
  ...
"""
    return help_text
```

**Step 5: Add Tests**

Create `/home/kali/OSCP/crack/tests/track/test_new_tool.py`:

```python
import pytest
from crack.track.interactive.session import InteractiveSession

class TestNewTool:
    def test_shortcut_registered(self):
        """Verify 'nt' shortcut exists"""
        from crack.track.interactive.shortcuts import ShortcutHandler

        session = InteractiveSession("192.168.45.100")
        handler = ShortcutHandler(session)

        assert 'nt' in handler.shortcuts
        assert handler.shortcuts['nt'][1] == 'new_tool'

    def test_handler_callable(self):
        """Verify handler method exists"""
        session = InteractiveSession("192.168.45.100")

        assert hasattr(session, 'handle_new_tool')
        assert callable(session.handle_new_tool)

    def test_workflow(self, mock_profile):
        """Test complete new tool workflow"""
        session = InteractiveSession(mock_profile.target)

        # Execute tool
        session.handle_new_tool()

        # Verify side effects
        assert session.last_action == "Used new tool"
        # ... additional assertions ...
```

**Step 6: Run Tests**

```bash
pytest tests/track/test_new_tool.py -v
```

**No reinstall needed** - interactive mode changes load dynamically.

---

### Adding a New Correlation Type

Edit `/home/kali/OSCP/crack/track/interactive/session.py`:

```python
def handle_finding_correlator(self):
    # ... existing code ...

    # Add new correlation logic
    new_correlations = self._correlate_new_type()

    if new_correlations:
        correlations.extend(new_correlations)

def _correlate_new_type(self) -> List[Dict]:
    """
    New correlation type description

    Returns:
        List of correlation dictionaries
    """
    correlations = []

    # Correlation logic
    # Example: Correlate file paths with LFI vulnerabilities

    for finding in self.profile.findings:
        if finding['type'] == 'lfi':
            for note in self.profile.notes:
                if 'path:' in note['note']:
                    correlations.append({
                        'type': 'lfi_path',
                        'priority': 'high',
                        'title': 'LFI + Path Disclosure',
                        'elements': [finding, note],
                        'recommendation': f"Test LFI with disclosed path: {note['note']}"
                    })

    return correlations
```

---

### Extending Time Tracker

Edit `/home/kali/OSCP/crack/track/interactive/time_tracker.py`:

```python
class TimeTrackerDashboard:
    def add_custom_metric(self, name: str, value: float):
        """Add custom time tracking metric"""
        if 'custom_metrics' not in self.session.profile.metadata:
            self.session.profile.metadata['custom_metrics'] = {}

        self.session.profile.metadata['custom_metrics'][name] = {
            'value': value,
            'timestamp': datetime.now().isoformat()
        }

        self.session.profile.save()
```

---

## Best Practices

### Error Handling

**Always wrap tool handlers with try/except**:

```python
def handle_new_tool(self):
    try:
        # Tool implementation
        pass
    except KeyboardInterrupt:
        print("\nCancelled")
        return
    except Exception as e:
        print(f"Error: {e}")
        # Log error but don't crash session
```

---

### Profile Modifications

**Always save after modifying profile**:

```python
def handle_new_tool(self):
    # Modify profile
    self.profile.add_note("Tool executed", source="new-tool")

    # ALWAYS save
    self.profile.save()

    # Update session state
    self.last_action = "Used new tool"
```

---

### Input Validation

**Validate all user input**:

```python
from .input_handler import InputProcessor

user_input = InputProcessor.get_input("Enter value: ")

# Validate
if not user_input:
    print("Input required")
    return

if not user_input.isdigit():
    print("Must be a number")
    return
```

---

### Confirmation Prompts

**Respect confirmation mode**:

```python
confirmation_mode = self.profile.metadata.get('confirmation_mode', 'always')

if confirmation_mode == 'never':
    # Execute without confirmation
    execute_action()
elif confirmation_mode == 'smart':
    # Smart decision based on risk
    if is_destructive:
        confirm = input("Confirm? [y/N]: ")
        if confirm.lower() == 'y':
            execute_action()
    else:
        execute_action()
else:  # 'always'
    confirm = input("Confirm? [Y/n]: ")
    if confirm.lower() != 'n':
        execute_action()
```

---

### Display Formatting

**Use DisplayManager for consistent UI**:

```python
from .display import DisplayManager

# Info message
print(DisplayManager.format_info("Processing..."))

# Success message
print(DisplayManager.format_success("Completed"))

# Warning
print(DisplayManager.format_warning("Time limit approaching"))

# Error
print(DisplayManager.format_error("Failed"))

# Menu
choices = [...]
print(DisplayManager.format_menu(choices, title="Select Option"))
```

---

## Testing Guidelines

### Test Structure

```python
class TestNewTool:
    """All tests for new tool"""

    def test_registration(self):
        """Verify tool registered correctly"""
        pass

    def test_handler_exists(self):
        """Verify handler method exists"""
        pass

    def test_basic_workflow(self, mock_profile):
        """Test basic tool usage"""
        pass

    def test_error_handling(self, mock_profile):
        """Verify graceful error handling"""
        pass

    def test_profile_modification(self, mock_profile):
        """Verify profile changes saved"""
        pass
```

### Fixtures

**Use existing fixtures** from `tests/track/conftest.py`:

```python
@pytest.fixture
def mock_profile():
    """Basic profile with target only"""
    pass

@pytest.fixture
def mock_profile_with_ports():
    """Profile with ports discovered"""
    pass

@pytest.fixture
def mock_profile_with_findings():
    """Profile with findings and credentials"""
    pass
```

### Value-Focused Assertions

**Test business value, not implementation**:

```python
# ✓ Good - Tests value
def test_time_savings(self, mock_profile):
    start = time.time()
    session.handle_batch_execute()
    duration = time.time() - start

    # Verify time savings claim
    assert duration < 60  # Batch should complete in <1 min

# ✗ Avoid - Tests implementation
def test_internal_method(self):
    result = session._internal_helper()
    assert result == expected  # Implementation detail
```

---

## Troubleshooting API Usage

### Common Issues

**Issue**: Tool handler not found
```python
AttributeError: 'InteractiveSession' object has no attribute 'handle_new_tool'
```
**Solution**: Verify method added to `session.py` and session instance created after code change

---

**Issue**: Shortcut not recognized
```python
KeyError: 'nt'
```
**Solution**: Verify shortcut added to `shortcuts.py` and `input_handler.py`

---

**Issue**: Profile changes not persisted
```python
# Changes lost after session exit
```
**Solution**: Always call `self.profile.save()` after modifications

---

**Issue**: Circular import
```python
ImportError: cannot import name 'InteractiveSession' from partially initialized module
```
**Solution**: Move import inside method (not top-level) or use TYPE_CHECKING

---

This API reference enables developers to extend CRACK Track Interactive Mode with new tools, correlation types, and workflow enhancements while maintaining consistency and quality.
