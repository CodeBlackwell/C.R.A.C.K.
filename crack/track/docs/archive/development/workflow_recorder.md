# Workflow Recorder (wr) - Implementation Summary

## Overview

The Workflow Recorder (wr) tool enables OSCP students to record successful task sequences and replay them across multiple targets, dramatically reducing repetitive enumeration work.

**Shortcut:** `wr`
**Value:** HIGH - Reuse proven enumeration patterns across OSCP lab machines
**Complexity:** HIGH - Sophisticated macro system with variable substitution
**Lines of Code:** ~360 lines (15 methods)
**Tests:** 19 (100% passing)

## Features Implemented

### ✅ Recording Functionality
- **Start/Stop Recording**: `wr start <name>` / `wr stop`
- **Auto-recording**: Tasks automatically recorded during execution when recording active
- **Metadata Capture**: Commands, tags, estimated times, task names
- **Recording Indicator**: Visual feedback (🔴 Recording workflow: name)

### ✅ Variable Extraction
- **Target IP**: `192.168.45.100` → `<TARGET>`
- **Attacker IP**: `192.168.45.200` → `<LHOST>`
- **Ports**: `80`, `443`, `22` → `<PORT>`
- **Wordlists**: `/usr/share/wordlists/...` → `<WORDLIST>`
- **Output Files**: `/tmp/...` → `<OUTPUT>`

### ✅ Workflow Management
- **List Workflows**: `wr list` - Shows all saved workflows with stats
- **Delete Workflow**: `wr delete <name>` - Remove workflow with confirmation
- **Export Workflow**: `wr export <name>` - Share with teammates
- **Storage**: `~/.crack/workflows/*.workflow.json`

### ✅ Replay System
- **Variable Substitution**: Interactive prompts for each variable
- **Default Values**: Smart defaults from variable metadata
- **Batch Execution**: All tasks executed in sequence
- **Progress Display**: [1/5] Task name... ✓ Success / ✗ Failed
- **Target Adaptation**: Same workflow works on any target

## Workflow Storage Format

```json
{
  "name": "web-enum",
  "description": "Complete HTTP/HTTPS enumeration workflow",
  "created": "2025-10-08T14:00:00",
  "original_target": "192.168.45.100",
  "tasks": [
    {
      "name": "Technology detection",
      "command": "whatweb <TARGET>",
      "order": 1,
      "variables": ["TARGET"],
      "estimated_time": 5,
      "tags": ["http", "QUICK_WIN"]
    },
    {
      "name": "Directory bruteforce",
      "command": "gobuster dir -u http://<TARGET> -w <WORDLIST> -o gobuster_<PORT>.txt",
      "order": 2,
      "variables": ["TARGET", "WORDLIST", "PORT"],
      "estimated_time": 60,
      "depends_on": [1]
    }
  ],
  "variables": {
    "<TARGET>": {
      "description": "Target IP or hostname",
      "example": "192.168.45.100",
      "required": true
    },
    "<WORDLIST>": {
      "description": "Wordlist path",
      "example": "/usr/share/wordlists/dirb/common.txt",
      "required": true,
      "default": "/usr/share/wordlists/dirb/common.txt"
    },
    "<PORT>": {
      "description": "Target port",
      "example": "80",
      "required": true
    }
  },
  "stats": {
    "total_tasks": 2,
    "total_time": 65,
    "success_rate": 100
  }
}
```

## Usage Examples

### Record a Workflow
```bash
# In interactive mode
crack track -i 192.168.45.100

# Start recording
wr start "web-enum"
# 🔴 Recording workflow: web-enum

# Execute tasks normally (they'll be recorded)
# ... run whatweb, gobuster, nikto, etc ...

# Stop recording
wr stop
# Description: Complete HTTP/HTTPS enumeration
# ✓ Workflow saved: web-enum
#   Location: /home/kali/.crack/workflows/web-enum.workflow.json
#   Tasks: 5
```

### Replay on Different Target
```bash
# In interactive mode for new target
crack track -i 192.168.45.101

# Replay workflow
wr play "web-enum"

# Enter values for variables:
#   <TARGET> (Target IP) [e.g., 192.168.45.100]: 192.168.45.101
#   <WORDLIST> (Wordlist path) [e.g., /usr/share/wordlists/dirb/common.txt]: [Enter for default]
#   <PORT> (Target port) [e.g., 80]: 80
#
# Execute workflow? [Y/n]: Y
#
# Executing workflow...
#
# [1/5] Technology detection
#   Command: whatweb 192.168.45.101
#   ✓ Success
#
# [2/5] Directory bruteforce
#   Command: gobuster dir -u http://192.168.45.101 -w /usr/share/wordlists/dirb/common.txt -o gobuster_80.txt
#   ✓ Success
# ...
```

### Manage Workflows
```bash
# List all saved workflows
wr list
# Saved Workflows (3):
#
# • web-enum
#   Description: Complete HTTP/HTTPS enumeration
#   Tasks: 5
#   Estimated time: 180s
#   Created: 2025-10-08
#
# • smb-enum
#   Description: SMB share enumeration
#   Tasks: 3
#   Estimated time: 45s
#   Created: 2025-10-08

# Delete workflow
wr delete "old-workflow"
# Delete workflow 'old-workflow'? [y/N]: y
# ✓ Deleted workflow: old-workflow

# Export to share
wr export "web-enum"
# Export path [./workflow_export.json]: /tmp/web-enum-workflow.json
# ✓ Exported to: /tmp/web-enum-workflow.json
#
# Share this file with teammates to replay the workflow on other targets.
```

## Integration Points

### 1. Session Initialization (`__init__`)
```python
# Workflow recording state
self.recording = False
self.recording_name = None
self.recording_start = None
self.recorded_tasks = []
```

### 2. Task Execution Hook (`execute_task`)
```python
if result.returncode == 0:
    print(DisplayManager.format_success("Command completed"))
    task.stop_timer()
    task.mark_complete()
    self.last_action = f"Completed: {task.name}"

    # Record task if workflow recording is active
    self._record_task(task)
```

### 3. Shortcut Registration (`shortcuts.py`)
```python
'wr': ('Workflow recorder', 'workflow_recorder')

def workflow_recorder(self):
    """Workflow recorder/player (shortcut: wr)"""
    self.session.handle_workflow_recorder()
```

### 4. Help Text (`prompts.py`)
```
wr - Workflow recorder (record and replay task sequences)
```

## Test Coverage (19 Tests)

### Recording Tests (4)
- ✅ test_start_recording - Can start recording workflow
- ✅ test_stop_recording_saves_workflow - Stopping saves to disk
- ✅ test_record_task_during_execution - Tasks recorded when active
- ✅ test_no_recording_when_not_active - No recording when inactive

### Variable Extraction Tests (6)
- ✅ test_templatize_target_ip - Target IP → <TARGET>
- ✅ test_templatize_wordlist_path - Wordlist paths → <WORDLIST>
- ✅ test_templatize_ports - Ports → <PORT>
- ✅ test_templatize_attacker_ip - Attacker IPs → <LHOST>
- ✅ test_find_variables - Extract variables from template
- ✅ test_extract_variables_with_metadata - Variables with descriptions

### Replay Tests (4)
- ✅ test_list_workflows - Lists all saved workflows
- ✅ test_play_workflow_variable_substitution - Correct substitution
- ✅ test_delete_workflow - Can delete workflows
- ✅ test_export_workflow - Can export to custom path

### Validation Tests (4)
- ✅ test_cannot_start_recording_twice - Prevents double recording
- ✅ test_stop_recording_without_start - Shows warning
- ✅ test_stop_recording_with_no_tasks - Shows warning
- ✅ test_play_nonexistent_workflow - Error handling

### Integration Test (1)
- ✅ test_complete_record_and_replay_workflow - End-to-end workflow

## OSCP Exam Value

### Time Savings
- **First Target**: Normal enumeration (30-60 min)
- **Subsequent Targets**: Workflow replay (5-10 min)
- **Potential Savings**: 20-50 min per additional target

### Use Cases
1. **Web Enumeration**: Record gobuster, nikto, whatweb sequence
2. **SMB Enumeration**: Record smbclient, enum4linux, share checks
3. **Linux PrivEsc**: Record SUID, cron, GTFO bins checks
4. **Windows PrivEsc**: Record winPEAS, privileges, services checks
5. **Post-Exploit**: Record loot collection, persistence setup

### Best Practices
- Record successful patterns on first target
- Use descriptive workflow names (e.g., "http-port-80-enum")
- Export workflows before exam for backup
- Test workflows on similar targets first
- Keep workflows modular (separate web, SMB, etc.)

## Files Modified

1. **crack/track/interactive/session.py** (+360 lines)
   - handle_workflow_recorder() - Main handler
   - _start_recording() - Start workflow recording
   - _stop_recording() - Stop and save workflow
   - _record_task() - Record task to workflow
   - _templatize_command() - Replace values with placeholders
   - _find_variables() - Extract variables from template
   - _extract_variables() - Build variable metadata
   - _get_variable_description() - Variable descriptions
   - _get_variable_example() - Variable examples
   - _list_workflows() - List saved workflows
   - _play_workflow() - Replay workflow
   - _delete_workflow() - Delete workflow
   - _export_workflow() - Export workflow
   - Recording state initialization in __init__
   - Task recording hook in execute_task

2. **crack/track/interactive/shortcuts.py** (+4 lines)
   - Added 'wr' shortcut registration
   - Added workflow_recorder() handler method

3. **crack/track/interactive/input_handler.py** (+1 line)
   - Added 'wr' to SHORTCUTS list

4. **crack/track/interactive/prompts.py** (+1 line)
   - Added 'wr' to help text

5. **crack/tests/track/test_workflow_recorder.py** (NEW, 450 lines)
   - Comprehensive test suite with 19 tests

## Success Criteria

✅ Record task sequences
✅ Variable extraction from commands
✅ Save workflows to disk
✅ Replay on different targets
✅ Variable substitution
✅ All 19 tests passing
✅ ~360 lines implementation

## Future Enhancements (Optional)

- Dependency tracking (task order requirements)
- Conditional execution (skip if port closed)
- Output parsing (auto-extract findings during replay)
- Workflow templates (pre-built for common scenarios)
- Import/share workflows from community
- Success rate tracking and optimization suggestions
