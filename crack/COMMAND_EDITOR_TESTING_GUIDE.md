# Command Editor Testing Guide

## Phase 5 Integration Complete! ✓

The command editor system is now integrated into the TUI and ready for testing.

---

## Quick Start

### 1. Launch TUI Mode

```bash
crack track --tui 192.168.45.100
```

### 2. Navigate to a Task

From the dashboard, press:
- **'l'** - Browse all tasks (Task List)
- Select a task (1-10)

### 3. Edit the Command

In the task workspace, press:
- **'e'** - Edit command

---

## What to Expect

### Command Editor Flow

1. **Header Display**
   - Shows tool name and current command
   - Provides escalation hints

2. **QuickEditor (Tier 1)** - Automatic for common tools
   - **Supported Tools**: gobuster, nmap, nikto, hydra, sqlmap
   - **Interface**: Numbered parameter menu (1-5)
   - **Actions**:
     - **1-5**: Edit specific parameter
     - **'a'**: Escalate to Advanced Editor
     - **'r'**: Escalate to Raw Editor
     - **'c'**: Cancel

3. **AdvancedEditor (Tier 2)** - Schema-driven forms
   - **Status**: Coming soon! Auto-escalates to Raw for now
   - **Future**: Full form interface with field validation

4. **RawEditor (Tier 3)** - Direct text editing
   - **Interface**: Multi-line text editor
   - **Actions**:
     - Type new command
     - Press Enter twice when done
     - Empty first line = cancel

5. **Result**
   - Command updated and saved to task
   - Success message displayed

---

## Example Test Scenarios

### Scenario 1: Edit Gobuster URL

```bash
# Original task command
gobuster dir -u http://192.168.45.100 -w /usr/share/wordlists/dirb/common.txt

# Steps:
1. Press 'e' in task workspace
2. See parameter menu with 5 options
3. Press '1' to edit URL
4. Enter new URL: http://192.168.45.200
5. Command updated automatically!
```

### Scenario 2: Edit Nmap Ports

```bash
# Original task command
nmap -sS -p- 192.168.45.100

# Steps:
1. Press 'e' in task workspace
2. See parameter menu
3. Press '2' to edit ports
4. Enter new ports: 22,80,443
5. Command updated!
```

### Scenario 3: Raw Edit for Custom Command

```bash
# Original task command
custom-tool --flag value

# Steps:
1. Press 'e' in task workspace
2. No common params → Auto-escalate to Advanced
3. Advanced not ready → Auto-escalate to Raw
4. Type new command directly
5. Press Enter twice to confirm
6. Command updated!
```

### Scenario 4: Cancel Editing

```bash
# Steps:
1. Press 'e' in task workspace
2. Press 'c' to cancel
3. No changes made
```

---

## Keyboard Shortcuts in Task Workspace

| Key | Action |
|-----|--------|
| **e** | **Edit command** (NEW!) |
| 1-3 | Execute action |
| n | Next task (after completion) |
| l | List all tasks (after completion) |
| b | Back to dashboard |
| : | Command mode |

---

## Validation Features

The editor includes safety checks:

✓ **Syntax Validation**: Checks for balanced quotes, parens, line continuations
✓ **Path Validation**: Warns if wordlist/output files don't exist
✓ **Flag Compatibility**: Validates tool-specific flag conflicts
✓ **Security Checks**: Blocks dangerous commands (rm -rf, /etc writes)
✓ **Runtime Estimation**: Shows estimated execution time

---

## Debugging

If you encounter issues, enable debug logging:

```bash
crack track --tui 192.168.45.100 --debug --debug-categories=UI.EDITOR:VERBOSE
```

Check logs in `.debug_logs/tui_debug_*.log`

### Common Issues

**Issue**: Command editor doesn't open
**Fix**: Ensure task has a 'command' in metadata

**Issue**: Editor shows "coming soon"
**Fix**: This is Advanced Editor (Tier 2) - currently escalates to Raw

**Issue**: Validation fails
**Fix**: Check command syntax, file paths, and flags

---

## Test Checklist

Test these scenarios to verify the integration:

- [ ] Open editor from task workspace with 'e' key
- [ ] Edit gobuster URL parameter
- [ ] Edit nmap ports parameter
- [ ] Escalate from Quick to Raw with 'r'
- [ ] Cancel editing with 'c'
- [ ] Verify command saves to profile
- [ ] Test validation error handling
- [ ] Test with custom/unknown tool (should go to Raw)
- [ ] Press 'e' when no command exists (should show warning)
- [ ] Edit command, then execute updated command

---

## Next Steps (Future Enhancements)

Phase 5 delivers:
- ✓ 'e' hotkey integration
- ✓ QuickEditor with parameter menu
- ✓ RawEditor with text editing
- ✓ Command validation
- ✓ State persistence

Future phases:
- ⏳ AdvancedEditor with schema-driven forms
- ⏳ Template saving from editor
- ⏳ Command history in editor
- ⏳ Diff preview before saving
- ⏳ Syntax highlighting in Raw editor

---

## Feedback

Test the editor and note:
1. What works well?
2. What's confusing?
3. What features are missing?
4. Any bugs or errors?

---

**Happy Testing!** 🚀
