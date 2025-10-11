# Command Editor Debug Log Patterns - Quick Reference

**Purpose:** Fast lookup of expected log patterns for command editor debugging.

**Usage:** Keep this open in a terminal while performing visual validation.

---

## Quick Debug Commands

```bash
# Watch logs in real-time (most useful)
tail -f .debug_logs/tui_debug_*.log | grep -E "\[UI.EDITOR|\[STATE.TRANSITION"

# All editor logs
grep "\[UI.EDITOR" .debug_logs/tui_debug_*.log | tail -50

# Tier transitions only
grep "Tier" .debug_logs/tui_debug_*.log

# Validation checks
grep -C 3 "Validation" .debug_logs/tui_debug_*.log

# Errors/warnings
grep -i "error\|warning\|exception" .debug_logs/tui_debug_*.log

# Performance timing
grep "elapsed=" .debug_logs/tui_debug_*.log | grep EDITOR
```

---

## Expected Log Sequences

### Successful Quick Edit

```
[UI.INPUT] Key pressed: e
[STATE.TRANSITION] task_workspace -> COMMAND_EDITOR (edit command)
[UI.EDITOR] CommandEditor initialized (command_length=78, tool=gobuster)
[UI.EDITOR_SCHEMA] Schema check for gobuster (exists=True, cached=False)
[UI.EDITOR_TIER] Tier selected: quick (in_common_params=True, has_schema=True)
[UI.EDITOR_TIER] Running tier: quick (command_length=78)
[UI.EDITOR] Editor complete (tier=quick, iterations=1)
[STATE.TRANSITION] COMMAND_EDITOR -> task_workspace (command updated)
```

**Verification:**
✓ Initialization logged
✓ Tier=quick selected
✓ Single iteration
✓ State returns to task_workspace
✓ "command updated" message present

---

### Escalation: Quick → Raw

```
[UI.EDITOR] CommandEditor initialized (tool=gobuster)
[UI.EDITOR_TIER] Tier selected: quick
[UI.EDITOR_TIER] Tier escalation (from_tier=quick, to_tier=raw, reason=user requested)
[UI.EDITOR_TIER] Running tier: raw
[UI.EDITOR] Editor complete (tier=raw, iterations=2)
[STATE.TRANSITION] COMMAND_EDITOR -> task_workspace
```

**Verification:**
✓ Started in quick tier
✓ Escalation logged with reason
✓ Ended in raw tier
✓ 2 iterations (quick + raw)

---

### Escalation: Quick → Advanced → Raw

```
[UI.EDITOR_TIER] Tier selected: quick
[UI.EDITOR_TIER] Tier escalation (from_tier=quick, to_tier=advanced)
[UI.EDITOR_TIER] Running tier: advanced
[UI.EDITOR_TIER] Tier escalation (from_tier=advanced, to_tier=raw, reason=schema placeholder)
[UI.EDITOR_TIER] Running tier: raw
[UI.EDITOR] Editor complete (tier=raw, iterations=3)
```

**Verification:**
✓ Three tiers visited
✓ 3 iterations total
✓ Reason logged for each escalation

---

### Validation Failure

```
[UI.EDITOR_TIER] Running tier: raw
[UI.EDITOR] Validation failed (errors=1, warnings=0)
[UI.EDITOR] User declined override
[UI.EDITOR] Editor cancelled (tier=raw)
[STATE.TRANSITION] COMMAND_EDITOR -> task_workspace
```

**Verification:**
✓ Validation ran
✓ Error count logged
✓ User decision logged
✓ Editor cancelled (not completed)

---

### Cancellation

```
[UI.EDITOR] CommandEditor initialized
[UI.EDITOR_TIER] Tier selected: quick
[UI.EDITOR] Editor cancelled (tier=quick)
[STATE.TRANSITION] COMMAND_EDITOR -> task_workspace
```

**Verification:**
✓ "cancelled" not "complete"
✓ No "command updated" message
✓ Returns to task_workspace

---

### No Command Error

```
[UI.INPUT] Key pressed: e
[UI.EDITOR] Error: No command metadata found
[STATE.TRANSITION] task_workspace -> task_workspace (no change)
```

**Verification:**
✓ Error logged immediately
✓ No initialization
✓ State doesn't change to COMMAND_EDITOR

---

## Log Categories

### UI.EDITOR

Main editor events:

- `CommandEditor initialized` - Editor starts
- `Editor complete` - User confirmed changes
- `Editor cancelled` - User cancelled
- `Validation failed` - Command validation error
- `Error: No command metadata found` - Missing command

### UI.EDITOR_TIER

Tier selection and routing:

- `Tier selected: <tier>` - Initial tier chosen
- `Running tier: <tier>` - Tier executing
- `Tier escalation` - User escalated to different tier

### UI.EDITOR_SCHEMA

Schema loading (for advanced tier):

- `Schema check for <tool>` - Schema existence check
- `exists=True/False` - Schema file found/missing
- `cached=True/False` - Schema loaded from cache

### STATE.TRANSITION

State machine transitions:

- `task_workspace -> COMMAND_EDITOR` - Editor opened
- `COMMAND_EDITOR -> task_workspace` - Editor closed
- `(command updated)` - Changes saved
- `(edit cancelled)` - No changes saved

---

## Troubleshooting Patterns

### Problem: Editor Not Launching

**Expected Logs:**
```
[UI.INPUT] Key pressed: e
[STATE.TRANSITION] task_workspace -> COMMAND_EDITOR
[UI.EDITOR] CommandEditor initialized
```

**If Missing:**
```bash
# Check if 'e' key was detected
grep "Key pressed: e" .debug_logs/tui_debug_*.log

# Check for warnings
grep -i "warning\|no command" .debug_logs/tui_debug_*.log

# Check hotkey registration
grep "hotkey.*e" .debug_logs/tui_debug_*.log
```

---

### Problem: Wrong Tier Selected

**Expected Logs:**
```
[UI.EDITOR_TIER] Tier selected: quick (in_common_params=True, has_schema=True)
```

**Debug:**
```bash
# Check tier selection logic
grep "Tier selected" .debug_logs/tui_debug_*.log

# Check schema detection
grep "Schema check" .debug_logs/tui_debug_*.log

# Check tool name
grep "tool=" .debug_logs/tui_debug_*.log | grep EDITOR
```

**Common Issues:**
- Tool not in `QuickEditor.COMMON_PARAMS` → Falls back to advanced/raw
- Schema missing → Falls back to raw
- Tool name mismatch → Wrong tier logic

---

### Problem: Changes Not Persisting

**Expected Logs:**
```
[UI.EDITOR] Editor complete (tier=quick, iterations=1)
[STATE.TRANSITION] COMMAND_EDITOR -> task_workspace (command updated)
```

**If Missing:**
```bash
# Check EditResult action
grep "action=" .debug_logs/tui_debug_*.log | tail -10

# Check profile save
grep "Profile saved" .debug_logs/tui_debug_*.log

# Check for file write errors
grep -i "permission\|write\|save.*fail" .debug_logs/tui_debug_*.log
```

**Common Issues:**
- Action is "cancel" not "execute"
- Profile not saved after metadata update
- File permissions issue

---

### Problem: Infinite Escalation Loop

**Expected Logs:**
```
[UI.EDITOR] Editor complete (tier=<final_tier>, iterations=<count>)
```

**If Missing:**
```bash
# Check iteration count
grep "iterations=" .debug_logs/tui_debug_*.log | grep EDITOR

# Check for max iterations
grep "Max iterations" .debug_logs/tui_debug_*.log

# Check escalation path
grep "Tier escalation" .debug_logs/tui_debug_*.log
```

**Common Issues:**
- EditResult returns `action="escalate"` with invalid `next_tier`
- Circular escalation (tier A → tier B → tier A)
- Hits max iterations (10)

---

### Problem: Performance Degradation

**Expected Logs (with --debug-timing):**
```
[PERFORMANCE] Editor launch elapsed=0.085s
[PERFORMANCE] Tier selection elapsed=0.012s
[PERFORMANCE] Schema load elapsed=0.008s (cached)
```

**Debug:**
```bash
# Check all timing logs
grep "elapsed=" .debug_logs/tui_debug_*.log | grep EDITOR

# Find slow operations (>500ms)
grep "elapsed=" .debug_logs/tui_debug_*.log | awk -F'=' '$2 > 0.5'

# Check schema caching
grep "Schema.*cached=" .debug_logs/tui_debug_*.log
```

---

## Cheat Sheet

### Launch Debug Session

```bash
crack track --tui 192.168.45.100 \
  --debug \
  --debug-categories=UI.EDITOR:TRACE,UI.EDITOR_TIER:VERBOSE,STATE.TRANSITION:VERBOSE \
  --debug-timing
```

### Monitor Logs (3 Terminal Setup)

**Terminal 1:** TUI
```bash
crack track --tui 192.168.45.100 --debug --debug-categories=UI.EDITOR:TRACE,STATE:VERBOSE
```

**Terminal 2:** Editor logs
```bash
tail -f .debug_logs/tui_debug_*.log | grep "\[UI.EDITOR"
```

**Terminal 3:** State transitions
```bash
tail -f .debug_logs/tui_debug_*.log | grep "\[STATE.TRANSITION"
```

### Quick Validation

```bash
# After editing workflow, run:
LOG_FILE=$(ls -t .debug_logs/tui_debug_*.log | head -1)

# Check editor launched
grep "CommandEditor initialized" "$LOG_FILE"

# Check tier
grep "Tier selected" "$LOG_FILE"

# Check completion
grep "Editor complete\|Editor cancelled" "$LOG_FILE"

# Check persistence
grep "command updated" "$LOG_FILE"
```

---

## Log Levels

| Level | Usage | Example |
|-------|-------|---------|
| MINIMAL | Production | Errors only |
| NORMAL | Default | Major events (init, complete, cancel) |
| VERBOSE | Development | Tier transitions, schema checks |
| TRACE | Deep debug | Every state change, timing |

**Setting Levels:**
```bash
# Per-category levels
--debug-categories=UI.EDITOR:TRACE,UI.EDITOR_TIER:VERBOSE,STATE:NORMAL

# Global level
--debug-level=VERBOSE
```

---

## Common Workflows

### Workflow 1: Debug Failed Edit

```bash
# 1. Run with debug enabled
crack track --tui TARGET --debug --debug-categories=UI.EDITOR:TRACE

# 2. Reproduce failure

# 3. Analyze logs
LOG=$(ls -t .debug_logs/*.log | head -1)
grep -C 10 "error\|fail" "$LOG"

# 4. Check last 50 editor events
grep "\[UI.EDITOR" "$LOG" | tail -50

# 5. Check state transitions
grep "\[STATE.TRANSITION" "$LOG" | tail -20
```

### Workflow 2: Verify Escalation

```bash
# 1. Run test
crack track --tui TARGET --debug --debug-categories=UI.EDITOR_TIER:VERBOSE

# 2. Press 'e' → 'a' → 'r'

# 3. Check escalation path
LOG=$(ls -t .debug_logs/*.log | head -1)
grep "Tier" "$LOG" | tail -10

# Expected:
# Tier selected: quick
# Tier escalation from_tier=quick to_tier=advanced
# Tier escalation from_tier=advanced to_tier=raw
# Running tier: raw
```

### Workflow 3: Performance Profiling

```bash
# 1. Run with timing
crack track --tui TARGET --debug --debug-timing --debug-categories=PERFORMANCE:VERBOSE,UI.EDITOR:VERBOSE

# 2. Perform edit workflow

# 3. Analyze timing
LOG=$(ls -t .debug_logs/*.log | head -1)
grep "elapsed=" "$LOG" | grep EDITOR

# 4. Find slow operations
grep "elapsed=" "$LOG" | awk -F'=' '$NF > 0.5 {print}'
```

---

## Reference

**Related Docs:**
- Main testing guide: `track/docs/COMMAND_EDITOR_TESTING.md`
- Debug logging cheat sheet: `track/docs/DEBUG_LOGGING_CHEATSHEET.md`
- Implementation: `track/interactive/components/command_editor/`

**Quick Links:**
- Integration tests: `tests/track/interactive/test_command_editor_integration.py`
- TUI integration: `track/interactive/tui_session_v2.py` (lines 852-905)
- Component checklist: `track/docs/CMD_PANEL_CHECKLIST.md`

---

**Last Updated:** 2025-10-11
**Status:** ✅ Complete
