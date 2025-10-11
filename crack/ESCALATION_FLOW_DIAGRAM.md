# Command Editor Escalation Flow

## How Escalation Works

The command editor uses a three-tier system with seamless escalation between tiers.

---

## Tier Hierarchy

```
QuickEditor (Tier 1)
    ↓ 'a' key
AdvancedEditor (Tier 2)
    ↓ 'r' key
RawEditor (Tier 3)
```

You can also jump directly:
```
QuickEditor (Tier 1)
    ↓ 'r' key
RawEditor (Tier 3)
```

---

## Escalation Triggers

### From QuickEditor:
- **'a'** → Escalate to AdvancedEditor
- **'r'** → Escalate directly to RawEditor
- **'1-5'** → Edit parameter and execute (no escalation)
- **'c'** → Cancel

### From AdvancedEditor:
- **'r'** → Escalate to RawEditor
- **(Currently auto-escalates to Raw - "coming soon" message)**

### From RawEditor:
- Final tier - no further escalation
- Edit command text directly

---

## Example Escalation Flow

### Scenario: User wants full control over command

```
User presses 'e' in task workspace
    ↓
QuickEditor opens with parameter menu
    ↓
User presses 'a' (escalate to advanced)
    ↓
AdvancedEditor shows "coming soon"
    ↓
Auto-escalates to RawEditor
    ↓
User edits command text directly
    ↓
Press Enter twice to finish
    ↓
Command validated and saved
```

### Scenario: User wants direct text editing

```
User presses 'e' in task workspace
    ↓
QuickEditor opens with parameter menu
    ↓
User presses 'r' (escalate to raw)
    ↓
RawEditor opens immediately
    ↓
User edits command text directly
    ↓
Command saved
```

---

## Technical Implementation

### 1. Orchestrator Loop (editor.py)

```python
while iterations < MAX_ITERATIONS:
    result = self._run_tier(self.current_tier)

    if result.action == "execute":
        return result  # Done!

    elif result.action == "escalate":
        # Handle escalation to next tier
        escalated_result = self._handle_escalation(result)

        if escalated_result.action == "execute":
            return escalated_result

        elif escalated_result.action == "escalate":
            # Continue loop for chained escalation
            result = escalated_result
            continue
```

### 2. State Preservation

During escalation:
- **Command edits are preserved** (`self.current_command` updated)
- **Metadata unchanged** (tool, task info)
- **Original command stored** (for revert in Raw editor)

### 3. TUI Integration (tui_integration.py)

```python
def _patch_tier_callbacks(self):
    """Inject TUI rendering into each tier"""
    def patched_run_tier(tier: str) -> EditResult:
        if tier == "quick":
            return self._run_quick_editor()  # Rich Table + Prompt
        elif tier == "advanced":
            return self._run_advanced_editor()  # Coming soon
        elif tier == "raw":
            return self._run_raw_editor()  # Syntax highlighting + validation

    self.editor._run_tier = patched_run_tier
```

---

## What You See During Escalation

### QuickEditor → Raw (via 'r')

```
📝 Edit Command
════════════════════════
Tool: gobuster
Command: gobuster dir -u http://target

Editable Parameters
┏━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━┓
┃ # ┃ Parameter┃ Value       ┃
┡━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━┩
│ 1 │ url      │ http://target│
│ 2 │ wordlist │ /path       │
└───┴──────────┴─────────────┘

Select: (1-5, a, r, c) r  ← User presses 'r'

✏ Raw Text Editor
═══════════════════════
Edit command directly. Press Enter twice when done.

1  gobuster dir -u http://target -w /path
2

Enter new command:
gobuster dir -u http://new-target -w /new-path  ← User types
                                                ← Press Enter
                                                ← Press Enter again

✓ Command updated: gobuster dir -u http://new-target -w /new-path
```

### QuickEditor → Advanced → Raw (via 'a')

```
📝 Edit Command
════════════════════════
[Parameter menu shown...]

Select: (1-5, a, r, c) a  ← User presses 'a'

Advanced editor (schema-driven forms) coming soon!
Escalating to raw text editor...

✏ Raw Text Editor
═══════════════════════
[Raw editor shown...]
```

---

## Testing Escalation

### Test 1: Quick → Raw

```bash
crack track --tui 192.168.45.100

1. Press 'l' to list tasks
2. Select a gobuster task (e.g., '1')
3. Press 'e' to edit
4. Press 'r' to escalate to raw
5. Verify raw editor opens with current command
6. Edit command and press Enter twice
7. Verify command saved
```

### Test 2: Quick → Advanced → Raw

```bash
1. Press 'e' in task workspace
2. Press 'a' to escalate to advanced
3. See "coming soon" message
4. Verify auto-escalation to raw
5. Edit and save
```

### Test 3: Edit in Quick, Then Escalate

```bash
1. Press 'e' in task workspace
2. Press '1' to edit URL parameter
3. Enter new URL: http://new-target
4. Press 'r' to escalate to raw
5. Verify raw editor shows UPDATED command with new URL
6. Make additional edits
7. Save
8. Verify both changes preserved
```

---

## Escalation State Preservation

**Edits Made in QuickEditor Are Preserved When Escalating:**

```
Start: gobuster dir -u http://old -w /path

QuickEditor:
  Edit URL → http://new

Press 'r' to escalate

RawEditor opens with:
  gobuster dir -u http://new -w /path  ← URL change preserved!
```

---

## Debugging Escalation

Enable detailed logging:

```bash
crack track --tui 192.168.45.100 --debug --debug-categories=UI.EDITOR.TIER:TRACE

# Check logs
grep "escalation\|tier" .debug_logs/tui_debug_*.log
```

**Expected Log Entries:**

```
[UI.EDITOR.TIER] Tier selected: quick
[UI.EDITOR.TIER] Tier escalation | from_tier=quick | to_tier=raw
[UI.EDITOR.TIER] Running tier: raw
[UI.EDITOR] Editor complete | tier=raw
```

---

## Current Status

✓ **QuickEditor → RawEditor** (works via 'r' key)
✓ **QuickEditor → AdvancedEditor → RawEditor** (works via 'a' key, auto-escalates)
✓ **State preservation during escalation** (command edits preserved)
✓ **Loop prevention** (MAX_ITERATIONS = 10)
✓ **Orchestrator handles all escalation logic** (TUI just renders)

⏳ **AdvancedEditor full implementation** (currently placeholder that escalates)

---

## Why Three Tiers?

**QuickEditor (Tier 1):**
- Fast parameter editing for common cases
- 80% of edits done here
- No typing needed (just select number)

**AdvancedEditor (Tier 2):**
- Schema-driven forms with validation
- For complex tool configurations
- Type safety and enum dropdowns

**RawEditor (Tier 3):**
- Full control for edge cases
- Custom commands
- Multi-line support
- Manual override of any validation

---

**Try the escalation flow and let me know if it works as expected!**
