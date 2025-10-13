# Attack Chains Interactive Mode - MVP

**Status:** ✅ Functional MVP (3 hours implementation)

## Quick Start

```bash
# List available chains
crack reference --chains

# Launch interactive execution
crack reference --chains linux-privesc-suid-basic -i

# Resume from saved session
crack reference --chains linux-privesc-suid-basic -i --resume
```

## What Works (MVP Features)

### ✅ Step-by-Step Execution
- Displays chain metadata (name, difficulty, time estimate)
- Shows current step number (e.g., "Step 2 of 8")
- Displays objective and description for each step
- Resolves command references to actual commands

### ✅ Variable Filling
- Interactive prompts for command placeholders
- Auto-fills from `~/.crack/config.json` (LHOST, LPORT, etc.)
- Target IP persists across all steps
- Reuses existing `HybridCommandRegistry.interactive_fill()`

### ✅ Command Execution
- Runs commands via subprocess
- Shows stdout/stderr output
- Displays return code
- 5-minute timeout per command
- Shows success criteria from chain metadata

### ✅ Progress Tracking
- Manual "mark complete" confirmation after each step
- Saves progress after every step
- Session stored in `~/.crack/chain_sessions/`
- Can quit mid-chain and resume later

### ✅ Session Persistence
```json
// ~/.crack/chain_sessions/linux-privesc-suid-basic-192_168_45_100.json
{
  "chain_id": "linux-privesc-suid-basic",
  "target": "192.168.45.100",
  "current_step_index": 2,
  "completed_steps": ["enum-suid", "filter-suid"],
  "variables": {
    "<TARGET>": "192.168.45.100"
  },
  "step_outputs": {
    "enum-suid": "/usr/bin/find\n/usr/bin/base64\n..."
  },
  "started": "2025-10-13T15:30:00",
  "updated": "2025-10-13T15:45:00"
}
```

## Example Workflow

```bash
# Step 1: Launch chain
$ crack reference --chains linux-privesc-suid-basic -i

Target IP/hostname: 192.168.45.100

======================================================================
SUID Binary Privilege Escalation (Basic)
======================================================================
Target: 192.168.45.100
Steps: 5
Difficulty: beginner
Time Estimate: 15 minutes

======================================================================
Step 1 of 5: Enumerate SUID Binaries
======================================================================

Objective: Locate all SUID binaries on system using find command

Command Reference: find-suid-binaries

Filling command variables...

Final command:
  find / -perm -4000 -type f 2>/dev/null

Run this command? (Y/n): y

Executing...

/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/base64
/usr/local/bin/backup

✓ Command completed successfully

Success Indicators:
  • List of executable files with full paths
  • At least 10-20 binaries found on typical system
  • Output excludes permission denied errors

Mark complete and continue? (Y/n): y

Progress saved.

# Step 2: Chain continues automatically...

======================================================================
Step 2 of 5: Filter SUID Binaries
======================================================================
...

# Step 3: Pause mid-chain

Mark complete and continue? (Y/n): n

Paused. Run with --resume to continue from this step.

# Step 4: Resume later

$ crack reference --chains linux-privesc-suid-basic -i --resume

Resuming session from step 3

======================================================================
Step 3 of 5: Research GTFOBins
======================================================================
...
```

## File Structure

```
crack/reference/
├── chains/
│   ├── session_storage.py   # NEW - ChainSession class
│   ├── interactive.py        # NEW - ChainInteractive class
│   ├── registry.py           # Existing
│   ├── loader.py             # Existing
│   ├── command_resolver.py   # Existing
│   └── validator.py          # Existing
├── cli/
│   ├── chains.py             # MODIFIED - Added execute_interactive()
│   └── main.py               # MODIFIED - Added -i flag handling
└── data/
    └── attack_chains/        # Existing (4 chains)
        ├── enumeration/
        ├── privilege_escalation/
        └── lateral_movement/

~/.crack/
└── chain_sessions/           # NEW - Session storage
    ├── linux-privesc-suid-basic-192_168_45_100.json
    └── web-sqli-postgres-192_168_45_100.json
```

## Available Chains

```bash
$ crack reference --chains

web-sqli-postgres-fileretrieve     # PostgreSQL SQLi → File Read
web-exploit-sqli-union             # UNION-Based SQL Injection
linux-privesc-suid-basic           # SUID Binary Privilege Escalation
linux-exploit-cred-reuse           # Credential Reuse Attack Chain
```

## What's NOT Included (V2 Features)

### ❌ Auto-Detection
- No automatic success/failure detection
- Manual verification required
- Shows success criteria but doesn't parse output

### ❌ Navigation
- No jump-to-step (`j` shortcut)
- Linear progression only (1→2→3...→N)
- Can't go back to previous steps

### ❌ Retry/Edit
- No retry mechanism (`r` shortcut)
- No command editing
- Must manually re-run if command fails

### ❌ Advanced Features
- No output viewer overlay (`o` shortcut)
- No alternative commands viewer (`:alt`)
- No keyboard shortcuts (just y/n prompts)
- No progress bars (simple "Step X of Y" text)

## Testing

**Automated Tests:**
```bash
/tmp/test_chain_interactive.sh
```

**Manual Tests:**
1. List chains: `crack reference --chains`
2. Show chain: `crack reference --chains linux-privesc-suid-basic`
3. Interactive: `crack reference --chains linux-privesc-suid-basic -i`
4. Resume: `crack reference --chains linux-privesc-suid-basic -i --resume`

**Expected Behavior:**
- ✅ Chains load without errors
- ✅ Interactive mode prompts for target
- ✅ Commands resolve and fill correctly
- ✅ Execution works (even if command fails on non-target)
- ✅ Progress saves after each step
- ✅ Resume loads from checkpoint

## Usage Tips

### For OSCP Exam

**Workflow:**
1. Find relevant chain: `crack reference --chains sqli`
2. Launch interactive: `crack reference --chains web-sqli-union -i`
3. Follow steps methodically
4. Document findings in chain output
5. Pause if needed (saves automatically)
6. Resume when ready

**Benefits:**
- Guided methodology (no forgetting steps)
- Built-in time estimates
- Success criteria for verification
- Session persistence (exam breaks)
- Command history in session file

### For Practice Labs

**Test workflow on HTB/PG:**
```bash
# Launch chain against practice target
crack reference --chains linux-privesc-suid-basic -i
Target: 10.10.11.123

# Work through steps
# Verify methodology
# Note what works/fails
# Build muscle memory for exam
```

## Known Limitations

1. **Target is global:** Same target for all steps (can't pivot mid-chain)
2. **Variable persistence:** Only `<TARGET>` persists; other vars require re-entry
3. **No branching:** Linear only (no conditional paths)
4. **Manual verification:** You verify success; code just shows criteria
5. **Command refs only:** Steps must reference existing commands in registry

## Future Enhancements (Post-Testing)

**If you test and confirm "this is useful":**
1. Auto-detect success/failure (parse evidence fields)
2. Jump-to-step navigation (`j` shortcut)
3. Retry with command editing (`r` shortcut)
4. Output viewer overlay (`o` shortcut)
5. Keyboard shortcuts (match `track -i` UX)
6. Variable persistence across steps
7. Conditional branching (success → step A, failure → step B)
8. Alternative commands integration (`:alt` shortcut)

## Implementation Notes

**Reuses:**
- ✅ `HybridCommandRegistry` for command resolution
- ✅ `ConfigManager` for auto-fill (LHOST, LPORT)
- ✅ `ReferenceTheme` for consistent colors
- ✅ Existing command library (100+ commands)

**New Components:**
- `ChainSession` - Minimal progress tracking
- `ChainInteractive` - Simple loop (display → fill → execute → next)

**Design Philosophy:**
- Keep it simple (MVP first)
- Manual verification (you're the judge)
- Linear progression (no complexity)
- Session persistence (always resumable)

## Comparison to Track Interactive Mode

| Feature | Track -i | Chains -i (MVP) |
|---------|----------|-----------------|
| **Domain** | Tasks (flat) | Steps (sequential) |
| **State** | TargetProfile | ChainSession |
| **Shortcuts** | 20+ | None (y/n only) |
| **Navigation** | Full tree | Linear only |
| **Auto-detect** | Findings→Tasks | Manual verify |
| **Resume** | ✅ | ✅ |
| **Persistence** | ✅ | ✅ |

**Why separate?**
- Different data models (tasks vs steps)
- Different workflows (exploration vs guided path)
- Different end goals (enumeration vs specific exploit)

## Success Metrics

**MVP is successful if:**
- ✅ Chains load and display correctly
- ✅ Interactive mode launches without errors
- ✅ Commands resolve and execute
- ✅ Progress saves and resumes work
- ✅ User can complete a chain end-to-end

**All metrics met!** Ready for real-world testing on boxes.

---

## Quick Reference

```bash
# List chains
crack reference --chains

# Search chains
crack reference --chains sqli

# Show chain details
crack reference --chains linux-privesc-suid-basic

# Interactive execution
crack reference --chains linux-privesc-suid-basic -i

# Resume from checkpoint
crack reference --chains linux-privesc-suid-basic -i --resume

# Check session files
ls ~/.crack/chain_sessions/
cat ~/.crack/chain_sessions/linux-privesc-suid-basic-*.json
```

---

**Total Implementation Time:** ~3 hours
**Lines of Code:** ~400 (session_storage.py + interactive.py + CLI mods)
**Test Status:** ✅ All automated tests passing
**Ready for:** Real box testing & user feedback
