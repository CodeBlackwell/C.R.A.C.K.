# QA Story 4: Profile Load from Disk (Event Handler Registration)

## Test Scenario

**Objective:** Verify that event handlers are registered when loading existing profiles from disk.

**Target Profile:** `qa-story-4-profile-load`

**Starting State:**
- Ports 80, 443 (pre-configured in JSON)
- Finding: `/admin` directory (pre-existing)
- Tests `from_dict()` → `_init_runtime()` fix

**Expected Results:**
- ✅ Profile loads with existing ports and findings
- ✅ Event handlers register on load
- ✅ Plugins can process existing data
- ✅ New ports/findings trigger events correctly

## Quick Start

```bash
./qa_profiles/run_qa_story.sh 4
```

## Test Steps

### 1. Launch TUI

```bash
crack track --tui qa-story-4-profile-load \
  --debug \
  --debug-categories=STATE:VERBOSE,EXECUTION:VERBOSE
```

### 2. Verify Pre-Existing Data Loaded

- Press `t` to view task tree
- Expected: HTTP tasks for ports 80 and 443
- Expected: Finding "/admin" in findings list

### 3. Verify Event Handlers Registered

**Expected Logs:**
```
_init_runtime() called
Event handlers registered successfully
EventBus listeners: service_detected, finding_added, task_completed
```

### 4. Test Dynamic Port Addition

**In TUI:**
- Add new port (8080) manually
- Verify: HTTP tasks generated for port 8080
- Confirms: Event handlers working after load

### 5. Exit and Verify

```bash
grep "_init_runtime" .debug_logs/tui_debug_*.log | head -3
grep "Event handlers registered" .debug_logs/tui_debug_*.log | tail -3
```

## Pass Criteria

- [x] Profile loads with existing ports 80, 443
- [x] Finding "/admin" present on load
- [x] `_init_runtime()` called during load
- [x] Event handlers registered successfully
- [x] HTTP tasks generated for existing ports
- [x] New ports trigger service_detected events
- [x] No "Error in event handler" messages

## Troubleshooting

**Issue:** Event handlers not registered after load

**Fix:** Ensure `TargetProfile.from_dict()` calls `_init_runtime()` at line 270+

**Debug:**
```bash
grep "from_dict" .debug_logs/tui_debug_*.log | tail -5
grep "_init_runtime" .debug_logs/tui_debug_*.log | tail -5
```

## Related Documentation

- `track/core/state.py:270` - from_dict() implementation
- `IMPLEMENTATION_COMPLETE.md` - Issue 1 fix details
