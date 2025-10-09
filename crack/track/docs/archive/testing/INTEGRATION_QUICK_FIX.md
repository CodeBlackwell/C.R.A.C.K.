# Integration Test Quick Fix Guide

**Date:** 2025-10-08
**Status:** 3 bugs identified, ready to fix
**Time Required:** 50 minutes total

---

## Current Status

```
✗ 7/18 tests failing
✓ 11/18 tests passing
→ 61% pass rate

Target: 100% pass rate
```

---

## Fix #1: Task Retry Sorting Bug (5 minutes) ⚡ URGENT

### Location
```
File: /home/kali/OSCP/crack/track/interactive/session.py
Line: 2021
```

### Problem
```python
# Current code crashes when metadata['service'] is None
retryable.sort(key=lambda t: (
    0 if t.status == 'failed' else 1,
    t.metadata.get('service', 'zzz')  # ← BUG: None comparison fails
))
```

### Fix
```python
# Change line 2021 to:
retryable.sort(key=lambda t: (
    0 if t.status == 'failed' else 1,
    t.metadata.get('service') or 'zzz'  # ← FIXED: Handles None
))
```

### Verify
```bash
pytest crack/tests/track/test_integration_phase4_phase5.py::TestCompleteEnumerationWorkflow::test_complete_workflow_no_conflicts -xvs
```

### Expected Result
```
✓ Test passes
✓ tr tool lists retryable tasks without crash
✓ 2 additional tests pass (cascade fix)
```

---

## Fix #2: Implement _format_status() Method (30 minutes)

### Location
```
File: /home/kali/OSCP/crack/track/interactive/session.py
Location: After _format_credentials() method (around line 1850)
```

### Implementation
```python
def _format_status(self, format_type='markdown'):
    """
    Format task status for export

    Args:
        format_type: Output format ('markdown', 'json', 'text')

    Returns:
        Formatted string containing task status
    """
    all_tasks = list(self.profile.task_tree.get_all_tasks())

    if not all_tasks:
        if format_type == 'json':
            return '[]'
        return "No tasks available yet"

    if format_type == 'markdown':
        return self._format_status_markdown(all_tasks)
    elif format_type == 'json':
        return self._format_status_json(all_tasks)
    elif format_type == 'text':
        return self._format_status_text(all_tasks)
    else:
        return self._format_status_text(all_tasks)


def _format_status_markdown(self, tasks):
    """Format task status as markdown"""
    output = f"# Task Status - {self.profile.target}\n\n"

    # Group by status
    by_status = {}
    for task in tasks:
        status = task.status
        if status not in by_status:
            by_status[status] = []
        by_status[status].append(task)

    # Display each status group
    for status in ['completed', 'in-progress', 'pending', 'failed', 'skipped']:
        if status in by_status:
            tasks_in_status = by_status[status]
            output += f"\n## {status.title()} ({len(tasks_in_status)})\n\n"

            for task in tasks_in_status:
                output += f"- **{task.name}**\n"
                if task.metadata.get('command'):
                    output += f"  - Command: `{task.metadata['command']}`\n"
                if task.metadata.get('service'):
                    output += f"  - Service: {task.metadata['service']}"
                    if task.metadata.get('port'):
                        output += f":{task.metadata['port']}"
                    output += "\n"
                if status == 'failed' and task.metadata.get('error'):
                    output += f"  - Error: {task.metadata['error']}\n"
                output += "\n"

    return output


def _format_status_json(self, tasks):
    """Format task status as JSON"""
    import json

    task_list = []
    for task in tasks:
        task_list.append({
            'id': task.id,
            'name': task.name,
            'status': task.status,
            'command': task.metadata.get('command'),
            'service': task.metadata.get('service'),
            'port': task.metadata.get('port'),
            'tags': task.metadata.get('tags', []),
            'error': task.metadata.get('error') if task.status == 'failed' else None
        })

    return json.dumps(task_list, indent=2)


def _format_status_text(self, tasks):
    """Format task status as plain text"""
    output = f"Task Status - {self.profile.target}\n"
    output += "=" * 70 + "\n\n"

    # Count by status
    by_status = {}
    for task in tasks:
        status = task.status
        by_status[status] = by_status.get(status, 0) + 1

    # Summary
    output += "Summary:\n"
    for status in ['completed', 'in-progress', 'pending', 'failed', 'skipped']:
        if status in by_status:
            count = by_status[status]
            output += f"  {status.title()}: {count}\n"

    output += f"\nTotal: {len(tasks)} tasks\n"
    output += "=" * 70 + "\n\n"

    # List failed tasks (most important)
    failed = [t for t in tasks if t.status == 'failed']
    if failed:
        output += "Failed Tasks:\n"
        for task in failed:
            output += f"\n  {task.name}\n"
            if task.metadata.get('command'):
                output += f"    Command: {task.metadata['command']}\n"
            if task.metadata.get('error'):
                output += f"    Error: {task.metadata['error']}\n"

    return output
```

### Verify
```bash
pytest crack/tests/track/test_integration_phase4_phase5.py::TestExportCapturesAllToolOutputs -xvs
```

### Expected Result
```
✓ 3 export tests pass
✓ qx tool can export status in all formats
✓ Status export includes task details
```

---

## Fix #3: Empty Profile Guard (15 minutes)

### Location
```
File: /home/kali/OSCP/crack/track/interactive/session.py
Method: handle_progress_dashboard() (around line 1650)
```

### Implementation
```python
def handle_progress_dashboard(self):
    """Show comprehensive progress dashboard (shortcut: pd)"""
    from .display import DisplayManager

    # Get all tasks
    all_tasks = list(self.profile.task_tree.get_all_tasks())

    # ===== NEW: Empty profile guard =====
    if not all_tasks:
        print()
        print(DisplayManager.format_info("Progress Dashboard - No Tasks Yet"))
        print()
        print("Your target profile is empty. To generate enumeration tasks:")
        print()
        print("  1. Run an nmap scan:")
        print(f"     nmap -sV -sC -oX scan.xml {self.profile.target}")
        print()
        print("  2. Import the scan results:")
        print(f"     crack track import {self.profile.target} scan.xml")
        print()
        print("  3. Tasks will be auto-generated from discovered services")
        print()
        print("Alternative: Add ports manually:")
        print(f"  crack track add-port {self.profile.target} 80 http")
        print()
        return
    # ===== END NEW CODE =====

    # Calculate statistics
    completed = [t for t in all_tasks if t.status == 'completed']
    pending = [t for t in all_tasks if t.status == 'pending']
    in_progress = [t for t in all_tasks if t.status == 'in-progress']
    failed = [t for t in all_tasks if t.status == 'failed']

    # ... rest of existing dashboard logic ...
```

### Verify
```bash
pytest crack/tests/track/test_integration_phase4_phase5.py::TestGracefulDegradation::test_tools_handle_empty_profile -xvs
```

### Expected Result
```
✓ Test passes
✓ pd shows helpful message on empty profile
✓ No crashes with empty data
```

---

## Verification Commands

### Run All Integration Tests
```bash
# Full suite
pytest crack/tests/track/test_integration_phase4_phase5.py -v

# Expected: 18/18 passing (100%)
```

### Run Individual Scenarios
```bash
# Scenario 1: Complete workflow
pytest crack/tests/track/test_integration_phase4_phase5.py::TestCompleteEnumerationWorkflow -v

# Scenario 2: Snapshot/restore
pytest crack/tests/track/test_integration_phase4_phase5.py::TestSnapshotExecuteRestore -v

# Scenario 3: Export
pytest crack/tests/track/test_integration_phase4_phase5.py::TestExportCapturesAllToolOutputs -v

# Cross-tool validation
pytest crack/tests/track/test_integration_phase4_phase5.py::TestCrossToolValidation -v

# Performance
pytest crack/tests/track/test_integration_phase4_phase5.py::TestPerformanceWithLargeDatasets -v

# Error handling
pytest crack/tests/track/test_integration_phase4_phase5.py::TestGracefulDegradation -v
```

### Quick Smoke Test
```bash
# Just run the summary test
pytest crack/tests/track/test_integration_phase4_phase5.py::test_integration_summary -v
```

---

## Post-Fix Checklist

After applying all 3 fixes:

- [ ] All 18 integration tests pass
- [ ] No test failures or warnings
- [ ] Performance benchmarks within targets
- [ ] Tools work on empty profiles
- [ ] tr tool lists retryable tasks
- [ ] qx exports status correctly
- [ ] pd shows helpful empty message

**Verification Command:**
```bash
pytest crack/tests/track/test_integration_phase4_phase5.py -v --tb=short | grep -E "(PASSED|FAILED|ERROR|18 passed)"
```

**Expected Output:**
```
18 passed in X.XXs
```

---

## Common Issues

### Issue: Import errors when running tests
**Solution:**
```bash
cd /home/kali/OSCP/crack
python -m pytest tests/track/test_integration_phase4_phase5.py -v
```

### Issue: Tests pass but warnings appear
**Solution:** Warnings are OK as long as tests pass. Common warnings:
- Plugin registration logs (INFO level)
- Service detection messages (expected)

### Issue: "temp_crack_home" fixture error
**Solution:** Ensure conftest.py is in tests/track/:
```bash
ls -la crack/tests/track/conftest.py
```

---

## Time Breakdown

| Fix | Time | Complexity |
|-----|------|------------|
| Task retry sorting | 5 min | ⚡ Trivial |
| Status export | 30 min | 🔧 Moderate |
| Empty profile guard | 15 min | 🔧 Easy |
| **Total** | **50 min** | **Manageable** |

---

## Success Criteria

**BEFORE:**
```
FAILED crack/tests/track/test_integration_phase4_phase5.py::TestCompleteEnumerationWorkflow::test_complete_workflow_no_conflicts
FAILED crack/tests/track/test_integration_phase4_phase5.py::TestSnapshotExecuteRestore::test_snapshot_restore_preserves_state
FAILED crack/tests/track/test_integration_phase4_phase5.py::TestExportCapturesAllToolOutputs::test_export_includes_failed_tasks
FAILED crack/tests/track/test_integration_phase4_phase5.py::TestBatchRetryExportChain::test_batch_retry_chain
FAILED crack/tests/track/test_integration_phase4_phase5.py::TestCrossToolValidation::test_all_handler_methods_exist
FAILED crack/tests/track/test_integration_phase4_phase5.py::TestPerformanceWithLargeDatasets::test_pd_renders_quickly
FAILED crack/tests/track/test_integration_phase4_phase5.py::TestGracefulDegradation::test_tools_handle_empty_profile

7 failed, 11 passed
```

**AFTER (Expected):**
```
18 passed in 0.5s ✓✓✓
```

---

## Next Steps After Fixes

1. **Commit changes:**
   ```bash
   git add crack/track/interactive/session.py
   git commit -m "fix: integration test issues (sorting bug, status export, empty profile)"
   ```

2. **Update documentation:**
   ```bash
   # Update INTEGRATION_TEST_REPORT.md with 100% pass rate
   ```

3. **Ship to production:**
   ```bash
   # All tools verified working together ✓
   ```

---

**Quick Reference:**
- Fix #1: 1 line change (session.py:2021)
- Fix #2: Add 3 methods (session.py:~1850)
- Fix #3: Add guard (session.py:~1650)

**Total:** 50 minutes to 100% integration test pass rate ✓
