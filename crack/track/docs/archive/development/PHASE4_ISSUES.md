# Phase 4 Tools - Issues Tracker

**Last Updated:** 2025-10-08
**Status:** 26 failing tests across 5 tools

---

## Issue #1: Progress Dashboard Not Implemented

**Tool:** pd (Progress Dashboard)
**Severity:** 🔴 CRITICAL - P0 BLOCKING
**Status:** OPEN
**Tests Affected:** 13/16

### Problem

The `handle_progress_dashboard()` method does not exist in `InteractiveSession`, causing all dashboard tests to fail.

```python
AttributeError: 'InteractiveSession' object has no attribute 'handle_progress_dashboard'
```

### Expected Behavior

Based on test expectations, the dashboard should:
1. Calculate overall progress percentage
2. Group tasks by service/port
3. Identify and count quick wins
4. Identify and count high-priority tasks
5. Display visual progress bar (using `█` and `░` characters)
6. Show status breakdown (completed, in-progress, pending, skipped)
7. Display current enumeration phase
8. Show next recommended task

### Current Behavior

Method does not exist. Shortcut infrastructure is in place but handler is missing.

### Location

File: `/home/kali/OSCP/crack/track/interactive/session.py`

### Failing Tests

1. `test_progress_zero_percent_no_tasks` - Shows 0% when no tasks
2. `test_progress_zero_percent_with_tasks` - Shows 0% with pending tasks
3. `test_progress_fifty_percent` - Calculates 50% correctly
4. `test_progress_one_hundred_percent` - Shows 100% when all complete
5. `test_groups_by_service_port` - Groups by service and port
6. `test_single_service_no_breakdown` - No breakdown for single service
7. `test_detects_quick_wins` - Counts QUICK_WIN tagged tasks
8. `test_detects_high_priority` - Counts OSCP:HIGH tagged tasks
9. `test_no_quick_wins_message` - Shows message when none exist
10. `test_progress_bar_renders` - Renders block characters
11. `test_status_breakdown_displayed` - Shows all statuses
12. `test_shows_current_phase` - Displays current phase
13. `test_shows_next_recommended` - Shows next task if available

### Proposed Fix

Implement `handle_progress_dashboard()` method with the following structure:

```python
def handle_progress_dashboard(self):
    """Display comprehensive progress dashboard for OSCP tracking"""
    print(DisplayManager.format_section_header("Progress Dashboard"))

    # 1. Calculate overall progress
    all_tasks = self.profile.task_tree.get_all_tasks()
    completed = [t for t in all_tasks if t.status == 'completed']
    total = len(all_tasks)

    if total == 0:
        print(DisplayManager.format_info("No tasks available yet"))
        return

    percentage = int((len(completed) / total) * 100)

    # 2. Render progress bar (10 chars wide)
    filled = int(percentage / 10)
    bar = '█' * filled + '░' * (10 - filled)
    print(f"\nOverall Progress: [{bar}] {percentage}%")
    print(f"Tasks: {len(completed)}/{total}\n")

    # 3. Status breakdown
    statuses = {}
    for task in all_tasks:
        statuses[task.status] = statuses.get(task.status, 0) + 1

    print(DisplayManager.format_subsection("Status Breakdown"))
    for status, count in statuses.items():
        status_display = status.replace('-', ' ').title()
        print(f"  {status_display}: {count}")

    # 4. Group by service (if multiple services)
    services = {}
    for task in all_tasks:
        service = task.metadata.get('service', 'general')
        port = task.metadata.get('port', '')
        key = f"{service}-{port}" if port else service

        if key not in services:
            services[key] = {'total': 0, 'completed': 0}

        services[key]['total'] += 1
        if task.status == 'completed':
            services[key]['completed'] += 1

    if len(services) > 1:
        print(DisplayManager.format_subsection("By Service"))
        for svc, stats in services.items():
            svc_pct = int((stats['completed'] / stats['total']) * 100)
            print(f"  {svc}: {svc_pct}% ({stats['completed']}/{stats['total']})")

    # 5. Quick wins and priorities
    quick_wins = [t for t in all_tasks
                  if 'QUICK_WIN' in t.metadata.get('tags', [])
                  and t.status == 'pending']

    high_priority = [t for t in all_tasks
                     if 'OSCP:HIGH' in t.metadata.get('tags', [])
                     and t.status != 'completed']

    if quick_wins:
        print(DisplayManager.format_subsection("Quick Wins"))
        print(f"  {len(quick_wins)} remaining")

    if high_priority:
        print(DisplayManager.format_subsection("High Priority"))
        print(f"  {len(high_priority)} pending")

    # 6. Current phase
    print(DisplayManager.format_subsection("Phase"))
    phase_display = self.profile.phase.replace('-', ' ').title()
    print(f"  {phase_display}")

    # 7. Next recommended task
    from crack.track.recommendations.engine import RecommendationEngine
    recommendations = RecommendationEngine.get_recommendations(self.profile)

    if recommendations.get('next'):
        next_task = recommendations['next']
        print(DisplayManager.format_subsection("Next Recommended"))
        print(f"  {next_task.name}")

    print()  # Blank line at end

    self.last_action = "Viewed progress dashboard"
```

### Estimated Effort

**4-6 hours**
- Implementation: 2-3 hours
- Test verification: 1-2 hours
- Edge case handling: 1 hour

### Dependencies

- `DisplayManager` from `crack.track.interactive.display`
- `RecommendationEngine` from `crack.track.recommendations.engine`

### Success Criteria

- All 13 failing tests pass
- Dashboard displays all required sections
- Visual progress bar renders correctly
- Quick wins and priorities counted accurately

---

## Issue #2: Session Snapshot Test Isolation Failure

**Tool:** ss (Session Snapshot)
**Severity:** 🔴 CRITICAL - P0 BLOCKING
**Status:** OPEN
**Tests Affected:** 11/16

### Problem

Snapshot tests fail because snapshots persist across test runs in `~/.crack/snapshots/`, causing assertion failures when tests expect specific counts.

```python
AssertionError: assert 62 == 1
# Expected 1 snapshot, found 62 from previous test runs
```

### Expected Behavior

Each test should run in isolation with a clean snapshot directory.

### Current Behavior

Snapshots accumulate across test runs, causing:
- `test_save_snapshot_basic`: Expected 1, found 4-65
- `test_list_snapshots_empty`: Expected 0, found 54+
- `test_list_snapshots_multiple`: Expected 3, found 58

### Location

File: `/home/kali/OSCP/crack/tests/track/test_session_snapshot.py`

### Root Cause

No cleanup fixture to clear snapshot directory before each test.

### Proposed Fix

Add cleanup fixture to test file:

```python
import shutil
from pathlib import Path

@pytest.fixture(autouse=True)
def clean_snapshots(temp_crack_home):
    """
    Clean snapshot directory before each test

    CRITICAL: Ensures test isolation by removing
    all snapshots from previous test runs.
    """
    # Clean before test
    snapshots_dir = Path.home() / '.crack' / 'snapshots'
    if snapshots_dir.exists():
        shutil.rmtree(snapshots_dir)
    snapshots_dir.mkdir(parents=True, exist_ok=True)

    yield

    # Clean after test (optional - before cleanup handles most cases)
    if snapshots_dir.exists():
        shutil.rmtree(snapshots_dir)
```

**Alternative:** Use unique temp directories per test:

```python
@pytest.fixture
def isolated_snapshot_dir(tmp_path, monkeypatch):
    """Create isolated snapshot directory for each test"""
    snapshot_dir = tmp_path / 'snapshots'
    snapshot_dir.mkdir()

    # Mock the snapshot directory path
    def mock_get_snapshots_dir(self):
        return snapshot_dir / self.target

    monkeypatch.setattr(
        'crack.track.interactive.session.InteractiveSession._get_snapshots_dir',
        mock_get_snapshots_dir
    )

    return snapshot_dir
```

### Estimated Effort

**1-2 hours**
- Add cleanup fixture: 30 minutes
- Verify all tests pass: 30-60 minutes
- Update test documentation: 30 minutes

### Failing Tests

1. `test_save_snapshot_basic` - Expected 1 snapshot
2. `test_save_snapshot_filename_format` - Expected 1 snapshot
3. `test_snapshot_metadata_complete` - Expected 1 snapshot
4. `test_list_snapshots_empty` - Expected 0 snapshots
5. `test_list_snapshots_multiple` - Expected 3 snapshots
6. `test_restore_snapshot` - Restore verification failing
7. `test_delete_snapshot` - Expected 1 snapshot
8. `test_snapshot_name_sanitization` - Expected 1 snapshot
9. `test_empty_snapshot_name_rejected` - Expected 0 snapshots
10. `test_snapshot_with_no_findings` - Expected 1 snapshot
11. `test_multiple_targets_isolated` - Expected 1 per target

### Success Criteria

- All tests pass consistently
- Tests can run in any order
- No test pollution between runs
- Snapshot counts match expectations

---

## Issue #3: Task Retry Doesn't Update Status

**Tool:** tr (Task Retry)
**Severity:** 🟠 HIGH - P1
**Status:** OPEN
**Tests Affected:** 1/17

### Problem

When a task is retried successfully, the task status is not updated from `failed` to `completed`.

```python
# Test expects:
assert failed_task.status == 'completed'

# Actual:
assert failed_task.status == 'failed'
```

### Expected Behavior

After successful retry (exit code 0), task status should be marked as `completed`.

### Current Behavior

Task metadata is updated (exit_code, retry_history) but status remains `failed`.

### Location

File: `/home/kali/OSCP/crack/track/interactive/session.py`
Method: `_retry_task(self, task, command=None)`

### Root Cause

Missing call to `task.mark_complete()` after successful execution.

### Proposed Fix

```python
def _retry_task(self, task, command=None):
    """Retry a task with optional command modification"""

    # ... existing code for command execution ...

    # Execute command
    exit_code, stdout, stderr = self._execute_command(final_command)

    # Update metadata
    task.metadata['exit_code'] = exit_code
    task.metadata['last_run'] = datetime.now().isoformat()

    # Add to retry history
    if 'retry_history' not in task.metadata:
        task.metadata['retry_history'] = []

    task.metadata['retry_history'].append({
        'timestamp': datetime.now().isoformat(),
        'command': final_command,
        'exit_code': exit_code,
        'success': exit_code == 0
    })

    # *** ADD THIS SECTION ***
    # Update task status based on exit code
    if exit_code == 0:
        task.mark_complete()  # Status -> 'completed'
        print(DisplayManager.format_success("Task completed successfully"))
    else:
        task.status = 'failed'  # Keep as failed
        print(DisplayManager.format_error(f"Task failed (exit code: {exit_code})"))
    # *** END NEW SECTION ***

    # Save profile
    self.profile.save()

    return exit_code == 0
```

### Estimated Effort

**30 minutes**
- Add status update: 10 minutes
- Test verification: 10 minutes
- Edge case testing: 10 minutes

### Failing Test

`test_handle_task_retry_full_workflow` - Full workflow doesn't update status

### Success Criteria

- Failed task becomes completed after successful retry
- Test passes consistently
- Profile saved with updated status

---

## Issue #4: Task Retry Sorting Incorrect

**Tool:** tr (Task Retry)
**Severity:** 🟡 MEDIUM - P2
**Status:** OPEN
**Tests Affected:** 1/17

### Problem

When listing retryable tasks, failed tasks should appear first, but completed tasks appear first instead.

```python
# Expected: retryable[0].status == 'failed'
# Actual: retryable[0].status == 'completed'
```

### Expected Behavior

Retryable tasks should be sorted with failed tasks first, then completed tasks.

### Current Behavior

Tasks appear to be sorted by creation time or some other criteria, not by status.

### Location

File: `/home/kali/OSCP/crack/track/interactive/session.py`
Method: `_get_retryable_tasks(self)`

### Root Cause

Sorting logic doesn't prioritize by status.

### Proposed Fix

```python
def _get_retryable_tasks(self):
    """
    Get list of tasks that can be retried

    Returns tasks sorted by:
    1. Failed tasks first (status = 'failed')
    2. Then completed tasks (status = 'completed')
    3. Within each group, sorted by last run timestamp (newest first)
    """
    all_tasks = self.profile.task_tree.get_all_tasks()

    # Filter to retryable tasks (failed or completed with commands)
    retryable = []
    for task in all_tasks:
        if task.type == 'command':  # Only command tasks are retryable
            if task.status == 'failed':
                retryable.append(task)
            elif task.status == 'completed' and task.metadata.get('command'):
                retryable.append(task)

    # Sort with failed first, then by timestamp
    def sort_key(task):
        # Failed tasks get priority 0, completed get priority 1
        status_priority = 0 if task.status == 'failed' else 1

        # Get timestamp (fallback to epoch if not available)
        timestamp = task.metadata.get('last_run', '1970-01-01T00:00:00')

        return (status_priority, timestamp)

    return sorted(retryable, key=sort_key, reverse=False)
```

### Estimated Effort

**15 minutes**
- Fix sort logic: 5 minutes
- Test verification: 5 minutes
- Documentation: 5 minutes

### Failing Test

`test_get_retryable_tasks_sorting` - Failed tasks not appearing first

### Success Criteria

- Failed tasks appear before completed tasks
- Within each group, tasks sorted by timestamp
- Test passes consistently

---

## Issue #5: Low Code Coverage Across All Tools

**Tool:** All (pd, ss, qe, qx, tr)
**Severity:** 🟡 MEDIUM - P2
**Status:** OPEN
**Impact:** Long-term code quality

### Problem

All Phase 4 tools have low code coverage (6-12%) compared to 95% target.

| Tool | Coverage | Gap to 95% |
|------|----------|------------|
| pd | 6% | 89% |
| ss | 7% | 88% |
| qe | 9% | 86% |
| qx | 11% | 84% |
| tr | 12% | 83% |

### Expected Behavior

Each tool should have 95%+ line coverage to ensure:
- All code paths tested
- Edge cases covered
- Regression protection
- Confidence in refactoring

### Current Behavior

Only happy-path scenarios tested. Many edge cases, error conditions, and alternative paths untested.

### Impact

- Potential bugs in untested code paths
- Difficult to refactor safely
- No regression protection
- Unknown behavior in edge cases

### Proposed Fix

**Incremental approach** - one tool at a time:

**Week 1: qe (Quick Execute)** - Already 100% test pass, easiest to improve
```python
# Add tests for:
- Long-running command interruption (Ctrl+C)
- Shell injection prevention
- Command size limits
- Background process handling
- Concurrent execution prevention
```

**Week 2: qx (Quick Export)** - Already 100% test pass
```python
# Add tests for:
- Large dataset performance (1000+ findings)
- Clipboard integration (xclip/xsel)
- Markdown escaping edge cases
- JSON schema validation
- Export file size limits
```

**Week 3: tr (Task Retry)** - Fix existing issues first
```python
# Add tests for:
- Concurrent retry prevention
- Retry history limits (max 10)
- Task tree structure preservation
- Placeholder preservation in commands
- Retry with modified commands
```

**Week 4: pd (Progress Dashboard)** - After implementation complete
```python
# Add tests for:
- Empty task tree edge cases
- 100% completion display
- Service grouping with many services
- Quick win edge cases
- Visual rendering accuracy
```

**Week 5: ss (Session Snapshot)** - After test isolation fixed
```python
# Add tests for:
- Snapshot corruption recovery
- Large profile performance (100+ tasks)
- Concurrent snapshot creation prevention
- Snapshot restore atomicity
- Cross-version compatibility
```

### Estimated Effort

**40-50 hours total**
- qe: 8-10 hours
- qx: 8-10 hours
- tr: 8-10 hours
- pd: 8-10 hours
- ss: 8-10 hours

### Success Criteria

- Each tool achieves 95%+ line coverage
- All critical paths tested
- Edge cases documented and tested
- Performance benchmarks established

---

## Priority Matrix

| Issue | Severity | Impact | Effort | Priority | Status |
|-------|----------|--------|--------|----------|--------|
| #1 pd Not Implemented | CRITICAL | Feature broken | 4-6h | **P0** | OPEN |
| #2 ss Test Isolation | CRITICAL | Tests failing | 1-2h | **P0** | OPEN |
| #3 tr Status Not Updated | HIGH | Workflow broken | 30min | **P1** | OPEN |
| #4 tr Sorting Incorrect | MEDIUM | UX degraded | 15min | **P2** | OPEN |
| #5 Low Coverage | MEDIUM | Long-term quality | 40-50h | **P2** | OPEN |

---

## Recommended Fix Order

**Sprint 1 (Week 1): Fix Blockers**
1. Issue #2: ss Test Isolation (1-2 hours) ← Quick win
2. Issue #4: tr Sorting (15 minutes) ← Quick win
3. Issue #3: tr Status Update (30 minutes) ← Quick win
4. Issue #1: pd Implementation (4-6 hours) ← Largest effort
5. **Milestone:** 100% tests passing

**Sprint 2-6 (Weeks 2-6): Improve Coverage**
6. Issue #5: Incremental coverage improvements (8-10 hours per tool)
7. **Milestone:** 95% coverage for all tools

---

## Testing Status Dashboard

```
PHASE 4 TOOLS TEST STATUS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

pd (Progress Dashboard)
├─ Tests: 16 | Pass: 3 | Fail: 13 | Coverage: 6%
├─ Status: ❌ CRITICAL - Feature not implemented
└─ Blockers: 1

ss (Session Snapshot)
├─ Tests: 16 | Pass: 5 | Fail: 11 | Coverage: 7%
├─ Status: ❌ CRITICAL - Test isolation broken
└─ Blockers: 1

qe (Quick Execute)
├─ Tests: 24 | Pass: 24 | Fail: 0 | Coverage: 9%
├─ Status: ✅ PRODUCTION READY
└─ Blockers: 0

qx (Quick Export)
├─ Tests: 27 | Pass: 27 | Fail: 0 | Coverage: 11%
├─ Status: ✅ PRODUCTION READY
└─ Blockers: 0

tr (Task Retry)
├─ Tests: 17 | Pass: 15 | Fail: 2 | Coverage: 12%
├─ Status: ⚠️ MINOR ISSUES
└─ Blockers: 0

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OVERALL: 100 tests | 74 pass | 26 fail | Avg: 9%
BLOCKERS: 2 | PRIORITY FIXES: 4 | ESTIMATED: 8-12h
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## Notes

- All issues verified through test execution on 2025-10-08
- Coverage reports available in `/home/kali/OSCP/crack/track/docs/coverage/`
- Test files location: `/home/kali/OSCP/crack/tests/track/`
- Implementation location: `/home/kali/OSCP/crack/track/interactive/session.py`
