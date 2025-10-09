# Improvement Roadmap - Phase 4 & 5 Interactive Tools
**Ranked by Return on Investment (ROI)**

**Date**: 2025-10-08
**Status**: Production Deployment Planning

---

## ROI Calculation Framework

```
ROI = (Value × Frequency) / (Risk × Effort)

Value:     1-10 (how much better the tool becomes)
Frequency: 1-10 (how often this is used)
Risk:      1-10 (chance of breaking things)
Effort:    1-10 (hours to implement: 1-2h=1, 3-5h=2, etc.)

ROI > 5.0  = HIGH VALUE - Implement immediately
ROI 2.0-5.0 = MEDIUM VALUE - Consider for next sprint
ROI < 2.0  = LOW VALUE - Skip or defer
```

---

## Immediate Priority (ROI > 10)

### #1: Implement Progress Dashboard Handler

**Category**: Critical Bug Fix
**ROI**: **15.0**

**Problem**: Progress dashboard ('pd') shortcut registered but handler method missing

**Impact**: CRITICAL
- Users get `AttributeError` when pressing 'pd'
- 13 tests failing (18.8% pass rate for feature)
- Advertised feature is completely non-functional

**Current Behavior**:
```python
# shortcuts.py
'pd': ('Progress dashboard', 'progress_dashboard')

# session.py
# Missing: def handle_progress_dashboard(self):
```

**Proposed Fix**:
Add `handle_progress_dashboard()` method to `InteractiveSession` class in `session.py`:

```python
def handle_progress_dashboard(self):
    """Display progress dashboard (shortcut: pd)"""
    from ..formatters.console import ConsoleFormatter

    profile = self.profile

    # Calculate progress metrics
    all_tasks = profile.task_tree.get_all_tasks()
    if not all_tasks:
        print(DisplayManager.format_warning("No tasks available"))
        return

    total = len(all_tasks)
    completed = len([t for t in all_tasks if t.status == 'completed'])
    failed = len([t for t in all_tasks if t.status == 'failed'])
    in_progress = len([t for t in all_tasks if t.status == 'in-progress'])
    pending = len([t for t in all_tasks if t.status == 'pending'])

    progress_pct = (completed / total * 100) if total > 0 else 0

    # Render visual dashboard
    print("\n" + "=" * 60)
    print(f"Progress Dashboard - {profile.target}")
    print("=" * 60)
    print(f"\nPhase: {profile.phase}")
    print(f"Overall Progress: {progress_pct:.1f}% ({completed}/{total} tasks)")

    # ASCII progress bar
    bar_length = 20
    filled = int(progress_pct / 5)
    bar = '[' + '#' * filled + '-' * (bar_length - filled) + ']'
    print(f"\n{bar} {progress_pct:.0f}%")

    # Status breakdown
    print(f"\nStatus Breakdown:")
    print(f"  ✓ Completed: {completed}")
    print(f"  ⏳ In Progress: {in_progress}")
    print(f"  ⏸ Pending: {pending}")
    print(f"  ✗ Failed: {failed}")

    # Group by service (if multiple services)
    service_groups = {}
    for task in all_tasks:
        service = task.metadata.get('service', 'other')
        if service not in service_groups:
            service_groups[service] = {'total': 0, 'completed': 0}
        service_groups[service]['total'] += 1
        if task.status == 'completed':
            service_groups[service]['completed'] += 1

    if len(service_groups) > 1:
        print(f"\nProgress by Service:")
        for service, stats in sorted(service_groups.items()):
            svc_pct = (stats['completed'] / stats['total'] * 100) if stats['total'] > 0 else 0
            print(f"  {service}: {svc_pct:.0f}% ({stats['completed']}/{stats['total']})")

    # Highlight quick wins
    quick_wins = [t for t in all_tasks
                  if t.status == 'pending'
                  and 'QUICK_WIN' in t.metadata.get('tags', [])]

    if quick_wins:
        print(f"\n⚡ Quick Wins Available: {len(quick_wins)}")
        for task in quick_wins[:3]:
            print(f"  • {task.name}")

    # High priority pending tasks
    high_priority = [t for t in all_tasks
                     if t.status == 'pending'
                     and 'OSCP:HIGH' in t.metadata.get('tags', [])]

    if high_priority:
        print(f"\n🔴 High Priority: {len(high_priority)} task(s)")

    # Next recommended task
    from ..recommendations.engine import RecommendationEngine
    recommendations = RecommendationEngine.get_recommendations(profile)
    next_task = recommendations.get('next')

    if next_task:
        print(f"\n📌 Next Recommended:")
        print(f"  {next_task.name}")
        if next_task.metadata.get('estimated_time'):
            print(f"  Time: {next_task.metadata['estimated_time']}")

    print("\n" + "=" * 60 + "\n")
```

**ROI Calculation**:
- **Value**: 10 (restores critical feature to working state)
- **Frequency**: 9 (users check progress constantly during OSCP exam)
- **Risk**: 1 (read-only display, no state modification)
- **Effort**: 2 (1-2 hours to implement and test)

**ROI = (10 × 9) / (1 × 2) = 45.0** ✓ **CRITICAL PRIORITY**

**Implementation Checklist**:
- [ ] Add method to `session.py` (line ~3800)
- [ ] Import `RecommendationEngine`
- [ ] Run tests: `pytest crack/tests/track/test_progress_dashboard.py -v`
- [ ] Manual test: `crack track -i TARGET`, press 'pd'
- [ ] Verify all 13 tests pass

**Estimated Effort**: 1-2 hours
**Risk Level**: LOW
**Dependencies**: None

---

### #2: Fix Session Snapshot Save/Restore

**Category**: Feature Completion
**ROI**: **12.5**

**Problem**: Session snapshot functionality incomplete - save/restore unreliable

**Impact**: HIGH
- 11 tests failing (31.3% pass rate)
- Users cannot reliably save/restore session state
- Data loss risk during long enumeration sessions

**Issues Identified**:
1. `save_snapshot()` filename format incorrect
2. `list_snapshots()` returns wrong data structure (list vs dict)
3. Snapshot metadata incomplete
4. Filename sanitization missing
5. Empty snapshot names not rejected

**Proposed Fix**:

**File**: `session.py`, method `handle_session_snapshot()`

```python
def handle_session_snapshot(self):
    """Session snapshot manager (shortcut: ss)"""
    from datetime import datetime
    import re

    print(DisplayManager.format_info("Session Snapshot Manager"))
    print("\nOptions:")
    print("  1. Save current session")
    print("  2. List saved snapshots")
    print("  3. Restore snapshot")
    print("  4. Delete snapshot")
    print("  5. Cancel")

    choice = input("\nSelect [1-5]: ").strip()

    if choice == '1':
        # Save snapshot
        name = input("Snapshot name: ").strip()

        # Validate and sanitize name
        if not name:
            print(DisplayManager.format_error("Snapshot name cannot be empty"))
            return

        # Sanitize filename (remove invalid chars)
        sanitized_name = re.sub(r'[^\w\s-]', '', name).strip()
        sanitized_name = re.sub(r'[-\s]+', '-', sanitized_name)

        if not sanitized_name:
            print(DisplayManager.format_error("Invalid snapshot name"))
            return

        # Create snapshot directory
        snapshot_dir = self.crack_home / 'sessions' / self.target / 'snapshots'
        snapshot_dir.mkdir(parents=True, exist_ok=True)

        # Generate filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{sanitized_name}_{timestamp}.json"
        snapshot_file = snapshot_dir / filename

        # Build snapshot data
        snapshot_data = {
            'name': name,
            'target': self.target,
            'timestamp': timestamp,
            'phase': self.profile.phase,
            'profile_data': {
                'ports': self.profile.ports,
                'findings': self.profile.findings,
                'credentials': self.profile.credentials,
                'notes': self.profile.notes,
                'task_tree': self.profile.task_tree.to_dict()
            },
            'session_state': {
                'last_action': self.last_action,
                'start_time': self.start_time
            }
        }

        # Save to file
        snapshot_file.write_text(json.dumps(snapshot_data, indent=2))

        print(DisplayManager.format_success(
            f"Snapshot saved: {filename}"
        ))

    elif choice == '2':
        # List snapshots
        snapshot_dir = self.crack_home / 'sessions' / self.target / 'snapshots'

        if not snapshot_dir.exists():
            print(DisplayManager.format_warning("No snapshots found"))
            return

        snapshots = []
        for file in snapshot_dir.glob('*.json'):
            try:
                data = json.loads(file.read_text())
                snapshots.append({
                    'filename': file.name,
                    'name': data.get('name', 'Unknown'),
                    'timestamp': data.get('timestamp', 'Unknown'),
                    'phase': data.get('phase', 'Unknown')
                })
            except Exception as e:
                continue

        if not snapshots:
            print(DisplayManager.format_warning("No valid snapshots found"))
            return

        # Display snapshots
        print(f"\nSnapshots for {self.target}:")
        for i, snap in enumerate(snapshots, 1):
            print(f"  {i}. {snap['name']} ({snap['timestamp']}) - Phase: {snap['phase']}")

    elif choice == '3':
        # Restore snapshot
        snapshot_dir = self.crack_home / 'sessions' / self.target / 'snapshots'

        if not snapshot_dir.exists():
            print(DisplayManager.format_warning("No snapshots found"))
            return

        # List snapshots first
        snapshots = []
        for file in sorted(snapshot_dir.glob('*.json')):
            try:
                data = json.loads(file.read_text())
                snapshots.append({
                    'filename': file.name,
                    'filepath': file,
                    'name': data.get('name', 'Unknown'),
                    'timestamp': data.get('timestamp', 'Unknown')
                })
            except Exception:
                continue

        if not snapshots:
            print(DisplayManager.format_warning("No valid snapshots found"))
            return

        # Display options
        for i, snap in enumerate(snapshots, 1):
            print(f"  {i}. {snap['name']} ({snap['timestamp']})")

        # Get selection
        selection = input("\nSelect snapshot [1-{}]: ".format(len(snapshots))).strip()

        try:
            idx = int(selection) - 1
            if 0 <= idx < len(snapshots):
                selected = snapshots[idx]

                # Load snapshot
                snapshot_data = json.loads(selected['filepath'].read_text())

                # Restore profile data
                self.profile.ports = snapshot_data['profile_data']['ports']
                self.profile.findings = snapshot_data['profile_data']['findings']
                self.profile.credentials = snapshot_data['profile_data']['credentials']
                self.profile.notes = snapshot_data['profile_data']['notes']

                # Restore task tree
                from ..core.task_tree import TaskNode
                self.profile.task_tree = TaskNode.from_dict(
                    snapshot_data['profile_data']['task_tree']
                )

                # Save restored profile
                self.profile.save()

                print(DisplayManager.format_success(
                    f"Snapshot restored: {selected['name']}"
                ))
            else:
                print(DisplayManager.format_error("Invalid selection"))
        except ValueError:
            print(DisplayManager.format_error("Invalid input"))

    elif choice == '4':
        # Delete snapshot (similar to restore, but delete file)
        snapshot_dir = self.crack_home / 'sessions' / self.target / 'snapshots'

        if not snapshot_dir.exists():
            print(DisplayManager.format_warning("No snapshots found"))
            return

        snapshots = []
        for file in sorted(snapshot_dir.glob('*.json')):
            try:
                data = json.loads(file.read_text())
                snapshots.append({
                    'filename': file.name,
                    'filepath': file,
                    'name': data.get('name', 'Unknown'),
                    'timestamp': data.get('timestamp', 'Unknown')
                })
            except Exception:
                continue

        if not snapshots:
            print(DisplayManager.format_warning("No valid snapshots found"))
            return

        for i, snap in enumerate(snapshots, 1):
            print(f"  {i}. {snap['name']} ({snap['timestamp']})")

        selection = input("\nSelect snapshot to delete [1-{}]: ".format(len(snapshots))).strip()

        try:
            idx = int(selection) - 1
            if 0 <= idx < len(snapshots):
                selected = snapshots[idx]

                # Confirm deletion
                confirm = input(DisplayManager.format_confirmation(
                    f"Delete '{selected['name']}'?", default='N'
                ))

                from .input_handler import InputProcessor
                if InputProcessor.parse_confirmation(confirm, default='N'):
                    selected['filepath'].unlink()
                    print(DisplayManager.format_success("Snapshot deleted"))
                else:
                    print("Cancelled")
            else:
                print(DisplayManager.format_error("Invalid selection"))
        except ValueError:
            print(DisplayManager.format_error("Invalid input"))
```

**ROI Calculation**:
- **Value**: 10 (critical for long sessions, prevents data loss)
- **Frequency**: 5 (used during multi-hour OSCP exam sessions)
- **Risk**: 2 (file operations, but well-tested)
- **Effort**: 4 (3-4 hours to implement all fixes)

**ROI = (10 × 5) / (2 × 4) = 6.25** ✓ **HIGH PRIORITY**

**Implementation Checklist**:
- [ ] Update `handle_session_snapshot()` method
- [ ] Add filename sanitization with `re.sub()`
- [ ] Fix data structure for list/restore
- [ ] Add empty name validation
- [ ] Run tests: `pytest crack/tests/track/test_session_snapshot.py -v`
- [ ] Manual test with real snapshots
- [ ] Verify all 16 tests pass

**Estimated Effort**: 3-4 hours
**Risk Level**: MEDIUM (file I/O operations)
**Dependencies**: None

---

## Short-Term Priority (ROI 5-10)

### #3: Add Progress Bar to Batch Execute

**Category**: UX Enhancement
**ROI**: **8.0**

**Problem**: Long batch executions show no progress feedback

**Impact**: MEDIUM
- Users uncertain if batch is frozen or running
- No ETA for completion
- Poor UX during multi-minute batches

**Current Behavior**:
```
Executing batch (10 tasks)...
[Long pause with no feedback]
Batch completed: 8 succeeded, 2 failed
```

**Proposed Fix**:
Add real-time progress bar using built-in terminal output:

```python
def _execute_batch(self, steps: List[List[TaskNode]]) -> Dict[str, List[TaskNode]]:
    """Execute batch with live progress bar"""
    results = {
        'succeeded': [],
        'failed': [],
        'skipped': []
    }

    # Calculate total tasks
    total_tasks = sum(len(step) for step in steps)
    completed_tasks = 0

    print(f"\nBatch Execution: {total_tasks} task(s)")
    print("=" * 60)

    for step_num, step in enumerate(steps, 1):
        print(f"\nStep {step_num}/{len(steps)}: {len(step)} task(s)")

        # Execute step with progress
        from concurrent.futures import ThreadPoolExecutor, as_completed

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = {executor.submit(self._execute_single_task, task): task
                      for task in step}

            step_completed = 0
            for future in as_completed(futures):
                task = futures[future]
                success = future.result()

                step_completed += 1
                completed_tasks += 1

                # Update progress bar
                progress_pct = (completed_tasks / total_tasks) * 100
                bar_length = 30
                filled = int(progress_pct / (100/bar_length))
                bar = '#' * filled + '-' * (bar_length - filled)

                # Clear line and print progress
                status = "✓" if success else "✗"
                print(f"\r[{bar}] {progress_pct:.0f}% | {status} {task.name[:40]}",
                      end='', flush=True)

                if success:
                    results['succeeded'].append(task)
                else:
                    results['failed'].append(task)

        print()  # Newline after step

    print("\n" + "=" * 60)
    print(f"Batch complete: {len(results['succeeded'])} succeeded, "
          f"{len(results['failed'])} failed")

    return results
```

**ROI Calculation**:
- **Value**: 8 (significantly better UX)
- **Frequency**: 8 (every batch execution)
- **Risk**: 1 (display only, no logic change)
- **Effort**: 2 (1-2 hours)

**ROI = (8 × 8) / (1 × 2) = 32.0** ✓ **VERY HIGH VALUE**

**Implementation Checklist**:
- [ ] Update `_execute_batch()` in `session.py`
- [ ] Add progress bar rendering
- [ ] Use `\r` for in-place updates
- [ ] Test with 10+ task batch
- [ ] Verify doesn't break existing tests

**Estimated Effort**: 1-2 hours
**Risk Level**: VERY LOW
**Dependencies**: None

---

### #4: Cache CVE Database in Finding Correlator

**Category**: Performance Optimization
**ROI**: **7.5**

**Problem**: CVE lookups slow if database queries repeated

**Impact**: MEDIUM
- Correlations take 2-3 seconds with large CVE data
- Repeated lookups for same CVE
- Poor UX when re-running correlator

**Proposed Fix**:
Cache CVE data in memory on first load:

```python
class FindingCorrelator:
    """Enhanced with CVE caching"""

    _cve_cache = None  # Class-level cache

    @classmethod
    def _get_cve_database(cls):
        """Load CVE database with caching"""
        if cls._cve_cache is None:
            # Load CVE data (simulated - replace with actual DB)
            cls._cve_cache = {
                'apache-2.4.49': ['CVE-2021-41773'],
                'apache-2.4.50': ['CVE-2021-42013'],
                'vsftpd-2.3.4': ['CVE-2011-2523'],
                # ... etc
            }
        return cls._cve_cache

    @classmethod
    def correlate_cve_version(cls, profile: TargetProfile):
        """Use cached CVE database"""
        cve_db = cls._get_cve_database()

        correlations = []
        for port, info in profile.ports.items():
            version = info.get('version', '')
            product = info.get('product', '')

            # Check cache
            key = f"{product.lower()}-{version}"
            if key in cve_db:
                for cve in cve_db[key]:
                    correlations.append({
                        'type': 'cve-match',
                        'priority': 'high',
                        'cve': cve,
                        'port': port,
                        'version': version
                    })

        return correlations
```

**ROI Calculation**:
- **Value**: 5 (faster correlations)
- **Frequency**: 6 (every fc invocation)
- **Risk**: 2 (memory usage slightly higher)
- **Effort**: 2 (simple dict caching)

**ROI = (5 × 6) / (2 × 2) = 7.5** ✓ **HIGH VALUE**

**Estimated Effort**: 1-2 hours
**Risk Level**: LOW

---

### #5: Fix Task Retry Timestamp Sorting

**Category**: Bug Fix
**ROI**: **6.0**

**Problem**: Retryable tasks not sorted by timestamp correctly

**Impact**: LOW
- Tasks displayed in wrong order
- Most recent failures not prioritized
- Minor UX annoyance

**Current Behavior**:
```python
# Sorts by task ID instead of timestamp
retryable.sort(key=lambda t: t.id)
```

**Proposed Fix**:
```python
# Sort by most recent failure first
retryable.sort(key=lambda t: t.metadata.get('failed_at', 0), reverse=True)
```

**ROI Calculation**:
- **Value**: 4 (better UX, easier to find recent failures)
- **Frequency**: 6 (every task retry session)
- **Risk**: 1 (trivial logic change)
- **Effort**: 1 (10 minutes to fix)

**ROI = (4 × 6) / (1 × 1) = 24.0** ✓ **HIGH VALUE**

**Implementation Checklist**:
- [ ] Update sort key in `_get_retryable_tasks()`
- [ ] Add `failed_at` timestamp to task metadata on failure
- [ ] Run test: `pytest crack/tests/track/test_task_retry.py::TestGetRetryableTasks::test_get_retryable_tasks_sorting -v`
- [ ] Verify test passes

**Estimated Effort**: 10-15 minutes
**Risk Level**: VERY LOW

---

## Medium-Term Priority (ROI 2-5)

### #6: Add Type Hints to Interactive Module

**Category**: Code Quality
**ROI**: **3.0**

**Problem**: Type hints missing in many methods

**Impact**: LOW
- Harder for new developers to understand
- No IDE autocomplete support
- Increased bug risk

**Proposed Fix**:
Add type hints to all public methods:

```python
from typing import Dict, List, Optional, Any, Tuple

def handle_progress_dashboard(self) -> None:
    """Display progress dashboard"""
    pass

def _get_retryable_tasks(self) -> List[TaskNode]:
    """Get tasks eligible for retry"""
    pass

def _parse_batch_selection(self,
                           selection: str,
                           tasks: List[TaskNode]) -> List[TaskNode]:
    """Parse batch selection string"""
    pass
```

**ROI Calculation**:
- **Value**: 3 (better maintainability)
- **Frequency**: 2 (benefits future development)
- **Risk**: 1 (no runtime impact)
- **Effort**: 2 (1-2 hours to add)

**ROI = (3 × 2) / (1 × 2) = 3.0** ✓ **MEDIUM VALUE**

**Estimated Effort**: 1-2 hours
**Risk Level**: NONE (doesn't affect runtime)

---

### #7: Expand CVE Database Coverage

**Category**: Feature Enhancement
**ROI**: **2.5**

**Problem**: Limited CVE coverage in finding correlator

**Impact**: MEDIUM
- Misses some CVE matches
- Reduces correlation accuracy

**Proposed Fix**:
Expand hardcoded CVE database with more entries:

```python
CVE_DATABASE = {
    # Apache
    'apache-2.4.49': ['CVE-2021-41773'],
    'apache-2.4.50': ['CVE-2021-42013'],

    # ProFTPD
    'proftpd-1.3.5': ['CVE-2015-3306'],

    # SSH
    'openssh-7.2p2': ['CVE-2016-6210'],

    # SMB
    'samba-3.5.0': ['CVE-2010-2063'],

    # ... add 50+ more entries
}
```

**ROI Calculation**:
- **Value**: 5 (better correlation accuracy)
- **Frequency**: 5 (benefits all fc usage)
- **Risk**: 1 (just data, no logic change)
- **Effort**: 5 (research and add CVEs)

**ROI = (5 × 5) / (1 × 5) = 5.0** ✓ **BORDERLINE HIGH VALUE**

**Estimated Effort**: 4-5 hours (CVE research)
**Risk Level**: NONE

---

## Long-Term / Deferred (ROI < 2)

### #8: Integration Tests Across All 7 Tools

**ROI**: **1.5** (LOW VALUE)

**Reason for Deferral**:
- High effort (10+ hours)
- Medium risk (complex test setup)
- Low frequency (only run during releases)

**Recommendation**: Defer to future release

---

### #9: Performance Benchmarking Suite

**ROI**: **1.8** (LOW VALUE)

**Reason for Deferral**:
- No performance issues detected
- High effort to build comprehensive suite
- Benefits only future optimization work

**Recommendation**: Implement only if performance problems arise

---

### #10: Video Tutorial for Interactive Mode

**ROI**: **1.2** (LOW VALUE)

**Reason for Deferral**:
- Documentation already comprehensive
- High effort (video production)
- Low frequency (one-time benefit)

**Recommendation**: Create only if user requests

---

## Implementation Priority Queue

### Sprint 1 (This Week) - Critical Fixes

**Estimated Total Effort**: 5-6 hours

1. ✅ **#1: Implement Progress Dashboard** (2 hours, ROI 45.0)
2. ✅ **#5: Fix Task Retry Sorting** (15 min, ROI 24.0)
3. ✅ **#2: Fix Session Snapshot** (3-4 hours, ROI 6.25)

**Goal**: Achieve 95%+ test pass rate

---

### Sprint 2 (Next Week) - UX Enhancements

**Estimated Total Effort**: 3-4 hours

1. ✅ **#3: Add Batch Execute Progress Bar** (2 hours, ROI 32.0)
2. ✅ **#4: Cache CVE Database** (1-2 hours, ROI 7.5)

**Goal**: Improve user experience

---

### Sprint 3 (Future) - Code Quality

**Estimated Total Effort**: 6-7 hours

1. ⚠️ **#6: Add Type Hints** (1-2 hours, ROI 3.0)
2. ⚠️ **#7: Expand CVE Database** (4-5 hours, ROI 2.5)

**Goal**: Long-term maintainability

---

## Success Metrics

### Definition of Done

**Sprint 1 Complete When:**
- [ ] All 137 tests passing (100% pass rate)
- [ ] Progress dashboard functional ('pd' works)
- [ ] Session snapshot save/restore reliable
- [ ] Task retry sorted correctly
- [ ] Manual testing confirms all fixes

**Sprint 2 Complete When:**
- [ ] Batch execute shows live progress bar
- [ ] Finding correlator uses CVE cache
- [ ] Performance benchmarks show improvement
- [ ] User feedback positive

**Sprint 3 Complete When:**
- [ ] All public methods have type hints
- [ ] CVE database covers 100+ entries
- [ ] Code quality metrics improved

---

## Rejected Ideas

### Why NOT Implemented

**Idea**: Add undo functionality to all tools
**Reason**: High complexity (state management), low ROI (1.5)

**Idea**: Multi-target batch operations
**Reason**: Rare use case, high risk, ROI < 1.0

**Idea**: AI-powered recommendation engine
**Reason**: Complexity too high, exam doesn't allow AI

---

## Summary

### High-Value Improvements (ROI > 5.0)

| # | Improvement | ROI | Effort | Status |
|---|-------------|-----|--------|--------|
| 1 | Implement Progress Dashboard | 45.0 | 2h | ⏳ Ready |
| 5 | Fix Task Retry Sorting | 24.0 | 15m | ⏳ Ready |
| 3 | Add Batch Progress Bar | 32.0 | 2h | ⏳ Ready |
| 4 | Cache CVE Database | 7.5 | 2h | ⏳ Ready |
| 2 | Fix Session Snapshot | 6.25 | 4h | ⏳ Ready |

**Total High-Value Effort**: 10-11 hours
**Expected Impact**: Test pass rate 86.9% → 100%

### Recommended Action Plan

**Week 1**: Implement #1, #5, #2 (critical fixes)
**Week 2**: Implement #3, #4 (UX improvements)
**Week 3**: Code review, integration testing, deployment

**Production Ready**: End of Week 1 (after critical fixes)
**Full Enhancement**: End of Week 2

---

**Document Version**: 1.0
**Last Updated**: 2025-10-08
**Owner**: Verification Agent 6
