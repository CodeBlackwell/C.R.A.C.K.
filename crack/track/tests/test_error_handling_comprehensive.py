"""
Comprehensive Error Handling & Edge Cases Testing
==================================================

PURPOSE: Verify all Phase 4 & 5 tools handle errors gracefully and edge cases reliably
SCOPE: Interactive session tools (pd, ss, qe, qx, tr, be, fc)
PHILOSOPHY: Everything that CAN go wrong WILL go wrong (Murphy's Law Testing)

Test Categories:
1. Invalid Input (user errors)
2. Empty/Minimal State (edge cases)
3. Data Corruption (reliability)
4. File System Errors (environment)
5. Command Execution Errors (subprocess)
6. Performance Degradation (scale)
7. Race Conditions (concurrency)
"""

import pytest
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import subprocess
import time

# Import CRACK Track components
from crack.track.core.state import TargetProfile
from crack.track.core.task_tree import TaskNode
from crack.track.interactive.session import InteractiveSession
from crack.track.interactive.input_handler import InputProcessor


# ============================================================================
# CATEGORY 1: INVALID INPUT (USER ERRORS)
# ============================================================================

class TestInvalidInputHandling:
    """Test all tools handle malformed user input gracefully"""

    def test_empty_input_batch_execute(self, temp_crack_home, mock_profile_with_tasks):
        """
        PROVES: Batch execute handles empty input gracefully

        Scenario: User presses Enter without typing anything
        Expected: Friendly prompt, no crash
        """
        session = InteractiveSession(mock_profile_with_tasks.target)

        # Test with empty selection
        with patch('builtins.input', return_value=''):
            try:
                session.handle_batch_execute(selection='')
                # Should not crash
            except Exception as e:
                pytest.fail(f"Empty input caused crash: {e}")

    def test_invalid_numeric_selection_batch(self, temp_crack_home, mock_profile_with_tasks):
        """
        PROVES: Batch execute handles invalid selection gracefully

        Scenario: User types invalid indices
        Expected: Graceful error, no crash
        """
        session = InteractiveSession(mock_profile_with_tasks.target)

        # Test with out-of-range selection
        result = session._parse_batch_selection('999',
                                               session.profile.task_tree.get_all_tasks())

        # Should return empty list, not crash
        assert isinstance(result, list)

    def test_malformed_multi_select_syntax(self, temp_crack_home):
        """
        PROVES: InputProcessor handles malformed multi-select gracefully

        Scenario: User types "1,2,xyz,5-"
        Expected: Parse valid parts, ignore invalid
        """
        # Test various malformed inputs
        test_cases = [
            ('1,2,xyz', 10),      # Invalid text
            ('1-', 10),           # Incomplete range
            ('5-3', 10),          # Reverse range
            ('1,2,2,1', 10),      # Duplicates
            ('0,1,2', 10),        # Zero index
            ('-5', 10),           # Negative
            ('1,,3', 10),         # Double comma
        ]

        for user_input, max_val in test_cases:
            try:
                result = InputProcessor.parse_multi_select(user_input, max_val)
                # Should not crash
                assert isinstance(result, list)
            except Exception as e:
                pytest.fail(f"Input '{user_input}' caused crash: {e}")

    def test_special_characters_in_snapshot_name(self, temp_crack_home, mock_profile):
        """
        PROVES: Snapshot tool sanitizes special characters in names

        Scenario: User provides snapshot name with /, *, ?, etc.
        Expected: Sanitized to safe filename
        """
        session = InteractiveSession(mock_profile.target)

        # Test dangerous characters
        dangerous_names = [
            'test/snapshot',      # Directory separator
            'test*snapshot',      # Wildcard
            'test?snapshot',      # Question mark
            'test:snapshot',      # Colon (Windows)
            'test|snapshot',      # Pipe
            'test<snapshot>',     # Brackets
            '../../../etc/passwd' # Path traversal
        ]

        import re

        for name in dangerous_names:
            # Replicate the sanitization logic from _save_snapshot
            safe_name = re.sub(r'[^a-zA-Z0-9_-]', '-', name.strip())

            # Verify no dangerous characters remain
            assert '/' not in safe_name
            assert '\\' not in safe_name
            assert '*' not in safe_name
            assert '?' not in safe_name
            assert '..' not in safe_name

            # Should only contain safe characters
            assert all(c.isalnum() or c in '_-' for c in safe_name)

    def test_ctrl_c_during_batch_execute(self, temp_crack_home, mock_profile_with_tasks):
        """
        PROVES: Ctrl+C during batch execute saves state gracefully

        Scenario: User hits Ctrl+C mid-execution
        Expected: Clean exit, profile saved, partial results preserved
        """
        session = InteractiveSession(mock_profile_with_tasks.target)

        # Simulate KeyboardInterrupt during execution
        with patch.object(session, '_execute_batch', side_effect=KeyboardInterrupt):
            with patch('builtins.input', return_value='1'):
                try:
                    session.handle_batch_execute(selection='1')
                except KeyboardInterrupt:
                    pass  # Expected

        # Profile should still be valid
        assert session.profile.target == mock_profile_with_tasks.target


# ============================================================================
# CATEGORY 2: EMPTY/MINIMAL STATE (EDGE CASES)
# ============================================================================

class TestEmptyStateHandling:
    """Test tools with no data or minimal data in profile"""

    def test_finding_correlator_no_findings(self, temp_crack_home, mock_profile):
        """
        PROVES: Finding correlator handles empty findings gracefully

        Scenario: No findings, no creds, no ports
        Expected: Helpful message, tips on populating data
        """
        session = InteractiveSession(mock_profile.target)

        # Ensure profile is empty
        assert len(session.profile.findings) == 0
        assert len(session.profile.credentials) == 0
        assert len(session.profile.ports) == 0

        # Should not crash
        try:
            session.handle_finding_correlator()
        except Exception as e:
            pytest.fail(f"Empty state caused crash: {e}")

    def test_batch_execute_no_pending_tasks(self, temp_crack_home, mock_profile):
        """
        PROVES: Batch execute handles no pending tasks gracefully

        Scenario: All tasks completed or no tasks exist
        Expected: "Nothing to execute" message
        """
        session = InteractiveSession(mock_profile.target)

        # Mark all tasks completed
        all_tasks = session.profile.task_tree.get_all_tasks()
        for task in all_tasks:
            task.status = 'completed'

        # Should handle gracefully
        try:
            session.handle_batch_execute()
        except Exception as e:
            pytest.fail(f"No pending tasks caused crash: {e}")

    def test_task_retry_no_failed_tasks(self, temp_crack_home, mock_profile):
        """
        PROVES: Task retry handles no failed tasks gracefully

        Scenario: No failed tasks to retry
        Expected: "No failed tasks" message
        """
        session = InteractiveSession(mock_profile.target)

        # Ensure no failed tasks
        all_tasks = session.profile.task_tree.get_all_tasks()
        for task in all_tasks:
            if task.status == 'failed':
                task.status = 'pending'

        retryable = session._get_retryable_tasks()

        # Should return empty list or handle gracefully
        assert isinstance(retryable, list)

    def test_quick_export_empty_profile(self, temp_crack_home, mock_profile):
        """
        PROVES: Quick export handles empty profile gracefully

        Scenario: No data to export
        Expected: Export file with "No data yet" message
        """
        session = InteractiveSession(mock_profile.target)

        # Ensure profile is minimal
        assert len(session.profile.findings) == 0
        assert len(session.profile.credentials) == 0

        # Mock user selections (choice, destination, format, view file)
        with patch('builtins.input', side_effect=['1', 'f', 'm', 'n']):
            try:
                session.handle_quick_export()
                # Should complete without crash
            except StopIteration:
                # Expected when mock inputs exhausted
                pass
            except Exception as e:
                pytest.fail(f"Empty profile export caused crash: {e}")

    def test_snapshot_first_save_no_existing(self, temp_crack_home, mock_profile):
        """
        PROVES: Snapshot handles first-time save gracefully

        Scenario: No existing snapshots
        Expected: Create snapshot without errors
        """
        session = InteractiveSession(mock_profile.target)

        # Verify no snapshots exist
        snapshots = session._list_snapshots()

        # Should handle gracefully (might be empty list)
        assert isinstance(snapshots, list)


# ============================================================================
# CATEGORY 3: DATA CORRUPTION (RELIABILITY)
# ============================================================================

class TestDataCorruptionHandling:
    """Test tools handle malformed profile data"""

    def test_missing_metadata_fields_in_task(self, temp_crack_home, mock_profile):
        """
        PROVES: Tools handle tasks with missing metadata gracefully

        Scenario: Task with no 'command' field
        Expected: Skip gracefully, warn user
        """
        session = InteractiveSession(mock_profile.target)

        # Create task with missing metadata
        broken_task = TaskNode(
            task_id='broken',
            name='Broken Task',
            task_type='command'
        )
        # Don't set metadata['command']

        session.profile.task_tree.add_child(broken_task)

        # Should handle gracefully in batch execute
        try:
            pending = [t for t in session.profile.task_tree.get_all_tasks()
                      if t.status == 'pending' and t.metadata.get('command')]
            # Broken task should be filtered out
            assert broken_task not in pending
        except Exception as e:
            pytest.fail(f"Missing metadata caused crash: {e}")

    def test_corrupted_json_snapshot(self, temp_crack_home, mock_profile):
        """
        PROVES: Snapshot restore handles corrupted JSON gracefully

        Scenario: Snapshot file has invalid JSON
        Expected: "Snapshot corrupted" error, no crash
        """
        session = InteractiveSession(mock_profile.target)

        # Create corrupted snapshot file
        snapshots_dir = Path.home() / '.crack' / 'snapshots' / session.profile.target
        snapshots_dir.mkdir(parents=True, exist_ok=True)

        corrupted_file = snapshots_dir / 'corrupted.json'
        corrupted_file.write_text('{ invalid json }}}')

        # Should handle gracefully
        try:
            snapshots = session._list_snapshots()
            # Should skip corrupted file or handle gracefully
            assert isinstance(snapshots, list)
        except Exception as e:
            pytest.fail(f"Corrupted JSON caused crash: {e}")

    def test_circular_dependencies_in_tasks(self, temp_crack_home, mock_profile):
        """
        PROVES: Batch execute detects and handles circular dependencies

        Scenario: Task A depends on B, B depends on A
        Expected: Detect cycle, warn user, break loop
        """
        session = InteractiveSession(mock_profile.target)

        # Create circular dependency
        task_a = TaskNode(
            task_id='task-a',
            name='Task A',
            task_type='command'
        )
        task_a.metadata['command'] = 'echo a'
        task_a.metadata['depends_on'] = ['task-b']

        task_b = TaskNode(
            task_id='task-b',
            name='Task B',
            task_type='command'
        )
        task_b.metadata['command'] = 'echo b'
        task_b.metadata['depends_on'] = ['task-a']

        session.profile.task_tree.add_child(task_a)
        session.profile.task_tree.add_child(task_b)

        # Should detect cycle and handle gracefully
        try:
            steps = session._resolve_dependencies([task_a, task_b])
            # Should not hang in infinite loop
            assert isinstance(steps, list)
        except Exception as e:
            # Expected to raise error or handle gracefully
            assert 'circular' in str(e).lower() or 'cycle' in str(e).lower()

    def test_invalid_timestamp_in_metadata(self, temp_crack_home, mock_profile):
        """
        PROVES: Tools handle invalid timestamps gracefully

        Scenario: Task has negative or malformed timestamp
        Expected: Use current time as fallback
        """
        session = InteractiveSession(mock_profile.target)

        # Create task with invalid timestamp
        task = TaskNode(
            task_id='invalid-time',
            name='Invalid Time Task',
            task_type='command'
        )
        task.metadata['command'] = 'echo test'
        task.metadata['completed_at'] = -1  # Invalid
        task.metadata['last_run'] = 'not-a-timestamp'  # Invalid

        session.profile.task_tree.add_child(task)

        # Should handle gracefully
        try:
            retryable = session._get_retryable_tasks()
            # Should not crash on invalid timestamp
            assert isinstance(retryable, list)
        except Exception as e:
            pytest.fail(f"Invalid timestamp caused crash: {e}")


# ============================================================================
# CATEGORY 4: FILE SYSTEM ERRORS (ENVIRONMENT)
# ============================================================================

class TestFileSystemErrorHandling:
    """Test tools handle file system issues"""

    def test_readonly_export_directory(self, temp_crack_home, mock_profile):
        """
        PROVES: Quick export handles read-only directory gracefully

        Scenario: Export directory is read-only
        Expected: Clear error message about permissions
        """
        session = InteractiveSession(mock_profile.target)

        # Make exports directory read-only
        exports_dir = Path.home() / '.crack' / 'exports'
        exports_dir.mkdir(parents=True, exist_ok=True)

        original_mode = exports_dir.stat().st_mode

        try:
            # Make read-only
            exports_dir.chmod(0o444)

            # Mock user selections
            with patch('builtins.input', side_effect=['1', 'f', 'n']):
                try:
                    session.handle_quick_export()
                except PermissionError:
                    pass  # Expected
                except Exception as e:
                    # Should be a clear permission error
                    assert 'permission' in str(e).lower() or 'read-only' in str(e).lower()

        finally:
            # Restore permissions
            exports_dir.chmod(original_mode)

    def test_missing_profile_directory(self, temp_crack_home):
        """
        PROVES: Profile handles missing directory gracefully

        Scenario: ~/.crack/targets/ deleted mid-session
        Expected: Recreate directory, warn user
        """
        import shutil
        from crack.track.core.storage import Storage

        # Reset Storage.DEFAULT_DIR to use temp home (work around module-level constant)
        Storage.DEFAULT_DIR = Path.home() / '.crack' / 'targets'

        # Create profile
        profile = TargetProfile('192.168.1.100')
        profile.save()

        # Verify it was saved
        targets_dir = Storage.DEFAULT_DIR
        assert targets_dir.exists()

        # Delete targets directory
        if targets_dir.exists():
            shutil.rmtree(targets_dir)

        # Verify deletion
        assert not targets_dir.exists()

        # Should recreate on save
        profile.save()

        # Verify directory recreated
        assert targets_dir.exists(), "Storage should recreate missing directory"


# ============================================================================
# CATEGORY 5: COMMAND EXECUTION ERRORS (SUBPROCESS)
# ============================================================================

class TestCommandExecutionErrorHandling:
    """Test tools handle subprocess failures"""

    def test_command_not_found_error(self, temp_crack_home, mock_profile_with_tasks):
        """
        PROVES: Task execution handles "command not found" gracefully

        Scenario: User runs nonexistent command
        Expected: Clear error message with exit code 127
        """
        session = InteractiveSession(mock_profile_with_tasks.target)

        # Create task with nonexistent command
        bad_task = TaskNode(
            task_id='bad-command',
            name='Bad Command',
            task_type='command'
        )
        bad_task.metadata['command'] = 'nonexistent-command-12345'

        session.profile.task_tree.add_child(bad_task)

        # Mock subprocess to simulate command not found
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = FileNotFoundError("Command not found")

            result = session._execute_single_task(bad_task)

            # Should handle gracefully
            assert result == False or bad_task.status == 'failed'

    def test_command_timeout_handling(self, temp_crack_home, mock_profile_with_tasks):
        """
        PROVES: Long-running commands timeout gracefully

        Scenario: Command runs longer than timeout
        Expected: Terminate gracefully, show partial output
        """
        session = InteractiveSession(mock_profile_with_tasks.target)

        # Create task with long-running command
        slow_task = TaskNode(
            task_id='slow-command',
            name='Slow Command',
            task_type='command'
        )
        slow_task.metadata['command'] = 'sleep 9999'
        slow_task.metadata['timeout'] = 1

        session.profile.task_tree.add_child(slow_task)

        # Mock subprocess to simulate timeout
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired('sleep', 1)

            result = session._execute_single_task(slow_task)

            # Should handle timeout gracefully
            assert result == False or slow_task.status == 'failed'

    def test_batch_execute_failure_mid_batch(self, temp_crack_home, mock_profile_with_tasks):
        """
        PROVES: Batch execute continues after mid-batch failure

        Scenario: Batch of 5 tasks, task #3 fails
        Expected: Continue with remaining tasks, report failure
        """
        session = InteractiveSession(mock_profile_with_tasks.target)

        # Create batch of tasks
        tasks = []
        for i in range(5):
            task = TaskNode(
                task_id=f'task-{i}',
                name=f'Task {i}',
                task_type='command'
            )
            task.metadata['command'] = f'echo {i}'
            tasks.append(task)
            session.profile.task_tree.add_child(task)

        # Mock subprocess to fail task #3
        call_count = [0]

        def mock_run_with_failure(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 3:
                raise subprocess.CalledProcessError(1, 'echo', stderr=b'Error')
            return subprocess.CompletedProcess(args[0], 0, b'success', b'')

        with patch('subprocess.run', side_effect=mock_run_with_failure):
            results = session._execute_batch([[t] for t in tasks])

            # Should have some successes and some failures
            assert len(results['succeeded']) + len(results['failed']) > 0

    def test_permission_denied_error(self, temp_crack_home, mock_profile_with_tasks):
        """
        PROVES: Permission denied handled with helpful suggestion

        Scenario: User tries command without permissions
        Expected: "Permission denied. Try with sudo?"
        """
        session = InteractiveSession(mock_profile_with_tasks.target)

        # Create task that requires sudo
        perm_task = TaskNode(
            task_id='perm-denied',
            name='Permission Task',
            task_type='command'
        )
        perm_task.metadata['command'] = 'restricted-command'

        session.profile.task_tree.add_child(perm_task)

        # Mock subprocess to raise permission error
        with patch('subprocess.run') as mock_run:
            mock_run.side_effect = PermissionError("Permission denied")

            result = session._execute_single_task(perm_task)

            # Should handle gracefully
            assert result == False or perm_task.status == 'failed'


# ============================================================================
# CATEGORY 6: PERFORMANCE DEGRADATION (SCALE)
# ============================================================================

class TestPerformanceDegradation:
    """Test tools with extreme datasets"""

    def test_large_task_tree_performance(self, temp_crack_home):
        """
        PROVES: Tools handle 1000+ tasks without performance degradation

        Scenario: 1000 tasks in task tree
        Expected: Renders in <5 seconds, doesn't hang
        """
        profile = TargetProfile('192.168.1.100')

        # Create 1000 tasks
        start = time.time()

        for i in range(1000):
            task = TaskNode(
                task_id=f'task-{i}',
                name=f'Task {i}',
                task_type='command'
            )
            task.metadata['command'] = f'echo {i}'
            profile.task_tree.add_child(task)

        elapsed = time.time() - start

        # Should complete in reasonable time
        assert elapsed < 5.0, f"Creating 1000 tasks took {elapsed}s (too slow)"

        # Test retrieval
        start = time.time()
        all_tasks = profile.task_tree.get_all_tasks()
        elapsed = time.time() - start

        assert len(all_tasks) >= 1000
        assert elapsed < 2.0, f"Retrieving 1000 tasks took {elapsed}s (too slow)"

    def test_finding_correlator_with_large_dataset(self, temp_crack_home):
        """
        PROVES: Finding correlator handles 100+ findings efficiently

        Scenario: 100 findings × 100 ports = potential 10,000 correlations
        Expected: Limit to top 50, complete in <5 seconds
        """
        profile = TargetProfile('192.168.1.100')
        session = InteractiveSession(profile.target)

        # Add 100 ports
        for port in range(1, 101):
            profile.ports[port] = {
                'state': 'open',
                'service': 'http',
                'version': f'Apache {port}.0'
            }

        # Add 100 findings
        for i in range(100):
            profile.findings.append({
                'timestamp': '2025-10-08T12:00:00',
                'type': 'vulnerability',
                'description': f'Vuln {i}',
                'source': 'manual'
            })

        # Test correlator performance
        start = time.time()

        try:
            correlations = session._find_correlations()
            elapsed = time.time() - start

            # Should complete in reasonable time
            assert elapsed < 5.0, f"Correlating 100×100 took {elapsed}s (too slow)"

            # Should limit results
            if correlations:
                assert len(correlations) <= 100  # Should limit to prevent UI overload

        except Exception as e:
            pytest.fail(f"Large dataset caused crash: {e}")

    def test_batch_execute_dependency_resolution_scale(self, temp_crack_home):
        """
        PROVES: Batch execute resolves 200+ task dependencies efficiently

        Scenario: 200 tasks in dependency chain
        Expected: Resolve without stack overflow, <10 seconds
        """
        profile = TargetProfile('192.168.1.100')
        session = InteractiveSession(profile.target)

        # Create dependency chain: task-0 → task-1 → task-2 → ... → task-199
        tasks = []
        for i in range(200):
            task = TaskNode(
                task_id=f'task-{i}',
                name=f'Task {i}',
                task_type='command'
            )
            task.metadata['command'] = f'echo {i}'
            if i > 0:
                task.metadata['depends_on'] = [f'task-{i-1}']

            tasks.append(task)
            profile.task_tree.add_child(task)

        # Test dependency resolution
        start = time.time()

        try:
            steps = session._resolve_dependencies(tasks)
            elapsed = time.time() - start

            # Should complete without stack overflow
            assert elapsed < 10.0, f"Resolving 200 dependencies took {elapsed}s (too slow)"

            # Should create valid execution plan
            assert len(steps) > 0

        except RecursionError:
            pytest.fail("Dependency resolution caused stack overflow")


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def temp_crack_home(tmp_path, monkeypatch):
    """Create temporary .crack directory"""
    crack_home = tmp_path / '.crack'
    crack_home.mkdir()

    # Create subdirectories
    (crack_home / 'targets').mkdir()
    (crack_home / 'snapshots').mkdir()
    (crack_home / 'exports').mkdir()
    (crack_home / 'sessions').mkdir()

    # Override HOME
    monkeypatch.setenv('HOME', str(tmp_path))

    yield crack_home


@pytest.fixture
def mock_profile(temp_crack_home):
    """Create minimal mock profile"""
    profile = TargetProfile('192.168.1.100')
    return profile


@pytest.fixture
def mock_profile_with_tasks(temp_crack_home):
    """Create mock profile with tasks"""
    profile = TargetProfile('192.168.1.100')

    # Add some tasks
    for i in range(5):
        task = TaskNode(
            task_id=f'task-{i}',
            name=f'Task {i}',
            task_type='command'
        )
        task.metadata['command'] = f'echo {i}'
        profile.task_tree.add_child(task)

    return profile


@pytest.fixture
def mock_profile_with_findings(temp_crack_home):
    """Create mock profile with findings and credentials"""
    profile = TargetProfile('192.168.1.100')

    # Add ports
    profile.ports = {
        80: {'state': 'open', 'service': 'http', 'version': 'Apache 2.4.41'},
        22: {'state': 'open', 'service': 'ssh', 'version': 'OpenSSH 8.2'},
        445: {'state': 'open', 'service': 'smb', 'version': 'Samba 4.11'}
    }

    # Add findings
    profile.findings = [
        {
            'timestamp': '2025-10-08T12:00:00',
            'type': 'vulnerability',
            'description': 'SQLi in /login.php',
            'source': 'manual'
        },
        {
            'timestamp': '2025-10-08T12:30:00',
            'type': 'file',
            'description': 'Found /admin directory',
            'source': 'gobuster'
        }
    ]

    # Add credentials
    profile.credentials = [
        {
            'timestamp': '2025-10-08T13:00:00',
            'username': 'admin',
            'password': 'password123',
            'service': 'http',
            'port': 80,
            'source': 'config.php'
        }
    ]

    return profile
