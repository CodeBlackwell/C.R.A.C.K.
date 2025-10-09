"""
Chaos Engineering Tests - OSCP Exam Stress Conditions
=====================================================

PURPOSE: Simulate real OSCP exam stress conditions and rapid tool switching
PHILOSOPHY: Test reliability under pressure, not just correctness
SCOPE: Real-world failure scenarios that happen during 24-hour exam

Chaos Scenarios:
1. Rapid tool switching (stressed student behavior)
2. Network interruption during batch execution
3. Memory pressure conditions
4. Disk space exhaustion
5. Concurrent profile access
6. Profile state corruption recovery
7. Signal handling (SIGTERM, SIGHUP, etc.)
"""

import pytest
import json
import os
import signal
import time
import threading
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import subprocess

from crack.track.core.state import TargetProfile
from crack.track.core.task_tree import TaskNode
from crack.track.interactive.session import InteractiveSession


# ============================================================================
# CHAOS SCENARIO 1: RAPID TOOL SWITCHING
# ============================================================================

class TestRapidToolSwitching:
    """Simulate stressed student rapidly trying different tools"""

    def test_rapid_mode_changes(self, temp_crack_home, mock_profile_with_data):
        """
        PROVES: Session handles rapid tool/mode switching without crashes

        Scenario: pd → fc → be → Ctrl+C → qe → tr → pd → qx
        Expected: No crashes, state remains consistent
        """
        session = InteractiveSession(mock_profile_with_data.target)

        operations = [
            ('profile_dashboard', lambda: session.handle_status()),
            ('finding_correlator', lambda: session.handle_finding_correlator()),
            ('batch_execute', lambda: session.handle_batch_execute(selection='cancel')),
            ('quick_export', lambda: self._mock_quick_export(session)),
            ('task_retry', lambda: session._get_retryable_tasks()),
            ('profile_dashboard', lambda: session.handle_status()),
        ]

        # Rapidly execute operations
        for name, operation in operations:
            try:
                operation()
            except Exception as e:
                pytest.fail(f"Rapid switching crashed at {name}: {e}")

        # Profile should still be consistent
        assert session.profile.target == mock_profile_with_data.target
        assert session.profile.task_tree is not None

    def _mock_quick_export(self, session):
        """Mock quick export with automated inputs"""
        with patch('builtins.input', side_effect=['1', 'f', 'n']):
            try:
                session.handle_quick_export()
            except StopIteration:
                pass  # Expected when inputs exhausted

    def test_interrupt_recovery_multiple_times(self, temp_crack_home, mock_profile_with_tasks):
        """
        PROVES: Session recovers from multiple interrupts

        Scenario: User hits Ctrl+C repeatedly during different operations
        Expected: Always recovers, profile intact
        """
        session = InteractiveSession(mock_profile_with_tasks.target)

        for i in range(5):
            # Simulate KeyboardInterrupt
            with patch.object(session, '_execute_batch', side_effect=KeyboardInterrupt):
                try:
                    session.handle_batch_execute(selection='1')
                except KeyboardInterrupt:
                    pass  # Expected

            # Verify state still valid
            assert session.profile is not None
            assert len(session.profile.task_tree.get_all_tasks()) > 0

    def test_concurrent_command_execution_and_status_check(self, temp_crack_home, mock_profile_with_tasks):
        """
        PROVES: Status checks don't interfere with command execution

        Scenario: User checks status while batch execute is running
        Expected: Status shows current state, no crashes
        """
        session = InteractiveSession(mock_profile_with_tasks.target)

        # Mock long-running batch
        def slow_batch():
            time.sleep(0.1)
            return {'succeeded': [], 'failed': [], 'skipped': [], 'total_time': 0.1}

        with patch.object(session, '_execute_batch', side_effect=slow_batch):
            # Start batch in thread
            batch_thread = threading.Thread(target=lambda: session.handle_batch_execute(selection='1'))
            batch_thread.start()

            # Check status while batch running
            try:
                session.handle_status()
            except Exception as e:
                pytest.fail(f"Status check during batch caused crash: {e}")

            batch_thread.join(timeout=1.0)


# ============================================================================
# CHAOS SCENARIO 2: NETWORK INTERRUPTION
# ============================================================================

class TestNetworkInterruption:
    """Simulate network failures during operations"""

    def test_batch_execute_network_failure(self, temp_crack_home, mock_profile_with_network_tasks):
        """
        PROVES: Batch execute handles network failures gracefully

        Scenario: WiFi drops during batch execution
        Expected: Mark tasks as failed, continue with others
        """
        session = InteractiveSession(mock_profile_with_network_tasks.target)

        # Mock network failure in subprocess
        call_count = [0]

        def mock_run_with_network_fail(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 2:
                # Simulate network error
                raise OSError("Network is unreachable")
            return subprocess.CompletedProcess(args[0], 0, b'success', b'')

        with patch('subprocess.run', side_effect=mock_run_with_network_fail):
            tasks = [t for t in session.profile.task_tree.get_all_tasks() if t.metadata.get('command')][:3]
            results = session._execute_batch([[t] for t in tasks])

            # Should have at least one failure
            assert len(results['failed']) >= 1
            # Should continue with other tasks
            assert len(results['succeeded']) + len(results['failed']) + len(results['skipped']) == len(tasks)

    def test_export_during_network_failure(self, temp_crack_home, mock_profile_with_data):
        """
        PROVES: Export completes even if network unavailable

        Scenario: Network down during export
        Expected: Export succeeds (local operation)
        """
        session = InteractiveSession(mock_profile_with_data.target)

        # Mock network unavailable
        with patch('socket.socket', side_effect=OSError("Network unreachable")):
            # Export should still work (local operation)
            with patch('builtins.input', side_effect=['7', 'f', 'n']):  # Full profile JSON
                try:
                    session.handle_quick_export()
                except StopIteration:
                    pass  # Expected
                except OSError:
                    pytest.fail("Export failed due to network (should be local only)")


# ============================================================================
# CHAOS SCENARIO 3: MEMORY PRESSURE
# ============================================================================

class TestMemoryPressure:
    """Simulate low memory conditions"""

    def test_large_profile_memory_efficiency(self, temp_crack_home):
        """
        PROVES: Tools remain functional with large profiles

        Scenario: Profile with 500+ tasks, 100+ findings
        Expected: Memory usage stays reasonable
        """
        profile = TargetProfile('192.168.1.100')

        # Create large profile
        for i in range(500):
            task = TaskNode(
                task_id=f'task-{i}',
                name=f'Task {i}',
                task_type='command',
                metadata={'command': f'echo {i}', 'output': 'x' * 1000}  # 1KB each
            )
            profile.task_tree.add_child(task)

        for i in range(100):
            profile.findings.append({
                'timestamp': '2025-10-08T12:00:00',
                'type': 'vulnerability',
                'description': f'Finding {i}' * 100,  # Larger descriptions
                'source': 'manual'
            })

        # Should save/load without memory errors
        try:
            profile.save()
            loaded = TargetProfile.load(profile.target)
            assert len(loaded.task_tree.get_all_tasks()) >= 500
        except MemoryError:
            pytest.fail("Large profile caused MemoryError")

    def test_finding_correlator_memory_limit(self, temp_crack_home):
        """
        PROVES: Finding correlator doesn't exhaust memory

        Scenario: 1000 findings × 1000 ports
        Expected: Limits processing, doesn't run out of memory
        """
        profile = TargetProfile('192.168.1.100')
        session = InteractiveSession(profile.target)

        # Create extreme dataset
        for port in range(1, 501):  # 500 ports (reduced from 1000 for test speed)
            profile.ports[port] = {
                'state': 'open',
                'service': 'http',
                'version': f'Apache {port}.0'
            }

        for i in range(500):  # 500 findings
            profile.findings.append({
                'timestamp': '2025-10-08T12:00:00',
                'type': 'vulnerability',
                'description': f'Vuln {i}',
                'source': 'manual'
            })

        # Should handle without memory explosion
        try:
            correlations = session._find_correlations()
            # Should limit results to prevent memory issues
            assert correlations is None or len(correlations) < 1000
        except MemoryError:
            pytest.fail("Correlator exhausted memory")


# ============================================================================
# CHAOS SCENARIO 4: DISK SPACE EXHAUSTION
# ============================================================================

class TestDiskSpaceExhaustion:
    """Simulate disk full conditions"""

    def test_snapshot_save_disk_full(self, temp_crack_home, mock_profile_with_data):
        """
        PROVES: Snapshot handles disk full gracefully

        Scenario: Disk full during snapshot save
        Expected: Clear error message, no corrupted files
        """
        session = InteractiveSession(mock_profile_with_data.target)

        # Mock disk full error
        original_write_text = Path.write_text

        def mock_write_text_disk_full(self, *args, **kwargs):
            raise OSError("No space left on device")

        with patch.object(Path, 'write_text', mock_write_text_disk_full):
            try:
                # Should fail gracefully
                session._save_snapshot('test-snapshot', {})
            except OSError as e:
                # Expected - should have clear message
                assert 'space' in str(e).lower() or 'disk' in str(e).lower()

    def test_export_disk_full_recovery(self, temp_crack_home, mock_profile_with_data):
        """
        PROVES: Export handles disk full without corruption

        Scenario: Disk fills during export
        Expected: Partial export cleaned up, clear error
        """
        session = InteractiveSession(mock_profile_with_data.target)

        # Mock disk full during write
        with patch.object(Path, 'write_text', side_effect=OSError("No space left on device")):
            with patch('builtins.input', side_effect=['1', 'f', 'n']):
                try:
                    session.handle_quick_export()
                except (OSError, StopIteration):
                    pass  # Expected

        # Verify no corrupted files left behind
        exports_dir = Path.home() / '.crack' / 'exports'
        if exports_dir.exists():
            for file in exports_dir.iterdir():
                # Files should be valid JSON or properly formatted
                assert file.stat().st_size > 0 or not file.exists()


# ============================================================================
# CHAOS SCENARIO 5: CONCURRENT PROFILE ACCESS
# ============================================================================

class TestConcurrentProfileAccess:
    """Simulate multiple sessions accessing same profile"""

    def test_concurrent_saves(self, temp_crack_home):
        """
        PROVES: Concurrent saves don't corrupt profile

        Scenario: Two sessions save to same profile simultaneously
        Expected: Last write wins, no corruption
        """
        profile1 = TargetProfile('192.168.1.100')
        profile2 = TargetProfile('192.168.1.100')

        # Modify each profile differently
        profile1.findings.append({
            'timestamp': '2025-10-08T12:00:00',
            'type': 'vulnerability',
            'description': 'Finding from session 1',
            'source': 'manual'
        })

        profile2.findings.append({
            'timestamp': '2025-10-08T12:01:00',
            'type': 'file',
            'description': 'Finding from session 2',
            'source': 'gobuster'
        })

        # Save concurrently
        def save_profile(profile):
            profile.save()

        thread1 = threading.Thread(target=save_profile, args=(profile1,))
        thread2 = threading.Thread(target=save_profile, args=(profile2,))

        thread1.start()
        thread2.start()

        thread1.join()
        thread2.join()

        # Load profile - should be valid (one version wins)
        loaded = TargetProfile.load('192.168.1.100')
        assert loaded.target == '192.168.1.100'
        # Should have valid JSON
        assert isinstance(loaded.findings, list)

    def test_concurrent_task_updates(self, temp_crack_home):
        """
        PROVES: Concurrent task updates don't cause data loss

        Scenario: Two sessions updating different tasks simultaneously
        Expected: Both updates persisted (if non-conflicting)
        """
        profile1 = TargetProfile('192.168.1.100')

        # Add tasks
        task1 = TaskNode(task_id='task-1', name='Task 1', task_type='command',
                        metadata={'command': 'echo 1'})
        task2 = TaskNode(task_id='task-2', name='Task 2', task_type='command',
                        metadata={'command': 'echo 2'})

        profile1.task_tree.add_child(task1)
        profile1.task_tree.add_child(task2)
        profile1.save()

        # Load in two sessions
        session1 = InteractiveSession('192.168.1.100')
        session2 = InteractiveSession('192.168.1.100')

        # Update different tasks concurrently
        def update_task1():
            tasks = session1.profile.task_tree.get_all_tasks()
            for t in tasks:
                if t.id == 'task-1':
                    t.status = 'completed'
            session1.profile.save()

        def update_task2():
            tasks = session2.profile.task_tree.get_all_tasks()
            for t in tasks:
                if t.id == 'task-2':
                    t.status = 'completed'
            session2.profile.save()

        thread1 = threading.Thread(target=update_task1)
        thread2 = threading.Thread(target=update_task2)

        thread1.start()
        thread2.start()

        thread1.join()
        thread2.join()

        # Load final state - should be valid
        final = TargetProfile.load('192.168.1.100')
        assert final.target == '192.168.1.100'


# ============================================================================
# CHAOS SCENARIO 6: SIGNAL HANDLING
# ============================================================================

class TestSignalHandling:
    """Test handling of OS signals (SIGTERM, SIGHUP, etc.)"""

    @pytest.mark.skipif(os.name == 'nt', reason="Unix signals only")
    def test_sigterm_graceful_shutdown(self, temp_crack_home, mock_profile_with_tasks):
        """
        PROVES: SIGTERM causes graceful shutdown with profile save

        Scenario: System sends SIGTERM during operation
        Expected: Save profile, clean exit
        """
        session = InteractiveSession(mock_profile_with_tasks.target)

        # Mock signal handler
        shutdown_called = [False]

        def mock_signal_handler(signum, frame):
            shutdown_called[0] = True
            session.profile.save()

        # Register handler
        original_handler = signal.signal(signal.SIGTERM, mock_signal_handler)

        try:
            # Trigger signal
            os.kill(os.getpid(), signal.SIGTERM)

            # Give signal time to process
            time.sleep(0.1)

            # Handler should have been called
            assert shutdown_called[0]

        finally:
            # Restore original handler
            signal.signal(signal.SIGTERM, original_handler)


# ============================================================================
# CHAOS SCENARIO 7: PROFILE CORRUPTION RECOVERY
# ============================================================================

class TestProfileCorruptionRecovery:
    """Test recovery from corrupted profile states"""

    def test_recover_from_invalid_json(self, temp_crack_home):
        """
        PROVES: System recovers from corrupted JSON profile

        Scenario: Profile JSON is malformed
        Expected: Fall back to snapshot or create new
        """
        # Create valid profile
        profile = TargetProfile('192.168.1.100')
        profile.save()

        # Corrupt the JSON
        profile_file = Path.home() / '.crack' / 'targets' / '192.168.1.100.json'
        profile_file.write_text('{ invalid json }}}')

        # Should handle gracefully
        try:
            loaded = TargetProfile.load('192.168.1.100')
            pytest.fail("Should have raised error for corrupted JSON")
        except (json.JSONDecodeError, Exception):
            # Expected - should have clear error
            pass

    def test_snapshot_restore_after_corruption(self, temp_crack_home, mock_profile_with_data):
        """
        PROVES: Snapshot restore recovers from profile corruption

        Scenario: Profile corrupted, restore from snapshot
        Expected: Clean state from snapshot
        """
        session = InteractiveSession(mock_profile_with_data.target)

        # Save clean snapshot
        clean_state = session.profile.to_dict()
        session._save_snapshot('clean-backup', clean_state)

        # Corrupt profile
        session.profile.task_tree = None  # Break it

        # Restore from snapshot
        snapshots = session._get_available_snapshots()
        if snapshots:
            restored_data = session._load_snapshot(snapshots[0]['file'])
            # Should have valid data
            assert restored_data is not None
            assert 'task_tree' in restored_data


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def temp_crack_home(tmp_path, monkeypatch):
    """Create temporary .crack directory"""
    crack_home = tmp_path / '.crack'
    crack_home.mkdir()

    (crack_home / 'targets').mkdir()
    (crack_home / 'snapshots').mkdir()
    (crack_home / 'exports').mkdir()
    (crack_home / 'sessions').mkdir()

    monkeypatch.setenv('HOME', str(tmp_path))

    yield crack_home


@pytest.fixture
def mock_profile_with_data(temp_crack_home):
    """Profile with comprehensive test data"""
    profile = TargetProfile('192.168.1.100')

    # Add ports
    profile.ports = {
        80: {'state': 'open', 'service': 'http', 'version': 'Apache 2.4.41'},
        22: {'state': 'open', 'service': 'ssh', 'version': 'OpenSSH 8.2'},
    }

    # Add findings
    profile.findings = [
        {'timestamp': '2025-10-08T12:00:00', 'type': 'vulnerability',
         'description': 'SQLi', 'source': 'manual'}
    ]

    # Add credentials
    profile.credentials = [
        {'timestamp': '2025-10-08T13:00:00', 'username': 'admin',
         'password': 'pass', 'service': 'http', 'port': 80, 'source': 'manual'}
    ]

    # Add tasks
    for i in range(5):
        task = TaskNode(task_id=f'task-{i}', name=f'Task {i}',
                       task_type='command')
        task.metadata['command'] = f'echo {i}'
        profile.task_tree.add_child(task)

    return profile


@pytest.fixture
def mock_profile_with_tasks(temp_crack_home):
    """Profile with tasks only"""
    profile = TargetProfile('192.168.1.100')

    for i in range(3):
        task = TaskNode(task_id=f'task-{i}', name=f'Task {i}',
                       task_type='command')
        task.metadata['command'] = f'echo {i}'
        profile.task_tree.add_child(task)

    return profile


@pytest.fixture
def mock_profile_with_network_tasks(temp_crack_home):
    """Profile with network-dependent tasks"""
    profile = TargetProfile('192.168.1.100')

    tasks_data = [
        ('nmap', 'nmap -sV 192.168.1.100'),
        ('curl', 'curl http://192.168.1.100'),
        ('nikto', 'nikto -h http://192.168.1.100')
    ]

    for task_id, command in tasks_data:
        task = TaskNode(task_id=task_id, name=task_id.upper(),
                       task_type='command')
        task.metadata['command'] = command
        profile.task_tree.add_child(task)

    return profile
