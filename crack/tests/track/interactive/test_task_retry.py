"""
Tests for Task Retry Handler

Tests verify:
1. Retry sorting by failed_at timestamp (most recent first)
2. failed_at metadata added on task failure
3. retry_count increments on each failure
4. Tasks without failed_at handled correctly (end of list)
5. ErrorHandler shows OSCP-specific messages
6. Error suggestions display properly
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch, MagicMock
from crack.track.core.state import TargetProfile
from crack.track.core.task_tree import TaskNode
from crack.track.interactive.session import InteractiveSession
from crack.track.interactive.components.error_handler import ErrorHandler, ErrorType


@pytest.fixture
def mock_profile():
    """Create mock profile with task tree"""
    profile = TargetProfile('192.168.45.100')

    # Create parent task
    parent = TaskNode('parent', 'Test Parent', 'parent')
    profile.task_tree = parent

    return profile


@pytest.fixture
def mock_session(mock_profile, tmp_path):
    """Create mock session with profile"""
    with patch('crack.track.interactive.session.TargetProfile.exists', return_value=False):
        with patch('crack.track.interactive.session.TargetProfile.load', return_value=mock_profile):
            with patch('crack.track.interactive.session.TargetProfile.save'):
                # Override snapshots directory for test isolation
                InteractiveSession.SNAPSHOTS_BASE_DIR = str(tmp_path / 'snapshots')

                session = InteractiveSession('192.168.45.100')
                session.profile = mock_profile
                return session


def test_retry_sorting_by_failed_at_newest_first(mock_session, mock_profile):
    """
    PROVES: Retry tasks are sorted by failed_at timestamp, newest first

    User scenario: User has 3 failed tasks with different failure times.
    Expected: Most recently failed task appears first in retry list.
    """
    now = datetime.now()

    # Create 3 failed tasks with different failure times
    task1 = TaskNode('task1', 'First Failed', 'command')
    task1.status = 'failed'
    task1.metadata['failed_at'] = (now - timedelta(hours=2)).isoformat()
    task1.metadata['command'] = 'nmap -p- 192.168.45.100'

    task2 = TaskNode('task2', 'Second Failed', 'command')
    task2.status = 'failed'
    task2.metadata['failed_at'] = (now - timedelta(minutes=5)).isoformat()  # Most recent
    task2.metadata['command'] = 'gobuster dir -u http://192.168.45.100'

    task3 = TaskNode('task3', 'Third Failed', 'command')
    task3.status = 'failed'
    task3.metadata['failed_at'] = (now - timedelta(hours=1)).isoformat()
    task3.metadata['command'] = 'nikto -h http://192.168.45.100'

    # Add to profile
    mock_profile.task_tree.add_child(task1)
    mock_profile.task_tree.add_child(task2)
    mock_profile.task_tree.add_child(task3)

    # Get retryable tasks
    retryable = mock_session._get_retryable_tasks()

    # Verify order: task2 (newest) -> task3 -> task1 (oldest)
    assert len(retryable) == 3
    assert retryable[0].id == 'task2', "Most recent failure should be first"
    assert retryable[1].id == 'task3', "Middle failure should be second"
    assert retryable[2].id == 'task1', "Oldest failure should be last"


def test_failed_at_timestamp_added_on_failure(mock_session, mock_profile):
    """
    PROVES: failed_at timestamp is added when task fails

    User scenario: Task execution fails with non-zero exit code.
    Expected: Task metadata contains failed_at timestamp.
    """
    task = TaskNode('test-task', 'Test Task', 'command')
    task.metadata['command'] = 'false'  # Command that fails
    mock_profile.task_tree.add_child(task)

    # Mock subprocess result (failure)
    mock_result = Mock()
    mock_result.returncode = 1

    before_time = datetime.now()

    # Mock input: first 'y' to execute, then 'n' to not mark complete
    with patch('subprocess.run', return_value=mock_result):
        with patch('builtins.input', side_effect=['y', 'n']):
            mock_session.execute_task(task)

    after_time = datetime.now()

    # Verify failed_at was set
    assert 'failed_at' in task.metadata, "failed_at should be added on failure"

    # Verify timestamp is recent
    failed_at = datetime.fromisoformat(task.metadata['failed_at'])
    assert before_time <= failed_at <= after_time, "failed_at should be current timestamp"


def test_retry_count_increments(mock_session, mock_profile):
    """
    PROVES: retry_count increments on each failure

    User scenario: Task fails, user retries, fails again.
    Expected: retry_count = 2 after two failures.
    """
    task = TaskNode('test-task', 'Test Task', 'command')
    task.metadata['command'] = 'false'
    mock_profile.task_tree.add_child(task)

    mock_result = Mock()
    mock_result.returncode = 1

    # First failure: 'y' to execute, 'n' to not mark complete
    with patch('subprocess.run', return_value=mock_result):
        with patch('builtins.input', side_effect=['y', 'n']):
            mock_session.execute_task(task)

    assert task.metadata.get('retry_count') == 1, "First failure should set retry_count=1"

    # Second failure: 'y' to execute, 'n' to not mark complete
    with patch('subprocess.run', return_value=mock_result):
        with patch('builtins.input', side_effect=['y', 'n']):
            mock_session.execute_task(task)

    assert task.metadata.get('retry_count') == 2, "Second failure should increment to retry_count=2"


def test_tasks_without_failed_at_handled_correctly(mock_session, mock_profile):
    """
    PROVES: Tasks without failed_at timestamp are handled correctly

    User scenario: Mix of tasks with and without failed_at timestamps.
    Expected: Tasks with failed_at sorted first, tasks without go to end.
    """
    now = datetime.now()

    # Task with failed_at
    task1 = TaskNode('task1', 'Has Timestamp', 'command')
    task1.status = 'failed'
    task1.metadata['failed_at'] = now.isoformat()
    task1.metadata['command'] = 'nmap -p- 192.168.45.100'

    # Task without failed_at (legacy)
    task2 = TaskNode('task2', 'No Timestamp', 'command')
    task2.status = 'failed'
    task2.metadata['command'] = 'gobuster dir -u http://192.168.45.100'
    # Note: no failed_at

    # Task with earlier failed_at
    task3 = TaskNode('task3', 'Earlier Timestamp', 'command')
    task3.status = 'failed'
    task3.metadata['failed_at'] = (now - timedelta(hours=1)).isoformat()
    task3.metadata['command'] = 'nikto -h http://192.168.45.100'

    mock_profile.task_tree.add_child(task1)
    mock_profile.task_tree.add_child(task2)
    mock_profile.task_tree.add_child(task3)

    retryable = mock_session._get_retryable_tasks()

    # Verify order: task1 (newest) -> task3 (older) -> task2 (no timestamp)
    assert len(retryable) == 3
    assert retryable[0].id == 'task1', "Newest timestamp first"
    assert retryable[1].id == 'task3', "Older timestamp second"
    assert retryable[2].id == 'task2', "No timestamp last"


def test_error_handler_shows_oscp_suggestions(mock_session):
    """
    PROVES: ErrorHandler provides OSCP-specific suggestions

    User scenario: Task fails with "command not found: nmap".
    Expected: ErrorHandler suggests installing nmap, mentions Kali Linux.
    """
    error_handler = ErrorHandler()

    # Test nmap error
    suggestions = error_handler.get_suggestions(
        ErrorType.EXECUTION,
        "nmap: command not found"
    )

    assert len(suggestions) > 0, "Should provide suggestions"
    assert any('nmap' in s.lower() for s in suggestions), "Should mention nmap"
    assert any('kali' in s.lower() or 'install' in s.lower() for s in suggestions), \
        "Should mention Kali or installation"


def test_error_handler_permission_denied_suggestions(mock_session):
    """
    PROVES: ErrorHandler provides OSCP-specific permission error suggestions

    User scenario: Task fails with "permission denied".
    Expected: ErrorHandler suggests sudo, raw socket info, OSCP context.
    """
    error_handler = ErrorHandler()

    suggestions = error_handler.get_suggestions(
        ErrorType.PERMISSION,
        "Operation not permitted: raw socket access denied"
    )

    assert len(suggestions) > 0, "Should provide suggestions"
    assert any('sudo' in s.lower() for s in suggestions), "Should mention sudo"
    assert any('oscp' in s.lower() or 'root' in s.lower() for s in suggestions), \
        "Should mention OSCP or root privileges"


def test_error_handler_network_unreachable_suggestions(mock_session):
    """
    PROVES: ErrorHandler provides network troubleshooting suggestions

    User scenario: Task fails with "network unreachable".
    Expected: ErrorHandler suggests VPN check, OSCP context.
    """
    error_handler = ErrorHandler()

    # Use exact pattern that triggers OSCP network_unreachable suggestions
    suggestions = error_handler.get_suggestions(
        ErrorType.NETWORK,
        "network unreachable"  # Lowercase to match OSCP pattern
    )

    assert len(suggestions) > 0, "Should provide suggestions"
    assert any('vpn' in s.lower() or 'tun0' in s.lower() for s in suggestions), \
        "Should mention VPN or tun0"
    assert any('oscp' in s.lower() or 'ovpn' in s.lower() for s in suggestions), \
        "Should mention OSCP or OVPN"


def test_failure_reason_stored_in_metadata(mock_session, mock_profile):
    """
    PROVES: Failure reason is stored in task metadata

    User scenario: Task fails with specific error.
    Expected: Task metadata contains failure_reason with error details.
    """
    task = TaskNode('test-task', 'Test Task', 'command')
    task.metadata['command'] = 'false'
    mock_profile.task_tree.add_child(task)

    mock_result = Mock()
    mock_result.returncode = 127

    with patch('subprocess.run', return_value=mock_result):
        with patch('builtins.input', side_effect=['y', 'n']):
            mock_session.execute_task(task)

    assert 'failure_reason' in task.metadata, "failure_reason should be stored"
    assert 'Exit code 127' in task.metadata['failure_reason'], \
        "failure_reason should contain exit code"


def test_completed_tasks_sorted_after_failed(mock_session, mock_profile):
    """
    PROVES: Completed tasks appear after failed tasks in retry list

    User scenario: Mix of failed and completed tasks.
    Expected: All failed tasks appear before completed tasks.
    """
    now = datetime.now()

    # Failed task
    task1 = TaskNode('task1', 'Failed Task', 'command')
    task1.status = 'failed'
    task1.metadata['failed_at'] = now.isoformat()
    task1.metadata['command'] = 'nmap -p- 192.168.45.100'

    # Completed task (can be retried)
    task2 = TaskNode('task2', 'Completed Task', 'command')
    task2.status = 'completed'
    task2.metadata['last_run'] = now.isoformat()
    task2.metadata['command'] = 'gobuster dir -u http://192.168.45.100'

    # Another failed task
    task3 = TaskNode('task3', 'Another Failed', 'command')
    task3.status = 'failed'
    task3.metadata['failed_at'] = (now - timedelta(minutes=30)).isoformat()
    task3.metadata['command'] = 'nikto -h http://192.168.45.100'

    mock_profile.task_tree.add_child(task1)
    mock_profile.task_tree.add_child(task2)
    mock_profile.task_tree.add_child(task3)

    retryable = mock_session._get_retryable_tasks()

    # Verify all failed tasks come before completed tasks
    failed_indices = [i for i, t in enumerate(retryable) if t.status == 'failed']
    completed_indices = [i for i, t in enumerate(retryable) if t.status == 'completed']

    assert len(failed_indices) == 2, "Should have 2 failed tasks"
    assert len(completed_indices) == 1, "Should have 1 completed task"

    if failed_indices and completed_indices:
        assert max(failed_indices) < min(completed_indices), \
            "All failed tasks should come before completed tasks"
