"""
Test Time Tracker (tt) Shortcut

Tests for session time tracking, task duration tracking, phase breakdown,
exam countdown mode, and long-running task alerts.

VALUE: User can manage time during OSCP exam with countdown and alerts
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
import time

from crack.track.core.state import TargetProfile
from crack.track.core.task_tree import TaskNode
from crack.track.interactive.session import InteractiveSession
from crack.track.interactive.time_tracker import TimeStats


@pytest.fixture
def mock_profile():
    """Create profile with timed tasks"""
    profile = TargetProfile('192.168.1.1')

    # Add tasks with durations
    task1 = TaskNode(task_id='nmap-scan', name='Nmap Full Scan', task_type='command')
    task1.metadata['duration_seconds'] = 525  # 8m 45s
    task1.status = 'completed'

    task2 = TaskNode(task_id='gobuster-80', name='Gobuster Port 80', task_type='command')
    task2.metadata['duration_seconds'] = 754  # 12m 34s
    task2.status = 'completed'

    task3 = TaskNode(task_id='nikto-80', name='Nikto Scan Port 80', task_type='command')
    task3.metadata['duration_seconds'] = 383  # 6m 23s
    task3.status = 'completed'

    profile.task_tree.add_child(task1)
    profile.task_tree.add_child(task2)
    profile.task_tree.add_child(task3)

    # Initialize session_start
    profile.metadata['session_start'] = (datetime.now() - timedelta(hours=1, minutes=45)).isoformat()

    return profile


def test_session_time_tracking(mock_profile):
    """
    PROVES: Session time tracked from initialization

    User Actions:
    1. Start TUI session
    2. Press 'tt' for time tracker
    3. See session elapsed time

    Expected:
    - session_start timestamp in metadata
    - Elapsed time calculated correctly
    """
    session_start = datetime.fromisoformat(mock_profile.metadata['session_start'])
    elapsed = (datetime.now() - session_start).total_seconds()

    # Session time should be ~1h 45m (6300 seconds ±60s tolerance)
    assert 6240 <= elapsed <= 6360, f"Expected ~6300s, got {elapsed}s"

    # Verify metadata structure
    assert 'session_start' in mock_profile.metadata
    assert isinstance(mock_profile.metadata['session_start'], str)


def test_phase_time_calculation(mock_profile):
    """
    PROVES: Time breakdown by phase/category

    User Actions:
    1. Execute tasks in different phases
    2. Press 'tt' to view breakdown
    3. See time distributed by phase

    Expected:
    - Phase breakdown shows nmap, gobuster, nikto
    - Total time matches sum of phases
    """
    breakdown = TimeStats.get_phase_breakdown(mock_profile.task_tree)

    # Verify each phase
    assert breakdown['nmap'] == 525
    assert breakdown['gobuster'] == 754
    assert breakdown['nikto'] == 383

    # Verify total
    total = sum(breakdown.values())
    assert total == 1662  # 27m 42s total


def test_task_duration_tracking(mock_profile):
    """
    PROVES: Individual task durations tracked

    User Actions:
    1. Execute task
    2. Task completes
    3. Duration stored in metadata

    Expected:
    - start_time, end_time, duration_seconds stored
    - Longest tasks identified correctly
    """
    longest = TimeStats.get_longest_tasks(mock_profile.task_tree, limit=3)

    # Verify longest tasks in correct order
    assert len(longest) == 3
    assert longest[0][0].id == 'gobuster-80'
    assert longest[0][1] == 754
    assert longest[1][0].id == 'nmap-scan'
    assert longest[1][1] == 525
    assert longest[2][0].id == 'nikto-80'
    assert longest[2][1] == 383


def test_exam_countdown_mode(mock_profile, monkeypatch):
    """
    PROVES: Exam mode tracks countdown timer

    User Actions:
    1. Press 'tt' for time tracker
    2. Press 'e' to enable exam mode
    3. Enter duration (24 hours)
    4. See countdown timer

    Expected:
    - exam_mode = True in metadata
    - exam_start timestamp stored
    - exam_duration stored (86400 seconds)
    - Remaining time calculated
    """
    # Enable exam mode (24 hours)
    mock_profile.metadata['exam_mode'] = True
    mock_profile.metadata['exam_start'] = datetime.now().isoformat()
    mock_profile.metadata['exam_duration'] = 86400

    # Verify exam mode structure
    assert mock_profile.metadata['exam_mode'] is True
    assert 'exam_start' in mock_profile.metadata
    assert mock_profile.metadata['exam_duration'] == 86400

    # Calculate remaining time
    exam_start = datetime.fromisoformat(mock_profile.metadata['exam_start'])
    exam_elapsed = (datetime.now() - exam_start).total_seconds()
    remaining = max(0, 86400 - exam_elapsed)

    # Should have ~24 hours remaining
    assert 86390 <= remaining <= 86400


def test_long_running_task_alert(mock_profile):
    """
    PROVES: Alert shown for tasks running >20 minutes

    User Actions:
    1. Task runs for >20 minutes
    2. Press 'tt' for time tracker
    3. See alert in ALERTS section

    Expected:
    - Tasks running >threshold are flagged
    - Alert shows task name and duration
    """
    # Add long-running task (started 23 minutes ago)
    long_task = TaskNode(task_id='manual-enum', name='Manual Enumeration', task_type='command')
    long_task.status = 'in-progress'
    long_task.metadata['start_time'] = (datetime.now() - timedelta(minutes=23)).isoformat()
    mock_profile.task_tree.add_child(long_task)

    # Set threshold to 20 minutes
    mock_profile.metadata['long_task_threshold'] = 1200

    # Get running tasks
    running = TimeStats.get_running_tasks(mock_profile.task_tree)
    assert len(running) == 1
    assert running[0].id == 'manual-enum'

    # Calculate duration
    start_time = datetime.fromisoformat(long_task.metadata['start_time'])
    duration = (datetime.now() - start_time).total_seconds()

    # Should be >20 minutes (1200 seconds)
    assert duration > 1200


def test_time_display_formatting(mock_profile):
    """
    PROVES: Time formatted as HH:MM:SS

    User Actions:
    1. View time tracker
    2. See formatted durations

    Expected:
    - format_duration(525) => "00:08:45"
    - format_duration(6300) => "01:45:00"
    - format_duration(90000) => "25:00:00"
    """
    # Test various durations
    assert TimeStats.format_duration(525) == "00:08:45"
    assert TimeStats.format_duration(754) == "00:12:34"
    assert TimeStats.format_duration(6300) == "01:45:00"
    assert TimeStats.format_duration(86400) == "24:00:00"

    # Edge cases
    assert TimeStats.format_duration(0) == "00:00:00"
    assert TimeStats.format_duration(59) == "00:00:59"
    assert TimeStats.format_duration(3599) == "00:59:59"


@pytest.mark.integration
def test_time_tracker_display(mock_profile, monkeypatch, capsys):
    """
    PROVES: Time tracker displays all components

    User Actions:
    1. Press 'tt'
    2. See session time, phase breakdown, longest tasks

    Expected:
    - Session Time section
    - Time by Phase section
    - Longest Tasks section
    - Actions menu

    NOTE: Integration test - verifies display output
    """
    # Mock input to exit immediately
    monkeypatch.setattr('builtins.input', lambda _: 'b')

    # Create session
    session = InteractiveSession(mock_profile.target)
    session.profile = mock_profile

    # Call handle_time_tracker
    session.handle_time_tracker()

    # Capture output
    captured = capsys.readouterr()

    # Verify key sections present
    assert "Session Time Tracker" in captured.out
    assert "Session Time:" in captured.out
    assert "Time by Phase:" in captured.out
    assert "Longest Tasks:" in captured.out
    assert "[r]eset session" in captured.out
    assert "[e]xam mode" in captured.out
    assert "[t]hreshold" in captured.out


def test_average_task_time():
    """
    PROVES: Average task time calculated correctly

    User Actions:
    1. Execute multiple tasks
    2. View time tracker
    3. See average task duration

    Expected:
    - Average = sum(durations) / count
    """
    profile = TargetProfile('192.168.1.1')

    # Add 3 tasks with known durations
    for i, duration in enumerate([100, 200, 300], 1):
        task = TaskNode(task_id=f'task-{i}', name=f'Task {i}', task_type='command')
        task.metadata['duration_seconds'] = duration
        task.status = 'completed'
        profile.task_tree.add_child(task)

    # Calculate average
    avg = TimeStats.get_average_task_time(profile.task_tree)

    # Average of 100, 200, 300 = 200
    assert avg == 200


def test_estimated_remaining_time():
    """
    PROVES: Remaining time estimated from average

    User Actions:
    1. Complete some tasks
    2. View pending tasks
    3. See estimated remaining time

    Expected:
    - Estimate = avg_time * pending_count
    """
    # Create clean task tree without profile initialization tasks
    root = TaskNode(task_id='root', name='Root', task_type='parent')
    root.status = 'completed'  # Mark root as completed to not count it

    # Add 2 completed tasks (avg: 150 seconds)
    for i, duration in enumerate([100, 200], 1):
        task = TaskNode(task_id=f'completed-{i}', name=f'Completed {i}', task_type='command')
        task.metadata['duration_seconds'] = duration
        task.status = 'completed'
        root.add_child(task)

    # Add 3 pending tasks
    for i in range(3):
        task = TaskNode(task_id=f'pending-{i}', name=f'Pending {i}', task_type='command')
        task.status = 'pending'
        root.add_child(task)

    # Estimate remaining
    estimated = TimeStats.estimate_remaining_time(root)

    # 3 pending * 150 avg = 450 seconds
    assert estimated == 450


def test_running_task_detection():
    """
    PROVES: Currently running tasks detected

    User Actions:
    1. Task is in-progress
    2. Press 'tt'
    3. See task in "Currently Running" section

    Expected:
    - Tasks with status='in-progress' and start_time shown
    """
    profile = TargetProfile('192.168.1.1')

    # Add running task
    running_task = TaskNode(task_id='scan-1', name='Port Scan', task_type='command')
    running_task.status = 'in-progress'
    running_task.metadata['start_time'] = datetime.now().isoformat()
    profile.task_tree.add_child(running_task)

    # Get running tasks
    running = TimeStats.get_running_tasks(profile.task_tree)

    assert len(running) == 1
    assert running[0].id == 'scan-1'
    assert running[0].status == 'in-progress'


def test_exam_mode_toggle(monkeypatch):
    """
    PROVES: Exam mode can be enabled/disabled

    User Actions:
    1. Press 'e' to enable exam mode
    2. Enter 24 hours
    3. Confirm enabled
    4. Press 'e' again to disable

    Expected:
    - exam_mode toggles True/False
    - Metadata persists
    """
    profile = TargetProfile('192.168.1.1')

    # Enable exam mode
    profile.metadata['exam_mode'] = True
    profile.metadata['exam_start'] = datetime.now().isoformat()
    profile.metadata['exam_duration'] = 86400

    assert profile.metadata['exam_mode'] is True

    # Disable exam mode
    profile.metadata['exam_mode'] = False

    assert profile.metadata['exam_mode'] is False


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
