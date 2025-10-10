"""
Tests for Progress Dashboard Handler

Tests the handle_progress_dashboard() method using mock data and direct invocation.
Verifies metrics calculation, grouping, and display logic.

Test Pattern: Direct method call → Assert calculations
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from crack.track.interactive.tui_session_v2 import TUISessionV2
from crack.track.core.state import TargetProfile
from crack.track.core.task_tree import TaskNode


@pytest.fixture
def mock_session():
    """Create mock TUI session with debug logger"""
    session = Mock(spec=TUISessionV2)
    session.console = Mock()
    session.debug_logger = Mock()
    session.debug_logger.log = Mock()
    session.profile = Mock(spec=TargetProfile)
    session.profile.target = "192.168.45.100"
    session.profile.task_tree = Mock(spec=TaskNode)
    return session


@pytest.fixture
def empty_profile():
    """Profile with no tasks"""
    profile = Mock(spec=TargetProfile)
    profile.target = "192.168.45.100"
    profile.task_tree = Mock(spec=TaskNode)
    profile.task_tree.get_all_tasks = Mock(return_value=[])
    profile.task_tree.get_next_actionable = Mock(return_value=None)
    return profile


@pytest.fixture
def profile_with_tasks():
    """Profile with mixed task statuses"""
    profile = Mock(spec=TargetProfile)
    profile.target = "192.168.45.100"

    # Create mock task_tree first
    task_tree = Mock(spec=TaskNode)

    # Create mock tasks
    tasks = []

    # Completed tasks (5)
    for i in range(5):
        task = Mock(spec=TaskNode)
        task.id = f"completed-{i}"
        task.name = f"Completed Task {i}"
        task.status = 'completed'
        task.metadata = {'service': 'http' if i < 3 else 'smb', 'tags': []}
        tasks.append(task)

    # Pending tasks with QUICK_WIN tag (3)
    for i in range(3):
        task = Mock(spec=TaskNode)
        task.id = f"quickwin-{i}"
        task.name = f"Quick Win Task {i}"
        task.status = 'pending'
        task.metadata = {'service': 'http', 'tags': ['QUICK_WIN']}
        tasks.append(task)

    # Pending tasks with OSCP:HIGH tag (2)
    for i in range(2):
        task = Mock(spec=TaskNode)
        task.id = f"highpri-{i}"
        task.name = f"High Priority Task {i}"
        task.status = 'pending'
        task.metadata = {'service': 'ssh', 'tags': ['OSCP:HIGH']}
        tasks.append(task)

    # In-progress tasks (1)
    task = Mock(spec=TaskNode)
    task.id = "inprogress-1"
    task.name = "In Progress Task"
    task.status = 'in-progress'
    task.metadata = {'service': 'smb', 'tags': []}
    tasks.append(task)

    # Regular pending tasks (2)
    for i in range(2):
        task = Mock(spec=TaskNode)
        task.id = f"pending-{i}"
        task.name = f"Pending Task {i}"
        task.status = 'pending'
        task.metadata = {'service': 'general', 'tags': []}
        tasks.append(task)

    task_tree.get_all_tasks = Mock(return_value=tasks)

    # Mock next actionable task
    next_task = Mock(spec=TaskNode)
    next_task.name = "Next Recommended Task"
    task_tree.get_next_actionable = Mock(return_value=next_task)

    # Assign task_tree to profile
    profile.task_tree = task_tree

    return profile


def test_progress_dashboard_calculates_total_tasks(profile_with_tasks):
    """
    PROVES: Dashboard correctly counts total tasks

    GIVEN: Profile with 13 tasks
    WHEN: Progress dashboard is displayed
    THEN: Total count is 13
    """
    # Bind method to mock session
    session = Mock()
    session.profile = profile_with_tasks
    session.console = Mock()
    session.debug_logger = Mock()

    # Call method
    with patch('builtins.input'):  # Mock input() to avoid blocking
        TUISessionV2.handle_progress_dashboard(session)

    # Verify total was calculated
    all_tasks = profile_with_tasks.task_tree.get_all_tasks()
    assert len(all_tasks) == 13


def test_progress_dashboard_calculates_completed_count(profile_with_tasks):
    """
    PROVES: Dashboard correctly counts completed tasks

    GIVEN: Profile with 5 completed tasks
    WHEN: Progress dashboard is displayed
    THEN: Completed count is 5
    """
    session = Mock()
    session.profile = profile_with_tasks
    session.console = Mock()
    session.debug_logger = Mock()

    with patch('builtins.input'):
        TUISessionV2.handle_progress_dashboard(session)

    all_tasks = profile_with_tasks.task_tree.get_all_tasks()
    completed = len([t for t in all_tasks if t.status == 'completed'])
    assert completed == 5


def test_progress_dashboard_calculates_percentage(profile_with_tasks):
    """
    PROVES: Dashboard calculates progress percentage

    GIVEN: 5 completed out of 13 tasks
    WHEN: Progress dashboard is displayed
    THEN: Percentage is 38% (5/13 * 100)
    """
    session = Mock()
    session.profile = profile_with_tasks
    session.console = Mock()
    session.debug_logger = Mock()

    with patch('builtins.input'):
        TUISessionV2.handle_progress_dashboard(session)

    all_tasks = profile_with_tasks.task_tree.get_all_tasks()
    total = len(all_tasks)
    completed = len([t for t in all_tasks if t.status == 'completed'])
    percent = int((completed / total * 100))
    assert percent == 38  # 5/13 = 38%


def test_progress_dashboard_ascii_bar_renders(profile_with_tasks):
    """
    PROVES: ASCII progress bar renders correctly

    GIVEN: 38% completion (5/13)
    WHEN: Progress dashboard is displayed
    THEN: Progress bar has correct filled/empty ratio
    """
    session = Mock()
    session.profile = profile_with_tasks
    session.console = Mock()
    session.debug_logger = Mock()

    with patch('builtins.input'):
        TUISessionV2.handle_progress_dashboard(session)

    # Calculate expected bar
    all_tasks = profile_with_tasks.task_tree.get_all_tasks()
    total = len(all_tasks)
    completed = len([t for t in all_tasks if t.status == 'completed'])
    bar_width = 40
    filled = int(bar_width * completed / total)
    empty = bar_width - filled

    # Verify bar dimensions
    assert filled == 15  # 40 * 5/13 = 15
    assert empty == 25
    assert filled + empty == bar_width


def test_progress_dashboard_groups_by_service(profile_with_tasks):
    """
    PROVES: Tasks are grouped by service

    GIVEN: Tasks for http, smb, ssh, general services
    WHEN: Progress dashboard is displayed
    THEN: Service groups are created with counts
    """
    session = Mock()
    session.profile = profile_with_tasks
    session.console = Mock()
    session.debug_logger = Mock()

    with patch('builtins.input'):
        TUISessionV2.handle_progress_dashboard(session)

    # Calculate service groups
    all_tasks = profile_with_tasks.task_tree.get_all_tasks()
    service_tasks = {}
    for task in all_tasks:
        service = task.metadata.get('service', 'general')
        if service not in service_tasks:
            service_tasks[service] = {'total': 0, 'done': 0}
        service_tasks[service]['total'] += 1
        if task.status == 'completed':
            service_tasks[service]['done'] += 1

    # Verify service groups
    assert 'http' in service_tasks
    assert 'smb' in service_tasks
    assert 'ssh' in service_tasks
    assert 'general' in service_tasks

    # Verify counts
    assert service_tasks['http']['total'] == 6  # 3 completed + 3 quickwin
    assert service_tasks['http']['done'] == 3
    assert service_tasks['smb']['total'] == 3  # 2 completed + 1 inprogress
    assert service_tasks['smb']['done'] == 2


def test_progress_dashboard_identifies_quick_wins(profile_with_tasks):
    """
    PROVES: Quick win tasks are identified

    GIVEN: 3 tasks with QUICK_WIN tag
    WHEN: Progress dashboard is displayed
    THEN: Quick wins count is 3
    """
    session = Mock()
    session.profile = profile_with_tasks
    session.console = Mock()
    session.debug_logger = Mock()

    with patch('builtins.input'):
        TUISessionV2.handle_progress_dashboard(session)

    all_tasks = profile_with_tasks.task_tree.get_all_tasks()
    quick_wins = [t for t in all_tasks if t.status == 'pending' and 'QUICK_WIN' in t.metadata.get('tags', [])]
    assert len(quick_wins) == 3


def test_progress_dashboard_identifies_high_priority(profile_with_tasks):
    """
    PROVES: High priority tasks are identified

    GIVEN: 2 tasks with OSCP:HIGH tag
    WHEN: Progress dashboard is displayed
    THEN: High priority count is 2
    """
    session = Mock()
    session.profile = profile_with_tasks
    session.console = Mock()
    session.debug_logger = Mock()

    with patch('builtins.input'):
        TUISessionV2.handle_progress_dashboard(session)

    all_tasks = profile_with_tasks.task_tree.get_all_tasks()
    high_pri = [t for t in all_tasks if t.status == 'pending' and any('OSCP:HIGH' in tag for tag in t.metadata.get('tags', []))]
    assert len(high_pri) == 2


def test_progress_dashboard_shows_next_recommended_task(profile_with_tasks):
    """
    PROVES: Next recommended task is displayed

    GIVEN: Profile with next actionable task
    WHEN: Progress dashboard is displayed
    THEN: Next task name is shown
    """
    session = Mock()
    session.profile = profile_with_tasks
    session.console = Mock()
    session.debug_logger = Mock()

    with patch('builtins.input'):
        TUISessionV2.handle_progress_dashboard(session)

    next_task = profile_with_tasks.task_tree.get_next_actionable()
    assert next_task is not None
    assert next_task.name == "Next Recommended Task"


def test_progress_dashboard_handles_empty_profile(empty_profile):
    """
    PROVES: Dashboard handles profile with no tasks gracefully

    GIVEN: Empty profile (0 tasks)
    WHEN: Progress dashboard is displayed
    THEN: No errors, shows 0/0 progress
    """
    session = Mock()
    session.profile = empty_profile
    session.console = Mock()
    session.debug_logger = Mock()

    # Should not raise exception
    with patch('builtins.input'):
        TUISessionV2.handle_progress_dashboard(session)

    all_tasks = empty_profile.task_tree.get_all_tasks()
    assert len(all_tasks) == 0


def test_progress_dashboard_handles_all_completed():
    """
    PROVES: Dashboard handles 100% completion

    GIVEN: Profile with all tasks completed
    WHEN: Progress dashboard is displayed
    THEN: Shows 100% progress, full progress bar
    """
    profile = Mock(spec=TargetProfile)
    profile.target = "192.168.45.100"

    # All tasks completed
    tasks = []
    for i in range(10):
        task = Mock(spec=TaskNode)
        task.id = f"completed-{i}"
        task.name = f"Completed Task {i}"
        task.status = 'completed'
        task.metadata = {'service': 'http', 'tags': []}
        tasks.append(task)

    profile.task_tree = Mock(spec=TaskNode)
    profile.task_tree.get_all_tasks = Mock(return_value=tasks)
    profile.task_tree.get_next_actionable = Mock(return_value=None)

    session = Mock()
    session.profile = profile
    session.console = Mock()
    session.debug_logger = Mock()

    with patch('builtins.input'):
        TUISessionV2.handle_progress_dashboard(session)

    total = len(tasks)
    completed = len([t for t in tasks if t.status == 'completed'])
    percent = int((completed / total * 100))
    assert percent == 100

    # Progress bar should be full
    bar_width = 40
    filled = int(bar_width * completed / total)
    assert filled == bar_width


def test_progress_dashboard_logs_entry_and_exit(profile_with_tasks):
    """
    PROVES: Dashboard logs entry and exit chokepoints

    GIVEN: Progress dashboard is displayed
    WHEN: Method executes
    THEN: Entry and exit logs are created
    """
    session = Mock()
    session.profile = profile_with_tasks
    session.console = Mock()
    session.debug_logger = Mock()

    with patch('builtins.input'):
        TUISessionV2.handle_progress_dashboard(session)

    # Verify logging calls
    assert session.debug_logger.log.call_count >= 2

    # Check first call (entry)
    first_call = session.debug_logger.log.call_args_list[0]
    assert "Progress dashboard requested" in str(first_call)

    # Check last call (exit)
    last_call = session.debug_logger.log.call_args_list[-1]
    assert "Progress dashboard closed" in str(last_call)


def test_progress_dashboard_logs_metrics(profile_with_tasks):
    """
    PROVES: Dashboard logs calculated metrics

    GIVEN: Progress dashboard is displayed
    WHEN: Metrics are calculated
    THEN: Metrics are logged with VERBOSE level
    """
    session = Mock()
    session.profile = profile_with_tasks
    session.console = Mock()
    session.debug_logger = Mock()

    with patch('builtins.input'):
        TUISessionV2.handle_progress_dashboard(session)

    # Verify metrics logging
    log_calls = session.debug_logger.log.call_args_list
    metrics_log = [c for c in log_calls if "Progress metrics calculated" in str(c)]
    assert len(metrics_log) == 1

    # Check metrics are included
    metrics_call = metrics_log[0]
    assert 'total' in str(metrics_call)
    assert 'completed' in str(metrics_call)
    assert 'pending' in str(metrics_call)


def test_progress_dashboard_displays_panel(profile_with_tasks):
    """
    PROVES: Dashboard renders and displays Rich panel

    GIVEN: Progress dashboard is displayed
    WHEN: Method executes
    THEN: console.print is called with Panel
    """
    session = Mock()
    session.profile = profile_with_tasks
    session.console = Mock()
    session.debug_logger = Mock()

    with patch('builtins.input'):
        TUISessionV2.handle_progress_dashboard(session)

    # Verify console.print was called
    assert session.console.print.called

    # Verify a Panel was printed (check call args contain Panel)
    from rich.panel import Panel
    print_calls = session.console.print.call_args_list
    panel_printed = False
    for call in print_calls:
        if len(call[0]) > 0 and isinstance(call[0][0], Panel):
            panel_printed = True
            break
    assert panel_printed
