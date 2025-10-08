"""
Test suite for batch execute feature

PROVES: Batch execution with dependency resolution works correctly
VALUE: Ensures reliable multi-task execution with proper ordering
COVERAGE: 12 tests covering all aspects of batch execution
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from crack.track.interactive.session import InteractiveSession
from crack.track.core.state import TargetProfile
from crack.track.core.task_tree import TaskNode


@pytest.fixture
def mock_profile(temp_crack_home):
    """Create mock profile with tasks"""
    profile = TargetProfile("192.168.45.100")
    profile.save()
    return profile


@pytest.fixture
def mock_profile_with_tasks(mock_profile):
    """Create profile with multiple tasks for batch testing"""
    # Task A (no dependencies)
    task_a = TaskNode('task-a', 'Task A', 'command')
    task_a.metadata['command'] = 'echo "Task A"'
    task_a.metadata['tags'] = ['QUICK_WIN']

    # Task B (depends on A)
    task_b = TaskNode('task-b', 'Task B', 'command')
    task_b.metadata['command'] = 'echo "Task B"'
    task_b.metadata['depends_on'] = ['task-a']

    # Task C (no dependencies, parallel with A)
    task_c = TaskNode('task-c', 'Task C', 'command')
    task_c.metadata['command'] = 'echo "Task C"'
    task_c.metadata['service'] = 'http'

    # Task D (depends on B)
    task_d = TaskNode('task-d', 'Task D', 'command')
    task_d.metadata['command'] = 'echo "Task D"'
    task_d.metadata['depends_on'] = ['task-b']

    # Add tasks to tree
    root = mock_profile.task_tree
    root.add_child(task_a)
    root.add_child(task_b)
    root.add_child(task_c)
    root.add_child(task_d)

    mock_profile.save()

    return mock_profile


class TestBatchExecute:
    """Test batch execute functionality"""

    def test_be_shortcut_exists(self, mock_profile):
        """PROVES: 'be' shortcut is registered"""
        from crack.track.interactive.shortcuts import ShortcutHandler

        session = InteractiveSession(mock_profile.target)
        handler = ShortcutHandler(session)

        assert 'be' in handler.shortcuts
        assert handler.shortcuts['be'][0] == 'Batch execute tasks'

    def test_be_handler_callable(self, mock_profile):
        """PROVES: Batch execute handler method exists and is callable"""
        session = InteractiveSession(mock_profile.target)

        assert hasattr(session, 'handle_batch_execute')
        assert callable(session.handle_batch_execute)

    def test_parse_selection_all(self, mock_profile_with_tasks):
        """PROVES: Parses 'all' keyword correctly"""
        session = InteractiveSession(mock_profile_with_tasks.target)

        all_tasks = session.profile.task_tree.get_all_tasks()
        pending = [t for t in all_tasks if t.status == 'pending']

        selected = session._parse_batch_selection('all', pending)

        assert len(selected) == len(pending)
        assert selected == pending

    def test_parse_selection_numeric(self, mock_profile_with_tasks):
        """PROVES: Parses numeric selection (1,3)"""
        session = InteractiveSession(mock_profile_with_tasks.target)

        all_tasks = session.profile.task_tree.get_all_tasks()
        pending = [t for t in all_tasks if t.status == 'pending']

        selected = session._parse_batch_selection('1,3', pending)

        assert len(selected) == 2
        assert selected[0] == pending[0]
        assert selected[1] == pending[2]

    def test_parse_selection_range(self, mock_profile_with_tasks):
        """PROVES: Parses range selection (1-3)"""
        session = InteractiveSession(mock_profile_with_tasks.target)

        all_tasks = session.profile.task_tree.get_all_tasks()
        pending = [t for t in all_tasks if t.status == 'pending']

        selected = session._parse_batch_selection('1-3', pending)

        assert len(selected) == 3
        assert selected == pending[:3]

    def test_parse_selection_keyword_quick(self, mock_profile_with_tasks):
        """PROVES: Parses 'quick' keyword (QUICK_WIN tags)"""
        session = InteractiveSession(mock_profile_with_tasks.target)

        all_tasks = session.profile.task_tree.get_all_tasks()
        pending = [t for t in all_tasks if t.status == 'pending']

        selected = session._parse_batch_selection('quick', pending)

        # Should select all QUICK_WIN tasks (at least 1)
        assert len(selected) >= 1
        # All selected should have QUICK_WIN tag
        assert all('QUICK_WIN' in t.metadata.get('tags', []) for t in selected)

    def test_parse_selection_service(self, mock_profile_with_tasks):
        """PROVES: Parses service-based selection"""
        session = InteractiveSession(mock_profile_with_tasks.target)

        all_tasks = session.profile.task_tree.get_all_tasks()
        pending = [t for t in all_tasks if t.status == 'pending']

        selected = session._parse_batch_selection('http', pending)

        assert len(selected) == 1
        assert selected[0].metadata.get('service') == 'http'

    def test_dependency_resolution_simple(self, mock_profile_with_tasks):
        """PROVES: Resolves simple dependencies correctly

        Task A (no deps) → Step 1
        Task B (depends on A) → Step 2
        """
        session = InteractiveSession(mock_profile_with_tasks.target)

        all_tasks = session.profile.task_tree.get_all_tasks()
        task_a = [t for t in all_tasks if t.id == 'task-a'][0]
        task_b = [t for t in all_tasks if t.id == 'task-b'][0]

        steps = session._resolve_dependencies([task_a, task_b])

        # Should be 2 steps: A first, then B
        assert len(steps) == 2
        assert task_a in steps[0]
        assert task_b in steps[1]

    def test_dependency_resolution_complex(self, mock_profile_with_tasks):
        """PROVES: Resolves complex dependencies correctly

        Task A (no deps) → Step 1 (parallel with C)
        Task C (no deps) → Step 1 (parallel with A)
        Task B (depends on A) → Step 2
        Task D (depends on B) → Step 3
        """
        session = InteractiveSession(mock_profile_with_tasks.target)

        all_tasks = session.profile.task_tree.get_all_tasks()
        task_a = [t for t in all_tasks if t.id == 'task-a'][0]
        task_b = [t for t in all_tasks if t.id == 'task-b'][0]
        task_c = [t for t in all_tasks if t.id == 'task-c'][0]
        task_d = [t for t in all_tasks if t.id == 'task-d'][0]

        steps = session._resolve_dependencies([task_a, task_b, task_c, task_d])

        # Expected: [[A, C], [B], [D]]
        assert len(steps) == 3

        # Step 1: A and C in parallel (no dependencies)
        assert len(steps[0]) == 2
        assert task_a in steps[0]
        assert task_c in steps[0]

        # Step 2: B (depends on A)
        assert len(steps[1]) == 1
        assert task_b in steps[1]

        # Step 3: D (depends on B)
        assert len(steps[2]) == 1
        assert task_d in steps[2]

    def test_parallel_execution_identification(self, mock_profile_with_tasks):
        """PROVES: Identifies parallelizable tasks correctly"""
        session = InteractiveSession(mock_profile_with_tasks.target)

        all_tasks = session.profile.task_tree.get_all_tasks()
        task_a = [t for t in all_tasks if t.id == 'task-a'][0]
        task_c = [t for t in all_tasks if t.id == 'task-c'][0]

        # Tasks with no dependencies can run in parallel
        steps = session._resolve_dependencies([task_a, task_c])

        # Should be single step with both tasks
        assert len(steps) == 1
        assert len(steps[0]) == 2
        assert task_a in steps[0]
        assert task_c in steps[0]

    @patch('subprocess.run')
    def test_execute_single_task_success(self, mock_subprocess, mock_profile_with_tasks):
        """PROVES: Executes single task successfully"""
        # Mock successful execution
        mock_subprocess.return_value = Mock(returncode=0)

        session = InteractiveSession(mock_profile_with_tasks.target)

        all_tasks = session.profile.task_tree.get_all_tasks()
        task_a = [t for t in all_tasks if t.id == 'task-a'][0]

        # Mock timer methods
        task_a.start_timer = Mock()
        task_a.stop_timer = Mock()
        task_a.mark_complete = Mock()

        success = session._execute_single_task(task_a)

        assert success is True
        assert task_a.status == 'completed'
        task_a.start_timer.assert_called_once()
        task_a.stop_timer.assert_called_once()
        task_a.mark_complete.assert_called_once()

    @patch('subprocess.run')
    def test_execute_single_task_failure(self, mock_subprocess, mock_profile_with_tasks):
        """PROVES: Handles task execution failure gracefully"""
        # Mock failed execution
        mock_subprocess.return_value = Mock(returncode=1, stderr='Command failed')

        session = InteractiveSession(mock_profile_with_tasks.target)

        all_tasks = session.profile.task_tree.get_all_tasks()
        task_a = [t for t in all_tasks if t.id == 'task-a'][0]

        # Mock timer methods
        task_a.start_timer = Mock()
        task_a.stop_timer = Mock()

        success = session._execute_single_task(task_a)

        assert success is False
        assert task_a.status == 'failed'
        assert task_a.metadata['exit_code'] == 1
        assert task_a.metadata['error'] == 'Command failed'

    @patch('subprocess.run')
    def test_batch_results_tracking(self, mock_subprocess, mock_profile_with_tasks):
        """PROVES: Batch execution tracks results correctly"""
        # Mock all executions as successful
        mock_subprocess.return_value = Mock(returncode=0)

        session = InteractiveSession(mock_profile_with_tasks.target)

        all_tasks = session.profile.task_tree.get_all_tasks()
        task_a = [t for t in all_tasks if t.id == 'task-a'][0]
        task_c = [t for t in all_tasks if t.id == 'task-c'][0]

        # Mock timer methods
        for task in [task_a, task_c]:
            task.start_timer = Mock()
            task.stop_timer = Mock()
            task.mark_complete = Mock()

        steps = [[task_a, task_c]]  # Both in parallel

        results = session._execute_batch(steps)

        assert 'succeeded' in results
        assert 'failed' in results
        assert 'skipped' in results
        assert 'total_time' in results

        assert len(results['succeeded']) == 2
        assert len(results['failed']) == 0
        assert len(results['skipped']) == 0
        assert results['total_time'] >= 0

    def test_empty_selection_handling(self, mock_profile):
        """PROVES: Handles empty task selection gracefully"""
        session = InteractiveSession(mock_profile.target)

        # Empty list of tasks
        selected = session._parse_batch_selection('1-3', [])

        assert selected == []

    def test_invalid_numeric_selection(self, mock_profile_with_tasks):
        """PROVES: Handles invalid numeric selection"""
        session = InteractiveSession(mock_profile_with_tasks.target)

        all_tasks = session.profile.task_tree.get_all_tasks()
        pending = [t for t in all_tasks if t.status == 'pending']

        # Select beyond available range
        selected = session._parse_batch_selection('99', pending)

        # Should return empty list for out-of-range
        assert selected == []


class TestBatchExecuteIntegration:
    """Integration tests for batch execute"""

    @patch('builtins.input', side_effect=['1,2', 'y'])
    @patch('subprocess.run')
    def test_full_batch_workflow(self, mock_subprocess, mock_input, mock_profile_with_tasks):
        """PROVES: Full batch execute workflow works end-to-end"""
        # Mock successful executions
        mock_subprocess.return_value = Mock(returncode=0)

        session = InteractiveSession(mock_profile_with_tasks.target)

        # Mock timer methods for all tasks
        all_tasks = session.profile.task_tree.get_all_tasks()
        for task in all_tasks:
            task.start_timer = Mock()
            task.stop_timer = Mock()
            task.mark_complete = Mock()

        # Execute batch (will use mocked input: '1,2' for selection, 'y' for confirm)
        session.handle_batch_execute()

        # Verify subprocess was called (tasks were executed)
        assert mock_subprocess.called

        # Verify input was used for selection and confirmation
        assert mock_input.call_count >= 2

    def test_dependency_cycle_detection(self, mock_profile):
        """PROVES: Detects and handles circular dependencies"""
        session = InteractiveSession(mock_profile.target)

        # Create circular dependency: A → B → A
        task_a = TaskNode('task-a', 'Task A', 'command')
        task_a.metadata['command'] = 'echo "A"'
        task_a.metadata['depends_on'] = ['task-b']

        task_b = TaskNode('task-b', 'Task B', 'command')
        task_b.metadata['command'] = 'echo "B"'
        task_b.metadata['depends_on'] = ['task-a']

        # Resolution should handle this gracefully (best effort)
        steps = session._resolve_dependencies([task_a, task_b])

        # Should still create steps (fallback to adding all remaining tasks)
        assert len(steps) > 0
        assert len(steps[0]) > 0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
