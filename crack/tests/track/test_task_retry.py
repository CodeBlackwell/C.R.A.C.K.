"""
Tests for tr (Task Retry) tool in CRACK Track Interactive Mode

PROVES: Task retry functionality with command editing capability
"""

import pytest
from datetime import datetime
from unittest.mock import Mock, patch, MagicMock
from crack.track.core.state import TargetProfile
from crack.track.core.task_tree import TaskNode
from crack.track.interactive.session import InteractiveSession


class TestTaskRetryShortcut:
    """Test shortcut registration and handler existence"""

    def test_tr_shortcut_exists(self):
        """PROVES: 'tr' shortcut is registered"""
        from crack.track.interactive.shortcuts import ShortcutHandler

        # Create mock session
        mock_session = Mock()
        handler = ShortcutHandler(mock_session)

        # Verify shortcut exists
        assert 'tr' in handler.shortcuts
        description, method_name = handler.shortcuts['tr']
        assert 'retry' in description.lower()
        assert method_name == 'task_retry'

    def test_tr_handler_callable(self):
        """PROVES: Handler method exists and is callable"""
        from crack.track.interactive.shortcuts import ShortcutHandler

        mock_session = Mock()
        handler = ShortcutHandler(mock_session)

        # Verify handler method exists
        assert hasattr(handler, 'task_retry')
        assert callable(getattr(handler, 'task_retry'))

    def test_tr_in_shortcuts_list(self):
        """PROVES: 'tr' is in SHORTCUTS list for input recognition"""
        from crack.track.interactive.input_handler import InputProcessor

        assert 'tr' in InputProcessor.SHORTCUTS


class TestGetRetryableTasks:
    """Test _get_retryable_tasks() method"""

    def test_get_retryable_tasks_failed(self, temp_crack_home):
        """PROVES: Lists failed tasks"""
        profile = TargetProfile("192.168.45.100")

        # Add failed task
        failed_task = TaskNode("test-failed", "Failed Task", "command")
        failed_task.status = 'failed'
        failed_task.metadata = {
            'command': 'nmap -p 80 192.168.45.100',
            'exit_code': 1,
            'error': 'Connection refused'
        }
        profile.task_tree.add_child(failed_task)
        profile.save()

        session = InteractiveSession(profile.target)
        retryable = session._get_retryable_tasks()

        assert len(retryable) >= 1
        assert failed_task.id in [t.id for t in retryable]
        assert retryable[0].status == 'failed'

    def test_get_retryable_tasks_completed(self, temp_crack_home):
        """PROVES: Lists completed tasks with commands"""
        profile = TargetProfile("192.168.45.100")

        # Add completed task
        completed_task = TaskNode("test-completed", "Completed Task", "command")
        completed_task.status = 'completed'
        completed_task.metadata = {
            'command': 'nmap -sV 192.168.45.100',
            'exit_code': 0
        }
        profile.task_tree.add_child(completed_task)
        profile.save()

        session = InteractiveSession(profile.target)
        retryable = session._get_retryable_tasks()

        assert len(retryable) >= 1
        assert completed_task.id in [t.id for t in retryable]

    def test_get_retryable_tasks_sorting(self, temp_crack_home):
        """PROVES: Failed tasks appear first in list"""
        profile = TargetProfile("192.168.45.100")

        # Add completed task (should be second)
        completed_task = TaskNode("test-completed", "Completed", "command")
        completed_task.status = 'completed'
        completed_task.metadata = {'command': 'echo completed'}
        profile.task_tree.add_child(completed_task)

        # Add failed task (should be first)
        failed_task = TaskNode("test-failed", "Failed", "command")
        failed_task.status = 'failed'
        failed_task.metadata = {'command': 'echo failed', 'exit_code': 1}
        profile.task_tree.add_child(failed_task)

        profile.save()

        session = InteractiveSession(profile.target)
        retryable = session._get_retryable_tasks()

        # Failed should be first
        assert len(retryable) >= 2
        assert retryable[0].status == 'failed'


class TestEditCommand:
    """Test _edit_command() method"""

    def test_edit_command_keep_same(self, temp_crack_home):
        """PROVES: Returns same command when user presses Enter"""
        profile = TargetProfile("192.168.45.100")
        session = InteractiveSession(profile.target)

        original_command = "nmap -p 80 192.168.45.100"

        with patch('builtins.input', return_value=''):
            result = session._edit_command(original_command)

        assert result == original_command

    def test_edit_command_modify(self, temp_crack_home):
        """PROVES: Returns edited command when user modifies"""
        profile = TargetProfile("192.168.45.100")
        session = InteractiveSession(profile.target)

        original_command = "nmap -p 80 192.168.45.100"
        new_command = "nmap -p 80,443 192.168.45.100"

        with patch('builtins.input', return_value=new_command):
            result = session._edit_command(original_command)

        assert result == new_command
        assert result != original_command


class TestRetryTask:
    """Test _retry_task() method"""

    @patch('subprocess.run')
    def test_retry_task_success(self, mock_run, temp_crack_home):
        """PROVES: Successfully retries task with same command"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Success",
            stderr=""
        )

        profile = TargetProfile("192.168.45.100")
        failed_task = TaskNode("test-failed", "Failed Task", "command")
        failed_task.status = 'failed'
        failed_task.metadata = {
            'command': 'nmap -p 80 {TARGET}',
            'exit_code': 1
        }
        profile.task_tree.add_child(failed_task)
        profile.save()

        session = InteractiveSession(profile.target)
        success = session._retry_task(failed_task)

        assert success is True
        assert failed_task.status == 'completed'
        assert failed_task.metadata['exit_code'] == 0
        assert 'retry_history' in failed_task.metadata

    @patch('subprocess.run')
    def test_retry_task_failure(self, mock_run, temp_crack_home):
        """PROVES: Handles task failure correctly"""
        mock_run.return_value = Mock(
            returncode=1,
            stdout="",
            stderr="Connection refused"
        )

        profile = TargetProfile("192.168.45.100")
        failed_task = TaskNode("test-failed", "Failed Task", "command")
        failed_task.status = 'failed'
        failed_task.metadata = {'command': 'nmap -p 80 {TARGET}'}
        profile.task_tree.add_child(failed_task)
        profile.save()

        session = InteractiveSession(profile.target)
        success = session._retry_task(failed_task)

        assert success is False
        assert failed_task.status == 'failed'
        assert failed_task.metadata['exit_code'] == 1

    @patch('subprocess.run')
    def test_retry_task_updates_metadata(self, mock_run, temp_crack_home):
        """PROVES: Updates task metadata after retry"""
        mock_run.return_value = Mock(
            returncode=0,
            stdout="Success",
            stderr=""
        )

        profile = TargetProfile("192.168.45.100")
        task = TaskNode("test", "Test Task", "command")
        task.metadata = {'command': 'echo test'}
        profile.task_tree.add_child(task)
        profile.save()

        session = InteractiveSession(profile.target)
        session._retry_task(task)

        # Check metadata updates
        assert 'last_run' in task.metadata
        assert 'retry_history' in task.metadata
        assert len(task.metadata['retry_history']) == 1
        assert task.metadata['retry_history'][0]['exit_code'] == 0

    @patch('subprocess.run')
    def test_retry_task_preserves_original_command(self, mock_run, temp_crack_home):
        """PROVES: Preserves original command for audit trail"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        profile = TargetProfile("192.168.45.100")
        task = TaskNode("test", "Test Task", "command")
        task.metadata = {'command': 'echo original'}
        profile.task_tree.add_child(task)
        profile.save()

        session = InteractiveSession(profile.target)
        session._retry_task(task, command='echo modified')

        assert task.metadata['original_command'] == 'echo original'
        assert task.metadata['retry_command'] == 'echo modified'


class TestHandleTaskRetry:
    """Test handle_task_retry() main handler"""

    def test_handle_task_retry_no_tasks(self, temp_crack_home, capsys):
        """PROVES: Handles case with no retryable tasks"""
        profile = TargetProfile("192.168.45.100")
        profile.save()

        session = InteractiveSession(profile.target)
        session.handle_task_retry()

        captured = capsys.readouterr()
        assert "No tasks available to retry" in captured.out

    @patch('builtins.input', side_effect=['1', 'r', 'Y'])
    @patch('subprocess.run')
    def test_handle_task_retry_full_workflow(self, mock_run, mock_input, temp_crack_home):
        """PROVES: Complete retry workflow works"""
        mock_run.return_value = Mock(returncode=0, stdout="Success", stderr="")

        profile = TargetProfile("192.168.45.100")
        failed_task = TaskNode("test-failed", "Failed Task", "command")
        failed_task.status = 'failed'
        failed_task.metadata = {
            'command': 'nmap -p 80 192.168.45.100',
            'exit_code': 1
        }
        profile.task_tree.add_child(failed_task)
        profile.save()

        session = InteractiveSession(profile.target)
        session.handle_task_retry()

        # Verify task was retried
        assert failed_task.status == 'completed'
        assert 'retry_history' in failed_task.metadata

    @patch('builtins.input', side_effect=['1', 'c'])
    def test_handle_task_retry_cancel(self, mock_input, temp_crack_home, capsys):
        """PROVES: Allows user to cancel retry"""
        profile = TargetProfile("192.168.45.100")
        failed_task = TaskNode("test-failed", "Failed Task", "command")
        failed_task.status = 'failed'
        failed_task.metadata = {'command': 'echo test', 'exit_code': 1}
        profile.task_tree.add_child(failed_task)
        profile.save()

        session = InteractiveSession(profile.target)
        session.handle_task_retry()

        captured = capsys.readouterr()
        assert "Cancelled" in captured.out


class TestRetryHistory:
    """Test retry history tracking"""

    @patch('subprocess.run')
    def test_retry_history_tracking(self, mock_run, temp_crack_home):
        """PROVES: Logs retry history in metadata"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        profile = TargetProfile("192.168.45.100")
        task = TaskNode("test", "Test Task", "command")
        task.metadata = {'command': 'echo test'}
        profile.task_tree.add_child(task)
        profile.save()

        session = InteractiveSession(profile.target)

        # First retry
        session._retry_task(task)
        assert len(task.metadata['retry_history']) == 1

        # Second retry
        session._retry_task(task)
        assert len(task.metadata['retry_history']) == 2

        # Verify history structure
        history_entry = task.metadata['retry_history'][0]
        assert 'timestamp' in history_entry
        assert 'command' in history_entry
        assert 'exit_code' in history_entry
        assert 'success' in history_entry

    @patch('subprocess.run')
    def test_retry_history_preserves_metadata(self, mock_run, temp_crack_home):
        """PROVES: Original metadata preserved after retries"""
        mock_run.return_value = Mock(returncode=0, stdout="", stderr="")

        profile = TargetProfile("192.168.45.100")
        task = TaskNode("test", "Test Task", "command")
        task.metadata = {
            'command': 'echo original',
            'custom_field': 'preserved_value',
            'tags': ['OSCP:HIGH']
        }
        profile.task_tree.add_child(task)
        profile.save()

        session = InteractiveSession(profile.target)
        session._retry_task(task)

        # Verify original metadata preserved
        assert task.metadata['custom_field'] == 'preserved_value'
        assert 'OSCP:HIGH' in task.metadata['tags']
        assert 'retry_history' in task.metadata  # New field added


# Fixtures
@pytest.fixture
def temp_crack_home(tmp_path, monkeypatch):
    """Create temporary CRACK home directory"""
    crack_home = tmp_path / '.crack'
    crack_home.mkdir()
    (crack_home / 'targets').mkdir()
    (crack_home / 'sessions').mkdir()
    monkeypatch.setenv('HOME', str(tmp_path))
    return crack_home
