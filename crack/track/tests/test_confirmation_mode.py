"""
Tests for Smart Confirmation Mode

Tests the confirmation mode feature that reduces friction by skipping
unnecessary prompts for read-only tasks.
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from crack.track.core.state import TargetProfile
from crack.track.core.task_tree import TaskNode
from crack.track.interactive.session import InteractiveSession


@pytest.fixture
def temp_crack_home(tmp_path, monkeypatch):
    """Setup temporary .crack directory"""
    crack_home = tmp_path / '.crack'
    crack_home.mkdir()
    (crack_home / 'targets').mkdir()
    (crack_home / 'sessions').mkdir()
    monkeypatch.setenv('HOME', str(tmp_path))
    return crack_home


@pytest.fixture
def mock_profile(temp_crack_home):
    """Create test profile with confirmation mode"""
    profile = TargetProfile('192.168.45.100')
    profile.save()
    return profile


@pytest.fixture
def read_only_task():
    """Create a read-only task"""
    task = TaskNode(
        task_id='test-readonly',
        name='Read-only Task',
        task_type='command'
    )
    task.metadata['command'] = 'echo test'
    task.metadata['tags'] = ['READ_ONLY']
    task.metadata['description'] = 'Test read-only task'
    return task


@pytest.fixture
def regular_task():
    """Create a regular task (not read-only)"""
    task = TaskNode(
        task_id='test-regular',
        name='Regular Task',
        task_type='command'
    )
    task.metadata['command'] = 'nmap 192.168.45.100'
    task.metadata['tags'] = ['OSCP:HIGH']
    task.metadata['description'] = 'Test regular task'
    return task


class TestConfirmationModeDefaults:
    """Test default confirmation mode behavior"""

    def test_new_profile_has_smart_mode(self, temp_crack_home):
        """PROVES: New profiles default to smart mode"""
        profile = TargetProfile('192.168.45.100')
        assert profile.metadata['confirmation_mode'] == 'smart'

    def test_loaded_profile_has_smart_mode(self, temp_crack_home):
        """PROVES: Loaded profiles default to smart mode if not set"""
        # Create profile without confirmation_mode
        profile = TargetProfile('192.168.45.100')
        del profile.metadata['confirmation_mode']
        profile.save()

        # Load and verify
        loaded = TargetProfile.load('192.168.45.100')
        assert loaded.metadata['confirmation_mode'] == 'smart'


class TestSetConfirmationMode:
    """Test set_confirmation_mode() method"""

    def test_set_valid_mode(self, temp_crack_home, mock_profile):
        """PROVES: Can set valid confirmation modes"""
        session = InteractiveSession(mock_profile.target)

        # Test each valid mode
        for mode in ['always', 'smart', 'never', 'batch']:
            session.set_confirmation_mode(mode)
            assert session.profile.metadata['confirmation_mode'] == mode

            # Verify persistence
            loaded = TargetProfile.load(mock_profile.target)
            assert loaded.metadata['confirmation_mode'] == mode

    def test_set_invalid_mode_raises(self, temp_crack_home, mock_profile):
        """PROVES: Invalid mode raises ValueError"""
        session = InteractiveSession(mock_profile.target)

        with pytest.raises(ValueError) as excinfo:
            session.set_confirmation_mode('invalid')

        assert 'must be one of' in str(excinfo.value)

    def test_mode_persists_across_sessions(self, temp_crack_home, mock_profile):
        """PROVES: Mode persists when session is closed and reopened"""
        # Set mode in first session
        session1 = InteractiveSession(mock_profile.target)
        session1.set_confirmation_mode('never')

        # Create new session
        session2 = InteractiveSession(mock_profile.target)
        assert session2.profile.metadata['confirmation_mode'] == 'never'


class TestSmartConfirmationLogic:
    """Test smart confirmation logic in execute_task()"""

    @patch('subprocess.run')
    @patch('builtins.input')
    def test_smart_mode_skips_readonly(self, mock_input, mock_subprocess,
                                       temp_crack_home, mock_profile, read_only_task):
        """PROVES: Smart mode skips confirmation for READ_ONLY tasks"""
        session = InteractiveSession(mock_profile.target)
        session.set_confirmation_mode('smart')

        # Mock subprocess success
        mock_subprocess.return_value = Mock(returncode=0)

        # Execute read-only task
        session.execute_task(read_only_task)

        # Verify input was NOT called (no confirmation prompt)
        mock_input.assert_not_called()

    @patch('subprocess.run')
    @patch('builtins.input')
    def test_smart_mode_asks_for_regular(self, mock_input, mock_subprocess,
                                         temp_crack_home, mock_profile, regular_task):
        """PROVES: Smart mode asks confirmation for regular tasks"""
        session = InteractiveSession(mock_profile.target)
        session.set_confirmation_mode('smart')

        # Mock user confirms
        mock_input.return_value = 'y'
        mock_subprocess.return_value = Mock(returncode=0)

        # Execute regular task
        session.execute_task(regular_task)

        # Verify input WAS called (confirmation prompt shown)
        mock_input.assert_called()

    @patch('subprocess.run')
    @patch('builtins.input')
    def test_never_mode_skips_all(self, mock_input, mock_subprocess,
                                   temp_crack_home, mock_profile, regular_task):
        """PROVES: Never mode skips all confirmations"""
        session = InteractiveSession(mock_profile.target)
        session.set_confirmation_mode('never')

        # Mock subprocess success
        mock_subprocess.return_value = Mock(returncode=0)

        # Execute task
        session.execute_task(regular_task)

        # Verify input was NOT called
        mock_input.assert_not_called()

    @patch('subprocess.run')
    @patch('builtins.input')
    def test_always_mode_asks_all(self, mock_input, mock_subprocess,
                                   temp_crack_home, mock_profile, read_only_task):
        """PROVES: Always mode asks for all tasks, even read-only"""
        session = InteractiveSession(mock_profile.target)
        session.set_confirmation_mode('always')

        # Mock user confirms
        mock_input.return_value = 'y'
        mock_subprocess.return_value = Mock(returncode=0)

        # Execute read-only task
        session.execute_task(read_only_task)

        # Verify input WAS called even for read-only
        mock_input.assert_called()


class TestConfirmationShortcut:
    """Test 'c' keyboard shortcut"""

    def test_shortcut_exists(self, temp_crack_home, mock_profile):
        """PROVES: 'c' shortcut is registered"""
        session = InteractiveSession(mock_profile.target)
        assert 'c' in session.shortcut_handler.shortcuts

    def test_shortcut_description(self, temp_crack_home, mock_profile):
        """PROVES: Shortcut has correct description"""
        session = InteractiveSession(mock_profile.target)
        desc, handler = session.shortcut_handler.shortcuts['c']
        assert 'confirmation' in desc.lower()
        assert handler == 'change_confirmation'

    @patch('builtins.input')
    def test_shortcut_handler_exists(self, mock_input, temp_crack_home, mock_profile):
        """PROVES: change_confirmation handler is callable"""
        session = InteractiveSession(mock_profile.target)
        handler = session.shortcut_handler

        # Verify handler method exists
        assert hasattr(handler, 'change_confirmation')
        assert callable(getattr(handler, 'change_confirmation'))


class TestConfirmationWorkflow:
    """Integration tests for complete confirmation mode workflows"""

    @patch('subprocess.run')
    @patch('builtins.input')
    def test_complete_workflow_smart_mode(self, mock_input, mock_subprocess,
                                          temp_crack_home, mock_profile):
        """
        PROVES: Complete workflow with smart mode

        Workflow:
        1. Set mode to smart
        2. Execute read-only task (no prompt)
        3. Execute regular task (prompts)
        4. Mode persists
        """
        session = InteractiveSession(mock_profile.target)

        # Step 1: Set smart mode
        session.set_confirmation_mode('smart')
        assert session.profile.metadata['confirmation_mode'] == 'smart'

        # Step 2: Execute read-only task
        read_only = TaskNode(
            task_id='readonly',
            name='Test',
            task_type='command'
        )
        read_only.metadata['command'] = 'echo test'
        read_only.metadata['tags'] = ['READ_ONLY']
        mock_subprocess.return_value = Mock(returncode=0)
        session.execute_task(read_only)

        # Should not have called input
        assert mock_input.call_count == 0

        # Step 3: Execute regular task
        regular = TaskNode(
            task_id='regular',
            name='Test',
            task_type='command'
        )
        regular.metadata['command'] = 'nmap test'
        regular.metadata['tags'] = ['OSCP:HIGH']
        mock_input.return_value = 'y'
        session.execute_task(regular)

        # Should have called input
        assert mock_input.call_count == 1

        # Step 4: Verify persistence
        loaded = TargetProfile.load(mock_profile.target)
        assert loaded.metadata['confirmation_mode'] == 'smart'

    @patch('subprocess.run')
    @patch('builtins.input')
    def test_never_mode_fast_execution(self, mock_input, mock_subprocess,
                                       temp_crack_home, mock_profile):
        """
        PROVES: Never mode enables fast batch execution

        Workflow:
        1. Set mode to never
        2. Execute multiple tasks
        3. No confirmations shown
        """
        session = InteractiveSession(mock_profile.target)
        session.set_confirmation_mode('never')

        # Create multiple tasks
        tasks = []
        for i in range(5):
            task = TaskNode(f'task-{i}', f'Task {i}', 'command')
            task.metadata['command'] = f'echo {i}'
            tasks.append(task)

        # Execute all
        mock_subprocess.return_value = Mock(returncode=0)
        for task in tasks:
            session.execute_task(task)

        # Verify no confirmations
        mock_input.assert_not_called()


class TestHelpText:
    """Test help text includes confirmation mode shortcut"""

    def test_help_includes_shortcut(self):
        """PROVES: Help text documents 'c' shortcut"""
        from crack.track.interactive.prompts import PromptBuilder

        help_text = PromptBuilder.build_help_text()
        assert 'c' in help_text.lower()
        assert 'confirmation' in help_text.lower()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
