"""
Tests for Quick Execute (qe) Tool

PROVES: Quick execute functionality for interactive mode
- Shortcut registration
- Command execution
- Output capture
- Error handling
- Logging functionality
"""

import pytest
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from crack.track.interactive.session import InteractiveSession
from crack.track.interactive.shortcuts import ShortcutHandler
from crack.track.core.state import TargetProfile


@pytest.fixture
def mock_profile(tmp_path):
    """Create mock target profile"""
    target = "192.168.45.100"

    # Create profile with minimal setup
    profile = TargetProfile(target)
    profile.metadata = {
        'confirmation_mode': 'smart',
        'environment': 'lab'
    }

    # Mock storage path
    profile.storage_path = tmp_path / f"{target}.json"

    return profile


@pytest.fixture
def mock_session(mock_profile):
    """Create mock interactive session"""
    with patch('crack.track.interactive.session.TargetProfile.load', return_value=mock_profile):
        with patch('crack.track.interactive.session.TargetProfile.exists', return_value=True):
            session = InteractiveSession(mock_profile.target)
            session.profile = mock_profile
            return session


class TestShortcutRegistration:
    """Test qe shortcut registration"""

    def test_qe_shortcut_exists(self, mock_session):
        """PROVES: 'qe' shortcut is registered"""
        handler = ShortcutHandler(mock_session)

        assert 'qe' in handler.shortcuts
        assert handler.shortcuts['qe'][0] == 'Quick execute'
        assert handler.shortcuts['qe'][1] == 'quick_execute'

    def test_qe_handler_callable(self, mock_session):
        """PROVES: qe handler method exists and is callable"""
        handler = ShortcutHandler(mock_session)

        assert hasattr(handler, 'quick_execute')
        assert callable(handler.quick_execute)

    def test_qe_in_input_shortcuts(self):
        """PROVES: 'qe' is recognized in input handler"""
        from crack.track.interactive.input_handler import InputProcessor

        assert 'qe' in InputProcessor.SHORTCUTS


class TestCommandExecution:
    """Test command execution functionality"""

    def test_execute_simple_command(self, mock_session):
        """PROVES: Quick execute runs simple commands correctly"""
        # Execute simple command
        exit_code, stdout, stderr = mock_session._execute_command("echo 'test output'")

        assert exit_code == 0
        assert 'test output' in stdout
        assert stderr == ""

    def test_execute_captures_stdout(self, mock_session):
        """PROVES: Captures command output correctly"""
        # Execute command with known output
        exit_code, stdout, stderr = mock_session._execute_command("echo 'line1' && echo 'line2'")

        assert exit_code == 0
        assert 'line1' in stdout
        assert 'line2' in stdout

    def test_execute_captures_stderr(self, mock_session):
        """PROVES: Captures error output correctly"""
        # Execute command that writes to stderr
        exit_code, stdout, stderr = mock_session._execute_command("echo 'error message' >&2")

        # Command should succeed but write to stderr
        assert exit_code == 0
        assert 'error message' in stderr

    def test_execute_exit_code(self, mock_session):
        """PROVES: Returns correct exit code"""
        # Execute command that fails
        exit_code, stdout, stderr = mock_session._execute_command("exit 42")

        assert exit_code == 42

    def test_execute_invalid_command(self, mock_session):
        """PROVES: Handles non-existent commands gracefully"""
        # Execute non-existent command
        exit_code, stdout, stderr = mock_session._execute_command("nonexistent-command-xyz-12345")

        assert exit_code != 0
        # stderr should contain error message about command not found
        assert stderr != ""
        assert 'not found' in stderr.lower() or 'command' in stderr.lower()

    def test_execute_with_multiline_output(self, mock_session):
        """PROVES: Handles multi-line output correctly"""
        # Execute command with multiple lines
        exit_code, stdout, stderr = mock_session._execute_command("printf 'line1\\nline2\\nline3\\n'")

        assert exit_code == 0
        assert stdout.count('\n') >= 3


class TestCommandValidation:
    """Test command validation functionality"""

    def test_validate_empty_command(self, mock_session, capsys):
        """PROVES: Rejects empty commands"""
        result = mock_session._validate_command("")

        assert result is False

        captured = capsys.readouterr()
        assert 'cannot be empty' in captured.out.lower()

    def test_validate_whitespace_command(self, mock_session, capsys):
        """PROVES: Rejects whitespace-only commands"""
        result = mock_session._validate_command("   ")

        assert result is False

        captured = capsys.readouterr()
        assert 'cannot be empty' in captured.out.lower()

    def test_validate_dangerous_command(self, mock_session, monkeypatch, capsys):
        """PROVES: Warns about dangerous commands"""
        # Mock user declining dangerous command
        monkeypatch.setattr('builtins.input', lambda _: 'n')

        result = mock_session._validate_command("rm -rf /")

        assert result is False

        captured = capsys.readouterr()
        assert 'destructive' in captured.out.lower()

    def test_validate_safe_command(self, mock_session):
        """PROVES: Accepts safe commands"""
        result = mock_session._validate_command("echo 'hello world'")

        assert result is True


class TestLoggingFunctionality:
    """Test logging to profile notes"""

    def test_logging_to_profile_accepted(self, mock_session, monkeypatch):
        """PROVES: Logs execution to notes when confirmed"""
        # Mock user accepting logging
        monkeypatch.setattr('builtins.input', lambda _: 'y')

        # Execute logging
        mock_session._log_execution(
            command="echo 'test'",
            exit_code=0,
            output="test\n",
            stderr=""
        )

        # Verify note was added
        assert len(mock_session.profile.notes) > 0

        # Check note contains command
        note = mock_session.profile.notes[-1]
        assert "echo 'test'" in note['note']
        assert 'quick-execute' in note['source']

    def test_logging_to_profile_declined(self, mock_session, monkeypatch):
        """PROVES: Skips logging when user declines"""
        # Get initial note count
        initial_count = len(mock_session.profile.notes)

        # Mock user declining logging
        monkeypatch.setattr('builtins.input', lambda _: 'n')

        # Execute logging
        mock_session._log_execution(
            command="echo 'test'",
            exit_code=0,
            output="test\n",
            stderr=""
        )

        # Verify note was NOT added
        assert len(mock_session.profile.notes) == initial_count

    def test_logging_includes_exit_code(self, mock_session, monkeypatch):
        """PROVES: Logged notes include exit code"""
        # Mock user accepting logging
        monkeypatch.setattr('builtins.input', lambda _: 'y')

        # Execute logging with non-zero exit code
        mock_session._log_execution(
            command="false",
            exit_code=1,
            output="",
            stderr=""
        )

        # Check note contains exit code
        note = mock_session.profile.notes[-1]
        assert 'Exit Code: 1' in note['note']

    def test_logging_truncates_long_output(self, mock_session, monkeypatch):
        """PROVES: Logs truncate very long output"""
        # Mock user accepting logging
        monkeypatch.setattr('builtins.input', lambda _: 'y')

        # Create very long output
        long_output = "x" * 1000

        # Execute logging
        mock_session._log_execution(
            command="echo 'test'",
            exit_code=0,
            output=long_output,
            stderr=""
        )

        # Check note was truncated
        note = mock_session.profile.notes[-1]
        assert '...' in note['note']


class TestIntegration:
    """Integration tests for full workflow"""

    def test_handle_quick_execute_full_workflow(self, mock_session, monkeypatch):
        """PROVES: Full quick execute workflow works end-to-end"""
        # Mock user inputs
        inputs = iter(['echo "integration test"', 'y', 'y'])  # command, confirm execute, confirm log
        monkeypatch.setattr('builtins.input', lambda _: next(inputs))

        # Execute
        mock_session.handle_quick_execute()

        # Verify last_action was set
        assert 'Quick execute' in mock_session.last_action

        # Verify note was logged
        assert len(mock_session.profile.notes) > 0

    def test_handle_quick_execute_with_direct_command(self, mock_session, monkeypatch):
        """PROVES: Can pass command directly to handler"""
        # Mock confirmation inputs
        inputs = iter(['y', 'n'])  # confirm execute, decline log
        monkeypatch.setattr('builtins.input', lambda _: next(inputs))

        # Execute with direct command
        mock_session.handle_quick_execute(command="echo 'direct command'")

        # Verify it executed (last_action should be set)
        assert 'Quick execute' in mock_session.last_action
        assert 'direct command' in mock_session.last_action

    def test_handle_quick_execute_cancel(self, mock_session, monkeypatch, capsys):
        """PROVES: Can cancel quick execute"""
        # Mock user canceling
        monkeypatch.setattr('builtins.input', lambda _: 'c')

        # Execute
        mock_session.handle_quick_execute()

        # Verify cancelled
        captured = capsys.readouterr()
        assert 'Cancelled' in captured.out

    def test_handle_quick_execute_respects_confirmation_mode(self, mock_session, monkeypatch):
        """PROVES: Respects confirmation mode setting"""
        # Set confirmation mode to 'never'
        mock_session.profile.metadata['confirmation_mode'] = 'never'

        # Mock only logging confirmation (no execute confirmation needed)
        monkeypatch.setattr('builtins.input', lambda _: 'n')

        # Execute with direct command
        mock_session.handle_quick_execute(command="echo 'no confirm'")

        # Should have executed without prompting for confirmation
        assert 'Quick execute' in mock_session.last_action


class TestErrorHandling:
    """Test error handling scenarios"""

    def test_execute_with_timeout(self, mock_session):
        """PROVES: Handles long-running commands"""
        # This should complete quickly
        exit_code, stdout, stderr = mock_session._execute_command("sleep 0.1 && echo 'done'")

        assert exit_code == 0
        assert 'done' in stdout

    def test_execute_command_with_pipes(self, mock_session):
        """PROVES: Handles piped commands correctly"""
        # Execute piped command
        exit_code, stdout, stderr = mock_session._execute_command("echo 'hello world' | grep 'hello'")

        assert exit_code == 0
        assert 'hello' in stdout

    def test_execute_command_with_special_chars(self, mock_session):
        """PROVES: Handles special characters in commands"""
        # Execute command with special characters
        exit_code, stdout, stderr = mock_session._execute_command("echo 'test@#$%^&*()'")

        assert exit_code == 0
        assert 'test@#$%^&*()' in stdout


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
