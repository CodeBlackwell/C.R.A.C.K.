"""
Tests for ShellUpgrader - shell upgrade automation.
"""

import pytest
from crack.sessions.shell import ShellUpgrader, ShellDetector
from crack.sessions.models import Session, ShellCapabilities
from crack.sessions.events import EventBus, SessionEvent


class TestShellUpgrader:
    """Test suite for ShellUpgrader."""

    @pytest.fixture(autouse=True)
    def reset_event_bus(self):
        """Reset event bus before each test."""
        EventBus.reset()
        yield
        EventBus.reset()

    @pytest.fixture
    def session(self):
        """Create test session with capabilities."""
        session = Session(
            type='tcp',
            target='192.168.45.150',
            port=4444,
            status='active',
            shell_type='bash'
        )
        session.capabilities = ShellCapabilities(
            shell_type='bash',
            os_type='linux',
            has_pty=False,
            detected_tools=['python3', 'script', 'bash', 'stty']
        )
        return session

    @pytest.fixture
    def mock_executor(self):
        """Create mock command executor."""
        executed_commands = []

        def executor(session, command):
            executed_commands.append(command)
            # Return mock responses
            if 'echo $SHELL' in command:
                return '/bin/bash'
            elif 'uname' in command:
                return 'Linux victim 5.10.0-21-amd64'
            elif 'tty' in command:
                return '/dev/pts/0'  # PTY available after upgrade
            elif 'which' in command or 'command -v' in command:
                if 'python3' in command:
                    return '/usr/bin/python3'
                elif 'script' in command:
                    return '/usr/bin/script'
            return ""

        executor.executed_commands = executed_commands
        return executor

    def test_upgrade_python_pty(self, session, mock_executor):
        """Test Python PTY upgrade."""
        upgrader = ShellUpgrader(command_executor=mock_executor)

        success = upgrader.upgrade_python_pty(session, 'python3')

        assert success is True
        # Check that python PTY command was executed
        assert any('python3' in cmd and 'pty.spawn' in cmd
                   for cmd in mock_executor.executed_commands)

    def test_upgrade_script(self, session, mock_executor):
        """Test script upgrade."""
        upgrader = ShellUpgrader(command_executor=mock_executor)

        success = upgrader.upgrade_script(session)

        assert success is True
        # Check that script command was executed
        assert any('script' in cmd and '/dev/null' in cmd
                   for cmd in mock_executor.executed_commands)

    def test_upgrade_python_pty_no_python(self, session, mock_executor):
        """Test Python PTY upgrade without Python available."""
        session.capabilities.detected_tools = ['bash', 'script']

        upgrader = ShellUpgrader(command_executor=mock_executor)
        success = upgrader.upgrade_python_pty(session, 'python3')

        assert success is False

    def test_upgrade_script_no_script(self, session, mock_executor):
        """Test script upgrade without script available."""
        session.capabilities.detected_tools = ['python3', 'bash']

        upgrader = ShellUpgrader(command_executor=mock_executor)
        success = upgrader.upgrade_script(session)

        assert success is False

    def test_auto_upgrade_tries_python_first(self, session, mock_executor):
        """Test auto-upgrade prioritizes Python PTY."""
        upgrader = ShellUpgrader(command_executor=mock_executor)

        success = upgrader.auto_upgrade(session)

        assert success is True
        # Python should be tried first
        commands = mock_executor.executed_commands
        python_index = next((i for i, cmd in enumerate(commands)
                           if 'python3' in cmd and 'pty.spawn' in cmd), None)
        assert python_index is not None

    def test_auto_upgrade_fallback_to_script(self, session, mock_executor):
        """Test auto-upgrade falls back to script."""
        # Remove Python from available tools but keep script
        session.capabilities.detected_tools = ['script', 'bash', 'stty']

        # Create custom executor that doesn't have python responses
        executed = []
        def executor(session, command):
            executed.append(command)
            if 'echo $SHELL' in command:
                return '/bin/bash'
            elif 'uname' in command:
                return 'Linux'
            elif 'tty' in command:
                return '/dev/pts/0'
            elif 'which script' in command or 'command -v script' in command:
                return '/usr/bin/script'
            return ""
        executor.executed_commands = executed

        upgrader = ShellUpgrader(command_executor=executor)
        success = upgrader.auto_upgrade(session)

        assert success is True
        # Script should be used
        assert any('script' in cmd and '/dev/null' in cmd
                   for cmd in executor.executed_commands)

    def test_upgrade_shell_with_auto(self, session, mock_executor):
        """Test upgrade_shell with auto method."""
        upgrader = ShellUpgrader(command_executor=mock_executor)

        success = upgrader.upgrade_shell(session, 'auto')

        assert success is True
        assert session.capabilities.has_pty is True
        assert session.status == 'active'

    def test_upgrade_shell_with_specific_method(self, session, mock_executor):
        """Test upgrade_shell with specific method."""
        upgrader = ShellUpgrader(command_executor=mock_executor)

        success = upgrader.upgrade_shell(session, 'python-pty')

        assert success is True
        assert session.capabilities.has_pty is True

    def test_upgrade_shell_invalid_method(self, session, mock_executor):
        """Test upgrade_shell with invalid method."""
        upgrader = ShellUpgrader(command_executor=mock_executor)

        # Should return False or raise ValueError
        try:
            result = upgrader.upgrade_shell(session, 'invalid-method')
            # If it returns instead of raising, it should be False
            assert result is False
        except ValueError as e:
            # Should contain "Unknown upgrade method"
            assert "Unknown upgrade method" in str(e)

    def test_upgrade_shell_emits_event(self, session, mock_executor):
        """Test that upgrade emits SESSION_UPGRADED event."""
        upgrader = ShellUpgrader(command_executor=mock_executor)

        event_received = []

        def handler(data):
            event_received.append(data)

        EventBus.subscribe(SessionEvent.SESSION_UPGRADED, handler)

        upgrader.upgrade_shell(session, 'python-pty')

        assert len(event_received) == 1
        assert event_received[0]['session_id'] == session.id
        assert event_received[0]['method'] == 'python-pty'

    def test_validate_upgrade_success(self, session, mock_executor):
        """Test upgrade validation success."""
        upgrader = ShellUpgrader(command_executor=mock_executor)

        # Mock PTY available
        is_valid = upgrader.validate_upgrade(session)

        assert is_valid is True

    def test_validate_upgrade_failure(self, session):
        """Test upgrade validation failure."""
        def executor(session, command):
            if 'tty' in command:
                return 'not a tty'
            return ""

        upgrader = ShellUpgrader(command_executor=executor)
        is_valid = upgrader.validate_upgrade(session)

        assert is_valid is False

    def test_detect_capabilities(self, session, mock_executor):
        """Test capability detection."""
        upgrader = ShellUpgrader(command_executor=mock_executor)

        caps = upgrader.detect_capabilities(session)

        assert isinstance(caps, ShellCapabilities)
        assert caps.shell_type == 'bash'
        assert caps.os_type == 'linux'

    def test_get_upgrade_recommendations(self, session, mock_executor):
        """Test upgrade recommendations."""
        upgrader = ShellUpgrader(command_executor=mock_executor)

        recommendations = upgrader.get_upgrade_recommendations(session)

        assert len(recommendations) > 0
        # Python should be first priority
        assert recommendations[0]['priority'] == 1
        assert recommendations[0]['method'] == 'python-pty'
        assert recommendations[0]['oscp_safe'] is True

    def test_upgrade_recommendations_sorted_by_priority(self, session, mock_executor):
        """Test recommendations are sorted by priority."""
        session.capabilities.detected_tools = ['python3', 'script', 'expect']

        upgrader = ShellUpgrader(command_executor=mock_executor)
        recommendations = upgrader.get_upgrade_recommendations(session)

        # Check priorities are in order
        priorities = [rec['priority'] for rec in recommendations]
        assert priorities == sorted(priorities)

    def test_upgrade_session_status_transitions(self, session, mock_executor):
        """Test session status transitions during upgrade."""
        upgrader = ShellUpgrader(command_executor=mock_executor)

        assert session.status == 'active'

        upgrader.upgrade_shell(session, 'python-pty')

        # Should be back to active after upgrade
        assert session.status == 'active'

    def test_stabilize_shell(self, session, mock_executor):
        """Test stabilization after upgrade."""
        upgrader = ShellUpgrader(command_executor=mock_executor)

        success = upgrader.stabilize_shell(session)

        # Should delegate to stabilizer
        assert success is True

    def test_upgrade_python2_pty(self, session, mock_executor):
        """Test Python 2 PTY upgrade."""
        session.capabilities.detected_tools = ['python', 'bash']

        upgrader = ShellUpgrader(command_executor=mock_executor)
        success = upgrader.upgrade_shell(session, 'python2-pty')

        assert success is True

    def test_upgrade_expect(self, session, mock_executor):
        """Test expect upgrade."""
        session.capabilities.detected_tools = ['expect', 'bash']

        upgrader = ShellUpgrader(command_executor=mock_executor)
        success = upgrader.upgrade_expect(session)

        assert success is True
        assert any('expect' in cmd for cmd in mock_executor.executed_commands)

    def test_upgrade_socat_no_socat(self, session, mock_executor):
        """Test socat upgrade without socat available."""
        upgrader = ShellUpgrader(command_executor=mock_executor)

        success = upgrader.upgrade_socat(session)

        assert success is False
