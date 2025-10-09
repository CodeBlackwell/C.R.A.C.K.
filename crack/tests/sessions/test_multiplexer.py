"""
Tests for ShellMultiplexer - tmux/screen integration.
"""

import pytest
from crack.sessions.shell import ShellMultiplexer
from crack.sessions.models import Session


class TestShellMultiplexer:
    """Test suite for ShellMultiplexer."""

    @pytest.fixture
    def session(self):
        """Create test session."""
        return Session(
            type='tcp',
            target='192.168.45.150',
            port=4444,
            status='active',
            shell_type='bash'
        )

    @pytest.fixture
    def mock_executor(self):
        """Create mock command executor."""
        executed_commands = []

        def executor(session, command):
            executed_commands.append(command)
            # Return mock responses for list commands
            if 'tmux list-sessions' in command:
                return 'crack_abc123\ncrack_def456'
            elif 'screen -ls' in command:
                return '12345.crack_abc123\n67890.crack_def456'
            return ""

        executor.executed_commands = executed_commands
        return executor

    def test_multiplex_tmux(self, session, mock_executor):
        """Test tmux session creation."""
        multiplexer = ShellMultiplexer(command_executor=mock_executor)

        # Mock tmux availability
        session.capabilities.detected_tools = ['tmux']

        success = multiplexer.multiplex_tmux(session)

        assert success is True
        # Check tmux command was executed
        assert any('tmux new' in cmd for cmd in mock_executor.executed_commands)
        # Session name should be stored
        assert 'tmux_session' in session.metadata

    def test_multiplex_tmux_custom_name(self, session, mock_executor):
        """Test tmux with custom session name."""
        multiplexer = ShellMultiplexer(command_executor=mock_executor)
        session.capabilities.detected_tools = ['tmux']

        success = multiplexer.multiplex_tmux(session, session_name='custom_session')

        assert success is True
        assert any('custom_session' in cmd for cmd in mock_executor.executed_commands)
        assert session.metadata['tmux_session'] == 'custom_session'

    def test_multiplex_tmux_not_available(self, session, mock_executor):
        """Test tmux when not available."""
        multiplexer = ShellMultiplexer(command_executor=mock_executor)
        session.capabilities.detected_tools = []

        success = multiplexer.multiplex_tmux(session)

        assert success is False

    def test_multiplex_screen(self, session, mock_executor):
        """Test screen session creation."""
        multiplexer = ShellMultiplexer(command_executor=mock_executor)
        session.capabilities.detected_tools = ['screen']

        success = multiplexer.multiplex_screen(session)

        assert success is True
        assert any('screen -S' in cmd for cmd in mock_executor.executed_commands)
        assert 'screen_session' in session.metadata

    def test_multiplex_screen_custom_name(self, session, mock_executor):
        """Test screen with custom session name."""
        multiplexer = ShellMultiplexer(command_executor=mock_executor)
        session.capabilities.detected_tools = ['screen']

        success = multiplexer.multiplex_screen(session, session_name='my_screen')

        assert success is True
        assert any('my_screen' in cmd for cmd in mock_executor.executed_commands)

    def test_multiplex_screen_not_available(self, session, mock_executor):
        """Test screen when not available."""
        multiplexer = ShellMultiplexer(command_executor=mock_executor)
        session.capabilities.detected_tools = []

        success = multiplexer.multiplex_screen(session)

        assert success is False

    def test_create_parallel_pane_horizontal(self, session, mock_executor):
        """Test horizontal pane creation."""
        multiplexer = ShellMultiplexer(command_executor=mock_executor)
        session.metadata['tmux_session'] = 'test_session'

        success = multiplexer.create_parallel_pane(session, direction='horizontal')

        assert success is True
        assert any('tmux split-window -h' in cmd
                   for cmd in mock_executor.executed_commands)

    def test_create_parallel_pane_vertical(self, session, mock_executor):
        """Test vertical pane creation."""
        multiplexer = ShellMultiplexer(command_executor=mock_executor)
        session.metadata['tmux_session'] = 'test_session'

        success = multiplexer.create_parallel_pane(session, direction='vertical')

        assert success is True
        assert any('tmux split-window -v' in cmd
                   for cmd in mock_executor.executed_commands)

    def test_create_parallel_pane_no_tmux_session(self, session, mock_executor):
        """Test pane creation without tmux session."""
        multiplexer = ShellMultiplexer(command_executor=mock_executor)

        success = multiplexer.create_parallel_pane(session)

        assert success is False

    def test_create_parallel_pane_invalid_direction(self, session, mock_executor):
        """Test pane creation with invalid direction."""
        multiplexer = ShellMultiplexer(command_executor=mock_executor)
        session.metadata['tmux_session'] = 'test_session'

        success = multiplexer.create_parallel_pane(session, direction='invalid')

        assert success is False

    def test_list_tmux_sessions(self, session, mock_executor):
        """Test listing tmux sessions."""
        multiplexer = ShellMultiplexer(command_executor=mock_executor)
        session.capabilities.detected_tools = ['tmux']

        sessions = multiplexer.list_tmux_sessions(session)

        assert len(sessions) == 2
        assert 'crack_abc123' in sessions
        assert 'crack_def456' in sessions

    def test_list_tmux_sessions_not_available(self, session, mock_executor):
        """Test listing tmux sessions when tmux not available."""
        multiplexer = ShellMultiplexer(command_executor=mock_executor)
        session.capabilities.detected_tools = []

        sessions = multiplexer.list_tmux_sessions(session)

        assert len(sessions) == 0

    def test_list_screen_sessions(self, session, mock_executor):
        """Test listing screen sessions."""
        multiplexer = ShellMultiplexer(command_executor=mock_executor)
        session.capabilities.detected_tools = ['screen']

        sessions = multiplexer.list_screen_sessions(session)

        assert len(sessions) > 0

    def test_list_screen_sessions_not_available(self, session, mock_executor):
        """Test listing screen sessions when screen not available."""
        multiplexer = ShellMultiplexer(command_executor=mock_executor)
        session.capabilities.detected_tools = []

        sessions = multiplexer.list_screen_sessions(session)

        assert len(sessions) == 0

    def test_attach_tmux(self, session, mock_executor):
        """Test attaching to tmux session."""
        multiplexer = ShellMultiplexer(command_executor=mock_executor)

        success = multiplexer.attach_tmux(session, 'existing_session')

        assert success is True
        assert any('tmux attach -t existing_session' in cmd
                   for cmd in mock_executor.executed_commands)
        assert session.metadata['tmux_session'] == 'existing_session'

    def test_attach_screen(self, session, mock_executor):
        """Test attaching to screen session."""
        multiplexer = ShellMultiplexer(command_executor=mock_executor)

        success = multiplexer.attach_screen(session, 'my_screen')

        assert success is True
        assert any('screen -r my_screen' in cmd
                   for cmd in mock_executor.executed_commands)
        assert session.metadata['screen_session'] == 'my_screen'

    def test_send_keys_to_pane(self, session, mock_executor):
        """Test sending keys to specific pane."""
        multiplexer = ShellMultiplexer(command_executor=mock_executor)

        success = multiplexer.send_keys_to_pane(session, './linpeas.sh\\n', pane_index=1)

        assert success is True
        assert any('./linpeas.sh' in cmd and 'tmux send-keys' in cmd
                   for cmd in mock_executor.executed_commands)

    def test_get_multiplexer_guide(self, session):
        """Test multiplexer guide generation."""
        multiplexer = ShellMultiplexer()

        guide = multiplexer.get_multiplexer_guide()

        assert 'tmux' in guide
        assert 'screen' in guide
        assert 'comparison' in guide

        # Check tmux structure
        assert 'name' in guide['tmux']
        assert 'prefix' in guide['tmux']
        assert 'commands' in guide['tmux']
        assert 'oscp_use_cases' in guide['tmux']

        # Check screen structure
        assert 'name' in guide['screen']
        assert 'commands' in guide['screen']

    def test_guide_has_essential_commands(self, session):
        """Test guide includes essential commands."""
        multiplexer = ShellMultiplexer()
        guide = multiplexer.get_multiplexer_guide()

        # Check tmux commands
        tmux_actions = [cmd['action'] for cmd in guide['tmux']['commands']]
        assert 'New session' in tmux_actions
        assert 'Detach' in tmux_actions
        assert 'Split horizontal' in tmux_actions
        assert 'Split vertical' in tmux_actions

        # Check screen commands
        screen_actions = [cmd['action'] for cmd in guide['screen']['commands']]
        assert 'New session' in screen_actions
        assert 'Detach' in screen_actions

    def test_guide_has_oscp_use_cases(self, session):
        """Test guide includes OSCP use cases."""
        multiplexer = ShellMultiplexer()
        guide = multiplexer.get_multiplexer_guide()

        oscp_cases = guide['tmux']['oscp_use_cases']
        assert len(oscp_cases) > 0
        # Should mention parallel enumeration
        assert any('parallel' in case.lower() for case in oscp_cases)
        # Should mention persistence
        assert any('persist' in case.lower() or 'interrupt' in case.lower()
                   for case in oscp_cases)
