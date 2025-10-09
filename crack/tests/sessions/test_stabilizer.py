"""
Tests for ShellStabilizer - post-upgrade stabilization.
"""

import pytest
from crack.sessions.shell import ShellStabilizer
from crack.sessions.models import Session
from crack.sessions.events import EventBus, SessionEvent


class TestShellStabilizer:
    """Test suite for ShellStabilizer."""

    @pytest.fixture(autouse=True)
    def reset_event_bus(self):
        """Reset event bus before each test."""
        EventBus.reset()
        yield
        EventBus.reset()

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
            return ""

        executor.executed_commands = executed_commands
        return executor

    def test_stabilize_full(self, session, mock_executor):
        """Test full stabilization process."""
        stabilizer = ShellStabilizer(command_executor=mock_executor)

        success = stabilizer.stabilize(session)

        assert success is True

        # Check all stabilization commands were executed
        commands = mock_executor.executed_commands
        assert any('stty rows' in cmd for cmd in commands)  # Terminal size
        assert any('export TERM' in cmd for cmd in commands)  # TERM variable
        assert any('export SHELL' in cmd for cmd in commands)  # SHELL variable
        assert any('stty -echoctl' in cmd for cmd in commands)  # Signal handling
        assert any('HISTFILE' in cmd for cmd in commands)  # History disabled

    def test_stabilize_emits_event(self, session, mock_executor):
        """Test that stabilization emits SESSION_STABILIZED event."""
        stabilizer = ShellStabilizer(command_executor=mock_executor)

        event_received = []

        def handler(data):
            event_received.append(data)

        EventBus.subscribe(SessionEvent.SESSION_STABILIZED, handler)

        stabilizer.stabilize(session)

        assert len(event_received) == 1
        assert event_received[0]['session_id'] == session.id

    def test_fix_terminal_size(self, session, mock_executor):
        """Test terminal size fixing."""
        stabilizer = ShellStabilizer(command_executor=mock_executor)

        success = stabilizer.fix_terminal_size(session)

        assert success is True
        # Check stty rows/cols command was executed
        commands = mock_executor.executed_commands
        assert any('stty rows' in cmd and 'cols' in cmd for cmd in commands)

    def test_set_term_variable(self, session, mock_executor):
        """Test TERM variable setting."""
        stabilizer = ShellStabilizer(command_executor=mock_executor)

        success = stabilizer.set_term_variable(session)

        assert success is True
        assert any('export TERM=xterm-256color' in cmd
                   for cmd in mock_executor.executed_commands)

    def test_set_term_variable_custom(self, session, mock_executor):
        """Test custom TERM variable."""
        stabilizer = ShellStabilizer(command_executor=mock_executor)

        success = stabilizer.set_term_variable(session, term='screen-256color')

        assert success is True
        assert any('export TERM=screen-256color' in cmd
                   for cmd in mock_executor.executed_commands)

    def test_set_shell_variable(self, session, mock_executor):
        """Test SHELL variable setting."""
        stabilizer = ShellStabilizer(command_executor=mock_executor)

        success = stabilizer.set_shell_variable(session)

        assert success is True
        assert any('export SHELL=/bin/bash' in cmd
                   for cmd in mock_executor.executed_commands)

    def test_configure_signal_handling(self, session, mock_executor):
        """Test signal handling configuration."""
        stabilizer = ShellStabilizer(command_executor=mock_executor)

        success = stabilizer.configure_signal_handling(session)

        assert success is True
        assert any('stty -echoctl' in cmd
                   for cmd in mock_executor.executed_commands)

    def test_disable_history(self, session, mock_executor):
        """Test history disabling (OPSEC)."""
        stabilizer = ShellStabilizer(command_executor=mock_executor)

        success = stabilizer.disable_history(session)

        assert success is True
        commands = mock_executor.executed_commands
        assert any('HISTFILE=/dev/null' in cmd for cmd in commands)
        assert any('HISTSIZE=0' in cmd for cmd in commands)
        assert any('unset HISTFILE' in cmd for cmd in commands)

    def test_enable_history(self, session, mock_executor):
        """Test history enabling."""
        stabilizer = ShellStabilizer(command_executor=mock_executor)

        success = stabilizer.enable_history(session)

        assert success is True
        commands = mock_executor.executed_commands
        assert any('HISTFILE=~/.bash_history' in cmd for cmd in commands)
        assert any('HISTSIZE=1000' in cmd for cmd in commands)

    def test_set_custom_prompt(self, session, mock_executor):
        """Test custom prompt setting."""
        stabilizer = ShellStabilizer(command_executor=mock_executor)

        success = stabilizer.set_custom_prompt(session)

        assert success is True
        assert any('export PS1=' in cmd
                   for cmd in mock_executor.executed_commands)

    def test_set_custom_prompt_custom_value(self, session, mock_executor):
        """Test custom prompt with custom value."""
        stabilizer = ShellStabilizer(command_executor=mock_executor)

        custom = r'\u@\h:\w\$ '
        success = stabilizer.set_custom_prompt(session, prompt=custom)

        assert success is True
        assert any(custom in cmd for cmd in mock_executor.executed_commands)

    def test_reset_terminal(self, session, mock_executor):
        """Test terminal reset."""
        stabilizer = ShellStabilizer(command_executor=mock_executor)

        success = stabilizer.reset_terminal(session)

        assert success is True
        assert any('reset' in cmd for cmd in mock_executor.executed_commands)

    def test_apply_bashrc(self, session, mock_executor):
        """Test bashrc application."""
        stabilizer = ShellStabilizer(command_executor=mock_executor)

        success = stabilizer.apply_bashrc(session)

        assert success is True
        assert any('source ~/.bashrc' in cmd
                   for cmd in mock_executor.executed_commands)

    def test_apply_bashrc_custom_path(self, session, mock_executor):
        """Test bashrc with custom path."""
        stabilizer = ShellStabilizer(command_executor=mock_executor)

        success = stabilizer.apply_bashrc(session, bashrc_path='/etc/bash.bashrc')

        assert success is True
        assert any('source /etc/bash.bashrc' in cmd
                   for cmd in mock_executor.executed_commands)

    def test_stabilize_without_history_disable(self, session, mock_executor):
        """Test stabilization without history disabling."""
        stabilizer = ShellStabilizer(command_executor=mock_executor)

        success = stabilizer.stabilize(session, disable_history=False)

        assert success is True
        # History commands should not be present
        commands = mock_executor.executed_commands
        assert not any('HISTFILE=/dev/null' in cmd for cmd in commands)

    def test_stabilize_without_custom_prompt(self, session, mock_executor):
        """Test stabilization without custom prompt."""
        stabilizer = ShellStabilizer(command_executor=mock_executor)

        success = stabilizer.stabilize(session, custom_prompt=False)

        assert success is True
        # Prompt commands should not be present
        commands = mock_executor.executed_commands
        assert not any('export PS1=' in cmd for cmd in commands)

    def test_get_stabilization_checklist(self, session):
        """Test stabilization checklist generation."""
        stabilizer = ShellStabilizer()

        checklist = stabilizer.get_stabilization_checklist()

        assert 'name' in checklist
        assert 'steps' in checklist
        assert len(checklist['steps']) > 0
        assert checklist['oscp_safe'] is True

        # Check step structure
        step = checklist['steps'][0]
        assert 'order' in step
        assert 'name' in step
        assert 'command' in step
        assert 'description' in step

    def test_checklist_has_required_steps(self, session):
        """Test checklist includes all required steps."""
        stabilizer = ShellStabilizer()
        checklist = stabilizer.get_stabilization_checklist()

        step_names = [step['name'] for step in checklist['steps']]

        assert 'Fix Terminal Size' in step_names
        assert 'Set TERM Variable' in step_names
        assert 'Set SHELL Variable' in step_names
        assert 'Configure Signals' in step_names

    def test_checklist_marks_opsec_steps(self, session):
        """Test checklist marks OPSEC steps."""
        stabilizer = ShellStabilizer()
        checklist = stabilizer.get_stabilization_checklist()

        opsec_steps = [step for step in checklist['steps']
                      if step.get('opsec', False)]

        assert len(opsec_steps) > 0
        # History disabling should be marked as OPSEC
        assert any('History' in step['name'] for step in opsec_steps)
