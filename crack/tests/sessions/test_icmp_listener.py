"""
Tests for ICMP tunnel listener (ICMPListener).

Tests cover:
- Listener initialization
- Start/stop lifecycle
- Client command generation
- ICMP reply management
- Connection handling (mocked)
"""

import pytest
from unittest.mock import Mock, patch, MagicMock

from crack.sessions.listeners.icmp_listener import ICMPListener
from crack.sessions.manager import SessionManager
from crack.sessions.storage.base import SessionStorage
from crack.sessions.config import SessionConfig
from crack.sessions.events import EventBus, SessionEvent


@pytest.fixture
def session_manager():
    """Create session manager for testing."""
    storage = SessionStorage()
    config = SessionConfig()
    return SessionManager(storage, config)


@pytest.fixture
def icmp_listener_ptunnel(session_manager):
    """Create ptunnel ICMP listener for testing."""
    return ICMPListener(
        session_manager=session_manager,
        tool='ptunnel',
        password='test123'
    )


@pytest.fixture
def icmp_listener_icmpsh(session_manager):
    """Create icmpsh ICMP listener for testing."""
    return ICMPListener(
        session_manager=session_manager,
        tool='icmpsh',
        target_ip='192.168.45.150'
    )


@pytest.fixture(autouse=True)
def reset_event_bus():
    """Reset event bus before each test."""
    EventBus.clear()
    yield
    EventBus.clear()


class TestICMPListenerInitialization:
    """Test ICMP listener initialization."""

    def test_ptunnel_initialization(self, icmp_listener_ptunnel):
        """Test ptunnel listener initializes correctly."""
        assert icmp_listener_ptunnel.tool == 'ptunnel'
        assert icmp_listener_ptunnel.password == 'test123'
        assert icmp_listener_ptunnel.listener.protocol == 'icmp'
        assert icmp_listener_ptunnel.listener.port is None
        assert icmp_listener_ptunnel.listener.status == 'stopped'

    def test_icmpsh_initialization(self, icmp_listener_icmpsh):
        """Test icmpsh listener initializes correctly."""
        assert icmp_listener_icmpsh.tool == 'icmpsh'
        assert icmp_listener_icmpsh.target_ip == '192.168.45.150'
        assert icmp_listener_icmpsh.listener.protocol == 'icmp'

    def test_auto_generated_password(self, session_manager):
        """Test auto-generated password."""
        listener = ICMPListener(session_manager=session_manager)
        assert listener.password is not None
        assert len(listener.password) > 0


class TestICMPListenerClientCommands:
    """Test client command generation."""

    def test_ptunnel_client_command(self, icmp_listener_ptunnel):
        """Test ptunnel client command generation."""
        cmd = icmp_listener_ptunnel.get_client_command('192.168.45.200', '10.10.10.10', 80)
        assert 'ptunnel' in cmd
        assert '-p 192.168.45.200' in cmd
        assert '-lp 8000' in cmd
        assert '-da 10.10.10.10' in cmd
        assert '-dp 80' in cmd
        assert '-x test123' in cmd

    def test_icmpsh_client_command(self, icmp_listener_icmpsh):
        """Test icmpsh client command generation."""
        cmd = icmp_listener_icmpsh.get_client_command('192.168.45.200')
        assert 'icmpsh.exe' in cmd
        assert '-t 192.168.45.200' in cmd

    def test_client_command_defaults(self, icmp_listener_ptunnel):
        """Test client command with defaults."""
        cmd = icmp_listener_ptunnel.get_client_command()
        assert '<LHOST>' in cmd
        assert '<DESTINATION_IP>' in cmd


class TestICMPListenerLifecycle:
    """Test listener start/stop lifecycle."""

    @patch('crack.sessions.listeners.icmp_listener.subprocess.Popen')
    @patch('crack.sessions.listeners.icmp_listener.os.geteuid')
    @patch.object(ICMPListener, '_check_tool_availability')
    @patch.object(ICMPListener, '_check_root_privileges')
    def test_start_ptunnel(self, mock_root, mock_check_tool, mock_geteuid,
                          mock_popen, icmp_listener_ptunnel):
        """Test starting ptunnel listener."""
        # Mock prerequisites
        mock_root.return_value = True
        mock_check_tool.return_value = True
        mock_geteuid.return_value = 0

        # Mock process
        mock_process = MagicMock()
        mock_process.poll.return_value = None
        mock_process.pid = 12345
        mock_popen.return_value = mock_process

        # Event subscriber
        events = []
        def capture_event(data):
            events.append(data)
        EventBus.subscribe(SessionEvent.LISTENER_STARTED, capture_event)

        # Start listener
        result = icmp_listener_ptunnel.start()

        assert result is True
        assert icmp_listener_ptunnel._running is True
        assert icmp_listener_ptunnel.listener.status == 'running'
        assert len(events) == 1
        assert events[0]['protocol'] == 'icmp'
        assert events[0]['tool'] == 'ptunnel'

    @patch('crack.sessions.listeners.icmp_listener.subprocess.Popen')
    @patch('crack.sessions.listeners.icmp_listener.os.geteuid')
    @patch.object(ICMPListener, '_check_tool_availability')
    @patch.object(ICMPListener, '_check_root_privileges')
    @patch.object(ICMPListener, '_disable_icmp_replies')
    def test_start_icmpsh(self, mock_disable, mock_root, mock_check_tool,
                         mock_geteuid, mock_popen, icmp_listener_icmpsh):
        """Test starting icmpsh listener."""
        # Mock prerequisites
        mock_root.return_value = True
        mock_check_tool.return_value = True
        mock_geteuid.return_value = 0
        mock_disable.return_value = True

        # Mock process
        mock_process = MagicMock()
        mock_process.poll.return_value = None
        mock_process.pid = 12345
        mock_popen.return_value = mock_process

        # Start listener
        result = icmp_listener_icmpsh.start()

        assert result is True
        assert icmp_listener_icmpsh._running is True
        mock_disable.assert_called_once()

    @patch.object(ICMPListener, '_check_root_privileges')
    def test_start_without_root(self, mock_root, icmp_listener_ptunnel):
        """Test starting without root privileges."""
        mock_root.return_value = False

        with pytest.raises(RuntimeError, match="root privileges"):
            icmp_listener_ptunnel.start()

    @patch.object(ICMPListener, '_check_tool_availability')
    @patch.object(ICMPListener, '_check_root_privileges')
    def test_start_without_tool(self, mock_root, mock_check_tool, icmp_listener_ptunnel):
        """Test starting without tool available."""
        mock_root.return_value = True
        mock_check_tool.return_value = False

        with pytest.raises(RuntimeError, match="not found"):
            icmp_listener_ptunnel.start()

    @patch.object(ICMPListener, '_enable_icmp_replies')
    def test_stop_icmpsh(self, mock_enable, icmp_listener_icmpsh):
        """Test stopping icmpsh listener."""
        # Mock running state
        icmp_listener_icmpsh._running = True
        icmp_listener_icmpsh._icmp_disabled = True
        icmp_listener_icmpsh.server_process = MagicMock()

        result = icmp_listener_icmpsh.stop()

        assert result is True
        assert icmp_listener_icmpsh._running is False
        mock_enable.assert_called_once()

    def test_stop_not_running(self, icmp_listener_ptunnel):
        """Test stopping listener that's not running."""
        result = icmp_listener_ptunnel.stop()
        assert result is False


class TestICMPListenerICMPManagement:
    """Test ICMP reply management."""

    @patch('crack.sessions.listeners.icmp_listener.subprocess.run')
    def test_disable_icmp_replies(self, mock_run, icmp_listener_icmpsh):
        """Test disabling kernel ICMP replies."""
        mock_run.return_value = MagicMock(returncode=0)

        result = icmp_listener_icmpsh._disable_icmp_replies()

        assert result is True
        assert icmp_listener_icmpsh._icmp_disabled is True
        mock_run.assert_called_once()
        assert 'icmp_echo_ignore_all=1' in str(mock_run.call_args)

    @patch('crack.sessions.listeners.icmp_listener.subprocess.run')
    def test_enable_icmp_replies(self, mock_run, icmp_listener_icmpsh):
        """Test enabling kernel ICMP replies."""
        icmp_listener_icmpsh._icmp_disabled = True
        mock_run.return_value = MagicMock(returncode=0)

        result = icmp_listener_icmpsh._enable_icmp_replies()

        assert result is True
        assert icmp_listener_icmpsh._icmp_disabled is False
        mock_run.assert_called_once()
        assert 'icmp_echo_ignore_all=0' in str(mock_run.call_args)


class TestICMPListenerConnectionHandling:
    """Test connection handling."""

    def test_handle_new_connection(self, icmp_listener_ptunnel, session_manager):
        """Test handling new ICMP tunnel connection."""
        # Mock listener state
        icmp_listener_ptunnel._running = True

        # Handle connection
        icmp_listener_ptunnel._handle_new_connection('192.168.45.150')

        # Verify session created
        sessions = session_manager.list_sessions({'type': 'icmp'})
        assert len(sessions) == 1
        assert sessions[0].target == '192.168.45.150'
        assert sessions[0].type == 'icmp'
        assert sessions[0].port == 0
        assert sessions[0].protocol == 'tunnel'

    def test_connection_callback(self, icmp_listener_ptunnel):
        """Test connection callbacks are invoked."""
        # Register callback
        callback_invoked = []
        def callback(session_id):
            callback_invoked.append(session_id)

        icmp_listener_ptunnel.on_connection(callback)

        # Handle connection
        icmp_listener_ptunnel._handle_new_connection('192.168.45.150')

        # Verify callback invoked
        assert len(callback_invoked) == 1


class TestICMPListenerInfo:
    """Test listener info retrieval."""

    def test_get_listener_info_ptunnel(self, icmp_listener_ptunnel):
        """Test getting ptunnel listener info."""
        info = icmp_listener_ptunnel.get_listener_info()

        assert info['protocol'] == 'icmp'
        assert info['port'] is None
        assert info['tool'] == 'ptunnel'
        assert info['password'] == 'test123'
        assert 'client_command' in info

    def test_get_listener_info_icmpsh(self, icmp_listener_icmpsh):
        """Test getting icmpsh listener info."""
        info = icmp_listener_icmpsh.get_listener_info()

        assert info['protocol'] == 'icmp'
        assert info['tool'] == 'icmpsh'
        assert info['target_ip'] == '192.168.45.150'
        assert 'icmp_disabled' in info


class TestICMPListenerToolDetection:
    """Test tool availability detection."""

    @patch('crack.sessions.listeners.icmp_listener.subprocess.run')
    def test_check_ptunnel_availability(self, mock_run, session_manager):
        """Test checking ptunnel availability."""
        listener = ICMPListener(session_manager=session_manager, tool='ptunnel')

        # Mock available
        mock_run.return_value = MagicMock(returncode=0)
        assert listener._check_tool_availability() is True

        # Mock not available
        mock_run.return_value = MagicMock(returncode=1)
        assert listener._check_tool_availability() is False

    @patch('crack.sessions.listeners.icmp_listener.Path')
    def test_check_icmpsh_availability(self, mock_path, session_manager):
        """Test checking icmpsh availability."""
        listener = ICMPListener(session_manager=session_manager, tool='icmpsh')

        # Mock get_icmpsh_path
        with patch.object(listener, '_get_icmpsh_path') as mock_get_path:
            # Available
            mock_get_path.return_value = Mock()
            assert listener._check_tool_availability() is True

            # Not available
            mock_get_path.return_value = None
            assert listener._check_tool_availability() is False
