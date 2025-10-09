"""
Tests for DNS tunnel listener (DNSListener).

Tests cover:
- Listener initialization
- Start/stop lifecycle
- Client command generation
- Connection handling (mocked)
- Tool availability detection
"""

import pytest
import subprocess
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

from crack.sessions.listeners.dns_listener import DNSListener
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
def dns_listener_iodine(session_manager):
    """Create iodine DNS listener for testing."""
    return DNSListener(
        domain='tunnel.test.com',
        session_manager=session_manager,
        tool='iodine',
        password='test123'
    )


@pytest.fixture
def dns_listener_dnscat2(session_manager):
    """Create dnscat2 DNS listener for testing."""
    return DNSListener(
        domain='tunnel.test.com',
        session_manager=session_manager,
        tool='dnscat2',
        secret='secret123'
    )


@pytest.fixture(autouse=True)
def reset_event_bus():
    """Reset event bus before each test."""
    EventBus.clear()
    yield
    EventBus.clear()


class TestDNSListenerInitialization:
    """Test DNS listener initialization."""

    def test_iodine_initialization(self, dns_listener_iodine):
        """Test iodine listener initializes correctly."""
        assert dns_listener_iodine.domain == 'tunnel.test.com'
        assert dns_listener_iodine.tool == 'iodine'
        assert dns_listener_iodine.password == 'test123'
        assert dns_listener_iodine.tunnel_network == '10.0.0.1'
        assert dns_listener_iodine.listener.protocol == 'dns'
        assert dns_listener_iodine.listener.port == 53
        assert dns_listener_iodine.listener.status == 'stopped'

    def test_dnscat2_initialization(self, dns_listener_dnscat2):
        """Test dnscat2 listener initializes correctly."""
        assert dns_listener_dnscat2.domain == 'tunnel.test.com'
        assert dns_listener_dnscat2.tool == 'dnscat2'
        assert dns_listener_dnscat2.secret == 'secret123'
        assert dns_listener_dnscat2.listener.protocol == 'dns'

    def test_auto_generated_password(self, session_manager):
        """Test auto-generated password/secret."""
        listener = DNSListener(
            domain='tunnel.test.com',
            session_manager=session_manager
        )
        assert listener.password is not None
        assert len(listener.password) > 0

    def test_listener_config(self, dns_listener_iodine):
        """Test listener configuration."""
        config = dns_listener_iodine.listener.config
        assert config['tool'] == 'iodine'
        assert config['domain'] == 'tunnel.test.com'
        assert config['password'] == 'test123'


class TestDNSListenerClientCommands:
    """Test client command generation."""

    def test_iodine_client_command(self, dns_listener_iodine):
        """Test iodine client command generation."""
        cmd = dns_listener_iodine.get_client_command()
        assert 'iodine' in cmd
        assert '-r' in cmd
        assert '-P test123' in cmd
        assert 'tunnel.test.com' in cmd

    def test_dnscat2_client_command(self, dns_listener_dnscat2):
        """Test dnscat2 client command generation."""
        cmd = dns_listener_dnscat2.get_client_command()
        assert 'dnscat' in cmd
        assert '--secret=secret123' in cmd
        assert 'tunnel.test.com' in cmd

    def test_client_command_with_server_ip(self, dns_listener_iodine):
        """Test client command with server IP."""
        cmd = dns_listener_iodine.get_client_command('192.168.45.200')
        # Iodine doesn't use IP in command (uses domain)
        assert 'tunnel.test.com' in cmd


class TestDNSListenerLifecycle:
    """Test listener start/stop lifecycle."""

    @patch('crack.sessions.listeners.dns_listener.subprocess.Popen')
    @patch('crack.sessions.listeners.dns_listener.os.geteuid')
    @patch.object(DNSListener, '_check_tool_availability')
    def test_start_iodine(self, mock_check_tool, mock_geteuid, mock_popen, dns_listener_iodine):
        """Test starting iodine listener."""
        # Mock tool availability
        mock_check_tool.return_value = True

        # Mock root privileges
        mock_geteuid.return_value = 0

        # Mock process
        mock_process = MagicMock()
        mock_process.poll.return_value = None  # Process running
        mock_process.pid = 12345
        mock_popen.return_value = mock_process

        # Event subscriber
        events = []
        def capture_event(data):
            events.append(data)
        EventBus.subscribe(SessionEvent.LISTENER_STARTED, capture_event)

        # Start listener
        result = dns_listener_iodine.start()

        assert result is True
        assert dns_listener_iodine._running is True
        assert dns_listener_iodine.listener.status == 'running'
        assert len(events) == 1
        assert events[0]['protocol'] == 'dns'
        assert events[0]['tool'] == 'iodine'

    @patch('crack.sessions.listeners.dns_listener.subprocess.Popen')
    @patch('crack.sessions.listeners.dns_listener.os.geteuid')
    @patch.object(DNSListener, '_check_tool_availability')
    def test_start_dnscat2(self, mock_check_tool, mock_geteuid, mock_popen, dns_listener_dnscat2):
        """Test starting dnscat2 listener."""
        # Mock tool availability
        mock_check_tool.return_value = True

        # Mock root privileges
        mock_geteuid.return_value = 0

        # Mock process
        mock_process = MagicMock()
        mock_process.poll.return_value = None
        mock_process.pid = 12345
        mock_popen.return_value = mock_process

        # Start listener
        result = dns_listener_dnscat2.start()

        assert result is True
        assert dns_listener_dnscat2._running is True

    @patch.object(DNSListener, '_check_tool_availability')
    def test_start_without_tool(self, mock_check_tool, dns_listener_iodine):
        """Test starting without tool available."""
        mock_check_tool.return_value = False

        with pytest.raises(RuntimeError, match="not found"):
            dns_listener_iodine.start()

    def test_stop_listener(self, dns_listener_iodine):
        """Test stopping listener."""
        # Mock running state
        dns_listener_iodine._running = True
        dns_listener_iodine.server_process = MagicMock()

        # Event subscriber
        events = []
        def capture_event(data):
            events.append(data)
        EventBus.subscribe(SessionEvent.LISTENER_STOPPED, capture_event)

        result = dns_listener_iodine.stop()

        assert result is True
        assert dns_listener_iodine._running is False
        assert dns_listener_iodine.listener.status == 'stopped'
        assert len(events) == 1

    def test_stop_not_running(self, dns_listener_iodine):
        """Test stopping listener that's not running."""
        result = dns_listener_iodine.stop()
        assert result is False


class TestDNSListenerConnectionHandling:
    """Test connection handling."""

    def test_handle_new_connection(self, dns_listener_iodine, session_manager):
        """Test handling new DNS tunnel connection."""
        # Mock listener state
        dns_listener_iodine._running = True

        # Handle connection
        dns_listener_iodine._handle_new_connection('192.168.45.150')

        # Verify session created
        sessions = session_manager.list_sessions({'type': 'dns'})
        assert len(sessions) == 1
        assert sessions[0].target == '192.168.45.150'
        assert sessions[0].type == 'dns'
        assert sessions[0].port == 53
        assert sessions[0].protocol == 'tunnel'

    def test_connection_callback(self, dns_listener_iodine):
        """Test connection callbacks are invoked."""
        # Register callback
        callback_invoked = []
        def callback(session_id):
            callback_invoked.append(session_id)

        dns_listener_iodine.on_connection(callback)

        # Handle connection
        dns_listener_iodine._handle_new_connection('192.168.45.150')

        # Verify callback invoked
        assert len(callback_invoked) == 1


class TestDNSListenerInfo:
    """Test listener info retrieval."""

    def test_get_listener_info_iodine(self, dns_listener_iodine):
        """Test getting iodine listener info."""
        info = dns_listener_iodine.get_listener_info()

        assert info['protocol'] == 'dns'
        assert info['port'] == 53
        assert info['tool'] == 'iodine'
        assert info['domain'] == 'tunnel.test.com'
        assert info['password'] == 'test123'
        assert info['tunnel_network'] == '10.0.0.1'
        assert 'client_command' in info

    def test_get_listener_info_dnscat2(self, dns_listener_dnscat2):
        """Test getting dnscat2 listener info."""
        info = dns_listener_dnscat2.get_listener_info()

        assert info['protocol'] == 'dns'
        assert info['tool'] == 'dnscat2'
        assert info['secret'] == 'secret123'
        assert 'client_command' in info

    def test_get_active_sessions(self, dns_listener_iodine):
        """Test getting active sessions."""
        # Create sessions
        dns_listener_iodine.sessions = ['session-1', 'session-2']

        sessions = dns_listener_iodine.get_active_sessions()

        assert len(sessions) == 2
        assert 'session-1' in sessions
        assert 'session-2' in sessions


class TestDNSListenerToolDetection:
    """Test tool availability detection."""

    @patch('crack.sessions.listeners.dns_listener.subprocess.run')
    def test_check_iodine_availability(self, mock_run, session_manager):
        """Test checking iodine availability."""
        listener = DNSListener(
            domain='test.com',
            session_manager=session_manager,
            tool='iodine'
        )

        # Mock available
        mock_run.return_value = MagicMock(returncode=0)
        assert listener._check_tool_availability() is True

        # Mock not available
        mock_run.return_value = MagicMock(returncode=1)
        assert listener._check_tool_availability() is False

    @patch('crack.sessions.listeners.dns_listener.Path')
    def test_check_dnscat2_availability(self, mock_path, session_manager):
        """Test checking dnscat2 availability."""
        listener = DNSListener(
            domain='test.com',
            session_manager=session_manager,
            tool='dnscat2'
        )

        # Mock available
        mock_path_obj = MagicMock()
        mock_path_obj.exists.return_value = True
        mock_path.return_value = mock_path_obj
        assert listener._check_tool_availability() is True

        # Mock not available
        mock_path_obj.exists.return_value = False
        assert listener._check_tool_availability() is False


class TestDNSListenerStatus:
    """Test listener status."""

    def test_status_stopped(self, dns_listener_iodine):
        """Test status when stopped."""
        assert dns_listener_iodine.status() == 'stopped'

    def test_status_running(self, dns_listener_iodine):
        """Test status when running."""
        dns_listener_iodine.listener.start()
        assert dns_listener_iodine.status() == 'running'
