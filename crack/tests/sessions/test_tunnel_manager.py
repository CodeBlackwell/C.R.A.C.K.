"""
Tests for TunnelManager.

Tests tunnel orchestration, port conflict detection, and lifecycle management.
"""

import pytest
import os
import signal
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from crack.sessions.tunnel.manager import TunnelManager
from crack.sessions.tunnel.models import Tunnel, TunnelConfig
from crack.sessions.storage.base import SessionStorage
from crack.sessions.config import SessionConfig


@pytest.fixture
def temp_storage(tmp_path):
    """Create temporary storage for testing."""
    storage_path = tmp_path / "tunnels"
    storage_path.mkdir()
    return SessionStorage(storage_path=storage_path)


@pytest.fixture
def mock_config():
    """Mock SessionConfig."""
    return Mock(spec=SessionConfig)


@pytest.fixture
def manager(temp_storage, mock_config):
    """Create TunnelManager for testing."""
    return TunnelManager(temp_storage, mock_config)


class TestTunnelCreation:
    """Test tunnel creation."""

    def test_create_ssh_local_tunnel(self, manager):
        """Test creating SSH local forward tunnel."""
        tunnel = manager.create_tunnel(
            session_id='test-session',
            tunnel_type='ssh-local',
            target='192.168.45.150',
            local_port=3306,
            remote_host='192.168.1.10',
            remote_port=3306
        )

        assert tunnel.type == 'ssh-local'
        assert tunnel.session_id == 'test-session'
        assert tunnel.target == '192.168.45.150'
        assert tunnel.config.local_port == 3306
        assert tunnel.config.remote_host == '192.168.1.10'
        assert tunnel.config.remote_port == 3306
        assert tunnel.status == 'starting'

    def test_create_ssh_dynamic_tunnel(self, manager):
        """Test creating SSH SOCKS proxy."""
        tunnel = manager.create_tunnel(
            session_id='test-session',
            tunnel_type='ssh-dynamic',
            target='192.168.45.150',
            socks_port=1080
        )

        assert tunnel.type == 'ssh-dynamic'
        assert tunnel.config.socks_port == 1080

    def test_create_socat_tunnel(self, manager):
        """Test creating socat relay."""
        tunnel = manager.create_tunnel(
            session_id='test-session',
            tunnel_type='socat',
            target='192.168.45.150',
            local_port=8080,
            remote_host='192.168.1.10',
            remote_port=80
        )

        assert tunnel.type == 'socat'
        assert tunnel.config.local_port == 8080
        assert tunnel.config.remote_host == '192.168.1.10'
        assert tunnel.config.remote_port == 80

    def test_create_chisel_tunnel(self, manager):
        """Test creating chisel tunnel."""
        tunnel = manager.create_tunnel(
            session_id='test-session',
            tunnel_type='chisel',
            target='192.168.45.150',
            server_port=8000
        )

        assert tunnel.type == 'chisel'
        assert tunnel.config.server_port == 8000

    def test_invalid_tunnel_type(self, manager):
        """Test creating tunnel with invalid type."""
        with pytest.raises(ValueError, match="Invalid tunnel type"):
            manager.create_tunnel(
                session_id='test-session',
                tunnel_type='invalid',
                target='192.168.45.150'
            )

    def test_missing_required_params_ssh_local(self, manager):
        """Test SSH local tunnel with missing params."""
        with pytest.raises(ValueError, match="ssh-local requires"):
            manager.create_tunnel(
                session_id='test-session',
                tunnel_type='ssh-local',
                target='192.168.45.150',
                local_port=3306
                # Missing remote_host and remote_port
            )

    def test_missing_required_params_ssh_dynamic(self, manager):
        """Test SSH dynamic tunnel with missing params."""
        with pytest.raises(ValueError, match="ssh-dynamic requires"):
            manager.create_tunnel(
                session_id='test-session',
                tunnel_type='ssh-dynamic',
                target='192.168.45.150'
                # Missing socks_port
            )

    def test_missing_target(self, manager):
        """Test creating tunnel without target."""
        with pytest.raises(ValueError, match="Target host is required"):
            manager.create_tunnel(
                session_id='test-session',
                tunnel_type='ssh-local',
                target=''
            )


class TestTunnelListing:
    """Test tunnel listing and filtering."""

    def test_list_all_tunnels(self, manager):
        """Test listing all tunnels."""
        # Create multiple tunnels
        tunnel1 = manager.create_tunnel(
            session_id='session-1',
            tunnel_type='ssh-local',
            target='192.168.45.150',
            local_port=3306,
            remote_host='192.168.1.10',
            remote_port=3306
        )

        tunnel2 = manager.create_tunnel(
            session_id='session-2',
            tunnel_type='ssh-dynamic',
            target='192.168.45.151',
            socks_port=1080
        )

        tunnels = manager.list_tunnels()
        assert len(tunnels) == 2
        assert tunnel1 in tunnels
        assert tunnel2 in tunnels

    def test_list_tunnels_by_session(self, manager):
        """Test filtering tunnels by session ID."""
        tunnel1 = manager.create_tunnel(
            session_id='session-1',
            tunnel_type='ssh-local',
            target='192.168.45.150',
            local_port=3306,
            remote_host='192.168.1.10',
            remote_port=3306
        )

        tunnel2 = manager.create_tunnel(
            session_id='session-2',
            tunnel_type='ssh-dynamic',
            target='192.168.45.151',
            socks_port=1080
        )

        # Filter by session-1
        tunnels = manager.list_tunnels(session_id='session-1')
        assert len(tunnels) == 1
        assert tunnels[0].session_id == 'session-1'

    def test_list_tunnels_by_status(self, manager):
        """Test filtering tunnels by status."""
        tunnel1 = manager.create_tunnel(
            session_id='session-1',
            tunnel_type='ssh-local',
            target='192.168.45.150',
            local_port=3306,
            remote_host='192.168.1.10',
            remote_port=3306
        )

        tunnel2 = manager.create_tunnel(
            session_id='session-2',
            tunnel_type='ssh-dynamic',
            target='192.168.45.151',
            socks_port=1080
        )

        # Mark tunnel1 as active
        tunnel1.mark_active()

        # Filter active only
        tunnels = manager.list_tunnels(filters={'status': 'active'})
        assert len(tunnels) == 1
        assert tunnels[0].status == 'active'

    def test_list_tunnels_by_type(self, manager):
        """Test filtering tunnels by type."""
        tunnel1 = manager.create_tunnel(
            session_id='session-1',
            tunnel_type='ssh-local',
            target='192.168.45.150',
            local_port=3306,
            remote_host='192.168.1.10',
            remote_port=3306
        )

        tunnel2 = manager.create_tunnel(
            session_id='session-2',
            tunnel_type='ssh-dynamic',
            target='192.168.45.151',
            socks_port=1080
        )

        # Filter by type
        tunnels = manager.list_tunnels(filters={'type': 'ssh-local'})
        assert len(tunnels) == 1
        assert tunnels[0].type == 'ssh-local'


class TestTunnelRetrieval:
    """Test tunnel retrieval by ID."""

    def test_get_tunnel_by_full_id(self, manager):
        """Test getting tunnel by full UUID."""
        tunnel = manager.create_tunnel(
            session_id='test-session',
            tunnel_type='ssh-local',
            target='192.168.45.150',
            local_port=3306,
            remote_host='192.168.1.10',
            remote_port=3306
        )

        retrieved = manager.get_tunnel(tunnel.id)
        assert retrieved.id == tunnel.id

    def test_get_tunnel_by_prefix(self, manager):
        """Test getting tunnel by ID prefix."""
        tunnel = manager.create_tunnel(
            session_id='test-session',
            tunnel_type='ssh-local',
            target='192.168.45.150',
            local_port=3306,
            remote_host='192.168.1.10',
            remote_port=3306
        )

        # Get by first 8 characters
        prefix = tunnel.id[:8]
        retrieved = manager.get_tunnel(prefix)
        assert retrieved.id == tunnel.id

    def test_get_nonexistent_tunnel(self, manager):
        """Test getting tunnel that doesn't exist."""
        tunnel = manager.get_tunnel('nonexistent')
        assert tunnel is None


class TestPortAvailability:
    """Test port conflict detection."""

    @patch('socket.socket')
    def test_port_available(self, mock_socket, manager):
        """Test checking if port is available."""
        # Mock port as available
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        mock_sock.bind.return_value = None

        assert manager._is_port_available(3306) is True

    @patch('socket.socket')
    def test_port_in_use(self, mock_socket, manager):
        """Test checking if port is in use."""
        # Mock port as in use
        mock_sock = MagicMock()
        mock_socket.return_value = mock_sock
        mock_sock.bind.side_effect = OSError("Address already in use")

        assert manager._is_port_available(3306) is False

    def test_get_next_available_port(self, manager):
        """Test finding next available port."""
        with patch.object(manager, '_is_port_available') as mock_available:
            # Mock first port as unavailable, second as available
            mock_available.side_effect = [False, True]

            port = manager.get_next_available_port(start=8000)
            assert port == 8001

    def test_no_available_ports(self, manager):
        """Test when no ports available in range."""
        with patch.object(manager, '_is_port_available', return_value=False):
            port = manager.get_next_available_port(start=8000, end=8001)
            assert port is None


class TestTunnelKilling:
    """Test tunnel termination."""

    @patch('os.kill')
    def test_kill_tunnel_with_pid(self, mock_kill, manager):
        """Test killing tunnel with process ID."""
        tunnel = manager.create_tunnel(
            session_id='test-session',
            tunnel_type='ssh-local',
            target='192.168.45.150',
            local_port=3306,
            remote_host='192.168.1.10',
            remote_port=3306
        )

        # Set PID and mark active
        tunnel.pid = 12345
        tunnel.mark_active()

        # Mock process as alive
        with patch.object(manager, '_is_pid_alive', return_value=True):
            result = manager.kill_tunnel(tunnel.id)

        assert result is True
        assert tunnel.status == 'dead'
        mock_kill.assert_called()

    def test_kill_nonexistent_tunnel(self, manager):
        """Test killing tunnel that doesn't exist."""
        result = manager.kill_tunnel('nonexistent')
        assert result is False

    def test_kill_already_dead_tunnel(self, manager):
        """Test killing tunnel that's already dead."""
        tunnel = manager.create_tunnel(
            session_id='test-session',
            tunnel_type='ssh-local',
            target='192.168.45.150',
            local_port=3306,
            remote_host='192.168.1.10',
            remote_port=3306
        )

        tunnel.mark_dead()
        result = manager.kill_tunnel(tunnel.id)
        assert result is False


class TestTunnelCleanup:
    """Test tunnel cleanup operations."""

    def test_cleanup_session_tunnels(self, manager):
        """Test cleaning up all tunnels for a session."""
        # Create multiple tunnels for same session
        tunnel1 = manager.create_tunnel(
            session_id='test-session',
            tunnel_type='ssh-local',
            target='192.168.45.150',
            local_port=3306,
            remote_host='192.168.1.10',
            remote_port=3306
        )

        tunnel2 = manager.create_tunnel(
            session_id='test-session',
            tunnel_type='ssh-dynamic',
            target='192.168.45.150',
            socks_port=1080
        )

        # Mark both as active
        tunnel1.mark_active()
        tunnel2.mark_active()

        # Mock killing process
        with patch.object(manager, '_is_pid_alive', return_value=False):
            killed = manager.cleanup_session_tunnels('test-session')

        assert killed == 2
        assert tunnel1.status == 'dead'
        assert tunnel2.status == 'dead'


class TestTunnelStats:
    """Test tunnel statistics."""

    def test_get_stats(self, manager):
        """Test getting tunnel statistics."""
        # Create tunnels with different statuses
        tunnel1 = manager.create_tunnel(
            session_id='session-1',
            tunnel_type='ssh-local',
            target='192.168.45.150',
            local_port=3306,
            remote_host='192.168.1.10',
            remote_port=3306
        )

        tunnel2 = manager.create_tunnel(
            session_id='session-2',
            tunnel_type='ssh-dynamic',
            target='192.168.45.151',
            socks_port=1080
        )

        tunnel1.mark_active()
        tunnel2.mark_dead()

        stats = manager.get_stats()

        assert stats['total'] == 2
        assert stats['active'] == 1
        assert stats['dead'] == 1
        assert stats['by_type']['ssh-local'] == 1
        assert stats['by_type']['ssh-dynamic'] == 1

    def test_get_stats_by_session(self, manager):
        """Test getting stats for specific session."""
        tunnel1 = manager.create_tunnel(
            session_id='session-1',
            tunnel_type='ssh-local',
            target='192.168.45.150',
            local_port=3306,
            remote_host='192.168.1.10',
            remote_port=3306
        )

        tunnel2 = manager.create_tunnel(
            session_id='session-2',
            tunnel_type='ssh-dynamic',
            target='192.168.45.151',
            socks_port=1080
        )

        stats = manager.get_stats(session_id='session-1')
        assert stats['total'] == 1
