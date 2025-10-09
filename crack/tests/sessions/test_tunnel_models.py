"""
Tests for tunnel models (Tunnel, TunnelConfig).

Tests model serialization, deserialization, and state management.
"""

import pytest
from datetime import datetime

from crack.sessions.tunnel.models import Tunnel, TunnelConfig


class TestTunnelConfig:
    """Test TunnelConfig model."""

    def test_create_config(self):
        """Test creating TunnelConfig."""
        config = TunnelConfig(
            local_port=3306,
            remote_host='192.168.1.10',
            remote_port=3306
        )

        assert config.local_port == 3306
        assert config.remote_host == '192.168.1.10'
        assert config.remote_port == 3306

    def test_config_to_dict(self):
        """Test serializing TunnelConfig to dict."""
        config = TunnelConfig(
            local_port=3306,
            remote_host='192.168.1.10',
            remote_port=3306
        )

        data = config.to_dict()

        assert data['local_port'] == 3306
        assert data['remote_host'] == '192.168.1.10'
        assert data['remote_port'] == 3306

    def test_config_from_dict(self):
        """Test deserializing TunnelConfig from dict."""
        data = {
            'local_port': 3306,
            'remote_host': '192.168.1.10',
            'remote_port': 3306
        }

        config = TunnelConfig.from_dict(data)

        assert config.local_port == 3306
        assert config.remote_host == '192.168.1.10'
        assert config.remote_port == 3306


class TestTunnel:
    """Test Tunnel model."""

    def test_create_tunnel(self):
        """Test creating Tunnel."""
        config = TunnelConfig(local_port=3306, remote_host='192.168.1.10', remote_port=3306)

        tunnel = Tunnel(
            type='ssh-local',
            session_id='test-session',
            target='192.168.45.150',
            config=config,
            status='active'
        )

        assert tunnel.type == 'ssh-local'
        assert tunnel.session_id == 'test-session'
        assert tunnel.target == '192.168.45.150'
        assert tunnel.config.local_port == 3306
        assert tunnel.status == 'active'

    def test_tunnel_is_active(self):
        """Test checking if tunnel is active."""
        tunnel = Tunnel(type='ssh-local', status='active')
        assert tunnel.is_active() is True

        tunnel.status = 'dead'
        assert tunnel.is_active() is False

        tunnel.status = 'starting'
        assert tunnel.is_active() is True

    def test_tunnel_mark_dead(self):
        """Test marking tunnel as dead."""
        tunnel = Tunnel(type='ssh-local', status='active')

        tunnel.mark_dead('Connection lost')

        assert tunnel.status == 'dead'
        assert tunnel.error_message == 'Connection lost'

    def test_tunnel_mark_active(self):
        """Test marking tunnel as active."""
        tunnel = Tunnel(type='ssh-local', status='dead')

        tunnel.mark_active()

        assert tunnel.status == 'active'
        assert tunnel.error_message is None

    def test_tunnel_mark_error(self):
        """Test marking tunnel as error."""
        tunnel = Tunnel(type='ssh-local', status='active')

        tunnel.mark_error('Failed to connect')

        assert tunnel.status == 'error'
        assert tunnel.error_message == 'Failed to connect'

    def test_tunnel_connection_string_ssh_local(self):
        """Test connection string for SSH local forward."""
        config = TunnelConfig(local_port=3306, remote_host='192.168.1.10', remote_port=3306)
        tunnel = Tunnel(type='ssh-local', config=config)

        conn_str = tunnel.get_connection_string()

        assert conn_str == 'localhost:3306 -> 192.168.1.10:3306'

    def test_tunnel_connection_string_ssh_remote(self):
        """Test connection string for SSH remote forward."""
        config = TunnelConfig(local_port=445, remote_port=445)
        tunnel = Tunnel(type='ssh-remote', target='192.168.45.150', config=config)

        conn_str = tunnel.get_connection_string()

        assert conn_str == '192.168.45.150:445 -> localhost:445'

    def test_tunnel_connection_string_ssh_dynamic(self):
        """Test connection string for SSH SOCKS proxy."""
        config = TunnelConfig(socks_port=1080)
        tunnel = Tunnel(type='ssh-dynamic', config=config)

        conn_str = tunnel.get_connection_string()

        assert conn_str == 'SOCKS proxy localhost:1080'

    def test_tunnel_to_dict(self):
        """Test serializing Tunnel to dict."""
        config = TunnelConfig(local_port=3306, remote_host='192.168.1.10', remote_port=3306)

        tunnel = Tunnel(
            type='ssh-local',
            session_id='test-session',
            target='192.168.45.150',
            config=config,
            status='active',
            pid=12345,
            command='ssh -N -L 3306:192.168.1.10:3306 user@192.168.45.150'
        )

        data = tunnel.to_dict()

        assert data['type'] == 'ssh-local'
        assert data['session_id'] == 'test-session'
        assert data['target'] == '192.168.45.150'
        assert data['status'] == 'active'
        assert data['pid'] == 12345
        assert data['command'] == 'ssh -N -L 3306:192.168.1.10:3306 user@192.168.45.150'
        assert 'config' in data
        assert isinstance(data['created_at'], str)  # ISO format

    def test_tunnel_from_dict(self):
        """Test deserializing Tunnel from dict."""
        data = {
            'id': 'test-id',
            'type': 'ssh-local',
            'session_id': 'test-session',
            'target': '192.168.45.150',
            'config': {
                'local_port': 3306,
                'remote_host': '192.168.1.10',
                'remote_port': 3306,
                'socks_port': None,
                'reverse': False,
                'server_port': None,
                'tunnel_spec': None,
                'extra_args': []
            },
            'status': 'active',
            'pid': 12345,
            'command': 'ssh -N -L 3306:192.168.1.10:3306 user@192.168.45.150',
            'metadata': {},
            'created_at': '2024-01-01T12:00:00',
            'last_seen': '2024-01-01T12:00:00',
            'error_message': None
        }

        tunnel = Tunnel.from_dict(data)

        assert tunnel.id == 'test-id'
        assert tunnel.type == 'ssh-local'
        assert tunnel.session_id == 'test-session'
        assert tunnel.target == '192.168.45.150'
        assert tunnel.status == 'active'
        assert tunnel.pid == 12345
        assert isinstance(tunnel.created_at, datetime)
        assert isinstance(tunnel.config, TunnelConfig)

    def test_tunnel_update_last_seen(self):
        """Test updating last_seen timestamp."""
        tunnel = Tunnel(type='ssh-local')

        old_time = tunnel.last_seen
        import time
        time.sleep(0.1)  # Small delay

        tunnel.update_last_seen()

        assert tunnel.last_seen > old_time
