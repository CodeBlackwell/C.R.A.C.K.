"""
Tunnel management for CRACK session system.

Provides comprehensive tunneling and pivoting capabilities:
- SSH tunneling (-L, -R, -D)
- Chisel HTTP tunneling
- Socat relay
- Proxychains configuration

Usage:
    >>> from sessions.tunnel import TunnelManager, SSHTunnel, ChiselTunnel
    >>> from sessions.storage.base import SessionStorage
    >>> from sessions.config import SessionConfig
    >>>
    >>> # Initialize manager
    >>> storage = SessionStorage()
    >>> config = SessionConfig()
    >>> manager = TunnelManager(storage, config)
    >>>
    >>> # Create SSH local forward tunnel
    >>> tunnel = manager.create_tunnel(
    ...     session_id='session-123',
    ...     tunnel_type='ssh-local',
    ...     target='192.168.45.150',
    ...     local_port=3306,
    ...     remote_host='192.168.1.10',
    ...     remote_port=3306
    ... )
"""

from .models import Tunnel, TunnelConfig
from .manager import TunnelManager
from .ssh import SSHTunnel
from .chisel import ChiselTunnel
from .proxychains import ProxychainsManager
from .socat import SocatTunnel

__all__ = [
    'Tunnel',
    'TunnelConfig',
    'TunnelManager',
    'SSHTunnel',
    'ChiselTunnel',
    'ProxychainsManager',
    'SocatTunnel'
]
