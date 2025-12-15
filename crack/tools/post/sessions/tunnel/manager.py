"""
Tunnel management orchestrator.

Central tunnel manager that coordinates all tunnel types:
- Creates and tracks tunnels
- Port conflict detection
- Auto-cleanup on session death
- Process validation
"""

import os
import signal
import socket
import threading
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

from .models import Tunnel, TunnelConfig
from ..storage.base import SessionStorage
from ..config import SessionConfig
from ..events import EventBus, SessionEvent


class TunnelManager:
    """Central tunnel management and orchestration.

    Features:
    - Create/list/kill tunnels (SSH, chisel, socat, proxychains)
    - Port conflict detection (checks if port is in use)
    - Auto-cleanup on session death
    - Multiple tunnel types support
    - Thread-safe operations

    Thread Safety:
        All tunnel operations are protected by a lock to ensure
        safe concurrent access from multiple sessions and threads.

    Example:
        >>> from sessions.storage.base import SessionStorage
        >>> from sessions.config import SessionConfig
        >>> from sessions.tunnel.manager import TunnelManager
        >>>
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
        >>>
        >>> # List active tunnels
        >>> tunnels = manager.list_tunnels(session_id='session-123')
        >>>
        >>> # Kill tunnel
        >>> manager.kill_tunnel(tunnel.id)
    """

    def __init__(self, storage: SessionStorage, config: SessionConfig):
        """Initialize tunnel manager.

        Args:
            storage: SessionStorage instance for persistence
            config: SessionConfig for default values
        """
        self.storage = storage
        self.config = config
        self._tunnels: Dict[str, Tunnel] = {}
        self._lock = threading.Lock()

        # Load existing tunnels (validate on load)
        self._load_tunnels()

    def _load_tunnels(self):
        """Load tunnels from storage and validate."""
        # For now, we'll store tunnels in session metadata
        # Future: Separate tunnel storage file
        pass

    def create_tunnel(self, session_id: str, tunnel_type: str, target: str, **kwargs) -> Tunnel:
        """Create and register a new tunnel.

        Args:
            session_id: Associated session ID
            tunnel_type: Tunnel type ('ssh-local', 'ssh-remote', 'ssh-dynamic',
                                     'chisel', 'socat', 'proxychains')
            target: Target host for tunnel
            **kwargs: Type-specific parameters:
                - local_port: Local port to bind
                - remote_host: Remote host to connect to
                - remote_port: Remote port to connect to
                - socks_port: SOCKS proxy port (for SSH -D)
                - reverse: Enable reverse mode (chisel, SSH -R)
                - server_port: Server port (chisel)
                - tunnel_spec: Chisel tunnel specification
                - extra_args: List of additional command arguments

        Returns:
            Newly created Tunnel instance

        Raises:
            ValueError: If invalid parameters or port conflict detected

        Example:
            >>> # SSH local forward
            >>> tunnel = manager.create_tunnel(
            ...     session_id='session-123',
            ...     tunnel_type='ssh-local',
            ...     target='192.168.45.150',
            ...     local_port=3306,
            ...     remote_host='192.168.1.10',
            ...     remote_port=3306
            ... )
            >>>
            >>> # SSH SOCKS proxy
            >>> tunnel = manager.create_tunnel(
            ...     session_id='session-123',
            ...     tunnel_type='ssh-dynamic',
            ...     target='192.168.45.150',
            ...     socks_port=1080
            ... )
            >>>
            >>> # Socat relay
            >>> tunnel = manager.create_tunnel(
            ...     session_id='session-123',
            ...     tunnel_type='socat',
            ...     target='192.168.45.150',
            ...     local_port=8080,
            ...     remote_host='192.168.1.10',
            ...     remote_port=80
            ... )
        """
        # Validate tunnel type
        valid_types = ['ssh-local', 'ssh-remote', 'ssh-dynamic', 'chisel', 'socat', 'proxychains']
        if tunnel_type not in valid_types:
            raise ValueError(f"Invalid tunnel type: {tunnel_type}. Valid types: {', '.join(valid_types)}")

        if not target:
            raise ValueError("Target host is required")

        # Extract configuration parameters
        config = TunnelConfig(
            local_port=kwargs.get('local_port'),
            remote_host=kwargs.get('remote_host'),
            remote_port=kwargs.get('remote_port'),
            socks_port=kwargs.get('socks_port'),
            reverse=kwargs.get('reverse', False),
            server_port=kwargs.get('server_port'),
            tunnel_spec=kwargs.get('tunnel_spec'),
            extra_args=kwargs.get('extra_args', [])
        )

        # Validate type-specific requirements
        if tunnel_type == 'ssh-local':
            if not all([config.local_port, config.remote_host, config.remote_port]):
                raise ValueError("ssh-local requires: local_port, remote_host, remote_port")
            # Check port conflict
            if not self._is_port_available(config.local_port):
                raise ValueError(f"Port {config.local_port} is already in use")

        elif tunnel_type == 'ssh-remote':
            if not all([config.local_port, config.remote_port]):
                raise ValueError("ssh-remote requires: local_port, remote_port")

        elif tunnel_type == 'ssh-dynamic':
            if not config.socks_port:
                raise ValueError("ssh-dynamic requires: socks_port")
            # Check port conflict
            if not self._is_port_available(config.socks_port):
                raise ValueError(f"Port {config.socks_port} is already in use")

        elif tunnel_type == 'chisel':
            if not config.server_port:
                raise ValueError("chisel requires: server_port")

        elif tunnel_type == 'socat':
            if not all([config.local_port, config.remote_host, config.remote_port]):
                raise ValueError("socat requires: local_port, remote_host, remote_port")
            # Check port conflict
            if not self._is_port_available(config.local_port):
                raise ValueError(f"Port {config.local_port} is already in use")

        elif tunnel_type == 'proxychains':
            if not config.socks_port:
                raise ValueError("proxychains requires: socks_port (SOCKS proxy port)")

        # Create tunnel instance
        tunnel = Tunnel(
            type=tunnel_type,
            session_id=session_id,
            target=target,
            config=config,
            status='starting',
            created_at=datetime.now(),
            last_seen=datetime.now()
        )

        # Store in memory
        with self._lock:
            self._tunnels[tunnel.id] = tunnel

        return tunnel

    def list_tunnels(self, session_id: str = None, filters: Dict[str, Any] = None) -> List[Tunnel]:
        """List tunnels with optional filtering.

        Args:
            session_id: Filter by session ID (None = all tunnels)
            filters: Additional filter criteria:
                - status: 'active', 'dead', 'starting', 'error'
                - type: Tunnel type
                - active_only: Boolean (shortcut for status='active')

        Returns:
            List of Tunnel instances matching filters

        Example:
            >>> # List all active tunnels for session
            >>> tunnels = manager.list_tunnels(session_id='session-123', filters={'status': 'active'})
            >>>
            >>> # List all SSH tunnels
            >>> ssh_tunnels = manager.list_tunnels(filters={'type': 'ssh-local'})
            >>>
            >>> # List all active tunnels (any session)
            >>> active = manager.list_tunnels(filters={'active_only': True})
        """
        filters = filters or {}

        with self._lock:
            tunnels = list(self._tunnels.values())

        # Apply filters
        results = []
        for tunnel in tunnels:
            match = True

            # Session ID filter
            if session_id and tunnel.session_id != session_id:
                match = False

            # Active only filter (shortcut)
            if filters.get('active_only'):
                if not tunnel.is_active():
                    match = False

            # Status filter
            if 'status' in filters:
                if tunnel.status != filters['status']:
                    match = False

            # Type filter
            if 'type' in filters:
                if tunnel.type != filters['type']:
                    match = False

            if match:
                results.append(tunnel)

        # Sort by created_at (most recent first)
        results.sort(key=lambda t: t.created_at, reverse=True)

        return results

    def get_tunnel(self, id: str) -> Optional[Tunnel]:
        """Retrieve tunnel by ID.

        Validates PID and updates last_seen timestamp.

        Args:
            id: Tunnel UUID (full or partial - matches prefix)

        Returns:
            Tunnel instance if found, None otherwise

        Example:
            >>> # Full UUID
            >>> tunnel = manager.get_tunnel('a1b2c3d4-1234-5678-90ab-cdef12345678')
            >>>
            >>> # Partial UUID (prefix match)
            >>> tunnel = manager.get_tunnel('a1b2c3d4')
        """
        with self._lock:
            # Try exact match first
            if id in self._tunnels:
                tunnel = self._tunnels[id]
            else:
                # Try prefix match (allows short IDs)
                matches = [t for tid, t in self._tunnels.items() if tid.startswith(id)]
                if len(matches) == 1:
                    tunnel = matches[0]
                elif len(matches) > 1:
                    print(f"Warning: Multiple tunnels match '{id}' - using exact match only")
                    return None
                else:
                    return None

        # Validate PID if tunnel is marked active
        if tunnel.status in ['active', 'starting']:
            if tunnel.pid and not self._is_pid_alive(tunnel.pid):
                tunnel.mark_dead('PID validation failed')

        # Update last_seen
        tunnel.update_last_seen()

        return tunnel

    def kill_tunnel(self, id: str) -> bool:
        """Terminate tunnel and cleanup resources.

        Args:
            id: Tunnel UUID

        Returns:
            True if tunnel was killed, False if not found or already dead

        Example:
            >>> if manager.kill_tunnel(tunnel_id):
            ...     print("Tunnel terminated successfully")
            ... else:
            ...     print("Tunnel not found or already dead")
        """
        tunnel = self.get_tunnel(id)

        if not tunnel:
            return False

        if tunnel.status == 'dead':
            return False

        # Kill process if PID exists
        if tunnel.pid:
            try:
                if self._is_pid_alive(tunnel.pid):
                    os.kill(tunnel.pid, signal.SIGTERM)

                    # Give process time to terminate gracefully
                    import time
                    time.sleep(0.5)

                    # Force kill if still alive
                    if self._is_pid_alive(tunnel.pid):
                        os.kill(tunnel.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError) as e:
                print(f"Warning: Failed to kill PID {tunnel.pid}: {e}")

        # Mark tunnel as dead
        with self._lock:
            tunnel.mark_dead('Manual termination')

        return True

    def cleanup_dead_tunnels(self, session_id: str = None) -> int:
        """Remove dead/stale tunnels from tracking.

        Scans all tunnels and marks those with dead PIDs as 'dead'.

        Args:
            session_id: Optional session ID to cleanup (None = all sessions)

        Returns:
            Number of tunnels cleaned up

        Example:
            >>> # Cleanup all dead tunnels
            >>> removed = manager.cleanup_dead_tunnels()
            >>> print(f"Cleaned up {removed} dead tunnels")
            >>>
            >>> # Cleanup tunnels for specific session
            >>> removed = manager.cleanup_dead_tunnels(session_id='session-123')
        """
        cleaned = 0

        with self._lock:
            tunnels = list(self._tunnels.values())

        for tunnel in tunnels:
            # Filter by session_id if provided
            if session_id and tunnel.session_id != session_id:
                continue

            # Skip already dead tunnels
            if tunnel.status == 'dead':
                continue

            # Check if PID is alive
            if tunnel.pid and not self._is_pid_alive(tunnel.pid):
                tunnel.mark_dead('PID validation failed during cleanup')
                cleaned += 1

            # Check for stale tunnels (no activity for > 24 hours)
            elif tunnel.status in ['active', 'starting']:
                time_since_activity = datetime.now() - tunnel.last_seen
                if time_since_activity > timedelta(hours=24):
                    tunnel.mark_dead(f'No activity for {time_since_activity}')
                    cleaned += 1

        return cleaned

    def cleanup_session_tunnels(self, session_id: str) -> int:
        """Kill all tunnels for a session (called when session dies).

        Args:
            session_id: Session ID

        Returns:
            Number of tunnels killed

        Example:
            >>> # Cleanup when session dies
            >>> killed = manager.cleanup_session_tunnels('session-123')
            >>> print(f"Killed {killed} tunnels for dead session")
        """
        tunnels = self.list_tunnels(session_id=session_id)
        killed = 0

        for tunnel in tunnels:
            if tunnel.is_active():
                if self.kill_tunnel(tunnel.id):
                    killed += 1

        return killed

    def get_next_available_port(self, start: int = 8000, end: int = 9000) -> Optional[int]:
        """Find next available port in range.

        Args:
            start: Start port number
            end: End port number

        Returns:
            Available port number, or None if no ports available

        Example:
            >>> port = manager.get_next_available_port(start=8000)
            >>> print(f"Use port {port} for tunnel")
        """
        for port in range(start, end + 1):
            if self._is_port_available(port):
                return port
        return None

    def _is_port_available(self, port: int) -> bool:
        """Check if port is available (not in use).

        Args:
            port: Port number to check

        Returns:
            True if port is available, False if in use
        """
        try:
            # Try to bind to port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.bind(('127.0.0.1', port))
            sock.close()
            return True
        except OSError:
            return False

    def _is_pid_alive(self, pid: int) -> bool:
        """Check if process ID is alive.

        Args:
            pid: Process ID to check

        Returns:
            True if process exists, False otherwise
        """
        try:
            # Send signal 0 (null signal) to check if process exists
            os.kill(pid, 0)
            return True
        except (ProcessLookupError, PermissionError):
            return False

    def get_stats(self, session_id: str = None) -> Dict[str, Any]:
        """Get tunnel statistics.

        Args:
            session_id: Optional session ID filter

        Returns:
            Dictionary with tunnel counts and stats

        Example:
            >>> stats = manager.get_stats()
            >>> print(f"Active: {stats['active']}, Dead: {stats['dead']}")
            >>>
            >>> # Stats for specific session
            >>> stats = manager.get_stats(session_id='session-123')
        """
        tunnels = self.list_tunnels(session_id=session_id)

        stats = {
            'total': len(tunnels),
            'active': sum(1 for t in tunnels if t.status == 'active'),
            'dead': sum(1 for t in tunnels if t.status == 'dead'),
            'starting': sum(1 for t in tunnels if t.status == 'starting'),
            'error': sum(1 for t in tunnels if t.status == 'error'),
            'by_type': {}
        }

        # Count by type
        for tunnel in tunnels:
            stats['by_type'][tunnel.type] = stats['by_type'].get(tunnel.type, 0) + 1

        return stats
