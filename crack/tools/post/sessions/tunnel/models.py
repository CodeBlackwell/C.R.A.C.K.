"""
Tunnel models for pivoting and port forwarding.

Data structures:
- Tunnel: Base tunnel configuration and state
- TunnelConfig: Tunnel-specific configuration
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, Any, List, Optional
import uuid


@dataclass
class TunnelConfig:
    """Configuration for tunnel creation.

    Stores tunnel-specific parameters that vary by tunnel type.

    Attributes:
        local_port: Local port to bind (for SSH -L, chisel, socat)
        remote_host: Remote host to connect to (for SSH -L, socat)
        remote_port: Remote port to connect to (for SSH -L, -R, socat)
        socks_port: SOCKS proxy port (for SSH -D)
        reverse: Enable reverse mode (for chisel, SSH -R)
        server_port: Server port for chisel/relay
        tunnel_spec: Chisel tunnel specification
        extra_args: Additional command-line arguments

    Example:
        >>> # SSH local forward config
        >>> config = TunnelConfig(
        ...     local_port=3306,
        ...     remote_host='192.168.1.10',
        ...     remote_port=3306
        ... )
        >>>
        >>> # SSH SOCKS proxy config
        >>> config = TunnelConfig(socks_port=1080)
        >>>
        >>> # Chisel reverse tunnel config
        >>> config = TunnelConfig(
        ...     server_port=8000,
        ...     reverse=True,
        ...     tunnel_spec='R:8080:localhost:80'
        ... )
    """
    local_port: Optional[int] = None
    remote_host: Optional[str] = None
    remote_port: Optional[int] = None
    socks_port: Optional[int] = None
    reverse: bool = False
    server_port: Optional[int] = None
    tunnel_spec: Optional[str] = None
    extra_args: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary.

        Returns:
            Dictionary representation for JSON storage
        """
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TunnelConfig':
        """Deserialize from dictionary.

        Args:
            data: Dictionary with config data

        Returns:
            TunnelConfig instance
        """
        return cls(**data)


@dataclass
class Tunnel:
    """Represents an active tunnel (SSH, chisel, socat, etc.).

    Tracks the complete state of a tunnel including type, configuration,
    process details, and lifecycle information. Used by TunnelManager to
    manage multiple concurrent tunnels.

    Attributes:
        id: Unique tunnel identifier (UUID)
        type: Tunnel type ('ssh-local', 'ssh-remote', 'ssh-dynamic', 'chisel', 'socat', 'proxychains')
        session_id: Associated session ID (if any)
        target: Target host for tunnel
        config: Tunnel-specific configuration
        status: Current status ('active', 'dead', 'starting', 'error')
        pid: Process ID of tunnel process (if applicable)
        command: Full command used to start tunnel
        metadata: Additional custom fields
        created_at: Tunnel creation timestamp
        last_seen: Last activity timestamp
        error_message: Error message if status='error'

    Example:
        >>> tunnel = Tunnel(
        ...     id=str(uuid.uuid4()),
        ...     type='ssh-local',
        ...     session_id='session-abc123',
        ...     target='192.168.45.150',
        ...     config=TunnelConfig(
        ...         local_port=3306,
        ...         remote_host='192.168.1.10',
        ...         remote_port=3306
        ...     ),
        ...     status='active',
        ...     pid=12345,
        ...     command='ssh -N -L 3306:192.168.1.10:3306 user@192.168.45.150'
        ... )
        >>> tunnel.is_active()
        True
        >>> tunnel.get_connection_string()
        'localhost:3306 -> 192.168.1.10:3306'
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: str = 'ssh-local'  # ssh-local, ssh-remote, ssh-dynamic, chisel, socat, proxychains
    session_id: Optional[str] = None
    target: str = ''
    config: TunnelConfig = field(default_factory=TunnelConfig)
    status: str = 'starting'  # starting, active, dead, error
    pid: Optional[int] = None
    command: str = ''
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    error_message: Optional[str] = None

    def is_active(self) -> bool:
        """Check if tunnel is currently active.

        Returns:
            True if status is 'active' or 'starting'
        """
        return self.status in ['active', 'starting']

    def update_last_seen(self):
        """Update last_seen timestamp to current time.

        Should be called whenever activity is detected on the tunnel.
        """
        self.last_seen = datetime.now()

    def mark_dead(self, reason: str = None):
        """Mark tunnel as dead (connection lost).

        Args:
            reason: Optional reason for tunnel death
        """
        self.status = 'dead'
        if reason:
            self.error_message = reason
        self.update_last_seen()

    def mark_active(self):
        """Mark tunnel as active."""
        self.status = 'active'
        self.error_message = None
        self.update_last_seen()

    def mark_error(self, error_message: str):
        """Mark tunnel as failed with error.

        Args:
            error_message: Error description
        """
        self.status = 'error'
        self.error_message = error_message
        self.update_last_seen()

    def get_connection_string(self) -> str:
        """Get human-readable connection string.

        Returns:
            Connection description (e.g., "localhost:3306 -> 192.168.1.10:3306")

        Example:
            >>> tunnel = Tunnel(
            ...     type='ssh-local',
            ...     config=TunnelConfig(local_port=3306, remote_host='192.168.1.10', remote_port=3306)
            ... )
            >>> tunnel.get_connection_string()
            'localhost:3306 -> 192.168.1.10:3306'
        """
        if self.type == 'ssh-local':
            return f"localhost:{self.config.local_port} -> {self.config.remote_host}:{self.config.remote_port}"
        elif self.type == 'ssh-remote':
            return f"{self.target}:{self.config.remote_port} -> localhost:{self.config.local_port}"
        elif self.type == 'ssh-dynamic':
            return f"SOCKS proxy localhost:{self.config.socks_port}"
        elif self.type == 'chisel':
            return f"chisel {self.config.tunnel_spec}"
        elif self.type == 'socat':
            return f"localhost:{self.config.local_port} -> {self.config.remote_host}:{self.config.remote_port}"
        elif self.type == 'proxychains':
            return f"proxychains config (SOCKS {self.target}:{self.config.socks_port})"
        else:
            return f"{self.type} tunnel"

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for JSON storage.

        Returns:
            Dictionary representation with ISO format timestamps
        """
        return {
            'id': self.id,
            'type': self.type,
            'session_id': self.session_id,
            'target': self.target,
            'config': self.config.to_dict(),
            'status': self.status,
            'pid': self.pid,
            'command': self.command,
            'metadata': self.metadata,
            'created_at': self.created_at.isoformat(),
            'last_seen': self.last_seen.isoformat(),
            'error_message': self.error_message
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Tunnel':
        """Deserialize from dictionary.

        Args:
            data: Dictionary with tunnel data

        Returns:
            Tunnel instance with restored state
        """
        # Parse datetime fields
        data = data.copy()
        if isinstance(data.get('created_at'), str):
            data['created_at'] = datetime.fromisoformat(data['created_at'])
        if isinstance(data.get('last_seen'), str):
            data['last_seen'] = datetime.fromisoformat(data['last_seen'])

        # Parse config
        if 'config' in data and isinstance(data['config'], dict):
            data['config'] = TunnelConfig.from_dict(data['config'])

        return cls(**data)

    def __repr__(self):
        return f"<Tunnel id={self.id[:8]} type={self.type} status={self.status} connection={self.get_connection_string()}>"
