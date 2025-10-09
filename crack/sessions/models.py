"""
Session and Listener models for reverse shell management.

Core data structures:
- Session: Represents an active reverse shell connection
- Listener: Represents a listener awaiting connections
- ShellCapabilities: Detected shell features and environment
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, Any, List, Optional
import uuid


@dataclass
class ShellCapabilities:
    """Detected capabilities and features of a shell session.

    Used to determine which upgrade/stabilization methods are available
    and to track the current state of the shell environment.

    Attributes:
        has_pty: Whether shell has pseudo-terminal (allows Ctrl+C, arrow keys, etc.)
        has_history: Whether command history is available (up/down arrows work)
        has_tab_completion: Whether tab completion works
        shell_type: Type of shell (bash, sh, powershell, cmd, etc.)
        detected_tools: Available tools on target (python, socat, script, stty, etc.)
        os_type: Operating system type (linux, windows, macos)

    Example:
        >>> caps = ShellCapabilities(
        ...     has_pty=True,
        ...     has_history=True,
        ...     has_tab_completion=True,
        ...     shell_type='bash',
        ...     detected_tools=['python3', 'socat', 'script'],
        ...     os_type='linux'
        ... )
        >>> if 'python3' in caps.detected_tools and not caps.has_pty:
        ...     # Python PTY upgrade available
        ...     pass
    """
    has_pty: bool = False
    has_history: bool = False
    has_tab_completion: bool = False
    shell_type: str = 'unknown'
    detected_tools: List[str] = field(default_factory=list)
    os_type: str = 'unknown'

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary.

        Returns:
            Dictionary representation for JSON storage
        """
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ShellCapabilities':
        """Deserialize from dictionary.

        Args:
            data: Dictionary with capability data

        Returns:
            ShellCapabilities instance
        """
        return cls(**data)


@dataclass
class Session:
    """Represents an active reverse shell or bind shell connection.

    Tracks the complete state of a shell session including connection details,
    capabilities, and lifecycle information. Used by SessionManager to manage
    multiple concurrent sessions.

    Attributes:
        id: Unique session identifier (UUID)
        type: Connection type ('tcp', 'http', 'dns', 'icmp')
        protocol: Connection direction ('reverse', 'bind', 'beacon')
        target: Target IP address or hostname
        port: Connection port number
        status: Current status ('active', 'dead', 'sleeping', 'upgrading')
        pid: Process ID of listener (if applicable)
        shell_type: Detected shell type ('bash', 'sh', 'powershell', 'cmd')
        capabilities: Detected shell capabilities and features
        metadata: Additional custom fields (listener_id, upgrade_method, etc.)
        created_at: Session creation timestamp
        last_seen: Last activity timestamp (for dead session detection)

    Example:
        >>> session = Session(
        ...     id=str(uuid.uuid4()),
        ...     type='tcp',
        ...     protocol='reverse',
        ...     target='192.168.45.150',
        ...     port=4444,
        ...     status='active',
        ...     shell_type='bash'
        ... )
        >>> session.is_active()
        True
        >>> session.capabilities.has_pty
        False
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    type: str = 'tcp'  # tcp, http, dns, icmp
    protocol: str = 'reverse'  # reverse, bind, beacon
    target: str = ''
    port: int = 0
    status: str = 'active'  # active, dead, sleeping, upgrading
    pid: Optional[int] = None
    shell_type: Optional[str] = None
    capabilities: ShellCapabilities = field(default_factory=ShellCapabilities)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)

    def is_active(self) -> bool:
        """Check if session is currently active.

        Returns:
            True if status is 'active' or 'upgrading'
        """
        return self.status in ['active', 'upgrading']

    def update_last_seen(self):
        """Update last_seen timestamp to current time.

        Should be called whenever activity is detected on the session.
        """
        self.last_seen = datetime.now()

    def mark_dead(self):
        """Mark session as dead (connection lost)."""
        self.status = 'dead'
        self.update_last_seen()

    def mark_upgrading(self):
        """Mark session as currently being upgraded."""
        self.status = 'upgrading'
        self.update_last_seen()

    def mark_active(self):
        """Mark session as active."""
        self.status = 'active'
        self.update_last_seen()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for JSON storage.

        Returns:
            Dictionary representation with ISO format timestamps
        """
        return {
            'id': self.id,
            'type': self.type,
            'protocol': self.protocol,
            'target': self.target,
            'port': self.port,
            'status': self.status,
            'pid': self.pid,
            'shell_type': self.shell_type,
            'capabilities': self.capabilities.to_dict(),
            'metadata': self.metadata,
            'created_at': self.created_at.isoformat(),
            'last_seen': self.last_seen.isoformat()
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Session':
        """Deserialize from dictionary.

        Args:
            data: Dictionary with session data

        Returns:
            Session instance with restored state
        """
        # Parse datetime fields
        data = data.copy()
        if isinstance(data.get('created_at'), str):
            data['created_at'] = datetime.fromisoformat(data['created_at'])
        if isinstance(data.get('last_seen'), str):
            data['last_seen'] = datetime.fromisoformat(data['last_seen'])

        # Parse capabilities
        if 'capabilities' in data and isinstance(data['capabilities'], dict):
            data['capabilities'] = ShellCapabilities.from_dict(data['capabilities'])

        return cls(**data)

    def __repr__(self):
        return f"<Session id={self.id[:8]} type={self.type} target={self.target}:{self.port} status={self.status}>"


@dataclass
class Listener:
    """Represents a listener process awaiting shell connections.

    Manages the state of a listener (netcat, metasploit, custom server, etc.)
    that accepts incoming reverse shells or serves bind shells. Can track
    multiple concurrent sessions per listener.

    Attributes:
        id: Unique listener identifier (UUID)
        protocol: Listener protocol ('tcp', 'http', 'https', 'dns', 'icmp')
        port: Listening port number
        status: Current status ('running', 'stopped', 'crashed')
        pid: Process ID of listener process
        session_ids: List of connected session IDs
        config: Listener-specific configuration (tool, command, options, etc.)
        started_at: Listener start timestamp
        stopped_at: Listener stop timestamp (if stopped)

    Example:
        >>> listener = Listener(
        ...     id=str(uuid.uuid4()),
        ...     protocol='tcp',
        ...     port=4444,
        ...     status='running',
        ...     pid=12345,
        ...     config={
        ...         'tool': 'netcat',
        ...         'command': 'nc -nlvp 4444',
        ...         'auto_upgrade': True
        ...     }
        ... )
        >>> listener.is_running()
        True
        >>> listener.add_session('session-123')
        >>> len(listener.session_ids)
        1
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    protocol: str = 'tcp'  # tcp, http, https, dns, icmp
    port: int = 0
    status: str = 'stopped'  # running, stopped, crashed
    pid: Optional[int] = None
    session_ids: List[str] = field(default_factory=list)
    config: Dict[str, Any] = field(default_factory=dict)
    started_at: Optional[datetime] = None
    stopped_at: Optional[datetime] = None

    def is_running(self) -> bool:
        """Check if listener is currently running.

        Returns:
            True if status is 'running'
        """
        return self.status == 'running'

    def start(self):
        """Mark listener as started."""
        self.status = 'running'
        self.started_at = datetime.now()
        self.stopped_at = None

    def stop(self):
        """Mark listener as stopped."""
        self.status = 'stopped'
        self.stopped_at = datetime.now()

    def crash(self):
        """Mark listener as crashed."""
        self.status = 'crashed'
        self.stopped_at = datetime.now()

    def add_session(self, session_id: str):
        """Add connected session ID.

        Args:
            session_id: Session ID to track
        """
        if session_id not in self.session_ids:
            self.session_ids.append(session_id)

    def remove_session(self, session_id: str):
        """Remove session ID (on disconnect).

        Args:
            session_id: Session ID to remove
        """
        if session_id in self.session_ids:
            self.session_ids.remove(session_id)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary for JSON storage.

        Returns:
            Dictionary representation with ISO format timestamps
        """
        return {
            'id': self.id,
            'protocol': self.protocol,
            'port': self.port,
            'status': self.status,
            'pid': self.pid,
            'session_ids': self.session_ids,
            'config': self.config,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'stopped_at': self.stopped_at.isoformat() if self.stopped_at else None
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Listener':
        """Deserialize from dictionary.

        Args:
            data: Dictionary with listener data

        Returns:
            Listener instance with restored state
        """
        # Parse datetime fields
        data = data.copy()
        if data.get('started_at') and isinstance(data['started_at'], str):
            data['started_at'] = datetime.fromisoformat(data['started_at'])
        if data.get('stopped_at') and isinstance(data['stopped_at'], str):
            data['stopped_at'] = datetime.fromisoformat(data['stopped_at'])

        return cls(**data)

    def __repr__(self):
        return f"<Listener id={self.id[:8]} protocol={self.protocol} port={self.port} status={self.status} sessions={len(self.session_ids)}>"
