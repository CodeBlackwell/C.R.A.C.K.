"""
Abstract interfaces for session management components.

Defines contracts for:
- SessionManager: Core session lifecycle management
- IListener: Listener process abstraction
- IStorage: Session persistence layer
- IShellEnhancer: Shell upgrade and stabilization
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Callable
from .models import Session, Listener, ShellCapabilities


class ISessionManager(ABC):
    """Abstract interface for session lifecycle management.

    Implementations handle creation, tracking, and cleanup of reverse shell
    sessions. The manager coordinates between listeners, storage, and
    shell enhancement operations.

    Example:
        >>> class ConcreteSessionManager(ISessionManager):
        ...     def create_session(self, type, target, port, **kwargs):
        ...         session = Session(type=type, target=target, port=port, **kwargs)
        ...         self._storage.save_session(session)
        ...         return session
        ...
        >>> manager = ConcreteSessionManager()
        >>> session = manager.create_session('tcp', '192.168.45.150', 4444)
        >>> sessions = manager.list_sessions({'status': 'active'})
    """

    @abstractmethod
    def create_session(self, type: str, target: str, port: int, **kwargs) -> Session:
        """Create and register a new session.

        Args:
            type: Connection type ('tcp', 'http', 'dns', 'icmp')
            target: Target IP or hostname
            port: Connection port
            **kwargs: Additional session properties (protocol, shell_type, metadata, etc.)

        Returns:
            Newly created Session instance

        Raises:
            ValueError: If invalid parameters provided
            StorageError: If unable to persist session

        Example:
            >>> session = manager.create_session(
            ...     type='tcp',
            ...     target='192.168.45.150',
            ...     port=4444,
            ...     protocol='reverse',
            ...     shell_type='bash',
            ...     metadata={'listener_id': 'abc123'}
            ... )
        """
        pass

    @abstractmethod
    def list_sessions(self, filters: Dict[str, Any] = None) -> List[Session]:
        """List sessions with optional filtering.

        Args:
            filters: Filter criteria as dict (e.g., {'status': 'active', 'type': 'tcp'})
                    If None or empty, returns all sessions.
                    Supported filters: status, type, protocol, target, port

        Returns:
            List of Session instances matching filters

        Example:
            >>> # Get all active sessions
            >>> active = manager.list_sessions({'status': 'active'})
            >>> # Get all TCP reverse shells
            >>> tcp_rev = manager.list_sessions({'type': 'tcp', 'protocol': 'reverse'})
            >>> # Get all sessions to specific target
            >>> target_sessions = manager.list_sessions({'target': '192.168.45.150'})
        """
        pass

    @abstractmethod
    def get_session(self, id: str) -> Optional[Session]:
        """Retrieve session by ID.

        Args:
            id: Session UUID

        Returns:
            Session instance if found, None otherwise

        Example:
            >>> session = manager.get_session('a1b2c3d4-1234-5678-90ab-cdef12345678')
            >>> if session and session.is_active():
            ...     print(f"Session to {session.target} is active")
        """
        pass

    @abstractmethod
    def update_session(self, id: str, updates: Dict[str, Any]) -> Session:
        """Update session properties.

        Args:
            id: Session UUID
            updates: Dictionary of fields to update (e.g., {'status': 'dead', 'shell_type': 'bash'})

        Returns:
            Updated Session instance

        Raises:
            ValueError: If session not found
            StorageError: If unable to persist updates

        Example:
            >>> # Mark session as dead
            >>> manager.update_session(session_id, {'status': 'dead'})
            >>> # Update detected shell type
            >>> manager.update_session(session_id, {
            ...     'shell_type': 'bash',
            ...     'capabilities': new_capabilities.to_dict()
            ... })
        """
        pass

    @abstractmethod
    def kill_session(self, id: str) -> bool:
        """Terminate session and cleanup resources.

        Args:
            id: Session UUID

        Returns:
            True if session was killed, False if not found or already dead

        Raises:
            RuntimeError: If unable to terminate session process

        Example:
            >>> if manager.kill_session(session_id):
            ...     print("Session terminated")
            ... else:
            ...     print("Session not found or already dead")
        """
        pass

    @abstractmethod
    def cleanup_dead_sessions(self) -> int:
        """Remove dead/stale sessions from tracking.

        Scans all sessions and removes those marked as 'dead' or inactive
        beyond timeout threshold. Useful for periodic cleanup.

        Returns:
            Number of sessions cleaned up

        Example:
            >>> removed = manager.cleanup_dead_sessions()
            >>> print(f"Cleaned up {removed} dead sessions")
        """
        pass


class IListener(ABC):
    """Abstract interface for listener implementations.

    Implementations wrap specific listener tools (netcat, metasploit, custom
    servers) and provide unified control interface. Listeners emit events
    on connection/disconnection.

    Example:
        >>> class NetcatListener(IListener):
        ...     def start(self):
        ...         self.process = subprocess.Popen(['nc', '-nlvp', str(self.port)])
        ...         return True
        ...
        >>> listener = NetcatListener(port=4444)
        >>> listener.on_connection(lambda session_id: print(f"Session: {session_id}"))
        >>> listener.start()
    """

    @abstractmethod
    def start(self) -> bool:
        """Start the listener process.

        Returns:
            True if started successfully, False otherwise

        Raises:
            RuntimeError: If listener fails to start
            PortInUseError: If port already in use

        Example:
            >>> listener = NetcatListener(port=4444)
            >>> if listener.start():
            ...     print(f"Listening on port {listener.port}")
        """
        pass

    @abstractmethod
    def stop(self) -> bool:
        """Stop the listener process.

        Returns:
            True if stopped successfully, False if not running

        Raises:
            RuntimeError: If unable to terminate process

        Example:
            >>> if listener.stop():
            ...     print("Listener stopped")
        """
        pass

    @abstractmethod
    def restart(self) -> bool:
        """Restart the listener (stop + start).

        Returns:
            True if restarted successfully

        Example:
            >>> if listener.restart():
            ...     print("Listener restarted")
        """
        pass

    @abstractmethod
    def status(self) -> str:
        """Get current listener status.

        Returns:
            Status string ('running', 'stopped', 'crashed')

        Example:
            >>> if listener.status() == 'running':
            ...     print(f"Listener has {len(listener.get_active_sessions())} sessions")
        """
        pass

    @abstractmethod
    def on_connection(self, callback: Callable[[str], None]) -> None:
        """Register callback for new connections.

        Args:
            callback: Function to call with session_id when connection received

        Example:
            >>> def handle_connection(session_id):
            ...     print(f"New session: {session_id}")
            ...     session = manager.get_session(session_id)
            ...     enhancer.upgrade_shell(session, 'python-pty')
            ...
            >>> listener.on_connection(handle_connection)
        """
        pass

    @abstractmethod
    def get_active_sessions(self) -> List[str]:
        """Get list of active session IDs connected to this listener.

        Returns:
            List of session UUID strings

        Example:
            >>> session_ids = listener.get_active_sessions()
            >>> for sid in session_ids:
            ...     session = manager.get_session(sid)
            ...     print(f"{session.target}:{session.port}")
        """
        pass


class IStorage(ABC):
    """Abstract interface for session persistence.

    Implementations handle serialization/deserialization of sessions and
    listeners to persistent storage (JSON files, databases, etc.).

    Example:
        >>> class JSONStorage(IStorage):
        ...     def save_session(self, session):
        ...         path = Path(f"~/.crack/sessions/{session.id}.json")
        ...         path.write_text(json.dumps(session.to_dict()))
        ...         return True
        ...
        >>> storage = JSONStorage()
        >>> storage.save_session(session)
    """

    @abstractmethod
    def save_session(self, session: Session) -> bool:
        """Persist session to storage.

        Args:
            session: Session instance to save

        Returns:
            True if saved successfully

        Raises:
            StorageError: If unable to write to storage

        Example:
            >>> session = Session(type='tcp', target='192.168.45.150', port=4444)
            >>> storage.save_session(session)
        """
        pass

    @abstractmethod
    def load_session(self, id: str) -> Optional[Session]:
        """Load session from storage.

        Args:
            id: Session UUID

        Returns:
            Session instance if found, None otherwise

        Example:
            >>> session = storage.load_session('a1b2c3d4-...')
            >>> if session:
            ...     print(f"Loaded session to {session.target}")
        """
        pass

    @abstractmethod
    def delete_session(self, id: str) -> bool:
        """Delete session from storage.

        Args:
            id: Session UUID

        Returns:
            True if deleted, False if not found

        Example:
            >>> if storage.delete_session(session_id):
            ...     print("Session removed from storage")
        """
        pass

    @abstractmethod
    def query_sessions(self, filters: Dict[str, Any] = None) -> List[Session]:
        """Query sessions with optional filters.

        Args:
            filters: Filter criteria (e.g., {'status': 'active', 'type': 'tcp'})

        Returns:
            List of matching Session instances

        Example:
            >>> active_sessions = storage.query_sessions({'status': 'active'})
            >>> tcp_sessions = storage.query_sessions({'type': 'tcp'})
        """
        pass

    @abstractmethod
    def save_listener(self, listener: Listener) -> bool:
        """Persist listener to storage.

        Args:
            listener: Listener instance to save

        Returns:
            True if saved successfully

        Raises:
            StorageError: If unable to write to storage

        Example:
            >>> listener = Listener(protocol='tcp', port=4444)
            >>> storage.save_listener(listener)
        """
        pass

    @abstractmethod
    def load_listener(self, id: str) -> Optional[Listener]:
        """Load listener from storage.

        Args:
            id: Listener UUID

        Returns:
            Listener instance if found, None otherwise

        Example:
            >>> listener = storage.load_listener('abc123...')
            >>> if listener and listener.is_running():
            ...     print(f"Listener on port {listener.port} is running")
        """
        pass


class IShellEnhancer(ABC):
    """Abstract interface for shell upgrade and stabilization.

    Implementations detect shell capabilities and apply upgrade techniques
    (Python PTY, socat, script, stty, PowerShell console tweaks, etc.).

    Example:
        >>> class ShellEnhancer(IShellEnhancer):
        ...     def detect_capabilities(self, session):
        ...         # Test for python, socat, etc.
        ...         return ShellCapabilities(has_pty=False, detected_tools=['python3'])
        ...
        >>> enhancer = ShellEnhancer()
        >>> caps = enhancer.detect_capabilities(session)
        >>> if 'python3' in caps.detected_tools and not caps.has_pty:
        ...     enhancer.upgrade_shell(session, 'python-pty')
    """

    @abstractmethod
    def detect_capabilities(self, session: Session) -> ShellCapabilities:
        """Detect shell capabilities and available tools.

        Probes the session to determine:
        - Shell type (bash, sh, powershell, cmd)
        - PTY status
        - Available tools (python, socat, script, stty, etc.)
        - OS type (linux, windows, macos)

        Args:
            session: Session to probe

        Returns:
            ShellCapabilities instance with detected features

        Raises:
            RuntimeError: If unable to communicate with session

        Example:
            >>> caps = enhancer.detect_capabilities(session)
            >>> print(f"Shell: {caps.shell_type}")
            >>> print(f"Tools: {', '.join(caps.detected_tools)}")
            >>> if caps.has_pty:
            ...     print("PTY already available")
        """
        pass

    @abstractmethod
    def upgrade_shell(self, session: Session, method: str) -> bool:
        """Upgrade shell using specified method.

        Applies upgrade technique to get interactive PTY or enhanced shell.
        Common methods:
        - 'python-pty': python -c 'import pty; pty.spawn("/bin/bash")'
        - 'script': script /dev/null -c bash
        - 'socat': Socat binary upload + execution
        - 'powershell': PowerShell console enhancements

        Args:
            session: Session to upgrade
            method: Upgrade method name

        Returns:
            True if upgrade successful

        Raises:
            ValueError: If method not supported or requirements not met
            RuntimeError: If upgrade command fails

        Example:
            >>> caps = enhancer.detect_capabilities(session)
            >>> if 'python3' in caps.detected_tools:
            ...     if enhancer.upgrade_shell(session, 'python-pty'):
            ...         print("Shell upgraded with Python PTY")
        """
        pass

    @abstractmethod
    def stabilize_shell(self, session: Session) -> bool:
        """Apply stabilization techniques (stty, terminal size, etc.).

        After PTY upgrade, stabilizes the shell by:
        - Backgrounding shell (Ctrl+Z)
        - Disabling terminal echo (stty raw -echo)
        - Foregrounding shell (fg)
        - Setting terminal type (export TERM=xterm)
        - Configuring terminal size (stty rows X cols Y)

        Args:
            session: Session to stabilize

        Returns:
            True if stabilization successful

        Raises:
            RuntimeError: If stabilization commands fail

        Example:
            >>> if enhancer.upgrade_shell(session, 'python-pty'):
            ...     if enhancer.stabilize_shell(session):
            ...         print("Shell fully stabilized - Ctrl+C safe!")
        """
        pass

    @abstractmethod
    def validate_upgrade(self, session: Session) -> bool:
        """Validate that upgrade was successful.

        Tests upgraded shell to confirm:
        - PTY is functional (can handle Ctrl+C)
        - Tab completion works
        - Command history works
        - Arrow keys work

        Args:
            session: Session to validate

        Returns:
            True if upgrade verified successful

        Example:
            >>> if enhancer.upgrade_shell(session, 'python-pty'):
            ...     if enhancer.validate_upgrade(session):
            ...         print("Upgrade verified successful")
            ...         # Update session capabilities
            ...         session.capabilities = enhancer.detect_capabilities(session)
        """
        pass
