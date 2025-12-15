"""
Core SessionManager implementation for reverse shell management.

Orchestrates session lifecycle:
- Creates and tracks sessions
- Manages session status (active/dead/upgrading)
- Validates PIDs and cleans up dead sessions
- Emits lifecycle events (SESSION_STARTED, SESSION_DIED)
- Thread-safe operations for concurrent access

Usage:
    >>> from sessions.manager import SessionManager
    >>> from sessions.storage.base import SessionStorage
    >>> from sessions.config import SessionConfig
    >>>
    >>> storage = SessionStorage()
    >>> config = SessionConfig()
    >>> manager = SessionManager(storage, config)
    >>>
    >>> # Create session
    >>> session = manager.create_session(
    ...     type='tcp',
    ...     target='192.168.45.150',
    ...     port=4444,
    ...     protocol='reverse'
    ... )
    >>>
    >>> # List active sessions
    >>> active = manager.list_sessions({'status': 'active'})
    >>>
    >>> # Kill session
    >>> manager.kill_session(session.id)
"""

import os
import signal
import threading
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta

from .models import Session, ShellCapabilities
from .storage.base import SessionStorage
from .config import SessionConfig
from .events import EventBus, SessionEvent
from .interfaces import ISessionManager


class SessionManager(ISessionManager):
    """Main session orchestrator - manages all session types.

    Features:
    - Create/track/kill sessions (TCP, HTTP, DNS, ICMP)
    - PID validation and dead session cleanup
    - Event emission for session lifecycle
    - Thread-safe operations
    - Persistent storage integration

    Thread Safety:
        All session operations are protected by a lock to ensure
        safe concurrent access from multiple listeners and threads.

    Example:
        >>> storage = SessionStorage()
        >>> config = SessionConfig()
        >>> manager = SessionManager(storage, config)
        >>>
        >>> # Create TCP reverse shell session
        >>> session = manager.create_session(
        ...     type='tcp',
        ...     target='192.168.45.150',
        ...     port=4444,
        ...     protocol='reverse',
        ...     shell_type='bash',
        ...     metadata={'listener_id': 'listener-123'}
        ... )
        >>>
        >>> # Get session by ID
        >>> session = manager.get_session(session.id)
        >>> print(f"Session status: {session.status}")
        >>>
        >>> # List active sessions
        >>> active_sessions = manager.list_sessions({'status': 'active'})
        >>>
        >>> # Kill session
        >>> if manager.kill_session(session.id):
        ...     print("Session terminated")
        >>>
        >>> # Cleanup dead sessions
        >>> removed = manager.cleanup_dead_sessions()
        >>> print(f"Cleaned up {removed} dead sessions")
    """

    def __init__(self, storage: SessionStorage, config: SessionConfig):
        """Initialize session manager.

        Args:
            storage: SessionStorage instance for persistence
            config: SessionConfig for default values and settings
        """
        self.storage = storage
        self.config = config
        self._sessions: Dict[str, Session] = {}
        self._lock = threading.Lock()

        # Load existing sessions from storage
        self._load_sessions()

    def _load_sessions(self):
        """Load sessions from persistent storage into memory."""
        try:
            stored_sessions = self.storage.list_all_sessions()

            for session_data in stored_sessions:
                try:
                    session = Session.from_dict(session_data)
                    self._sessions[session.id] = session

                    # Validate if session is still active (check PID if exists)
                    if session.status in ['active', 'upgrading']:
                        if session.pid and not self._is_pid_alive(session.pid):
                            session.mark_dead()
                            self.storage.save_session(session)

                except Exception as e:
                    print(f"Warning: Failed to load session: {e}")
                    continue

        except Exception as e:
            print(f"Warning: Failed to load sessions from storage: {e}")

    def create_session(self, type: str, target: str, port: Optional[int] = None, **kwargs) -> Session:
        """Create and register a new session.

        Args:
            type: Connection type ('tcp', 'http', 'dns', 'icmp')
            target: Target IP or hostname
            port: Connection port
            **kwargs: Additional properties:
                - protocol: 'reverse', 'bind', 'beacon' (default: 'reverse')
                - shell_type: 'bash', 'sh', 'powershell', 'cmd', etc.
                - pid: Process ID (if applicable)
                - metadata: Dict with custom fields
                - capabilities: ShellCapabilities instance

        Returns:
            Newly created Session instance

        Raises:
            ValueError: If invalid parameters provided

        Example:
            >>> session = manager.create_session(
            ...     type='tcp',
            ...     target='192.168.45.150',
            ...     port=4444,
            ...     protocol='reverse',
            ...     shell_type='bash',
            ...     metadata={'listener_id': 'listener-abc123'}
            ... )
            >>> print(f"Created session {session.id[:8]}")
        """
        # Validate required fields
        if not target:
            raise ValueError("Target is required")

        # Port validation: ICMP and DNS don't use ports (allow None)
        if type in ['icmp', 'dns']:
            port = None  # Normalize to None for portless protocols
        elif not port or port <= 0:
            raise ValueError(f"Valid port is required for {type} sessions")

        if type not in ['tcp', 'http', 'https', 'dns', 'icmp']:
            raise ValueError(f"Invalid session type: {type}")

        # Extract optional parameters
        protocol = kwargs.get('protocol', 'reverse')
        shell_type = kwargs.get('shell_type')
        pid = kwargs.get('pid')
        metadata = kwargs.get('metadata', {})
        capabilities = kwargs.get('capabilities', ShellCapabilities())

        # Create session instance
        session = Session(
            type=type,
            protocol=protocol,
            target=target,
            port=port,
            status='active',
            pid=pid,
            shell_type=shell_type,
            capabilities=capabilities,
            metadata=metadata,
            created_at=datetime.now(),
            last_seen=datetime.now()
        )

        # Store in memory and persist
        with self._lock:
            self._sessions[session.id] = session

        try:
            self.storage.save_session(session)
        except Exception as e:
            # Rollback in-memory state on storage failure
            with self._lock:
                del self._sessions[session.id]
            raise RuntimeError(f"Failed to persist session: {e}")

        # Emit SESSION_STARTED event
        EventBus.publish(SessionEvent.SESSION_STARTED, {
            'session_id': session.id,
            'type': session.type,
            'protocol': session.protocol,
            'target': session.target,
            'port': session.port,
            'shell_type': session.shell_type
        })

        return session

    def list_sessions(self, filters: Dict[str, Any] = None) -> List[Session]:
        """List sessions with optional filtering.

        Args:
            filters: Filter criteria:
                - status: 'active', 'dead', 'sleeping', 'upgrading'
                - type: 'tcp', 'http', 'dns', 'icmp'
                - protocol: 'reverse', 'bind', 'beacon'
                - target: Target IP/hostname
                - port: Port number
                - active_only: Boolean (shortcut for status='active')

        Returns:
            List of Session instances matching filters

        Example:
            >>> # Get all active TCP sessions
            >>> tcp_active = manager.list_sessions({
            ...     'type': 'tcp',
            ...     'status': 'active'
            ... })
            >>>
            >>> # Get all sessions to specific target
            >>> target_sessions = manager.list_sessions({
            ...     'target': '192.168.45.150'
            ... })
            >>>
            >>> # Get all active sessions (any type)
            >>> active = manager.list_sessions({'active_only': True})
        """
        filters = filters or {}

        with self._lock:
            sessions = list(self._sessions.values())

        # Apply filters
        results = []
        for session in sessions:
            match = True

            # Active only filter (shortcut)
            if filters.get('active_only'):
                if not session.is_active():
                    match = False

            # Status filter
            if 'status' in filters:
                if session.status != filters['status']:
                    match = False

            # Type filter
            if 'type' in filters:
                if session.type != filters['type']:
                    match = False

            # Protocol filter
            if 'protocol' in filters:
                if session.protocol != filters['protocol']:
                    match = False

            # Target filter
            if 'target' in filters:
                if session.target != filters['target']:
                    match = False

            # Port filter
            if 'port' in filters:
                if session.port != filters['port']:
                    match = False

            if match:
                results.append(session)

        # Sort by created_at (most recent first)
        results.sort(key=lambda s: s.created_at, reverse=True)

        return results

    def get_session(self, id: str) -> Optional[Session]:
        """Retrieve session by ID.

        Validates PID and updates last_seen timestamp.

        Args:
            id: Session UUID (full or partial - matches prefix)

        Returns:
            Session instance if found, None otherwise

        Example:
            >>> # Full UUID
            >>> session = manager.get_session('a1b2c3d4-1234-5678-90ab-cdef12345678')
            >>>
            >>> # Partial UUID (prefix match)
            >>> session = manager.get_session('a1b2c3d4')
            >>>
            >>> if session and session.is_active():
            ...     print(f"Session to {session.target}:{session.port} is active")
        """
        with self._lock:
            # Try exact match first
            if id in self._sessions:
                session = self._sessions[id]
            else:
                # Try prefix match (allows short IDs)
                matches = [s for sid, s in self._sessions.items() if sid.startswith(id)]
                if len(matches) == 1:
                    session = matches[0]
                elif len(matches) > 1:
                    print(f"Warning: Multiple sessions match '{id}' - using exact match only")
                    return None
                else:
                    return None

        # Validate PID if session is marked active
        if session.status in ['active', 'upgrading']:
            if session.pid and not self._is_pid_alive(session.pid):
                session.mark_dead()
                self.storage.save_session(session)
                EventBus.publish(SessionEvent.SESSION_DIED, {
                    'session_id': session.id,
                    'reason': 'PID validation failed'
                })

        # Update last_seen
        session.update_last_seen()
        self.storage.save_session(session)

        return session

    def update_session(self, id: str, updates: Dict[str, Any]) -> Session:
        """Update session properties.

        Args:
            id: Session UUID
            updates: Dictionary of fields to update:
                - status: New status
                - shell_type: Detected shell type
                - capabilities: ShellCapabilities dict or instance
                - metadata: Metadata updates (merged with existing)
                - pid: Process ID

        Returns:
            Updated Session instance

        Raises:
            ValueError: If session not found

        Example:
            >>> # Update shell type after detection
            >>> manager.update_session(session_id, {
            ...     'shell_type': 'bash',
            ...     'capabilities': ShellCapabilities(
            ...         has_pty=True,
            ...         shell_type='bash',
            ...         detected_tools=['python3', 'socat']
            ...     ).to_dict()
            ... })
            >>>
            >>> # Mark session as upgrading
            >>> manager.update_session(session_id, {'status': 'upgrading'})
        """
        session = self.get_session(id)

        if not session:
            raise ValueError(f"Session not found: {id}")

        old_status = session.status

        # Apply updates
        with self._lock:
            if 'status' in updates:
                session.status = updates['status']

            if 'shell_type' in updates:
                session.shell_type = updates['shell_type']

            if 'pid' in updates:
                session.pid = updates['pid']

            if 'capabilities' in updates:
                caps_data = updates['capabilities']
                if isinstance(caps_data, dict):
                    session.capabilities = ShellCapabilities.from_dict(caps_data)
                elif isinstance(caps_data, ShellCapabilities):
                    session.capabilities = caps_data

            if 'metadata' in updates:
                # Merge metadata (don't replace)
                session.metadata.update(updates['metadata'])

            session.update_last_seen()

        # Persist changes
        self.storage.save_session(session)

        # Emit events if status changed
        if old_status != session.status:
            if session.status == 'dead':
                EventBus.publish(SessionEvent.SESSION_DIED, {
                    'session_id': session.id,
                    'reason': 'Manual status update'
                })
            elif session.status == 'active' and old_status == 'upgrading':
                EventBus.publish(SessionEvent.SESSION_UPGRADED, {
                    'session_id': session.id,
                    'capabilities': session.capabilities.to_dict()
                })

        return session

    def kill_session(self, id: str) -> bool:
        """Terminate session and cleanup resources.

        Args:
            id: Session UUID

        Returns:
            True if session was killed, False if not found or already dead

        Example:
            >>> if manager.kill_session(session_id):
            ...     print("Session terminated successfully")
            ... else:
            ...     print("Session not found or already dead")
        """
        session = self.get_session(id)

        if not session:
            return False

        if session.status == 'dead':
            return False

        # Kill process if PID exists
        if session.pid:
            try:
                if self._is_pid_alive(session.pid):
                    os.kill(session.pid, signal.SIGTERM)

                    # Give process time to terminate gracefully
                    import time
                    time.sleep(0.5)

                    # Force kill if still alive
                    if self._is_pid_alive(session.pid):
                        os.kill(session.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError) as e:
                print(f"Warning: Failed to kill PID {session.pid}: {e}")

        # Mark session as dead
        with self._lock:
            session.mark_dead()

        self.storage.save_session(session)

        # Emit SESSION_DIED event
        EventBus.publish(SessionEvent.SESSION_DIED, {
            'session_id': session.id,
            'reason': 'Manual termination'
        })

        return True

    def cleanup_dead_sessions(self) -> int:
        """Remove dead/stale sessions from tracking.

        Scans all sessions and marks those with dead PIDs as 'dead'.
        Does not delete from storage (preserves history).

        Returns:
            Number of sessions cleaned up

        Example:
            >>> # Periodic cleanup (run from cron or background thread)
            >>> removed = manager.cleanup_dead_sessions()
            >>> if removed > 0:
            ...     print(f"Cleaned up {removed} dead sessions")
        """
        cleaned = 0

        with self._lock:
            sessions = list(self._sessions.values())

        for session in sessions:
            # Skip already dead sessions
            if session.status == 'dead':
                continue

            # Check if PID is alive
            if session.pid and not self._is_pid_alive(session.pid):
                session.mark_dead()
                self.storage.save_session(session)

                EventBus.publish(SessionEvent.SESSION_DIED, {
                    'session_id': session.id,
                    'reason': 'PID validation failed during cleanup'
                })

                cleaned += 1

            # Check for stale sessions (no activity for > 1 hour)
            elif session.status in ['active', 'upgrading']:
                time_since_activity = datetime.now() - session.last_seen
                if time_since_activity > timedelta(hours=1):
                    session.mark_dead()
                    self.storage.save_session(session)

                    EventBus.publish(SessionEvent.SESSION_DIED, {
                        'session_id': session.id,
                        'reason': f'No activity for {time_since_activity}'
                    })

                    cleaned += 1

        return cleaned

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

    def get_stats(self) -> Dict[str, Any]:
        """Get session statistics.

        Returns:
            Dictionary with session counts and stats

        Example:
            >>> stats = manager.get_stats()
            >>> print(f"Active: {stats['active']}, Dead: {stats['dead']}")
        """
        with self._lock:
            sessions = list(self._sessions.values())

        stats = {
            'total': len(sessions),
            'active': sum(1 for s in sessions if s.status == 'active'),
            'dead': sum(1 for s in sessions if s.status == 'dead'),
            'upgrading': sum(1 for s in sessions if s.status == 'upgrading'),
            'sleeping': sum(1 for s in sessions if s.status == 'sleeping'),
            'by_type': {},
            'by_protocol': {}
        }

        # Count by type
        for session in sessions:
            stats['by_type'][session.type] = stats['by_type'].get(session.type, 0) + 1
            stats['by_protocol'][session.protocol] = stats['by_protocol'].get(session.protocol, 0) + 1

        return stats
