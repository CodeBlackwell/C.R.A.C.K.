"""
Query builder for session filtering

Provides chainable filters for session queries
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Callable


class SessionQuery:
    """Chainable query builder for sessions

    Example:
        query = SessionQuery(storage)
        sessions = query.by_target("192.168.1.100") \\
                        .by_type("reverse_shell") \\
                        .active_only() \\
                        .sort_by('created_at', desc=True) \\
                        .execute()
    """

    def __init__(self, storage: Any):
        """Initialize query builder

        Args:
            storage: SessionStorage instance
        """
        self.storage = storage
        self._filters: List[Callable[[Dict[str, Any]], bool]] = []
        self._sort_key: Optional[str] = None
        self._sort_desc: bool = False
        self._limit: Optional[int] = None

    def by_target(self, target: str) -> 'SessionQuery':
        """Filter by target

        Args:
            target: Target IP or hostname

        Returns:
            Self for chaining
        """
        def filter_fn(session: Dict[str, Any]) -> bool:
            return session.get('target') == target

        self._filters.append(filter_fn)
        return self

    def by_type(self, session_type: str) -> 'SessionQuery':
        """Filter by session type

        Args:
            session_type: Session type (e.g., 'reverse_shell', 'bind_shell')

        Returns:
            Self for chaining
        """
        def filter_fn(session: Dict[str, Any]) -> bool:
            return session.get('type') == session_type

        self._filters.append(filter_fn)
        return self

    def by_status(self, status: str) -> 'SessionQuery':
        """Filter by session status

        Args:
            status: Session status (e.g., 'active', 'closed', 'upgraded')

        Returns:
            Self for chaining
        """
        def filter_fn(session: Dict[str, Any]) -> bool:
            return session.get('status') == status

        self._filters.append(filter_fn)
        return self

    def by_protocol(self, protocol: str) -> 'SessionQuery':
        """Filter by protocol

        Args:
            protocol: Protocol type (e.g., 'tcp', 'http', 'https')

        Returns:
            Self for chaining
        """
        def filter_fn(session: Dict[str, Any]) -> bool:
            return session.get('protocol') == protocol

        self._filters.append(filter_fn)
        return self

    def active_only(self) -> 'SessionQuery':
        """Filter for active sessions only

        Returns:
            Self for chaining
        """
        def filter_fn(session: Dict[str, Any]) -> bool:
            status = session.get('status', '').lower()
            return status in ['active', 'connected', 'established']

        self._filters.append(filter_fn)
        return self

    def upgraded_only(self) -> 'SessionQuery':
        """Filter for upgraded sessions only

        Returns:
            Self for chaining
        """
        def filter_fn(session: Dict[str, Any]) -> bool:
            return session.get('upgraded', False) is True

        self._filters.append(filter_fn)
        return self

    def in_last_hours(self, hours: int) -> 'SessionQuery':
        """Filter for sessions created in last N hours

        Args:
            hours: Number of hours

        Returns:
            Self for chaining
        """
        cutoff = datetime.now() - timedelta(hours=hours)

        def filter_fn(session: Dict[str, Any]) -> bool:
            created_at_str = session.get('created_at')
            if not created_at_str:
                return False

            try:
                created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
                # Make both timezone-naive for comparison
                if created_at.tzinfo is not None:
                    created_at = created_at.replace(tzinfo=None)
                return created_at >= cutoff
            except (ValueError, AttributeError):
                return False

        self._filters.append(filter_fn)
        return self

    def in_last_days(self, days: int) -> 'SessionQuery':
        """Filter for sessions created in last N days

        Args:
            days: Number of days

        Returns:
            Self for chaining
        """
        return self.in_last_hours(days * 24)

    def since(self, start_time: datetime) -> 'SessionQuery':
        """Filter for sessions created after start_time

        Args:
            start_time: Start datetime

        Returns:
            Self for chaining
        """
        def filter_fn(session: Dict[str, Any]) -> bool:
            created_at_str = session.get('created_at')
            if not created_at_str:
                return False

            try:
                created_at = datetime.fromisoformat(created_at_str.replace('Z', '+00:00'))
                # Make both timezone-naive for comparison
                if created_at.tzinfo is not None:
                    created_at = created_at.replace(tzinfo=None)
                if start_time.tzinfo is not None:
                    start_time_naive = start_time.replace(tzinfo=None)
                else:
                    start_time_naive = start_time
                return created_at >= start_time_naive
            except (ValueError, AttributeError):
                return False

        self._filters.append(filter_fn)
        return self

    def has_notes(self) -> 'SessionQuery':
        """Filter for sessions with notes

        Returns:
            Self for chaining
        """
        def filter_fn(session: Dict[str, Any]) -> bool:
            notes = session.get('notes', '')
            return bool(notes and notes.strip())

        self._filters.append(filter_fn)
        return self

    def custom_filter(self, filter_fn: Callable[[Dict[str, Any]], bool]) -> 'SessionQuery':
        """Add custom filter function

        Args:
            filter_fn: Function that takes session dict and returns bool

        Returns:
            Self for chaining
        """
        self._filters.append(filter_fn)
        return self

    def sort_by(self, key: str, desc: bool = False) -> 'SessionQuery':
        """Sort results by key

        Args:
            key: Key to sort by (e.g., 'created_at', 'last_seen')
            desc: Sort descending if True

        Returns:
            Self for chaining
        """
        self._sort_key = key
        self._sort_desc = desc
        return self

    def limit(self, count: int) -> 'SessionQuery':
        """Limit number of results

        Args:
            count: Maximum number of results

        Returns:
            Self for chaining
        """
        self._limit = count
        return self

    def execute(self) -> List[Dict[str, Any]]:
        """Execute query and return results

        Returns:
            List of matching session dictionaries
        """
        # Get all sessions
        sessions = self.storage.list_all_sessions()

        # Apply filters
        for filter_fn in self._filters:
            sessions = [s for s in sessions if filter_fn(s)]

        # Sort if requested
        if self._sort_key:
            sessions.sort(
                key=lambda s: s.get(self._sort_key, ''),
                reverse=self._sort_desc
            )

        # Limit if requested
        if self._limit is not None:
            sessions = sessions[:self._limit]

        return sessions

    def count(self) -> int:
        """Count matching sessions without returning them

        Returns:
            Number of matching sessions
        """
        return len(self.execute())

    def first(self) -> Optional[Dict[str, Any]]:
        """Get first matching session

        Returns:
            First matching session or None
        """
        results = self.limit(1).execute()
        return results[0] if results else None

    def exists(self) -> bool:
        """Check if any sessions match

        Returns:
            True if at least one session matches
        """
        return self.count() > 0

    def reset(self) -> 'SessionQuery':
        """Reset all filters

        Returns:
            Self for chaining
        """
        self._filters = []
        self._sort_key = None
        self._sort_desc = False
        self._limit = None
        return self


# Convenience functions for common queries

def find_active_sessions(storage: Any, target: Optional[str] = None) -> List[Dict[str, Any]]:
    """Find all active sessions, optionally for a specific target

    Args:
        storage: SessionStorage instance
        target: Optional target to filter by

    Returns:
        List of active sessions
    """
    query = SessionQuery(storage).active_only()

    if target:
        query = query.by_target(target)

    return query.execute()


def find_recent_sessions(storage: Any, hours: int = 24) -> List[Dict[str, Any]]:
    """Find sessions created in last N hours

    Args:
        storage: SessionStorage instance
        hours: Number of hours to look back

    Returns:
        List of recent sessions
    """
    return SessionQuery(storage).in_last_hours(hours).execute()


def find_upgraded_sessions(storage: Any, target: Optional[str] = None) -> List[Dict[str, Any]]:
    """Find upgraded sessions

    Args:
        storage: SessionStorage instance
        target: Optional target to filter by

    Returns:
        List of upgraded sessions
    """
    query = SessionQuery(storage).upgraded_only()

    if target:
        query = query.by_target(target)

    return query.execute()
