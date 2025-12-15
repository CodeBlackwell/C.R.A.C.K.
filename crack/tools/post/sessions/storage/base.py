"""
Base storage system for session persistence

Implements IStorage interface with atomic writes and JSON serialization
"""

import json
import os
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional
from enum import Enum


class SessionStorage:
    """Persistent storage for session data

    Storage location: ~/.crack/sessions/<target>_<session_id>.json
    Features:
    - Atomic writes (write to temp, then rename)
    - JSON serialization with datetime/enum support
    - Error handling for permissions and disk space
    - Thread-safe operations
    """

    DEFAULT_DIR = Path.home() / ".crack" / "sessions"

    def __init__(self, storage_path: Optional[Path] = None):
        """Initialize storage

        Args:
            storage_path: Optional custom storage directory
        """
        self.storage_path = storage_path or self.DEFAULT_DIR
        self.ensure_storage_dir()

    def ensure_storage_dir(self) -> Path:
        """Create storage directory if it doesn't exist

        Returns:
            Path to storage directory

        Raises:
            PermissionError: If directory cannot be created
        """
        try:
            self.storage_path.mkdir(parents=True, exist_ok=True)
            return self.storage_path
        except PermissionError as e:
            raise PermissionError(
                f"Cannot create storage directory {self.storage_path}: {e}"
            )

    def _serialize_value(self, obj: Any) -> Any:
        """Convert Python objects to JSON-serializable format

        Args:
            obj: Object to serialize

        Returns:
            JSON-serializable representation
        """
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, Enum):
            return obj.value
        elif isinstance(obj, Path):
            return str(obj)
        elif hasattr(obj, '__dict__'):
            # Handle custom objects with __dict__
            return self._serialize_dict(obj.__dict__)
        elif isinstance(obj, dict):
            return self._serialize_dict(obj)
        elif isinstance(obj, (list, tuple)):
            return [self._serialize_value(item) for item in obj]
        else:
            return obj

    def _serialize_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively serialize dictionary values

        Args:
            data: Dictionary to serialize

        Returns:
            Serialized dictionary
        """
        result = {}
        for key, value in data.items():
            # Skip private attributes
            if key.startswith('_'):
                continue
            result[key] = self._serialize_value(value)
        return result

    def _get_session_path(self, session_id: str, target: Optional[str] = None) -> Path:
        """Get path to session file

        Args:
            session_id: Session identifier
            target: Optional target (for filename formatting)

        Returns:
            Path to session JSON file
        """
        if target:
            # Sanitize target for filename
            safe_target = target.replace('/', '_').replace(':', '_').replace('.', '-')
            filename = f"{safe_target}_{session_id}.json"
        else:
            filename = f"{session_id}.json"

        return self.storage_path / filename

    def save_session(self, session: Any) -> bool:
        """Save session to disk with atomic write

        Args:
            session: Session object to save (must have 'id' and 'target' attributes)

        Returns:
            True if save successful, False otherwise

        Raises:
            ValueError: If session missing required attributes
            OSError: If disk write fails
        """
        # Validate session has required attributes
        if not hasattr(session, 'id'):
            raise ValueError("Session must have 'id' attribute")

        target = getattr(session, 'target', None)
        session_id = session.id

        # Get final path
        final_path = self._get_session_path(session_id, target)

        # Serialize session data
        if hasattr(session, 'to_dict'):
            data = session.to_dict()
        else:
            data = self._serialize_value(session)

        try:
            # Atomic write: write to temp file first
            temp_fd, temp_path = tempfile.mkstemp(
                dir=self.storage_path,
                prefix=f".{session_id}_",
                suffix='.json.tmp'
            )

            try:
                with os.fdopen(temp_fd, 'w') as f:
                    json.dump(data, f, indent=2, default=str)

                # Atomic rename
                os.replace(temp_path, final_path)
                return True

            except Exception as e:
                # Clean up temp file on error
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
                raise

        except OSError as e:
            # Handle disk full, permissions, etc.
            if e.errno == 28:  # No space left on device
                raise OSError(f"Disk full: cannot save session {session_id}")
            elif e.errno == 13:  # Permission denied
                raise PermissionError(f"Permission denied: cannot save session {session_id}")
            else:
                raise OSError(f"Failed to save session {session_id}: {e}")

    def load_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Load session from disk

        Args:
            session_id: Session identifier

        Returns:
            Session data dictionary or None if not found
        """
        # Try to find session file (may have target prefix)
        matching_files = list(self.storage_path.glob(f"*{session_id}.json"))

        if not matching_files:
            return None

        # Use first match (should be only one)
        session_path = matching_files[0]

        try:
            with open(session_path, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            # Log error but don't crash
            print(f"Warning: Failed to load session {session_id}: {e}")
            return None

    def delete_session(self, session_id: str) -> bool:
        """Delete session from disk

        Args:
            session_id: Session identifier

        Returns:
            True if deleted, False if not found
        """
        # Find session file
        matching_files = list(self.storage_path.glob(f"*{session_id}.json"))

        if not matching_files:
            return False

        try:
            matching_files[0].unlink()
            return True
        except OSError:
            return False

    def query_sessions(self, filters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Query sessions with filters

        Args:
            filters: Dictionary of filter criteria
                - target: Target IP/hostname
                - type: Session type
                - status: Session status
                - active_only: Boolean

        Returns:
            List of matching session dictionaries
        """
        sessions = self.list_all_sessions()

        # Apply filters
        results = []
        for session in sessions:
            match = True

            # Filter by target
            if 'target' in filters:
                if session.get('target') != filters['target']:
                    match = False

            # Filter by type
            if 'type' in filters:
                if session.get('type') != filters['type']:
                    match = False

            # Filter by status
            if 'status' in filters:
                if session.get('status') != filters['status']:
                    match = False

            # Filter active only
            if filters.get('active_only'):
                if session.get('status') not in ['active', 'connected']:
                    match = False

            if match:
                results.append(session)

        return results

    def list_all_sessions(self) -> List[Dict[str, Any]]:
        """List all stored sessions

        Returns:
            List of all session dictionaries
        """
        sessions = []

        # Find all session JSON files
        for session_file in self.storage_path.glob("*.json"):
            # Skip temp files
            if session_file.name.startswith('.'):
                continue

            try:
                with open(session_file, 'r') as f:
                    session_data = json.load(f)
                    sessions.append(session_data)
            except (json.JSONDecodeError, IOError):
                # Skip corrupt files
                continue

        # Sort by created_at (most recent first)
        sessions.sort(
            key=lambda s: s.get('created_at', ''),
            reverse=True
        )

        return sessions

    def get_storage_stats(self) -> Dict[str, Any]:
        """Get storage statistics

        Returns:
            Dictionary with storage stats
        """
        total_sessions = len(list(self.storage_path.glob("*.json")))

        # Calculate total size
        total_size = sum(
            f.stat().st_size
            for f in self.storage_path.glob("*.json")
            if not f.name.startswith('.')
        )

        return {
            'total_sessions': total_sessions,
            'total_size_bytes': total_size,
            'storage_path': str(self.storage_path),
            'exists': self.storage_path.exists()
        }
