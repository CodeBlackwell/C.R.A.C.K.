"""
Engagement Storage

Handles persistent storage of active engagement context.
Stores in ~/.crack/engagement.json for session persistence.
"""

import json
import os
from pathlib import Path
from typing import Optional, Dict, Any
from datetime import datetime


class EngagementStorage:
    """
    Manages engagement state persistence.

    Storage location: ~/.crack/engagement.json
    Structure:
    {
        "active_engagement_id": "eng-abc123",
        "last_used": "2024-01-15T10:30:00",
        "history": [
            {"id": "eng-abc123", "name": "...", "last_used": "..."}
        ]
    }
    """

    DEFAULT_DIR = Path.home() / ".crack"
    DEFAULT_FILE = "engagement.json"

    def __init__(self, storage_path: Optional[Path] = None):
        """
        Initialize storage.

        Args:
            storage_path: Optional custom path (defaults to ~/.crack/engagement.json)
        """
        if storage_path:
            self.storage_path = Path(storage_path)
        else:
            self.storage_path = self.DEFAULT_DIR / self.DEFAULT_FILE

        self._ensure_dir()
        self._data: Dict[str, Any] = self._load()

    def _ensure_dir(self) -> None:
        """Ensure storage directory exists"""
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> Dict[str, Any]:
        """Load storage from disk"""
        if self.storage_path.exists():
            try:
                with open(self.storage_path, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return self._default_data()
        return self._default_data()

    def _default_data(self) -> Dict[str, Any]:
        """Return default storage structure"""
        return {
            "active_engagement_id": None,
            "last_used": None,
            "history": []
        }

    def _save(self) -> None:
        """Save storage to disk"""
        with open(self.storage_path, 'w') as f:
            json.dump(self._data, f, indent=2)

    @property
    def active_engagement_id(self) -> Optional[str]:
        """Get currently active engagement ID"""
        return self._data.get("active_engagement_id")

    def set_active(self, engagement_id: str, engagement_name: str = "") -> None:
        """
        Set the active engagement.

        Args:
            engagement_id: ID of engagement to activate
            engagement_name: Optional name for history tracking
        """
        now = datetime.now().isoformat()

        self._data["active_engagement_id"] = engagement_id
        self._data["last_used"] = now

        # Update history
        history = self._data.get("history", [])

        # Remove existing entry if present
        history = [h for h in history if h.get("id") != engagement_id]

        # Add to front of history
        history.insert(0, {
            "id": engagement_id,
            "name": engagement_name,
            "last_used": now
        })

        # Keep only last 10 entries
        self._data["history"] = history[:10]

        self._save()

    def clear_active(self) -> None:
        """Clear active engagement (deactivate)"""
        self._data["active_engagement_id"] = None
        self._save()

    def get_history(self, limit: int = 10) -> list:
        """
        Get recent engagement history.

        Args:
            limit: Max entries to return

        Returns:
            List of {id, name, last_used} dicts
        """
        return self._data.get("history", [])[:limit]

    def is_active(self, engagement_id: str) -> bool:
        """Check if given engagement is currently active"""
        return self._data.get("active_engagement_id") == engagement_id


# =============================================================================
# Convenience Functions
# =============================================================================

_storage: Optional[EngagementStorage] = None


def _get_storage() -> EngagementStorage:
    """Get singleton storage instance"""
    global _storage
    if _storage is None:
        _storage = EngagementStorage()
    return _storage


def get_active_engagement_id() -> Optional[str]:
    """
    Get the currently active engagement ID.

    Returns:
        Engagement ID string or None if no active engagement
    """
    return _get_storage().active_engagement_id


def set_active_engagement_id(engagement_id: str, name: str = "") -> None:
    """
    Set the active engagement.

    Args:
        engagement_id: ID of engagement to activate
        name: Optional name for history
    """
    _get_storage().set_active(engagement_id, name)


def clear_active_engagement() -> None:
    """Clear/deactivate the current engagement"""
    _get_storage().clear_active()


def get_engagement_history(limit: int = 10) -> list:
    """Get recent engagement history"""
    return _get_storage().get_history(limit)


if __name__ == '__main__':
    # Test storage
    print("Testing engagement storage...")

    # Use temp path for testing
    import tempfile
    test_path = Path(tempfile.gettempdir()) / "crack_test_engagement.json"

    storage = EngagementStorage(test_path)

    # Test set/get active
    storage.set_active("eng-test-001", "Test Engagement 1")
    print(f"Active: {storage.active_engagement_id}")
    assert storage.active_engagement_id == "eng-test-001"

    # Test history
    storage.set_active("eng-test-002", "Test Engagement 2")
    history = storage.get_history()
    print(f"History: {history}")
    assert len(history) == 2
    assert history[0]["id"] == "eng-test-002"

    # Test clear
    storage.clear_active()
    assert storage.active_engagement_id is None

    # Cleanup
    test_path.unlink()

    print("\nStorage tests passed!")
