"""
JSON storage for target profiles

Stores target state in ~/.crack/targets/<TARGET>.json
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, List


class Storage:
    """Handle persistent storage of target profiles"""

    DEFAULT_DIR = Path.home() / ".crack" / "targets"

    @classmethod
    def ensure_directory(cls):
        """Create storage directory if it doesn't exist"""
        cls.DEFAULT_DIR.mkdir(parents=True, exist_ok=True)

    @classmethod
    def get_target_path(cls, target: str) -> Path:
        """Get path to target's JSON file

        Args:
            target: Target IP or hostname

        Returns:
            Path to JSON file
        """
        cls.ensure_directory()
        # Sanitize target name for filename
        safe_target = target.replace('/', '_').replace(':', '_')
        return cls.DEFAULT_DIR / f"{safe_target}.json"

    @classmethod
    def save(cls, target: str, data: Dict[str, Any]):
        """Save target profile to disk

        Args:
            target: Target IP or hostname
            data: Profile data dictionary
        """
        path = cls.get_target_path(target)
        with open(path, 'w') as f:
            json.dump(data, f, indent=2)

    @classmethod
    def load(cls, target: str) -> Dict[str, Any]:
        """Load target profile from disk

        Args:
            target: Target IP or hostname

        Returns:
            Profile data dictionary or None if not found
        """
        path = cls.get_target_path(target)
        if not path.exists():
            return None

        with open(path, 'r') as f:
            return json.load(f)

    @classmethod
    def exists(cls, target: str) -> bool:
        """Check if target profile exists

        Args:
            target: Target IP or hostname

        Returns:
            True if profile exists
        """
        return cls.get_target_path(target).exists()

    @classmethod
    def delete(cls, target: str):
        """Delete target profile

        Args:
            target: Target IP or hostname
        """
        path = cls.get_target_path(target)
        if path.exists():
            path.unlink()

    @classmethod
    def list_targets(cls) -> List[str]:
        """List all stored targets

        Returns:
            List of target names
        """
        cls.ensure_directory()
        targets = []
        for path in cls.DEFAULT_DIR.glob("*.json"):
            # Remove .json extension and restore original target name
            target = path.stem.replace('_', '.')
            targets.append(target)
        return sorted(targets)
