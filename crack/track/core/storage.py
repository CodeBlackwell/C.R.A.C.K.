"""
JSON storage for target profiles

Stores target state in ./CRACK_targets/<TARGET>.json (project-local)
Legacy support for ~/.crack/targets/ (fallback)
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, List


class Storage:
    """Handle persistent storage of target profiles

    Storage Priority Order:
    1. CRACK_TARGETS_DIR environment variable (if set)
    2. ./CRACK_targets/ (project-local, new default)
    3. ~/.crack/targets/ (legacy fallback for existing profiles)
    """

    @classmethod
    def get_targets_dir(cls) -> Path:
        """Get targets directory with fallback logic

        Priority:
        1. CRACK_TARGETS_DIR environment variable
        2. ./CRACK_targets/ (project-local, new default)
        3. ~/.crack/targets/ (legacy fallback)

        Returns:
            Path to targets directory
        """
        # Priority 1: Environment variable override
        env_dir = os.environ.get('CRACK_TARGETS_DIR')
        if env_dir:
            return Path(env_dir)

        # Priority 2: Project-local (new default)
        local_dir = Path.cwd() / "CRACK_targets"
        if local_dir.exists():
            return local_dir

        # Priority 3: Legacy fallback (if it exists and local doesn't)
        legacy_dir = Path.home() / ".crack" / "targets"
        if legacy_dir.exists():
            return legacy_dir

        # Default to project-local for new installations
        return local_dir

    @classmethod
    def ensure_directory(cls):
        """Create storage directory if it doesn't exist"""
        targets_dir = cls.get_targets_dir()
        targets_dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def get_target_path(cls, target: str) -> Path:
        """Get path to target's JSON file

        Searches in priority order, creates in get_targets_dir() if not found.
        This enables transparent fallback to legacy location while preferring
        the new project-local directory.

        Args:
            target: Target IP or hostname

        Returns:
            Path to JSON file (existing or new)
        """
        # Sanitize target name for filename
        safe_target = target.replace('/', '_').replace(':', '_')
        filename = f"{safe_target}.json"

        # Priority 1: Check environment variable location first
        env_dir = os.environ.get('CRACK_TARGETS_DIR')
        if env_dir:
            path = Path(env_dir) / filename
            if path.exists():
                return path
            # If env var set but file doesn't exist, create here
            Path(env_dir).mkdir(parents=True, exist_ok=True)
            return path

        # Priority 2: Check project-local directory
        local_path = Path.cwd() / "CRACK_targets" / filename
        if local_path.exists():
            return local_path

        # Priority 3: Check legacy directory
        legacy_path = Path.home() / ".crack" / "targets" / filename
        if legacy_path.exists():
            return legacy_path

        # Default to project-local for new profiles
        cls.ensure_directory()
        return cls.get_targets_dir() / filename

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
        """List all stored targets from all locations

        Searches environment variable location, project-local, and legacy directories.

        Returns:
            List of target names (deduplicated)
        """
        targets_set = set()

        # Check environment variable location
        env_dir = os.environ.get('CRACK_TARGETS_DIR')
        if env_dir:
            env_path = Path(env_dir)
            if env_path.exists():
                for path in env_path.glob("*.json"):
                    target = path.stem.replace('_', '.')
                    targets_set.add(target)

        # Check project-local directory
        local_dir = Path.cwd() / "CRACK_targets"
        if local_dir.exists():
            for path in local_dir.glob("*.json"):
                target = path.stem.replace('_', '.')
                targets_set.add(target)

        # Check legacy directory
        legacy_dir = Path.home() / ".crack" / "targets"
        if legacy_dir.exists():
            for path in legacy_dir.glob("*.json"):
                target = path.stem.replace('_', '.')
                targets_set.add(target)

        return sorted(targets_set)

    @classmethod
    def migrate_from_legacy(cls, target: str = None) -> Dict[str, Any]:
        """Migrate profiles from ~/.crack/targets/ to ./CRACK_targets/

        Args:
            target: Specific target to migrate (None = migrate all)

        Returns:
            Dict with migration stats: {'migrated': 5, 'skipped': 2, 'errors': 0}
        """
        legacy_dir = Path.home() / ".crack" / "targets"
        if not legacy_dir.exists():
            return {'migrated': 0, 'skipped': 0, 'errors': 0, 'message': 'No legacy directory found'}

        new_dir = Path.cwd() / "CRACK_targets"
        new_dir.mkdir(parents=True, exist_ok=True)

        stats = {'migrated': 0, 'skipped': 0, 'errors': 0}

        # Migrate specific target or all
        if target:
            safe_target = target.replace('/', '_').replace(':', '_')
            targets = [safe_target]
        else:
            targets = [p.stem for p in legacy_dir.glob("*.json")]

        for tgt in targets:
            legacy_path = legacy_dir / f"{tgt}.json"
            new_path = new_dir / f"{tgt}.json"

            if not legacy_path.exists():
                stats['errors'] += 1
                continue

            if new_path.exists():
                stats['skipped'] += 1
                continue

            try:
                import shutil
                shutil.copy2(legacy_path, new_path)
                stats['migrated'] += 1
            except Exception as e:
                stats['errors'] += 1

        return stats
