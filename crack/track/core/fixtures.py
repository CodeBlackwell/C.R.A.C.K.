"""
Fixture storage for dev mode profile states

Manages immutable profile snapshots for rapid testing:
- Save current profile as reusable fixture
- Load fixture to any target
- List/preview fixtures with metadata
- Delete unused fixtures

Fixtures enable instant state loading:
  crack track --dev=web-enum 192.168.45.100
  # Loads pre-configured HTTP enumeration state
"""

import json
import shutil
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime


class FixtureStorage:
    """Manage immutable dev profile fixtures"""

    FIXTURES_DIR = Path.home() / ".crack" / "fixtures"

    @classmethod
    def ensure_directory(cls):
        """Create fixtures directory if it doesn't exist"""
        cls.FIXTURES_DIR.mkdir(parents=True, exist_ok=True)

    @classmethod
    def get_fixture_path(cls, fixture_name: str) -> Path:
        """Get path to fixture JSON file

        Args:
            fixture_name: Fixture identifier (e.g., 'web-enum')

        Returns:
            Path to fixture JSON file
        """
        cls.ensure_directory()
        # Sanitize fixture name for filename
        safe_name = fixture_name.replace('/', '_').replace(':', '_')
        return cls.FIXTURES_DIR / f"{safe_name}.json"

    @classmethod
    def save_fixture(cls, target: str, fixture_name: str, description: str = None):
        """Save current profile as reusable fixture

        Args:
            target: Target IP/hostname of profile to save
            fixture_name: Name for the fixture (e.g., 'web-enum')
            description: Optional description of fixture state

        Raises:
            ValueError: If target profile doesn't exist
        """
        from .storage import Storage
        from .state import TargetProfile

        # Load source profile
        if not TargetProfile.exists(target):
            raise ValueError(f"Profile for {target} does not exist")

        profile_data = Storage.load(target)

        # Add fixture metadata
        profile_data['_fixture_metadata'] = {
            'name': fixture_name,
            'description': description or f'Fixture saved from {target}',
            'created': datetime.now().isoformat(),
            'source_target': target,
            'phase': profile_data.get('phase', 'unknown'),
            'port_count': len(profile_data.get('ports', {})),
            'finding_count': len(profile_data.get('findings', [])),
            'task_count': cls._count_tasks(profile_data.get('task_tree', {}))
        }

        # Save to fixtures directory
        fixture_path = cls.get_fixture_path(fixture_name)
        with open(fixture_path, 'w') as f:
            json.dump(profile_data, f, indent=2)

        return fixture_path

    @classmethod
    def load_fixture(cls, fixture_name: str, target: str):
        """Load fixture to target profile (creates copy)

        Args:
            fixture_name: Name of fixture to load
            target: Target IP/hostname to load fixture into

        Raises:
            ValueError: If fixture doesn't exist
        """
        from .storage import Storage

        # Check fixture exists
        if not cls.exists(fixture_name):
            raise ValueError(f"Fixture '{fixture_name}' not found")

        # Load fixture data
        fixture_path = cls.get_fixture_path(fixture_name)
        with open(fixture_path, 'r') as f:
            fixture_data = json.load(f)

        # Remove fixture metadata (not part of profile schema)
        fixture_data.pop('_fixture_metadata', None)

        # Update target in profile data
        fixture_data['target'] = target

        # Update timestamps to reflect load time
        fixture_data['updated'] = datetime.now().isoformat()

        # Save to target location (overwrites existing profile)
        Storage.save(target, fixture_data)

    @classmethod
    def list_fixtures(cls) -> List[Dict[str, Any]]:
        """List all available fixtures with metadata

        Returns:
            List of fixture info dicts with keys:
            - name: Fixture name
            - description: Description
            - phase: Enumeration phase
            - ports: Port count
            - findings: Finding count
            - tasks: Task count
            - created: Creation timestamp
        """
        cls.ensure_directory()
        fixtures = []

        for fixture_path in sorted(cls.FIXTURES_DIR.glob("*.json")):
            try:
                with open(fixture_path, 'r') as f:
                    data = json.load(f)

                metadata = data.get('_fixture_metadata', {})

                # Extract metadata (with fallbacks for old fixtures)
                fixtures.append({
                    'name': fixture_path.stem,
                    'description': metadata.get('description', 'No description'),
                    'phase': metadata.get('phase', data.get('phase', 'unknown')),
                    'ports': metadata.get('port_count', len(data.get('ports', {}))),
                    'findings': metadata.get('finding_count', len(data.get('findings', []))),
                    'tasks': metadata.get('task_count', cls._count_tasks(data.get('task_tree', {}))),
                    'created': metadata.get('created', 'Unknown'),
                    'source_target': metadata.get('source_target', 'Unknown')
                })
            except (json.JSONDecodeError, KeyError) as e:
                # Skip invalid fixtures
                continue

        return fixtures

    @classmethod
    def get_fixture_details(cls, fixture_name: str) -> Dict[str, Any]:
        """Get detailed info about a specific fixture

        Args:
            fixture_name: Name of fixture to inspect

        Returns:
            Dict with fixture metadata and profile summary

        Raises:
            ValueError: If fixture doesn't exist
        """
        if not cls.exists(fixture_name):
            raise ValueError(f"Fixture '{fixture_name}' not found")

        fixture_path = cls.get_fixture_path(fixture_name)
        with open(fixture_path, 'r') as f:
            data = json.load(f)

        metadata = data.get('_fixture_metadata', {})

        # Build port summary
        ports = data.get('ports', {})
        port_summary = []
        for port, info in sorted(ports.items(), key=lambda x: int(x[0])):
            service = info.get('service', 'unknown')
            port_summary.append(f"{port} ({service})")

        # Build finding summary
        findings = data.get('findings', [])
        finding_types = {}
        for finding in findings:
            ftype = finding.get('type', 'unknown')
            finding_types[ftype] = finding_types.get(ftype, 0) + 1

        return {
            'name': fixture_name,
            'metadata': metadata,
            'profile': {
                'target': data.get('target', 'Unknown'),
                'phase': data.get('phase', 'unknown'),
                'status': data.get('status', 'unknown'),
                'port_summary': ', '.join(port_summary) if port_summary else 'No ports',
                'finding_summary': ', '.join([f"{count} {ftype}" for ftype, count in finding_types.items()]),
                'task_count': cls._count_tasks(data.get('task_tree', {})),
                'credential_count': len(data.get('credentials', [])),
                'note_count': len(data.get('notes', []))
            }
        }

    @classmethod
    def delete_fixture(cls, fixture_name: str):
        """Delete fixture

        Args:
            fixture_name: Name of fixture to delete

        Raises:
            ValueError: If fixture doesn't exist
        """
        if not cls.exists(fixture_name):
            raise ValueError(f"Fixture '{fixture_name}' not found")

        fixture_path = cls.get_fixture_path(fixture_name)
        fixture_path.unlink()

    @classmethod
    def exists(cls, fixture_name: str) -> bool:
        """Check if fixture exists

        Args:
            fixture_name: Name of fixture to check

        Returns:
            True if fixture exists
        """
        return cls.get_fixture_path(fixture_name).exists()

    @classmethod
    def _count_tasks(cls, task_tree: Dict[str, Any]) -> int:
        """Recursively count tasks in task tree

        Args:
            task_tree: Task tree dict from profile

        Returns:
            Total task count (including children)
        """
        if not task_tree:
            return 0

        count = 1  # Count this task

        # Count children recursively
        for child in task_tree.get('children', []):
            count += cls._count_tasks(child)

        return count
