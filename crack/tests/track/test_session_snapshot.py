"""
Test Session Snapshot Functionality

PROVES: Session snapshots enable safe checkpointing before risky operations

Coverage:
- Snapshot creation and storage
- Snapshot listing and metadata
- Snapshot restoration
- Snapshot deletion
- Name sanitization
- Directory management
"""

import pytest
import json
from pathlib import Path
from datetime import datetime
from crack.track.core.state import TargetProfile
from crack.track.interactive.session import InteractiveSession


class TestSnapshotCreation:
    """PROVES: Snapshots save complete profile state correctly"""

    def test_ss_shortcut_exists(self):
        """PROVES: 'ss' shortcut is registered in shortcuts"""
        from crack.track.interactive.shortcuts import ShortcutHandler

        # Create minimal session
        profile = TargetProfile("192.168.45.100")
        from crack.track.interactive.session import InteractiveSession
        session = InteractiveSession.__new__(InteractiveSession)
        session.profile = profile
        session.target = "192.168.45.100"

        handler = ShortcutHandler(session)

        # Verify shortcut exists
        assert 'ss' in handler.shortcuts
        assert handler.shortcuts['ss'][0] == 'Session snapshot'
        assert handler.shortcuts['ss'][1] == 'session_snapshot'

    def test_ss_handler_callable(self, temp_crack_home):
        """PROVES: session_snapshot handler method exists and is callable"""
        profile = TargetProfile("192.168.45.100")
        session = InteractiveSession.__new__(InteractiveSession)
        session.profile = profile
        session.target = "192.168.45.100"
        session.last_action = None
        session.checkpoint_dir = Path.home() / '.crack' / 'sessions'
        session.checkpoint_dir.mkdir(parents=True, exist_ok=True)

        # Verify method exists
        assert hasattr(session, 'handle_session_snapshot')
        assert callable(session.handle_session_snapshot)

    def test_snapshot_directory_creation(self, temp_crack_home):
        """PROVES: Creates ~/.crack/snapshots/TARGET/ directory"""
        target = "192.168.45.100"
        profile = TargetProfile(target)
        session = InteractiveSession.__new__(InteractiveSession)
        session.profile = profile
        session.target = target
        session.last_action = None

        # Create snapshots directory
        snapshots_dir = session._get_snapshots_dir()

        # Verify directory exists
        assert snapshots_dir.exists()
        assert snapshots_dir.is_dir()
        assert str(snapshots_dir).endswith(f"snapshots/{target}")

    def test_save_snapshot_basic(self, temp_crack_home):
        """PROVES: Saves snapshot successfully with correct structure"""
        target = "192.168.45.100"
        profile = TargetProfile(target)

        # Add some data
        profile.add_port(80, state='open', service='http', source='test')
        profile.add_finding(
            finding_type='vulnerability',
            description='Test vuln',
            source='manual'
        )

        session = InteractiveSession.__new__(InteractiveSession)
        session.profile = profile
        session.target = target
        session.last_action = None

        # Save snapshot
        snapshot_name = "test-checkpoint"
        success = session._save_snapshot(snapshot_name)

        assert success

        # Verify file exists
        snapshots_dir = session._get_snapshots_dir()
        snapshot_files = list(snapshots_dir.glob(f"*{snapshot_name}*.json"))

        assert len(snapshot_files) == 1

        # Verify content structure
        data = json.loads(snapshot_files[0].read_text())
        assert 'snapshot_metadata' in data
        assert 'profile_data' in data
        assert data['snapshot_metadata']['name'] == snapshot_name
        assert data['snapshot_metadata']['stats']['findings'] == 1
        assert data['profile_data']['target'] == target

    def test_save_snapshot_filename_format(self, temp_crack_home):
        """PROVES: Snapshot filename follows TARGET_NAME_TIMESTAMP.json format"""
        target = "192.168.45.100"
        profile = TargetProfile(target)
        session = InteractiveSession.__new__(InteractiveSession)
        session.profile = profile
        session.target = target
        session.last_action = None

        snapshot_name = "before-sqli"
        session._save_snapshot(snapshot_name)

        snapshots_dir = session._get_snapshots_dir()
        snapshot_files = list(snapshots_dir.glob('*.json'))

        assert len(snapshot_files) == 1

        filename = snapshot_files[0].name
        # Format: TARGET_NAME_TIMESTAMP.json
        assert filename.startswith(target.replace('.', '_') + '_' + snapshot_name)
        assert filename.endswith('.json')
        assert '_' in filename  # Contains timestamp separator

    def test_snapshot_metadata_complete(self, temp_crack_home):
        """PROVES: Snapshot metadata includes all required stats"""
        target = "192.168.45.100"
        profile = TargetProfile(target)

        # Add comprehensive data
        profile.add_port(80, state='open', service='http', source='nmap')
        profile.add_port(443, state='open', service='https', source='nmap')
        profile.add_finding(
            finding_type='vulnerability',
            description='SQLi in id param',
            source='sqlmap'
        )
        profile.add_credential(
            username='admin',
            password='password123',
            service='http',
            port=80,
            source='hydra'
        )

        session = InteractiveSession.__new__(InteractiveSession)
        session.profile = profile
        session.target = target
        session.last_action = None

        # Save snapshot
        session._save_snapshot("comprehensive-test")

        # Load and verify metadata
        snapshots = session._list_snapshots()
        assert len(snapshots) == 1

        meta = snapshots[0]['metadata']
        stats = meta['stats']

        # Verify all required metadata fields
        assert 'name' in meta
        assert 'created' in meta
        assert 'description' in meta
        assert 'stats' in meta

        # Verify stats content
        assert stats['findings'] == 1
        assert stats['credentials'] == 1
        assert 'total_tasks' in stats
        assert 'completed_tasks' in stats
        assert stats['phase'] == 'discovery'


class TestSnapshotListing:
    """PROVES: Snapshot listing and retrieval works correctly"""

    def test_list_snapshots_empty(self, temp_crack_home):
        """PROVES: Returns empty list when no snapshots exist"""
        target = "192.168.45.100"
        profile = TargetProfile(target)
        session = InteractiveSession.__new__(InteractiveSession)
        session.profile = profile
        session.target = target
        session.last_action = None

        snapshots = session._list_snapshots()

        assert snapshots == []

    def test_list_snapshots_multiple(self, temp_crack_home):
        """PROVES: Lists all snapshots sorted by creation time"""
        target = "192.168.45.100"
        profile = TargetProfile(target)
        session = InteractiveSession.__new__(InteractiveSession)
        session.profile = profile
        session.target = target
        session.last_action = None

        # Create multiple snapshots
        session._save_snapshot("snapshot-1")
        session._save_snapshot("snapshot-2")
        session._save_snapshot("snapshot-3")

        snapshots = session._list_snapshots()

        # Verify count
        assert len(snapshots) == 3

        # Verify all have required fields
        for snapshot in snapshots:
            assert 'filename' in snapshot
            assert 'metadata' in snapshot
            assert 'path' in snapshot

            meta = snapshot['metadata']
            assert 'name' in meta
            assert 'created' in meta

        # Verify sorting (newest first)
        creation_times = [s['metadata']['created'] for s in snapshots]
        assert creation_times == sorted(creation_times, reverse=True)


class TestSnapshotRestoration:
    """PROVES: Snapshots restore profile state correctly"""

    def test_restore_snapshot(self, temp_crack_home):
        """PROVES: Restores profile from snapshot successfully"""
        target = "192.168.45.100"

        # Create original profile with data
        profile = TargetProfile(target)
        profile.add_port(80, state='open', service='http', source='nmap')
        profile.add_finding(
            finding_type='vulnerability',
            description='Original finding',
            source='manual'
        )

        session = InteractiveSession.__new__(InteractiveSession)
        session.profile = profile
        session.target = target
        session.last_action = None
        session.checkpoint_dir = Path.home() / '.crack' / 'sessions'
        session.checkpoint_dir.mkdir(parents=True, exist_ok=True)

        # Save snapshot
        session._save_snapshot("checkpoint-1")

        # Modify profile after snapshot
        profile.add_port(443, state='open', service='https', source='nmap')
        profile.add_finding(
            finding_type='vulnerability',
            description='New finding after snapshot',
            source='manual'
        )

        # Verify modified state
        assert len(profile.ports) == 2
        assert len(profile.findings) == 2

        # Restore snapshot
        snapshots = session._list_snapshots()
        success = session._restore_snapshot(snapshots[0]['path'])

        assert success

        # Verify restored state matches snapshot
        assert len(session.profile.ports) == 1
        assert len(session.profile.findings) == 1
        assert 80 in session.profile.ports
        assert 443 not in session.profile.ports

    def test_restore_snapshot_preserves_task_tree(self, temp_crack_home):
        """PROVES: Restoring snapshot preserves task tree structure"""
        target = "192.168.45.100"

        # Create profile with task tree
        profile = TargetProfile(target)
        profile.add_port(80, state='open', service='http', source='nmap')

        session = InteractiveSession.__new__(InteractiveSession)
        session.profile = profile
        session.target = target
        session.last_action = None
        session.checkpoint_dir = Path.home() / '.crack' / 'sessions'
        session.checkpoint_dir.mkdir(parents=True, exist_ok=True)

        # Get initial task count
        initial_task_count = len(profile.task_tree.get_all_tasks())

        # Save snapshot
        session._save_snapshot("task-tree-test")

        # Modify task tree (mark some complete)
        all_tasks = profile.task_tree.get_all_tasks()
        if len(all_tasks) > 1:
            all_tasks[1].mark_complete()

        # Restore snapshot
        snapshots = session._list_snapshots()
        session._restore_snapshot(snapshots[0]['path'])

        # Verify task tree restored
        restored_count = len(session.profile.task_tree.get_all_tasks())
        assert restored_count == initial_task_count

        # Verify tasks reset to pending
        restored_tasks = session.profile.task_tree.get_all_tasks()
        for task in restored_tasks[1:]:  # Skip root
            if task.type != 'parent':
                assert task.status == 'pending'


class TestSnapshotDeletion:
    """PROVES: Snapshot deletion works correctly"""

    def test_delete_snapshot(self, temp_crack_home):
        """PROVES: Deletes snapshot file successfully"""
        target = "192.168.45.100"
        profile = TargetProfile(target)
        session = InteractiveSession.__new__(InteractiveSession)
        session.profile = profile
        session.target = target
        session.last_action = None

        # Create snapshot
        session._save_snapshot("to-delete")

        # Verify exists
        snapshots = session._list_snapshots()
        assert len(snapshots) == 1

        # Delete
        snapshot_path = snapshots[0]['path']
        snapshot_path.unlink()

        # Verify deleted
        snapshots_after = session._list_snapshots()
        assert len(snapshots_after) == 0


class TestSnapshotNameSanitization:
    """PROVES: Snapshot names are sanitized correctly"""

    def test_snapshot_name_sanitization(self, temp_crack_home):
        """PROVES: Special characters in names are sanitized"""
        target = "192.168.45.100"
        profile = TargetProfile(target)
        session = InteractiveSession.__new__(InteractiveSession)
        session.profile = profile
        session.target = target
        session.last_action = None

        # Save with special characters
        unsafe_name = "before/sql*injection?test"
        session._save_snapshot(unsafe_name)

        # Verify sanitized
        snapshots = session._list_snapshots()
        assert len(snapshots) == 1

        meta = snapshots[0]['metadata']
        safe_name = meta['name']

        # Should not contain special chars
        assert '/' not in safe_name
        assert '*' not in safe_name
        assert '?' not in safe_name

        # Should contain dashes or underscores
        assert '-' in safe_name or '_' in safe_name

    def test_empty_snapshot_name_rejected(self, temp_crack_home):
        """PROVES: Empty snapshot names are rejected"""
        target = "192.168.45.100"
        profile = TargetProfile(target)
        session = InteractiveSession.__new__(InteractiveSession)
        session.profile = profile
        session.target = target
        session.last_action = None

        # Try empty name
        success = session._save_snapshot("")
        assert success is False

        # Try whitespace only
        success = session._save_snapshot("   ")
        assert success is False

        # Verify no snapshots created
        snapshots = session._list_snapshots()
        assert len(snapshots) == 0


class TestSnapshotEdgeCases:
    """PROVES: Snapshot system handles edge cases correctly"""

    def test_snapshot_with_no_findings(self, temp_crack_home):
        """PROVES: Can snapshot profile with no findings or credentials"""
        target = "192.168.45.100"
        profile = TargetProfile(target)
        session = InteractiveSession.__new__(InteractiveSession)
        session.profile = profile
        session.target = target
        session.last_action = None

        # Save empty profile
        success = session._save_snapshot("empty-profile")
        assert success

        snapshots = session._list_snapshots()
        assert len(snapshots) == 1

        stats = snapshots[0]['metadata']['stats']
        assert stats['findings'] == 0
        assert stats['credentials'] == 0

    def test_snapshot_with_large_dataset(self, temp_crack_home):
        """PROVES: Can snapshot profile with many ports, findings, credentials"""
        target = "192.168.45.100"
        profile = TargetProfile(target)

        # Add many ports
        for port in range(80, 90):
            profile.add_port(port, state='open', service=f'service-{port}', source='nmap')

        # Add many findings
        for i in range(50):
            profile.add_finding(
                finding_type='vulnerability',
                description=f'Finding {i}',
                source='test'
            )

        # Add many credentials
        for i in range(20):
            profile.add_credential(
                username=f'user{i}',
                password=f'pass{i}',
                service='ssh',
                port=22,
                source='hydra'
            )

        session = InteractiveSession.__new__(InteractiveSession)
        session.profile = profile
        session.target = target
        session.last_action = None

        # Save large profile
        success = session._save_snapshot("large-dataset")
        assert success

        # Verify stats
        snapshots = session._list_snapshots()
        stats = snapshots[0]['metadata']['stats']
        assert stats['findings'] == 50
        assert stats['credentials'] == 20

        # Verify can restore
        session._restore_snapshot(snapshots[0]['path'])
        assert len(session.profile.findings) == 50
        assert len(session.profile.credentials) == 20
        assert len(session.profile.ports) == 10

    def test_multiple_targets_isolated(self, temp_crack_home):
        """PROVES: Snapshots for different targets are isolated"""
        target1 = "192.168.45.100"
        target2 = "192.168.45.101"

        # Create profile for target1
        profile1 = TargetProfile(target1)
        session1 = InteractiveSession.__new__(InteractiveSession)
        session1.profile = profile1
        session1.target = target1
        session1.last_action = None

        # Create profile for target2
        profile2 = TargetProfile(target2)
        session2 = InteractiveSession.__new__(InteractiveSession)
        session2.profile = profile2
        session2.target = target2
        session2.last_action = None

        # Save snapshots
        session1._save_snapshot("target1-snapshot")
        session2._save_snapshot("target2-snapshot")

        # Verify isolation
        snapshots1 = session1._list_snapshots()
        snapshots2 = session2._list_snapshots()

        assert len(snapshots1) == 1
        assert len(snapshots2) == 1
        assert snapshots1[0]['metadata']['name'] == 'target1-snapshot'
        assert snapshots2[0]['metadata']['name'] == 'target2-snapshot'

        # Verify different directories
        assert str(snapshots1[0]['path']) != str(snapshots2[0]['path'])
        assert target1.replace('.', '_') in str(snapshots1[0]['path'])
        assert target2.replace('.', '_') in str(snapshots2[0]['path'])
