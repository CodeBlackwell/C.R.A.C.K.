"""
Tests for session storage infrastructure

Tests:
- SessionStorage: Save/load/delete/query sessions
- ListenerRegistry: Register/unregister listeners, port conflicts
- SessionQuery: Filter and query operations
"""

import json
import os
import tempfile
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch
import pytest

from crack.sessions.models import Session, Listener, ShellCapabilities
from crack.sessions.storage.base import SessionStorage
from crack.sessions.storage.listener_store import ListenerRegistry
from crack.sessions.storage.query import SessionQuery


class TestSessionStorage:
    """Test SessionStorage class"""

    @pytest.fixture
    def temp_storage_dir(self):
        """Create temporary storage directory"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def storage(self, temp_storage_dir):
        """Create SessionStorage instance with temp directory"""
        return SessionStorage(storage_path=temp_storage_dir)

    @pytest.fixture
    def sample_session(self):
        """Create sample session"""
        return Session(
            id='test-session-123',
            type='tcp',
            protocol='reverse',
            target='192.168.45.150',
            port=4444,
            status='active',
            shell_type='bash'
        )

    def test_ensure_storage_dir_creates_directory(self, temp_storage_dir):
        """Test storage directory creation"""
        storage_path = temp_storage_dir / "newsessions"
        storage = SessionStorage(storage_path=storage_path)

        assert storage_path.exists()
        assert storage_path.is_dir()

    def test_save_session_creates_file(self, storage, sample_session):
        """Test saving session creates JSON file"""
        result = storage.save_session(sample_session)

        assert result is True

        # Check file exists
        expected_file = storage.storage_path / f"192-168-45-150_test-session-123.json"
        assert expected_file.exists()

    def test_save_session_atomic_write(self, storage, sample_session):
        """Test atomic write (temp file then rename)"""
        storage.save_session(sample_session)

        # No temp files should remain
        temp_files = list(storage.storage_path.glob("*.tmp"))
        assert len(temp_files) == 0

    def test_save_session_serializes_datetime(self, storage, sample_session):
        """Test datetime serialization to ISO format"""
        storage.save_session(sample_session)

        session_file = storage.storage_path / f"192-168-45-150_test-session-123.json"
        with open(session_file, 'r') as f:
            data = json.load(f)

        # Check datetime fields are strings
        assert isinstance(data['created_at'], str)
        assert isinstance(data['last_seen'], str)

        # Verify ISO format
        datetime.fromisoformat(data['created_at'])

    def test_load_session_returns_data(self, storage, sample_session):
        """Test loading session returns dictionary"""
        storage.save_session(sample_session)

        loaded_data = storage.load_session('test-session-123')

        assert loaded_data is not None
        assert loaded_data['id'] == 'test-session-123'
        assert loaded_data['target'] == '192.168.45.150'
        assert loaded_data['port'] == 4444

    def test_load_session_not_found(self, storage):
        """Test loading non-existent session returns None"""
        result = storage.load_session('nonexistent-id')

        assert result is None

    def test_load_session_handles_corrupt_json(self, storage, temp_storage_dir):
        """Test loading corrupt JSON doesn't crash"""
        # Create corrupt JSON file
        corrupt_file = temp_storage_dir / "corrupt_session-123.json"
        corrupt_file.write_text("{invalid json")

        result = storage.load_session('session-123')

        assert result is None

    def test_delete_session_removes_file(self, storage, sample_session):
        """Test deleting session removes file"""
        storage.save_session(sample_session)

        result = storage.delete_session('test-session-123')

        assert result is True

        # File should be gone
        session_file = storage.storage_path / f"192-168-45-150_test-session-123.json"
        assert not session_file.exists()

    def test_delete_session_not_found(self, storage):
        """Test deleting non-existent session returns False"""
        result = storage.delete_session('nonexistent-id')

        assert result is False

    def test_query_sessions_by_target(self, storage):
        """Test querying sessions by target"""
        # Create multiple sessions
        session1 = Session(id='s1', target='192.168.1.10', type='tcp')
        session2 = Session(id='s2', target='192.168.1.20', type='tcp')
        session3 = Session(id='s3', target='192.168.1.10', type='http')

        storage.save_session(session1)
        storage.save_session(session2)
        storage.save_session(session3)

        # Query by target
        results = storage.query_sessions({'target': '192.168.1.10'})

        assert len(results) == 2
        assert all(s['target'] == '192.168.1.10' for s in results)

    def test_query_sessions_by_type(self, storage):
        """Test querying sessions by type"""
        session1 = Session(id='s1', target='192.168.1.10', type='tcp')
        session2 = Session(id='s2', target='192.168.1.20', type='http')

        storage.save_session(session1)
        storage.save_session(session2)

        results = storage.query_sessions({'type': 'tcp'})

        assert len(results) == 1
        assert results[0]['type'] == 'tcp'

    def test_query_sessions_by_status(self, storage):
        """Test querying sessions by status"""
        session1 = Session(id='s1', target='192.168.1.10', status='active')
        session2 = Session(id='s2', target='192.168.1.20', status='dead')

        storage.save_session(session1)
        storage.save_session(session2)

        results = storage.query_sessions({'status': 'active'})

        assert len(results) == 1
        assert results[0]['status'] == 'active'

    def test_query_sessions_active_only(self, storage):
        """Test querying active sessions only"""
        session1 = Session(id='s1', target='192.168.1.10', status='active')
        session2 = Session(id='s2', target='192.168.1.20', status='connected')
        session3 = Session(id='s3', target='192.168.1.30', status='dead')

        storage.save_session(session1)
        storage.save_session(session2)
        storage.save_session(session3)

        results = storage.query_sessions({'active_only': True})

        assert len(results) == 2

    def test_list_all_sessions(self, storage):
        """Test listing all sessions"""
        session1 = Session(id='s1', target='192.168.1.10')
        session2 = Session(id='s2', target='192.168.1.20')

        storage.save_session(session1)
        storage.save_session(session2)

        all_sessions = storage.list_all_sessions()

        assert len(all_sessions) == 2

    def test_list_all_sessions_sorted_by_created(self, storage):
        """Test sessions sorted by created_at (most recent first)"""
        # Create sessions with different timestamps
        session1 = Session(id='s1', target='192.168.1.10')
        time.sleep(0.01)  # Small delay to ensure different timestamps
        session2 = Session(id='s2', target='192.168.1.20')

        storage.save_session(session1)
        storage.save_session(session2)

        all_sessions = storage.list_all_sessions()

        # Most recent first
        assert all_sessions[0]['id'] == 's2'
        assert all_sessions[1]['id'] == 's1'

    def test_get_storage_stats(self, storage, sample_session):
        """Test storage statistics"""
        storage.save_session(sample_session)

        stats = storage.get_storage_stats()

        assert stats['total_sessions'] == 1
        assert stats['total_size_bytes'] > 0
        assert stats['exists'] is True
        assert str(storage.storage_path) in stats['storage_path']


class TestListenerRegistry:
    """Test ListenerRegistry class"""

    @pytest.fixture
    def temp_registry_file(self):
        """Create temporary registry file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            registry_path = Path(f.name)

        yield registry_path

        # Cleanup
        if registry_path.exists():
            registry_path.unlink()

    @pytest.fixture
    def registry(self, temp_registry_file):
        """Create ListenerRegistry instance"""
        return ListenerRegistry(registry_path=temp_registry_file)

    @pytest.fixture
    def sample_listener(self):
        """Create sample listener"""
        listener = Listener(
            id='listener-123',
            protocol='tcp',
            port=4444,
            pid=12345
        )
        listener.start()
        return listener

    def test_ensure_registry_file_created(self, temp_registry_file):
        """Test registry file creation"""
        registry = ListenerRegistry(registry_path=temp_registry_file)

        assert temp_registry_file.exists()

    def test_register_listener_success(self, registry, sample_listener):
        """Test registering listener"""
        with patch.object(registry, '_is_process_alive', return_value=True):
            result = registry.register_listener(sample_listener)

        assert result is True

    def test_register_listener_missing_id(self, registry):
        """Test registering listener without ID raises error"""
        class BadListener:
            port = 4444

        with pytest.raises(ValueError, match="must have 'id' attribute"):
            registry.register_listener(BadListener())

    def test_register_listener_missing_port(self, registry):
        """Test registering listener without port raises error"""
        class BadListener:
            id = 'test'

        with pytest.raises(ValueError, match="must have 'port' attribute"):
            registry.register_listener(BadListener())

    def test_register_listener_port_conflict(self, registry, sample_listener):
        """Test registering listener on used port raises error"""
        with patch.object(registry, '_is_process_alive', return_value=True):
            registry.register_listener(sample_listener)

            # Try to register another listener on same port
            listener2 = Listener(id='listener-456', protocol='tcp', port=4444, pid=12346)
            listener2.start()

            with pytest.raises(RuntimeError, match="Port 4444 already in use"):
                registry.register_listener(listener2)

    def test_unregister_listener_success(self, registry, sample_listener):
        """Test unregistering listener"""
        with patch.object(registry, '_is_process_alive', return_value=True):
            registry.register_listener(sample_listener)

        result = registry.unregister_listener('listener-123')

        assert result is True

    def test_unregister_listener_not_found(self, registry):
        """Test unregistering non-existent listener"""
        result = registry.unregister_listener('nonexistent')

        assert result is False

    def test_get_listener_by_id(self, registry, sample_listener):
        """Test getting listener by ID"""
        with patch.object(registry, '_is_process_alive', return_value=True):
            registry.register_listener(sample_listener)

        listener = registry.get_listener('listener-123')

        assert listener is not None
        assert listener['id'] == 'listener-123'

    def test_get_listener_by_port(self, registry, sample_listener):
        """Test getting listener by port"""
        with patch.object(registry, '_is_process_alive', return_value=True):
            registry.register_listener(sample_listener)
            listener = registry.get_listener_by_port(4444)

        assert listener is not None
        assert listener['port'] == 4444

    def test_get_listener_by_port_process_dead(self, registry, sample_listener):
        """Test getting listener by port when process is dead"""
        with patch.object(registry, '_is_process_alive', return_value=True):
            registry.register_listener(sample_listener)

        # Now process is dead
        with patch.object(registry, '_is_process_alive', return_value=False):
            listener = registry.get_listener_by_port(4444)

        assert listener is None

    def test_list_active_listeners(self, registry):
        """Test listing active listeners"""
        listener1 = Listener(id='l1', protocol='tcp', port=4444, pid=12345)
        listener2 = Listener(id='l2', protocol='tcp', port=5555, pid=12346)
        listener1.start()
        listener2.start()

        with patch.object(registry, '_is_process_alive', return_value=True):
            registry.register_listener(listener1)
            registry.register_listener(listener2)

            active = registry.list_active_listeners()

        assert len(active) == 2

    def test_list_active_listeners_filters_dead(self, registry):
        """Test active listeners filters out dead processes"""
        listener1 = Listener(id='l1', protocol='tcp', port=4444, pid=12345)
        listener2 = Listener(id='l2', protocol='tcp', port=5555, pid=12346)
        listener1.start()
        listener2.start()

        with patch.object(registry, '_is_process_alive', return_value=True):
            registry.register_listener(listener1)
            registry.register_listener(listener2)

        # Now only one is alive
        def process_check(pid):
            return pid == 12345

        with patch.object(registry, '_is_process_alive', side_effect=process_check):
            active = registry.list_active_listeners()

        assert len(active) == 1
        assert active[0]['pid'] == 12345

    def test_cleanup_stale_listeners(self, registry):
        """Test cleaning up stale listeners"""
        listener1 = Listener(id='l1', protocol='tcp', port=4444, pid=12345)
        listener2 = Listener(id='l2', protocol='tcp', port=5555, pid=12346)
        listener1.start()
        listener2.start()

        with patch.object(registry, '_is_process_alive', return_value=True):
            registry.register_listener(listener1)
            registry.register_listener(listener2)

        # All processes are now dead
        with patch.object(registry, '_is_process_alive', return_value=False):
            removed = registry.cleanup_stale_listeners()

        assert removed == 2

    def test_is_port_available(self, registry, sample_listener):
        """Test checking if port is available"""
        with patch.object(registry, '_is_process_alive', return_value=True):
            registry.register_listener(sample_listener)
            assert registry.is_port_available(4444) is False
            assert registry.is_port_available(5555) is True

    def test_get_next_available_port(self, registry):
        """Test finding next available port"""
        # Register listeners on 4444 and 4445
        listener1 = Listener(id='l1', protocol='tcp', port=4444, pid=12345)
        listener2 = Listener(id='l2', protocol='tcp', port=4445, pid=12346)
        listener1.start()
        listener2.start()

        with patch.object(registry, '_is_process_alive', return_value=True):
            registry.register_listener(listener1)
            registry.register_listener(listener2)
            next_port = registry.get_next_available_port(start_port=4444)

        assert next_port == 4446

    def test_get_registry_stats(self, registry, sample_listener):
        """Test registry statistics"""
        with patch.object(registry, '_is_process_alive', return_value=True):
            registry.register_listener(sample_listener)
            stats = registry.get_registry_stats()

        assert stats['total_registered'] == 1
        assert stats['active'] == 1
        assert stats['stale'] == 0


class TestSessionQuery:
    """Test SessionQuery class"""

    @pytest.fixture
    def temp_storage_dir(self):
        """Create temporary storage directory"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def storage(self, temp_storage_dir):
        """Create SessionStorage instance"""
        return SessionStorage(storage_path=temp_storage_dir)

    @pytest.fixture
    def sample_sessions(self, storage):
        """Create sample sessions"""
        sessions = [
            Session(id='s1', target='192.168.1.10', type='tcp', status='active'),
            Session(id='s2', target='192.168.1.20', type='http', status='active'),
            Session(id='s3', target='192.168.1.10', type='tcp', status='dead'),
            Session(id='s4', target='192.168.1.30', type='tcp', status='active')
        ]

        for session in sessions:
            storage.save_session(session)

        return sessions

    def test_by_target(self, storage, sample_sessions):
        """Test filtering by target"""
        query = SessionQuery(storage)
        results = query.by_target('192.168.1.10').execute()

        assert len(results) == 2
        assert all(s['target'] == '192.168.1.10' for s in results)

    def test_by_type(self, storage, sample_sessions):
        """Test filtering by type"""
        query = SessionQuery(storage)
        results = query.by_type('tcp').execute()

        assert len(results) == 3

    def test_by_status(self, storage, sample_sessions):
        """Test filtering by status"""
        query = SessionQuery(storage)
        results = query.by_status('active').execute()

        assert len(results) == 3

    def test_active_only(self, storage, sample_sessions):
        """Test filtering active sessions"""
        query = SessionQuery(storage)
        results = query.active_only().execute()

        assert len(results) == 3
        assert all(s['status'] in ['active', 'connected'] for s in results)

    def test_chained_filters(self, storage, sample_sessions):
        """Test chaining multiple filters"""
        query = SessionQuery(storage)
        results = query.by_target('192.168.1.10').by_type('tcp').active_only().execute()

        assert len(results) == 1
        assert results[0]['id'] == 's1'

    def test_in_last_hours(self, storage):
        """Test filtering by time range"""
        # Create old session
        old_session = Session(id='old', target='192.168.1.10')
        old_session.created_at = datetime.now() - timedelta(hours=25)
        storage.save_session(old_session)

        # Create recent session
        recent_session = Session(id='recent', target='192.168.1.20')
        storage.save_session(recent_session)

        query = SessionQuery(storage)
        results = query.in_last_hours(24).execute()

        assert len(results) == 1
        assert results[0]['id'] == 'recent'

    def test_sort_by(self, storage, sample_sessions):
        """Test sorting results"""
        query = SessionQuery(storage)
        results = query.sort_by('target', desc=False).execute()

        # Check sorted order
        targets = [s['target'] for s in results]
        assert targets == sorted(targets)

    def test_limit(self, storage, sample_sessions):
        """Test limiting results"""
        query = SessionQuery(storage)
        results = query.limit(2).execute()

        assert len(results) == 2

    def test_count(self, storage, sample_sessions):
        """Test counting results"""
        query = SessionQuery(storage)
        count = query.by_type('tcp').count()

        assert count == 3

    def test_first(self, storage, sample_sessions):
        """Test getting first result"""
        query = SessionQuery(storage)
        result = query.by_target('192.168.1.10').first()

        assert result is not None
        assert result['target'] == '192.168.1.10'

    def test_exists(self, storage, sample_sessions):
        """Test checking if results exist"""
        query = SessionQuery(storage)

        assert query.by_target('192.168.1.10').exists() is True
        assert query.by_target('192.168.1.99').exists() is False

    def test_reset(self, storage, sample_sessions):
        """Test resetting filters"""
        query = SessionQuery(storage)

        # Add filters
        query.by_target('192.168.1.10').by_type('tcp')
        assert len(query._filters) == 2

        # Reset
        query.reset()
        assert len(query._filters) == 0
