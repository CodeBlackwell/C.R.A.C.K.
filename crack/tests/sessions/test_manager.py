"""
Tests for SessionManager

Covers:
- Session creation
- Session listing and filtering
- Session updates
- Session killing
- PID validation
- Dead session cleanup
"""

import pytest
import sys
import uuid
import os
import signal
import tempfile
from pathlib import Path
from datetime import datetime, timedelta

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from crack.sessions.manager import SessionManager
from crack.sessions.storage.base import SessionStorage
from crack.sessions.config import SessionConfig
from crack.sessions.models import Session, ShellCapabilities
from crack.sessions.events import EventBus, SessionEvent


@pytest.fixture
def temp_storage(tmp_path):
    """Temporary storage for tests"""
    return SessionStorage(storage_path=tmp_path)


@pytest.fixture
def config():
    """Test configuration"""
    return SessionConfig()


@pytest.fixture
def manager(temp_storage, config):
    """Test session manager"""
    return SessionManager(temp_storage, config)


@pytest.fixture(autouse=True)
def clear_events():
    """Clear event handlers before each test"""
    EventBus.clear()
    yield
    EventBus.clear()


class TestSessionCreation:
    """Test session creation"""

    def test_create_tcp_session(self, manager):
        """Should create TCP session with required fields"""
        session = manager.create_session(
            type='tcp',
            target='192.168.45.150',
            port=4444,
            protocol='reverse'
        )

        assert session.id is not None
        assert session.type == 'tcp'
        assert session.target == '192.168.45.150'
        assert session.port == 4444
        assert session.protocol == 'reverse'
        assert session.status == 'active'

    def test_create_session_with_metadata(self, manager):
        """Should create session with custom metadata"""
        metadata = {
            'listener_id': 'test-listener',
            'connection_time': '2025-10-09T12:00:00'
        }

        session = manager.create_session(
            type='tcp',
            target='192.168.45.150',
            port=4444,
            metadata=metadata
        )

        assert session.metadata['listener_id'] == 'test-listener'
        assert session.metadata['connection_time'] == '2025-10-09T12:00:00'

    def test_create_session_emits_event(self, manager):
        """Should emit SESSION_STARTED event on creation"""
        events = []

        def capture_event(data):
            events.append(data)

        EventBus.subscribe(SessionEvent.SESSION_STARTED, capture_event)

        session = manager.create_session(
            type='tcp',
            target='192.168.45.150',
            port=4444
        )

        assert len(events) == 1
        assert events[0]['session_id'] == session.id
        assert events[0]['target'] == '192.168.45.150'
        assert events[0]['port'] == 4444

    def test_create_session_invalid_target(self, manager):
        """Should raise ValueError for missing target"""
        with pytest.raises(ValueError, match='Target is required'):
            manager.create_session(
                type='tcp',
                target='',
                port=4444
            )

    def test_create_session_invalid_port(self, manager):
        """Should raise ValueError for invalid port"""
        with pytest.raises(ValueError, match='Valid port is required'):
            manager.create_session(
                type='tcp',
                target='192.168.45.150',
                port=0
            )

    def test_create_session_invalid_type(self, manager):
        """Should raise ValueError for invalid type"""
        with pytest.raises(ValueError, match='Invalid session type'):
            manager.create_session(
                type='invalid',
                target='192.168.45.150',
                port=4444
            )


class TestSessionRetrieval:
    """Test session retrieval and listing"""

    def test_get_session_by_id(self, manager):
        """Should retrieve session by full ID"""
        session = manager.create_session(
            type='tcp',
            target='192.168.45.150',
            port=4444
        )

        retrieved = manager.get_session(session.id)

        assert retrieved is not None
        assert retrieved.id == session.id
        assert retrieved.target == session.target

    def test_get_session_by_prefix(self, manager):
        """Should retrieve session by ID prefix"""
        session = manager.create_session(
            type='tcp',
            target='192.168.45.150',
            port=4444
        )

        prefix = session.id[:8]
        retrieved = manager.get_session(prefix)

        assert retrieved is not None
        assert retrieved.id == session.id

    def test_get_nonexistent_session(self, manager):
        """Should return None for nonexistent session"""
        result = manager.get_session('nonexistent-id')
        assert result is None

    def test_list_all_sessions(self, manager):
        """Should list all sessions"""
        session1 = manager.create_session(type='tcp', target='192.168.45.150', port=4444)
        session2 = manager.create_session(type='tcp', target='192.168.45.151', port=4445)

        sessions = manager.list_sessions()

        assert len(sessions) == 2
        session_ids = [s.id for s in sessions]
        assert session1.id in session_ids
        assert session2.id in session_ids

    def test_list_sessions_filter_by_status(self, manager):
        """Should filter sessions by status"""
        active_session = manager.create_session(type='tcp', target='192.168.45.150', port=4444)
        dead_session = manager.create_session(type='tcp', target='192.168.45.151', port=4445)

        manager.update_session(dead_session.id, {'status': 'dead'})

        active_sessions = manager.list_sessions({'status': 'active'})

        assert len(active_sessions) == 1
        assert active_sessions[0].id == active_session.id

    def test_list_sessions_filter_by_type(self, manager):
        """Should filter sessions by type"""
        tcp_session = manager.create_session(type='tcp', target='192.168.45.150', port=4444)
        http_session = manager.create_session(type='http', target='192.168.45.151', port=8080)

        tcp_sessions = manager.list_sessions({'type': 'tcp'})

        assert len(tcp_sessions) == 1
        assert tcp_sessions[0].id == tcp_session.id

    def test_list_sessions_filter_by_target(self, manager):
        """Should filter sessions by target"""
        target1_session = manager.create_session(type='tcp', target='192.168.45.150', port=4444)
        target2_session = manager.create_session(type='tcp', target='192.168.45.151', port=4444)

        target1_sessions = manager.list_sessions({'target': '192.168.45.150'})

        assert len(target1_sessions) == 1
        assert target1_sessions[0].id == target1_session.id

    def test_list_sessions_active_only_filter(self, manager):
        """Should filter active sessions only"""
        active = manager.create_session(type='tcp', target='192.168.45.150', port=4444)
        dead = manager.create_session(type='tcp', target='192.168.45.151', port=4445)

        manager.update_session(dead.id, {'status': 'dead'})

        active_only = manager.list_sessions({'active_only': True})

        assert len(active_only) == 1
        assert active_only[0].id == active.id


class TestSessionUpdates:
    """Test session updates"""

    def test_update_session_status(self, manager):
        """Should update session status"""
        session = manager.create_session(type='tcp', target='192.168.45.150', port=4444)

        updated = manager.update_session(session.id, {'status': 'upgrading'})

        assert updated.status == 'upgrading'

    def test_update_session_shell_type(self, manager):
        """Should update shell type"""
        session = manager.create_session(type='tcp', target='192.168.45.150', port=4444)

        updated = manager.update_session(session.id, {'shell_type': 'bash'})

        assert updated.shell_type == 'bash'

    def test_update_session_capabilities(self, manager):
        """Should update session capabilities"""
        session = manager.create_session(type='tcp', target='192.168.45.150', port=4444)

        caps = ShellCapabilities(
            has_pty=True,
            shell_type='bash',
            detected_tools=['python3', 'socat']
        )

        updated = manager.update_session(session.id, {
            'capabilities': caps.to_dict()
        })

        assert updated.capabilities.has_pty is True
        assert updated.capabilities.shell_type == 'bash'
        assert 'python3' in updated.capabilities.detected_tools

    def test_update_session_metadata(self, manager):
        """Should merge metadata updates"""
        session = manager.create_session(
            type='tcp',
            target='192.168.45.150',
            port=4444,
            metadata={'key1': 'value1'}
        )

        updated = manager.update_session(session.id, {
            'metadata': {'key2': 'value2'}
        })

        assert updated.metadata['key1'] == 'value1'
        assert updated.metadata['key2'] == 'value2'

    def test_update_nonexistent_session(self, manager):
        """Should raise ValueError for nonexistent session"""
        with pytest.raises(ValueError, match='Session not found'):
            manager.update_session('nonexistent-id', {'status': 'dead'})

    def test_update_emits_event_on_death(self, manager):
        """Should emit SESSION_DIED when status changes to dead"""
        events = []

        def capture_event(data):
            events.append(data)

        EventBus.subscribe(SessionEvent.SESSION_DIED, capture_event)

        session = manager.create_session(type='tcp', target='192.168.45.150', port=4444)

        manager.update_session(session.id, {'status': 'dead'})

        assert len(events) == 1
        assert events[0]['session_id'] == session.id


class TestSessionKill:
    """Test session killing"""

    def test_kill_active_session(self, manager):
        """Should kill active session"""
        session = manager.create_session(type='tcp', target='192.168.45.150', port=4444)

        result = manager.kill_session(session.id)

        assert result is True

        killed_session = manager.get_session(session.id)
        assert killed_session.status == 'dead'

    def test_kill_dead_session(self, manager):
        """Should return False for already dead session"""
        session = manager.create_session(type='tcp', target='192.168.45.150', port=4444)

        manager.kill_session(session.id)

        # Try killing again
        result = manager.kill_session(session.id)
        assert result is False

    def test_kill_nonexistent_session(self, manager):
        """Should return False for nonexistent session"""
        result = manager.kill_session('nonexistent-id')
        assert result is False

    def test_kill_emits_event(self, manager):
        """Should emit SESSION_DIED on kill"""
        events = []

        def capture_event(data):
            events.append(data)

        EventBus.subscribe(SessionEvent.SESSION_DIED, capture_event)

        session = manager.create_session(type='tcp', target='192.168.45.150', port=4444)

        manager.kill_session(session.id)

        assert len(events) == 1
        assert events[0]['session_id'] == session.id
        assert events[0]['reason'] == 'Manual termination'


class TestDeadSessionCleanup:
    """Test dead session cleanup"""

    def test_cleanup_finds_dead_pid(self, manager):
        """Should mark sessions with invalid PIDs as dead"""
        # Create session with fake dead PID
        session = manager.create_session(
            type='tcp',
            target='192.168.45.150',
            port=4444,
            pid=99999  # Unlikely to exist
        )

        cleaned = manager.cleanup_dead_sessions()

        assert cleaned == 1

        updated_session = manager.get_session(session.id)
        assert updated_session.status == 'dead'

    def test_cleanup_ignores_already_dead(self, manager):
        """Should not count already dead sessions"""
        session = manager.create_session(type='tcp', target='192.168.45.150', port=4444)

        manager.update_session(session.id, {'status': 'dead'})

        cleaned = manager.cleanup_dead_sessions()

        assert cleaned == 0


class TestSessionStats:
    """Test session statistics"""

    def test_get_stats(self, manager):
        """Should return session statistics"""
        tcp1 = manager.create_session(type='tcp', target='192.168.45.150', port=4444)
        tcp2 = manager.create_session(type='tcp', target='192.168.45.151', port=4445)
        http = manager.create_session(type='http', target='192.168.45.152', port=8080)

        manager.update_session(tcp2.id, {'status': 'dead'})

        stats = manager.get_stats()

        assert stats['total'] == 3
        assert stats['active'] == 2
        assert stats['dead'] == 1
        assert stats['by_type']['tcp'] == 2
        assert stats['by_type']['http'] == 1
