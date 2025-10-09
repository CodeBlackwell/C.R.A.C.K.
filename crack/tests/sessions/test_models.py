"""
Unit tests for session management models.

Tests cover:
- ShellCapabilities: Serialization, defaults, detection state
- Session: Lifecycle, status transitions, metadata, serialization
- Listener: Control operations, session tracking, serialization
"""

import unittest
from datetime import datetime
from crack.sessions.models import Session, Listener, ShellCapabilities


class TestShellCapabilities(unittest.TestCase):
    """Test ShellCapabilities dataclass."""

    def test_default_initialization(self):
        """Test default capability values."""
        caps = ShellCapabilities()

        self.assertFalse(caps.has_pty)
        self.assertFalse(caps.has_history)
        self.assertFalse(caps.has_tab_completion)
        self.assertEqual(caps.shell_type, 'unknown')
        self.assertEqual(caps.os_type, 'unknown')
        self.assertEqual(caps.detected_tools, [])

    def test_custom_initialization(self):
        """Test custom capability configuration."""
        caps = ShellCapabilities(
            has_pty=True,
            has_history=True,
            has_tab_completion=True,
            shell_type='bash',
            detected_tools=['python3', 'socat', 'script'],
            os_type='linux'
        )

        self.assertTrue(caps.has_pty)
        self.assertTrue(caps.has_history)
        self.assertTrue(caps.has_tab_completion)
        self.assertEqual(caps.shell_type, 'bash')
        self.assertEqual(caps.os_type, 'linux')
        self.assertIn('python3', caps.detected_tools)
        self.assertIn('socat', caps.detected_tools)

    def test_serialization(self):
        """Test to_dict() and from_dict() round-trip."""
        caps = ShellCapabilities(
            has_pty=True,
            shell_type='bash',
            detected_tools=['python3', 'script'],
            os_type='linux'
        )

        # Serialize
        data = caps.to_dict()
        self.assertIsInstance(data, dict)
        self.assertTrue(data['has_pty'])
        self.assertEqual(data['shell_type'], 'bash')
        self.assertEqual(data['detected_tools'], ['python3', 'script'])

        # Deserialize
        restored = ShellCapabilities.from_dict(data)
        self.assertEqual(restored.has_pty, caps.has_pty)
        self.assertEqual(restored.shell_type, caps.shell_type)
        self.assertEqual(restored.detected_tools, caps.detected_tools)
        self.assertEqual(restored.os_type, caps.os_type)


class TestSession(unittest.TestCase):
    """Test Session dataclass and lifecycle methods."""

    def test_default_initialization(self):
        """Test session creation with defaults."""
        session = Session(
            type='tcp',
            protocol='reverse',
            target='192.168.45.150',
            port=4444
        )

        self.assertIsNotNone(session.id)
        self.assertEqual(session.type, 'tcp')
        self.assertEqual(session.protocol, 'reverse')
        self.assertEqual(session.target, '192.168.45.150')
        self.assertEqual(session.port, 4444)
        self.assertEqual(session.status, 'active')
        self.assertIsNone(session.pid)
        self.assertIsNone(session.shell_type)
        self.assertIsInstance(session.capabilities, ShellCapabilities)
        self.assertIsInstance(session.metadata, dict)
        self.assertIsInstance(session.created_at, datetime)
        self.assertIsInstance(session.last_seen, datetime)

    def test_custom_initialization(self):
        """Test session with custom configuration."""
        caps = ShellCapabilities(shell_type='bash', os_type='linux')
        metadata = {'listener_id': 'listener-123', 'upgrade_method': 'python-pty'}

        session = Session(
            id='custom-session-id',
            type='tcp',
            protocol='reverse',
            target='10.10.10.100',
            port=9001,
            status='upgrading',
            pid=12345,
            shell_type='bash',
            capabilities=caps,
            metadata=metadata
        )

        self.assertEqual(session.id, 'custom-session-id')
        self.assertEqual(session.status, 'upgrading')
        self.assertEqual(session.pid, 12345)
        self.assertEqual(session.shell_type, 'bash')
        self.assertEqual(session.capabilities.shell_type, 'bash')
        self.assertEqual(session.metadata['listener_id'], 'listener-123')

    def test_is_active(self):
        """Test is_active() status check."""
        session = Session(type='tcp', target='192.168.45.150', port=4444)

        # Active status
        session.status = 'active'
        self.assertTrue(session.is_active())

        # Upgrading status
        session.status = 'upgrading'
        self.assertTrue(session.is_active())

        # Dead status
        session.status = 'dead'
        self.assertFalse(session.is_active())

        # Sleeping status
        session.status = 'sleeping'
        self.assertFalse(session.is_active())

    def test_update_last_seen(self):
        """Test last_seen timestamp update."""
        session = Session(type='tcp', target='192.168.45.150', port=4444)
        original_time = session.last_seen

        # Wait a bit and update
        import time
        time.sleep(0.01)
        session.update_last_seen()

        self.assertGreater(session.last_seen, original_time)

    def test_mark_dead(self):
        """Test marking session as dead."""
        session = Session(type='tcp', target='192.168.45.150', port=4444)
        self.assertEqual(session.status, 'active')

        session.mark_dead()

        self.assertEqual(session.status, 'dead')
        self.assertFalse(session.is_active())

    def test_mark_upgrading(self):
        """Test marking session as upgrading."""
        session = Session(type='tcp', target='192.168.45.150', port=4444)

        session.mark_upgrading()

        self.assertEqual(session.status, 'upgrading')
        self.assertTrue(session.is_active())

    def test_mark_active(self):
        """Test marking session as active."""
        session = Session(type='tcp', target='192.168.45.150', port=4444)
        session.status = 'dead'

        session.mark_active()

        self.assertEqual(session.status, 'active')
        self.assertTrue(session.is_active())

    def test_serialization(self):
        """Test to_dict() and from_dict() round-trip."""
        caps = ShellCapabilities(
            has_pty=True,
            shell_type='bash',
            detected_tools=['python3'],
            os_type='linux'
        )

        session = Session(
            id='test-session-123',
            type='tcp',
            protocol='reverse',
            target='192.168.45.150',
            port=4444,
            status='active',
            pid=12345,
            shell_type='bash',
            capabilities=caps,
            metadata={'listener_id': 'abc'}
        )

        # Serialize
        data = session.to_dict()
        self.assertIsInstance(data, dict)
        self.assertEqual(data['id'], 'test-session-123')
        self.assertEqual(data['type'], 'tcp')
        self.assertEqual(data['target'], '192.168.45.150')
        self.assertEqual(data['port'], 4444)
        self.assertEqual(data['status'], 'active')
        self.assertEqual(data['pid'], 12345)
        self.assertIsInstance(data['created_at'], str)
        self.assertIsInstance(data['last_seen'], str)
        self.assertIsInstance(data['capabilities'], dict)

        # Deserialize
        restored = Session.from_dict(data)
        self.assertEqual(restored.id, session.id)
        self.assertEqual(restored.type, session.type)
        self.assertEqual(restored.target, session.target)
        self.assertEqual(restored.port, session.port)
        self.assertEqual(restored.status, session.status)
        self.assertEqual(restored.pid, session.pid)
        self.assertEqual(restored.shell_type, session.shell_type)
        self.assertEqual(restored.capabilities.shell_type, caps.shell_type)
        self.assertEqual(restored.metadata, session.metadata)
        self.assertIsInstance(restored.created_at, datetime)
        self.assertIsInstance(restored.last_seen, datetime)

    def test_repr(self):
        """Test string representation."""
        session = Session(
            id='test-session-123456789',
            type='tcp',
            target='192.168.45.150',
            port=4444,
            status='active'
        )

        repr_str = repr(session)
        self.assertIn('test-ses', repr_str)  # First 8 chars of ID
        self.assertIn('tcp', repr_str)
        self.assertIn('192.168.45.150', repr_str)
        self.assertIn('4444', repr_str)
        self.assertIn('active', repr_str)


class TestListener(unittest.TestCase):
    """Test Listener dataclass and control methods."""

    def test_default_initialization(self):
        """Test listener creation with defaults."""
        listener = Listener(
            protocol='tcp',
            port=4444
        )

        self.assertIsNotNone(listener.id)
        self.assertEqual(listener.protocol, 'tcp')
        self.assertEqual(listener.port, 4444)
        self.assertEqual(listener.status, 'stopped')
        self.assertIsNone(listener.pid)
        self.assertEqual(listener.session_ids, [])
        self.assertIsInstance(listener.config, dict)
        self.assertIsNone(listener.started_at)
        self.assertIsNone(listener.stopped_at)

    def test_custom_initialization(self):
        """Test listener with custom configuration."""
        config = {
            'tool': 'netcat',
            'command': 'nc -nlvp 4444',
            'auto_upgrade': True
        }

        listener = Listener(
            id='listener-123',
            protocol='tcp',
            port=4444,
            status='running',
            pid=12345,
            session_ids=['session-1', 'session-2'],
            config=config
        )

        self.assertEqual(listener.id, 'listener-123')
        self.assertEqual(listener.status, 'running')
        self.assertEqual(listener.pid, 12345)
        self.assertEqual(len(listener.session_ids), 2)
        self.assertEqual(listener.config['tool'], 'netcat')

    def test_is_running(self):
        """Test is_running() status check."""
        listener = Listener(protocol='tcp', port=4444)

        # Stopped status
        listener.status = 'stopped'
        self.assertFalse(listener.is_running())

        # Running status
        listener.status = 'running'
        self.assertTrue(listener.is_running())

        # Crashed status
        listener.status = 'crashed'
        self.assertFalse(listener.is_running())

    def test_start(self):
        """Test starting listener."""
        listener = Listener(protocol='tcp', port=4444)
        self.assertEqual(listener.status, 'stopped')
        self.assertIsNone(listener.started_at)

        listener.start()

        self.assertEqual(listener.status, 'running')
        self.assertIsInstance(listener.started_at, datetime)
        self.assertIsNone(listener.stopped_at)
        self.assertTrue(listener.is_running())

    def test_stop(self):
        """Test stopping listener."""
        listener = Listener(protocol='tcp', port=4444)
        listener.start()

        listener.stop()

        self.assertEqual(listener.status, 'stopped')
        self.assertIsInstance(listener.stopped_at, datetime)
        self.assertFalse(listener.is_running())

    def test_crash(self):
        """Test marking listener as crashed."""
        listener = Listener(protocol='tcp', port=4444)
        listener.start()

        listener.crash()

        self.assertEqual(listener.status, 'crashed')
        self.assertIsInstance(listener.stopped_at, datetime)
        self.assertFalse(listener.is_running())

    def test_add_session(self):
        """Test adding session to listener."""
        listener = Listener(protocol='tcp', port=4444)
        self.assertEqual(len(listener.session_ids), 0)

        listener.add_session('session-123')

        self.assertEqual(len(listener.session_ids), 1)
        self.assertIn('session-123', listener.session_ids)

        # Adding duplicate should not create duplicate entry
        listener.add_session('session-123')
        self.assertEqual(len(listener.session_ids), 1)

    def test_remove_session(self):
        """Test removing session from listener."""
        listener = Listener(protocol='tcp', port=4444)
        listener.add_session('session-123')
        listener.add_session('session-456')

        listener.remove_session('session-123')

        self.assertEqual(len(listener.session_ids), 1)
        self.assertNotIn('session-123', listener.session_ids)
        self.assertIn('session-456', listener.session_ids)

        # Removing non-existent session should not raise error
        listener.remove_session('session-999')
        self.assertEqual(len(listener.session_ids), 1)

    def test_serialization(self):
        """Test to_dict() and from_dict() round-trip."""
        listener = Listener(
            id='listener-123',
            protocol='tcp',
            port=4444,
            status='running',
            pid=12345,
            session_ids=['session-1', 'session-2'],
            config={'tool': 'netcat'}
        )
        listener.start()

        # Serialize
        data = listener.to_dict()
        self.assertIsInstance(data, dict)
        self.assertEqual(data['id'], 'listener-123')
        self.assertEqual(data['protocol'], 'tcp')
        self.assertEqual(data['port'], 4444)
        self.assertEqual(data['status'], 'running')
        self.assertEqual(data['pid'], 12345)
        self.assertEqual(len(data['session_ids']), 2)
        self.assertIsInstance(data['started_at'], str)

        # Deserialize
        restored = Listener.from_dict(data)
        self.assertEqual(restored.id, listener.id)
        self.assertEqual(restored.protocol, listener.protocol)
        self.assertEqual(restored.port, listener.port)
        self.assertEqual(restored.status, listener.status)
        self.assertEqual(restored.pid, listener.pid)
        self.assertEqual(restored.session_ids, listener.session_ids)
        self.assertEqual(restored.config, listener.config)
        self.assertIsInstance(restored.started_at, datetime)

    def test_repr(self):
        """Test string representation."""
        listener = Listener(
            id='listener-123456789',
            protocol='tcp',
            port=4444,
            status='running'
        )
        listener.add_session('session-1')
        listener.add_session('session-2')

        repr_str = repr(listener)
        self.assertIn('listener', repr_str)
        self.assertIn('tcp', repr_str)
        self.assertIn('4444', repr_str)
        self.assertIn('running', repr_str)
        self.assertIn('2', repr_str)  # Session count


if __name__ == '__main__':
    unittest.main()
