"""
Tests for HTTP beacon listener.

Test Coverage:
- HTTP/HTTPS listener startup
- Beacon registration
- Command queuing
- Response storage
- Session management
"""

import pytest
import json
import time
import threading
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
from flask import Flask
from werkzeug.test import Client
from werkzeug.serving import WSGIRequestHandler

from crack.sessions.listeners.http_listener import HTTPListener
from crack.sessions.models import Session
from crack.sessions.events import EventBus, SessionEvent


@pytest.fixture
def mock_session_manager():
    """Mock SessionManager"""
    manager = Mock()
    manager.create_session = Mock(return_value=Session(
        id='test-session-123',
        type='http',
        target='192.168.45.150',
        port=8080,
        protocol='beacon'
    ))
    manager.update_session = Mock()
    manager.get_session = Mock()
    return manager


@pytest.fixture
def http_listener(mock_session_manager):
    """Create HTTP listener fixture"""
    listener = HTTPListener(
        port=8888,  # Use non-standard port for testing
        session_manager=mock_session_manager,
        https=False,
        host='127.0.0.1'  # Localhost only for testing
    )
    yield listener
    # Cleanup
    if listener._running:
        listener.stop()


@pytest.fixture
def https_listener(mock_session_manager, tmp_path):
    """Create HTTPS listener fixture"""
    # Mock cert generation
    cert_path = tmp_path / "test.crt"
    key_path = tmp_path / "test.key"
    cert_path.touch()
    key_path.touch()

    listener = HTTPListener(
        port=8889,
        session_manager=mock_session_manager,
        https=True,
        host='127.0.0.1',
        cert_path=cert_path,
        key_path=key_path
    )
    yield listener
    # Cleanup
    if listener._running:
        listener.stop()


class TestHTTPListenerBasics:
    """Test basic listener functionality"""

    def test_listener_initialization(self, http_listener):
        """Test listener initializes correctly"""
        assert http_listener.port == 8888
        assert http_listener.https is False
        assert http_listener.host == '127.0.0.1'
        assert http_listener.listener.protocol == 'http'
        assert http_listener.listener.port == 8888
        assert http_listener.listener.status == 'stopped'

    def test_listener_initialization_https(self, https_listener):
        """Test HTTPS listener initializes correctly"""
        assert https_listener.https is True
        assert https_listener.listener.protocol == 'https'
        assert https_listener.cert_path is not None
        assert https_listener.key_path is not None

    def test_command_queue_initialization(self, http_listener):
        """Test command queues initialize empty"""
        assert len(http_listener.command_queues) == 0
        assert len(http_listener.responses) == 0
        assert len(http_listener.session_metadata) == 0

    def test_listener_id_generation(self, http_listener):
        """Test listener ID is generated"""
        assert http_listener.listener_id is not None
        assert len(http_listener.listener_id) == 36  # UUID length


class TestListenerLifecycle:
    """Test listener start/stop/restart"""

    @patch('crack.sessions.listeners.http_listener.ListenerRegistry')
    @patch.object(Flask, 'run')  # CRITICAL: Mock Flask.run to prevent real server
    def test_listener_start(self, mock_flask_run, mock_registry_class, http_listener):
        """Test listener starts successfully"""
        # Mock registry
        mock_registry = Mock()
        mock_registry.is_port_available.return_value = True
        mock_registry_class.return_value = mock_registry
        http_listener.registry = mock_registry

        # Mock Flask run to prevent actual server startup
        mock_flask_run.return_value = None

        # Start listener (now safe with mocked Flask)
        result = http_listener.start()

        assert result is True
        assert http_listener._running is True
        assert http_listener.listener.status == 'running'

        # Verify Flask.run was called with correct params
        mock_flask_run.assert_called_once()
        call_kwargs = mock_flask_run.call_args[1]
        assert call_kwargs['host'] == '127.0.0.1'
        assert call_kwargs['port'] == 8888
        assert call_kwargs['threaded'] is True
        assert call_kwargs['use_reloader'] is False

        # Stop
        http_listener.stop()

    def test_listener_stop(self, http_listener):
        """Test listener stops gracefully"""
        http_listener._running = True
        http_listener.listener.start()

        result = http_listener.stop()

        assert result is True
        assert http_listener._running is False
        assert http_listener.listener.status == 'stopped'

    def test_listener_status(self, http_listener):
        """Test status method"""
        assert http_listener.status() == 'stopped'

        http_listener.listener.start()
        assert http_listener.status() == 'running'

        http_listener.listener.stop()
        assert http_listener.status() == 'stopped'


class TestBeaconRegistration:
    """Test beacon registration flow"""

    def test_create_beacon_session(self, http_listener, mock_session_manager):
        """Test beacon session creation"""
        data = {
            'target': '192.168.45.150',
            'hostname': 'victim-pc',
            'username': 'www-data',
            'os': 'Linux',
            'shell_type': 'bash'
        }

        # Use Flask test request context to avoid "outside of request context" error
        with http_listener.app.test_request_context():
            session = http_listener._create_beacon_session(data)

        assert session.type == 'http'
        assert session.target == '192.168.45.150'
        assert session.protocol == 'beacon'

        # Verify session manager called with correct metadata
        mock_session_manager.create_session.assert_called_once()
        call_kwargs = mock_session_manager.create_session.call_args[1]
        assert call_kwargs['metadata']['hostname'] == 'victim-pc'
        assert call_kwargs['metadata']['username'] == 'www-data'
        assert call_kwargs['metadata']['os'] == 'Linux'

    def test_session_metadata_tracking(self, http_listener):
        """Test session metadata updates"""
        session_id = 'test-123'
        data = {
            'hostname': 'test-host',
            'username': 'test-user',
            'os': 'Linux',
            'shell_type': 'bash'
        }

        http_listener._update_session_metadata(session_id, data)

        assert session_id in http_listener.session_metadata
        assert http_listener.session_metadata[session_id]['hostname'] == 'test-host'
        assert http_listener.session_metadata[session_id]['username'] == 'test-user'
        assert 'last_seen' in http_listener.session_metadata[session_id]


class TestCommandQueueing:
    """Test command queue functionality"""

    def test_send_command(self, http_listener):
        """Test command queueing"""
        session_id = 'test-123'
        http_listener.command_queues[session_id] = []

        http_listener.send_command(session_id, 'whoami')

        assert len(http_listener.command_queues[session_id]) == 1
        assert http_listener.command_queues[session_id][0] == 'whoami'

    def test_send_multiple_commands(self, http_listener):
        """Test multiple commands queue in order"""
        session_id = 'test-123'
        http_listener.command_queues[session_id] = []

        http_listener.send_command(session_id, 'whoami')
        http_listener.send_command(session_id, 'id')
        http_listener.send_command(session_id, 'hostname')

        assert len(http_listener.command_queues[session_id]) == 3
        assert http_listener.command_queues[session_id] == ['whoami', 'id', 'hostname']

    def test_get_next_command(self, http_listener):
        """Test command retrieval (FIFO)"""
        session_id = 'test-123'
        http_listener.command_queues[session_id] = ['whoami', 'id', 'hostname']

        cmd1 = http_listener._get_next_command(session_id)
        assert cmd1 == 'whoami'
        assert len(http_listener.command_queues[session_id]) == 2

        cmd2 = http_listener._get_next_command(session_id)
        assert cmd2 == 'id'
        assert len(http_listener.command_queues[session_id]) == 1

    def test_get_next_command_empty_queue(self, http_listener):
        """Test get command from empty queue"""
        session_id = 'test-123'
        http_listener.command_queues[session_id] = []

        cmd = http_listener._get_next_command(session_id)
        assert cmd is None

    def test_send_command_nonexistent_session(self, http_listener):
        """Test sending command to nonexistent session"""
        with pytest.raises(ValueError, match="Session .* not found"):
            http_listener.send_command('nonexistent-123', 'whoami')


class TestResponseStorage:
    """Test response storage functionality"""

    def test_store_response(self, http_listener):
        """Test storing command response"""
        session_id = 'test-123'

        http_listener._store_response(session_id, 'root')

        assert session_id in http_listener.responses
        assert len(http_listener.responses[session_id]) == 1
        assert http_listener.responses[session_id][0]['output'] == 'root'
        assert 'timestamp' in http_listener.responses[session_id][0]

    def test_store_multiple_responses(self, http_listener):
        """Test storing multiple responses"""
        session_id = 'test-123'

        http_listener._store_response(session_id, 'response1')
        http_listener._store_response(session_id, 'response2')
        http_listener._store_response(session_id, 'response3')

        assert len(http_listener.responses[session_id]) == 3

    def test_response_limit(self, http_listener):
        """Test response storage limit (100 max)"""
        session_id = 'test-123'

        # Store 105 responses
        for i in range(105):
            http_listener._store_response(session_id, f'response{i}')

        # Should keep only last 100
        assert len(http_listener.responses[session_id]) == 100
        # First response should be response5 (0-4 dropped)
        assert http_listener.responses[session_id][0]['output'] == 'response5'

    def test_get_response(self, http_listener):
        """Test getting response"""
        session_id = 'test-123'
        http_listener._store_response(session_id, 'response1')
        http_listener._store_response(session_id, 'response2')

        # Get last response
        last = http_listener.get_response(session_id)
        assert last['output'] == 'response2'

        # Get first response
        first = http_listener.get_response(session_id, index=0)
        assert first['output'] == 'response1'

    def test_get_all_responses(self, http_listener):
        """Test getting all responses"""
        session_id = 'test-123'
        http_listener._store_response(session_id, 'response1')
        http_listener._store_response(session_id, 'response2')

        responses = http_listener.get_all_responses(session_id)

        assert len(responses) == 2
        assert responses[0]['output'] == 'response1'
        assert responses[1]['output'] == 'response2'

    def test_clear_responses(self, http_listener):
        """Test clearing response history"""
        session_id = 'test-123'
        http_listener._store_response(session_id, 'response1')
        http_listener._store_response(session_id, 'response2')

        http_listener.clear_responses(session_id)

        assert len(http_listener.responses[session_id]) == 0


class TestSessionInfo:
    """Test session info retrieval"""

    def test_get_session_info(self, http_listener):
        """Test getting session metadata"""
        session_id = 'test-123'
        http_listener.session_metadata[session_id] = {
            'hostname': 'victim-pc',
            'username': 'www-data',
            'os': 'Linux'
        }

        info = http_listener.get_session_info(session_id)

        assert info['hostname'] == 'victim-pc'
        assert info['username'] == 'www-data'
        assert info['os'] == 'Linux'

    def test_get_active_sessions(self, http_listener):
        """Test listing active sessions"""
        http_listener.session_metadata['session-1'] = {'hostname': 'host1'}
        http_listener.session_metadata['session-2'] = {'hostname': 'host2'}
        http_listener.session_metadata['session-3'] = {'hostname': 'host3'}

        active = http_listener.get_active_sessions()

        assert len(active) == 3
        assert 'session-1' in active
        assert 'session-2' in active
        assert 'session-3' in active


class TestEventEmission:
    """Test event emission"""

    @patch.object(Flask, 'run')  # CRITICAL: Mock Flask.run to prevent real server
    def test_listener_started_event(self, mock_flask_run, http_listener):
        """Test LISTENER_STARTED event emission"""
        event_data = {}

        def capture_event(data):
            event_data.update(data)

        EventBus.subscribe(SessionEvent.LISTENER_STARTED, capture_event)

        # Mock Flask run to prevent actual server startup
        mock_flask_run.return_value = None

        # Mock port availability
        with patch.object(http_listener.registry, 'is_port_available', return_value=True):
            with patch.object(http_listener.registry, 'register_listener'):
                # Start listener (now safe with mocked Flask)
                result = http_listener.start()

                assert result is True
                assert 'listener_id' in event_data
                assert event_data['port'] == 8888
                assert event_data['protocol'] == 'http'

                http_listener.stop()

        EventBus.clear(SessionEvent.LISTENER_STARTED)

    def test_connection_callback(self, http_listener):
        """Test connection callback invocation"""
        callback_data = {}

        def connection_callback(session_id):
            callback_data['session_id'] = session_id

        http_listener.on_connection(connection_callback)

        # Simulate beacon registration
        data = {
            'hostname': 'test-host',
            'username': 'test-user',
            'os': 'Linux',
            'shell_type': 'bash',
            'target': '192.168.45.151'  # Add target to avoid needing request context
        }

        # Use Flask test request context to avoid "outside of request context" error
        with http_listener.app.test_request_context():
            session = http_listener._create_beacon_session(data)

        # Trigger callbacks
        for cb in http_listener._connection_callbacks:
            cb(session.id)

        assert callback_data['session_id'] == session.id


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
