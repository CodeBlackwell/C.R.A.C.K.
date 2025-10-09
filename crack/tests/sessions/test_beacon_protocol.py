"""
Tests for beacon protocol and script generation.

Test Coverage:
- Beacon script generation (all types)
- Variable substitution
- Registration payload creation
- Script templates
"""

import pytest
import uuid

from crack.sessions.listeners.beacon_protocol import BeaconProtocol


class TestBeaconScriptGeneration:
    """Test beacon script generation"""

    def test_generate_bash_beacon(self):
        """Test bash beacon generation"""
        protocol = BeaconProtocol()
        session_id = str(uuid.uuid4())

        script = protocol.generate_beacon_script(
            beacon_type='bash',
            listener_url='http://192.168.45.150:8080',
            session_id=session_id,
            interval=5,
            jitter=0
        )

        assert script is not None
        assert '#!/bin/bash' in script
        assert session_id in script
        assert 'http://192.168.45.150:8080/beacon' in script
        assert 'INTERVAL=5' in script
        assert 'curl' in script or 'wget' in script

    def test_generate_php_beacon(self):
        """Test PHP beacon generation"""
        protocol = BeaconProtocol()
        session_id = str(uuid.uuid4())

        script = protocol.generate_beacon_script(
            beacon_type='php',
            listener_url='http://192.168.45.150:8080',
            session_id=session_id,
            interval=5
        )

        assert script is not None
        assert '<?php' in script
        assert session_id in script
        assert 'http://192.168.45.150:8080/beacon' in script
        assert '$interval = 5' in script
        assert 'curl_init' in script

    def test_generate_php_web_beacon(self):
        """Test PHP web shell beacon generation"""
        protocol = BeaconProtocol()
        session_id = str(uuid.uuid4())

        script = protocol.generate_beacon_script(
            beacon_type='php_web',
            listener_url='http://192.168.45.150:8080',
            session_id=session_id,
            interval=5
        )

        assert script is not None
        assert '<?php' in script
        assert session_id in script
        assert 'beacon=1' in script  # Beacon trigger parameter
        assert '<form' in script  # Web shell form
        assert 'setInterval' in script  # JavaScript auto-beacon

    def test_generate_powershell_beacon(self):
        """Test PowerShell beacon generation"""
        protocol = BeaconProtocol()
        session_id = str(uuid.uuid4())

        script = protocol.generate_beacon_script(
            beacon_type='powershell',
            listener_url='http://192.168.45.150:8080',
            session_id=session_id,
            interval=5
        )

        assert script is not None
        assert session_id in script
        assert 'http://192.168.45.150:8080/beacon' in script
        assert '$Interval = 5' in script
        assert 'Invoke-RestMethod' in script or 'Invoke-WebRequest' in script

    def test_generate_python_beacon(self):
        """Test Python beacon generation"""
        protocol = BeaconProtocol()
        session_id = str(uuid.uuid4())

        script = protocol.generate_beacon_script(
            beacon_type='python',
            listener_url='http://192.168.45.150:8080',
            session_id=session_id,
            interval=5
        )

        assert script is not None
        assert '#!/usr/bin/env python3' in script or 'import' in script
        assert session_id in script
        assert 'http://192.168.45.150:8080/beacon' in script
        assert 'INTERVAL = 5' in script
        assert 'requests' in script or 'urllib' in script

    def test_unsupported_beacon_type(self):
        """Test error on unsupported beacon type"""
        protocol = BeaconProtocol()

        with pytest.raises(ValueError, match="Unsupported beacon type"):
            protocol.generate_beacon_script(
                beacon_type='invalid',
                listener_url='http://192.168.45.150:8080',
                session_id='test',
                interval=5
            )


class TestBeaconConfiguration:
    """Test beacon configuration options"""

    def test_beacon_interval_configuration(self):
        """Test interval configuration"""
        protocol = BeaconProtocol()

        script = protocol.generate_beacon_script(
            beacon_type='bash',
            listener_url='http://192.168.45.150:8080',
            session_id='test',
            interval=10
        )

        assert 'INTERVAL=10' in script

    def test_beacon_jitter_configuration(self):
        """Test jitter configuration"""
        protocol = BeaconProtocol()

        script = protocol.generate_beacon_script(
            beacon_type='bash',
            listener_url='http://192.168.45.150:8080',
            session_id='test',
            interval=5,
            jitter=3
        )

        assert 'RANDOM % 3' in script or 'jitter' in script.lower()

    def test_beacon_zero_jitter(self):
        """Test zero jitter (no randomization)"""
        protocol = BeaconProtocol()

        script = protocol.generate_beacon_script(
            beacon_type='bash',
            listener_url='http://192.168.45.150:8080',
            session_id='test',
            interval=5,
            jitter=0
        )

        assert script is not None
        # Should not include jitter logic
        assert 'SLEEP_TIME=$INTERVAL' in script


class TestRegistrationPayload:
    """Test registration payload creation"""

    def test_create_registration_payload(self):
        """Test registration payload creation"""
        payload = BeaconProtocol.create_registration_payload(
            target='192.168.45.150',
            hostname='victim-pc',
            username='www-data',
            os_type='Linux',
            shell_type='bash'
        )

        assert payload['target'] == '192.168.45.150'
        assert payload['hostname'] == 'victim-pc'
        assert payload['username'] == 'www-data'
        assert payload['os'] == 'Linux'
        assert payload['shell_type'] == 'bash'

    def test_create_registration_payload_auto_detect(self):
        """Test registration payload with auto-detected values"""
        payload = BeaconProtocol.create_registration_payload(
            target='192.168.45.150'
        )

        assert payload['target'] == '192.168.45.150'
        assert 'hostname' in payload
        assert 'username' in payload
        assert 'os' in payload
        assert 'shell_type' in payload


class TestScriptStructure:
    """Test beacon script structure and components"""

    def test_bash_beacon_structure(self):
        """Test bash beacon has required components"""
        protocol = BeaconProtocol()
        session_id = 'test-123'

        script = protocol.generate_beacon_script(
            beacon_type='bash',
            listener_url='http://192.168.45.150:8080',
            session_id=session_id,
            interval=5
        )

        # Required components
        assert 'SESSION_ID=' in script
        assert 'BEACON_URL=' in script
        assert 'INTERVAL=' in script
        assert 'while true' in script or 'while :' in script
        assert 'curl' in script or 'wget' in script
        assert 'sleep' in script

        # System info gathering
        assert 'hostname' in script.lower()
        assert 'whoami' in script.lower()
        assert 'uname' in script.lower()

    def test_php_beacon_structure(self):
        """Test PHP beacon has required components"""
        protocol = BeaconProtocol()

        script = protocol.generate_beacon_script(
            beacon_type='php',
            listener_url='http://192.168.45.150:8080',
            session_id='test-123',
            interval=5
        )

        # Required components
        assert '$session_id' in script
        assert '$beacon_url' in script
        assert '$interval' in script
        assert 'while (true)' in script
        assert 'curl_init' in script
        assert 'json_encode' in script
        assert 'sleep' in script

    def test_powershell_beacon_structure(self):
        """Test PowerShell beacon has required components"""
        protocol = BeaconProtocol()

        script = protocol.generate_beacon_script(
            beacon_type='powershell',
            listener_url='http://192.168.45.150:8080',
            session_id='test-123',
            interval=5
        )

        # Required components
        assert '$SessionId' in script
        assert '$BeaconUrl' in script
        assert '$Interval' in script
        assert 'while ($true)' in script
        assert 'Invoke-RestMethod' in script or 'Invoke-WebRequest' in script
        assert 'ConvertTo-Json' in script
        assert 'Start-Sleep' in script

    def test_python_beacon_structure(self):
        """Test Python beacon has required components"""
        protocol = BeaconProtocol()

        script = protocol.generate_beacon_script(
            beacon_type='python',
            listener_url='http://192.168.45.150:8080',
            session_id='test-123',
            interval=5
        )

        # Required components
        assert 'SESSION_ID' in script
        assert 'BEACON_URL' in script
        assert 'INTERVAL' in script
        assert 'while True' in script
        assert 'import' in script
        assert 'json' in script
        assert 'time.sleep' in script


class TestEncryption:
    """Test encryption functionality (future feature)"""

    def test_encrypt_payload_base64(self):
        """Test payload encryption (currently base64)"""
        protocol = BeaconProtocol()

        encrypted = protocol.encrypt_payload('test data', 'key')

        assert encrypted != 'test data'
        assert encrypted is not None

    def test_decrypt_payload_base64(self):
        """Test payload decryption (currently base64)"""
        protocol = BeaconProtocol()

        encrypted = protocol.encrypt_payload('test data', 'key')
        decrypted = protocol.decrypt_payload(encrypted, 'key')

        assert decrypted == 'test data'


class TestBeaconTypes:
    """Test all beacon types generate valid scripts"""

    @pytest.mark.parametrize('beacon_type', [
        'bash',
        'php',
        'php_web',
        'powershell',
        'python'
    ])
    def test_all_beacon_types(self, beacon_type):
        """Test all beacon types generate without errors"""
        protocol = BeaconProtocol()

        script = protocol.generate_beacon_script(
            beacon_type=beacon_type,
            listener_url='http://192.168.45.150:8080',
            session_id='test-123',
            interval=5
        )

        assert script is not None
        assert len(script) > 100  # Should be a substantial script
        assert 'test-123' in script
        assert '192.168.45.150' in script


class TestEdgeCases:
    """Test edge cases and error handling"""

    def test_https_listener_url(self):
        """Test HTTPS listener URL"""
        protocol = BeaconProtocol()

        script = protocol.generate_beacon_script(
            beacon_type='bash',
            listener_url='https://192.168.45.150:443',
            session_id='test-123',
            interval=5
        )

        assert 'https://192.168.45.150:443/beacon' in script

    def test_custom_port(self):
        """Test custom port in listener URL"""
        protocol = BeaconProtocol()

        script = protocol.generate_beacon_script(
            beacon_type='bash',
            listener_url='http://192.168.45.150:9999',
            session_id='test-123',
            interval=5
        )

        assert '9999' in script

    def test_long_session_id(self):
        """Test long session ID (UUID)"""
        protocol = BeaconProtocol()
        session_id = str(uuid.uuid4())

        script = protocol.generate_beacon_script(
            beacon_type='bash',
            listener_url='http://192.168.45.150:8080',
            session_id=session_id,
            interval=5
        )

        assert session_id in script


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
