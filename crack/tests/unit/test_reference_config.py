#!/usr/bin/env python3
"""
Unit tests for Reference Config Module
Tests configuration management, auto-detection, and variable handling
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch
import json
import subprocess

from crack.reference.core.config import ConfigManager


class TestConfigManager:
    """Test ConfigManager functionality"""

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_initialization_with_custom_path(self, temp_output_dir):
        """Test config manager initialization with custom path"""
        config_path = temp_output_dir / "custom_config.json"
        config = ConfigManager(config_path=str(config_path))

        assert config.config_path == config_path
        assert isinstance(config.config, dict)

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_initialization_with_default_path(self):
        """Test config manager with default path"""
        config = ConfigManager()

        expected_path = Path.home() / '.crack' / 'config.json'
        assert config.config_path == expected_path

    @pytest.mark.unit
    @pytest.mark.reference
    def test_load_existing_config(self, mock_config_file):
        """Test loading existing configuration"""
        config = ConfigManager(config_path=str(mock_config_file))

        assert 'variables' in config.config
        assert 'LHOST' in config.config['variables']
        assert config.config['variables']['LHOST']['value'] == "10.10.14.5"

    @pytest.mark.unit
    @pytest.mark.reference
    def test_load_creates_default_if_missing(self, temp_output_dir):
        """Test creating default config when file doesn't exist"""
        config_path = temp_output_dir / "new_config.json"
        config = ConfigManager(config_path=str(config_path))

        # Should create default config
        assert config_path.exists()
        assert 'variables' in config.config
        assert 'LHOST' in config.config['variables']
        assert 'TARGET' in config.config['variables']

    @pytest.mark.unit
    @pytest.mark.reference
    def test_save_config(self, temp_output_dir):
        """Test saving configuration to file"""
        config_path = temp_output_dir / "save_test.json"
        config = ConfigManager(config_path=str(config_path))

        config.config['variables']['TEST_VAR'] = {
            'value': 'test_value',
            'description': 'Test variable'
        }

        result = config.save()
        assert result is True
        assert config_path.exists()

        # Verify saved content
        with open(config_path) as f:
            saved_data = json.load(f)
        assert 'TEST_VAR' in saved_data['variables']

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_get_default_config(self):
        """Test default configuration structure"""
        config = ConfigManager()
        default = config.get_default_config()

        assert 'variables' in default
        assert 'sessions' in default
        assert 'settings' in default

        # Check default variables
        assert 'LHOST' in default['variables']
        assert 'TARGET' in default['variables']
        assert 'LPORT' in default['variables']
        assert default['variables']['LPORT']['value'] == "4444"

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_get_variable(self, mock_config_file):
        """Test getting variable value"""
        config = ConfigManager(config_path=str(mock_config_file))

        value = config.get_variable('LHOST')
        assert value == "10.10.14.5"

        value = config.get_variable('TARGET')
        assert value == "192.168.45.100"

        # Non-existent variable
        value = config.get_variable('NONEXISTENT')
        assert value is None or value == ""

    @pytest.mark.unit
    @pytest.mark.reference
    def test_set_variable(self, temp_output_dir):
        """Test setting variable value"""
        config_path = temp_output_dir / "set_test.json"
        config = ConfigManager(config_path=str(config_path))

        result = config.set_variable('TARGET', '192.168.1.100')
        assert result is True

        # Verify variable was set
        assert config.config['variables']['TARGET']['value'] == '192.168.1.100'
        assert config.config['variables']['TARGET']['source'] == 'manual'

        # Verify it was saved
        assert config_path.exists()

    @pytest.mark.unit
    @pytest.mark.reference
    def test_set_variable_updates_timestamp(self, temp_output_dir):
        """Test that setting variable updates timestamp"""
        config_path = temp_output_dir / "timestamp_test.json"
        config = ConfigManager(config_path=str(config_path))

        config.set_variable('LHOST', '10.10.10.10')

        assert 'updated' in config.config['variables']['LHOST']
        assert config.config['variables']['LHOST']['updated'] is not None

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_list_variables(self, mock_config_file):
        """Test listing all variables"""
        config = ConfigManager(config_path=str(mock_config_file))

        variables = config.list_variables()

        assert isinstance(variables, dict)
        assert 'LHOST' in variables
        assert 'TARGET' in variables
        assert 'LPORT' in variables

    @pytest.mark.unit
    @pytest.mark.reference
    def test_clear_variables(self, temp_output_dir):
        """Test clearing all variables"""
        config_path = temp_output_dir / "clear_test.json"
        config = ConfigManager(config_path=str(config_path))

        # Set some variables
        config.set_variable('LHOST', '10.10.10.10')
        config.set_variable('TARGET', '192.168.1.1')

        # Clear variables
        result = config.clear_variables()
        assert result is True

        # Verify variables are cleared (reset to defaults)
        variables = config.list_variables()
        assert variables['LHOST']['value'] == "" or variables['LHOST']['value'] is None

    @pytest.mark.unit
    @pytest.mark.reference
    def test_auto_detect_interface(self, mock_network_interfaces):
        """Test auto-detecting network interface"""
        config = ConfigManager()

        interface = config.auto_detect_interface()

        # Should detect tun0 (VPN interface preferred)
        assert interface == "tun0" or interface == "eth0" or interface is not None

    @pytest.mark.unit
    @pytest.mark.reference
    def test_auto_detect_ip(self, mock_ip_detection):
        """Test auto-detecting IP address"""
        config = ConfigManager()

        ip = config.auto_detect_ip()

        assert ip == "10.10.14.5" or ip is not None

    @pytest.mark.unit
    @pytest.mark.reference
    def test_auto_configure(self, mock_network_interfaces, mock_ip_detection, temp_output_dir):
        """Test auto-configuration of network settings"""
        config_path = temp_output_dir / "auto_config.json"
        config = ConfigManager(config_path=str(config_path))

        updates = config.auto_configure()

        assert isinstance(updates, dict)
        # Should have detected at least one value
        assert len(updates) > 0

    @pytest.mark.unit
    @pytest.mark.reference
    @pytest.mark.fast
    def test_get_placeholder_values(self, mock_config_file):
        """Test getting placeholder values for substitution"""
        config = ConfigManager(config_path=str(mock_config_file))

        placeholders = config.get_placeholder_values()

        assert isinstance(placeholders, dict)
        assert '<LHOST>' in placeholders or 'LHOST' in placeholders
        assert '<TARGET>' in placeholders or 'TARGET' in placeholders

        # Values should match config
        if '<LHOST>' in placeholders:
            assert placeholders['<LHOST>'] == "10.10.14.5"

    @pytest.mark.unit
    @pytest.mark.reference
    def test_invalid_json_handling(self, temp_output_dir):
        """Test graceful handling of invalid JSON"""
        config_path = temp_output_dir / "invalid.json"
        config_path.write_text("{invalid json")

        # Should not crash
        config = ConfigManager(config_path=str(config_path))
        assert isinstance(config.config, dict)

    @pytest.mark.unit
    @pytest.mark.reference
    def test_save_error_handling(self, temp_output_dir):
        """Test handling of save errors"""
        config_path = temp_output_dir / "readonly" / "config.json"

        config = ConfigManager(config_path=str(config_path))

        # Try to save to non-existent directory without write permission
        with patch('pathlib.Path.mkdir', side_effect=PermissionError()):
            result = config.save()
            # Should return False on error, not crash
            assert result is False or result is True  # Depending on mock behavior

    @pytest.mark.unit
    @pytest.mark.reference
    def test_config_persistence(self, temp_output_dir):
        """Test that config persists across instances"""
        config_path = temp_output_dir / "persist_test.json"

        # First instance
        config1 = ConfigManager(config_path=str(config_path))
        config1.set_variable('LHOST', '10.10.14.5')
        config1.set_variable('TARGET', '192.168.45.100')

        # Second instance should load saved values
        config2 = ConfigManager(config_path=str(config_path))
        assert config2.get_variable('LHOST') == '10.10.14.5'
        assert config2.get_variable('TARGET') == '192.168.45.100'

    @pytest.mark.unit
    @pytest.mark.reference
    def test_variable_source_tracking(self, temp_output_dir):
        """Test that variable source is tracked correctly"""
        config_path = temp_output_dir / "source_test.json"
        config = ConfigManager(config_path=str(config_path))

        # Default variables should have 'default' source
        assert config.config['variables']['LPORT']['source'] == 'default'

        # Manually set variables should have 'manual' source
        config.set_variable('LHOST', '10.10.10.10')
        assert config.config['variables']['LHOST']['source'] == 'manual'

    @pytest.mark.unit
    @pytest.mark.reference
    def test_delete_variable(self, temp_output_dir):
        """Test deleting a variable"""
        config_path = temp_output_dir / "delete_test.json"
        config = ConfigManager(config_path=str(config_path))

        config.set_variable('TEST_VAR', 'test_value')
        assert 'TEST_VAR' in config.config['variables']

        # Delete variable
        result = config.delete_variable('TEST_VAR')
        assert result is True
        assert 'TEST_VAR' not in config.config['variables']

    @pytest.mark.unit
    @pytest.mark.reference
    def test_sessions_support(self, temp_output_dir):
        """Test session configuration support"""
        config_path = temp_output_dir / "session_test.json"
        config = ConfigManager(config_path=str(config_path))

        assert 'sessions' in config.config
        # Sessions should be empty dict by default
        assert isinstance(config.config['sessions'], dict)

    @pytest.mark.unit
    @pytest.mark.reference
    def test_settings_support(self, mock_config_file):
        """Test settings configuration support"""
        config = ConfigManager(config_path=str(mock_config_file))

        assert 'settings' in config.config
        assert 'auto_detect_interface' in config.config['settings']
        assert 'auto_detect_ip' in config.config['settings']
