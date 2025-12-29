"""
Tests for Reference CLI config.py - Configuration management commands

Business Value Focus:
- Users need to manage configuration variables for auto-fill
- Auto-detection saves time during setup
- Clear feedback on config changes
- Config persistence across sessions
"""

import pytest
import sys
from pathlib import Path
from io import StringIO
from unittest.mock import Mock, patch

# Add project root
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tests.reference.cli.conftest import (
    ThemeFactory, ConfigFactory, CLIAssertions
)


class TestConfigCLIInitialization:
    """Tests for ConfigCLI initialization"""

    def test_initialization_with_dependencies(self):
        """
        BV: ConfigCLI initializes with required dependencies

        Scenario:
          Given: Config manager and theme
          When: ConfigCLI is instantiated
          Then: Dependencies are stored correctly
        """
        from crack.reference.cli.config import ConfigCLI

        mock_config = ConfigFactory.create_mock()
        mock_theme = ThemeFactory.create_mock()

        config_cli = ConfigCLI(config_manager=mock_config, theme=mock_theme)

        assert config_cli.config == mock_config
        assert config_cli.theme == mock_theme


class TestHandleConfig:
    """Tests for handle_config routing"""

    def test_handle_config_list_routes_correctly(self):
        """
        BV: 'list' action routes to list_config

        Scenario:
          Given: ConfigCLI instance
          When: handle_config('list') is called
          Then: list_config is invoked
        """
        from crack.reference.cli.config import ConfigCLI

        mock_config = ConfigFactory.create_mock()
        mock_theme = ThemeFactory.create_mock()

        config_cli = ConfigCLI(config_manager=mock_config, theme=mock_theme)
        config_cli.list_config = Mock(return_value=0)

        result = config_cli.handle_config('list')

        config_cli.list_config.assert_called_once()
        assert result == 0

    def test_handle_config_edit_routes_correctly(self):
        """
        BV: 'edit' action routes to edit_config

        Scenario:
          Given: ConfigCLI instance
          When: handle_config('edit') is called
          Then: edit_config is invoked
        """
        from crack.reference.cli.config import ConfigCLI

        mock_config = ConfigFactory.create_mock()
        mock_theme = ThemeFactory.create_mock()

        config_cli = ConfigCLI(config_manager=mock_config, theme=mock_theme)
        config_cli.edit_config = Mock(return_value=0)

        result = config_cli.handle_config('edit')

        config_cli.edit_config.assert_called_once()
        assert result == 0

    def test_handle_config_auto_routes_correctly(self):
        """
        BV: 'auto' action routes to auto_config

        Scenario:
          Given: ConfigCLI instance
          When: handle_config('auto') is called
          Then: auto_config is invoked
        """
        from crack.reference.cli.config import ConfigCLI

        mock_config = ConfigFactory.create_mock()
        mock_theme = ThemeFactory.create_mock()

        config_cli = ConfigCLI(config_manager=mock_config, theme=mock_theme)
        config_cli.auto_config = Mock(return_value=0)

        result = config_cli.handle_config('auto')

        config_cli.auto_config.assert_called_once()
        assert result == 0


class TestListConfig:
    """Tests for list_config command"""

    def test_list_config_shows_all_variables(self):
        """
        BV: List displays all configured variables

        Scenario:
          Given: Config with variables
          When: list_config() is called
          Then: All variables are displayed
        """
        from crack.reference.cli.config import ConfigCLI

        variables = {
            "LHOST": {"value": "10.10.14.5", "source": "manual"},
            "TARGET": {"value": "192.168.1.100", "source": "auto"},
            "LPORT": {"value": "4444", "source": "manual"}
        }

        mock_config = ConfigFactory.create_mock(variables=variables)
        mock_theme = ThemeFactory.create_mock()

        config_cli = ConfigCLI(config_manager=mock_config, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            result = config_cli.list_config()

        assert result == 0
        output_text = output.getvalue()
        assert 'LHOST' in output_text
        assert '10.10.14.5' in output_text
        assert 'TARGET' in output_text
        assert 'LPORT' in output_text

    def test_list_config_shows_config_path(self):
        """
        BV: List shows config file location

        Scenario:
          Given: Config with known path
          When: list_config() is called
          Then: Config path is displayed
        """
        from crack.reference.cli.config import ConfigCLI

        mock_config = ConfigFactory.create_mock()
        mock_theme = ThemeFactory.create_mock()

        config_cli = ConfigCLI(config_manager=mock_config, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            config_cli.list_config()

        output_text = output.getvalue()
        assert 'config.json' in output_text or 'Config file' in output_text

    def test_list_config_handles_empty_variables(self):
        """
        BV: List handles case with no variables configured

        Scenario:
          Given: Config with no variables
          When: list_config() is called
          Then: Appropriate message is shown
        """
        from crack.reference.cli.config import ConfigCLI

        mock_config = ConfigFactory.create_mock(variables={})
        mock_theme = ThemeFactory.create_mock()

        config_cli = ConfigCLI(config_manager=mock_config, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            result = config_cli.list_config()

        assert result == 0
        output_text = output.getvalue()
        assert 'No variables' in output_text or 'not set' in output_text.lower()

    def test_list_config_shows_source_information(self):
        """
        BV: List shows where each variable came from (manual/auto)

        Scenario:
          Given: Variables with different sources
          When: list_config() is called
          Then: Source is displayed for each
        """
        from crack.reference.cli.config import ConfigCLI

        variables = {
            "LHOST": {"value": "10.10.14.5", "source": "manual"},
            "INTERFACE": {"value": "tun0", "source": "auto"}
        }

        mock_config = ConfigFactory.create_mock(variables=variables)
        mock_theme = ThemeFactory.create_mock()

        config_cli = ConfigCLI(config_manager=mock_config, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            config_cli.list_config()

        output_text = output.getvalue()
        assert 'manual' in output_text
        assert 'auto' in output_text


class TestSetConfigVar:
    """Tests for set_config_var command"""

    def test_set_config_var_success(self):
        """
        BV: Users can set configuration variables

        Scenario:
          Given: ConfigCLI instance
          When: set_config_var('LHOST', '10.10.14.5') is called
          Then: Variable is set and confirmed
        """
        from crack.reference.cli.config import ConfigCLI

        mock_config = ConfigFactory.create_mock()
        mock_theme = ThemeFactory.create_mock()

        config_cli = ConfigCLI(config_manager=mock_config, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            result = config_cli.set_config_var('LHOST', '10.10.14.5')

        assert result == 0
        mock_config.set_variable.assert_called_once_with('LHOST', '10.10.14.5')
        assert 'Set LHOST' in output.getvalue() or 'LHOST' in output.getvalue()

    def test_set_config_var_converts_to_uppercase(self):
        """
        BV: Variable names are normalized to uppercase

        Scenario:
          Given: ConfigCLI instance
          When: set_config_var('lhost', '10.10.14.5') is called
          Then: Variable is set as 'LHOST'
        """
        from crack.reference.cli.config import ConfigCLI

        mock_config = ConfigFactory.create_mock()
        mock_theme = ThemeFactory.create_mock()

        config_cli = ConfigCLI(config_manager=mock_config, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            config_cli.set_config_var('lhost', '10.10.14.5')

        # Should be called with uppercase
        mock_config.set_variable.assert_called_with('LHOST', '10.10.14.5')

    def test_set_config_var_auto_detect_lhost(self):
        """
        BV: 'auto' value triggers IP auto-detection for LHOST

        Scenario:
          Given: ConfigCLI instance
          When: set_config_var('LHOST', 'auto') is called
          Then: IP is auto-detected
        """
        from crack.reference.cli.config import ConfigCLI

        mock_config = ConfigFactory.create_mock()
        mock_config.auto_detect_ip.return_value = '10.10.14.5'
        mock_theme = ThemeFactory.create_mock()

        config_cli = ConfigCLI(config_manager=mock_config, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            result = config_cli.set_config_var('LHOST', 'auto')

        assert result == 0
        mock_config.auto_detect_ip.assert_called_once()
        mock_config.set_variable.assert_called_with('LHOST', '10.10.14.5')
        assert 'Auto-detected' in output.getvalue()

    def test_set_config_var_auto_detect_interface(self):
        """
        BV: 'auto' value triggers interface auto-detection for INTERFACE

        Scenario:
          Given: ConfigCLI instance
          When: set_config_var('INTERFACE', 'auto') is called
          Then: Interface is auto-detected
        """
        from crack.reference.cli.config import ConfigCLI

        mock_config = ConfigFactory.create_mock()
        mock_config.auto_detect_interface.return_value = 'tun0'
        mock_theme = ThemeFactory.create_mock()

        config_cli = ConfigCLI(config_manager=mock_config, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            result = config_cli.set_config_var('INTERFACE', 'auto')

        assert result == 0
        mock_config.auto_detect_interface.assert_called_once()
        mock_config.set_variable.assert_called_with('INTERFACE', 'tun0')

    def test_set_config_var_auto_detect_fails(self):
        """
        BV: Clear error when auto-detection fails

        Scenario:
          Given: ConfigCLI instance
          When: set_config_var('LHOST', 'auto') fails to detect
          Then: Error message and non-zero exit code
        """
        from crack.reference.cli.config import ConfigCLI

        mock_config = ConfigFactory.create_mock()
        mock_config.auto_detect_ip.return_value = None
        mock_theme = ThemeFactory.create_mock()

        config_cli = ConfigCLI(config_manager=mock_config, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            result = config_cli.set_config_var('LHOST', 'auto')

        assert result == 1
        assert 'Could not' in output.getvalue() or 'auto-detect' in output.getvalue()

    def test_set_config_var_failure(self):
        """
        BV: Clear error when set fails

        Scenario:
          Given: ConfigCLI instance
          When: set_variable returns False
          Then: Error message and non-zero exit code
        """
        from crack.reference.cli.config import ConfigCLI

        mock_config = ConfigFactory.create_mock()
        mock_config.set_variable.return_value = False
        mock_theme = ThemeFactory.create_mock()

        config_cli = ConfigCLI(config_manager=mock_config, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            result = config_cli.set_config_var('BADVAR', 'value')

        assert result == 1
        assert 'Failed' in output.getvalue()


class TestGetConfigVar:
    """Tests for get_config_var command"""

    def test_get_config_var_found(self):
        """
        BV: Get displays variable value

        Scenario:
          Given: Variable is configured
          When: get_config_var('LHOST') is called
          Then: Value is displayed
        """
        from crack.reference.cli.config import ConfigCLI

        variables = {"LHOST": {"value": "10.10.14.5", "source": "manual"}}
        mock_config = ConfigFactory.create_mock(variables=variables)
        mock_theme = ThemeFactory.create_mock()

        config_cli = ConfigCLI(config_manager=mock_config, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            result = config_cli.get_config_var('LHOST')

        assert result == 0
        output_text = output.getvalue()
        assert 'LHOST' in output_text
        assert '10.10.14.5' in output_text

    def test_get_config_var_not_found(self):
        """
        BV: Get shows clear message for unset variable

        Scenario:
          Given: Variable is not configured
          When: get_config_var('UNKNOWN') is called
          Then: "not set" message and non-zero exit
        """
        from crack.reference.cli.config import ConfigCLI

        mock_config = ConfigFactory.create_mock(variables={})
        mock_config.get_variable.return_value = None
        mock_theme = ThemeFactory.create_mock()

        config_cli = ConfigCLI(config_manager=mock_config, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            result = config_cli.get_config_var('UNKNOWN')

        assert result == 1
        assert 'not set' in output.getvalue()

    def test_get_config_var_converts_to_uppercase(self):
        """
        BV: Variable names are normalized to uppercase

        Scenario:
          Given: Variable 'LHOST' is configured
          When: get_config_var('lhost') is called
          Then: Variable is found (case-insensitive)
        """
        from crack.reference.cli.config import ConfigCLI

        variables = {"LHOST": {"value": "10.10.14.5", "source": "manual"}}
        mock_config = ConfigFactory.create_mock(variables=variables)
        mock_theme = ThemeFactory.create_mock()

        config_cli = ConfigCLI(config_manager=mock_config, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            config_cli.get_config_var('lhost')

        # Should query with uppercase
        mock_config.get_variable.assert_called_with('LHOST')


class TestClearConfig:
    """Tests for clear_config command"""

    def test_clear_config_with_confirmation(self):
        """
        BV: Clear requires user confirmation

        Scenario:
          Given: ConfigCLI instance
          When: clear_config() is called and user confirms
          Then: All variables are cleared
        """
        from crack.reference.cli.config import ConfigCLI

        mock_config = ConfigFactory.create_mock()
        mock_theme = ThemeFactory.create_mock()

        config_cli = ConfigCLI(config_manager=mock_config, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output), patch('builtins.input', return_value='y'):
            result = config_cli.clear_config()

        assert result == 0
        mock_config.clear_variables.assert_called_once()
        assert 'cleared' in output.getvalue()

    def test_clear_config_cancelled(self):
        """
        BV: Clear can be cancelled by user

        Scenario:
          Given: ConfigCLI instance
          When: clear_config() is called and user declines
          Then: No variables are cleared
        """
        from crack.reference.cli.config import ConfigCLI

        mock_config = ConfigFactory.create_mock()
        mock_theme = ThemeFactory.create_mock()

        config_cli = ConfigCLI(config_manager=mock_config, theme=mock_theme)

        with patch('builtins.input', return_value='n'):
            result = config_cli.clear_config()

        assert result == 1
        mock_config.clear_variables.assert_not_called()

    def test_clear_config_failure(self):
        """
        BV: Clear shows error on failure

        Scenario:
          Given: ConfigCLI instance
          When: clear_variables returns False
          Then: Error message and non-zero exit
        """
        from crack.reference.cli.config import ConfigCLI

        mock_config = ConfigFactory.create_mock()
        mock_config.clear_variables.return_value = False
        mock_theme = ThemeFactory.create_mock()

        config_cli = ConfigCLI(config_manager=mock_config, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output), patch('builtins.input', return_value='y'):
            result = config_cli.clear_config()

        assert result == 1
        assert 'Failed' in output.getvalue()


class TestEditConfig:
    """Tests for edit_config command"""

    def test_edit_config_opens_editor(self):
        """
        BV: Edit opens config in user's editor

        Scenario:
          Given: ConfigCLI instance
          When: edit_config() is called
          Then: Editor is opened
        """
        from crack.reference.cli.config import ConfigCLI

        mock_config = ConfigFactory.create_mock()
        mock_theme = ThemeFactory.create_mock()

        config_cli = ConfigCLI(config_manager=mock_config, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            result = config_cli.edit_config()

        assert result == 0
        mock_config.open_editor.assert_called_once()
        assert 'Opening' in output.getvalue() or 'reloaded' in output.getvalue()

    def test_edit_config_editor_failure(self):
        """
        BV: Edit shows error when editor fails

        Scenario:
          Given: ConfigCLI instance
          When: open_editor returns False
          Then: Error message and non-zero exit
        """
        from crack.reference.cli.config import ConfigCLI

        mock_config = ConfigFactory.create_mock()
        mock_config.open_editor.return_value = False
        mock_theme = ThemeFactory.create_mock()

        config_cli = ConfigCLI(config_manager=mock_config, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            result = config_cli.edit_config()

        assert result == 1
        assert 'Failed' in output.getvalue() or 'failed' in output.getvalue()


class TestAutoConfig:
    """Tests for auto_config command"""

    def test_auto_config_detects_values(self):
        """
        BV: Auto detects LHOST and INTERFACE

        Scenario:
          Given: ConfigCLI instance
          When: auto_config() is called
          Then: Auto-detected values are displayed
        """
        from crack.reference.cli.config import ConfigCLI

        mock_config = ConfigFactory.create_mock()
        mock_config.auto_configure.return_value = {
            "LHOST": "10.10.14.5",
            "INTERFACE": "tun0"
        }
        mock_theme = ThemeFactory.create_mock()

        config_cli = ConfigCLI(config_manager=mock_config, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            result = config_cli.auto_config()

        assert result == 0
        output_text = output.getvalue()
        assert 'LHOST' in output_text
        assert '10.10.14.5' in output_text
        assert 'INTERFACE' in output_text
        assert 'tun0' in output_text

    def test_auto_config_no_detection(self):
        """
        BV: Auto shows message when nothing detected

        Scenario:
          Given: ConfigCLI instance
          When: auto_configure returns empty
          Then: Appropriate message and non-zero exit
        """
        from crack.reference.cli.config import ConfigCLI

        mock_config = ConfigFactory.create_mock()
        mock_config.auto_configure.return_value = {}
        mock_theme = ThemeFactory.create_mock()

        config_cli = ConfigCLI(config_manager=mock_config, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            result = config_cli.auto_config()

        assert result == 1
        assert 'No values' in output.getvalue() or 'auto-detected' in output.getvalue()

    def test_auto_config_saves_to_file(self):
        """
        BV: Auto-detected values are persisted

        Scenario:
          Given: ConfigCLI instance
          When: auto_config() succeeds
          Then: Config file path is mentioned
        """
        from crack.reference.cli.config import ConfigCLI

        mock_config = ConfigFactory.create_mock()
        mock_config.auto_configure.return_value = {"LHOST": "10.10.14.5"}
        mock_theme = ThemeFactory.create_mock()

        config_cli = ConfigCLI(config_manager=mock_config, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            config_cli.auto_config()

        output_text = output.getvalue()
        assert 'saved' in output_text.lower() or 'config' in output_text.lower()


class TestEdgeCases:
    """Tests for edge cases in config CLI"""

    def test_handle_config_unknown_action(self):
        """
        BV: Unknown config action returns gracefully

        Scenario:
          Given: ConfigCLI instance
          When: handle_config('unknown') is called
          Then: Returns 0 without error
        """
        from crack.reference.cli.config import ConfigCLI

        mock_config = ConfigFactory.create_mock()
        mock_theme = ThemeFactory.create_mock()

        config_cli = ConfigCLI(config_manager=mock_config, theme=mock_theme)

        result = config_cli.handle_config('unknown')

        assert result == 0

    def test_variable_with_special_characters(self):
        """
        BV: Variables with special values are handled

        Scenario:
          Given: Variable value with special characters
          When: set_config_var is called
          Then: Value is preserved correctly
        """
        from crack.reference.cli.config import ConfigCLI

        mock_config = ConfigFactory.create_mock()
        mock_theme = ThemeFactory.create_mock()

        config_cli = ConfigCLI(config_manager=mock_config, theme=mock_theme)

        # Value with spaces and special chars
        config_cli.set_config_var('WORDLIST', '/usr/share/wordlists/rockyou.txt')

        mock_config.set_variable.assert_called_with(
            'WORDLIST', '/usr/share/wordlists/rockyou.txt'
        )

    def test_list_handles_legacy_format(self):
        """
        BV: List handles both dict and string variable formats

        Scenario:
          Given: Mix of variable formats
          When: list_config() is called
          Then: Both formats are displayed
        """
        from crack.reference.cli.config import ConfigCLI

        # Mix of formats
        variables = {
            "LHOST": {"value": "10.10.14.5", "source": "manual"},
            "LEGACY_VAR": "legacy_value"  # Old string format
        }

        mock_config = ConfigFactory.create_mock(variables=variables)
        mock_theme = ThemeFactory.create_mock()

        config_cli = ConfigCLI(config_manager=mock_config, theme=mock_theme)

        output = StringIO()
        with patch('sys.stdout', output):
            result = config_cli.list_config()

        assert result == 0
        output_text = output.getvalue()
        assert 'LHOST' in output_text
        assert 'LEGACY_VAR' in output_text
