"""
Tests for ConfigManager - Configuration persistence and variable management.

Business Value Focus:
- User settings MUST persist across restarts (no data loss)
- Variable validation prevents invalid configurations
- Session management allows context switching between targets
- Config file creation is automatic (first-run experience)

TIER 1: DATA INTEGRITY (Critical) - Config persistence, variable storage
TIER 2: FUNCTIONAL CORRECTNESS (High) - Validation, defaults, sessions
"""

import json
import pytest
from pathlib import Path
from datetime import datetime
from unittest.mock import patch, MagicMock


class TestConfigManagerInitialization:
    """Tests for ConfigManager initialization and file creation"""

    def test_creates_default_config_when_file_missing(self, config_path: Path):
        """
        BV: First-run users get a working config without manual setup.

        Scenario:
          Given: No config file exists
          When: ConfigManager is instantiated
          Then: Default config file is created with expected structure
        """
        from core.config.manager import ConfigManager

        assert not config_path.exists(), "Config file should not exist before test"

        manager = ConfigManager(config_path=str(config_path))

        assert config_path.exists(), "Config file should be created"
        assert manager.config.get('settings') is not None
        assert manager.config.get('variables') is not None

    def test_loads_existing_config_file(self, prepopulated_config: Path):
        """
        BV: Existing user configuration is preserved across restarts.

        Scenario:
          Given: Config file exists with user data
          When: ConfigManager loads
          Then: User data is available in memory
        """
        from core.config.manager import ConfigManager

        manager = ConfigManager(config_path=str(prepopulated_config))

        lhost = manager.get_variable('LHOST')
        assert lhost == "10.10.14.5", f"Expected '10.10.14.5', got '{lhost}'"

    def test_handles_corrupted_config_gracefully(self, config_path: Path):
        """
        BV: Corrupted config doesn't crash application; defaults are used.

        Scenario:
          Given: Config file contains invalid JSON
          When: ConfigManager loads
          Then: Default configuration is used without exception
        """
        from core.config.manager import ConfigManager

        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text("{ invalid json content }")

        # Should not raise exception
        manager = ConfigManager(config_path=str(config_path))

        # Should have default structure
        assert manager.config.get('settings') is not None

    def test_default_config_has_required_sections(self, fresh_config_manager):
        """
        BV: Default config structure enables all features immediately.

        Scenario:
          Given: Fresh config manager
          When: Inspecting default structure
          Then: All required sections exist
        """
        manager = fresh_config_manager

        assert 'variables' in manager.config
        assert 'settings' in manager.config
        assert 'sessions' in manager.config
        assert 'theme' in manager.config


class TestConfigManagerGet:
    """Tests for ConfigManager.get() method"""

    def test_get_returns_value_for_existing_key(self, prepopulated_config: Path):
        """
        BV: Users can retrieve configured settings.

        Scenario:
          Given: Config with settings.auto_detect_interface = True
          When: get('settings.auto_detect_interface') is called
          Then: Returns True
        """
        from core.config.manager import ConfigManager
        manager = ConfigManager(config_path=str(prepopulated_config))

        value = manager.get('settings.auto_detect_interface')

        assert value is True

    def test_get_returns_default_for_missing_key(self, fresh_config_manager):
        """
        BV: Missing keys don't crash; sensible default is returned.

        Scenario:
          Given: Fresh config without 'custom.setting' key
          When: get('custom.setting', 'fallback') is called
          Then: Returns 'fallback'
        """
        manager = fresh_config_manager

        value = manager.get('custom.nonexistent.setting', 'fallback')

        assert value == 'fallback'

    def test_get_with_nested_dot_notation(self, prepopulated_config: Path):
        """
        BV: Deeply nested settings are accessible via dot notation.

        Scenario:
          Given: Config with theme.current = 'dark'
          When: get('theme.current') is called
          Then: Returns 'dark'
        """
        from core.config.manager import ConfigManager
        manager = ConfigManager(config_path=str(prepopulated_config))

        value = manager.get('theme.current')

        assert value == 'dark'

    def test_get_returns_none_for_partial_path(self, fresh_config_manager):
        """
        BV: Partial path traversal returns None, not KeyError.

        Scenario:
          Given: Config without 'nonexistent' section
          When: get('nonexistent.key') is called with no default
          Then: Returns None
        """
        manager = fresh_config_manager

        value = manager.get('nonexistent.key')

        assert value is None


class TestConfigManagerSet:
    """Tests for ConfigManager.set() method"""

    def test_set_creates_nested_path(self, fresh_config_manager, config_path: Path):
        """
        BV: Users can create new settings without pre-existing structure.

        Scenario:
          Given: Fresh config without 'custom' section
          When: set('custom.setting', 'value') is called
          Then: Nested path is created and value is stored
        """
        manager = fresh_config_manager

        result = manager.set('custom.deep.setting', 'test_value')

        assert result is True
        assert manager.get('custom.deep.setting') == 'test_value'

        # Verify persistence
        loaded = json.loads(config_path.read_text())
        assert loaded['custom']['deep']['setting'] == 'test_value'

    def test_set_persists_to_disk(self, fresh_config_manager, config_path: Path):
        """
        BV: Configuration changes survive application restart.

        Scenario:
          Given: Config manager
          When: set() is called with new value
          Then: Value is saved to disk
        """
        manager = fresh_config_manager

        manager.set('settings.custom_flag', True)

        # Read directly from file
        saved = json.loads(config_path.read_text())
        assert saved['settings']['custom_flag'] is True

    def test_set_overwrites_existing_value(self, prepopulated_config: Path, config_path: Path):
        """
        BV: Users can update existing settings.

        Scenario:
          Given: Config with settings.auto_detect_ip = False
          When: set('settings.auto_detect_ip', True) is called
          Then: Value is updated
        """
        from core.config.manager import ConfigManager
        manager = ConfigManager(config_path=str(prepopulated_config))

        original = manager.get('settings.auto_detect_ip')
        assert original is False

        manager.set('settings.auto_detect_ip', True)

        assert manager.get('settings.auto_detect_ip') is True


class TestConfigManagerVariables:
    """Tests for variable management (get_variable, set_variable, etc.)"""

    def test_get_variable_returns_value(self, prepopulated_config: Path):
        """
        BV: Users can retrieve variable values by name.

        Scenario:
          Given: Config with LHOST = '10.10.14.5'
          When: get_variable('LHOST') is called
          Then: Returns '10.10.14.5'
        """
        from core.config.manager import ConfigManager
        manager = ConfigManager(config_path=str(prepopulated_config))

        value = manager.get_variable('LHOST')

        assert value == '10.10.14.5'

    def test_get_variable_handles_angle_brackets(self, prepopulated_config: Path):
        """
        BV: Users can use <VAR> syntax and get clean value.

        Scenario:
          Given: Config with LHOST variable
          When: get_variable('<LHOST>') is called
          Then: Returns value without angle brackets
        """
        from core.config.manager import ConfigManager
        manager = ConfigManager(config_path=str(prepopulated_config))

        value = manager.get_variable('<LHOST>')

        assert value == '10.10.14.5'

    def test_get_variable_is_case_insensitive(self, prepopulated_config: Path):
        """
        BV: Users don't need to remember exact case for variables.

        Scenario:
          Given: Config with LHOST variable
          When: get_variable('lhost') is called (lowercase)
          Then: Returns value (matches case-insensitively)
        """
        from core.config.manager import ConfigManager
        manager = ConfigManager(config_path=str(prepopulated_config))

        value = manager.get_variable('lhost')

        assert value == '10.10.14.5'

    def test_set_variable_creates_with_metadata(self, fresh_config_manager, config_path: Path):
        """
        BV: Variable storage includes metadata for debugging.

        Scenario:
          Given: Fresh config
          When: set_variable('LHOST', '10.10.14.5', source='manual') is called
          Then: Variable is stored with description, source, and timestamp
        """
        manager = fresh_config_manager

        success, error = manager.set_variable('LHOST', '10.10.14.5', source='manual')

        assert success is True
        assert error is None

        saved = json.loads(config_path.read_text())
        var_data = saved['variables']['LHOST']

        assert var_data['value'] == '10.10.14.5'
        assert var_data['source'] == 'manual'
        assert 'updated' in var_data
        assert 'description' in var_data

    def test_set_variable_validates_ip_format(self, fresh_config_manager):
        """
        BV: Invalid IP addresses are rejected with clear error message.

        Scenario:
          Given: Fresh config
          When: set_variable('LHOST', 'invalid_ip') is called
          Then: Returns (False, error_message)
        """
        manager = fresh_config_manager

        success, error = manager.set_variable('LHOST', 'not.an.ip.address')

        assert success is False
        assert error is not None
        assert 'Invalid IP' in error or 'IP' in error

    def test_set_variable_validates_port_range(self, fresh_config_manager):
        """
        BV: Ports outside valid range are rejected.

        Scenario:
          Given: Fresh config
          When: set_variable('LPORT', '99999') is called
          Then: Returns (False, error_message)
        """
        manager = fresh_config_manager

        success, error = manager.set_variable('LPORT', '99999')

        assert success is False
        assert error is not None

    def test_set_variable_allows_skipping_validation(self, fresh_config_manager):
        """
        BV: Advanced users can bypass validation for custom scenarios.

        Scenario:
          Given: Fresh config
          When: set_variable with validate=False is called
          Then: Value is stored regardless of format
        """
        manager = fresh_config_manager

        success, error = manager.set_variable('CUSTOM_VAR', 'anything', validate=False)

        assert success is True
        assert manager.get_variable('CUSTOM_VAR') == 'anything'

    def test_delete_variable_removes_from_config(self, prepopulated_config: Path):
        """
        BV: Users can remove variables they no longer need.

        Scenario:
          Given: Config with TARGET variable
          When: delete_variable('TARGET') is called
          Then: Variable is removed from config
        """
        from core.config.manager import ConfigManager
        manager = ConfigManager(config_path=str(prepopulated_config))

        assert manager.get_variable('TARGET') is not None

        result = manager.delete_variable('TARGET')

        assert result is True
        assert manager.get_variable('TARGET') is None

    def test_list_variables_returns_all(self, prepopulated_config: Path):
        """
        BV: Users can see all configured variables at once.

        Scenario:
          Given: Config with LHOST and TARGET variables
          When: list_variables() is called
          Then: Both variables are returned
        """
        from core.config.manager import ConfigManager
        manager = ConfigManager(config_path=str(prepopulated_config))

        variables = manager.list_variables()

        assert 'LHOST' in variables
        assert 'TARGET' in variables


class TestConfigManagerSave:
    """Tests for ConfigManager.save() method"""

    def test_save_creates_parent_directories(self, tmp_path: Path):
        """
        BV: Config save works even if ~/.crack/ doesn't exist.

        Scenario:
          Given: Config path in non-existent directory
          When: save() is called
          Then: Directory is created and file is saved
        """
        from core.config.manager import ConfigManager

        deep_path = tmp_path / "deep" / "nested" / ".crack" / "config.json"
        manager = ConfigManager(config_path=str(deep_path))

        result = manager.save()

        assert result is True
        assert deep_path.exists()

    def test_save_writes_valid_json(self, fresh_config_manager, config_path: Path):
        """
        BV: Saved config is valid JSON that can be reloaded.

        Scenario:
          Given: Config with modifications
          When: save() is called
          Then: File contains valid, parseable JSON
        """
        manager = fresh_config_manager
        manager.set('test.key', 'test_value')

        # Verify by reloading
        loaded = json.loads(config_path.read_text())

        assert loaded['test']['key'] == 'test_value'

    def test_save_preserves_formatting(self, fresh_config_manager, config_path: Path):
        """
        BV: Config file is human-readable (indented JSON).

        Scenario:
          Given: Config manager
          When: save() is called
          Then: JSON is indented for readability
        """
        manager = fresh_config_manager
        manager.save()

        content = config_path.read_text()

        # Pretty-printed JSON has newlines and indentation
        assert '\n' in content
        assert '  ' in content  # Indentation


class TestConfigManagerLoad:
    """Tests for ConfigManager.load() method"""

    def test_load_returns_config_dict(self, prepopulated_config: Path):
        """
        BV: load() provides access to raw config for advanced use.

        Scenario:
          Given: Existing config file
          When: load() is called
          Then: Returns dict with all sections
        """
        from core.config.manager import ConfigManager
        manager = ConfigManager(config_path=str(prepopulated_config))

        config = manager.load()

        assert isinstance(config, dict)
        assert 'variables' in config
        assert 'settings' in config

    def test_load_refreshes_from_disk(self, prepopulated_config: Path):
        """
        BV: External config edits are picked up on reload.

        Scenario:
          Given: Config file modified externally
          When: load() is called
          Then: New values are available
        """
        from core.config.manager import ConfigManager
        manager = ConfigManager(config_path=str(prepopulated_config))

        # External modification
        config = json.loads(prepopulated_config.read_text())
        config['variables']['NEW_VAR'] = {'value': 'external_edit'}
        prepopulated_config.write_text(json.dumps(config))

        manager.load()

        assert manager.get_variable('NEW_VAR') == 'external_edit'


class TestConfigManagerSessions:
    """Tests for session management"""

    def test_create_session_saves_current_variables(self, prepopulated_config: Path, config_path: Path):
        """
        BV: Users can save variable snapshots for different targets.

        Scenario:
          Given: Config with LHOST and TARGET variables
          When: create_session('target1') is called
          Then: Session contains current variable values
        """
        from core.config.manager import ConfigManager
        manager = ConfigManager(config_path=str(prepopulated_config))

        result = manager.create_session('target1')

        assert result is True

        sessions = manager.list_sessions()
        assert 'target1' in sessions
        assert 'variables' in sessions['target1']

    def test_load_session_restores_variables(self, prepopulated_config: Path):
        """
        BV: Users can switch between target configurations.

        Scenario:
          Given: Session 'lab1' with LHOST = '10.10.14.1'
          When: load_session('lab1') is called
          Then: LHOST is restored to session value
        """
        from core.config.manager import ConfigManager
        manager = ConfigManager(config_path=str(prepopulated_config))

        # Pre-existing session from fixture
        result = manager.load_session('lab1')

        assert result is True
        assert manager.get_variable('LHOST') == '10.10.14.1'

    def test_load_session_returns_false_for_missing(self, fresh_config_manager):
        """
        BV: Loading non-existent session doesn't crash; returns False.

        Scenario:
          Given: No sessions exist
          When: load_session('nonexistent') is called
          Then: Returns False
        """
        manager = fresh_config_manager

        result = manager.load_session('nonexistent')

        assert result is False

    def test_delete_session_removes_session(self, prepopulated_config: Path):
        """
        BV: Users can remove sessions they no longer need.

        Scenario:
          Given: Session 'lab1' exists
          When: delete_session('lab1') is called
          Then: Session is removed from config
        """
        from core.config.manager import ConfigManager
        manager = ConfigManager(config_path=str(prepopulated_config))

        assert 'lab1' in manager.list_sessions()

        result = manager.delete_session('lab1')

        assert result is True
        assert 'lab1' not in manager.list_sessions()


class TestConfigManagerExportImport:
    """Tests for config export/import functionality"""

    def test_export_config_writes_to_file(self, prepopulated_config: Path, tmp_path: Path):
        """
        BV: Users can backup or share configuration.

        Scenario:
          Given: Config with data
          When: export_config(path) is called
          Then: Complete config is written to file
        """
        from core.config.manager import ConfigManager
        manager = ConfigManager(config_path=str(prepopulated_config))

        export_path = tmp_path / "exported_config.json"

        result = manager.export_config(str(export_path))

        assert result is True
        assert export_path.exists()

        exported = json.loads(export_path.read_text())
        assert 'variables' in exported
        assert 'LHOST' in exported['variables']

    def test_import_config_replaces_current(self, fresh_config_manager, tmp_path: Path):
        """
        BV: Users can restore configuration from backup.

        Scenario:
          Given: Import file with LHOST = '192.168.1.1'
          When: import_config(path, merge=False) is called
          Then: Current config is replaced with imported
        """
        manager = fresh_config_manager

        import_file = tmp_path / "import.json"
        import_file.write_text(json.dumps({
            'variables': {'LHOST': {'value': '192.168.1.1'}},
            'settings': {'custom': True}
        }))

        result = manager.import_config(str(import_file), merge=False)

        assert result is True
        assert manager.get_variable('LHOST') == '192.168.1.1'
        assert manager.get('settings.custom') is True

    def test_import_config_merges_when_requested(self, prepopulated_config: Path, tmp_path: Path):
        """
        BV: Users can merge configs to add new sections without losing unrelated data.

        Scenario:
          Given: Existing config with variables and settings
          When: import_config with new 'custom' section and merge=True
          Then: Both original settings and new section exist

        Note: merge=True uses dict.update() which replaces top-level keys.
              Variables merging would require deep merge implementation.
        """
        from core.config.manager import ConfigManager
        manager = ConfigManager(config_path=str(prepopulated_config))

        import_file = tmp_path / "import.json"
        import_file.write_text(json.dumps({
            'custom_section': {'key': 'value'}
        }))

        result = manager.import_config(str(import_file), merge=True)

        assert result is True
        # Original settings preserved (not in imported file)
        assert manager.get('settings.auto_detect_interface') is True
        # New section added
        assert manager.get('custom_section.key') == 'value'


class TestConfigManagerPlaceholders:
    """Tests for placeholder value retrieval"""

    def test_get_placeholder_values_formats_with_brackets(self, prepopulated_config: Path):
        """
        BV: Placeholder engine gets correctly formatted values for substitution.

        Scenario:
          Given: Config with LHOST = '10.10.14.5'
          When: get_placeholder_values() is called
          Then: Returns {'<LHOST>': '10.10.14.5'}
        """
        from core.config.manager import ConfigManager
        manager = ConfigManager(config_path=str(prepopulated_config))

        placeholders = manager.get_placeholder_values()

        assert '<LHOST>' in placeholders
        assert placeholders['<LHOST>'] == '10.10.14.5'

    def test_get_placeholder_values_excludes_empty(self, fresh_config_manager):
        """
        BV: Empty variables don't clutter placeholder list.

        Scenario:
          Given: Config with empty variable value
          When: get_placeholder_values() is called
          Then: Empty variables are excluded
        """
        manager = fresh_config_manager
        manager.config['variables']['EMPTY_VAR'] = {'value': ''}

        placeholders = manager.get_placeholder_values()

        assert '<EMPTY_VAR>' not in placeholders


class TestConfigManagerValidation:
    """Tests for variable validation"""

    def test_validate_all_returns_errors_for_invalid(self, fresh_config_manager):
        """
        BV: Users can check if all variables are valid before use.

        Scenario:
          Given: Config with invalid IP address stored
          When: validate_all() is called
          Then: Returns error dict with variable name and error
        """
        manager = fresh_config_manager
        manager.config['variables']['LHOST'] = {'value': 'invalid-ip'}

        errors = manager.validate_all()

        assert 'LHOST' in errors
        assert len(errors['LHOST']) > 0

    def test_validate_all_returns_empty_for_valid(self, prepopulated_config: Path):
        """
        BV: Valid configurations pass validation.

        Scenario:
          Given: Config with valid IP addresses
          When: validate_all() is called
          Then: Returns empty dict (no errors)
        """
        from core.config.manager import ConfigManager
        manager = ConfigManager(config_path=str(prepopulated_config))

        errors = manager.validate_all()

        assert errors == {} or len(errors) == 0
