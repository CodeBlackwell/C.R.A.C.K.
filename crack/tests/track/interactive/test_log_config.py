"""
Unit tests for precision debug logging configuration
"""

import json
import os
import pytest
import tempfile
from pathlib import Path

from crack.track.interactive.log_types import (
    LogCategory, LogLevel, OutputTarget, LogFormat, parse_category_spec
)
from crack.track.interactive.log_config import LogConfig


class TestLogLevel:
    """Test LogLevel enum and comparisons"""

    def test_level_ordering(self):
        """Test log level value ordering"""
        assert LogLevel.MINIMAL < LogLevel.NORMAL
        assert LogLevel.NORMAL < LogLevel.VERBOSE
        assert LogLevel.VERBOSE < LogLevel.TRACE

        assert LogLevel.TRACE > LogLevel.VERBOSE
        assert LogLevel.VERBOSE > LogLevel.NORMAL
        assert LogLevel.NORMAL > LogLevel.MINIMAL

    def test_level_equality(self):
        """Test log level equality"""
        assert LogLevel.NORMAL == LogLevel.NORMAL
        assert LogLevel.NORMAL <= LogLevel.NORMAL
        assert LogLevel.NORMAL >= LogLevel.NORMAL


class TestLogCategory:
    """Test LogCategory enum and hierarchy"""

    def test_exact_match(self):
        """Test exact category matching"""
        assert LogCategory.UI_INPUT.matches("UI.INPUT")
        assert LogCategory.UI.matches("UI")
        assert not LogCategory.UI_INPUT.matches("UI.RENDER")

    def test_parent_match(self):
        """Test parent category matching"""
        assert LogCategory.UI_INPUT.matches("UI")
        assert LogCategory.UI_RENDER.matches("UI")
        assert LogCategory.STATE_TRANSITION.matches("STATE")

    def test_wildcard_match(self):
        """Test wildcard category matching"""
        assert LogCategory.UI_INPUT.matches("UI.*")
        assert LogCategory.STATE_CHECKPOINT.matches("STATE.*")
        assert not LogCategory.EXECUTION_START.matches("UI.*")

    def test_get_parent(self):
        """Test parent category retrieval"""
        assert LogCategory.UI_INPUT.get_parent() == LogCategory.UI
        assert LogCategory.STATE_TRANSITION.get_parent() == LogCategory.STATE
        assert LogCategory.UI.get_parent() is None

    def test_get_children(self):
        """Test child category retrieval"""
        ui_children = LogCategory.UI.get_children()
        assert LogCategory.UI_INPUT in ui_children
        assert LogCategory.UI_RENDER in ui_children
        assert LogCategory.STATE_TRANSITION not in ui_children

    def test_is_parent_of(self):
        """Test parent relationship check"""
        assert LogCategory.UI.is_parent_of(LogCategory.UI_INPUT)
        assert LogCategory.STATE.is_parent_of(LogCategory.STATE_TRANSITION)
        assert not LogCategory.UI.is_parent_of(LogCategory.STATE_TRANSITION)

    def test_is_child_of(self):
        """Test child relationship check"""
        assert LogCategory.UI_INPUT.is_child_of(LogCategory.UI)
        assert LogCategory.STATE_CHECKPOINT.is_child_of(LogCategory.STATE)
        assert not LogCategory.UI_INPUT.is_child_of(LogCategory.STATE)


class TestParseCategorySpec:
    """Test category specification parsing"""

    def test_parse_simple_category(self):
        """Test parsing category without level"""
        cat, level = parse_category_spec("UI.INPUT")
        assert cat == LogCategory.UI_INPUT
        assert level is None

    def test_parse_category_with_level(self):
        """Test parsing category with level"""
        cat, level = parse_category_spec("UI.INPUT:VERBOSE")
        assert cat == LogCategory.UI_INPUT
        assert level == LogLevel.VERBOSE

    def test_parse_parent_category(self):
        """Test parsing parent category"""
        cat, level = parse_category_spec("UI:TRACE")
        assert cat == LogCategory.UI
        assert level == LogLevel.TRACE

    def test_parse_invalid_category(self):
        """Test parsing invalid category"""
        with pytest.raises(ValueError, match="Invalid category"):
            parse_category_spec("INVALID_CATEGORY")

    def test_parse_invalid_level(self):
        """Test parsing invalid level"""
        with pytest.raises(ValueError, match="Invalid log level"):
            parse_category_spec("UI:INVALID_LEVEL")


class TestLogConfig:
    """Test LogConfig filtering and configuration"""

    def test_default_config(self):
        """Test default configuration"""
        config = LogConfig()
        assert not config.enabled
        assert config.global_level == LogLevel.NORMAL
        assert config.output_target == OutputTarget.FILE

    def test_should_log_disabled(self):
        """Test logging disabled by default"""
        config = LogConfig(enabled=False)
        assert not config.should_log(category=LogCategory.UI_INPUT)

    def test_should_log_global_level(self):
        """Test global log level filtering"""
        config = LogConfig(enabled=True, global_level=LogLevel.NORMAL)

        assert config.should_log(level=LogLevel.MINIMAL)
        assert config.should_log(level=LogLevel.NORMAL)
        assert not config.should_log(level=LogLevel.VERBOSE)
        assert not config.should_log(level=LogLevel.TRACE)

    def test_should_log_category_level(self):
        """Test category-specific log level"""
        config = LogConfig(enabled=True, global_level=LogLevel.MINIMAL)
        config.enable_category(LogCategory.UI_INPUT, LogLevel.VERBOSE)

        # UI.INPUT category should allow VERBOSE
        assert config.should_log(
            category=LogCategory.UI_INPUT,
            level=LogLevel.VERBOSE
        )

        # But not TRACE
        assert not config.should_log(
            category=LogCategory.UI_INPUT,
            level=LogLevel.TRACE
        )

    def test_should_log_parent_level_inheritance(self):
        """Test child categories inherit parent level"""
        config = LogConfig(enabled=True, global_level=LogLevel.MINIMAL)
        config.enable_category(LogCategory.UI, LogLevel.VERBOSE)

        # UI.INPUT should inherit UI's VERBOSE level
        assert config.should_log(
            category=LogCategory.UI_INPUT,
            level=LogLevel.VERBOSE
        )

    def test_should_log_module_filter(self):
        """Test module filtering"""
        config = LogConfig(enabled=True)
        config.enable_module("session")

        # Should log from session module
        assert config.should_log(module="session")

        # Should not log from other modules
        assert not config.should_log(module="prompts")

    def test_should_log_module_disable(self):
        """Test module disabling"""
        config = LogConfig(enabled=True)
        config.disable_module("test_module")

        # Should not log from disabled module
        assert not config.should_log(module="test_module")

    def test_should_log_category_match(self):
        """Test category matching in filter"""
        config = LogConfig(enabled=True)
        config.enable_category(LogCategory.UI)

        # Should log UI and all UI.* categories
        assert config.should_log(category=LogCategory.UI)
        assert config.should_log(category=LogCategory.UI_INPUT)
        assert config.should_log(category=LogCategory.UI_RENDER)

        # Should not log other categories
        assert not config.should_log(category=LogCategory.STATE_TRANSITION)

    def test_from_string_simple(self):
        """Test parsing simple category string"""
        config = LogConfig.from_string("UI.INPUT:VERBOSE")

        assert config.enabled
        assert LogCategory.UI_INPUT in config.enabled_categories
        assert config.category_levels[LogCategory.UI_INPUT] == LogLevel.VERBOSE

    def test_from_string_multiple(self):
        """Test parsing multiple categories"""
        config = LogConfig.from_string("UI.INPUT:VERBOSE,STATE:NORMAL")

        assert LogCategory.UI_INPUT in config.enabled_categories
        assert LogCategory.STATE in config.enabled_categories
        assert config.category_levels[LogCategory.UI_INPUT] == LogLevel.VERBOSE
        assert config.category_levels[LogCategory.STATE] == LogLevel.NORMAL

    def test_from_string_all(self):
        """Test enabling all categories"""
        config = LogConfig.from_string("all")

        assert config.enabled
        assert len(config.enabled_categories) > 0

    def test_from_cli_args(self):
        """Test CLI argument parsing"""
        config = LogConfig.from_cli_args(
            categories="UI.INPUT:VERBOSE,STATE:NORMAL",
            modules="session,prompts",
            level="TRACE",
            output="console",
            format="json"
        )

        assert config.enabled
        assert LogCategory.UI_INPUT in config.enabled_categories
        assert "session" in config.enabled_modules
        assert config.global_level == LogLevel.TRACE
        assert config.output_target == OutputTarget.CONSOLE
        assert config.log_format == LogFormat.JSON

    def test_from_cli_args_module_disable(self):
        """Test disabling modules via CLI"""
        config = LogConfig.from_cli_args(modules="session,!test_module")

        assert "session" in config.enabled_modules
        assert "test_module" in config.disabled_modules

    def test_from_file(self):
        """Test loading config from JSON file"""
        config_data = {
            "enabled": True,
            "global_level": "VERBOSE",
            "categories": {
                "UI.INPUT": "TRACE",
                "STATE": "NORMAL"
            },
            "modules": ["session", "prompts"],
            "output_target": "console",
            "log_format": "json"
        }

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name

        try:
            config = LogConfig.from_file(Path(temp_path))

            assert config.enabled
            assert config.global_level == LogLevel.VERBOSE
            assert LogCategory.UI_INPUT in config.enabled_categories
            assert config.category_levels[LogCategory.UI_INPUT] == LogLevel.TRACE
            assert "session" in config.enabled_modules
            assert config.output_target == OutputTarget.CONSOLE
            assert config.log_format == LogFormat.JSON
        finally:
            os.unlink(temp_path)

    def test_from_env(self):
        """Test loading config from environment variables"""
        os.environ['CRACK_DEBUG_ENABLED'] = '1'
        os.environ['CRACK_DEBUG_CATEGORIES'] = 'UI.INPUT:VERBOSE'
        os.environ['CRACK_DEBUG_MODULES'] = 'session'
        os.environ['CRACK_DEBUG_LEVEL'] = 'TRACE'

        try:
            config = LogConfig.from_env()

            assert config.enabled
            assert LogCategory.UI_INPUT in config.enabled_categories
            assert "session" in config.enabled_modules
            assert config.global_level == LogLevel.TRACE
        finally:
            del os.environ['CRACK_DEBUG_ENABLED']
            del os.environ['CRACK_DEBUG_CATEGORIES']
            del os.environ['CRACK_DEBUG_MODULES']
            del os.environ['CRACK_DEBUG_LEVEL']

    def test_to_dict(self):
        """Test exporting config to dictionary"""
        config = LogConfig(enabled=True, global_level=LogLevel.VERBOSE)
        config.enable_category(LogCategory.UI_INPUT, LogLevel.TRACE)
        config.enable_module("session")

        data = config.to_dict()

        assert data['enabled'] is True
        assert data['global_level'] == 'VERBOSE'
        assert 'UI.INPUT' in data['categories']
        assert data['categories']['UI.INPUT'] == 'TRACE'
        assert 'session' in data['modules']

    def test_to_file(self):
        """Test saving config to file"""
        config = LogConfig(enabled=True, global_level=LogLevel.VERBOSE)
        config.enable_category(LogCategory.UI_INPUT, LogLevel.TRACE)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            temp_path = Path(f.name)

        try:
            config.to_file(temp_path)

            # Verify file was created and is valid JSON
            with open(temp_path, 'r') as f:
                data = json.load(f)

            assert data['enabled'] is True
            assert data['global_level'] == 'VERBOSE'
        finally:
            os.unlink(temp_path)

    def test_runtime_config_changes(self):
        """Test runtime configuration modifications"""
        config = LogConfig(enabled=True)

        # Enable category
        config.enable_category(LogCategory.UI_INPUT, LogLevel.VERBOSE)
        config.enable_category(LogCategory.STATE, LogLevel.NORMAL)
        assert config.should_log(category=LogCategory.UI_INPUT, level=LogLevel.NORMAL)

        # Disable one category (other categories still enabled)
        config.disable_category(LogCategory.UI_INPUT)
        assert not config.should_log(category=LogCategory.UI_INPUT, level=LogLevel.NORMAL)
        assert config.should_log(category=LogCategory.STATE, level=LogLevel.NORMAL)

        # Enable module
        config.enable_module("session")
        assert config.should_log(module="session")

        # Disable module
        config.disable_module("session")
        assert not config.should_log(module="session")


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
