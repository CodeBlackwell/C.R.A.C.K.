"""
Core module test fixtures.

Provides isolated fixtures for ConfigManager, ThemeManager, and utility testing.
All fixtures use temporary directories to prevent filesystem pollution.
"""

import json
import pytest
from pathlib import Path
from typing import Dict, Any


@pytest.fixture
def config_dir(tmp_path: Path) -> Path:
    """
    Isolated configuration directory for config tests.

    BV: Config tests don't modify user's ~/.crack/ directory.
    """
    config_dir = tmp_path / ".crack"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


@pytest.fixture
def config_path(config_dir: Path) -> Path:
    """
    Path to config.json for testing.

    BV: Each test gets a fresh config file path.
    """
    return config_dir / "config.json"


@pytest.fixture
def fresh_config_manager(config_path: Path):
    """
    ConfigManager with isolated config file.

    BV: Tests don't share state or affect user configuration.

    Usage:
        def test_set_variable(fresh_config_manager):
            manager = fresh_config_manager
            manager.set_variable('LHOST', '10.10.14.5')
    """
    from core.config.manager import ConfigManager
    return ConfigManager(config_path=str(config_path))


@pytest.fixture
def prepopulated_config(config_path: Path) -> Path:
    """
    Config file pre-populated with sample data.

    BV: Tests can verify loading behavior without manual setup.
    """
    sample_config = {
        "variables": {
            "LHOST": {
                "value": "10.10.14.5",
                "description": "Local IP",
                "source": "manual",
                "updated": "2024-01-15T12:00:00"
            },
            "TARGET": {
                "value": "192.168.1.100",
                "description": "Target IP",
                "source": "auto-detected",
                "updated": "2024-01-15T12:00:00"
            }
        },
        "settings": {
            "auto_detect_interface": True,
            "auto_detect_ip": False,
            "confirm_before_fill": True,
            "show_source": True
        },
        "theme": {
            "current": "dark"
        },
        "sessions": {
            "lab1": {
                "variables": {"LHOST": {"value": "10.10.14.1"}},
                "created": "2024-01-10T10:00:00",
                "last_used": "2024-01-14T15:00:00"
            }
        }
    }

    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(sample_config, indent=2))

    return config_path


@pytest.fixture
def theme_config_path(tmp_path: Path) -> Path:
    """
    Isolated theme config path for ThemeManager tests.

    BV: Theme tests don't modify user preferences.
    """
    config_dir = tmp_path / ".crack_theme_test"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir / "config.json"


@pytest.fixture
def theme_manager(theme_config_path: Path):
    """
    ThemeManager with isolated config file.

    BV: Theme tests are isolated from user theme settings.
    """
    from core.themes.manager import ThemeManager
    return ThemeManager(config_path=str(theme_config_path))


@pytest.fixture
def theme_config_with_theme(theme_config_path: Path, theme_name: str = "dark") -> Path:
    """
    Factory to create theme config with specified theme.

    BV: Tests can verify theme loading from various saved states.
    """
    def _create_config(name: str = "dark") -> Path:
        config = {"theme": {"current": name}}
        theme_config_path.parent.mkdir(parents=True, exist_ok=True)
        theme_config_path.write_text(json.dumps(config))
        return theme_config_path

    return _create_config


@pytest.fixture
def sample_curl_commands() -> Dict[str, str]:
    """
    Sample curl commands for parser testing.

    BV: Consistent test data for curl parser edge cases.
    """
    return {
        "simple_get": "curl http://example.com",
        "get_with_headers": "curl -H 'Host: example.com' -H 'User-Agent: test' http://example.com",
        "post_with_data": "curl -X POST -d 'user=admin&pass=secret' http://example.com/login",
        "post_json": "curl -X POST -H 'Content-Type: application/json' -d '{\"user\":\"admin\"}' http://example.com/api",
        "burp_export": "curl -X POST -H 'Host: 10.10.10.100' --data-binary 'username=admin' http://10.10.10.100/login",
        "multiline": "curl -X POST \\\n  -H 'Host: test.com' \\\n  -d 'data=value' \\\n  http://test.com/api",
        "with_backticks": "curl -X `POST` -H `Host: example.com` http://example.com",
        "malformed_quotes": "curl -X POST' -H Host: example.com' http://example.com",
    }
