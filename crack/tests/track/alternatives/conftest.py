"""
Fixtures for alternative commands tests
"""

import pytest
from pathlib import Path
from crack.reference.core.config import ConfigManager


@pytest.fixture
def mock_config(tmp_path):
    """
    Mock ConfigManager with test config

    Returns ConfigManager instance with test configuration
    """
    # Create temporary config file
    config_file = tmp_path / "test_config.json"

    # Create ConfigManager with custom path
    config = ConfigManager(config_path=str(config_file))

    # Set default test values
    config.config = {
        'variables': {
            'LHOST': {
                'value': '192.168.45.1',
                'source': 'test',
                'description': 'Test LHOST'
            },
            'LPORT': {
                'value': '4444',
                'source': 'test',
                'description': 'Test LPORT'
            },
            'WORDLIST': {
                'value': '/usr/share/wordlists/rockyou.txt',
                'source': 'test',
                'description': 'Test wordlist'
            },
            'TARGET': {
                'value': '',
                'source': 'test',
                'description': 'Test target'
            }
        },
        'settings': {
            'auto_detect_interface': False,
            'auto_detect_ip': False
        }
    }

    config.save()

    return config


@pytest.fixture
def temp_wordlists_dir(tmp_path):
    """
    Create temporary wordlists directory with sample files

    Simulates /usr/share/wordlists/ structure for testing
    """
    wordlists_dir = tmp_path / "wordlists"
    wordlists_dir.mkdir()

    # Create sample wordlists
    (wordlists_dir / "rockyou.txt").write_text("password123\nadmin\ntest\n")
    (wordlists_dir / "common.txt").write_text("/admin\n/login\n/test\n")
    (wordlists_dir / "small.txt").write_text("/home\n/index\n")
    (wordlists_dir / "directory-list-2.3-medium.txt").write_text("/admin\n/login\n/test\n/backup\n/config\n")

    return wordlists_dir


@pytest.fixture
def temp_cache_file(tmp_path):
    """
    Create temporary cache file for WordlistManager

    Returns path to cache file (doesn't need to exist initially)
    """
    return tmp_path / "wordlist_cache.json"
