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
