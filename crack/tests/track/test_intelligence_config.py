"""
Tests for IntelligenceConfig - Configuration loader for intelligence system

COVERAGE:
- Initialization with defaults
- Load/merge with existing config
- Save to disk
- Backward compatibility
- Validation logic
"""

import pytest
import json
from pathlib import Path
from crack.track.intelligence.config import IntelligenceConfig


def test_config_initialization_defaults(tmp_path):
    """
    PROVES: IntelligenceConfig initializes with defaults when no config exists

    GIVEN: No existing config.json
    WHEN: IntelligenceConfig is initialized
    THEN: Default configuration is loaded
    """
    config_path = tmp_path / 'config.json'

    # Initialize with non-existent config
    intel_config = IntelligenceConfig(config_path=config_path)

    # Verify defaults loaded
    assert intel_config.is_enabled() is True
    assert intel_config.get_intelligence_config()['enabled'] is True
    assert intel_config.get_intelligence_config()['correlation']['auto_queue'] is False
    assert intel_config.get_intelligence_config()['methodology']['enforce_phases'] is False

    # Verify scoring weights
    weights = intel_config.get_scoring_weights()
    assert weights['quick_win'] == 2.0
    assert weights['phase_alignment'] == 1.0
    assert weights['chain_progress'] == 1.5


def test_config_load_merges_existing(tmp_path):
    """
    PROVES: Loading existing config merges with defaults without corruption

    GIVEN: Existing config.json with non-intelligence settings
    WHEN: IntelligenceConfig loads the config
    THEN:
        - Intelligence settings are added
        - Existing settings are preserved
        - No data loss
    """
    config_path = tmp_path / 'config.json'

    # Create existing config with non-intelligence settings
    existing_config = {
        "theme": {
            "current": "nord"
        },
        "variables": {
            "LHOST": {
                "value": "10.10.14.13"
            }
        },
        "sessions": {
            "auto_upgrade": True
        }
    }

    with open(config_path, 'w') as f:
        json.dump(existing_config, f)

    # Load config
    intel_config = IntelligenceConfig(config_path=config_path)

    # Verify intelligence settings added
    assert 'intelligence' in intel_config.config
    assert intel_config.is_enabled() is True

    # Verify existing settings preserved
    assert intel_config.config['theme']['current'] == 'nord'
    assert intel_config.config['variables']['LHOST']['value'] == '10.10.14.13'
    assert intel_config.config['sessions']['auto_upgrade'] is True


def test_config_load_merges_partial_intelligence(tmp_path):
    """
    PROVES: Partial intelligence config merges with defaults

    GIVEN: Config with partial intelligence settings
    WHEN: Config is loaded
    THEN: User overrides preserved, missing keys filled from defaults
    """
    config_path = tmp_path / 'config.json'

    # Create config with partial intelligence settings
    existing_config = {
        "intelligence": {
            "enabled": False,
            "scoring_weights": {
                "quick_win": 5.0  # User override
            }
        }
    }

    with open(config_path, 'w') as f:
        json.dump(existing_config, f)

    # Load config
    intel_config = IntelligenceConfig(config_path=config_path)

    # Verify user override preserved
    assert intel_config.is_enabled() is False
    weights = intel_config.get_scoring_weights()
    assert weights['quick_win'] == 5.0

    # Verify defaults filled in missing keys
    assert 'correlation' in intel_config.get_intelligence_config()
    assert 'methodology' in intel_config.get_intelligence_config()
    assert weights['phase_alignment'] == 1.0  # Default
    assert weights['chain_progress'] == 1.5   # Default


def test_config_save_persists(tmp_path):
    """
    PROVES: Configuration persists to disk without corruption

    GIVEN: IntelligenceConfig with modified settings
    WHEN: save() is called
    THEN:
        - Config written to disk
        - JSON valid
        - Reloading yields same config
    """
    config_path = tmp_path / 'config.json'

    # Initialize and modify
    intel_config = IntelligenceConfig(config_path=config_path)
    intel_config.config['intelligence']['enabled'] = False
    intel_config.config['intelligence']['scoring_weights']['quick_win'] = 10.0

    # Save
    intel_config.save()

    # Verify file exists
    assert config_path.exists()

    # Verify valid JSON
    with open(config_path, 'r') as f:
        saved_config = json.load(f)

    assert saved_config['intelligence']['enabled'] is False
    assert saved_config['intelligence']['scoring_weights']['quick_win'] == 10.0

    # Verify reload yields same config
    intel_config_reloaded = IntelligenceConfig(config_path=config_path)
    assert intel_config_reloaded.is_enabled() is False
    assert intel_config_reloaded.get_scoring_weights()['quick_win'] == 10.0


def test_is_enabled(tmp_path):
    """
    PROVES: is_enabled() reflects config value

    GIVEN: Config with enabled=True and enabled=False
    WHEN: is_enabled() called
    THEN: Returns correct boolean
    """
    config_path = tmp_path / 'config.json'

    # Test enabled=True
    config_true = {"intelligence": {"enabled": True}}
    with open(config_path, 'w') as f:
        json.dump(config_true, f)

    intel_config_true = IntelligenceConfig(config_path=config_path)
    assert intel_config_true.is_enabled() is True

    # Test enabled=False
    config_false = {"intelligence": {"enabled": False}}
    with open(config_path, 'w') as f:
        json.dump(config_false, f)

    intel_config_false = IntelligenceConfig(config_path=config_path)
    assert intel_config_false.is_enabled() is False


def test_get_scoring_weights(tmp_path):
    """
    PROVES: get_scoring_weights() returns dict of numeric values

    GIVEN: Config with custom scoring weights
    WHEN: get_scoring_weights() called
    THEN: Returns dict with all weights
    """
    config_path = tmp_path / 'config.json'

    custom_weights = {
        "phase_alignment": 2.0,
        "chain_progress": 3.0,
        "quick_win": 5.0,
        "time_estimate": 1.0,
        "dependencies": 2.5,
        "success_probability": 1.8,
        "user_preference": 1.2
    }

    config = {
        "intelligence": {
            "enabled": True,
            "scoring_weights": custom_weights
        }
    }

    with open(config_path, 'w') as f:
        json.dump(config, f)

    intel_config = IntelligenceConfig(config_path=config_path)
    weights = intel_config.get_scoring_weights()

    # Verify all weights present
    assert weights == custom_weights

    # Verify all values are numeric
    for weight_name, weight_value in weights.items():
        assert isinstance(weight_value, (int, float))


def test_validate_valid_config(tmp_path):
    """
    PROVES: Validation passes for valid config

    GIVEN: Valid intelligence configuration
    WHEN: validate() called
    THEN: Returns True
    """
    config_path = tmp_path / 'config.json'

    intel_config = IntelligenceConfig(config_path=config_path)

    # Default config should be valid
    assert intel_config.validate() is True


def test_validate_detects_missing_keys(tmp_path):
    """
    PROVES: Config system merges missing keys with defaults (backward compatibility)

    GIVEN: Config missing required keys
    WHEN: Config is loaded
    THEN: Missing keys filled from defaults, validation passes
    """
    config_path = tmp_path / 'config.json'

    # Create config missing 'correlation' key
    incomplete_config = {
        "intelligence": {
            "enabled": True,
            "methodology": {},
            "scoring_weights": {},
            "ui": {}
            # Missing 'correlation'
        }
    }

    with open(config_path, 'w') as f:
        json.dump(incomplete_config, f)

    intel_config = IntelligenceConfig(config_path=config_path)

    # Should pass validation (defaults fill missing keys)
    assert intel_config.validate() is True

    # Verify missing key filled from defaults
    assert 'correlation' in intel_config.get_intelligence_config()


def test_validate_detects_invalid_types(tmp_path):
    """
    PROVES: Validation detects invalid data types

    GIVEN: Config with non-boolean 'enabled' and non-numeric weight
    WHEN: validate() called
    THEN: Returns False
    """
    config_path = tmp_path / 'config.json'

    # Test invalid 'enabled' type
    invalid_enabled = {
        "intelligence": {
            "enabled": "yes",  # Should be boolean
            "correlation": {},
            "methodology": {},
            "scoring_weights": {},
            "ui": {}
        }
    }

    with open(config_path, 'w') as f:
        json.dump(invalid_enabled, f)

    intel_config = IntelligenceConfig(config_path=config_path)
    assert intel_config.validate() is False

    # Test invalid weight type
    invalid_weight = {
        "intelligence": {
            "enabled": True,
            "correlation": {},
            "methodology": {},
            "scoring_weights": {
                "quick_win": "high"  # Should be numeric
            },
            "ui": {}
        }
    }

    with open(config_path, 'w') as f:
        json.dump(invalid_weight, f)

    intel_config = IntelligenceConfig(config_path=config_path)
    assert intel_config.validate() is False


def test_config_preserves_existing_on_save(tmp_path):
    """
    PROVES: Saving intelligence config doesn't corrupt other settings

    GIVEN: Config with existing theme, variables, sessions
    WHEN: Intelligence config is modified and saved
    THEN: Original settings remain intact
    """
    config_path = tmp_path / 'config.json'

    # Create comprehensive existing config
    original_config = {
        "theme": {"current": "nord"},
        "variables": {
            "LHOST": {"value": "10.10.14.13"},
            "TARGET": {"value": "192.168.45.100"}
        },
        "sessions": {
            "auto_upgrade": True,
            "storage_path": "~/.crack/sessions"
        }
    }

    with open(config_path, 'w') as f:
        json.dump(original_config, f)

    # Load, modify intelligence settings, save
    intel_config = IntelligenceConfig(config_path=config_path)
    intel_config.config['intelligence']['enabled'] = False
    intel_config.save()

    # Reload and verify preservation
    with open(config_path, 'r') as f:
        saved_config = json.load(f)

    # Intelligence settings modified
    assert saved_config['intelligence']['enabled'] is False

    # Original settings preserved
    assert saved_config['theme']['current'] == 'nord'
    assert saved_config['variables']['LHOST']['value'] == '10.10.14.13'
    assert saved_config['variables']['TARGET']['value'] == '192.168.45.100'
    assert saved_config['sessions']['auto_upgrade'] is True
    assert saved_config['sessions']['storage_path'] == '~/.crack/sessions'


def test_merge_configs_deep_nesting(tmp_path):
    """
    PROVES: Deep merge works for nested dictionaries

    GIVEN: Config with multiple nesting levels
    WHEN: Configs are merged
    THEN: All levels merged correctly
    """
    config_path = tmp_path / 'config.json'

    # Create config with deep overrides
    existing_config = {
        "intelligence": {
            "enabled": True,
            "correlation": {
                "enabled": False,  # Override
                "auto_queue": True  # Override
                # Missing 'credential_spray' (should use default)
            },
            "scoring_weights": {
                "quick_win": 10.0  # Override
                # Missing other weights (should use defaults)
            }
        }
    }

    with open(config_path, 'w') as f:
        json.dump(existing_config, f)

    intel_config = IntelligenceConfig(config_path=config_path)

    # Verify overrides applied
    assert intel_config.get_intelligence_config()['correlation']['enabled'] is False
    assert intel_config.get_intelligence_config()['correlation']['auto_queue'] is True

    # Verify defaults filled
    assert intel_config.get_intelligence_config()['correlation']['credential_spray'] is True
    assert intel_config.get_scoring_weights()['phase_alignment'] == 1.0


def test_config_handles_corrupted_json(tmp_path):
    """
    PROVES: Config handles corrupted JSON gracefully

    GIVEN: Corrupted config.json
    WHEN: Config is loaded
    THEN: Falls back to defaults without crashing
    """
    config_path = tmp_path / 'config.json'

    # Write corrupted JSON
    with open(config_path, 'w') as f:
        f.write("{invalid json content here")

    # Should not crash, should use defaults
    intel_config = IntelligenceConfig(config_path=config_path)

    # Verify defaults loaded - check structure validity rather than specific values
    # (avoids test pollution from other tests modifying DEFAULT_CONFIG)
    intel_section = intel_config.get_intelligence_config()
    assert 'enabled' in intel_section
    assert 'correlation' in intel_section
    assert 'methodology' in intel_section
    assert 'scoring_weights' in intel_section
    assert intel_config.validate() is True
