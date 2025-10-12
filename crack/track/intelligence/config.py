"""
Intelligence Configuration - Load/save settings for hybrid intelligence system

Extends ~/.crack/config.json with intelligence-specific settings while
maintaining backward compatibility with existing configuration.
"""

from typing import Dict, Any, Optional
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class IntelligenceConfig:
    """Manages intelligence system configuration"""

    # Default configuration structure
    DEFAULT_CONFIG = {
        "intelligence": {
            "enabled": True,
            "correlation": {
                "enabled": True,
                "auto_queue": False,  # Conservative default
                "credential_spray": True,
                "cross_service_patterns": True
            },
            "methodology": {
                "enabled": True,
                "enforce_phases": False,  # Suggestions not requirements
                "quick_wins_priority": True,
                "phase_transition_auto": False
            },
            "scoring_weights": {
                "phase_alignment": 1.0,
                "chain_progress": 1.5,
                "quick_win": 2.0,
                "time_estimate": 0.5,
                "dependencies": 1.0,
                "success_probability": 1.2,
                "user_preference": 0.8
            },
            "ui": {
                "show_guidance": True,
                "guidance_position": "top",
                "max_suggestions": 5,
                "show_reasoning": True
            }
        }
    }

    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize intelligence configuration

        Args:
            config_path: Path to config.json (defaults to ~/.crack/config.json)
        """
        if config_path is None:
            config_path = Path.home() / '.crack' / 'config.json'

        self.config_path = config_path
        self.config = self.load()

        logger.info(f"[INTEL.CONFIG] Loaded from {config_path}")

    def load(self) -> Dict[str, Any]:
        """
        Load intelligence configuration

        Returns:
            Configuration dict with intelligence settings
        """
        # Start with defaults
        config = self.DEFAULT_CONFIG.copy()

        # Load existing config if present
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    existing_config = json.load(f)

                # Merge intelligence settings (preserves existing non-intelligence settings)
                if 'intelligence' in existing_config:
                    config['intelligence'] = self._merge_configs(
                        config['intelligence'],
                        existing_config['intelligence']
                    )
                    logger.debug("[INTEL.CONFIG] Merged with existing intelligence settings")
                else:
                    logger.debug("[INTEL.CONFIG] No existing intelligence settings, using defaults")

                # Preserve other top-level keys
                for key in existing_config:
                    if key != 'intelligence':
                        config[key] = existing_config[key]

            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"[INTEL.CONFIG] Failed to load existing config: {e}, using defaults")
        else:
            logger.info("[INTEL.CONFIG] No existing config, using defaults")

        return config

    def save(self):
        """Save current configuration to disk"""
        try:
            # Ensure directory exists
            self.config_path.parent.mkdir(parents=True, exist_ok=True)

            # Write config
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2)

            logger.info(f"[INTEL.CONFIG] Saved to {self.config_path}")
        except IOError as e:
            logger.error(f"[INTEL.CONFIG] Failed to save: {e}")
            raise

    def get_intelligence_config(self) -> Dict[str, Any]:
        """Get intelligence-specific configuration"""
        return self.config.get('intelligence', self.DEFAULT_CONFIG['intelligence'])

    def is_enabled(self) -> bool:
        """Check if intelligence system is enabled"""
        intel_config = self.get_intelligence_config()
        return intel_config.get('enabled', True)

    def get_scoring_weights(self) -> Dict[str, float]:
        """Get scoring weights for TaskScorer"""
        intel_config = self.get_intelligence_config()
        return intel_config.get('scoring_weights', self.DEFAULT_CONFIG['intelligence']['scoring_weights'])

    def _merge_configs(self, default: Dict, override: Dict) -> Dict:
        """
        Deep merge configuration dicts

        Args:
            default: Default configuration
            override: User-provided overrides

        Returns:
            Merged configuration (override takes precedence)
        """
        result = default.copy()

        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                # Recursive merge for nested dicts
                result[key] = self._merge_configs(result[key], value)
            else:
                # Direct override
                result[key] = value

        return result

    def validate(self) -> bool:
        """
        Validate configuration structure and types

        Returns:
            True if valid, False otherwise
        """
        try:
            intel_config = self.get_intelligence_config()

            # Check required keys
            required_keys = ['enabled', 'correlation', 'methodology', 'scoring_weights', 'ui']
            for key in required_keys:
                if key not in intel_config:
                    logger.warning(f"[INTEL.CONFIG] Missing required key: {key}")
                    return False

            # Validate types
            if not isinstance(intel_config['enabled'], bool):
                logger.warning("[INTEL.CONFIG] 'enabled' must be boolean")
                return False

            # Validate scoring weights are numeric
            weights = intel_config.get('scoring_weights', {})
            for weight_name, weight_value in weights.items():
                if not isinstance(weight_value, (int, float)):
                    logger.warning(f"[INTEL.CONFIG] Weight '{weight_name}' must be numeric")
                    return False

            logger.info("[INTEL.CONFIG] Configuration valid")
            return True

        except Exception as e:
            logger.error(f"[INTEL.CONFIG] Validation failed: {e}")
            return False
