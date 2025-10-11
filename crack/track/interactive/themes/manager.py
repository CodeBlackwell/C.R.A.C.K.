"""
Theme Manager - Centralized theme loading and color access

Handles:
- Loading theme from config
- Switching themes dynamically
- Accessing semantic colors
- Accessing component-specific colors
"""

import json
from pathlib import Path
from typing import Optional, Dict, Any

from .presets import get_theme, get_theme_names, list_themes as list_preset_themes

# Import for type hints only - avoid circular imports
try:
    from ..log_types import LogCategory, LogLevel
except ImportError:
    # Graceful fallback if imports fail
    LogCategory = None
    LogLevel = None


class ThemeManager:
    """Central theme management system"""

    def __init__(self, config_path: Optional[str] = None, debug_logger=None):
        """
        Initialize theme manager

        Args:
            config_path: Path to config.json (default: ~/.crack/config.json)
            debug_logger: Optional DebugLogger instance for logging
        """
        self.config_path = config_path or str(Path.home() / ".crack" / "config.json")
        self.debug_logger = debug_logger
        self.current_theme_name = "oscp"  # Default theme
        self.current_theme = get_theme("oscp")

        if self.debug_logger and LogCategory and LogLevel:
            self.debug_logger.log("ThemeManager initializing", category=LogCategory.SYSTEM_INIT, level=LogLevel.VERBOSE,
                                 config_path=self.config_path)

        self._load_from_config()

    def _load_from_config(self):
        """Load theme preference from config file"""
        try:
            config_file = Path(self.config_path)
            if config_file.exists():
                with open(config_file, 'r') as f:
                    config = json.load(f)

                # Get theme from config (support multiple locations for backward compat)
                theme_name = config.get('theme', {}).get('current')
                if not theme_name:
                    theme_name = config.get('settings', {}).get('theme')
                if not theme_name:
                    theme_name = 'oscp'  # Fallback to default

                if self.debug_logger and LogCategory and LogLevel:
                    self.debug_logger.log("Theme preference loaded from config", category=LogCategory.CONFIG_LOAD, level=LogLevel.VERBOSE,
                                         theme_name=theme_name, config_file=str(config_file))

                # Validate and load theme
                if theme_name in get_theme_names():
                    self.current_theme_name = theme_name
                    self.current_theme = get_theme(theme_name)

                    if self.debug_logger and LogCategory and LogLevel:
                        self.debug_logger.log("✓ Theme loaded successfully", category=LogCategory.THEME_LOAD, level=LogLevel.NORMAL,
                                             theme_name=theme_name)
                else:
                    # Invalid theme in config - fall back to oscp
                    if self.debug_logger and LogCategory and LogLevel:
                        self.debug_logger.log("✗ Invalid theme in config - falling back to oscp", category=LogCategory.THEME_LOAD,
                                             level=LogLevel.NORMAL, invalid_theme=theme_name)

                    self.current_theme_name = 'oscp'
                    self.current_theme = get_theme('oscp')
            else:
                if self.debug_logger and LogCategory and LogLevel:
                    self.debug_logger.log("Config file not found - using default theme", category=LogCategory.CONFIG_LOAD,
                                         level=LogLevel.VERBOSE, config_file=str(config_file))

        except (json.JSONDecodeError, FileNotFoundError, KeyError) as e:
            # Config error - use default theme
            if self.debug_logger and LogCategory and LogLevel:
                self.debug_logger.log("Config load error - using default theme", category=LogCategory.CONFIG_ERROR,
                                     level=LogLevel.NORMAL, error=str(e))

            self.current_theme_name = 'oscp'
            self.current_theme = get_theme('oscp')

    def set_theme(self, theme_name: str) -> bool:
        """
        Switch to a different theme

        Args:
            theme_name: Name of theme to switch to

        Returns:
            True if successful, False if theme not found
        """
        if self.debug_logger and LogCategory and LogLevel:
            self.debug_logger.log("Theme switch requested", category=LogCategory.THEME_SWITCH, level=LogLevel.NORMAL,
                                 from_theme=self.current_theme_name, to_theme=theme_name)

        try:
            new_theme = get_theme(theme_name)
            self.current_theme_name = theme_name
            self.current_theme = new_theme

            if self.debug_logger and LogCategory and LogLevel:
                self.debug_logger.log("✓ Theme switched successfully", category=LogCategory.THEME_SWITCH, level=LogLevel.NORMAL,
                                     theme_name=theme_name)

            # Persist to config
            self._save_to_config()
            return True

        except KeyError:
            if self.debug_logger and LogCategory and LogLevel:
                self.debug_logger.log("✗ Theme switch failed: theme not found", category=LogCategory.THEME_SWITCH,
                                     level=LogLevel.NORMAL, theme_name=theme_name)
            return False

    def _save_to_config(self):
        """Save current theme preference to config file"""
        try:
            config_file = Path(self.config_path)

            # Load existing config
            if config_file.exists():
                with open(config_file, 'r') as f:
                    config = json.load(f)
            else:
                config = {}

            # Update theme setting
            if 'theme' not in config:
                config['theme'] = {}
            config['theme']['current'] = self.current_theme_name

            # Save config
            config_file.parent.mkdir(parents=True, exist_ok=True)
            with open(config_file, 'w') as f:
                json.dump(config, f, indent=2)

            if self.debug_logger and LogCategory and LogLevel:
                self.debug_logger.log("✓ Theme preference saved to config", category=LogCategory.CONFIG_SAVE, level=LogLevel.VERBOSE,
                                     theme_name=self.current_theme_name, config_file=str(config_file))

        except Exception as e:
            # Silent fail - theme still works in memory
            if self.debug_logger and LogCategory and LogLevel:
                self.debug_logger.log("✗ Failed to save theme to config (theme still active in memory)",
                                     category=LogCategory.CONFIG_ERROR, level=LogLevel.NORMAL, error=str(e))

    def get_color(self, role: str, fallback: str = "white") -> str:
        """
        Get semantic color by role

        Args:
            role: Color role (e.g., 'primary', 'success', 'warning')
            fallback: Fallback color if role not found

        Returns:
            Rich color name (e.g., 'cyan', 'bright_green')
        """
        return self.current_theme.get('colors', {}).get(role, fallback)

    def get_component_color(self, component: str, fallback: str = "white") -> str:
        """
        Get component-specific color

        Args:
            component: Component name (e.g., 'panel_border', 'task_pending')
            fallback: Fallback color if component not found

        Returns:
            Rich color name
        """
        return self.current_theme.get('components', {}).get(component, fallback)

    def get_theme_name(self) -> str:
        """Get current theme name"""
        return self.current_theme_name

    def get_theme_info(self) -> Dict[str, str]:
        """
        Get current theme metadata

        Returns:
            Dict with keys: name, display_name, description
        """
        return {
            "name": self.current_theme_name,
            "display_name": self.current_theme.get("name", self.current_theme_name),
            "description": self.current_theme.get("description", "")
        }

    def list_themes(self) -> list:
        """
        Get list of all available themes

        Returns:
            List of theme metadata dicts
        """
        return list_preset_themes()

    # Convenience methods for common colors

    def primary(self, text: str) -> str:
        """Wrap text in primary color markup"""
        color = self.get_color('primary')
        return f"[{color}]{text}[/{color}]"

    def secondary(self, text: str) -> str:
        """Wrap text in secondary color markup"""
        color = self.get_color('secondary')
        return f"[{color}]{text}[/{color}]"

    def success(self, text: str) -> str:
        """Wrap text in success color markup"""
        color = self.get_color('success')
        return f"[{color}]{text}[/{color}]"

    def warning(self, text: str) -> str:
        """Wrap text in warning color markup"""
        color = self.get_color('warning')
        return f"[{color}]{text}[/{color}]"

    def danger(self, text: str) -> str:
        """Wrap text in danger color markup"""
        color = self.get_color('danger')
        return f"[{color}]{text}[/{color}]"

    def info(self, text: str) -> str:
        """Wrap text in info color markup"""
        color = self.get_color('info')
        return f"[{color}]{text}[/{color}]"

    def muted(self, text: str) -> str:
        """Wrap text in muted color markup"""
        color = self.get_color('muted')
        return f"[{color}]{text}[/{color}]"

    def emphasis(self, text: str) -> str:
        """Wrap text in emphasis color markup"""
        color = self.get_color('emphasis')
        return f"[{color}]{text}[/{color}]"

    # Component-specific convenience methods

    def panel_border(self) -> str:
        """Get panel border color"""
        return self.get_component_color('panel_border')

    def overlay_border(self) -> str:
        """Get overlay border color"""
        return self.get_component_color('overlay_border')

    def form_border(self) -> str:
        """Get form border color"""
        return self.get_component_color('form_border')

    def task_state_color(self, state: str) -> str:
        """
        Get color for task state

        Args:
            state: Task state ('pending', 'in-progress', 'completed', 'failed', 'skipped')

        Returns:
            Rich color name
        """
        state_normalized = state.replace('_', '-').lower()
        component_key = f'task_{state_normalized.replace("-", "_")}'
        return self.get_component_color(component_key, 'white')

    def finding_type_color(self, finding_type: str) -> str:
        """
        Get color for finding type

        Args:
            finding_type: Finding type ('vulnerability', 'directory', 'file', etc.)

        Returns:
            Rich color name
        """
        component_key = f'finding_{finding_type}'
        return self.get_component_color(component_key, 'white')

    def port_state_color(self, state: str) -> str:
        """
        Get color for port state

        Args:
            state: Port state ('open', 'filtered', 'closed')

        Returns:
            Rich color name
        """
        component_key = f'port_{state}'
        return self.get_component_color(component_key, 'white')


__all__ = ['ThemeManager']
