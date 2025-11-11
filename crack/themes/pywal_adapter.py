"""
Pywal theme adapter for CRACK

Imports 250+ themes from pywal16 library and converts them to CRACK theme format.
Falls back gracefully if pywal16 is not installed.
"""

from typing import Dict, Any, Optional
import warnings


# Pywal color0-15 → Rich color name mapping
PYWAL_TO_RICH_MAP = {
    'color0': 'black',           # Base00 - Black
    'color1': 'red',             # Base08 - Red
    'color2': 'green',           # Base0B - Green
    'color3': 'yellow',          # Base0A - Yellow
    'color4': 'blue',            # Base0D - Blue
    'color5': 'magenta',         # Base0E - Magenta/Purple
    'color6': 'cyan',            # Base0C - Cyan
    'color7': 'white',           # Base05 - White
    'color8': 'bright_black',    # Base03 - Bright Black (Gray)
    'color9': 'bright_red',      # Base08 variant
    'color10': 'bright_green',   # Base0B variant
    'color11': 'bright_yellow',  # Base0A variant
    'color12': 'bright_blue',    # Base0D variant
    'color13': 'bright_magenta', # Base0E variant
    'color14': 'bright_cyan',    # Base0C variant
    'color15': 'bright_white',   # Base07 - Bright White
}


def _map_pywal_to_theme(colors_dict: Dict[str, str], theme_name: str, theme_desc: str = "") -> Dict[str, Any]:
    """
    Convert pywal color dictionary to CRACK theme format

    Args:
        colors_dict: Pywal colors dictionary (color0-15)
        theme_name: Display name for the theme
        theme_desc: Optional description

    Returns:
        Theme dictionary matching BUILT_IN_THEMES structure
    """
    # Convert pywal colors to Rich names
    rich_colors = {
        pywal_key: PYWAL_TO_RICH_MAP.get(pywal_key, 'white')
        for pywal_key in colors_dict.keys()
    }

    # Map to semantic roles
    return {
        "name": theme_name,
        "description": theme_desc or f"Pywal theme: {theme_name}",
        "colors": {
            # Core semantic colors (using base16 standard mapping)
            "primary": rich_colors.get('color4', 'cyan'),         # Blue
            "secondary": rich_colors.get('color5', 'magenta'),    # Purple
            "success": rich_colors.get('color2', 'green'),        # Green
            "warning": rich_colors.get('color3', 'yellow'),       # Yellow
            "danger": rich_colors.get('color1', 'red'),           # Red
            "info": rich_colors.get('color6', 'cyan'),            # Cyan
            "muted": rich_colors.get('color8', 'dim'),            # Bright Black
            "emphasis": f"bold {rich_colors.get('color15', 'bright_white')}",  # Bold White

            # Text colors
            "text": rich_colors.get('color7', 'white'),
            "text_dim": rich_colors.get('color8', 'dim'),
            "text_bright": rich_colors.get('color15', 'bright_white'),
        },
        "components": {
            # Panel borders
            "panel_border": rich_colors.get('color6', 'cyan'),
            "overlay_border": rich_colors.get('color4', 'blue'),
            "form_border": rich_colors.get('color2', 'green'),
            "error_border": rich_colors.get('color1', 'red'),
            "warning_border": rich_colors.get('color3', 'yellow'),

            # Task states
            "task_pending": rich_colors.get('color3', 'yellow'),
            "task_in_progress": rich_colors.get('color6', 'cyan'),
            "task_completed": rich_colors.get('color2', 'green'),
            "task_failed": rich_colors.get('color1', 'red'),
            "task_skipped": rich_colors.get('color8', 'dim'),

            # Priority badges
            "priority_high": rich_colors.get('color9', 'bright_red'),
            "priority_medium": rich_colors.get('color3', 'yellow'),
            "priority_low": rich_colors.get('color8', 'dim'),
            "quick_win": rich_colors.get('color11', 'bright_yellow'),

            # Port states
            "port_open": rich_colors.get('color2', 'green'),
            "port_filtered": rich_colors.get('color3', 'yellow'),
            "port_closed": rich_colors.get('color8', 'dim'),

            # Finding types
            "finding_vulnerability": rich_colors.get('color1', 'red'),
            "finding_directory": rich_colors.get('color6', 'cyan'),
            "finding_file": rich_colors.get('color4', 'blue'),
            "finding_credential": rich_colors.get('color3', 'yellow'),
            "finding_user": rich_colors.get('color5', 'magenta'),
            "finding_general": rich_colors.get('color7', 'white'),

            # UI elements
            "menu_number": f"bold {rich_colors.get('color15', 'bright_white')}",
            "hotkey": rich_colors.get('color6', 'cyan'),
            "command": rich_colors.get('color8', 'bright_black'),
            "timestamp": rich_colors.get('color8', 'dim'),
            "progress_bar": rich_colors.get('color6', 'cyan'),

            # Status indicators
            "status_active": rich_colors.get('color2', 'green'),
            "status_inactive": rich_colors.get('color8', 'dim'),
            "status_error": rich_colors.get('color1', 'red'),
        }
    }


def load_pywal_themes() -> Dict[str, Dict[str, Any]]:
    """
    Load all available pywal themes by reading JSON files directly

    Returns:
        Dictionary of themes in CRACK format, empty dict if pywal16 not installed
    """
    try:
        from pywal import theme as pywal_theme
        import json
    except ImportError:
        warnings.warn(
            "pywal16 not found. Please reinstall CRACK to enable 250+ themes: pip install -e .",
            ImportWarning,
            stacklevel=2
        )
        return {}

    pywal_themes = {}

    try:
        # Get list of available theme files (DirEntry objects with .path attribute)
        available_themes = pywal_theme.list_themes()

        for theme_entry in available_themes:
            try:
                # Extract theme name from DirEntry
                if hasattr(theme_entry, 'name'):
                    theme_name = theme_entry.name.replace('.json', '')
                    theme_path = theme_entry.path
                else:
                    # Fallback for string entries (shouldn't happen with pywal16)
                    theme_name = str(theme_entry).replace('.json', '')
                    continue  # Skip if we don't have a path

                # Read JSON file directly (no theme setting)
                with open(theme_path, 'r') as f:
                    theme_data = json.load(f)

                # Extract colors and special data
                colors = theme_data.get('colors', {})
                special = theme_data.get('special', {})

                # Convert to CRACK format
                crack_theme = _map_pywal_to_theme(
                    colors,
                    theme_name,
                    special.get('background', '')
                )

                # Use pywal theme name as key (with 'pw_' prefix to avoid collisions)
                pywal_themes[f"pw_{theme_name}"] = crack_theme

            except Exception as e:
                # Skip themes that fail to load
                warnings.warn(f"Failed to load pywal theme '{theme_name}': {e}", stacklevel=2)
                continue

    except Exception as e:
        warnings.warn(f"Failed to enumerate pywal themes: {e}", stacklevel=2)
        return {}

    return pywal_themes


def get_pywal_theme(theme_name: str) -> Optional[Dict[str, Any]]:
    """
    Get a specific pywal theme by name

    Args:
        theme_name: Name of the pywal theme (with or without 'pw_' prefix)

    Returns:
        Theme dictionary or None if not found
    """
    themes = load_pywal_themes()

    # Try with and without prefix
    if theme_name in themes:
        return themes[theme_name]

    prefixed = f"pw_{theme_name}"
    if prefixed in themes:
        return themes[prefixed]

    return None


# Lazy-load themes on module import (cached)
_PYWAL_THEMES_CACHE: Optional[Dict[str, Dict[str, Any]]] = None


def get_all_pywal_themes() -> Dict[str, Dict[str, Any]]:
    """
    Get all pywal themes (cached)

    Returns:
        Dictionary of all pywal themes, empty dict if pywal16 not installed
    """
    global _PYWAL_THEMES_CACHE

    if _PYWAL_THEMES_CACHE is None:
        _PYWAL_THEMES_CACHE = load_pywal_themes()

    return _PYWAL_THEMES_CACHE


def is_pywal_available() -> bool:
    """Check if pywal16 is installed"""
    try:
        import pywal
        return True
    except ImportError:
        return False


__all__ = [
    'load_pywal_themes',
    'get_pywal_theme',
    'get_all_pywal_themes',
    'is_pywal_available',
]
