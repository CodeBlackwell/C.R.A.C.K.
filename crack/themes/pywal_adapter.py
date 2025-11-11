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
        colors_dict: Pywal colors dictionary (color0-15) with hex values
        theme_name: Display name for the theme
        theme_desc: Optional description

    Returns:
        Theme dictionary matching BUILT_IN_THEMES structure

    Note:
        Preserves hex color values for true 24-bit color output.
        The hex colors will be converted to RGB ANSI codes by Colors.from_rich().
    """
    # Use hex colors directly (no conversion to generic names!)
    # colors_dict already contains hex values like '#689d6a'

    # Map to semantic roles
    return {
        "name": theme_name,
        "description": theme_desc or f"Pywal theme: {theme_name}",
        "colors": {
            # Core semantic colors (using base16 standard mapping with hex values)
            "primary": colors_dict.get('color4', '#0000ff'),         # Blue hex
            "secondary": colors_dict.get('color5', '#ff00ff'),       # Magenta hex
            "success": colors_dict.get('color2', '#00ff00'),         # Green hex
            "warning": colors_dict.get('color3', '#ffff00'),         # Yellow hex
            "danger": colors_dict.get('color1', '#ff0000'),          # Red hex
            "info": colors_dict.get('color6', '#00ffff'),            # Cyan hex
            "muted": colors_dict.get('color8', '#808080'),           # Bright black/gray hex
            "emphasis": f"bold {colors_dict.get('color15', '#ffffff')}",  # Bold white hex

            # Text colors
            "text": colors_dict.get('color7', '#ffffff'),            # White hex
            "text_dim": colors_dict.get('color8', '#808080'),        # Gray hex
            "text_bright": colors_dict.get('color15', '#ffffff'),   # Bright white hex
        },
        "components": {
            # Panel borders (using hex colors)
            "panel_border": colors_dict.get('color6', '#00ffff'),       # Cyan hex
            "overlay_border": colors_dict.get('color4', '#0000ff'),     # Blue hex
            "form_border": colors_dict.get('color2', '#00ff00'),        # Green hex
            "error_border": colors_dict.get('color1', '#ff0000'),       # Red hex
            "warning_border": colors_dict.get('color3', '#ffff00'),     # Yellow hex

            # Task states (using hex colors)
            "task_pending": colors_dict.get('color3', '#ffff00'),       # Yellow hex
            "task_in_progress": colors_dict.get('color6', '#00ffff'),   # Cyan hex
            "task_completed": colors_dict.get('color2', '#00ff00'),     # Green hex
            "task_failed": colors_dict.get('color1', '#ff0000'),        # Red hex
            "task_skipped": colors_dict.get('color8', '#808080'),       # Gray hex

            # Priority badges (using hex colors)
            "priority_high": colors_dict.get('color9', '#ff0000'),      # Bright red hex
            "priority_medium": colors_dict.get('color3', '#ffff00'),    # Yellow hex
            "priority_low": colors_dict.get('color8', '#808080'),       # Gray hex
            "quick_win": colors_dict.get('color11', '#ffff00'),         # Bright yellow hex

            # Port states (using hex colors)
            "port_open": colors_dict.get('color2', '#00ff00'),          # Green hex
            "port_filtered": colors_dict.get('color3', '#ffff00'),      # Yellow hex
            "port_closed": colors_dict.get('color8', '#808080'),        # Gray hex

            # Finding types (using hex colors)
            "finding_vulnerability": colors_dict.get('color1', '#ff0000'),  # Red hex
            "finding_directory": colors_dict.get('color6', '#00ffff'),      # Cyan hex
            "finding_file": colors_dict.get('color4', '#0000ff'),           # Blue hex
            "finding_credential": colors_dict.get('color3', '#ffff00'),     # Yellow hex
            "finding_user": colors_dict.get('color5', '#ff00ff'),           # Magenta hex
            "finding_general": colors_dict.get('color7', '#ffffff'),        # White hex

            # UI elements (using hex colors)
            "menu_number": f"bold {colors_dict.get('color15', '#ffffff')}",  # Bold white hex
            "hotkey": colors_dict.get('color6', '#00ffff'),                   # Cyan hex
            "command": colors_dict.get('color8', '#808080'),                  # Gray hex
            "timestamp": colors_dict.get('color8', '#808080'),                # Gray hex
            "progress_bar": colors_dict.get('color6', '#00ffff'),             # Cyan hex

            # Status indicators (using hex colors)
            "status_active": colors_dict.get('color2', '#00ff00'),      # Green hex
            "status_inactive": colors_dict.get('color8', '#808080'),    # Gray hex
            "status_error": colors_dict.get('color1', '#ff0000'),       # Red hex

            # Notes formatting (for command descriptions, cheatsheets) (using hex colors)
            "notes_step": f"bold {colors_dict.get('color3', '#ffff00')}",      # Step markers (yellow)
            "notes_section": f"bold {colors_dict.get('color6', '#00ffff')}",   # Section headers (cyan)
            "notes_success": colors_dict.get('color2', '#00ff00'),              # Success indicators (green)
            "notes_failure": colors_dict.get('color1', '#ff0000'),              # Failure messages (red)
            "notes_code": colors_dict.get('color8', '#808080'),                 # Inline code (gray)
            "notes_warning": colors_dict.get('color3', '#ffff00'),              # WARNING markers (yellow)
            "notes_tip": colors_dict.get('color6', '#00ffff'),                  # TIP markers (cyan)
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
