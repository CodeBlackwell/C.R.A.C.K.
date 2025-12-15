"""
Built-in theme presets for CRACK Track TUI

Each theme defines semantic color roles and component-specific colors.
All colors use Rich markup style names (e.g., 'cyan', 'bold green', 'bright_yellow')
"""

from typing import Dict, Any

# Import pywal adapter (optional - graceful fallback if not installed)
try:
    from .pywal_adapter import get_all_pywal_themes, is_pywal_available
except ImportError:
    def get_all_pywal_themes():
        return {}
    def is_pywal_available():
        return False


# Theme structure:
# - colors: Semantic roles (primary, success, warning, etc.)
# - components: Specific UI elements (panel_border, task states, etc.)

BUILT_IN_THEMES: Dict[str, Dict[str, Any]] = {
    "oscp": {
        "name": "OSCP Classic",
        "description": "Cyan-heavy aesthetic optimized for OSCP workflow",
        "colors": {
            # Core semantic colors
            "primary": "cyan",
            "secondary": "blue",
            "success": "green",
            "warning": "yellow",
            "danger": "red",
            "info": "blue",
            "muted": "dim",
            "emphasis": "bold bright_cyan",

            # Text colors
            "text": "white",
            "text_dim": "dim",
            "text_bright": "bright_white",
        },
        "components": {
            # Panel borders
            "panel_border": "cyan",
            "overlay_border": "blue",
            "form_border": "green",
            "error_border": "red",
            "warning_border": "yellow",

            # Task states
            "task_pending": "yellow",
            "task_in_progress": "cyan",
            "task_completed": "green",
            "task_failed": "red",
            "task_skipped": "dim",

            # Priority badges
            "priority_high": "bright_red",
            "priority_medium": "yellow",
            "priority_low": "dim",
            "quick_win": "bright_yellow",

            # Port states
            "port_open": "green",
            "port_filtered": "yellow",
            "port_closed": "dim",

            # Finding types
            "finding_vulnerability": "red",
            "finding_directory": "cyan",
            "finding_file": "blue",
            "finding_credential": "yellow",
            "finding_user": "magenta",
            "finding_general": "white",

            # UI elements
            "menu_number": "bold bright_white",
            "hotkey": "cyan",
            "command": "bright_black",
            "timestamp": "dim",
            "progress_bar": "cyan",

            # Status indicators
            "status_active": "green",
            "status_inactive": "dim",
            "status_error": "red",

            # Notes formatting (for command descriptions, cheatsheets)
            "notes_step": "bold yellow",           # Step markers (Step 1:, (1), etc.)
            "notes_section": "bold bright_cyan",   # Section headers (OSCP METHODOLOGY:, etc.)
            "notes_success": "green",              # Success indicators and expected outputs
            "notes_failure": "red",                # Failure messages and error indicators
            "notes_code": "bright_black",          # Inline code/commands in notes
            "notes_warning": "yellow",             # WARNING:, CRITICAL:, PITFALL: markers
            "notes_tip": "bright_cyan",            # TIP:, EXAM TIP: markers
        }
    },

    "dark": {
        "name": "Dark Mode",
        "description": "Dark terminal optimized with muted colors",
        "colors": {
            "primary": "bright_blue",
            "secondary": "blue",
            "success": "bright_green",
            "warning": "bright_yellow",
            "danger": "bright_red",
            "info": "bright_cyan",
            "muted": "dim",
            "emphasis": "bold bright_white",
            "text": "white",
            "text_dim": "bright_black",
            "text_bright": "bright_white",
        },
        "components": {
            "panel_border": "bright_blue",
            "overlay_border": "blue",
            "form_border": "bright_green",
            "error_border": "bright_red",
            "warning_border": "bright_yellow",
            "task_pending": "bright_yellow",
            "task_in_progress": "bright_cyan",
            "task_completed": "bright_green",
            "task_failed": "bright_red",
            "task_skipped": "bright_black",
            "priority_high": "bright_red",
            "priority_medium": "bright_yellow",
            "priority_low": "bright_black",
            "quick_win": "bright_yellow",
            "port_open": "bright_green",
            "port_filtered": "bright_yellow",
            "port_closed": "bright_black",
            "finding_vulnerability": "bright_red",
            "finding_directory": "bright_cyan",
            "finding_file": "bright_blue",
            "finding_credential": "bright_yellow",
            "finding_user": "bright_magenta",
            "finding_general": "white",
            "menu_number": "bold bright_white",
            "hotkey": "bright_cyan",
            "command": "bright_black",
            "timestamp": "bright_black",
            "progress_bar": "bright_blue",
            "status_active": "bright_green",
            "status_inactive": "bright_black",
            "status_error": "bright_red",

            # Notes formatting (for command descriptions, cheatsheets)
            "notes_step": "bold bright_yellow",       # Step markers (Step 1:, (1), etc.)
            "notes_section": "bold bright_white",     # Section headers (OSCP METHODOLOGY:, etc.)
            "notes_success": "bright_green",          # Success indicators and expected outputs
            "notes_failure": "bright_red",            # Failure messages and error indicators
            "notes_code": "bright_black",             # Inline code/commands in notes
            "notes_warning": "bright_yellow",         # WARNING:, CRITICAL:, PITFALL: markers
            "notes_tip": "bright_cyan",               # TIP:, EXAM TIP: markers
        }
    },

    "light": {
        "name": "Light Mode",
        "description": "Light terminal optimized with darker colors for contrast",
        "colors": {
            "primary": "blue",
            "secondary": "cyan",
            "success": "green",
            "warning": "yellow",
            "danger": "red",
            "info": "blue",
            "muted": "dim",
            "emphasis": "bold black",
            "text": "black",
            "text_dim": "dim",
            "text_bright": "black",
        },
        "components": {
            "panel_border": "blue",
            "overlay_border": "cyan",
            "form_border": "green",
            "error_border": "red",
            "warning_border": "yellow",
            "task_pending": "yellow",
            "task_in_progress": "blue",
            "task_completed": "green",
            "task_failed": "red",
            "task_skipped": "dim",
            "priority_high": "red",
            "priority_medium": "yellow",
            "priority_low": "dim",
            "quick_win": "yellow",
            "port_open": "green",
            "port_filtered": "yellow",
            "port_closed": "dim",
            "finding_vulnerability": "red",
            "finding_directory": "blue",
            "finding_file": "cyan",
            "finding_credential": "yellow",
            "finding_user": "magenta",
            "finding_general": "black",
            "menu_number": "bold black",
            "hotkey": "blue",
            "command": "dim",
            "timestamp": "dim",
            "progress_bar": "blue",
            "status_active": "green",
            "status_inactive": "dim",
            "status_error": "red",

            # Notes formatting (for command descriptions, cheatsheets)
            "notes_step": "bold yellow",          # Step markers (Step 1:, (1), etc.)
            "notes_section": "bold black",        # Section headers (OSCP METHODOLOGY:, etc.)
            "notes_success": "green",             # Success indicators and expected outputs
            "notes_failure": "red",               # Failure messages and error indicators
            "notes_code": "dim",                  # Inline code/commands in notes
            "notes_warning": "yellow",            # WARNING:, CRITICAL:, PITFALL: markers
            "notes_tip": "blue",                  # TIP:, EXAM TIP: markers
        }
    },

    "nord": {
        "name": "Nord",
        "description": "Arctic-inspired blue color scheme",
        "colors": {
            "primary": "bright_cyan",
            "secondary": "bright_blue",
            "success": "green",
            "warning": "yellow",
            "danger": "red",
            "info": "bright_blue",
            "muted": "dim",
            "emphasis": "bold bright_white",
            "text": "white",
            "text_dim": "dim",
            "text_bright": "bright_white",
        },
        "components": {
            "panel_border": "bright_cyan",
            "overlay_border": "bright_blue",
            "form_border": "green",
            "error_border": "red",
            "warning_border": "yellow",
            "task_pending": "yellow",
            "task_in_progress": "bright_cyan",
            "task_completed": "green",
            "task_failed": "red",
            "task_skipped": "dim",
            "priority_high": "red",
            "priority_medium": "yellow",
            "priority_low": "dim",
            "quick_win": "yellow",
            "port_open": "green",
            "port_filtered": "yellow",
            "port_closed": "dim",
            "finding_vulnerability": "red",
            "finding_directory": "bright_cyan",
            "finding_file": "bright_blue",
            "finding_credential": "yellow",
            "finding_user": "magenta",
            "finding_general": "white",
            "menu_number": "bold bright_white",
            "hotkey": "bright_cyan",
            "command": "dim",
            "timestamp": "dim",
            "progress_bar": "bright_cyan",
            "status_active": "green",
            "status_inactive": "dim",
            "status_error": "red",

            # Notes formatting (for command descriptions, cheatsheets)
            "notes_step": "bold yellow",             # Step markers (Step 1:, (1), etc.)
            "notes_section": "bold bright_white",    # Section headers (OSCP METHODOLOGY:, etc.)
            "notes_success": "green",                # Success indicators and expected outputs
            "notes_failure": "red",                  # Failure messages and error indicators
            "notes_code": "dim",                     # Inline code/commands in notes
            "notes_warning": "yellow",               # WARNING:, CRITICAL:, PITFALL: markers
            "notes_tip": "bright_cyan",              # TIP:, EXAM TIP: markers
        }
    },

    "dracula": {
        "name": "Dracula",
        "description": "Dark theme with purple accents",
        "colors": {
            "primary": "magenta",
            "secondary": "bright_magenta",
            "success": "green",
            "warning": "yellow",
            "danger": "red",
            "info": "cyan",
            "muted": "dim",
            "emphasis": "bold bright_magenta",
            "text": "white",
            "text_dim": "dim",
            "text_bright": "bright_white",
        },
        "components": {
            "panel_border": "magenta",
            "overlay_border": "bright_magenta",
            "form_border": "green",
            "error_border": "red",
            "warning_border": "yellow",
            "task_pending": "yellow",
            "task_in_progress": "magenta",
            "task_completed": "green",
            "task_failed": "red",
            "task_skipped": "dim",
            "priority_high": "red",
            "priority_medium": "yellow",
            "priority_low": "dim",
            "quick_win": "yellow",
            "port_open": "green",
            "port_filtered": "yellow",
            "port_closed": "dim",
            "finding_vulnerability": "red",
            "finding_directory": "magenta",
            "finding_file": "bright_magenta",
            "finding_credential": "yellow",
            "finding_user": "cyan",
            "finding_general": "white",
            "menu_number": "bold bright_white",
            "hotkey": "magenta",
            "command": "dim",
            "timestamp": "dim",
            "progress_bar": "magenta",
            "status_active": "green",
            "status_inactive": "dim",
            "status_error": "red",

            # Notes formatting (for command descriptions, cheatsheets)
            "notes_step": "bold yellow",              # Step markers (Step 1:, (1), etc.)
            "notes_section": "bold bright_magenta",   # Section headers (OSCP METHODOLOGY:, etc.)
            "notes_success": "green",                 # Success indicators and expected outputs
            "notes_failure": "red",                   # Failure messages and error indicators
            "notes_code": "dim",                      # Inline code/commands in notes
            "notes_warning": "yellow",                # WARNING:, CRITICAL:, PITFALL: markers
            "notes_tip": "cyan",                      # TIP:, EXAM TIP: markers
        }
    },

    "mono": {
        "name": "Monochrome",
        "description": "No colors - exam-safe, screenreader-friendly",
        "colors": {
            "primary": "white",
            "secondary": "white",
            "success": "white",
            "warning": "white",
            "danger": "white",
            "info": "white",
            "muted": "dim",
            "emphasis": "bold white",
            "text": "white",
            "text_dim": "dim",
            "text_bright": "bold white",
        },
        "components": {
            "panel_border": "white",
            "overlay_border": "white",
            "form_border": "white",
            "error_border": "white",
            "warning_border": "white",
            "task_pending": "white",
            "task_in_progress": "bold white",
            "task_completed": "white",
            "task_failed": "white",
            "task_skipped": "dim",
            "priority_high": "bold white",
            "priority_medium": "white",
            "priority_low": "dim",
            "quick_win": "bold white",
            "port_open": "white",
            "port_filtered": "white",
            "port_closed": "dim",
            "finding_vulnerability": "white",
            "finding_directory": "white",
            "finding_file": "white",
            "finding_credential": "white",
            "finding_user": "white",
            "finding_general": "white",
            "menu_number": "bold white",
            "hotkey": "white",
            "command": "dim",
            "timestamp": "dim",
            "progress_bar": "white",
            "status_active": "white",
            "status_inactive": "dim",
            "status_error": "white",

            # Notes formatting (for command descriptions, cheatsheets)
            "notes_step": "bold white",       # Step markers (Step 1:, (1), etc.)
            "notes_section": "bold white",    # Section headers (OSCP METHODOLOGY:, etc.)
            "notes_success": "white",         # Success indicators and expected outputs
            "notes_failure": "white",         # Failure messages and error indicators
            "notes_code": "dim",              # Inline code/commands in notes
            "notes_warning": "white",         # WARNING:, CRITICAL:, PITFALL: markers
            "notes_tip": "white",             # TIP:, EXAM TIP: markers
        }
    }
}


def get_all_themes() -> Dict[str, Dict[str, Any]]:
    """Get all available themes (built-in + pywal)"""
    all_themes = dict(BUILT_IN_THEMES)  # Copy built-in themes
    all_themes.update(get_all_pywal_themes())  # Add pywal themes (if available)
    return all_themes


def get_theme_names():
    """Get list of available theme names (built-in + pywal)"""
    return list(get_all_themes().keys())


def get_theme(name: str) -> Dict[str, Any]:
    """
    Get theme configuration by name (searches built-in + pywal themes)

    Args:
        name: Theme name (e.g., 'oscp', 'dark', 'pw_gruvbox')

    Returns:
        Theme configuration dict

    Raises:
        KeyError: If theme name not found
    """
    all_themes = get_all_themes()

    if name not in all_themes:
        available = ', '.join(get_theme_names())
        pywal_status = " (including pywal themes)" if is_pywal_available() else ""
        raise KeyError(f"Theme '{name}' not found. Available themes{pywal_status}: {available}")

    return all_themes[name]


def list_themes() -> list:
    """
    Get list of all themes with metadata (built-in + pywal)

    Returns:
        List of dicts with keys: name, display_name, description
    """
    all_themes = get_all_themes()

    return [
        {
            "name": name,
            "display_name": theme["name"],
            "description": theme["description"]
        }
        for name, theme in all_themes.items()
    ]


__all__ = ['BUILT_IN_THEMES', 'get_theme', 'get_theme_names', 'get_all_themes', 'list_themes', 'is_pywal_available']
