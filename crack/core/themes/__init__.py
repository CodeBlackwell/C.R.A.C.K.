"""
CRACK Core Theme System

Unified theming for all modules (CLI, reference, track, future modules)

Provides:
- ThemeManager: Central theme loading and switching
- Colors: ANSI escape codes for terminal output
- ReferenceTheme: Semantic theme-aware coloring (Rich → ANSI)
- ThemeSelector: Interactive theme selection with live preview
- helpers: Utility functions for theme operations

Example Usage:
    # Use theme manager
    from themes import ThemeManager
    theme_mgr = ThemeManager()
    color = theme_mgr.get_color('primary')  # 'cyan' for OSCP theme

    # Use semantic colors (ANSI output)
    from themes import ReferenceTheme
    theme = ReferenceTheme()
    print(theme.primary("Important text"))
    print(theme.banner_title("CRACK"))

    # Use direct ANSI codes
    from themes import Colors
    print(f"{Colors.BOLD}{Colors.RED}Error{Colors.END}")

    # Interactive theme selection
    from themes import interactive_theme_selector
    interactive_theme_selector()  # Arrow keys + live preview
"""

from .manager import ThemeManager
from .colors import Colors, ReferenceTheme, get_theme as get_reference_theme, disable_colors
from .selector import ThemeSelector, interactive_theme_selector
from .presets import get_theme, get_theme_names, get_all_themes, list_themes, is_pywal_available
from . import helpers

__all__ = [
    'ThemeManager',
    'Colors',
    'ReferenceTheme',
    'ThemeSelector',
    'interactive_theme_selector',
    'get_theme',
    'get_theme_names',
    'get_all_themes',
    'list_themes',
    'is_pywal_available',
    'disable_colors',
    'helpers',
]

__version__ = '2.0.0'
