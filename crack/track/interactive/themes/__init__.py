"""
Theme System for CRACK Track TUI

Provides centralized theme management with semantic color roles.

Usage:
    from track.interactive.themes import ThemeManager

    # Initialize theme manager (loads from config)
    theme = ThemeManager()

    # Access semantic colors
    primary_color = theme.get_color('primary')  # Returns 'cyan' for oscp theme
    success_color = theme.get_color('success')  # Returns 'green'

    # Access component-specific colors
    border_color = theme.panel_border()  # Returns 'cyan' for oscp theme
    task_color = theme.task_state_color('pending')  # Returns 'yellow'

    # Convenience methods for text formatting
    text = theme.primary("Important text")  # Returns "[cyan]Important text[/cyan]"
    text = theme.success("✓ Done")  # Returns "[green]✓ Done[/green]"

    # Switch themes dynamically
    theme.set_theme('dark')  # Switches to dark mode

    # List available themes
    themes = theme.list_themes()  # Returns list of theme metadata

Example integration in panel:
    from track.interactive.themes import ThemeManager
    from track.interactive.themes.helpers import format_panel_title, format_menu_number

    def render_panel(profile, theme: ThemeManager):
        # Use theme for panel border
        panel = Panel(
            content,
            title=format_panel_title(theme, "Dashboard", "Main Hub"),
            border_style=theme.panel_border(),
            box=box.ROUNDED
        )

        # Use theme for menu items
        menu_text = f"{format_menu_number(theme, 1)} Execute task"

        return panel
"""

from .manager import ThemeManager
from .presets import get_theme, get_theme_names, list_themes, BUILT_IN_THEMES
from . import helpers

__all__ = [
    'ThemeManager',
    'get_theme',
    'get_theme_names',
    'list_themes',
    'BUILT_IN_THEMES',
    'helpers',
]

__version__ = '1.0.0'
