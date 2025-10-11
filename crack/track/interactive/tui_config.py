"""
TUI Config Panel - First screen to confirm/edit configuration

Simple panel shown before main menu:
- Display current LHOST, LPORT, WORDLIST, etc.
- Allow editing each value
- Select UI theme
- Save to ~/.crack/config.json
- Continue to main menu

This is Phase 1: Prove the TUI foundation works with simple operations.
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional

from rich.panel import Panel
from rich.table import Table
from rich import box


class ConfigPanel:
    """Manage configuration panel display and editing"""

    CONFIG_PATH = Path.home() / ".crack" / "config.json"

    # Key variables to display and edit
    KEY_VARIABLES = [
        ('LHOST', 'Local IP for reverse shells'),
        ('LPORT', 'Local port for listeners'),
        ('WORDLIST', 'Default wordlist path'),
        ('INTERFACE', 'Network interface'),
        ('THEME', 'UI color theme'),
    ]

    @classmethod
    def load_config(cls) -> Dict[str, Any]:
        """Load config from JSON file"""
        if not cls.CONFIG_PATH.exists():
            return {}

        with open(cls.CONFIG_PATH, 'r') as f:
            return json.load(f)

    @classmethod
    def save_config(cls, config: Dict[str, Any]):
        """Save config to JSON file"""
        cls.CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(cls.CONFIG_PATH, 'w') as f:
            json.dump(config, f, indent=2)

    @classmethod
    def get_variable(cls, config: Dict[str, Any], var_name: str) -> str:
        """Get variable value from config"""
        # Special handling for THEME - load from theme config
        if var_name == 'THEME':
            return config.get('theme', {}).get('current', 'oscp')

        variables = config.get('variables', {})
        var_info = variables.get(var_name, {})
        return var_info.get('value', 'Not set')

    @classmethod
    def set_variable(cls, config: Dict[str, Any], var_name: str, value: str):
        """Set variable value in config"""
        # Special handling for THEME - save to theme config
        if var_name == 'THEME':
            if 'theme' not in config:
                config['theme'] = {}
            config['theme']['current'] = value
            return

        if 'variables' not in config:
            config['variables'] = {}

        if var_name not in config['variables']:
            config['variables'][var_name] = {}

        config['variables'][var_name]['value'] = value
        config['variables'][var_name]['source'] = 'manual'

        from datetime import datetime
        config['variables'][var_name]['updated'] = datetime.now().isoformat()

    @classmethod
    def render_panel(cls, config: Dict[str, Any], target: Optional[str] = None, theme=None) -> Panel:
        """
        Render configuration panel

        Args:
            config: Config dictionary
            target: Optional target IP (shown but not editable)
            theme: Optional ThemeManager instance

        Returns:
            Rich Panel
        """
        # Theme fallback
        if theme is None:
            from .themes import ThemeManager
            theme = ThemeManager()

        from .themes.helpers import format_menu_number

        # Build table
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Variable", style=f"bold {theme.get_color('primary')}", width=12)
        table.add_column("Value", style=theme.get_color('text'))

        # Add key variables
        for var_name, description in cls.KEY_VARIABLES:
            value = cls.get_variable(config, var_name)
            # Truncate long values
            if len(value) > 40:
                value = value[:37] + "..."
            table.add_row(f"{var_name}:", value)

        # Add target (read-only, shown for info)
        if target:
            table.add_row("TARGET:", target)

        # Add blank line
        table.add_row("", "")

        # Add menu options
        table.add_row(format_menu_number(theme, 1), "Edit LHOST")
        table.add_row(format_menu_number(theme, 2), "Edit LPORT")
        table.add_row(format_menu_number(theme, 3), "Edit WORDLIST")
        table.add_row(format_menu_number(theme, 4), "Edit INTERFACE")
        table.add_row(format_menu_number(theme, 5), "Select Theme")
        table.add_row("", "")
        table.add_row(f"[{theme.get_color('success')}]{format_menu_number(theme, 6)}[/]",
                      theme.success("Continue to Main Menu"))

        return Panel(
            table,
            title=f"[bold {theme.get_color('primary')}] Configuration Setup [/]",
            subtitle=theme.muted("Confirm settings before starting enumeration"),
            border_style=theme.panel_border(),
            box=box.DOUBLE
        )

    @classmethod
    def get_menu_choices(cls) -> list:
        """Get menu choices for input parsing"""
        return [
            {'id': 'edit-lhost', 'label': 'Edit LHOST', 'var': 'LHOST'},
            {'id': 'edit-lport', 'label': 'Edit LPORT', 'var': 'LPORT'},
            {'id': 'edit-wordlist', 'label': 'Edit WORDLIST', 'var': 'WORDLIST'},
            {'id': 'edit-interface', 'label': 'Edit INTERFACE', 'var': 'INTERFACE'},
            {'id': 'select-theme', 'label': 'Select Theme', 'var': 'THEME'},
            {'id': 'continue', 'label': 'Continue to Main Menu', 'var': None},
        ]

    @classmethod
    def render_theme_selection(cls, current_theme: str, theme=None) -> Panel:
        """
        Render theme selection panel with preview

        Args:
            current_theme: Current theme name
            theme: Optional ThemeManager instance

        Returns:
            Rich Panel
        """
        # Theme fallback
        if theme is None:
            from .themes import ThemeManager
            theme = ThemeManager()

        from .themes import list_themes

        # Build table
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Number", style=f"bold {theme.get_color('primary')}", width=4)
        table.add_column("Theme", style=theme.get_color('text'), width=15)
        table.add_column("Description", style=theme.get_color('muted'))

        # Add theme options
        available_themes = list_themes()
        for idx, theme_info in enumerate(available_themes, 1):
            theme_name = theme_info['name']
            display_name = theme_info['display_name']
            description = theme_info['description']

            # Mark current theme
            marker = theme.success("✓ ") if theme_name == current_theme else "  "
            table.add_row(f"{idx}.", f"{marker}{display_name}", description)

        # Add blank line
        table.add_row("", "", "")

        # Add preview section
        table.add_row("", theme.emphasis("Preview:"), "")
        table.add_row("", theme.primary("Primary"), theme.muted("Panel borders, hotkeys"))
        table.add_row("", theme.success("Success"), theme.muted("Completed tasks"))
        table.add_row("", theme.warning("Warning"), theme.muted("Pending tasks"))
        table.add_row("", theme.danger("Danger"), theme.muted("Failed tasks, errors"))

        return Panel(
            table,
            title=f"[bold {theme.get_color('primary')}] Theme Selection [/]",
            subtitle=theme.muted("Choose a color scheme (changes take effect immediately)"),
            border_style=theme.panel_border(),
            box=box.ROUNDED
        )
