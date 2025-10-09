"""
TUI Config Panel - First screen to confirm/edit configuration

Simple panel shown before main menu:
- Display current LHOST, LPORT, WORDLIST, etc.
- Allow editing each value
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
        variables = config.get('variables', {})
        var_info = variables.get(var_name, {})
        return var_info.get('value', 'Not set')

    @classmethod
    def set_variable(cls, config: Dict[str, Any], var_name: str, value: str):
        """Set variable value in config"""
        if 'variables' not in config:
            config['variables'] = {}

        if var_name not in config['variables']:
            config['variables'][var_name] = {}

        config['variables'][var_name]['value'] = value
        config['variables'][var_name]['source'] = 'manual'

        from datetime import datetime
        config['variables'][var_name]['updated'] = datetime.now().isoformat()

    @classmethod
    def render_panel(cls, config: Dict[str, Any], target: Optional[str] = None) -> Panel:
        """
        Render configuration panel

        Args:
            config: Config dictionary
            target: Optional target IP (shown but not editable)

        Returns:
            Rich Panel
        """
        # Build table
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Variable", style="bold cyan", width=12)
        table.add_column("Value", style="white")

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
        table.add_row("[bold]1.[/]", "Edit LHOST")
        table.add_row("[bold]2.[/]", "Edit LPORT")
        table.add_row("[bold]3.[/]", "Edit WORDLIST")
        table.add_row("[bold]4.[/]", "Edit INTERFACE")
        table.add_row("", "")
        table.add_row("[bold bright_green]5.[/]", "[bright_green]Continue to Main Menu[/]")

        return Panel(
            table,
            title="[bold white on blue] Configuration Setup [/]",
            subtitle="[dim]Confirm settings before starting enumeration[/]",
            border_style="blue",
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
            {'id': 'continue', 'label': 'Continue to Main Menu', 'var': None},
        ]
