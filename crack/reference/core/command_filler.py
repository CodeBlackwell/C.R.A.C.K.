"""
Command Filler - Centralized interactive command filling logic

This module provides a single source of truth for interactive command placeholder filling,
eliminating 270+ lines of duplicated code across neo4j_adapter, sql_adapter, and registry.
"""

from typing import Dict, Optional
from .registry import Command


class CommandFiller:
    """
    Centralized interactive command filling logic

    Handles user prompts for command placeholders with:
    - Config value pre-loading
    - Variable descriptions and examples
    - Optional vs required fields
    - Keyboard interrupt handling
    - Colorized output via theme
    """

    def __init__(self, config_manager=None, theme=None):
        """
        Initialize CommandFiller

        Args:
            config_manager: ConfigManager instance for auto-fill values
            theme: ReferenceTheme instance for colorized output
        """
        self.config_manager = config_manager
        self.theme = theme

    def fill_command(self, command: Command) -> str:
        """
        Interactively fill command placeholders

        Single source of truth for placeholder filling across all adapters.
        Prompts user for each placeholder with context from variable definitions.

        Args:
            command: Command dataclass to fill

        Returns:
            Filled command string with all placeholders replaced

        Example:
            >>> filler = CommandFiller(config, theme)
            >>> cmd = registry.get_command('nmap-ping-sweep')
            >>> filled = filler.fill_command(cmd)
            # Prompts user for <TARGET>, <SUBNET>, etc.
            # Returns: "nmap -sn -PE 192.168.1.0/24"
        """
        values = {}
        placeholders = command.extract_placeholders()

        t = self.theme

        # Header
        print(f"\n{t.primary('[*] Filling command:')} {t.command_name(command.name)}")
        print(f"{t.primary('[*] Command:')} {t.hint(command.command)}\n")

        # Pre-load config values if available
        config_values = {}
        if self.config_manager:
            config_values = self.config_manager.get_placeholder_values()

        try:
            for placeholder in placeholders:
                # Check if we have a config value for this placeholder
                config_value = config_values.get(placeholder, '')

                # Find variable definition
                var = next((v for v in command.variables if v.name == placeholder), None)

                if var:
                    # Build colorized prompt with variable metadata
                    prompt_parts = [
                        t.prompt("Enter value for"),
                        t.placeholder(placeholder)
                    ]
                    if var.description:
                        prompt_parts.append(t.hint(f"({var.description})"))
                    if var.example:
                        prompt_parts.append(t.hint(f"[e.g., {var.example}]"))
                    if config_value:
                        prompt_parts.append(t.hint(f"[config: {t.value(config_value)}]"))
                    if not var.required:
                        prompt_parts.append(t.hint("(optional)"))

                    prompt = " ".join(prompt_parts) + t.prompt(": ")
                    value = input(prompt).strip()

                    # Use config value if user just pressed enter and we have one
                    if not value and config_value:
                        value = config_value
                        print(f"  {t.success('✓')} Using configured value: {t.value(config_value)}")

                    if value or var.required:
                        values[placeholder] = value
                else:
                    # Placeholder not defined in variables (fallback)
                    prompt_parts = [
                        t.prompt("Enter value for"),
                        t.placeholder(placeholder)
                    ]
                    if config_value:
                        prompt_parts.append(t.hint(f"[config: {t.value(config_value)}]"))

                    prompt = " ".join(prompt_parts) + t.prompt(": ")
                    value = input(prompt).strip()

                    # Use config value if user just pressed enter
                    if not value and config_value:
                        value = config_value
                        print(f"  {t.success('✓')} Using configured value: {t.value(config_value)}")

                    if value:
                        values[placeholder] = value

        except KeyboardInterrupt:
            print(f"\n{t.warning('[Cancelled by user]')}")
            return ""

        filled_command = command.fill_placeholders(values)
        print(f"\n{t.success('[+] Final command:')} {t.command_name(filled_command)}")
        return filled_command
