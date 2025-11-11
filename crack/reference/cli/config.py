"""
CLI config handler for configuration management
"""

from crack.reference.cli.base import BaseCLIHandler


class ConfigCLI(BaseCLIHandler):
    """Handler for configuration management"""

    def __init__(self, config_manager=None, theme=None):
        """Initialize config handler

        Args:
            config_manager: ConfigManager instance
            theme: ReferenceTheme instance
        """
        super().__init__(theme)
        self.config = config_manager

    def handle_config(self, action: str) -> int:
        """Handle config actions

        Args:
            action: Config action (list, edit, auto)

        Returns:
            Exit code (0 for success)
        """
        if action == 'list':
            return self.list_config()
        elif action == 'edit':
            return self.edit_config()
        elif action == 'auto':
            return self.auto_config()
        return 0

    def list_config(self) -> int:
        """List all config variables

        Returns:
            Exit code (0 for success)
        """
        variables = self.config.list_variables()

        print("\n=== CRACK Reference Configuration ===")
        print(f"Config file: {self.config.config_path}\n")

        if not variables:
            print("No variables configured")
            return 0

        print("Current Variables:")
        for name, var_data in variables.items():
            if isinstance(var_data, dict):
                value = var_data.get('value', '')
                source = var_data.get('source', 'manual')
                description = var_data.get('description', '')

                # Format output
                if value:
                    print(f"  {name:15} = {value:20} [{source}]")
                    if description:
                        print(f"  {'':15}   {description}")
                else:
                    print(f"  {name:15} = {'(not set)':20} [{source}]")
                    if description:
                        print(f"  {'':15}   {description}")
            else:
                print(f"  {name:15} = {var_data}")

        print("\nUse --set VAR VALUE to set a variable")
        print("Use --config edit to open in editor")
        return 0

    def set_config_var(self, var_name: str, value: str) -> int:
        """Set a config variable

        Args:
            var_name: Variable name to set
            value: Value to set (or 'auto' for auto-detection)

        Returns:
            Exit code (0 for success, 1 for error)
        """
        # Auto-detect special values
        if value.lower() == 'auto':
            if var_name.upper() == 'LHOST':
                detected = self.config.auto_detect_ip()
                if detected:
                    value = detected
                    print(f"Auto-detected LHOST: {value}")
                else:
                    print("Could not auto-detect IP address")
                    return 1
            elif var_name.upper() == 'INTERFACE':
                detected = self.config.auto_detect_interface()
                if detected:
                    value = detected
                    print(f"Auto-detected interface: {value}")
                else:
                    print("Could not auto-detect interface")
                    return 1

        if self.config.set_variable(var_name.upper(), value):
            print(f"✅ Set {var_name.upper()} = {value}")
            print(f"Config saved to: {self.config.config_path}")
            return 0
        else:
            print(f"❌ Failed to set {var_name}")
            return 1

    def get_config_var(self, var_name: str) -> int:
        """Get a config variable value

        Args:
            var_name: Variable name to retrieve

        Returns:
            Exit code (0 for success, 1 for not found)
        """
        value = self.config.get_variable(var_name.upper())
        if value:
            print(f"{var_name.upper()} = {value}")
            return 0
        else:
            print(f"{var_name.upper()} is not set")
            return 1

    def clear_config(self) -> int:
        """Clear all config variables

        Returns:
            Exit code (0 for success, 1 for cancelled/error)
        """
        confirm = input("Clear all config variables? (y/N): ").strip().lower()
        if confirm == 'y':
            if self.config.clear_variables():
                print("✅ All variables cleared")
                return 0
            else:
                print("❌ Failed to clear variables")
                return 1
        return 1

    def edit_config(self) -> int:
        """Open config file in editor

        Returns:
            Exit code (0 for success, 1 for error)
        """
        print(f"Opening config file: {self.config.config_path}")
        if self.config.open_editor():
            print("Config reloaded")
            return 0
        else:
            print("Failed to open editor")
            return 1

    def auto_config(self) -> int:
        """Auto-detect and configure variables

        Returns:
            Exit code (0 for success, 1 for no values detected)
        """
        print("Auto-detecting configuration...")
        updates = self.config.auto_configure()

        if updates:
            print("\n✅ Auto-configured:")
            for var, value in updates.items():
                print(f"  {var} = {value}")
            print(f"\nConfig saved to: {self.config.config_path}")
            return 0
        else:
            print("No values auto-detected")
            return 1
