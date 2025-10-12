"""
Unified configuration manager for CRACK toolkit

Provides centralized variable storage, validation, and auto-detection
for all CRACK modules (reference, track, etc.)
"""

import json
import os
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime

from .variables import (
    Variable,
    VARIABLE_REGISTRY,
    get_by_category,
    get_all_categories,
    resolve_alias,
    get_variable_info
)
from .validators import Validators


class ConfigManager:
    """Shared configuration manager for all crack modules"""

    def __init__(self, config_path: str = None):
        """
        Initialize configuration manager

        Args:
            config_path: Path to config file (defaults to ~/.crack/config.json)
        """
        if config_path:
            self.config_path = Path(config_path)
        else:
            self.config_path = Path.home() / '.crack' / 'config.json'

        self.variables = VARIABLE_REGISTRY  # Single source of truth
        self.config = {}
        self.load()

    def load(self) -> Dict[str, Any]:
        """Load configuration from file"""
        if self.config_path.exists():
            try:
                with open(self.config_path, 'r') as f:
                    self.config = json.load(f)
            except Exception as e:
                print(f"Warning: Could not load config: {e}")
                self.config = self._get_default_config()
        else:
            # Create default config
            self.config = self._get_default_config()
            self.save()

        return self.config

    def save(self) -> bool:
        """Save configuration to file"""
        try:
            # Create directory if it doesn't exist
            self.config_path.parent.mkdir(parents=True, exist_ok=True)

            # Save with pretty formatting
            with open(self.config_path, 'w') as f:
                json.dump(self.config, f, indent=2, sort_keys=True)
            return True
        except Exception as e:
            print(f"Error saving config: {e}")
            return False

    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration structure"""
        return {
            "variables": {},
            "sessions": {},
            "settings": {
                "auto_detect_interface": True,
                "auto_detect_ip": True,
                "confirm_before_fill": False,
                "show_source": True
            },
            "theme": {
                "current": "oscp",
                "description": "TUI color theme (oscp, dark, light, nord, dracula, mono)"
            }
        }

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value

        Args:
            key: Config key (supports dot notation: 'settings.auto_detect_ip')
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        keys = key.split('.')
        value = self.config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def set(self, key: str, value: Any, source: str = "manual") -> bool:
        """
        Set a configuration value

        Args:
            key: Config key (supports dot notation)
            value: Value to set
            source: Source of value (manual, auto-detected, default)

        Returns:
            True if successful
        """
        keys = key.split('.')

        # Navigate to the parent of the target key
        current = self.config
        for k in keys[:-1]:
            if k not in current:
                current[k] = {}
            current = current[k]

        # Set the value
        if keys[-1] in current and isinstance(current[keys[-1]], dict):
            # If it's a variable with metadata, update it
            current[keys[-1]]['value'] = value
            current[keys[-1]]['source'] = source
            current[keys[-1]]['updated'] = datetime.now().isoformat()
        else:
            # Simple value set
            current[keys[-1]] = value

        return self.save()

    def get_variable(self, name: str, resolve_aliases: bool = True) -> Optional[str]:
        """
        Get a variable value

        Args:
            name: Variable name (with or without angle brackets)
            resolve_aliases: If True, resolve aliases to canonical names

        Returns:
            Variable value or None
        """
        # Remove angle brackets if present
        name = name.strip('<>').upper()

        # Resolve alias if enabled
        if resolve_aliases:
            name = resolve_alias(name)

        var_data = self.config.get('variables', {}).get(name)

        if isinstance(var_data, dict):
            return var_data.get('value', '')
        elif var_data:
            return var_data

        return None

    def set_variable(
        self,
        name: str,
        value: str,
        source: str = "manual",
        validate: bool = True
    ) -> Tuple[bool, Optional[str]]:
        """
        Set a variable value with optional validation

        Args:
            name: Variable name (with or without angle brackets)
            value: Value to set
            source: Source of value (manual, auto-detected, default)
            validate: If True, validate value before setting

        Returns:
            (success, error_message)
        """
        # Remove angle brackets and convert to uppercase
        name = name.strip('<>').upper()

        # Resolve alias to canonical name
        name = resolve_alias(name)

        # Get variable definition
        var_def = self.variables.get(name)

        # Validate if requested
        if validate and var_def:
            is_valid, error = Validators.validate_variable(name, value)
            if not is_valid:
                return False, error

        # Create or update variable entry
        self.config.setdefault('variables', {})[name] = {
            'value': value,
            'description': var_def.description if var_def else f'User-defined variable: {name}',
            'source': source,
            'updated': datetime.now().isoformat()
        }

        success = self.save()
        return (success, None) if success else (False, "Failed to save config")

    def list_variables(self, category: str = None) -> Dict[str, Any]:
        """
        List all variables with their values and metadata

        Args:
            category: If specified, filter by category

        Returns:
            Dict of variables with metadata
        """
        if category:
            # Filter by category from registry
            category_vars = get_by_category(category)
            result = {}
            for var_name in category_vars.keys():
                var_data = self.config.get('variables', {}).get(var_name)
                if var_data:
                    result[var_name] = var_data
            return result
        else:
            return self.config.get('variables', {})

    def delete_variable(self, name: str) -> bool:
        """Delete a variable"""
        name = name.strip('<>').upper()
        name = resolve_alias(name)

        if name in self.config.get('variables', {}):
            del self.config['variables'][name]
            return self.save()
        return False

    def clear_variables(self, keep_defaults: bool = False) -> bool:
        """
        Clear all variables

        Args:
            keep_defaults: If True, keep variables with source='default'

        Returns:
            True if successful
        """
        if keep_defaults:
            # Keep only default variables
            self.config['variables'] = {
                name: var for name, var in self.config.get('variables', {}).items()
                if isinstance(var, dict) and var.get('source') == 'default'
            }
        else:
            self.config['variables'] = {}

        return self.save()

    def get_unconfigured(self, required_only: bool = True) -> List[Variable]:
        """
        Get variables that are not configured

        Args:
            required_only: If True, only return required variables

        Returns:
            List of Variable definitions
        """
        configured = set(self.config.get('variables', {}).keys())
        unconfigured = []

        for name, var in self.variables.items():
            if name not in configured:
                if not required_only or var.required:
                    unconfigured.append(var)

        return unconfigured

    def get_placeholder_values(self) -> Dict[str, str]:
        """
        Get all variables formatted for placeholder substitution

        Returns:
            Dict with <VAR_NAME> keys and string values
        """
        values = {}

        for name, var_data in self.config.get('variables', {}).items():
            if isinstance(var_data, dict):
                value = var_data.get('value', '')
            else:
                value = var_data

            # Add with angle brackets for placeholder matching
            if value:
                values[f'<{name}>'] = value

        return values

    def auto_detect_interface(self) -> Optional[str]:
        """
        Auto-detect the active network interface

        Returns:
            Interface name or None
        """
        try:
            # Check for VPN interface first (tun0, tun1, etc.)
            result = subprocess.run(
                ['ip', 'link', 'show'],
                capture_output=True,
                text=True,
                timeout=2
            )

            for line in result.stdout.split('\n'):
                if 'tun' in line and 'state UP' in line:
                    # Extract interface name
                    interface = line.split(':')[1].strip()
                    return interface

            # Fallback to default active interface
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True,
                text=True,
                timeout=2
            )

            if result.stdout:
                # Extract interface from default route
                parts = result.stdout.split()
                if 'dev' in parts:
                    idx = parts.index('dev')
                    if idx + 1 < len(parts):
                        return parts[idx + 1]
        except:
            pass

        return None

    def auto_detect_ip(self, interface: str = None) -> Optional[str]:
        """
        Auto-detect IP address for given interface

        Args:
            interface: Interface name (auto-detect if None)

        Returns:
            IP address or None
        """
        try:
            if not interface:
                interface = self.auto_detect_interface()

            if interface:
                result = subprocess.run(
                    ['ip', 'addr', 'show', interface],
                    capture_output=True,
                    text=True,
                    timeout=2
                )

                for line in result.stdout.split('\n'):
                    if 'inet ' in line:
                        # Extract IP address
                        ip = line.strip().split()[1].split('/')[0]
                        return ip
        except:
            pass

        return None

    def auto_configure(self) -> Dict[str, str]:
        """
        Auto-configure common variables

        Returns:
            Dict of auto-configured variables
        """
        updates = {}

        # Auto-detect interface
        if self.get('settings.auto_detect_interface'):
            interface = self.auto_detect_interface()
            if interface:
                success, _ = self.set_variable('INTERFACE', interface, source='auto-detected')
                if success:
                    updates['INTERFACE'] = interface

        # Auto-detect IP
        if self.get('settings.auto_detect_ip'):
            ip = self.auto_detect_ip()
            if ip:
                success, _ = self.set_variable('LHOST', ip, source='auto-detected')
                if success:
                    updates['LHOST'] = ip

        return updates

    def get_all_categories(self) -> List[str]:
        """Get list of all variable categories"""
        return get_all_categories()

    def get_variables_by_category(self, category: str) -> Dict[str, Variable]:
        """Get all variable definitions in a category"""
        return get_by_category(category)

    def validate_all(self) -> Dict[str, List[str]]:
        """
        Validate all configured variables

        Returns:
            Dict of variable names to list of error messages
        """
        errors = {}

        for name, var_data in self.config.get('variables', {}).items():
            if isinstance(var_data, dict):
                value = var_data.get('value', '')
            else:
                value = var_data

            if value:
                is_valid, error = Validators.validate_variable(name, value)
                if not is_valid:
                    errors[name] = [error]

        return errors

    # Session management methods
    def create_session(self, name: str, variables: Dict[str, str] = None) -> bool:
        """Create a named session with specific variables"""
        self.config.setdefault('sessions', {})[name] = {
            'variables': variables or self.config.get('variables', {}).copy(),
            'created': datetime.now().isoformat(),
            'last_used': None
        }
        return self.save()

    def load_session(self, name: str) -> bool:
        """Load a named session"""
        session = self.config.get('sessions', {}).get(name)
        if session:
            self.config['variables'] = session['variables'].copy()
            session['last_used'] = datetime.now().isoformat()
            return self.save()
        return False

    def list_sessions(self) -> Dict[str, Any]:
        """List all saved sessions"""
        return self.config.get('sessions', {})

    def delete_session(self, name: str) -> bool:
        """Delete a named session"""
        if name in self.config.get('sessions', {}):
            del self.config['sessions'][name]
            return self.save()
        return False

    # Import/Export methods
    def export_config(self, filepath: str) -> bool:
        """Export configuration to file"""
        try:
            with open(filepath, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            print(f"Error exporting config: {e}")
            return False

    def import_config(self, filepath: str, merge: bool = False) -> bool:
        """Import configuration from file"""
        try:
            with open(filepath, 'r') as f:
                imported = json.load(f)

            if merge:
                # Merge with existing config
                self.config.update(imported)
            else:
                # Replace config
                self.config = imported

            return self.save()
        except Exception as e:
            print(f"Error importing config: {e}")
            return False

    def open_editor(self) -> bool:
        """Open config file in default editor"""
        editor = os.environ.get('EDITOR', 'nano')

        try:
            subprocess.run([editor, str(self.config_path)])
            # Reload config after editing
            self.load()
            return True
        except Exception as e:
            print(f"Error opening editor: {e}")
            return False
