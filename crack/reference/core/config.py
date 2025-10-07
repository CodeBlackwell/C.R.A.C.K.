"""
Configuration management for CRACK Reference System
Stores and manages user variables for auto-filling placeholders
"""

import json
import os
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime


class ConfigManager:
    """Manage user configuration and variables"""

    def __init__(self, config_path: str = None):
        """Initialize configuration manager"""
        if config_path:
            self.config_path = Path(config_path)
        else:
            # Default to ~/.crack/config.json
            self.config_path = Path.home() / '.crack' / 'config.json'

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
                self.config = {}
        else:
            # Create default config
            self.config = self.get_default_config()
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

    def get_default_config(self) -> Dict[str, Any]:
        """Get default configuration structure"""
        return {
            "variables": {
                "LHOST": {
                    "value": "",
                    "description": "Local/attacker IP address",
                    "source": "manual",
                    "updated": None
                },
                "LPORT": {
                    "value": "4444",
                    "description": "Local port for listener",
                    "source": "default",
                    "updated": None
                },
                "TARGET": {
                    "value": "",
                    "description": "Target IP address",
                    "source": "manual",
                    "updated": None
                },
                "TARGET_SUBNET": {
                    "value": "",
                    "description": "Target subnet in CIDR notation",
                    "source": "manual",
                    "updated": None
                },
                "WORDLIST": {
                    "value": "/usr/share/wordlists/rockyou.txt",
                    "description": "Default wordlist path",
                    "source": "default",
                    "updated": None
                },
                "THREADS": {
                    "value": "10",
                    "description": "Default thread count",
                    "source": "default",
                    "updated": None
                },
                "INTERFACE": {
                    "value": "tun0",
                    "description": "Network interface",
                    "source": "default",
                    "updated": None
                },
                "OUTPUT_DIR": {
                    "value": "./scans",
                    "description": "Default output directory",
                    "source": "default",
                    "updated": None
                }
            },
            "sessions": {},
            "settings": {
                "auto_detect_interface": True,
                "auto_detect_ip": True,
                "confirm_before_fill": False,
                "show_source": True
            }
        }

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value"""
        # Handle nested keys with dot notation
        keys = key.split('.')
        value = self.config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def set(self, key: str, value: Any, source: str = "manual") -> bool:
        """Set a configuration value"""
        # Handle nested keys with dot notation
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

    def get_variable(self, name: str) -> Optional[str]:
        """Get a variable value (without angle brackets)"""
        # Remove angle brackets if present
        name = name.strip('<>')

        var = self.get(f'variables.{name}')
        if isinstance(var, dict):
            return var.get('value', '')
        return var

    def set_variable(self, name: str, value: str, source: str = "manual") -> bool:
        """Set a variable value"""
        # Remove angle brackets if present
        name = name.strip('<>')

        if f'variables.{name}' not in self.config.get('variables', {}):
            # Create new variable entry
            self.config.setdefault('variables', {})[name] = {
                'value': value,
                'description': f'User-defined variable: {name}',
                'source': source,
                'updated': datetime.now().isoformat()
            }
        else:
            # Update existing variable
            self.config['variables'][name]['value'] = value
            self.config['variables'][name]['source'] = source
            self.config['variables'][name]['updated'] = datetime.now().isoformat()

        return self.save()

    def list_variables(self) -> Dict[str, Any]:
        """List all variables with their values and metadata"""
        return self.config.get('variables', {})

    def delete_variable(self, name: str) -> bool:
        """Delete a variable"""
        name = name.strip('<>')

        if name in self.config.get('variables', {}):
            del self.config['variables'][name]
            return self.save()
        return False

    def clear_variables(self, keep_defaults: bool = True) -> bool:
        """Clear all variables, optionally keeping defaults"""
        if keep_defaults:
            # Reset to default config
            default_vars = self.get_default_config()['variables']
            self.config['variables'] = default_vars
        else:
            self.config['variables'] = {}

        return self.save()

    def auto_detect_interface(self) -> Optional[str]:
        """Auto-detect the active network interface"""
        try:
            # Check for VPN interface first (tun0, tun1, etc.)
            result = subprocess.run(['ip', 'link', 'show'],
                                  capture_output=True, text=True, timeout=2)

            for line in result.stdout.split('\n'):
                if 'tun' in line and 'state UP' in line:
                    # Extract interface name
                    interface = line.split(':')[1].strip()
                    return interface

            # Fallback to default active interface
            result = subprocess.run(['ip', 'route', 'show', 'default'],
                                  capture_output=True, text=True, timeout=2)

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
        """Auto-detect IP address for given interface"""
        try:
            if not interface:
                interface = self.auto_detect_interface()

            if interface:
                result = subprocess.run(['ip', 'addr', 'show', interface],
                                      capture_output=True, text=True, timeout=2)

                for line in result.stdout.split('\n'):
                    if 'inet ' in line:
                        # Extract IP address
                        ip = line.strip().split()[1].split('/')[0]
                        return ip
        except:
            pass

        return None

    def auto_configure(self) -> Dict[str, str]:
        """Auto-configure common variables"""
        updates = {}

        # Auto-detect interface
        if self.get('settings.auto_detect_interface'):
            interface = self.auto_detect_interface()
            if interface:
                self.set_variable('INTERFACE', interface, source='auto-detected')
                updates['INTERFACE'] = interface

        # Auto-detect IP
        if self.get('settings.auto_detect_ip'):
            ip = self.auto_detect_ip()
            if ip:
                self.set_variable('LHOST', ip, source='auto-detected')
                updates['LHOST'] = ip

        return updates

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

    def get_placeholder_values(self) -> Dict[str, str]:
        """Get all variables formatted for placeholder substitution"""
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