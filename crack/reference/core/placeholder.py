"""
Placeholder engine for variable substitution and management
"""

import re
import os
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class PlaceholderDefinition:
    """Definition of a placeholder with metadata"""
    name: str
    description: str
    example: str
    validation_regex: Optional[str] = None
    default_value: Optional[str] = None
    source: Optional[str] = None  # Environment variable or config key


class PlaceholderEngine:
    """Engine for managing and substituting placeholders"""

    def __init__(self, config_manager=None):
        self.definitions = self._load_standard_placeholders()
        self.user_values = {}
        self.config_manager = config_manager
        self._load_environment_values()
        self._load_config_values()

    def _load_standard_placeholders(self) -> Dict[str, PlaceholderDefinition]:
        """Load standard placeholder definitions"""
        return {
            '<TARGET>': PlaceholderDefinition(
                name='<TARGET>',
                description='Target IP address or hostname',
                example='192.168.1.100',
                validation_regex=r'^[\w\.\-]+$'
            ),
            '<TARGET_IP>': PlaceholderDefinition(
                name='<TARGET_IP>',
                description='Target IP address',
                example='192.168.45.100',
                validation_regex=r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
            ),
            '<TARGET_SUBNET>': PlaceholderDefinition(
                name='<TARGET_SUBNET>',
                description='Target network in CIDR notation',
                example='192.168.1.0/24',
                validation_regex=r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$'
            ),
            '<LHOST>': PlaceholderDefinition(
                name='<LHOST>',
                description='Local/attacker IP address',
                example='10.10.14.5',
                validation_regex=r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',
                source='LHOST'
            ),
            '<LPORT>': PlaceholderDefinition(
                name='<LPORT>',
                description='Local port for listener',
                example='4444',
                validation_regex=r'^\d{1,5}$',
                default_value='4444'
            ),
            '<PORT>': PlaceholderDefinition(
                name='<PORT>',
                description='Target port number',
                example='80',
                validation_regex=r'^\d{1,5}$'
            ),
            '<PORTS>': PlaceholderDefinition(
                name='<PORTS>',
                description='Port range or comma-separated list',
                example='80,443,8080',
                validation_regex=r'^[\d,\-]+$'
            ),
            '<URL>': PlaceholderDefinition(
                name='<URL>',
                description='Full URL to target',
                example='http://192.168.1.100/login.php',
                validation_regex=r'^https?://.*$'
            ),
            '<DOMAIN>': PlaceholderDefinition(
                name='<DOMAIN>',
                description='Domain name',
                example='example.com',
                validation_regex=r'^[\w\.\-]+$'
            ),
            '<USERNAME>': PlaceholderDefinition(
                name='<USERNAME>',
                description='Username for authentication',
                example='admin',
                validation_regex=r'^[\w\-\.]+$'
            ),
            '<PASSWORD>': PlaceholderDefinition(
                name='<PASSWORD>',
                description='Password for authentication',
                example='password123',
                validation_regex=None  # No validation for passwords
            ),
            '<FILE>': PlaceholderDefinition(
                name='<FILE>',
                description='File path or name',
                example='shell.php',
                validation_regex=r'^[\w\-\./]+$'
            ),
            '<WORDLIST>': PlaceholderDefinition(
                name='<WORDLIST>',
                description='Path to wordlist file',
                example='/usr/share/wordlists/rockyou.txt',
                validation_regex=r'^[\w\-\./]+$',
                default_value='/usr/share/wordlists/rockyou.txt'
            ),
            '<OUTPUT>': PlaceholderDefinition(
                name='<OUTPUT>',
                description='Output file path',
                example='scan_results.txt',
                validation_regex=r'^[\w\-\./]+$'
            ),
            '<COMMAND>': PlaceholderDefinition(
                name='<COMMAND>',
                description='System command to execute',
                example='whoami',
                validation_regex=None  # Commands can be complex
            ),
            '<PAYLOAD>': PlaceholderDefinition(
                name='<PAYLOAD>',
                description='Attack payload',
                example="' OR 1=1--",
                validation_regex=None  # Payloads can contain special chars
            ),
            '<INTERFACE>': PlaceholderDefinition(
                name='<INTERFACE>',
                description='Network interface',
                example='tun0',
                validation_regex=r'^[\w\d]+$',
                source='INTERFACE'
            ),
            '<SESSION>': PlaceholderDefinition(
                name='<SESSION>',
                description='Session identifier',
                example='sess_abc123',
                validation_regex=r'^[\w\-]+$'
            ),
            '<TOKEN>': PlaceholderDefinition(
                name='<TOKEN>',
                description='Authentication or CSRF token',
                example='csrf_token_xyz',
                validation_regex=None
            ),
            '<THREADS>': PlaceholderDefinition(
                name='<THREADS>',
                description='Number of threads',
                example='10',
                validation_regex=r'^\d+$',
                default_value='10'
            ),
            '<DELAY>': PlaceholderDefinition(
                name='<DELAY>',
                description='Delay in seconds',
                example='1',
                validation_regex=r'^\d+$',
                default_value='1'
            ),
            '<TIMEOUT>': PlaceholderDefinition(
                name='<TIMEOUT>',
                description='Timeout in seconds',
                example='30',
                validation_regex=r'^\d+$',
                default_value='30'
            ),
            '<RATE>': PlaceholderDefinition(
                name='<RATE>',
                description='Scan rate (packets/sec)',
                example='1000',
                validation_regex=r'^\d+$',
                default_value='1000'
            )
        }

    def _load_environment_values(self):
        """Load values from environment variables"""
        for placeholder, definition in self.definitions.items():
            if definition.source:
                env_value = os.environ.get(definition.source)
                if env_value:
                    self.user_values[placeholder] = env_value

    def _load_config_values(self):
        """Load values from config manager if available"""
        if self.config_manager:
            # Get all configured values
            config_values = self.config_manager.get_placeholder_values()
            # Merge with user values (config takes precedence)
            self.user_values.update(config_values)

    def extract_placeholders(self, text: str) -> List[str]:
        """Extract all placeholders from text"""
        return re.findall(r'<[A-Z_]+>', text)

    def validate_value(self, placeholder: str, value: str) -> Tuple[bool, str]:
        """Validate a value for a placeholder"""
        if placeholder not in self.definitions:
            return True, "No validation rules defined"

        definition = self.definitions[placeholder]
        if not definition.validation_regex:
            return True, "No validation required"

        if re.match(definition.validation_regex, value):
            return True, "Valid"
        else:
            return False, f"Value doesn't match expected format: {definition.example}"

    def substitute(self, text: str, values: Dict[str, str] = None) -> str:
        """Substitute placeholders in text"""
        values = values or {}
        result = text

        # Merge with stored user values
        all_values = {**self.user_values, **values}

        # Replace each placeholder
        for placeholder in self.extract_placeholders(text):
            if placeholder in all_values:
                result = result.replace(placeholder, all_values[placeholder])
            elif placeholder in self.definitions:
                # Use default value if available
                if self.definitions[placeholder].default_value:
                    result = result.replace(placeholder, self.definitions[placeholder].default_value)

        return result

    def interactive_fill(self, text: str, skip_defaults: bool = False) -> str:
        """Interactively fill placeholders"""
        placeholders = self.extract_placeholders(text)
        values = {}

        print("\n[*] Interactive placeholder filling")
        print(f"[*] Text: {text}\n")

        for placeholder in set(placeholders):  # Unique placeholders
            definition = self.definitions.get(placeholder)

            # Build prompt
            prompt = f"Enter value for {placeholder}"
            if definition:
                prompt += f" ({definition.description})"
                if definition.example:
                    prompt += f"\n   Example: {definition.example}"
                if definition.default_value and not skip_defaults:
                    prompt += f"\n   Default: {definition.default_value} (press Enter to use)"
            prompt += "\n   > "

            # Get user input
            user_input = input(prompt).strip()

            # Use default if empty and available
            if not user_input and definition and definition.default_value and not skip_defaults:
                user_input = definition.default_value
                print(f"   Using default: {user_input}")

            if user_input:
                # Validate if rules exist
                if definition and definition.validation_regex:
                    valid, message = self.validate_value(placeholder, user_input)
                    if not valid:
                        print(f"   Warning: {message}")
                        retry = input("   Use anyway? (y/N): ").strip().lower()
                        if retry != 'y':
                            continue

                values[placeholder] = user_input

        # Perform substitution
        result = self.substitute(text, values)
        print(f"\n[+] Result: {result}")
        return result

    def set_value(self, placeholder: str, value: str):
        """Set a persistent value for a placeholder"""
        self.user_values[placeholder] = value

    def get_value(self, placeholder: str) -> Optional[str]:
        """Get stored value for a placeholder"""
        return self.user_values.get(placeholder)

    def clear_values(self):
        """Clear all stored values"""
        self.user_values = {}
        self._load_environment_values()  # Reload from environment

    def add_custom_placeholder(self, name: str, description: str,
                             example: str = "", regex: str = None,
                             default: str = None):
        """Add a custom placeholder definition"""
        self.definitions[name] = PlaceholderDefinition(
            name=name,
            description=description,
            example=example,
            validation_regex=regex,
            default_value=default
        )

    def suggest_values(self, placeholder: str) -> List[str]:
        """Suggest common values for a placeholder"""
        suggestions = {
            '<PORT>': ['80', '443', '22', '21', '3306', '3389', '445', '8080'],
            '<LPORT>': ['4444', '4445', '9001', '9002', '1337', '8888'],
            '<WORDLIST>': [
                '/usr/share/wordlists/rockyou.txt',
                '/usr/share/wordlists/dirb/common.txt',
                '/usr/share/seclists/Discovery/Web-Content/common.txt',
                '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'
            ],
            '<THREADS>': ['10', '25', '50', '100'],
            '<DELAY>': ['0', '1', '5', '10'],
            '<TIMEOUT>': ['10', '30', '60', '120'],
            '<INTERFACE>': ['eth0', 'tun0', 'tun1', 'wlan0']
        }
        return suggestions.get(placeholder, [])

    def export_definitions(self) -> Dict[str, dict]:
        """Export all placeholder definitions as dict"""
        result = {}
        for name, definition in self.definitions.items():
            result[name] = {
                'description': definition.description,
                'example': definition.example,
                'validation': definition.validation_regex,
                'default': definition.default_value,
                'source': definition.source
            }
        return result