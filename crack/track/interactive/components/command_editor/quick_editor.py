"""
QuickEditor (Tier 1) - Parameter Menu Editor

Pure logic component for quick parameter editing.
NO TUI rendering - returns data structures only.
"""

from dataclasses import dataclass
from typing import Optional, Dict, List, Callable


@dataclass
class EditResult:
    """Result of editing operation"""
    command: Optional[str]
    action: str  # "execute", "escalate", "cancel"
    next_tier: Optional[str] = None  # "advanced", "raw"
    save_behavior: Optional[str] = None  # "once", "update", "template"


class QuickEditor:
    """Quick parameter editor for common tool parameters"""

    # Most common parameters per tool (extracted from usage patterns)
    COMMON_PARAMS = {
        'gobuster': ['url', 'wordlist', 'threads', 'extensions', 'output'],
        'nmap': ['target', 'ports', 'scan_type', 'timing', 'output'],
        'nikto': ['host', 'port', 'ssl', 'tuning', 'output'],
        'hydra': ['target', 'username', 'password_list', 'service', 'threads'],
        'sqlmap': ['url', 'dbs', 'tables', 'dump', 'threads']
    }

    # Map common names to actual flag names
    PARAM_FLAG_MAP = {
        'gobuster': {
            'url': 'u',
            'wordlist': 'w',
            'threads': 't',
            'extensions': 'x',
            'output': 'o'
        },
        'nmap': {
            'target': 'target',  # positional arg
            'ports': 'p',
            'scan_type': 'scan_type',  # derived from flags like -sS
            'timing': 'T',
            'output': 'oA'
        },
        'nikto': {
            'host': 'h',
            'port': 'p',
            'ssl': 'ssl',
            'tuning': 'Tuning',
            'output': 'output'
        },
        'hydra': {
            'target': 'target',  # positional arg
            'username': 'l',
            'password_list': 'P',
            'service': 'service',  # positional arg
            'threads': 't'
        },
        'sqlmap': {
            'url': 'u',
            'dbs': 'dbs',
            'tables': 'tables',
            'dump': 'dump',
            'threads': 'threads'
        }
    }

    def __init__(
        self,
        command: str,
        metadata: Dict,
        input_callback: Optional[Callable[[str], str]] = None,
        choice_callback: Optional[Callable[[str], str]] = None
    ):
        """
        Initialize QuickEditor.

        Args:
            command: Original command string
            metadata: Task metadata (must contain 'tool' key)
            input_callback: Function to get user input (default: no-op)
            choice_callback: Function to get user choice (default: no-op)
        """
        self.command = command
        self.metadata = metadata
        self.tool = metadata.get('tool', '').lower()
        self.modified_command = command

        # Callbacks for testing (allow mocking user interaction)
        self.input_callback = input_callback or (lambda prompt: "")
        self.choice_callback = choice_callback or (lambda prompt: "")

    def run(self) -> EditResult:
        """
        Main quick edit flow (NO TUI rendering, pure logic).

        Returns:
            EditResult with action and modified command
        """
        # Parse command to extract current parameters
        from .parser import CommandParser, ParsedCommand
        parsed = CommandParser.parse(self.command)

        # Extract editable parameters for this tool
        editable_params = self._extract_common_params(parsed)

        if not editable_params:
            # No common params found - escalate to advanced editor
            return EditResult(
                command=None,
                action="escalate",
                next_tier="advanced"
            )

        # Build menu of parameters (returns data structure, no rendering)
        menu_items = self._build_menu(editable_params)

        # Get user choice (1-5 for param, 'a' for advanced, 'c' for cancel)
        choice = self.choice_callback("Select parameter to edit:")

        if choice == 'c':
            return EditResult(command=None, action="cancel")

        if choice == 'a':
            return EditResult(
                command=self.command,
                action="escalate",
                next_tier="advanced"
            )

        if choice == 'r':
            return EditResult(
                command=self.command,
                action="escalate",
                next_tier="raw"
            )

        # Edit selected parameter
        if choice.isdigit():
            param_idx = int(choice) - 1
            if 0 <= param_idx < len(menu_items):
                param_name, current_value = menu_items[param_idx]
                new_value = self._edit_parameter(param_name, current_value)

                if new_value is not None:
                    # Update command with new value
                    self.modified_command = self._update_command(
                        parsed, param_name, new_value
                    )
                    return EditResult(
                        command=self.modified_command,
                        action="execute"
                    )

        # Invalid choice or cancelled edit
        return EditResult(command=None, action="cancel")

    def _extract_common_params(self, parsed) -> Dict[str, str]:
        """
        Extract editable parameters from parsed command.

        Args:
            parsed: ParsedCommand object

        Returns:
            Dict mapping common param names to current values
        """
        common_params = self.COMMON_PARAMS.get(self.tool, [])
        flag_map = self.PARAM_FLAG_MAP.get(self.tool, {})

        extracted = {}

        for param_name in common_params:
            flag_name = flag_map.get(param_name)

            if not flag_name:
                continue

            # Handle positional arguments
            if flag_name in ['target', 'service']:
                if parsed.arguments:
                    extracted[param_name] = parsed.arguments[0]
                continue

            # Handle derived values (scan_type from flags)
            if flag_name == 'scan_type':
                # Extract scan type from flags like -sS, -sT, -sV
                scan_flags = [f for f in parsed.flags.keys() if f.startswith('s')]
                if scan_flags:
                    extracted[param_name] = ','.join(scan_flags)
                continue

            # Handle normal parameters
            if flag_name in parsed.parameters:
                extracted[param_name] = parsed.parameters[flag_name]

        return extracted

    def _build_menu(self, params: Dict[str, str]) -> List[tuple]:
        """
        Build menu items from parameters.

        Args:
            params: Dict of param_name -> value

        Returns:
            List of (param_name, value) tuples
        """
        return list(params.items())

    def _edit_parameter(self, param_name: str, current_value: str) -> Optional[str]:
        """
        Edit single parameter (return new value or None).

        Args:
            param_name: Name of parameter to edit
            current_value: Current value

        Returns:
            New value or None if cancelled
        """
        prompt = f"Edit {param_name} (current: {current_value}):"
        new_value = self.input_callback(prompt)

        # Empty input = cancel
        if not new_value or new_value.strip() == "":
            return None

        return new_value.strip()

    def _update_command(self, parsed, param_name: str, new_value: str) -> str:
        """
        Update command with new parameter value.

        Args:
            parsed: ParsedCommand object
            param_name: Common parameter name
            new_value: New value for parameter

        Returns:
            Updated command string
        """
        from .formatter import CommandFormatter

        flag_map = self.PARAM_FLAG_MAP.get(self.tool, {})
        flag_name = flag_map.get(param_name)

        if not flag_name:
            return self.command

        # Update positional arguments
        if flag_name in ['target', 'service']:
            if parsed.arguments:
                parsed.arguments[0] = new_value
            else:
                parsed.arguments.append(new_value)
        # Update scan_type (special case)
        elif flag_name == 'scan_type':
            # Clear old scan flags
            parsed.flags = {k: v for k, v in parsed.flags.items() if not k.startswith('s')}
            # Add new scan flags
            for scan_flag in new_value.split(','):
                parsed.flags[scan_flag.strip()] = True
        # Update normal parameters
        else:
            parsed.parameters[flag_name] = new_value

        # Rebuild command from parsed structure
        return CommandFormatter.format_command(parsed)

    def get_preview_diff(self, original: str, modified: str) -> str:
        """
        Generate preview diff between original and modified commands.

        Args:
            original: Original command
            modified: Modified command

        Returns:
            Diff string (before/after)
        """
        return f"Before: {original}\nAfter:  {modified}"
