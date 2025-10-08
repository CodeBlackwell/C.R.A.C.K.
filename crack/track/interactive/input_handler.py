"""
Input Processor - Parse and validate user input

Handles all user input including:
- Numeric choices (1, 2, 3)
- Keyword matching (scan, enumerate, skip)
- Command execution (!command)
- Keyboard shortcuts (s, t, r, n, c, x, b, h, q)
- Multi-select parsing (1,3,5 or all/none)
- Navigation commands (back, menu, exit)
"""

import re
from typing import List, Dict, Any, Optional, Tuple, Union


class InputProcessor:
    """Parse and validate user input in interactive mode"""

    # Navigation commands
    NAV_COMMANDS = {
        'back': 'Go back to previous menu',
        'menu': 'Return to main menu',
        'exit': 'Exit interactive mode',
        'quit': 'Exit interactive mode',
        'q': 'Exit interactive mode'
    }

    # Shortcuts (handled separately in ShortcutHandler, but recognized here)
    SHORTCUTS = ['s', 't', 'r', 'n', 'c', 'x', 'ch', 'pl', 'tf', 'qn', 'tt', 'pd', 'qx', 'fc', 'qe', 'ss', 'tr', 'be', 'b', 'h', 'q']

    @classmethod
    def parse_choice(cls, user_input: str, choices: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Parse user input and match to available choices

        Supports:
        - Numeric selection (1, 2, 3)
        - Keyword matching (partial case-insensitive match)
        - Choice ID matching

        Args:
            user_input: Raw input string from user
            choices: List of choice dicts with 'id', 'label', etc.

        Returns:
            Matched choice dict or None if invalid
        """
        if not user_input or not choices:
            return None

        user_input = user_input.strip().lower()

        # Try numeric match first (most common)
        if user_input.isdigit():
            index = int(user_input) - 1  # Convert to 0-based index
            if 0 <= index < len(choices):
                return choices[index]
            return None

        # Try keyword matching (match against label, name, or id)
        for choice in choices:
            # Get searchable fields
            label = choice.get('label', choice.get('name', '')).lower()
            choice_id = str(choice.get('id', '')).lower()

            # Check for partial match in label or exact match in id
            if user_input in label or user_input == choice_id:
                return choice

        return None

    @classmethod
    def parse_multi_select(cls, user_input: str, total_items: int) -> List[int]:
        """
        Parse multi-select input

        Supports:
        - Individual numbers: "1" → [1]
        - Comma-separated: "1,3,5" → [1, 3, 5]
        - Ranges: "1-3" → [1, 2, 3]
        - Special keywords: "all", "none"

        Args:
            user_input: Raw input string
            total_items: Total number of selectable items

        Returns:
            List of selected indices (1-based)
        """
        if not user_input:
            return []

        user_input = user_input.strip().lower()

        # Handle special keywords
        if user_input in ['all', 'a']:
            return list(range(1, total_items + 1))
        if user_input in ['none', 'n', '']:
            return []

        selected = []

        # Split by comma and process each part
        parts = user_input.split(',')

        for part in parts:
            part = part.strip()

            # Handle range (e.g., "1-3")
            if '-' in part:
                try:
                    start, end = part.split('-')
                    start_idx = int(start.strip())
                    end_idx = int(end.strip())

                    # Validate range
                    if 1 <= start_idx <= total_items and 1 <= end_idx <= total_items:
                        selected.extend(range(start_idx, end_idx + 1))
                except ValueError:
                    continue  # Skip invalid ranges

            # Handle single number
            elif part.isdigit():
                idx = int(part)
                if 1 <= idx <= total_items:
                    selected.append(idx)

        # Remove duplicates and sort
        return sorted(list(set(selected)))

    @classmethod
    def parse_command(cls, user_input: str) -> Optional[Tuple[str, List[str]]]:
        """
        Parse command input (prefixed with ! or /)

        Args:
            user_input: Raw input string

        Returns:
            Tuple of (command, args) or None if not a command
        """
        if not user_input:
            return None

        # Support both ! and / prefixes
        if not (user_input.startswith('!') or user_input.startswith('/')):
            return None

        # Remove prefix and split into command and args
        cmd_line = user_input[1:].strip()
        if not cmd_line:
            return None

        parts = cmd_line.split()
        command = parts[0]
        args = parts[1:] if len(parts) > 1 else []

        return (command, args)

    @classmethod
    def parse_shortcut(cls, user_input: str) -> Optional[str]:
        """
        Check if input is a keyboard shortcut

        Args:
            user_input: Raw input string

        Returns:
            Shortcut key if recognized, None otherwise
        """
        if not user_input:
            return None

        user_input = user_input.strip().lower()

        if user_input in cls.SHORTCUTS:
            return user_input

        return None

    @classmethod
    def parse_navigation(cls, user_input: str) -> Optional[str]:
        """
        Check if input is a navigation command

        Args:
            user_input: Raw input string

        Returns:
            Navigation command name or None
        """
        if not user_input:
            return None

        user_input = user_input.strip().lower()

        if user_input in cls.NAV_COMMANDS:
            return user_input

        return None

    @classmethod
    def parse_confirmation(cls, user_input: str, default: str = 'Y') -> bool:
        """
        Parse Y/N confirmation input

        Args:
            user_input: Raw input string
            default: Default value if empty ('Y' or 'N')

        Returns:
            True for yes, False for no
        """
        if not user_input or user_input.strip() == '':
            return default.upper() == 'Y'

        user_input = user_input.strip().lower()

        # Accept various forms of yes/no
        if user_input in ['y', 'yes', 'yeah', 'yep', '1', 'true']:
            return True
        if user_input in ['n', 'no', 'nope', '0', 'false']:
            return False

        # Default if ambiguous
        return default.upper() == 'Y'

    @classmethod
    def parse_field_value(cls, user_input: str, field_type: type,
                         required: bool, default: Any = None) -> Tuple[bool, Any]:
        """
        Parse and validate field value in guided entry

        Args:
            user_input: Raw input string
            field_type: Expected type (str, int, float, etc.)
            required: Whether field is required
            default: Default value if empty

        Returns:
            Tuple of (is_valid, parsed_value)
        """
        # Handle empty input
        if not user_input or user_input.strip() == '':
            if default is not None:
                return (True, default)
            if not required:
                return (True, None)
            return (False, None)  # Required but not provided

        user_input = user_input.strip()

        # Try to convert to field_type
        try:
            if field_type == str:
                return (True, user_input)
            elif field_type == int:
                return (True, int(user_input))
            elif field_type == float:
                return (True, float(user_input))
            elif field_type == bool:
                return (True, cls.parse_confirmation(user_input))
            else:
                # Unknown type, return as string
                return (True, user_input)
        except ValueError:
            return (False, None)

    @classmethod
    def validate_and_retry(cls, prompt: str, validator: callable,
                          max_retries: int = 3) -> Optional[Any]:
        """
        Prompt user and retry on validation failure

        Args:
            prompt: Prompt to display
            validator: Function that validates input and returns (is_valid, value)
            max_retries: Maximum retry attempts

        Returns:
            Validated value or None if max retries exceeded
        """
        for attempt in range(max_retries):
            try:
                user_input = input(prompt)
                is_valid, value = validator(user_input)

                if is_valid:
                    return value
                else:
                    print(f"\nInvalid input. Please try again. ({attempt + 1}/{max_retries})")

            except KeyboardInterrupt:
                print("\n\nOperation cancelled.")
                return None
            except EOFError:
                return None

        print(f"\nMax retries exceeded. Operation cancelled.")
        return None

    @classmethod
    def get_input(cls, prompt: str = "Choice: ", allow_empty: bool = False) -> str:
        """
        Get input from user with error handling

        Args:
            prompt: Prompt to display
            allow_empty: Whether to allow empty input

        Returns:
            User input string (stripped)
        """
        try:
            user_input = input(prompt).strip()

            if not allow_empty and not user_input:
                return cls.get_input(prompt, allow_empty)

            return user_input

        except KeyboardInterrupt:
            print("\n\nOperation cancelled.")
            return 'exit'
        except EOFError:
            return 'exit'

    @classmethod
    def is_valid_choice(cls, user_input: str, num_choices: int) -> bool:
        """
        Check if input is a valid choice number

        Args:
            user_input: Raw input string
            num_choices: Number of available choices

        Returns:
            True if valid choice number
        """
        if not user_input or not user_input.strip().isdigit():
            return False

        choice_num = int(user_input.strip())
        return 1 <= choice_num <= num_choices

    @classmethod
    def parse_any(cls, user_input: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Unified parser that tries all parsing methods

        Args:
            user_input: Raw input string
            context: Dict with 'choices', 'total_items', etc.

        Returns:
            Dict with 'type' and 'value' keys indicating what was parsed
        """
        if not user_input:
            return {'type': 'empty', 'value': None}

        # Check shortcuts first (highest priority)
        shortcut = cls.parse_shortcut(user_input)
        if shortcut:
            return {'type': 'shortcut', 'value': shortcut}

        # Check navigation commands
        nav = cls.parse_navigation(user_input)
        if nav:
            return {'type': 'navigation', 'value': nav}

        # Check for command execution
        cmd = cls.parse_command(user_input)
        if cmd:
            return {'type': 'command', 'value': cmd}

        # Try to match against choices if provided
        if 'choices' in context:
            choice = cls.parse_choice(user_input, context['choices'])
            if choice:
                return {'type': 'choice', 'value': choice}

        # Default: raw input
        return {'type': 'raw', 'value': user_input.strip()}
