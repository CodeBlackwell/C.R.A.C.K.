"""
Interactive selection UI for multi-result findings.

Provides numbered lists with single-keystroke selection.
"""

import sys
import tty
import termios
from typing import List, Dict, Any, Optional, Callable


class FindingSelector:
    """
    Interactive selection UI for findings with multiple options.

    Provides consistent UX across all chain types:
    - Numbered list (1-9 for single-key)
    - Clear prompt showing selection
    - Auto-select for single option
    - Skip option if appropriate
    """

    def __init__(self, theme):
        """
        Initialize selector.

        Args:
            theme: ReferenceTheme instance for consistent coloring
        """
        self.theme = theme

    def select_single(
        self,
        options: List[Any],
        prompt: str,
        display_field: Optional[str] = None,
        display_fn: Optional[Callable[[Any], str]] = None,
        allow_skip: bool = False,
    ) -> Optional[Any]:
        """
        Present numbered list and get user selection.

        Args:
            options: List of options to choose from
            prompt: Question to show user
            display_field: Field name to display (for dict options)
            display_fn: Custom function to format display (overrides display_field)
            allow_skip: Allow user to skip selection (press 's')

        Returns:
            Selected option or None if skipped/cancelled

        Note:
            - Single option auto-selects
            - Shows first 9 options for single-key selection
            - Remaining options shown but require Enter
        """
        if not options:
            print(self.theme.warning("\nNo options available"))
            return None

        if len(options) == 1:
            # Auto-select single option
            display = self._format_display(options[0], display_field, display_fn)
            print(self.theme.hint(f"\n→ Auto-selecting: {display}"))
            return options[0]

        # Display options
        print(f"\n{self.theme.primary(prompt)}")
        print(self.theme.hint("=" * 70))

        for idx, option in enumerate(options[:9], 1):  # Max 9 for single-key
            display = self._format_display(option, display_field, display_fn)
            print(f"  {self.theme.primary(str(idx))}. {display}")

        if len(options) > 9:
            print(
                f"\n{self.theme.hint(f'... and {len(options) - 9} more (type number + Enter)')}"
            )

        # Show skip option
        skip_hint = ""
        if allow_skip:
            skip_hint = ", 's' to skip"

        # Get selection
        max_option = len(options)
        prompt_text = f"\nSelect option (1-{max_option}{skip_hint}): "

        while True:
            choice = self._read_input(prompt_text)

            if allow_skip and choice.lower() == 's':
                print(self.theme.hint("Skipped selection"))
                return None

            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(options):
                    selected = options[idx]
                    display = self._format_display(selected, display_field, display_fn)
                    print(self.theme.success(f"\n✓ Selected: {display}"))
                    return selected

            print(self.theme.error("Invalid selection, try again"))

    def select_multiple(
        self,
        options: List[Any],
        prompt: str,
        display_field: Optional[str] = None,
        display_fn: Optional[Callable[[Any], str]] = None,
        min_selections: int = 1,
        max_selections: Optional[int] = None,
    ) -> List[Any]:
        """
        Allow multiple selections from list.

        Args:
            options: List of options to choose from
            prompt: Question to show user
            display_field: Field name to display (for dict options)
            display_fn: Custom function to format display
            min_selections: Minimum required selections
            max_selections: Maximum allowed selections (None = unlimited)

        Returns:
            List of selected options
        """
        if not options:
            print(self.theme.warning("\nNo options available"))
            return []

        # Display options with checkboxes
        print(f"\n{self.theme.primary(prompt)}")
        print(self.theme.hint("=" * 70))

        for idx, option in enumerate(options, 1):
            display = self._format_display(option, display_field, display_fn)
            print(f"  {self.theme.muted('[ ]')} {self.theme.primary(str(idx))}. {display}")

        # Show instructions
        max_hint = f" (max {max_selections})" if max_selections else ""
        print(
            f"\n{self.theme.hint(f'Enter numbers separated by spaces or commas{max_hint}')}"
        )
        print(self.theme.hint("Example: 1,3,5 or 1 3 5"))

        # Get selections
        while True:
            choice = self._read_input(f"\nSelect {min_selections}+ options: ")

            # Parse input
            indices = self._parse_multi_input(choice)

            # Validate
            if not indices:
                print(self.theme.error("No valid selections"))
                continue

            if len(indices) < min_selections:
                print(
                    self.theme.error(
                        f"Need at least {min_selections} selections, got {len(indices)}"
                    )
                )
                continue

            if max_selections and len(indices) > max_selections:
                print(
                    self.theme.error(
                        f"Maximum {max_selections} selections, got {len(indices)}"
                    )
                )
                continue

            # Check bounds
            if any(idx < 1 or idx > len(options) for idx in indices):
                print(self.theme.error(f"Invalid option number (must be 1-{len(options)})"))
                continue

            # Get selected options
            selected = [options[idx - 1] for idx in indices]

            # Show confirmation
            print(self.theme.success(f"\n✓ Selected {len(selected)} options:"))
            for option in selected:
                display = self._format_display(option, display_field, display_fn)
                print(f"  • {display}")

            return selected

    def _format_display(
        self,
        option: Any,
        display_field: Optional[str],
        display_fn: Optional[Callable[[Any], str]],
    ) -> str:
        """
        Format option for display with fuzzy match indicators.

        Args:
            option: Option to format
            display_field: Field name for dict options
            display_fn: Custom formatter

        Returns:
            Formatted string with GTFOBins match indicators
        """
        # Check if this is a GTFOBins match dict with metadata
        if isinstance(option, dict) and 'gtfobin_match' in option:
            path = option['path']
            match_name = option['gtfobin_match']
            match_type = option.get('match_type', 'exact')

            if match_type == 'exact':
                return f"{path} (GTFOBins)"
            else:
                # Fuzzy match - show the matched GTFOBin name with asterisk
                return f"{path} (GTFOBins: {match_name}*)"

        # Custom formatter
        if display_fn:
            return display_fn(option)

        # Dict with specific field
        if display_field and isinstance(option, dict):
            return str(option.get(display_field, option))

        # Default: just convert to string
        return str(option)

    def _read_input(self, prompt: str) -> str:
        """
        Read user input with prompt.

        Args:
            prompt: Prompt text

        Returns:
            User input string
        """
        return input(self.theme.prompt(prompt)).strip()

    def _parse_multi_input(self, input_str: str) -> List[int]:
        """
        Parse comma/space separated numbers.

        Args:
            input_str: User input

        Returns:
            List of integers
        """
        # Replace commas with spaces
        normalized = input_str.replace(',', ' ')

        # Split and convert to ints
        indices = []
        for part in normalized.split():
            if part.isdigit():
                indices.append(int(part))

        # Remove duplicates, preserve order
        seen = set()
        result = []
        for idx in indices:
            if idx not in seen:
                seen.add(idx)
                result.append(idx)

        return result
