"""
Display Manager - Terminal formatting utilities

Handles all terminal display logic including:
- Context banners showing current state
- Numbered menus with descriptions
- Progress bars and indicators
- Multi-select checkboxes
- Status formatting
"""

import os
from typing import List, Dict, Any, Optional
from datetime import datetime

# Try to import Colors from crack utils
try:
    from crack.themes import Colors
except ImportError:
    # Fallback if running standalone
    class Colors:
        HEADER = '\033[95m'
        BLUE = '\033[94m'
        CYAN = '\033[96m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        RED = '\033[91m'
        BOLD = '\033[1m'
        END = '\033[0m'
        # Bright variants
        BRIGHT_BLACK = '\033[90m'
        BRIGHT_RED = '\033[91m'
        BRIGHT_GREEN = '\033[92m'
        BRIGHT_YELLOW = '\033[93m'
        BRIGHT_BLUE = '\033[94m'
        BRIGHT_MAGENTA = '\033[95m'
        BRIGHT_CYAN = '\033[96m'
        BRIGHT_WHITE = '\033[97m'
        # Combinations
        BOLD_GREEN = '\033[1m\033[92m'
        BOLD_YELLOW = '\033[1m\033[93m'
        BOLD_RED = '\033[1m\033[91m'
        BOLD_CYAN = '\033[1m\033[96m'
        BOLD_WHITE = '\033[1m\033[97m'


class DisplayManager:
    """Terminal display and formatting utilities"""

    # Status symbols matching existing ConsoleFormatter
    SYMBOLS = {
        'pending': '[ ]',
        'in-progress': '[~]',
        'completed': '[✓]',
        'skipped': '[✗]'
    }

    STATUS_COLORS = {
        'pending': Colors.BRIGHT_YELLOW,
        'in-progress': Colors.BRIGHT_CYAN,
        'completed': Colors.BRIGHT_GREEN,
        'skipped': Colors.BRIGHT_RED
    }

    @classmethod
    def clear_screen(cls):
        """Clear terminal screen (optional, can be disabled)"""
        # Don't clear by default - preserves command history
        pass

    @classmethod
    def format_context_banner(cls, profile, phase: str = None, last_action: str = None) -> str:
        """
        Format current state banner displayed before each prompt

        Args:
            profile: TargetProfile instance
            phase: Current phase (optional, uses profile.phase if not provided)
            last_action: Description of last completed action

        Returns:
            Formatted banner string
        """
        phase = phase or profile.phase
        progress = profile.get_progress()
        total = progress['total']
        completed = progress['completed']
        pct = (completed / total * 100) if total > 0 else 0

        # Calculate time elapsed
        created = datetime.fromisoformat(profile.created)
        elapsed = datetime.now() - created
        hours = int(elapsed.total_seconds() // 3600)
        minutes = int((elapsed.total_seconds() % 3600) // 60)
        time_str = f"{hours:02d}:{minutes:02d}:00"

        banner = f"""
{Colors.BOLD_CYAN}{'=' * 70}{Colors.END}
{Colors.BOLD_CYAN}Target:{Colors.END} {Colors.BOLD_WHITE}{profile.target}{Colors.END}
{Colors.BOLD_CYAN}Phase:{Colors.END} {Colors.BRIGHT_WHITE}{phase.replace('-', ' ').title()}{Colors.END}
{Colors.BOLD_CYAN}Progress:{Colors.END} {Colors.BRIGHT_WHITE}{completed}/{total}{Colors.END} tasks completed {Colors.BRIGHT_GREEN}({pct:.0f}%){Colors.END}
"""
        if last_action:
            banner += f"{Colors.BOLD_CYAN}Last Action:{Colors.END} {Colors.BRIGHT_WHITE}{last_action}{Colors.END}\n"

        banner += f"{Colors.BOLD_CYAN}Time Elapsed:{Colors.END} {Colors.BRIGHT_WHITE}{time_str}{Colors.END}\n"
        banner += f"{Colors.BOLD_CYAN}{'=' * 70}{Colors.END}"

        return banner

    @classmethod
    def format_menu(cls, choices: List[Dict[str, Any]], title: str = None) -> str:
        """
        Format numbered menu with descriptions

        Args:
            choices: List of choice dicts with 'id', 'label', 'description' (optional)
            title: Optional menu title

        Returns:
            Formatted menu string
        """
        output = []

        if title:
            output.append(f"\n{Colors.BOLD}{title}{Colors.END}\n")

        for i, choice in enumerate(choices, 1):
            label = choice.get('label', choice.get('name', str(choice.get('id'))))
            description = choice.get('description', '')

            # Format choice line
            line = f"  {Colors.BOLD}{i}.{Colors.END} {label}"
            if description:
                line += f"\n     {Colors.CYAN}→{Colors.END} {description}"

            output.append(line)

        return "\n".join(output)

    @classmethod
    def format_multi_select(cls, tasks: List[Any], selected: List[int] = None) -> str:
        """
        Format multi-select checkbox menu

        Args:
            tasks: List of TaskNode objects or choice dicts
            selected: List of indices that are selected

        Returns:
            Formatted multi-select menu
        """
        selected = selected or []
        output = ["\n" + Colors.BOLD + "Multiple tasks can run in parallel. Select all:" + Colors.END + "\n"]

        for i, task in enumerate(tasks, 1):
            checkbox = '[x]' if i in selected else '[ ]'

            # Handle both TaskNode objects and dicts
            if hasattr(task, 'name'):
                name = task.name
            else:
                name = task.get('name', task.get('label', str(i)))

            output.append(f"  {checkbox} {Colors.BOLD}{i}.{Colors.END} {name}")

        output.append("")
        output.append("Select: 1,3 or 'all' or 'none': ")

        return "\n".join(output)

    @classmethod
    def format_progress_bar(cls, current: int, total: int, width: int = 50,
                           label: str = None) -> str:
        """
        Format progress bar

        Args:
            current: Current progress value
            total: Total/maximum value
            width: Width of progress bar in characters
            label: Optional label to display before bar

        Returns:
            Formatted progress bar string
        """
        if total == 0:
            percentage = 0
        else:
            percentage = int((current / total) * 100)

        filled = int((current / total) * width) if total > 0 else 0
        bar = '#' * filled + '.' * (width - filled)

        output = f"[{bar}] {percentage}%"

        if label:
            output = f"{label}: {output}"

        # Add fraction
        output += f" - {current}/{total}"

        return output

    @classmethod
    def format_task_summary(cls, task) -> str:
        """
        Format single task summary with metadata

        Args:
            task: TaskNode instance

        Returns:
            Formatted task summary
        """
        output = []

        # Task header
        status_symbol = cls.SYMBOLS.get(task.status, '[ ]')
        status_color = cls.STATUS_COLORS.get(task.status, '')

        output.append(f"\n{status_color}{status_symbol}{Colors.END} {Colors.BOLD}{task.name}{Colors.END}")

        # Metadata
        metadata = task.metadata

        if metadata.get('description'):
            output.append(f"  {Colors.CYAN}Description:{Colors.END} {metadata['description']}")

        if metadata.get('command'):
            output.append(f"  {Colors.CYAN}Command:{Colors.END} {metadata['command']}")

        # Phase 5.3: Display wordlist info if present
        if metadata.get('wordlist'):
            wordlist_name = metadata.get('wordlist_name', 'custom')
            line_count = metadata.get('wordlist_line_count')
            if line_count:
                # Format line count (e.g., "4.6K lines")
                if line_count >= 1_000_000:
                    line_str = f"{line_count / 1_000_000:.1f}M lines"
                elif line_count >= 1_000:
                    line_str = f"{line_count / 1_000:.1f}K lines"
                else:
                    line_str = f"{line_count} lines"
                output.append(f"  {Colors.CYAN}Wordlist:{Colors.END} {wordlist_name} ({line_str})")
            else:
                output.append(f"  {Colors.CYAN}Wordlist:{Colors.END} {wordlist_name}")

        if metadata.get('tags'):
            tags_str = ', '.join(metadata['tags'])
            output.append(f"  {Colors.CYAN}Tags:{Colors.END} {tags_str}")

        return "\n".join(output)

    @classmethod
    def format_confirmation(cls, message: str, default: str = 'Y') -> str:
        """
        Format confirmation prompt

        Args:
            message: Question to ask
            default: Default choice ('Y' or 'N')

        Returns:
            Formatted confirmation string
        """
        if default.upper() == 'Y':
            choices = f"{Colors.BOLD}[Y/n]{Colors.END}"
        else:
            choices = f"{Colors.BOLD}[y/N]{Colors.END}"

        return f"\n{message} {choices}: "

    @classmethod
    def format_guided_entry_field(cls, field_name: str, field_type: type,
                                  required: bool, example: str = None,
                                  default: Any = None) -> str:
        """
        Format single field in guided entry form

        Args:
            field_name: Name of field
            field_type: Type of field (str, int, etc.)
            required: Whether field is required
            example: Example value
            default: Default value if any

        Returns:
            Formatted field prompt
        """
        output = []

        # Field name
        req_marker = f"{Colors.RED}*{Colors.END}" if required else ""
        output.append(f"\n{Colors.BOLD}{field_name}{req_marker}:{Colors.END}")

        # Example or default
        if example:
            output.append(f"  {Colors.CYAN}Example:{Colors.END} {example}")
        elif default:
            output.append(f"  {Colors.CYAN}Default:{Colors.END} {default}")

        # Type hint
        type_name = field_type.__name__
        output.append(f"  {Colors.CYAN}({type_name}){Colors.END}")

        return "\n".join(output)

    @classmethod
    def format_shortcuts_help(cls, shortcuts: Dict[str, tuple]) -> str:
        """
        Format keyboard shortcuts help display

        Args:
            shortcuts: Dict mapping shortcut keys to (description, handler) tuples

        Returns:
            Formatted shortcuts help
        """
        output = ["\n" + Colors.BOLD + "Keyboard Shortcuts:" + Colors.END + "\n"]

        for key, (description, _) in shortcuts.items():
            output.append(f"  {Colors.BOLD}{key}{Colors.END} - {description}")

        return "\n".join(output)

    @classmethod
    def format_error(cls, message: str) -> str:
        """Format error message"""
        return f"\n{Colors.BOLD_RED}✗ Error:{Colors.END} {message}\n"

    @classmethod
    def format_success(cls, message: str) -> str:
        """Format success message"""
        return f"\n{Colors.BOLD_GREEN}✓{Colors.END} {message}\n"

    @classmethod
    def format_warning(cls, message: str) -> str:
        """Format warning message"""
        return f"\n{Colors.BOLD_YELLOW}⚠{Colors.END} {message}\n"

    @classmethod
    def format_info(cls, message: str) -> str:
        """Format info message"""
        return f"\n{Colors.BOLD_CYAN}ℹ{Colors.END} {message}\n"

    @classmethod
    def format_shortcuts_footer(cls) -> str:
        """
        Format persistent shortcut footer bar

        Shows essential keyboard shortcuts in compact format:
        ([key]) [description] | ([key]) [description] | ...

        Returns:
            Formatted footer string
        """
        # Define essential shortcuts to display
        shortcuts = [
            ('s', 'Status'),
            ('t', 'Tree'),
            ('r', 'Recs'),
            ('n', 'Next'),
            ('w', 'Wordlist'),
            ('alt', 'Alts'),
            ('h', 'Help'),
            ('q', 'Quit')
        ]

        # Format each shortcut with bold key
        formatted_shortcuts = []
        for key, desc in shortcuts:
            formatted_shortcuts.append(f"{Colors.BOLD_CYAN}({key}){Colors.END} {desc}")

        # Join with separator
        footer = " | ".join(formatted_shortcuts)

        # Add top border
        border = Colors.BRIGHT_BLACK + "─" * 80 + Colors.END

        return f"\n{border}\n{footer}\n"
