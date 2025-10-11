"""
CommandFormatter - Rebuild and Format Commands

Converts ParsedCommand structures back to executable strings with:
- Multi-line formatting with backslashes
- Syntax highlighting using Rich
- Diff display for command modifications

Usage:
    formatted = CommandFormatter.format_command(parsed, multi_line=True)
    highlighted = CommandFormatter.highlight_syntax(command)
    diff_output = CommandFormatter.show_diff(original, modified)
"""

from dataclasses import dataclass
from typing import Optional, Dict, List
from difflib import unified_diff


@dataclass
class ParsedCommand:
    """Parsed command structure (matches parser.py interface)"""
    tool: str
    subcommand: Optional[str]
    flags: Dict[str, bool]  # Boolean flags (-v, -f)
    parameters: Dict[str, str]  # Value params (-u URL, -w PATH)
    arguments: List[str]  # Positional args


class CommandFormatter:
    """Format parsed commands back to executable strings"""

    # Tool-specific formatting rules
    FLAG_ORDER = {
        'gobuster': ['u', 'w', 't', 'x', 'o'],
        'nmap': ['sS', 'sV', 'p', 'T', 'A', 'oA'],
        'nikto': ['h', 'p', 'ssl', 'Tuning'],
        'hydra': ['l', 'L', 'p', 'P', 't'],
        'sqlmap': ['u', 'dbs', 'tables', 'dump']
    }

    @staticmethod
    def format_command(parsed: ParsedCommand, multi_line: bool = False) -> str:
        """
        Rebuild command string from parsed structure

        Args:
            parsed: ParsedCommand dataclass
            multi_line: If True, format with backslashes (max 80 chars/line)

        Returns:
            Executable command string

        Examples:
            >>> parsed = ParsedCommand('gobuster', 'dir', {}, {'u': 'http://target', 'w': '/path'}, [])
            >>> CommandFormatter.format_command(parsed)
            'gobuster dir -u http://target -w /path'
        """
        parts = [parsed.tool]

        # Add subcommand if present
        if parsed.subcommand:
            parts.append(parsed.subcommand)

        # Add boolean flags (sorted for consistency)
        for flag in sorted(parsed.flags.keys()):
            if parsed.flags[flag]:
                prefix = '--' if len(flag) > 1 else '-'
                parts.append(f"{prefix}{flag}")

        # Add parameters (tool-specific order if available)
        param_keys = list(parsed.parameters.keys())
        if parsed.tool in CommandFormatter.FLAG_ORDER:
            # Order by tool preference, then alphabetically for unknowns
            ordered_flags = CommandFormatter.FLAG_ORDER[parsed.tool]
            param_keys = sorted(
                param_keys,
                key=lambda k: (ordered_flags.index(k) if k in ordered_flags else 999, k)
            )
        else:
            param_keys = sorted(param_keys)

        for key in param_keys:
            value = parsed.parameters[key]
            prefix = '--' if len(key) > 1 else '-'
            # Quote value if it contains spaces
            if ' ' in value:
                value = f'"{value}"'
            parts.append(f"{prefix}{key} {value}")

        # Add positional arguments
        for arg in parsed.arguments:
            # Quote if contains spaces
            if ' ' in arg:
                arg = f'"{arg}"'
            parts.append(arg)

        command = ' '.join(parts)

        # Multi-line formatting
        if multi_line and len(command) > 80:
            return CommandFormatter._format_multiline(parts)

        return command

    @staticmethod
    def _format_multiline(parts: List[str]) -> str:
        """
        Format command across multiple lines with backslashes

        Args:
            parts: List of command parts

        Returns:
            Multi-line formatted string
        """
        lines = []
        current_line = []
        current_length = 0

        for part in parts:
            part_length = len(part) + 1  # +1 for space

            # Start new line if adding part exceeds 80 chars
            if current_length + part_length > 80 and current_line:
                lines.append(' '.join(current_line) + ' \\')
                current_line = ['    ' + part]  # Indent continuation
                current_length = 4 + len(part)
            else:
                current_line.append(part)
                current_length += part_length

        # Add final line
        if current_line:
            lines.append(' '.join(current_line))

        return '\n'.join(lines)

    @staticmethod
    def highlight_syntax(command: str) -> str:
        """
        Apply Rich syntax highlighting to command string

        Args:
            command: Command string to highlight

        Returns:
            Rich markup string with syntax highlighting

        Examples:
            >>> CommandFormatter.highlight_syntax('gobuster dir -u http://target')
            '[cyan]gobuster[/cyan] [green]dir[/green] [yellow]-u[/yellow] http://target'
        """
        if not command.strip():
            return command

        parts = command.split()
        highlighted = []

        for i, part in enumerate(parts):
            if i == 0:
                # Tool name
                highlighted.append(f'[cyan bold]{part}[/cyan bold]')
            elif i == 1 and not part.startswith('-'):
                # Subcommand
                highlighted.append(f'[green]{part}[/green]')
            elif part.startswith('-'):
                # Flag or parameter
                highlighted.append(f'[yellow]{part}[/yellow]')
            elif part.startswith('http'):
                # URLs (check before file paths since URLs contain '/')
                highlighted.append(f'[magenta]{part}[/magenta]')
            elif '/' in part or part.endswith(('.txt', '.xml', '.json', '.html')):
                # File paths
                highlighted.append(f'[blue]{part}[/blue]')
            else:
                # Regular arguments
                highlighted.append(part)

        return ' '.join(highlighted)

    @staticmethod
    def show_diff(original: str, modified: str) -> str:
        """
        Show side-by-side diff with colors

        Args:
            original: Original command string
            modified: Modified command string

        Returns:
            Rich markup string with colored diff

        Examples:
            >>> CommandFormatter.show_diff('gobuster -w old.txt', 'gobuster -w new.txt')
            '[red]- gobuster -w old.txt[/red]\n[green]+ gobuster -w new.txt[/green]'
        """
        # Normalize line breaks for multi-line commands
        orig_lines = original.split('\n')
        mod_lines = modified.split('\n')

        # Generate unified diff
        diff = unified_diff(
            orig_lines,
            mod_lines,
            lineterm='',
            fromfile='original',
            tofile='modified',
            n=0  # No context lines
        )

        # Convert diff to Rich markup
        diff_lines = []
        for line in diff:
            if line.startswith('---') or line.startswith('+++'):
                # Skip file headers
                continue
            elif line.startswith('@@'):
                # Skip hunk headers
                continue
            elif line.startswith('-'):
                # Removed line
                diff_lines.append(f'[red]{line}[/red]')
            elif line.startswith('+'):
                # Added line
                diff_lines.append(f'[green]{line}[/green]')
            else:
                # Context line (shouldn't happen with n=0)
                diff_lines.append(line)

        # Add summary if no diff
        if not diff_lines:
            return '[dim]No changes detected[/dim]'

        return '\n'.join(diff_lines)
