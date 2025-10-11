"""
Debug Stream Overlay - Live debug log viewer (D shortcut, debug mode only)

Features:
- Real-time colorized debug log streaming
- Category and level-based colorization
- Pagination with vim-style navigation
- Live tail mode with auto-refresh
- Filter by category/level
- Search functionality

Only available when --debug flag is active.
"""

import re
import time
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box
from rich.console import Console


class DebugStreamOverlay:
    """Debug log stream overlay with live tail and filtering"""

    # Log level color mapping
    LEVEL_COLORS = {
        'TRACE': 'dim cyan',
        'DEBUG': 'dim white',
        'INFO': 'cyan',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'bold red'
    }

    # Category color mapping
    CATEGORY_COLORS = {
        'UI': 'green',
        'STATE': 'blue',
        'EXECUTION': 'magenta',
        'DATA': 'yellow',
        'PERFORMANCE': 'cyan',
        'SYSTEM': 'white',
        'THEME': 'bright_magenta',
        'CONFIG': 'bright_blue',
        'HISTORY': 'bright_green',
        'NETWORK': 'bright_yellow'
    }

    # Log pattern: HH:MM:SS.mmm [LEVEL] func:line - [CATEGORY] Message | key=value
    LOG_PATTERN = re.compile(
        r'(?P<timestamp>\d{2}:\d{2}:\d{2}\.\d{3})\s+'
        r'\[(?P<level>\w+)\]\s+'
        r'(?P<function>\w+):(?P<line>\d+)\s+-\s+'
        r'(?:\[(?P<category>[\w\.]+)\]\s+)?'
        r'(?P<message>.*?)(?:\s+\|\s+(?P<metadata>.*))?$'
    )

    @classmethod
    def render(
        cls,
        theme=None,
        debug_log_dir: str = '.debug_logs',
        lines_per_page: int = 20,
        target: str = None
    ) -> Tuple[Panel, Dict[str, Any]]:
        """
        Render debug stream overlay

        Args:
            theme: ThemeManager instance
            debug_log_dir: Directory containing debug logs
            lines_per_page: Number of lines to show per page
            target: Target name to find specific log file

        Returns:
            Tuple of (Panel, state_dict) where state_dict contains:
                - log_lines: Parsed log entries
                - current_offset: Current scroll position
                - log_file: Path to log file
                - filter_category: Active category filter
                - filter_level: Active level filter
        """
        # Fallback theme for backward compatibility
        if theme is None:
            from ..themes import ThemeManager
            theme = ThemeManager()

        # Find latest debug log
        log_file = cls._find_latest_log(debug_log_dir, target)

        if not log_file:
            # No logs found - show friendly message
            no_logs_text = f"""[bold {theme.get_color('warning')}]Debug Stream - No Logs Available[/]

{theme.muted('Debug mode is enabled but no logs exist yet.')}

{theme.primary('To generate debug logs:')}
  • Execute a task
  • Import scan results
  • Navigate between panels
  • Perform any TUI action

{theme.muted('Logs will appear in:')} {theme.emphasis('.debug_logs/')}

{theme.muted('Press any key to close...')}"""

            return Panel(
                no_logs_text,
                title=f"[bold {theme.get_color('info')}]Debug Stream[/]",
                border_style=theme.overlay_border(),
                box=box.DOUBLE
            ), {'log_lines': [], 'current_offset': 0, 'log_file': None}

        # Read and parse log file
        log_lines = cls._parse_log_file(log_file)

        if not log_lines:
            # Log exists but empty
            empty_text = f"""[bold {theme.get_color('warning')}]Debug Stream - Log Empty[/]

{theme.muted('Log file exists but contains no entries yet.')}

{theme.primary('Log file:')} {theme.emphasis(str(log_file))}

{theme.muted('Press any key to close or wait for activity...')}"""

            return Panel(
                empty_text,
                title=f"[bold {theme.get_color('info')}]Debug Stream[/]",
                border_style=theme.overlay_border(),
                box=box.DOUBLE
            ), {'log_lines': [], 'current_offset': 0, 'log_file': log_file}

        # Render first page
        display_text = cls._render_log_page(
            log_lines,
            offset=0,
            lines_per_page=lines_per_page,
            theme=theme
        )

        # Build navigation help footer
        nav_help = cls._build_navigation_help(theme)

        panel = Panel(
            display_text + "\n\n" + nav_help,
            title=f"[bold {theme.get_color('info')}]Debug Stream - {log_file.name}[/]",
            subtitle=theme.muted(f"{len(log_lines)} entries | Press 'D' to close"),
            border_style=theme.overlay_border(),
            box=box.DOUBLE
        )

        state = {
            'log_lines': log_lines,
            'current_offset': 0,
            'log_file': log_file,
            'filter_category': None,
            'filter_level': None,
            'lines_per_page': lines_per_page
        }

        return panel, state

    @classmethod
    def _find_latest_log(cls, log_dir: str, target: Optional[str] = None) -> Optional[Path]:
        """
        Find latest debug log file

        Args:
            log_dir: Directory containing debug logs
            target: Optional target name to filter logs

        Returns:
            Path to latest log file or None
        """
        log_path = Path(log_dir)

        if not log_path.exists():
            return None

        # Find all debug log files
        if target:
            # Look for target-specific logs
            pattern = f"tui_debug_{target.replace('.', '_')}_*.log"
        else:
            pattern = "tui_debug_*.log"

        log_files = sorted(log_path.glob(pattern), key=lambda p: p.stat().st_mtime, reverse=True)

        if log_files:
            return log_files[0]

        # Fallback: try any debug log
        all_logs = sorted(log_path.glob("tui_debug_*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
        return all_logs[0] if all_logs else None

    @classmethod
    def _parse_log_file(cls, log_file: Path, max_lines: int = 1000) -> List[Dict[str, Any]]:
        """
        Parse log file into structured entries

        Args:
            log_file: Path to log file
            max_lines: Maximum lines to read (tail mode)

        Returns:
            List of parsed log entries
        """
        try:
            with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
                lines = f.readlines()

            # Only keep last max_lines if file is large
            if len(lines) > max_lines:
                lines = lines[-max_lines:]

            parsed_entries = []

            for line in lines:
                line = line.rstrip()
                if not line:
                    continue

                match = cls.LOG_PATTERN.match(line)

                if match:
                    entry = {
                        'timestamp': match.group('timestamp'),
                        'level': match.group('level'),
                        'function': match.group('function'),
                        'line': match.group('line'),
                        'category': match.group('category') or 'UNCATEGORIZED',
                        'message': match.group('message') or '',
                        'metadata': match.group('metadata') or '',
                        'raw': line
                    }
                    parsed_entries.append(entry)
                else:
                    # Line doesn't match pattern - likely continuation or special format
                    parsed_entries.append({
                        'timestamp': '??:??:??.???',
                        'level': 'INFO',
                        'function': '',
                        'line': '',
                        'category': 'RAW',
                        'message': line,
                        'metadata': '',
                        'raw': line
                    })

            return parsed_entries

        except Exception as e:
            # Error reading log file
            return [{
                'timestamp': '??:??:??.???',
                'level': 'ERROR',
                'function': 'parse',
                'line': '0',
                'category': 'SYSTEM',
                'message': f'Failed to read log file: {e}',
                'metadata': '',
                'raw': str(e)
            }]

    @classmethod
    def _render_log_page(
        cls,
        log_lines: List[Dict[str, Any]],
        offset: int,
        lines_per_page: int,
        theme,
        filter_category: Optional[str] = None,
        filter_level: Optional[str] = None,
        search_term: Optional[str] = None
    ) -> str:
        """
        Render a page of log entries with colorization

        Args:
            log_lines: Parsed log entries
            offset: Starting line number
            lines_per_page: Number of lines to display
            theme: ThemeManager instance
            filter_category: Category filter (matches prefix)
            filter_level: Level filter (exact match)
            search_term: Search term to highlight

        Returns:
            Formatted text for display
        """
        # Apply filters
        filtered_lines = log_lines

        if filter_category:
            filtered_lines = [
                entry for entry in filtered_lines
                if entry['category'].startswith(filter_category)
            ]

        if filter_level:
            filtered_lines = [
                entry for entry in filtered_lines
                if entry['level'] == filter_level
            ]

        # Calculate page
        total_lines = len(filtered_lines)
        end_offset = min(offset + lines_per_page, total_lines)

        if offset >= total_lines:
            return theme.muted("No entries to display")

        page_lines = filtered_lines[offset:end_offset]

        # Build display
        display_lines = []

        for entry in page_lines:
            line = cls._colorize_entry(entry, theme, search_term)
            display_lines.append(line)

        # Add page info
        page_num = (offset // lines_per_page) + 1
        total_pages = (total_lines + lines_per_page - 1) // lines_per_page

        page_info = theme.muted(f"Page {page_num}/{total_pages} | Lines {offset+1}-{end_offset}/{total_lines}")

        if filter_category or filter_level:
            filters = []
            if filter_category:
                filters.append(f"category={filter_category}")
            if filter_level:
                filters.append(f"level={filter_level}")
            page_info += theme.warning(f" [Filtered: {', '.join(filters)}]")

        display_text = "\n".join(display_lines)

        return f"{page_info}\n\n{display_text}"

    @classmethod
    def _colorize_entry(
        cls,
        entry: Dict[str, Any],
        theme,
        search_term: Optional[str] = None
    ) -> str:
        """
        Colorize a single log entry

        Args:
            entry: Parsed log entry
            theme: ThemeManager instance
            search_term: Optional search term to highlight

        Returns:
            Colorized text
        """
        # Get colors
        level = entry['level']
        category = entry['category']

        level_color = cls.LEVEL_COLORS.get(level, 'white')

        # Category color: check for parent category match
        category_color = 'white'
        for cat_prefix, color in cls.CATEGORY_COLORS.items():
            if category.startswith(cat_prefix):
                category_color = color
                break

        # Build colorized line
        timestamp = f"[dim]{entry['timestamp']}[/]"
        level_text = f"[{level_color}]{level:8}[/]"
        category_text = f"[{category_color}]{category}[/]"
        message = entry['message']

        # Highlight search term
        if search_term and search_term.lower() in message.lower():
            # Simple highlighting - replace with bold version
            message = re.sub(
                f"({re.escape(search_term)})",
                f"[bold yellow]\\1[/]",
                message,
                flags=re.IGNORECASE
            )

        # Format: timestamp [LEVEL] [CATEGORY] message
        line = f"{timestamp} {level_text} {category_text:20} {message}"

        # Add metadata if present
        if entry['metadata']:
            line += f" [dim]| {entry['metadata']}[/]"

        return line

    @classmethod
    def _build_navigation_help(cls, theme) -> str:
        """Build navigation help text"""
        hk = theme.get_component_color('hotkey')

        return f"""[bold {theme.get_color('primary')}]Navigation:[/]
  [{hk}]↑/k[/] Up  [{hk}]↓/j[/] Down  [{hk}]PgUp/b[/] Page Up  [{hk}]PgDn/f[/] Page Down  [{hk}]g[/] Top  [{hk}]G[/] Bottom
  [{hk}]r[/] Refresh  [{hk}]t[/] Live Tail  [{hk}]c[/] Filter Category  [{hk}]l[/] Filter Level  [{hk}]/[/] Search
  [{hk}]D[/] Close  [{hk}]?[/] Help"""

    @classmethod
    def render_help(cls, theme) -> Panel:
        """Render debug stream help panel"""
        hk = theme.get_component_color('hotkey')
        warn = theme.get_color('warning')

        help_text = f"""[bold {theme.get_color('primary')}]DEBUG STREAM HELP[/]

[bold {warn}]Navigation:[/]
  [{hk}]↑[/] or [{hk}]k[/] - Scroll up one line
  [{hk}]↓[/] or [{hk}]j[/] - Scroll down one line
  [{hk}]PgUp[/] or [{hk}]b[/] - Page up
  [{hk}]PgDn[/] or [{hk}]f[/] - Page down
  [{hk}]g[/] - Jump to top (first line)
  [{hk}]G[/] - Jump to bottom (last line)

[bold {warn}]Actions:[/]
  [{hk}]r[/] - Refresh (re-read log file)
  [{hk}]t[/] - Toggle live tail mode (auto-refresh every 500ms)
  [{hk}]/[/] - Search for pattern
  [{hk}]c[/] - Filter by category (UI, STATE, EXECUTION, etc.)
  [{hk}]l[/] - Filter by level (INFO, WARNING, ERROR, etc.)
  [{hk}]x[/] - Clear all filters

[bold {warn}]Exit:[/]
  [{hk}]D[/] - Close debug stream (toggle)
  [{hk}]Any other key[/] - Smart dismiss (close and execute command)

[bold {warn}]Color Legend:[/]
  [dim cyan]TRACE[/] | [dim white]DEBUG[/] | [cyan]INFO[/] | [yellow]WARNING[/] | [red]ERROR[/] | [bold red]CRITICAL[/]

  [green]UI[/] | [blue]STATE[/] | [magenta]EXECUTION[/] | [yellow]DATA[/] | [cyan]PERFORMANCE[/] | [white]SYSTEM[/]

{theme.muted('Debug stream only available when --debug flag is active')}"""

        return Panel(
            help_text,
            title=f"[bold {theme.get_color('info')}]Debug Stream Help[/]",
            border_style=theme.overlay_border(),
            box=box.ROUNDED
        )
