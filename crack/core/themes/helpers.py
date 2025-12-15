"""
Theme Helper Utilities - Convenient functions for Rich text styling

Provides higher-level abstractions for common theming patterns:
- Panel title formatting
- Status badges
- Priority indicators
- Menu formatting
"""

from typing import Optional
from rich.text import Text


def format_panel_title(theme, title: str, subtitle: Optional[str] = None) -> str:
    """
    Format panel title with theme colors

    Args:
        theme: ThemeManager instance
        title: Main title text
        subtitle: Optional subtitle text

    Returns:
        Formatted title string with Rich markup
    """
    formatted = f"[bold {theme.get_color('primary')}]{title}[/]"
    if subtitle:
        formatted += f" [{theme.get_color('muted')}]{subtitle}[/]"
    return formatted


def format_menu_number(theme, number: int) -> str:
    """
    Format menu number with theme colors

    Args:
        theme: ThemeManager instance
        number: Menu option number

    Returns:
        Formatted string like "[bold bright_white]1.[/]"
    """
    color = theme.get_component_color('menu_number')
    return f"[{color}]{number}.[/]"


def format_hotkey(theme, key: str) -> str:
    """
    Format hotkey with theme colors

    Args:
        theme: ThemeManager instance
        key: Hotkey character(s)

    Returns:
        Formatted hotkey like "[cyan]h[/]"
    """
    color = theme.get_component_color('hotkey')
    return f"[{color}]{key}[/]"


def format_command(theme, command: str) -> str:
    """
    Format command preview with theme colors

    Args:
        theme: ThemeManager instance
        command: Command string

    Returns:
        Formatted command with muted color
    """
    color = theme.get_component_color('command')
    return f"[{color}]{command}[/]"


def format_task_status(theme, status: str) -> str:
    """
    Format task status badge with appropriate color

    Args:
        theme: ThemeManager instance
        status: Task status ('pending', 'in-progress', 'completed', 'failed', 'skipped')

    Returns:
        Colored status string
    """
    color = theme.task_state_color(status)
    status_display = status.replace('-', ' ').replace('_', ' ').title()
    return f"[{color}]{status_display}[/]"


def format_priority_badge(theme, priority: str) -> str:
    """
    Format priority badge with icon and color

    Args:
        theme: ThemeManager instance
        priority: Priority level ('OSCP:HIGH', 'OSCP:MEDIUM', 'QUICK_WIN', etc.)

    Returns:
        Formatted badge string with icon
    """
    priority_lower = priority.lower()

    if 'high' in priority_lower:
        color = theme.get_component_color('priority_high')
        return f"[{color}]🎯 OSCP HIGH[/]"
    elif 'medium' in priority_lower or 'med' in priority_lower:
        color = theme.get_component_color('priority_medium')
        return f"[{color}]🎯 OSCP MED[/]"
    elif 'quick_win' in priority_lower:
        color = theme.get_component_color('quick_win')
        return f"[{color}]⚡ QUICK WIN[/]"
    else:
        color = theme.get_component_color('priority_low')
        return f"[{color}]Standard Priority[/]"


def format_port_state(theme, port: int, state: str, service: Optional[str] = None,
                      version: Optional[str] = None) -> str:
    """
    Format port information with state-based coloring

    Args:
        theme: ThemeManager instance
        port: Port number
        state: Port state ('open', 'filtered', 'closed')
        service: Optional service name
        version: Optional version string

    Returns:
        Formatted port info string
    """
    port_line = f"{port}/tcp"

    if service and service != 'unknown':
        port_line += f" - {service}"
    if version:
        port_line += f" ({version})"

    color = theme.port_state_color(state)
    return f"[{color}]{port_line}[/]"


def format_finding_icon(finding_type: str) -> str:
    """
    Get icon for finding type

    Args:
        finding_type: Type of finding

    Returns:
        Emoji icon
    """
    icons = {
        'vulnerability': '🔓',
        'directory': '📁',
        'file': '📄',
        'credential': '🔑',
        'user': '👤',
        'note': '📝',
        'general': '•'
    }
    return icons.get(finding_type, '•')


def format_finding_type(theme, finding_type: str, count: Optional[int] = None) -> str:
    """
    Format finding type with icon and color

    Args:
        theme: ThemeManager instance
        finding_type: Type of finding
        count: Optional count of findings of this type

    Returns:
        Formatted finding type string
    """
    icon = format_finding_icon(finding_type)
    color = theme.finding_type_color(finding_type)
    display = finding_type.replace('_', ' ').title()

    if count is not None:
        return f"[{color}]{icon} {display}: {count}[/]"
    else:
        return f"[{color}]{icon} {display}[/]"


def format_progress_bar(theme, completed: int, total: int, width: int = 20) -> str:
    """
    Create a simple text-based progress bar

    Args:
        theme: ThemeManager instance
        completed: Number of completed items
        total: Total number of items
        width: Width of progress bar in characters

    Returns:
        Formatted progress bar string
    """
    if total == 0:
        pct = 0
    else:
        pct = completed / total

    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)

    color = theme.get_component_color('progress_bar')
    pct_display = int(pct * 100)

    return f"[{color}]{bar}[/] {pct_display}%"


def format_timestamp(theme, timestamp_str: str) -> str:
    """
    Format timestamp with muted color

    Args:
        theme: ThemeManager instance
        timestamp_str: Timestamp string

    Returns:
        Formatted timestamp
    """
    color = theme.get_component_color('timestamp')
    return f"[{color}]{timestamp_str}[/]"


def format_subtitle(theme, subtitle: str) -> str:
    """
    Format subtitle with muted color

    Args:
        theme: ThemeManager instance
        subtitle: Subtitle text

    Returns:
        Formatted subtitle with dim style
    """
    return theme.muted(subtitle)


def format_section_header(theme, header: str) -> str:
    """
    Format section header with emphasis

    Args:
        theme: ThemeManager instance
        header: Header text

    Returns:
        Formatted header with emphasis
    """
    return theme.emphasis(header)


def create_themed_text(theme, text: str, style: str = 'primary') -> Text:
    """
    Create Rich Text object with theme styling

    Args:
        theme: ThemeManager instance
        text: Text content
        style: Style name ('primary', 'success', 'warning', etc.)

    Returns:
        Rich Text object
    """
    if style in ['primary', 'secondary', 'success', 'warning', 'danger', 'info', 'muted', 'emphasis']:
        color = theme.get_color(style)
    else:
        color = theme.get_component_color(style, 'white')

    return Text(text, style=color)


__all__ = [
    'format_panel_title',
    'format_menu_number',
    'format_hotkey',
    'format_command',
    'format_task_status',
    'format_priority_badge',
    'format_port_state',
    'format_finding_icon',
    'format_finding_type',
    'format_progress_bar',
    'format_timestamp',
    'format_subtitle',
    'format_section_header',
    'create_themed_text',
]
