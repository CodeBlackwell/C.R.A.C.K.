"""
Color themes for terminal visualization

Simple dict-based color schemes with regex-based application
"""

import re


THEMES = {
    'oscp': {
        # Status colors
        'completed': '\033[92m',      # Green
        'pending': '\033[90m',        # Gray
        'in-progress': '\033[93m',    # Yellow
        'skipped': '\033[90m',        # Gray

        # Component colors
        'phase': '\033[94m',          # Blue
        'plugin': '\033[95m',         # Magenta
        'event': '\033[93m',          # Yellow
        'component': '\033[96m',      # Cyan
        'task': '\033[97m',           # White

        # Status icons
        'success': '\033[92m',        # Green (✓)
        'current': '\033[93m',        # Yellow (⧗)
        'inactive': '\033[90m',       # Gray (○)

        # Structural
        'header': '\033[1;36m',       # Bold Cyan
        'emphasis': '\033[1;97m',     # Bold White
        'reset': '\033[0m'
    },

    'dark': {
        'completed': '\033[32m',      # Dark Green
        'pending': '\033[37m',        # Light Gray
        'in-progress': '\033[33m',    # Orange
        'skipped': '\033[90m',        # Dark Gray
        'phase': '\033[34m',          # Dark Blue
        'plugin': '\033[35m',         # Dark Magenta
        'event': '\033[36m',          # Dark Cyan
        'component': '\033[96m',      # Cyan
        'task': '\033[97m',           # White
        'success': '\033[32m',        # Dark Green
        'current': '\033[33m',        # Orange
        'inactive': '\033[37m',       # Light Gray
        'header': '\033[1;34m',       # Bold Blue
        'emphasis': '\033[1;37m',     # Bold White
        'reset': '\033[0m'
    },

    'light': {
        'completed': '\033[32m',      # Green
        'pending': '\033[90m',        # Gray
        'in-progress': '\033[33m',    # Yellow
        'skipped': '\033[90m',        # Gray
        'phase': '\033[34m',          # Blue
        'plugin': '\033[35m',         # Magenta
        'event': '\033[36m',          # Cyan
        'component': '\033[34m',      # Blue
        'task': '\033[30m',           # Black
        'success': '\033[32m',        # Green
        'current': '\033[33m',        # Yellow
        'inactive': '\033[90m',       # Gray
        'header': '\033[1;34m',       # Bold Blue
        'emphasis': '\033[1;30m',     # Bold Black
        'reset': '\033[0m'
    },

    'mono': {k: '' for k in [
        'completed', 'pending', 'in-progress', 'skipped',
        'phase', 'plugin', 'event', 'component', 'task',
        'success', 'current', 'inactive', 'header', 'emphasis', 'reset'
    ]}
}


def colorize(text: str, theme: str = 'oscp', validate: bool = False) -> str:
    """
    Apply colors to text using markup tags

    Markup format: [color_key]text[/color_key]
    Example: [completed]Task Done[/completed]

    Args:
        text: Text with markup tags
        theme: Theme name from THEMES dict
        validate: If True, warn about malformed/unknown tags

    Returns:
        Text with ANSI color codes
    """
    colors = THEMES.get(theme, THEMES['mono'])

    # Validation mode - check for issues
    if validate:
        import sys
        # Check for unknown tags
        all_tags = re.findall(r'\[(\w+)\]', text)
        known_tags = set(colors.keys()) | {'reset'}
        unknown = set(all_tags) - known_tags
        if unknown:
            print(f"Warning: Unknown color tags: {unknown}", file=sys.stderr)

        # Check for unclosed tags
        for key in colors.keys():
            if key == 'reset':
                continue
            open_count = text.count(f'[{key}]')
            close_count = text.count(f'[/{key}]')
            if open_count != close_count:
                print(f"Warning: Mismatched tags for '{key}': {open_count} open, {close_count} close", file=sys.stderr)

    # Replace markup tags with color codes
    for key, code in colors.items():
        if key == 'reset':
            continue

        # Pattern: [key]...[/key]
        pattern = rf'\[{re.escape(key)}\](.*?)\[/{re.escape(key)}\]'
        replacement = f'{code}\\1{colors["reset"]}'
        text = re.sub(pattern, replacement, text)

    return text


def strip_colors(text: str) -> str:
    """
    Remove all ANSI color codes from text

    Args:
        text: Text with ANSI codes

    Returns:
        Plain text
    """
    ansi_escape = re.compile(r'\033\[[0-9;]+m')
    return ansi_escape.sub('', text)


def get_theme_names():
    """Get list of available theme names"""
    return list(THEMES.keys())


__all__ = ['THEMES', 'colorize', 'strip_colors', 'get_theme_names']
