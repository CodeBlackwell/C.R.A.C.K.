"""
Simple ANSI color system for reference CLI
Bridges Rich color names (from ThemeManager) to ANSI escape codes
"""

class Colors:
    """ANSI escape codes for terminal colors"""

    # Basic colors
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

    # Foreground colors
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'

    # Bright foreground colors
    BRIGHT_BLACK = '\033[90m'
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'

    # Rich → ANSI mapping
    _RICH_MAP = {
        'black': BLACK, 'red': RED, 'green': GREEN, 'yellow': YELLOW,
        'blue': BLUE, 'magenta': MAGENTA, 'cyan': CYAN, 'white': WHITE,
        'bright_black': BRIGHT_BLACK, 'bright_red': BRIGHT_RED,
        'bright_green': BRIGHT_GREEN, 'bright_yellow': BRIGHT_YELLOW,
        'bright_blue': BRIGHT_BLUE, 'bright_magenta': BRIGHT_MAGENTA,
        'bright_cyan': BRIGHT_CYAN, 'bright_white': BRIGHT_WHITE,
        'dim': DIM, 'bold': BOLD
    }

    @classmethod
    def from_rich(cls, rich_color: str) -> str:
        """Convert Rich color name to ANSI (e.g., 'bold cyan' → '\033[1m\033[36m')"""
        return ''.join(cls._RICH_MAP.get(part, '') for part in rich_color.split())

    @classmethod
    def strip(cls, text: str) -> str:
        """Remove all ANSI color codes from text"""
        import re
        ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
        return ansi_escape.sub('', text)


class ReferenceTheme:
    """Theme for reference system using shared ThemeManager"""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        try:
            from crack.track.interactive.themes import ThemeManager
            self._theme_mgr = ThemeManager()
        except ImportError:
            self._theme_mgr = None

    def _get_ansi(self, role: str) -> str:
        """Get ANSI code for semantic role from ThemeManager"""
        if not self.enabled or not self._theme_mgr:
            return ''
        rich_color = self._theme_mgr.get_color(role, fallback='white')
        return Colors.from_rich(rich_color)

    def _color(self, text: str, ansi: str) -> str:
        """Wrap text in ANSI color"""
        return f"{ansi}{text}{Colors.RESET}" if ansi else text

    # Semantic colors
    def primary(self, text: str) -> str:
        return self._color(text, self._get_ansi('primary'))

    def secondary(self, text: str) -> str:
        return self._color(text, self._get_ansi('secondary'))

    def success(self, text: str) -> str:
        return self._color(text, self._get_ansi('success'))

    def warning(self, text: str) -> str:
        return self._color(text, self._get_ansi('warning'))

    def error(self, text: str) -> str:
        return self._color(text, self._get_ansi('danger'))

    def info(self, text: str) -> str:
        return self._color(text, self._get_ansi('info'))

    def muted(self, text: str) -> str:
        return self._color(text, self._get_ansi('muted'))

    def bold(self, text: str) -> str:
        return self._color(text, Colors.BOLD) if self.enabled else text

    def bold_white(self, text: str) -> str:
        return self._color(text, self._get_ansi('emphasis'))

    # Component helpers
    def command_name(self, text: str) -> str:
        return self.bold_white(text)

    def placeholder(self, text: str) -> str:
        return self.primary(text)

    def value(self, text: str) -> str:
        return self.primary(text)

    def prompt(self, text: str) -> str:
        return self.warning(text)

    def hint(self, text: str) -> str:
        return self.muted(text)

    def match_metadata(self, text: str) -> str:
        """Color for match reason metadata (e.g., '→ matched in: tags')"""
        return self._color(text, Colors.BRIGHT_BLUE)  # Subtle blue for metadata


# Global theme instance
_theme = ReferenceTheme()

def get_theme() -> ReferenceTheme:
    """Get current theme instance"""
    return _theme

def disable_colors():
    """Disable colors globally"""
    global _theme
    _theme = ReferenceTheme(enabled=False)
