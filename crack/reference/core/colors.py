"""
Simple ANSI color system for reference CLI
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

    @classmethod
    def strip(cls, text: str) -> str:
        """Remove all ANSI color codes from text"""
        import re
        ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
        return ansi_escape.sub('', text)


class ReferenceTheme:
    """Theme for reference system - OSCP cyan-heavy"""

    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def _color(self, text: str, color: str) -> str:
        """Wrap text in color if enabled"""
        if not self.enabled:
            return text
        return f"{color}{text}{Colors.RESET}"

    # Semantic colors
    def primary(self, text: str) -> str:
        """Primary color (cyan) - command names, values"""
        return self._color(text, Colors.CYAN)

    def secondary(self, text: str) -> str:
        """Secondary color (bright cyan) - highlights"""
        return self._color(text, Colors.BRIGHT_CYAN)

    def success(self, text: str) -> str:
        """Success color (green)"""
        return self._color(text, Colors.GREEN)

    def warning(self, text: str) -> str:
        """Warning color (yellow)"""
        return self._color(text, Colors.YELLOW)

    def error(self, text: str) -> str:
        """Error color (red)"""
        return self._color(text, Colors.RED)

    def info(self, text: str) -> str:
        """Info color (blue)"""
        return self._color(text, Colors.BLUE)

    def muted(self, text: str) -> str:
        """Muted/dim color"""
        return self._color(text, Colors.DIM)

    def bold(self, text: str) -> str:
        """Bold text"""
        if not self.enabled:
            return text
        return f"{Colors.BOLD}{text}{Colors.RESET}"

    def bold_white(self, text: str) -> str:
        """Bold bright white"""
        if not self.enabled:
            return text
        return f"{Colors.BOLD}{Colors.BRIGHT_WHITE}{text}{Colors.RESET}"

    # Component-specific helpers
    def command_name(self, text: str) -> str:
        """Command name styling"""
        return self.bold_white(text)

    def placeholder(self, text: str) -> str:
        """Placeholder styling"""
        return self.primary(text)

    def value(self, text: str) -> str:
        """User value styling"""
        return self.primary(text)

    def prompt(self, text: str) -> str:
        """Prompt text styling"""
        return self.warning(text)

    def hint(self, text: str) -> str:
        """Hint text styling"""
        return self.muted(text)


# Global theme instance
_theme = ReferenceTheme()

def get_theme() -> ReferenceTheme:
    """Get current theme instance"""
    return _theme

def disable_colors():
    """Disable colors globally"""
    global _theme
    _theme = ReferenceTheme(enabled=False)
