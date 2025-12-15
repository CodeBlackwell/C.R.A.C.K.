"""
ANSI Color System for CRACK - Unified color handling

This module provides:
1. Colors class: ANSI escape codes for terminal output
2. ReferenceTheme class: Semantic theme-aware coloring (converts Rich → ANSI)

Example:
    from crack.themes import Colors, ReferenceTheme

    # Direct ANSI codes
    print(f"{Colors.BOLD}{Colors.RED}Error{Colors.END}")

    # Theme-aware coloring
    theme = ReferenceTheme()
    print(theme.primary("Primary text"))
    print(theme.banner_title("CRACK"))
"""

import re


class Colors:
    """ANSI color codes for terminal output"""

    # Standard colors
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    END = '\033[0m'
    RESET = '\033[0m'  # Alias for END
    DIM = '\033[2m'

    # Bright variants for better visibility
    BRIGHT_BLACK = '\033[90m'    # Gray
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'

    # Common combinations for readability
    BOLD_GREEN = '\033[1m\033[92m'
    BOLD_YELLOW = '\033[1m\033[93m'
    BOLD_RED = '\033[1m\033[91m'
    BOLD_CYAN = '\033[1m\033[96m'
    BOLD_WHITE = '\033[1m\033[97m'

    # Basic colors (for backward compatibility)
    BLACK = '\033[30m'
    MAGENTA = '\033[35m'
    WHITE = '\033[37m'

    # Rich → ANSI mapping for theme system
    _RICH_MAP = {
        'black': '\033[30m', 'red': '\033[31m', 'green': '\033[32m', 'yellow': '\033[33m',
        'blue': '\033[34m', 'magenta': '\033[35m', 'cyan': '\033[36m', 'white': '\033[37m',
        'bright_black': '\033[90m', 'bright_red': '\033[91m',
        'bright_green': '\033[92m', 'bright_yellow': '\033[93m',
        'bright_blue': '\033[94m', 'bright_magenta': '\033[95m',
        'bright_cyan': '\033[96m', 'bright_white': '\033[97m',
        'dim': '\033[2m', 'bold': '\033[1m'
    }

    @classmethod
    def hex_to_rgb(cls, hex_color: str) -> tuple:
        """
        Convert hex color to RGB tuple

        Args:
            hex_color: Hex color string (e.g., '#689d6a' or '689d6a')

        Returns:
            RGB tuple (r, g, b) with values 0-255

        Example:
            >>> Colors.hex_to_rgb('#689d6a')
            (104, 157, 106)
        """
        hex_color = hex_color.lstrip('#')
        return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))

    @classmethod
    def rgb_to_ansi(cls, r: int, g: int, b: int, foreground: bool = True) -> str:
        """
        Convert RGB values to ANSI true color escape code

        Args:
            r: Red value (0-255)
            g: Green value (0-255)
            b: Blue value (0-255)
            foreground: If True, sets foreground color; if False, sets background

        Returns:
            ANSI escape code for 24-bit true color

        Example:
            >>> Colors.rgb_to_ansi(104, 157, 106)
            '\\033[38;2;104;157;106m'
        """
        code = 38 if foreground else 48  # 38=foreground, 48=background
        return f'\033[{code};2;{r};{g};{b}m'

    @classmethod
    def from_rich(cls, rich_color: str) -> str:
        """
        Convert Rich color name OR hex color to ANSI escape code

        Args:
            rich_color: Rich color name (e.g., 'cyan', 'bold cyan') OR hex color (e.g., '#689d6a')

        Returns:
            ANSI escape code string (16-color or 24-bit RGB)

        Example:
            >>> Colors.from_rich('bold cyan')
            '\\033[1m\\033[36m'
            >>> Colors.from_rich('#689d6a')
            '\\033[38;2;104;157;106m'
            >>> Colors.from_rich('bold #689d6a')
            '\\033[1m\\033[38;2;104;157;106m'
        """
        # Handle modifiers and hex colors
        parts = rich_color.split()
        ansi_parts = []

        for part in parts:
            # Check if it's a hex color
            if part.startswith('#') or (len(part) == 6 and all(c in '0123456789abcdefABCDEF' for c in part)):
                r, g, b = cls.hex_to_rgb(part)
                ansi_parts.append(cls.rgb_to_ansi(r, g, b))
            else:
                # Regular color name or modifier
                ansi_parts.append(cls._RICH_MAP.get(part, ''))

        return ''.join(ansi_parts)

    @classmethod
    def strip(cls, text: str) -> str:
        """
        Remove all ANSI color codes from text

        Args:
            text: Text potentially containing ANSI codes

        Returns:
            Clean text without ANSI codes

        Example:
            >>> Colors.strip('\\033[91mRed text\\033[0m')
            'Red text'
        """
        ansi_escape = re.compile(r'\x1b\[[0-9;]*m')
        return ansi_escape.sub('', text)

    @classmethod
    def disable(cls):
        """Disable colors (useful for non-terminal output)"""
        cls.HEADER = ''
        cls.BLUE = ''
        cls.CYAN = ''
        cls.GREEN = ''
        cls.YELLOW = ''
        cls.RED = ''
        cls.BOLD = ''
        cls.END = ''
        cls.RESET = ''
        cls.DIM = ''
        # Disable bright variants
        cls.BRIGHT_BLACK = ''
        cls.BRIGHT_RED = ''
        cls.BRIGHT_GREEN = ''
        cls.BRIGHT_YELLOW = ''
        cls.BRIGHT_BLUE = ''
        cls.BRIGHT_MAGENTA = ''
        cls.BRIGHT_CYAN = ''
        cls.BRIGHT_WHITE = ''
        # Disable combinations
        cls.BOLD_GREEN = ''
        cls.BOLD_YELLOW = ''
        cls.BOLD_RED = ''
        cls.BOLD_CYAN = ''
        cls.BOLD_WHITE = ''
        # Disable basic colors
        cls.BLACK = ''
        cls.MAGENTA = ''
        cls.WHITE = ''

    @classmethod
    def enable(cls):
        """Re-enable colors"""
        cls.HEADER = '\033[95m'
        cls.BLUE = '\033[94m'
        cls.CYAN = '\033[96m'
        cls.GREEN = '\033[92m'
        cls.YELLOW = '\033[93m'
        cls.RED = '\033[91m'
        cls.BOLD = '\033[1m'
        cls.END = '\033[0m'
        cls.RESET = '\033[0m'
        cls.DIM = '\033[2m'
        # Re-enable bright variants
        cls.BRIGHT_BLACK = '\033[90m'
        cls.BRIGHT_RED = '\033[91m'
        cls.BRIGHT_GREEN = '\033[92m'
        cls.BRIGHT_YELLOW = '\033[93m'
        cls.BRIGHT_BLUE = '\033[94m'
        cls.BRIGHT_MAGENTA = '\033[95m'
        cls.BRIGHT_CYAN = '\033[96m'
        cls.BRIGHT_WHITE = '\033[97m'
        # Re-enable combinations
        cls.BOLD_GREEN = '\033[1m\033[92m'
        cls.BOLD_YELLOW = '\033[1m\033[93m'
        cls.BOLD_RED = '\033[1m\033[91m'
        cls.BOLD_CYAN = '\033[1m\033[96m'
        cls.BOLD_WHITE = '\033[1m\033[97m'
        # Re-enable basic colors
        cls.BLACK = '\033[30m'
        cls.MAGENTA = '\033[35m'
        cls.WHITE = '\033[37m'


class ReferenceTheme:
    """
    Theme for non-Rich contexts (CLI, banner, simple output)

    Uses ThemeManager for semantic color roles, converts to ANSI escape codes.
    Provides semantic methods for consistent coloring across CRACK tools.

    Example:
        from crack.themes import ReferenceTheme

        theme = ReferenceTheme()
        print(theme.primary("Important text"))  # Cyan (oscp theme)
        print(theme.error("Error message"))      # Red
        print(theme.banner_title("CRACK"))        # Bold Red
    """

    def __init__(self, enabled: bool = True):
        """
        Initialize ReferenceTheme

        Args:
            enabled: If False, returns uncolored text
        """
        self.enabled = enabled
        try:
            from .manager import ThemeManager
            self._theme_mgr = ThemeManager()
        except ImportError:
            self._theme_mgr = None

    def _get_ansi(self, role: str) -> str:
        """
        Get ANSI code for semantic role from ThemeManager

        Args:
            role: Semantic color role (e.g., 'primary', 'success', 'danger')

        Returns:
            ANSI escape code
        """
        if not self.enabled or not self._theme_mgr:
            return ''
        rich_color = self._theme_mgr.get_color(role, fallback='white')
        return Colors.from_rich(rich_color)

    def _color(self, text: str, ansi: str) -> str:
        """
        Wrap text in ANSI color

        Args:
            text: Text to color
            ansi: ANSI escape code

        Returns:
            Colored text with reset code
        """
        return f"{ansi}{text}{Colors.RESET}" if ansi else text

    # Semantic colors (match theme roles)

    def primary(self, text: str) -> str:
        """Format text in primary theme color (cyan in OSCP theme)"""
        return self._color(text, self._get_ansi('primary'))

    def secondary(self, text: str) -> str:
        """Format text in secondary theme color (blue in OSCP theme)"""
        return self._color(text, self._get_ansi('secondary'))

    def success(self, text: str) -> str:
        """Format text in success theme color (green)"""
        return self._color(text, self._get_ansi('success'))

    def warning(self, text: str) -> str:
        """Format text in warning theme color (yellow)"""
        return self._color(text, self._get_ansi('warning'))

    def error(self, text: str) -> str:
        """Format text in error theme color (red)"""
        return self._color(text, self._get_ansi('danger'))

    def info(self, text: str) -> str:
        """Format text in info theme color (bright_blue)"""
        return self._color(text, self._get_ansi('info'))

    def muted(self, text: str) -> str:
        """Format text in muted theme color (dim gray)"""
        return self._color(text, self._get_ansi('muted'))

    def bold(self, text: str) -> str:
        """Format text in bold"""
        return self._color(text, Colors.BOLD) if self.enabled else text

    def bold_white(self, text: str) -> str:
        """Format text in bold white (emphasis)"""
        return self._color(text, self._get_ansi('emphasis'))

    # Component helpers

    def command_name(self, text: str) -> str:
        """Format command name (bold white)"""
        return self.bold_white(text)

    def placeholder(self, text: str) -> str:
        """Format placeholder (primary color)"""
        return self.primary(text)

    def value(self, text: str) -> str:
        """Format value (primary color)"""
        return self.primary(text)

    def prompt(self, text: str) -> str:
        """Format prompt (warning color)"""
        return self.warning(text)

    def hint(self, text: str) -> str:
        """Format hint text (muted)"""
        return self.muted(text)

    def match_metadata(self, text: str) -> str:
        """Color for match reason metadata (e.g., '→ matched in: tags')"""
        return self._color(text, self._get_ansi('info'))  # Use theme info color

    # Banner-specific methods

    def banner_title(self, text: str) -> str:
        """
        Format banner title (main ASCII art)

        Uses danger color (red) + bold for maximum visibility

        Example:
            print(theme.banner_title(ascii_art))
        """
        # Danger color (red) + bold
        ansi = self._get_ansi('danger')
        if ansi and self.enabled:
            return f"{Colors.BOLD}{ansi}{text}{Colors.RESET}"
        return text

    def banner_subtitle(self, text: str) -> str:
        """
        Format banner subtitle line

        Uses primary color (cyan in OSCP theme)

        Example:
            print(theme.banner_subtitle("  (C)omprehensive..."))
        """
        return self.primary(text)

    def banner_tagline(self, text: str) -> str:
        """
        Format banner tagline

        Uses warning color (yellow in OSCP theme)

        Example:
            print(theme.banner_tagline("  Professional OSCP..."))
        """
        return self.warning(text)

    # Notes formatting methods (for cheatsheets, command descriptions)

    def _get_component_ansi(self, component: str) -> str:
        """
        Get ANSI code for component color from ThemeManager

        Args:
            component: Component name (e.g., 'notes_step', 'notes_section')

        Returns:
            ANSI escape code
        """
        if not self.enabled or not self._theme_mgr:
            return ''
        rich_color = self._theme_mgr.get_component_color(component, fallback='white')
        return Colors.from_rich(rich_color)

    def notes_step(self, text: str) -> str:
        """
        Format text for step markers

        Used for: Step 1:, (1), etc.

        Example:
            print(theme.notes_step("Step 1:") + " Run nmap scan")
        """
        return self._color(text, self._get_component_ansi('notes_step'))

    def notes_section(self, text: str) -> str:
        """
        Format text for section headers

        Used for: OSCP METHODOLOGY:, ATTACK VECTOR:, etc.

        Example:
            print(theme.notes_section("OSCP METHODOLOGY:"))
        """
        return self._color(text, self._get_component_ansi('notes_section'))

    def notes_success(self, text: str) -> str:
        """
        Format text for success indicators

        Used for: SUCCESS:, EXPECTED OUTPUT:, etc.

        Example:
            print(theme.notes_success("✓ Command successful"))
        """
        return self._color(text, self._get_component_ansi('notes_success'))

    def notes_failure(self, text: str) -> str:
        """
        Format text for failure/error indicators

        Used for: FAILURE:, ERROR:, etc.

        Example:
            print(theme.notes_failure("✗ Connection failed"))
        """
        return self._color(text, self._get_component_ansi('notes_failure'))

    def notes_code(self, text: str) -> str:
        """
        Format text for inline code/commands

        Used for: Inline code snippets in notes

        Example:
            print("Run " + theme.notes_code("nmap -sV") + " to scan")
        """
        return self._color(text, self._get_component_ansi('notes_code'))

    def notes_warning(self, text: str) -> str:
        """
        Format text for warning markers

        Used for: WARNING:, CRITICAL:, PITFALL:, etc.

        Example:
            print(theme.notes_warning("WARNING:") + " This may trigger IDS")
        """
        return self._color(text, self._get_component_ansi('notes_warning'))

    def notes_tip(self, text: str) -> str:
        """
        Format text for tip markers

        Used for: TIP:, EXAM TIP:, etc.

        Example:
            print(theme.notes_tip("EXAM TIP:") + " Always check version numbers")
        """
        return self._color(text, self._get_component_ansi('notes_tip'))


# Global theme instance
_theme = ReferenceTheme()


def get_theme() -> ReferenceTheme:
    """Get current theme instance"""
    return _theme


def disable_colors():
    """Disable colors globally"""
    global _theme
    _theme = ReferenceTheme(enabled=False)


__all__ = ['Colors', 'ReferenceTheme', 'get_theme', 'disable_colors']
