"""
Terminal colors for enhanced output formatting
"""

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