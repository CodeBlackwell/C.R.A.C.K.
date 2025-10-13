"""
Base CLI handler with shared utilities
"""

from typing import List, Dict, Any
from crack.reference.core.colors import ReferenceTheme


class BaseCLIHandler:
    """Base class for CLI command handlers providing shared functionality"""

    def __init__(self, theme=None):
        """Initialize with optional theme

        Args:
            theme: ReferenceTheme instance, creates new if None
        """
        self.theme = theme or ReferenceTheme()

    def print_banner(self, title: str, width: int = 70):
        """Print section banner

        Args:
            title: Banner title text
            width: Total width of banner
        """
        print(f"\n{self.theme.primary('═' * width)}")
        print(f"{self.theme.command_name(title)}")
        print(f"{self.theme.primary('═' * width)}\n")

    def format_error(self, message: str) -> str:
        """Format error message with color

        Args:
            message: Error message text

        Returns:
            Colored error string
        """
        return f"{self.theme.error('✗ Error:')} {message}"

    def format_success(self, message: str) -> str:
        """Format success message with color

        Args:
            message: Success message text

        Returns:
            Colored success string
        """
        return f"{self.theme.success('✓')} {message}"

    def format_warning(self, message: str) -> str:
        """Format warning message with color

        Args:
            message: Warning message text

        Returns:
            Colored warning string
        """
        return f"{self.theme.warning('⚠')} {message}"

    def format_table_row(self, columns: List[str], widths: List[int]) -> str:
        """Format a table row with column alignment

        Args:
            columns: List of column values
            widths: List of column widths

        Returns:
            Formatted row string
        """
        parts = []
        for col, width in zip(columns, widths):
            parts.append(str(col).ljust(width))
        return "  ".join(parts)

    def print_separator(self, char: str = '─', width: int = 70):
        """Print a horizontal separator

        Args:
            char: Character to use for separator
            width: Width of separator
        """
        print(self.theme.muted(char * width))
