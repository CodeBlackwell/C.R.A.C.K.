"""
Base parser class for PRISM tool output parsing

Parsers extract credentials, tickets, and other security data
from tool outputs and return structured summaries.
"""

from abc import ABC, abstractmethod
from typing import Optional
from pathlib import Path

from ..models import ParsedSummary


class PrismParser(ABC):
    """Base class for PRISM parsers"""

    @property
    @abstractmethod
    def name(self) -> str:
        """Parser name identifier (e.g., 'mimikatz', 'secretsdump')"""
        pass

    @property
    def description(self) -> str:
        """Human-readable parser description"""
        return f"{self.name} output parser"

    @abstractmethod
    def can_parse(self, filepath: str) -> bool:
        """Determine if this parser can handle the file

        Args:
            filepath: Path to file to check

        Returns:
            True if this parser can parse this file
        """
        pass

    @abstractmethod
    def parse(self, filepath: str, hostname: Optional[str] = None) -> ParsedSummary:
        """Parse file and return structured summary

        Args:
            filepath: Path to file to parse
            hostname: Optional source hostname hint

        Returns:
            ParsedSummary with extracted credentials and tickets
        """
        pass

    def validate_file(self, filepath: str) -> bool:
        """Validate file exists and is readable

        Args:
            filepath: Path to file

        Returns:
            True if file is valid
        """
        path = Path(filepath)
        return path.exists() and path.is_file() and path.stat().st_size > 0

    def read_file(self, filepath: str) -> str:
        """Read file contents with error handling

        Args:
            filepath: Path to file

        Returns:
            File contents as string
        """
        path = Path(filepath)
        # Try UTF-8 first, fall back to latin-1 for Windows output
        try:
            return path.read_text(encoding='utf-8')
        except UnicodeDecodeError:
            return path.read_text(encoding='latin-1')

    def __repr__(self) -> str:
        return f"<PrismParser name={self.name}>"
