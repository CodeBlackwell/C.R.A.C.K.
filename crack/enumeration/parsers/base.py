"""
Base parser class for tool output parsing

Parsers extract information from tool outputs and emit events
to trigger task generation and state updates.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, List
from pathlib import Path


class Parser(ABC):
    """Base class for result parsers"""

    @property
    @abstractmethod
    def name(self) -> str:
        """Parser name (nmap-xml, nmap-gnmap, burp-xml, etc.)"""
        pass

    @abstractmethod
    def can_parse(self, filepath: str) -> bool:
        """Determine if this parser can handle the file

        Args:
            filepath: Path to file

        Returns:
            True if this parser can parse this file
        """
        pass

    @abstractmethod
    def parse(self, filepath: str, target: str = None) -> Dict[str, Any]:
        """Parse file and return extracted information

        Args:
            filepath: Path to file to parse
            target: Optional target IP/hostname hint

        Returns:
            Dictionary with extracted information:
            {
                'target': '<ip>',
                'ports': [
                    {'port': 80, 'state': 'open', 'service': 'http', 'version': '...'},
                    ...
                ],
                'hostnames': [...],
                'os_guess': '...',
                ...
            }
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

    def __repr__(self):
        return f"<Parser name={self.name}>"
