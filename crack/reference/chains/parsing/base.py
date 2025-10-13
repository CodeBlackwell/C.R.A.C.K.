"""
Base classes for output parsing in attack chains.

All parsers inherit from BaseOutputParser and implement the required methods.
ParsingResult is the standardized return type for all parsers.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional


@dataclass
class ParsingResult:
    """Standardized output from all parsers"""

    # Core findings extracted from output
    findings: Dict[str, Any] = field(default_factory=dict)

    # Variables that can be used in subsequent steps
    variables: Dict[str, str] = field(default_factory=dict)

    # Variables that need user selection (value is list of options)
    selection_required: Dict[str, List[str]] = field(default_factory=dict)

    # Parser metadata
    parser_name: str = ""
    success: bool = True
    warnings: List[str] = field(default_factory=list)

    def has_selections(self) -> bool:
        """Check if user selection is required"""
        return bool(self.selection_required)

    def get_all_variables(self) -> Dict[str, str]:
        """Get all resolved variables (excludes selections)"""
        return self.variables.copy()


class BaseOutputParser(ABC):
    """
    Abstract base class for all chain output parsers.

    Parsers are automatically discovered and registered via the @ParserRegistry.register
    decorator. Each parser defines what commands it can handle and how to extract
    structured data from the output.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """
        Unique identifier for this parser.

        Used for logging, debugging, and explicit parser selection in chain JSON.
        Should be lowercase with hyphens (e.g., 'suid', 'web-enum', 'sqli').
        """
        pass

    @abstractmethod
    def can_parse(self, step: Dict[str, Any], command: str) -> bool:
        """
        Determine if this parser can handle the given command.

        Args:
            step: Chain step dictionary (contains metadata)
            command: Filled command string that was executed

        Returns:
            True if this parser should handle this output

        Note:
            Multiple parsers can return True. The registry will use the first match.
            More specific parsers should be registered before generic ones.
        """
        pass

    @abstractmethod
    def parse(self, output: str, step: Dict[str, Any], command: str) -> ParsingResult:
        """
        Parse command output and extract structured findings.

        Args:
            output: Raw command output (stdout)
            step: Chain step dictionary (for context)
            command: Filled command string (for context)

        Returns:
            ParsingResult with findings, variables, and selection requirements

        Note:
            - Store raw data in findings dict (e.g., {'binaries': [...]})
            - Extract single-value variables to variables dict
            - Put multi-option variables in selection_required dict
            - Set success=False if parsing fails or output indicates failure
        """
        pass

    def _extract_lines(self, output: str) -> List[str]:
        """
        Helper to extract non-empty lines from output.

        Args:
            output: Raw output string

        Returns:
            List of non-empty, stripped lines
        """
        return [line.strip() for line in output.split('\n') if line.strip()]

    def _is_error_output(self, output: str) -> bool:
        """
        Helper to detect common error patterns.

        Args:
            output: Raw output string

        Returns:
            True if output contains error indicators
        """
        error_patterns = [
            'command not found',
            'permission denied',
            'no such file',
            'error:',
            'failed',
            'unable to',
            'could not',
        ]

        output_lower = output.lower()
        return any(pattern in output_lower for pattern in error_patterns)
