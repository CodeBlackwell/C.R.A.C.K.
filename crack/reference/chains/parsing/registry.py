"""
Parser registry with automatic discovery via decorators.

Provides centralized management of all parsers with zero-configuration registration.
"""

from typing import Dict, Optional, List, Any
from .base import BaseOutputParser


class ParserRegistry:
    """
    Central registry for all output parsers.

    Parsers self-register via the @ParserRegistry.register decorator.
    The registry automatically discovers parsers at import time.
    """

    _parsers: Dict[str, BaseOutputParser] = {}
    _parser_order: List[str] = []  # Maintain registration order

    @classmethod
    def register(cls, parser_class):
        """
        Decorator to register a parser class.

        Usage:
            @ParserRegistry.register
            class MyParser(BaseOutputParser):
                ...

        Args:
            parser_class: Parser class (not instance)

        Returns:
            The parser class (allows chaining decorators)

        Note:
            Instantiates the parser immediately and stores it.
            Registration order matters - first match wins in get_parser().
        """
        try:
            parser = parser_class()
            parser_name = parser.name

            if parser_name in cls._parsers:
                # Allow re-registration during testing
                cls._parser_order.remove(parser_name)

            cls._parsers[parser_name] = parser
            cls._parser_order.append(parser_name)

        except Exception as e:
            # Don't crash on bad parser - just log warning
            import sys

            print(
                f"Warning: Failed to register parser {parser_class.__name__}: {e}",
                file=sys.stderr,
            )

        return parser_class

    @classmethod
    def get_parser(
        cls, step: Dict[str, Any], command: str
    ) -> Optional[BaseOutputParser]:
        """
        Find the first parser that can handle this command.

        Args:
            step: Chain step dictionary
            command: Filled command string

        Returns:
            Parser instance or None if no parser matches

        Note:
            Parsers are checked in registration order.
            More specific parsers should be registered before generic ones.
        """
        for parser_name in cls._parser_order:
            parser = cls._parsers[parser_name]
            try:
                if parser.can_parse(step, command):
                    return parser
            except Exception:
                # Parser's can_parse() raised error - skip it
                continue

        return None

    @classmethod
    def get_parser_by_name(cls, name: str) -> Optional[BaseOutputParser]:
        """
        Get parser by explicit name.

        Args:
            name: Parser identifier

        Returns:
            Parser instance or None if not found

        Note:
            Useful for testing or when chain JSON specifies parser explicitly.
        """
        return cls._parsers.get(name)

    @classmethod
    def list_parsers(cls) -> List[str]:
        """
        Get all registered parser names.

        Returns:
            List of parser names in registration order
        """
        return cls._parser_order.copy()

    @classmethod
    def clear(cls):
        """
        Clear all registered parsers.

        Note:
            Primarily for testing. Use with caution in production code.
        """
        cls._parsers.clear()
        cls._parser_order.clear()
