"""
Parser registry with auto-detection

Parsers register themselves and are auto-selected based on file content.
"""

from typing import Dict, List, Optional
import logging

from .base import PrismParser

logger = logging.getLogger(__name__)


class PrismParserRegistry:
    """Central registry for PRISM file parsers"""

    _parsers: Dict[str, PrismParser] = {}
    _initialized: bool = False

    @classmethod
    def register(cls, parser_class):
        """Decorator to register a parser

        Usage:
            @PrismParserRegistry.register
            class MimikatzParser(PrismParser):
                ...

        Args:
            parser_class: PrismParser subclass

        Returns:
            The parser class (for decorator chaining)
        """
        try:
            parser = parser_class()
            cls._parsers[parser.name] = parser
            logger.info(f"Registered PRISM parser: {parser.name}")
        except Exception as e:
            logger.error(f"Failed to register parser {parser_class}: {e}")

        return parser_class

    @classmethod
    def get_parser(cls, filepath: str) -> Optional[PrismParser]:
        """Auto-detect appropriate parser for file

        Args:
            filepath: Path to file

        Returns:
            Parser instance or None
        """
        cls.initialize_parsers()

        for parser in cls._parsers.values():
            try:
                if parser.can_parse(filepath):
                    logger.info(f"Selected PRISM parser '{parser.name}' for {filepath}")
                    return parser
            except Exception as e:
                logger.debug(f"Parser {parser.name} failed can_parse check: {e}")

        logger.warning(f"No PRISM parser found for {filepath}")
        return None

    @classmethod
    def get_parser_by_name(cls, name: str) -> Optional[PrismParser]:
        """Get parser by name

        Args:
            name: Parser name

        Returns:
            Parser instance or None
        """
        cls.initialize_parsers()
        return cls._parsers.get(name)

    @classmethod
    def get_all_parsers(cls) -> List[PrismParser]:
        """Get all registered parsers

        Returns:
            List of parser instances
        """
        cls.initialize_parsers()
        return list(cls._parsers.values())

    @classmethod
    def list_parser_names(cls) -> List[str]:
        """Get names of all registered parsers

        Returns:
            List of parser names
        """
        cls.initialize_parsers()
        return list(cls._parsers.keys())

    @classmethod
    def initialize_parsers(cls):
        """Initialize all parsers (import parser modules)"""
        if cls._initialized:
            return

        # Import parser modules to trigger @register decorators
        try:
            from . import mimikatz  # noqa: F401
            from . import nmap  # noqa: F401
            from . import gpp  # noqa: F401
            from . import kerberoast  # noqa: F401
            from . import secretsdump  # noqa: F401
        except ImportError as e:
            logger.warning(f"Some PRISM parsers failed to import: {e}")

        cls._initialized = True
        logger.info(f"Initialized {len(cls._parsers)} PRISM parsers")

    @classmethod
    def clear(cls):
        """Clear initialization state (for testing)"""
        cls._initialized = False
