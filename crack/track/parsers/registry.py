"""
Parser registry with auto-detection

Parsers register themselves and are auto-selected based on file format
"""

from typing import Dict, List, Optional, Any
from .base import Parser
from ..core.events import EventBus
import logging

logger = logging.getLogger(__name__)


class ParserRegistry:
    """Central registry for file parsers"""

    _parsers: Dict[str, Parser] = {}
    _initialized: bool = False

    @classmethod
    def register(cls, parser_class):
        """Decorator to register a parser

        Usage:
            @ParserRegistry.register
            class NmapXMLParser(Parser):
                ...

        Args:
            parser_class: Parser subclass

        Returns:
            The parser class (for decorator chaining)
        """
        try:
            parser = parser_class()
            cls._parsers[parser.name] = parser
            logger.info(f"Registered parser: {parser.name}")

        except Exception as e:
            logger.error(f"Failed to register parser {parser_class}: {e}")

        return parser_class

    @classmethod
    def get_parser(cls, filepath: str) -> Optional[Parser]:
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
                    logger.info(f"Selected parser '{parser.name}' for {filepath}")
                    return parser
            except Exception as e:
                logger.debug(f"Parser {parser.name} failed can_parse check: {e}")

        logger.warning(f"No parser found for {filepath}")
        return None

    @classmethod
    def parse_file(cls, filepath: str, target: str = None, profile = None) -> Dict[str, Any]:
        """Parse file using appropriate parser and update profile

        Args:
            filepath: Path to file to parse
            target: Optional target hint
            profile: Optional TargetProfile to update

        Returns:
            Parsed data dictionary
        """
        parser = cls.get_parser(filepath)
        if not parser:
            raise ValueError(f"No parser available for file: {filepath}")

        # Parse file
        data = parser.parse(filepath, target)

        # Update profile if provided
        if profile:
            cls._update_profile(profile, data, filepath, parser.name)

        return data

    @classmethod
    def _update_profile(cls, profile, data: Dict[str, Any], filepath: str, parser_name: str):
        """Update target profile with parsed data

        Args:
            profile: TargetProfile instance
            data: Parsed data dictionary
            filepath: Source file path
            parser_name: Name of parser used
        """
        # Track imported file with enhanced metadata (Chapter 8)
        file_metadata = {
            'file': filepath,
            'type': parser_name,
            'nmap_command': data.get('nmap_command'),
            'scan_stats': data.get('scan_stats', {})
        }
        profile.add_imported_file(filepath, parser_name, metadata=file_metadata)

        # Add discovered ports
        for port_data in data.get('ports', []):
            profile.add_port(
                port=port_data['port'],
                state=port_data.get('state', 'open'),
                service=port_data.get('service'),
                version=port_data.get('version'),
                source=f"{parser_name}: {filepath}",
                **port_data.get('extra', {})
            )

        # Add OS information if available (enhanced with accuracy)
        os_details = data.get('os_details', {})
        if os_details.get('best_match'):
            os_note = f"OS detection: {os_details['best_match']}"
            accuracy = os_details.get('accuracy', 0)
            if accuracy > 0:
                os_note += f" ({accuracy}% accuracy)"

            profile.add_note(
                note=os_note,
                source=f"{parser_name}: {filepath}"
            )

            # Store OS details for use in exports
            if not hasattr(profile, 'os_info'):
                profile.os_info = os_details

        # Add traceroute/topology information if available
        traceroute = data.get('traceroute', [])
        if traceroute:
            hops_summary = f"Network path: {len(traceroute)} hops"
            profile.add_note(
                note=hops_summary,
                source=f"{parser_name}: {filepath}"
            )

        # Add hostnames if found
        if data.get('hostnames'):
            profile.add_note(
                note=f"Hostnames: {', '.join(data['hostnames'])}",
                source=f"{parser_name}: {filepath}"
            )

    @classmethod
    def get_all_parsers(cls) -> List[Parser]:
        """Get all registered parsers

        Returns:
            List of parser instances
        """
        cls.initialize_parsers()
        return list(cls._parsers.values())

    @classmethod
    def get_parser_by_name(cls, name: str) -> Optional[Parser]:
        """Get parser by name

        Args:
            name: Parser name

        Returns:
            Parser instance or None
        """
        cls.initialize_parsers()
        return cls._parsers.get(name)

    @classmethod
    def initialize_parsers(cls):
        """Initialize all parsers (import parser modules)"""
        if cls._initialized:
            return

        # Import all parser modules to trigger @register decorators
        try:
            from . import nmap_xml, nmap_gnmap
        except ImportError as e:
            logger.warning(f"Some parsers failed to import: {e}")

        cls._initialized = True
        logger.info(f"Initialized {len(cls._parsers)} parsers")

    @classmethod
    def clear(cls):
        """Clear initialization state but preserve registered parsers (for testing isolation)

        NOTE: We do NOT clear cls._parsers because parser registration happens
        at module import time via @ParserRegistry.register decorators. Once modules
        are imported, the parsers are registered and should persist across tests.
        Clearing _parsers would require re-importing modules, which doesn't work
        since Python caches imports in sys.modules.

        This method only clears:
        - _initialized: Flag to allow re-initialization

        To fully reset for testing, call this method along with EventBus.clear()
        and ServiceRegistry.clear() to reset all shared state.
        """
        cls._initialized = False
