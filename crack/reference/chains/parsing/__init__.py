"""
Chain output parsing system - Plugin-based architecture for extensibility.

Provides base interfaces and registry for automatic parser discovery.
Each chain type can implement a custom parser without modifying core code.
"""

from .base import BaseOutputParser, ParsingResult
from .registry import ParserRegistry
from .suid_parser import SUIDParser  # Import to trigger registration
from .capabilities_parser import CapabilitiesParser  # Import to trigger registration

__all__ = [
    'BaseOutputParser',
    'ParsingResult',
    'ParserRegistry',
    'SUIDParser',
    'CapabilitiesParser',
]
