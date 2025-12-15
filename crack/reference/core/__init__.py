"""
Core functionality for the CRACK Reference System
"""

from .registry import HybridCommandRegistry, Command, CommandVariable
from .neo4j_adapter import Neo4jCommandRegistryAdapter
from .parser import MarkdownCommandParser
from .placeholder import PlaceholderEngine
from .validator import CommandValidator
from crack.core.themes import ReferenceTheme, Colors, disable_colors
from crack.core.themes.colors import get_theme as get_reference_theme
from .cheatsheet_registry import CheatsheetRegistry, Cheatsheet, CheatsheetScenario, CheatsheetSection, EducationalHeader

# Alias for backward compatibility
get_theme = get_reference_theme

# Shared infrastructure (DRY refactoring)
from .command_filler import CommandFiller
from .command_mapper import CommandMapper
from .exceptions import (
    AdapterError,
    QueryExecutionError,
    ConnectionError,
    DataMappingError,
    ConfigurationError,
    AdapterErrorHandler
)
from .adapter_interface import CommandRegistryAdapter, ReadOnlyAdapter, MutableAdapter

# Import shared config from crack.core.config
from crack.core.config import ConfigManager

__all__ = [
    'HybridCommandRegistry',
    'Command',
    'CommandVariable',
    'Neo4jCommandRegistryAdapter',
    'MarkdownCommandParser',
    'PlaceholderEngine',
    'CommandValidator',
    'ConfigManager',
    'ReferenceTheme',
    'Colors',
    'get_theme',
    'disable_colors',
    'CheatsheetRegistry',
    'Cheatsheet',
    'CheatsheetScenario',
    'CheatsheetSection',
    'EducationalHeader',
    # Shared infrastructure
    'CommandFiller',
    'CommandMapper',
    'AdapterError',
    'QueryExecutionError',
    'ConnectionError',
    'DataMappingError',
    'ConfigurationError',
    'AdapterErrorHandler',
    'CommandRegistryAdapter',
    'ReadOnlyAdapter',
    'MutableAdapter'
]