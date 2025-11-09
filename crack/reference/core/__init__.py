"""
Core functionality for the CRACK Reference System
"""

from .registry import HybridCommandRegistry, Command, CommandVariable
from .sql_adapter import SQLCommandRegistryAdapter
from .neo4j_adapter import Neo4jCommandRegistryAdapter
from .router import CommandRegistryRouter
from .parser import MarkdownCommandParser
from .placeholder import PlaceholderEngine
from .validator import CommandValidator
from .colors import ReferenceTheme, Colors, get_theme, disable_colors
from .cheatsheet_registry import CheatsheetRegistry, Cheatsheet, CheatsheetScenario, CheatsheetSection, EducationalHeader

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

# Import shared config from crack.config
from crack.config import ConfigManager

__all__ = [
    'HybridCommandRegistry',
    'Command',
    'CommandVariable',
    'SQLCommandRegistryAdapter',
    'Neo4jCommandRegistryAdapter',
    'CommandRegistryRouter',
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