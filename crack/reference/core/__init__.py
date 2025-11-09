"""
Core functionality for the CRACK Reference System
"""

from .registry import HybridCommandRegistry
from .sql_adapter import SQLCommandRegistryAdapter
from .router import CommandRegistryRouter
from .parser import MarkdownCommandParser
from .placeholder import PlaceholderEngine
from .validator import CommandValidator
from .colors import ReferenceTheme, Colors, get_theme, disable_colors
from .cheatsheet_registry import CheatsheetRegistry, Cheatsheet, CheatsheetScenario, CheatsheetSection, EducationalHeader

# Import shared config from crack.config
from crack.config import ConfigManager

__all__ = [
    'HybridCommandRegistry',
    'SQLCommandRegistryAdapter',
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
    'EducationalHeader'
]