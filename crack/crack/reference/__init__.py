"""CRACK Reference - Command Registry and Reference System"""

# Import from the actual reference.core module
import sys
from pathlib import Path

# Add reference directory to path if not already there
reference_dir = Path(__file__).parent.parent.parent / 'reference'
if str(reference_dir) not in sys.path:
    sys.path.insert(0, str(reference_dir))

# Now import from reference.core
from reference.core import (
    HybridCommandRegistry,
    ConfigManager,
    ReferenceTheme,
    CommandFiller,
    CommandMapper,
    AdapterErrorHandler,
    CommandRegistryAdapter,
    Command,
    CommandVariable
)

__all__ = [
    'HybridCommandRegistry',
    'ConfigManager',
    'ReferenceTheme',
    'CommandFiller',
    'CommandMapper',
    'AdapterErrorHandler',
    'CommandRegistryAdapter',
    'Command',
    'CommandVariable'
]
