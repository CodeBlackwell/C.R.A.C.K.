"""
Shared configuration system for CRACK toolkit

Provides centralized variable management, validation, and configuration
for all CRACK modules (reference, track, etc.)

Usage:
    from crack.config import ConfigManager, Variable, VARIABLE_REGISTRY

    config = ConfigManager()
    config.set_variable('LHOST', '10.10.14.5')
    lhost = config.get_variable('LHOST')
"""

from .manager import ConfigManager
from .variables import Variable, VARIABLE_REGISTRY
from .validators import Validators

__all__ = [
    'ConfigManager',
    'Variable',
    'VARIABLE_REGISTRY',
    'Validators'
]

__version__ = '1.0.0'
