"""Phase system for enumeration progression"""

from .base import Phase
from .registry import PhaseManager
from .definitions import PHASES

__all__ = ['Phase', 'PhaseManager', 'PHASES']
