"""
Methodology Module - OSCP Phase-based Task Generation

Provides proactive task suggestions based on penetration testing methodology.
"""

from .methodology_engine import MethodologyEngine
from .phases import Phase, PhaseTransition

__all__ = ['MethodologyEngine', 'Phase', 'PhaseTransition']
