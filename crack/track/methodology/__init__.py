"""
Methodology Module - OSCP Phase-based Task Generation

Provides proactive task suggestions based on penetration testing methodology.
Includes attack chain execution and progress tracking (Stage 3).
"""

from .methodology_engine import MethodologyEngine
from .phases import Phase, PhaseTransition
from .attack_chains import AttackChain, ChainStep, ChainRegistry
from .chain_executor import ChainExecutor, ChainProgress

__all__ = [
    'MethodologyEngine',
    'Phase',
    'PhaseTransition',
    'AttackChain',
    'ChainStep',
    'ChainRegistry',
    'ChainExecutor',
    'ChainProgress'
]
