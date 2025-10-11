"""
Intelligence System - Hybrid guidance engine for penetration testing workflows

Provides context-aware task recommendations, cross-service correlation,
and methodology-driven guidance without automation.

Architecture:
- TaskOrchestrator: Central coordinator merging multiple intelligence sources
- CorrelationIntelligence: Method 1 - Reactive event-driven correlation
- MethodologyEngine: Method 2 - Proactive methodology state machine
- TaskScorer: Priority calculation engine
- IntelligenceConfig: Configuration management
"""

__version__ = "2.0.0-alpha"

from .config import IntelligenceConfig
from .scoring import TaskScorer
from .task_orchestrator import TaskOrchestrator
from .correlation_engine import CorrelationIntelligence

__all__ = [
    'IntelligenceConfig',
    'TaskScorer',
    'TaskOrchestrator',
    'CorrelationIntelligence'
]
