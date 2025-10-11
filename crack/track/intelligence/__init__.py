"""
Intelligence System - Hybrid guidance engine for penetration testing workflows

Provides context-aware task recommendations, cross-service correlation,
and methodology-driven guidance without automation.

Architecture:
- TaskOrchestrator: Central coordinator merging multiple intelligence sources
- Method 1: Reactive event-driven correlation (Stage 2)
- Method 2: Proactive methodology state machine (Stage 2)
"""

__version__ = "2.0.0-alpha"

from .config import IntelligenceConfig
from .scoring import TaskScorer
from .task_orchestrator import TaskOrchestrator

__all__ = ['IntelligenceConfig', 'TaskScorer', 'TaskOrchestrator']
