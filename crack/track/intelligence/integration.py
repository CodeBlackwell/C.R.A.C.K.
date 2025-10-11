"""
Intelligence Integration - Wire engines to TaskOrchestrator

Helper functions for initializing and connecting intelligence components.
"""

from typing import Optional
import logging
from pathlib import Path
from .task_orchestrator import TaskOrchestrator
from .correlation_engine import CorrelationIntelligence
from .scoring import TaskScorer
from .config import IntelligenceConfig
from ..methodology.methodology_engine import MethodologyEngine

logger = logging.getLogger(__name__)


def initialize_intelligence_system(target: str, profile: 'TargetProfile',
                                   config_path: Optional[str] = None) -> Optional[TaskOrchestrator]:
    """
    Initialize complete intelligence system

    Args:
        target: Target IP/hostname
        profile: TargetProfile instance
        config_path: Optional path to config.json

    Returns:
        Configured TaskOrchestrator with engines attached, or None if disabled
    """
    logger.info(f"[INTEGRATION] Initializing intelligence for {target}")

    # Load configuration (convert string to Path if provided)
    path_obj = Path(config_path) if config_path else None
    config = IntelligenceConfig(config_path=path_obj)

    if not config.is_enabled():
        logger.info("[INTEGRATION] Intelligence system disabled in config")
        return None

    intel_config = config.get_intelligence_config()

    # Initialize orchestrator
    orchestrator = TaskOrchestrator(target, profile, intel_config)

    # Initialize scorer
    scorer = TaskScorer(intel_config)
    orchestrator.set_scorer(scorer)

    # Initialize Method 1: Correlation
    if intel_config.get('correlation', {}).get('enabled', True):
        correlation = CorrelationIntelligence(target, profile, intel_config)
        orchestrator.correlation_engine = correlation
        logger.info("[INTEGRATION] Correlation engine enabled")

    # Initialize Method 2: Methodology
    if intel_config.get('methodology', {}).get('enabled', True):
        methodology = MethodologyEngine(target, profile, intel_config)
        orchestrator.methodology_engine = methodology
        logger.info("[INTEGRATION] Methodology engine enabled")

    logger.info("[INTEGRATION] Intelligence system initialized")
    return orchestrator
