"""
Telemetry - Anonymous usage statistics for intelligence system

Collects anonymous metrics about intelligence system effectiveness:
- Attack chain success rates
- Common failure points
- Performance metrics
- Feature usage

Privacy: No IP addresses, no target details, no credentials, opt-in only.
Storage: Local only, never transmitted.
"""

from typing import Dict, Any, Optional
import logging
from datetime import datetime
import json
from pathlib import Path

logger = logging.getLogger(__name__)


class Telemetry:
    """Anonymous telemetry collection"""

    def __init__(self, storage_path: Optional[Path] = None, enabled: bool = False):
        """
        Initialize telemetry

        Args:
            storage_path: Path to telemetry storage (default: ~/.crack/telemetry.json)
            enabled: Whether telemetry is enabled (opt-in)
        """
        self.enabled = enabled

        # Default storage location
        if storage_path is None:
            crack_home = Path.home() / ".crack"
            self.storage_path = crack_home / 'telemetry.json'
        else:
            self.storage_path = storage_path

        # Load existing metrics
        self.metrics = self._load_metrics()

        logger.info(f"[TELEMETRY] Initialized (enabled: {enabled})")

    def _load_metrics(self) -> Dict[str, Any]:
        """Load metrics from storage"""
        if not self.storage_path.exists():
            return {
                'intelligence_suggestions': 0,
                'suggestions_accepted': 0,
                'chain_attempts': 0,
                'chain_completions': 0,
                'pattern_detections': 0,
                'weight_updates': 0,
                'started_at': datetime.now().isoformat()
            }

        try:
            with open(self.storage_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"[TELEMETRY] Failed to load metrics: {e}")
            return {
                'intelligence_suggestions': 0,
                'suggestions_accepted': 0,
                'chain_attempts': 0,
                'chain_completions': 0,
                'pattern_detections': 0,
                'weight_updates': 0,
                'started_at': datetime.now().isoformat()
            }

    def _save_metrics(self):
        """Save metrics to storage"""
        if not self.enabled:
            return

        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.storage_path, 'w') as f:
                json.dump(self.metrics, f, indent=2)
        except Exception as e:
            logger.error(f"[TELEMETRY] Failed to save metrics: {e}")

    def record_intelligence_suggestion(self, suggestion_count: int):
        """
        Record intelligence suggestions generated

        Args:
            suggestion_count: Number of suggestions generated
        """
        if not self.enabled:
            return

        self.metrics['intelligence_suggestions'] += suggestion_count
        self._save_metrics()
        logger.debug(f"[TELEMETRY] Recorded {suggestion_count} suggestions")

    def record_suggestion_accepted(self, suggestion_id: str):
        """
        Record user accepting a suggestion

        Args:
            suggestion_id: ID of accepted suggestion (anonymized)
        """
        if not self.enabled:
            return

        self.metrics['suggestions_accepted'] += 1
        self._save_metrics()
        logger.debug(f"[TELEMETRY] Suggestion accepted: {suggestion_id}")

    def record_chain_attempt(self, chain_id: str):
        """
        Record attack chain attempt

        Args:
            chain_id: Chain identifier (anonymized)
        """
        if not self.enabled:
            return

        self.metrics['chain_attempts'] += 1
        self._save_metrics()
        logger.debug(f"[TELEMETRY] Chain attempt: {chain_id}")

    def record_chain_completion(self, chain_id: str, completion_rate: float):
        """
        Record attack chain completion

        Args:
            chain_id: Chain identifier (anonymized)
            completion_rate: Completion rate (0.0-1.0)
        """
        if not self.enabled:
            return

        self.metrics['chain_completions'] += 1
        self._save_metrics()
        logger.debug(f"[TELEMETRY] Chain completion: {chain_id} ({completion_rate:.1%})")

    def record_pattern_detection(self):
        """Record successful pattern detection"""
        if not self.enabled:
            return

        self.metrics['pattern_detections'] += 1
        self._save_metrics()
        logger.debug("[TELEMETRY] Pattern detected")

    def record_weight_update(self):
        """Record scoring weight update"""
        if not self.enabled:
            return

        self.metrics['weight_updates'] += 1
        self._save_metrics()
        logger.debug("[TELEMETRY] Weight updated")

    def get_metrics(self) -> Dict[str, Any]:
        """
        Get current metrics

        Returns:
            Metrics dict with all collected data
        """
        if not self.enabled:
            return {}

        # Calculate derived metrics
        acceptance_rate = (
            self.metrics['suggestions_accepted'] / self.metrics['intelligence_suggestions']
            if self.metrics['intelligence_suggestions'] > 0
            else 0.0
        )

        completion_rate = (
            self.metrics['chain_completions'] / self.metrics['chain_attempts']
            if self.metrics['chain_attempts'] > 0
            else 0.0
        )

        return {
            **self.metrics,
            'acceptance_rate': acceptance_rate,
            'completion_rate': completion_rate
        }

    def clear_metrics(self):
        """Clear all collected metrics"""
        self.metrics = {
            'intelligence_suggestions': 0,
            'suggestions_accepted': 0,
            'chain_attempts': 0,
            'chain_completions': 0,
            'pattern_detections': 0,
            'weight_updates': 0,
            'started_at': datetime.now().isoformat()
        }
        self._save_metrics()
        logger.info("[TELEMETRY] Metrics cleared")
