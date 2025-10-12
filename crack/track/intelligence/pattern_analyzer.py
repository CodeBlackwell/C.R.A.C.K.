"""
Pattern Analyzer - Success pattern detection and weight optimization

Analyzes historical task execution data to detect successful patterns
and automatically tune scoring weights for improved suggestions.

Uses simple heuristics (no machine learning library dependencies).
"""

from typing import Dict, Any, List
import logging
from collections import Counter

logger = logging.getLogger(__name__)


class PatternAnalyzer:
    """Analyzes success patterns and optimizes scoring weights"""

    # Default scoring weights
    DEFAULT_WEIGHTS = {
        'phase_alignment': 1.0,
        'chain_progress': 1.5,
        'quick_win': 2.0,
        'time_estimate': 0.5,
        'dependencies': 1.0,
        'success_probability': 1.2,
        'user_preference': 0.8
    }

    def __init__(self, success_tracker: 'SuccessTracker', config: Dict[str, Any]):
        """
        Initialize pattern analyzer

        Args:
            success_tracker: SuccessTracker instance with historical data
            config: Intelligence configuration
        """
        self.tracker = success_tracker
        self.config = config

        # Load current weights (user-configured or defaults)
        intel_config = config.get('intelligence', {})
        self.weights = intel_config.get('scoring_weights', self.DEFAULT_WEIGHTS.copy())

        logger.info(f"[PATTERN_ANALYZER] Initialized")

    def analyze_user_preferences(self) -> Dict[str, float]:
        """
        Analyze user task selection patterns

        Returns:
            Dict of category preferences (category -> preference score 0.0-1.0)
        """
        task_outcomes = self.tracker.task_outcomes
        if not task_outcomes:
            return {}

        # Count task categories
        category_counts = Counter()
        category_successes = Counter()

        for task_id, outcomes in task_outcomes.items():
            for outcome in outcomes:
                category = outcome.get('metadata', {}).get('category', 'unknown')
                category_counts[category] += 1
                if outcome['success']:
                    category_successes[category] += 1

        # Calculate preference scores (frequency + success rate)
        preferences = {}
        max_count = max(category_counts.values()) if category_counts else 1

        for category, count in category_counts.items():
            frequency_score = count / max_count  # Normalize to 0-1
            success_rate = category_successes[category] / count if count > 0 else 0.5
            preferences[category] = (frequency_score + success_rate) / 2  # Average

        logger.info(f"[PATTERN_ANALYZER] User preferences: {len(preferences)} categories")
        return preferences

    def detect_successful_patterns(self, min_samples: int = 3) -> List[Dict[str, Any]]:
        """
        Detect high-success patterns from history

        Args:
            min_samples: Minimum samples required to qualify as a pattern

        Returns:
            List of pattern dicts with success_rate, sample_count, pattern_id
        """
        patterns = []

        # Detect task patterns
        for task_id, outcomes in self.tracker.task_outcomes.items():
            if len(outcomes) < min_samples:
                continue

            success_rate = self.tracker.get_success_rate(task_id, 'task')
            if success_rate >= 0.7:  # 70%+ success rate
                patterns.append({
                    'pattern_id': task_id,
                    'pattern_type': 'task',
                    'success_rate': success_rate,
                    'sample_count': len(outcomes)
                })

        # Detect chain patterns
        for chain_id, completions in self.tracker.chain_completions.items():
            completion_list = completions if isinstance(completions, list) else [completions]
            if len(completion_list) < min_samples:
                continue

            avg_rate = sum(c.get('completion_rate', 0) for c in completion_list) / len(completion_list)
            if avg_rate >= 0.6:  # 60%+ completion rate
                patterns.append({
                    'pattern_id': chain_id,
                    'pattern_type': 'chain',
                    'success_rate': avg_rate,
                    'sample_count': len(completion_list)
                })

        logger.info(f"[PATTERN_ANALYZER] Detected {len(patterns)} successful patterns")
        return patterns

    def update_scoring_weights(self, learning_rate: float = 0.1) -> Dict[str, float]:
        """
        Auto-tune scoring weights based on patterns

        Args:
            learning_rate: How aggressively to update weights (0.0-1.0)

        Returns:
            Updated weights dict
        """
        preferences = self.analyze_user_preferences()
        patterns = self.detect_successful_patterns()

        # Clone current weights
        updated_weights = self.weights.copy()
        weights_changed = False

        # Adjust quick_win weight based on quick-win success rate
        quick_win_tasks = [
            outcome
            for task_id, outcomes in self.tracker.task_outcomes.items()
            for outcome in outcomes
            if outcome.get('metadata', {}).get('category') == 'quick_win'
        ]

        if quick_win_tasks:
            quick_win_success = sum(1 for o in quick_win_tasks if o['success']) / len(quick_win_tasks)
            if quick_win_success > 0.7:
                updated_weights['quick_win'] *= (1 + learning_rate)  # Increase weight
                weights_changed = True
            elif quick_win_success < 0.4:
                updated_weights['quick_win'] *= (1 - learning_rate)  # Decrease weight
                weights_changed = True

        # Adjust chain_progress weight based on chain completion rates
        if patterns:
            chain_patterns = [p for p in patterns if p['pattern_type'] == 'chain']
            if chain_patterns:
                avg_chain_success = sum(p['success_rate'] for p in chain_patterns) / len(chain_patterns)
                if avg_chain_success > 0.7:
                    updated_weights['chain_progress'] *= (1 + learning_rate)
                    weights_changed = True

        # Adjust user_preference weight based on preference variance
        if preferences and len(preferences) > 2:
            # If user has strong preferences (high variance), increase weight
            pref_values = list(preferences.values())
            pref_variance = sum((p - 0.5) ** 2 for p in pref_values) / len(pref_values)
            if pref_variance > 0.1:  # High variance
                updated_weights['user_preference'] *= (1 + learning_rate * 0.5)
                weights_changed = True

        # Only proceed if weights actually changed
        if not weights_changed:
            logger.debug(f"[PATTERN_ANALYZER] No weight adjustments triggered")
            return self.weights

        # Normalize weights to prevent runaway growth
        total_weight = sum(updated_weights.values())
        normalized_weights = {k: v / total_weight * 7.0 for k, v in updated_weights.items()}  # Keep sum ~7.0

        # Check if normalized changes are significant
        weight_diff = sum(abs(normalized_weights[k] - self.weights[k]) for k in self.weights)
        if weight_diff > 0.1:
            self.weights = normalized_weights
            logger.info(f"[PATTERN_ANALYZER] Weights updated (diff: {weight_diff:.3f})")
            return normalized_weights

        logger.debug(f"[PATTERN_ANALYZER] Weight changes insignificant after normalization")
        return self.weights

    def get_pattern_insights(self) -> Dict[str, Any]:
        """
        Get comprehensive pattern analysis insights

        Returns:
            Dict with preferences, patterns, weights, recommendations
        """
        preferences = self.analyze_user_preferences()
        patterns = self.detect_successful_patterns()

        insights = {
            'user_preferences': preferences,
            'successful_patterns': patterns,
            'current_weights': self.weights,
            'sample_count': len(self.tracker.task_outcomes),
            'recommendations': []
        }

        # Generate recommendations
        if len(self.tracker.task_outcomes) < 10:
            insights['recommendations'].append("Collect more task data for better pattern detection")

        if patterns:
            top_pattern = max(patterns, key=lambda p: p['success_rate'])
            insights['recommendations'].append(
                f"High success pattern: {top_pattern['pattern_id']} ({top_pattern['success_rate']:.1%})"
            )

        return insights
