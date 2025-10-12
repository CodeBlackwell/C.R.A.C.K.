"""
Task Scoring Engine - Priority calculation for task suggestions

Scores tasks using 7 weighted factors:
1. Phase alignment (0-20 pts): Task matches current methodology phase
2. Chain progress (0-30 pts): Part of active attack chain
3. Quick-win potential (0-25 pts): High-probability OSCP vulnerability
4. Time estimate (0-10 pts): Faster tasks preferred
5. Dependency satisfaction (0-15 pts): Prerequisites met
6. Success probability (0-20 pts): Historical success rate
7. User preference (0-10 pts): User tends to select similar tasks

Maximum score: 130 points
"""

from typing import Dict, Any, TYPE_CHECKING
import logging

if TYPE_CHECKING:
    from crack.track.core.state import TargetProfile

logger = logging.getLogger(__name__)


class TaskScorer:
    """Calculate priority scores for task suggestions"""

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

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize task scorer

        Args:
            config: Scoring configuration with optional weight overrides
        """
        self.weights = self.DEFAULT_WEIGHTS.copy()

        # Override weights from config
        if 'scoring_weights' in config:
            self.weights.update(config['scoring_weights'])

        logger.info(f"[SCORER] Initialized with weights: {self.weights}")

    def calculate_priority(self, task: Dict[str, Any], profile: 'TargetProfile') -> float:
        """
        Calculate priority score for a task

        Args:
            task: Task dictionary with metadata
            profile: TargetProfile for context

        Returns:
            Priority score (0-130, higher = more important)
        """
        score = 0.0
        breakdown = {}

        # Factor 1: Phase alignment (0-20)
        phase_score = self._score_phase_alignment(task, profile)
        score += phase_score * self.weights['phase_alignment']
        breakdown['phase_alignment'] = phase_score

        # Factor 2: Chain progress (0-30)
        chain_score = self._score_chain_progress(task)
        score += chain_score * self.weights['chain_progress']
        breakdown['chain_progress'] = chain_score

        # Factor 3: Quick-win potential (0-25)
        quickwin_score = self._score_quick_win(task)
        score += quickwin_score * self.weights['quick_win']
        breakdown['quick_win'] = quickwin_score

        # Factor 4: Time estimate (0-10)
        time_score = self._score_time_estimate(task)
        score += time_score * self.weights['time_estimate']
        breakdown['time_estimate'] = time_score

        # Factor 5: Dependency satisfaction (0-15)
        dep_score = self._score_dependencies(task, profile)
        score += dep_score * self.weights['dependencies']
        breakdown['dependencies'] = dep_score

        # Factor 6: Success probability (0-20)
        success_score = self._score_success_probability(task)
        score += success_score * self.weights['success_probability']
        breakdown['success_probability'] = success_score

        # Factor 7: User preference (0-10)
        pref_score = self._score_user_preference(task, profile)
        score += pref_score * self.weights['user_preference']
        breakdown['user_preference'] = pref_score

        # Store breakdown in task for transparency
        task['priority_breakdown'] = breakdown

        logger.debug(f"[SCORER] Task '{task.get('id', 'unknown')}' scored {score:.1f}")

        return score

    def _score_phase_alignment(self, task: Dict, profile: 'TargetProfile') -> float:
        """Score based on methodology phase alignment (0-20)"""
        if task.get('phase_alignment'):
            return 20.0
        return 5.0  # Neutral score

    def _score_chain_progress(self, task: Dict) -> float:
        """Score based on attack chain membership (0-30)"""
        if not task.get('in_attack_chain'):
            return 5.0  # Neutral

        # Higher score for chains near completion
        progress = task.get('chain_progress', 0.0)
        return 10.0 + (20.0 * progress)

    def _score_quick_win(self, task: Dict) -> float:
        """Score based on OSCP quick-win potential (0-25)"""
        if not task.get('matches_oscp_pattern'):
            return 5.0  # Neutral

        likelihood = task.get('oscp_likelihood', 0.5)
        return 5.0 + (20.0 * likelihood)

    def _score_time_estimate(self, task: Dict) -> float:
        """Score based on estimated execution time (0-10, faster = higher)"""
        time_minutes = task.get('estimated_time_minutes', 10)

        # Inverse scoring: faster tasks score higher
        if time_minutes <= 1:
            return 10.0
        elif time_minutes <= 5:
            return 7.0
        elif time_minutes <= 15:
            return 5.0
        else:
            return 2.0

    def _score_dependencies(self, task: Dict, profile: 'TargetProfile') -> float:
        """Score based on dependency satisfaction (0-15)"""
        # Stage 1: Placeholder (no dependency tracking yet)
        # Future: Check if task prerequisites are met
        return 10.0  # Assume dependencies met

    def _score_success_probability(self, task: Dict) -> float:
        """Score based on historical success rate (0-20)"""
        # Stage 1: Placeholder (no success tracking yet)
        # Future: Query SuccessTracker for this task pattern
        return 10.0  # Neutral

    def _score_user_preference(self, task: Dict, profile: 'TargetProfile') -> float:
        """Score based on user's historical preferences (0-10)"""
        # Stage 1: Placeholder (no preference learning yet)
        # Future: Check if user tends to select similar tasks
        return 5.0  # Neutral
