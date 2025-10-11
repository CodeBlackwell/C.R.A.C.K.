"""
Success Tracker - Task outcome tracking for pattern learning

Tracks task execution outcomes, chain completions, and timing metrics
to enable pattern analysis and scoring weight optimization.

Persistence: Stores in profile.metadata['success_tracker']
"""

from typing import Dict, Any, List, Optional
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class SuccessTracker:
    """Tracks task outcomes and success metrics"""

    def __init__(self, profile: 'TargetProfile'):
        """
        Initialize success tracker

        Args:
            profile: TargetProfile for persistence
        """
        self.profile = profile

        # Load existing data from profile
        tracker_data = profile.metadata.get('success_tracker', {})
        self.task_outcomes: Dict[str, List[Dict[str, Any]]] = tracker_data.get('task_outcomes', {})
        self.chain_completions: Dict[str, List[Dict[str, Any]]] = tracker_data.get('chain_completions', {})
        self.pattern_success: Dict[str, Dict[str, Any]] = tracker_data.get('pattern_success', {})

        logger.info(f"[SUCCESS_TRACKER] Initialized ({len(self.task_outcomes)} tracked tasks)")

    def record_task_outcome(self, task_id: str, success: bool, time_taken: float, metadata: Optional[Dict] = None):
        """
        Record outcome of a task execution

        Args:
            task_id: Task identifier
            success: Whether task succeeded
            time_taken: Execution time in seconds
            metadata: Additional context (category, source, etc.)
        """
        outcome = {
            'success': success,
            'time_taken': time_taken,
            'timestamp': datetime.now().isoformat(),
            'metadata': metadata or {}
        }

        if task_id not in self.task_outcomes:
            self.task_outcomes[task_id] = []

        self.task_outcomes[task_id].append(outcome)
        self._persist()

        logger.info(f"[SUCCESS_TRACKER] Task outcome: {task_id} -> {'✓' if success else '✗'} ({time_taken:.1f}s)")

    def record_chain_completion(self, chain_id: str, steps_completed: int, total_steps: int, total_time: float):
        """
        Record attack chain completion

        Args:
            chain_id: Chain identifier
            steps_completed: Number of steps successfully completed
            total_steps: Total steps in chain
            total_time: Total execution time in seconds
        """
        completion = {
            'steps_completed': steps_completed,
            'total_steps': total_steps,
            'total_time': total_time,
            'completion_rate': steps_completed / total_steps if total_steps > 0 else 0.0,
            'timestamp': datetime.now().isoformat()
        }

        if chain_id not in self.chain_completions:
            self.chain_completions[chain_id] = []

        self.chain_completions[chain_id].append(completion)
        self._persist()

        logger.info(f"[SUCCESS_TRACKER] Chain completion: {chain_id} -> {steps_completed}/{total_steps} ({completion['completion_rate']:.1%})")

    def get_success_rate(self, pattern: str, pattern_type: str = 'task') -> float:
        """
        Calculate success rate for a pattern

        Args:
            pattern: Pattern identifier (task_id, chain_id, category, etc.)
            pattern_type: Type of pattern ('task', 'chain', 'category')

        Returns:
            Success rate as 0.0-1.0
        """
        if pattern_type == 'task':
            outcomes = self.task_outcomes.get(pattern, [])
            if not outcomes:
                return 0.5  # Default: 50% if no history

            successes = sum(1 for o in outcomes if o['success'])
            return successes / len(outcomes)

        elif pattern_type == 'chain':
            completions = self.chain_completions.get(pattern, [])
            if not completions:
                return 0.5

            # Average completion rate across all attempts
            avg_rate = sum(c['completion_rate'] for c in completions) / len(completions)
            return avg_rate

        elif pattern_type == 'category':
            # Calculate success rate for all tasks in category
            category_outcomes = []
            for task_id, outcomes in self.task_outcomes.items():
                for outcome in outcomes:
                    if outcome.get('metadata', {}).get('category') == pattern:
                        category_outcomes.append(outcome)

            if not category_outcomes:
                return 0.5

            successes = sum(1 for o in category_outcomes if o['success'])
            return successes / len(category_outcomes)

        return 0.5

    def get_average_time(self, task_id: str) -> float:
        """
        Get average execution time for a task

        Args:
            task_id: Task identifier

        Returns:
            Average time in seconds, or 0 if no history
        """
        outcomes = self.task_outcomes.get(task_id, [])
        if not outcomes:
            return 0.0

        total_time = sum(o['time_taken'] for o in outcomes)
        return total_time / len(outcomes)

    def get_pattern_statistics(self, pattern: str, pattern_type: str = 'task') -> Dict[str, Any]:
        """
        Get comprehensive statistics for a pattern

        Args:
            pattern: Pattern identifier
            pattern_type: Type of pattern

        Returns:
            Statistics dict with success_rate, avg_time, sample_count
        """
        success_rate = self.get_success_rate(pattern, pattern_type)
        avg_time = self.get_average_time(pattern) if pattern_type == 'task' else 0.0

        if pattern_type == 'task':
            sample_count = len(self.task_outcomes.get(pattern, []))
        elif pattern_type == 'chain':
            sample_count = len(self.chain_completions.get(pattern, []))
        else:
            # Count outcomes matching category
            sample_count = 0
            for outcomes in self.task_outcomes.values():
                for outcome in outcomes:
                    if outcome.get('metadata', {}).get('category') == pattern:
                        sample_count += 1

        return {
            'pattern': pattern,
            'pattern_type': pattern_type,
            'success_rate': success_rate,
            'average_time': avg_time,
            'sample_count': sample_count
        }

    def _persist(self):
        """Persist tracker data to profile"""
        self.profile.metadata['success_tracker'] = {
            'task_outcomes': self.task_outcomes,
            'chain_completions': self.chain_completions,
            'pattern_success': self.pattern_success
        }
        self.profile.save()
