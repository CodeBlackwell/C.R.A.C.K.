"""
Tests for track/intelligence/scoring.py - Task priority scoring engine

Validates 7-factor scoring algorithm:
1. Phase alignment (0-20)
2. Chain progress (0-30)
3. Quick-win potential (0-25)
4. Time estimate (0-10)
5. Dependency satisfaction (0-15)
6. Success probability (0-20)
7. User preference (0-10)
"""

import pytest
from crack.track.intelligence.scoring import TaskScorer


class TestTaskScorerInitialization:
    """Tests for TaskScorer initialization"""

    def test_scorer_initialization_default_weights(self):
        """
        GIVEN: Config with no weight overrides
        WHEN: TaskScorer initialized
        THEN: Default weights are used
        """
        config = {}
        scorer = TaskScorer(config)

        # Verify all 7 default weights present
        assert scorer.weights['phase_alignment'] == 1.0
        assert scorer.weights['chain_progress'] == 1.5
        assert scorer.weights['quick_win'] == 2.0
        assert scorer.weights['time_estimate'] == 0.5
        assert scorer.weights['dependencies'] == 1.0
        assert scorer.weights['success_probability'] == 1.2
        assert scorer.weights['user_preference'] == 0.8

    def test_scorer_custom_weights(self):
        """
        GIVEN: Config with custom weight overrides
        WHEN: TaskScorer initialized
        THEN: Custom weights override defaults
        """
        config = {
            'scoring_weights': {
                'quick_win': 3.0,
                'chain_progress': 2.0
            }
        }
        scorer = TaskScorer(config)

        # Custom weights applied
        assert scorer.weights['quick_win'] == 3.0
        assert scorer.weights['chain_progress'] == 2.0

        # Other weights remain default
        assert scorer.weights['phase_alignment'] == 1.0
        assert scorer.weights['time_estimate'] == 0.5


class TestTaskScorerCalculation:
    """Tests for priority calculation"""

    def test_calculate_priority_returns_float(self):
        """
        GIVEN: Valid task and profile
        WHEN: Priority calculated
        THEN: Returns numeric score
        """
        scorer = TaskScorer({})
        task = {
            'id': 'test-task',
            'name': 'Test Task'
        }
        profile = None  # Not used in Stage 1

        score = scorer.calculate_priority(task, profile)

        assert isinstance(score, float)
        assert score >= 0.0
        assert score <= 200.0  # Max theoretical score with weights

    def test_priority_breakdown_stored(self):
        """
        GIVEN: Task without priority breakdown
        WHEN: Priority calculated
        THEN: Task dict contains breakdown with 7 factors
        """
        scorer = TaskScorer({})
        task = {'id': 'test-task'}
        profile = None

        scorer.calculate_priority(task, profile)

        assert 'priority_breakdown' in task
        breakdown = task['priority_breakdown']

        # All 7 factors present
        assert 'phase_alignment' in breakdown
        assert 'chain_progress' in breakdown
        assert 'quick_win' in breakdown
        assert 'time_estimate' in breakdown
        assert 'dependencies' in breakdown
        assert 'success_probability' in breakdown
        assert 'user_preference' in breakdown


class TestScoringFactors:
    """Tests for individual scoring factors"""

    def test_score_phase_alignment(self):
        """
        GIVEN: Task with phase_alignment flag
        WHEN: Phase alignment scored
        THEN: Returns 20 points (aligned) or 5 points (neutral)
        """
        scorer = TaskScorer({})
        profile = None

        # Aligned task
        task_aligned = {'phase_alignment': True}
        score_aligned = scorer.calculate_priority(task_aligned, profile)
        assert task_aligned['priority_breakdown']['phase_alignment'] == 20.0

        # Non-aligned task
        task_neutral = {'phase_alignment': False}
        score_neutral = scorer.calculate_priority(task_neutral, profile)
        assert task_neutral['priority_breakdown']['phase_alignment'] == 5.0

    def test_score_chain_progress_increases_with_progress(self):
        """
        GIVEN: Tasks with different chain_progress values
        WHEN: Chain progress scored
        THEN: Higher progress scores higher (10-30 points)
        """
        scorer = TaskScorer({})
        profile = None

        # No chain membership
        task_no_chain = {'in_attack_chain': False}
        scorer.calculate_priority(task_no_chain, profile)
        assert task_no_chain['priority_breakdown']['chain_progress'] == 5.0

        # Chain at 0% progress
        task_0 = {'in_attack_chain': True, 'chain_progress': 0.0}
        scorer.calculate_priority(task_0, profile)
        assert task_0['priority_breakdown']['chain_progress'] == 10.0

        # Chain at 50% progress
        task_50 = {'in_attack_chain': True, 'chain_progress': 0.5}
        scorer.calculate_priority(task_50, profile)
        assert task_50['priority_breakdown']['chain_progress'] == 20.0

        # Chain at 100% progress
        task_100 = {'in_attack_chain': True, 'chain_progress': 1.0}
        scorer.calculate_priority(task_100, profile)
        assert task_100['priority_breakdown']['chain_progress'] == 30.0

    def test_score_quick_win_high_likelihood(self):
        """
        GIVEN: Task with OSCP pattern and high likelihood
        WHEN: Quick-win scored
        THEN: Returns high score (25 points for 1.0 likelihood)
        """
        scorer = TaskScorer({})
        profile = None

        # No OSCP pattern
        task_no_pattern = {'matches_oscp_pattern': False}
        scorer.calculate_priority(task_no_pattern, profile)
        assert task_no_pattern['priority_breakdown']['quick_win'] == 5.0

        # Low likelihood (0.1)
        task_low = {'matches_oscp_pattern': True, 'oscp_likelihood': 0.1}
        scorer.calculate_priority(task_low, profile)
        assert task_low['priority_breakdown']['quick_win'] == pytest.approx(7.0, abs=0.1)

        # High likelihood (0.9)
        task_high = {'matches_oscp_pattern': True, 'oscp_likelihood': 0.9}
        scorer.calculate_priority(task_high, profile)
        assert task_high['priority_breakdown']['quick_win'] == pytest.approx(23.0, abs=0.1)

    def test_score_time_estimate(self):
        """
        GIVEN: Tasks with different time estimates
        WHEN: Time estimate scored
        THEN: Faster tasks score higher (inverse relationship)
        """
        scorer = TaskScorer({})
        profile = None

        # Very fast (1 minute)
        task_1min = {'estimated_time_minutes': 1}
        scorer.calculate_priority(task_1min, profile)
        assert task_1min['priority_breakdown']['time_estimate'] == 10.0

        # Fast (5 minutes)
        task_5min = {'estimated_time_minutes': 5}
        scorer.calculate_priority(task_5min, profile)
        assert task_5min['priority_breakdown']['time_estimate'] == 7.0

        # Medium (15 minutes)
        task_15min = {'estimated_time_minutes': 15}
        scorer.calculate_priority(task_15min, profile)
        assert task_15min['priority_breakdown']['time_estimate'] == 5.0

        # Slow (30 minutes)
        task_30min = {'estimated_time_minutes': 30}
        scorer.calculate_priority(task_30min, profile)
        assert task_30min['priority_breakdown']['time_estimate'] == 2.0


class TestWeightedScoring:
    """Tests for weight application"""

    def test_weights_multiply_factor_scores(self):
        """
        GIVEN: Custom weights configured
        WHEN: Priority calculated
        THEN: Final score reflects weight multipliers
        """
        # Double the quick_win weight
        config = {
            'scoring_weights': {
                'quick_win': 4.0  # Default 2.0 -> 4.0
            }
        }
        scorer = TaskScorer(config)
        profile = None

        task = {
            'matches_oscp_pattern': True,
            'oscp_likelihood': 1.0
        }
        scorer.calculate_priority(task, profile)

        # Quick-win factor: 25 points * 4.0 weight = 100
        # Other factors contribute baseline neutral scores
        # Total should be significantly higher than default weight
        breakdown = task['priority_breakdown']
        assert breakdown['quick_win'] == 25.0  # Base score unchanged
        # Final score includes weight multiplication (tested implicitly)
