"""
Tests for track/intelligence/pattern_analyzer.py - Pattern detection and weight optimization

Validates pattern analysis for adaptive scoring:
- User preference analysis
- Successful pattern detection
- Scoring weight auto-tuning
- Weight normalization
- Insight generation
"""

import pytest
from crack.track.core.state import TargetProfile
from crack.track.intelligence.success_tracker import SuccessTracker
from crack.track.intelligence.pattern_analyzer import PatternAnalyzer


class TestPatternAnalyzerInitialization:
    """Tests for PatternAnalyzer initialization"""

    def test_initialization_loads_weights_from_config(self, temp_crack_home):
        """
        GIVEN: Config with custom scoring weights
        WHEN: PatternAnalyzer initialized
        THEN: Weights loaded from config
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        config = {
            'intelligence': {
                'scoring_weights': {
                    'phase_alignment': 1.5,
                    'quick_win': 3.0
                }
            }
        }

        analyzer = PatternAnalyzer(tracker, config)

        assert analyzer.weights['phase_alignment'] == 1.5
        assert analyzer.weights['quick_win'] == 3.0

    def test_initialization_uses_defaults_if_no_config(self, temp_crack_home):
        """
        GIVEN: Empty config
        WHEN: PatternAnalyzer initialized
        THEN: Default weights used
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        config = {}
        analyzer = PatternAnalyzer(tracker, config)

        assert analyzer.weights == PatternAnalyzer.DEFAULT_WEIGHTS


class TestUserPreferenceAnalysis:
    """Tests for user preference analysis"""

    def test_analyze_user_preferences_calculates_category_scores(self, temp_crack_home):
        """
        GIVEN: Tasks with different categories
        WHEN: User preferences analyzed
        THEN: Preference scores calculated (frequency + success)
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        # Category 'web': 3 tasks, 2 successes (66%)
        tracker.record_task_outcome('web-1', True, 5.0, {'category': 'web'})
        tracker.record_task_outcome('web-2', False, 3.0, {'category': 'web'})
        tracker.record_task_outcome('web-3', True, 4.0, {'category': 'web'})

        # Category 'smb': 2 tasks, 2 successes (100%)
        tracker.record_task_outcome('smb-1', True, 10.0, {'category': 'smb'})
        tracker.record_task_outcome('smb-2', True, 8.0, {'category': 'smb'})

        config = {}
        analyzer = PatternAnalyzer(tracker, config)

        preferences = analyzer.analyze_user_preferences()

        # Web has higher frequency (3 vs 2), SMB has higher success (100% vs 66%)
        assert 'web' in preferences
        assert 'smb' in preferences
        assert 0 < preferences['web'] <= 1.0
        assert 0 < preferences['smb'] <= 1.0

    def test_analyze_user_preferences_empty_history(self, temp_crack_home):
        """
        GIVEN: No task history
        WHEN: User preferences analyzed
        THEN: Empty dict returned
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        config = {}
        analyzer = PatternAnalyzer(tracker, config)

        preferences = analyzer.analyze_user_preferences()

        assert preferences == {}


class TestSuccessfulPatternDetection:
    """Tests for pattern detection"""

    def test_detect_successful_patterns_finds_high_success_tasks(self, temp_crack_home):
        """
        GIVEN: Tasks with 70%+ success rate
        WHEN: Patterns detected
        THEN: High-success tasks identified
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        # Task with 75% success (3/4)
        tracker.record_task_outcome('high-success-task', True, 5.0)
        tracker.record_task_outcome('high-success-task', True, 6.0)
        tracker.record_task_outcome('high-success-task', False, 4.0)
        tracker.record_task_outcome('high-success-task', True, 5.5)

        config = {}
        analyzer = PatternAnalyzer(tracker, config)

        patterns = analyzer.detect_successful_patterns(min_samples=3)

        assert len(patterns) == 1
        assert patterns[0]['pattern_id'] == 'high-success-task'
        assert patterns[0]['pattern_type'] == 'task'
        assert patterns[0]['success_rate'] == 0.75
        assert patterns[0]['sample_count'] == 4

    def test_detect_successful_patterns_finds_high_completion_chains(self, temp_crack_home):
        """
        GIVEN: Chains with 60%+ completion rate
        WHEN: Patterns detected
        THEN: High-completion chains identified
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        # Chain with 70% average completion (0.6 + 0.8 + 0.7) / 3
        tracker.record_chain_completion('exploit-chain', 3, 5, 20.0)  # 60%
        tracker.record_chain_completion('exploit-chain', 4, 5, 25.0)  # 80%
        tracker.record_chain_completion('exploit-chain', 7, 10, 30.0)  # 70%

        config = {}
        analyzer = PatternAnalyzer(tracker, config)

        patterns = analyzer.detect_successful_patterns(min_samples=3)

        assert len(patterns) == 1
        assert patterns[0]['pattern_id'] == 'exploit-chain'
        assert patterns[0]['pattern_type'] == 'chain'
        assert patterns[0]['success_rate'] == pytest.approx(0.7, abs=0.01)

    def test_detect_successful_patterns_respects_min_samples(self, temp_crack_home):
        """
        GIVEN: Task with high success but insufficient samples
        WHEN: Patterns detected with min_samples=3
        THEN: Task not included in patterns
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        # Only 2 samples (below min_samples=3)
        tracker.record_task_outcome('low-sample-task', True, 5.0)
        tracker.record_task_outcome('low-sample-task', True, 6.0)

        config = {}
        analyzer = PatternAnalyzer(tracker, config)

        patterns = analyzer.detect_successful_patterns(min_samples=3)

        assert len(patterns) == 0

    def test_detect_successful_patterns_ignores_low_success(self, temp_crack_home):
        """
        GIVEN: Task with low success rate (<70%)
        WHEN: Patterns detected
        THEN: Task not included
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        # 50% success (2/4) - below 70% threshold
        tracker.record_task_outcome('low-success-task', True, 5.0)
        tracker.record_task_outcome('low-success-task', False, 6.0)
        tracker.record_task_outcome('low-success-task', True, 4.0)
        tracker.record_task_outcome('low-success-task', False, 5.5)

        config = {}
        analyzer = PatternAnalyzer(tracker, config)

        patterns = analyzer.detect_successful_patterns(min_samples=3)

        assert len(patterns) == 0


class TestScoringWeightUpdates:
    """Tests for automatic weight tuning"""

    def test_update_weights_increases_quick_win_for_high_success(self, temp_crack_home):
        """
        GIVEN: Quick-win tasks with >70% success
        WHEN: Weights updated
        THEN: quick_win weight increased (relative to other weights)
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        # Quick-win tasks with 80% success (4/5)
        for i in range(4):
            tracker.record_task_outcome(f'qw-{i}', True, 5.0, {'category': 'quick_win'})
        tracker.record_task_outcome('qw-4', False, 3.0, {'category': 'quick_win'})

        config = {}
        analyzer = PatternAnalyzer(tracker, config)

        # Calculate ratio before update
        original_ratio = analyzer.weights['quick_win'] / analyzer.weights['phase_alignment']
        updated_weights = analyzer.update_scoring_weights(learning_rate=0.1)
        new_ratio = updated_weights['quick_win'] / updated_weights['phase_alignment']

        # Ratio should increase (quick_win boosted relative to other weights)
        assert new_ratio > original_ratio

    def test_update_weights_decreases_quick_win_for_low_success(self, temp_crack_home):
        """
        GIVEN: Quick-win tasks with <40% success
        WHEN: Weights updated
        THEN: quick_win weight decreased
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        # Quick-win tasks with 20% success (1/5)
        tracker.record_task_outcome('qw-1', True, 5.0, {'category': 'quick_win'})
        for i in range(4):
            tracker.record_task_outcome(f'qw-{i+2}', False, 3.0, {'category': 'quick_win'})

        config = {}
        analyzer = PatternAnalyzer(tracker, config)

        original_weight = analyzer.weights['quick_win']
        updated_weights = analyzer.update_scoring_weights(learning_rate=0.1)

        assert updated_weights['quick_win'] < original_weight

    def test_update_weights_increases_chain_progress_for_high_completion(self, temp_crack_home):
        """
        GIVEN: Chains with >70% completion rate
        WHEN: Weights updated
        THEN: chain_progress weight increased (relative to other weights)
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        # Chains with high completion (all >70%)
        tracker.record_chain_completion('chain-1', 4, 5, 20.0)  # 80%
        tracker.record_chain_completion('chain-1', 4, 5, 22.0)  # 80%
        tracker.record_chain_completion('chain-1', 5, 5, 25.0)  # 100%

        config = {}
        analyzer = PatternAnalyzer(tracker, config)

        # Calculate ratio before update
        original_ratio = analyzer.weights['chain_progress'] / analyzer.weights['phase_alignment']
        updated_weights = analyzer.update_scoring_weights(learning_rate=0.1)
        new_ratio = updated_weights['chain_progress'] / updated_weights['phase_alignment']

        # Ratio should increase (chain_progress boosted relative to other weights)
        assert new_ratio > original_ratio

    def test_update_weights_increases_user_preference_for_high_variance(self, temp_crack_home):
        """
        GIVEN: User with strong category preferences (high variance)
        WHEN: Weights updated
        THEN: user_preference weight increased (relative to other weights)
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        # Strong preference for 'web' (many tasks, high success)
        for i in range(10):
            tracker.record_task_outcome(f'web-{i}', True, 5.0, {'category': 'web'})

        # Weak preference for 'smb' (few tasks)
        tracker.record_task_outcome('smb-1', True, 10.0, {'category': 'smb'})

        # Weak preference for 'ftp' (few tasks)
        tracker.record_task_outcome('ftp-1', False, 3.0, {'category': 'ftp'})

        config = {}
        analyzer = PatternAnalyzer(tracker, config)

        # Calculate ratio before update
        original_ratio = analyzer.weights['user_preference'] / analyzer.weights['phase_alignment']
        updated_weights = analyzer.update_scoring_weights(learning_rate=0.1)
        new_ratio = updated_weights['user_preference'] / updated_weights['phase_alignment']

        # Ratio should increase (user_preference boosted relative to other weights)
        assert new_ratio > original_ratio

    def test_update_weights_normalizes_to_prevent_runaway(self, temp_crack_home):
        """
        GIVEN: Weights updated multiple times
        WHEN: Normalization applied
        THEN: Weight sum remains ~7.0
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        # Create pattern that increases multiple weights
        for i in range(10):
            tracker.record_task_outcome(f'qw-{i}', True, 5.0, {'category': 'quick_win'})

        for i in range(3):
            tracker.record_chain_completion(f'chain-{i}', 5, 5, 20.0)

        config = {}
        analyzer = PatternAnalyzer(tracker, config)

        updated_weights = analyzer.update_scoring_weights(learning_rate=0.2)

        # Sum should be ~7.0 (normalized)
        weight_sum = sum(updated_weights.values())
        assert weight_sum == pytest.approx(7.0, abs=0.1)

    def test_update_weights_no_change_if_insignificant(self, temp_crack_home):
        """
        GIVEN: Insufficient data for weight changes
        WHEN: Weights updated
        THEN: Original weights returned (diff < 0.1)
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        # Minimal data - shouldn't trigger significant weight change
        tracker.record_task_outcome('test-1', True, 5.0, {'category': 'other'})

        config = {}
        analyzer = PatternAnalyzer(tracker, config)

        original_weights = analyzer.weights.copy()
        updated_weights = analyzer.update_scoring_weights(learning_rate=0.1)

        # Weights should remain unchanged
        assert updated_weights == original_weights


class TestPatternInsights:
    """Tests for comprehensive insight generation"""

    def test_get_pattern_insights_returns_comprehensive_analysis(self, temp_crack_home):
        """
        GIVEN: Tracker with task history
        WHEN: Pattern insights retrieved
        THEN: Complete analysis returned
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        # Add some task history
        tracker.record_task_outcome('web-1', True, 5.0, {'category': 'web'})
        tracker.record_task_outcome('web-2', True, 6.0, {'category': 'web'})
        tracker.record_task_outcome('web-3', True, 4.0, {'category': 'web'})

        config = {}
        analyzer = PatternAnalyzer(tracker, config)

        insights = analyzer.get_pattern_insights()

        assert 'user_preferences' in insights
        assert 'successful_patterns' in insights
        assert 'current_weights' in insights
        assert 'sample_count' in insights
        assert 'recommendations' in insights

        assert insights['sample_count'] == 3
        assert 'web' in insights['user_preferences']

    def test_get_pattern_insights_recommends_more_data_if_insufficient(self, temp_crack_home):
        """
        GIVEN: Tracker with <10 task outcomes
        WHEN: Pattern insights retrieved
        THEN: Recommendation to collect more data included
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        # Only 5 tasks
        for i in range(5):
            tracker.record_task_outcome(f'task-{i}', True, 5.0)

        config = {}
        analyzer = PatternAnalyzer(tracker, config)

        insights = analyzer.get_pattern_insights()

        assert any("more task data" in rec for rec in insights['recommendations'])

    def test_get_pattern_insights_highlights_top_pattern(self, temp_crack_home):
        """
        GIVEN: Multiple successful patterns
        WHEN: Pattern insights retrieved
        THEN: Top pattern highlighted in recommendations
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        # Pattern 1: 80% success
        for i in range(4):
            tracker.record_task_outcome('pattern-1', True, 5.0)
        tracker.record_task_outcome('pattern-1', False, 3.0)

        # Pattern 2: 100% success (top pattern)
        for i in range(3):
            tracker.record_task_outcome('pattern-2', True, 8.0)

        config = {}
        analyzer = PatternAnalyzer(tracker, config)

        insights = analyzer.get_pattern_insights()

        # Should recommend pattern-2 as top pattern (100% success)
        assert any("pattern-2" in rec and "100" in rec for rec in insights['recommendations'])
