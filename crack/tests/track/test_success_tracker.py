"""
Tests for track/intelligence/success_tracker.py - Task outcome tracking

Validates success tracking for pattern learning:
- Task outcome recording
- Chain completion tracking
- Success rate calculations
- Average time tracking
- Pattern statistics
- Persistence
"""

import pytest
from crack.track.core.state import TargetProfile
from crack.track.intelligence.success_tracker import SuccessTracker


class TestSuccessTrackerInitialization:
    """Tests for SuccessTracker initialization and persistence"""

    def test_initialization_with_new_profile(self, temp_crack_home):
        """
        GIVEN: New profile without tracker data
        WHEN: SuccessTracker initialized
        THEN: Empty data structures created
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        assert tracker.task_outcomes == {}
        assert tracker.chain_completions == {}
        assert tracker.pattern_success == {}

    def test_initialization_loads_existing_data(self, temp_crack_home):
        """
        GIVEN: Profile with existing tracker data
        WHEN: SuccessTracker initialized
        THEN: Existing data loaded from profile
        """
        profile = TargetProfile("192.168.45.100")

        # Pre-populate profile with tracker data
        profile.metadata['success_tracker'] = {
            'task_outcomes': {
                'task-1': [{'success': True, 'time_taken': 10.0}]
            },
            'chain_completions': {},
            'pattern_success': {}
        }

        tracker = SuccessTracker(profile)

        assert 'task-1' in tracker.task_outcomes
        assert len(tracker.task_outcomes['task-1']) == 1


class TestTaskOutcomeRecording:
    """Tests for recording task outcomes"""

    def test_record_task_outcome_persists_data(self, temp_crack_home):
        """
        GIVEN: SuccessTracker initialized
        WHEN: Task outcome recorded
        THEN: Outcome saved to profile metadata
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        tracker.record_task_outcome('test-task', success=True, time_taken=5.0)

        # Verify persistence
        assert 'success_tracker' in profile.metadata
        assert 'test-task' in profile.metadata['success_tracker']['task_outcomes']

    def test_record_multiple_outcomes_for_same_task(self, temp_crack_home):
        """
        GIVEN: Task executed multiple times
        WHEN: Outcomes recorded
        THEN: All outcomes stored as list
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        tracker.record_task_outcome('test-task', success=True, time_taken=5.0)
        tracker.record_task_outcome('test-task', success=False, time_taken=3.0)
        tracker.record_task_outcome('test-task', success=True, time_taken=4.0)

        outcomes = tracker.task_outcomes['test-task']
        assert len(outcomes) == 3
        assert outcomes[0]['success'] is True
        assert outcomes[1]['success'] is False
        assert outcomes[2]['success'] is True

    def test_record_task_outcome_with_metadata(self, temp_crack_home):
        """
        GIVEN: Task with category metadata
        WHEN: Outcome recorded with metadata
        THEN: Metadata stored in outcome
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        metadata = {'category': 'enumeration', 'source': 'nmap'}
        tracker.record_task_outcome('test-task', success=True, time_taken=5.0, metadata=metadata)

        outcome = tracker.task_outcomes['test-task'][0]
        assert outcome['metadata']['category'] == 'enumeration'
        assert outcome['metadata']['source'] == 'nmap'


class TestChainCompletionTracking:
    """Tests for tracking attack chain completions"""

    def test_record_chain_completion(self, temp_crack_home):
        """
        GIVEN: Attack chain executed
        WHEN: Completion recorded
        THEN: Completion rate calculated and stored
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        tracker.record_chain_completion('smb-chain', steps_completed=2, total_steps=4, total_time=30.0)

        completion = tracker.chain_completions['smb-chain'][0]
        assert completion['steps_completed'] == 2
        assert completion['total_steps'] == 4
        assert completion['completion_rate'] == 0.5
        assert completion['total_time'] == 30.0

    def test_record_multiple_chain_attempts(self, temp_crack_home):
        """
        GIVEN: Chain executed multiple times
        WHEN: Completions recorded
        THEN: All attempts tracked
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        tracker.record_chain_completion('test-chain', 2, 5, 20.0)
        tracker.record_chain_completion('test-chain', 4, 5, 35.0)
        tracker.record_chain_completion('test-chain', 5, 5, 40.0)

        completions = tracker.chain_completions['test-chain']
        assert len(completions) == 3
        assert completions[0]['completion_rate'] == 0.4
        assert completions[1]['completion_rate'] == 0.8
        assert completions[2]['completion_rate'] == 1.0


class TestSuccessRateCalculation:
    """Tests for success rate calculations"""

    def test_success_rate_task_pattern(self, temp_crack_home):
        """
        GIVEN: Task with mixed success outcomes
        WHEN: Success rate calculated
        THEN: Correct percentage returned
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        # 3 successes, 2 failures = 60%
        tracker.record_task_outcome('test-task', True, 5.0)
        tracker.record_task_outcome('test-task', True, 4.0)
        tracker.record_task_outcome('test-task', False, 3.0)
        tracker.record_task_outcome('test-task', True, 6.0)
        tracker.record_task_outcome('test-task', False, 2.0)

        success_rate = tracker.get_success_rate('test-task', 'task')
        assert success_rate == 0.6

    def test_success_rate_no_history_defaults_to_half(self, temp_crack_home):
        """
        GIVEN: Task with no execution history
        WHEN: Success rate calculated
        THEN: Default 0.5 returned
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        success_rate = tracker.get_success_rate('unknown-task', 'task')
        assert success_rate == 0.5

    def test_success_rate_chain_pattern(self, temp_crack_home):
        """
        GIVEN: Chain with multiple completions
        WHEN: Success rate calculated
        THEN: Average completion rate returned
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        tracker.record_chain_completion('test-chain', 2, 5, 20.0)  # 0.4
        tracker.record_chain_completion('test-chain', 4, 5, 30.0)  # 0.8
        tracker.record_chain_completion('test-chain', 5, 5, 35.0)  # 1.0

        success_rate = tracker.get_success_rate('test-chain', 'chain')
        assert success_rate == pytest.approx(0.733, abs=0.01)

    def test_success_rate_category_pattern(self, temp_crack_home):
        """
        GIVEN: Multiple tasks in same category
        WHEN: Category success rate calculated
        THEN: Aggregated success rate returned
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        metadata_enum = {'category': 'enumeration'}
        tracker.record_task_outcome('task-1', True, 5.0, metadata_enum)
        tracker.record_task_outcome('task-2', False, 3.0, metadata_enum)
        tracker.record_task_outcome('task-3', True, 4.0, metadata_enum)
        tracker.record_task_outcome('task-4', True, 6.0, metadata_enum)

        success_rate = tracker.get_success_rate('enumeration', 'category')
        assert success_rate == 0.75


class TestAverageTimeTracking:
    """Tests for average execution time calculations"""

    def test_average_time_calculation(self, temp_crack_home):
        """
        GIVEN: Task with multiple executions
        WHEN: Average time calculated
        THEN: Correct average returned
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        tracker.record_task_outcome('test-task', True, 10.0)
        tracker.record_task_outcome('test-task', True, 20.0)
        tracker.record_task_outcome('test-task', False, 15.0)

        avg_time = tracker.get_average_time('test-task')
        assert avg_time == 15.0

    def test_average_time_no_history_returns_zero(self, temp_crack_home):
        """
        GIVEN: Task with no executions
        WHEN: Average time calculated
        THEN: Zero returned
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        avg_time = tracker.get_average_time('unknown-task')
        assert avg_time == 0.0


class TestPatternStatistics:
    """Tests for comprehensive pattern statistics"""

    def test_pattern_statistics_task(self, temp_crack_home):
        """
        GIVEN: Task with execution history
        WHEN: Pattern statistics retrieved
        THEN: Complete stats returned
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        tracker.record_task_outcome('test-task', True, 10.0)
        tracker.record_task_outcome('test-task', False, 5.0)
        tracker.record_task_outcome('test-task', True, 15.0)

        stats = tracker.get_pattern_statistics('test-task', 'task')

        assert stats['pattern'] == 'test-task'
        assert stats['pattern_type'] == 'task'
        assert stats['success_rate'] == pytest.approx(0.667, abs=0.01)
        assert stats['average_time'] == 10.0
        assert stats['sample_count'] == 3

    def test_pattern_statistics_chain(self, temp_crack_home):
        """
        GIVEN: Chain with completion history
        WHEN: Pattern statistics retrieved
        THEN: Chain stats returned
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        tracker.record_chain_completion('test-chain', 3, 5, 20.0)
        tracker.record_chain_completion('test-chain', 5, 5, 30.0)

        stats = tracker.get_pattern_statistics('test-chain', 'chain')

        assert stats['pattern'] == 'test-chain'
        assert stats['pattern_type'] == 'chain'
        assert stats['success_rate'] == 0.8
        assert stats['sample_count'] == 2

    def test_pattern_statistics_category(self, temp_crack_home):
        """
        GIVEN: Multiple tasks in category
        WHEN: Category statistics retrieved
        THEN: Aggregated stats returned
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        metadata = {'category': 'web'}
        tracker.record_task_outcome('task-1', True, 5.0, metadata)
        tracker.record_task_outcome('task-2', True, 10.0, metadata)
        tracker.record_task_outcome('task-3', False, 3.0, metadata)

        stats = tracker.get_pattern_statistics('web', 'category')

        assert stats['pattern'] == 'web'
        assert stats['pattern_type'] == 'category'
        assert stats['success_rate'] == pytest.approx(0.667, abs=0.01)
        assert stats['sample_count'] == 3


class TestPersistence:
    """Tests for data persistence"""

    def test_persistence_survives_reload(self, temp_crack_home):
        """
        GIVEN: Tracker with recorded outcomes
        WHEN: Profile saved and reloaded
        THEN: Tracker data persists
        """
        profile = TargetProfile("192.168.45.100")
        tracker = SuccessTracker(profile)

        tracker.record_task_outcome('test-task', True, 10.0)
        tracker.record_chain_completion('test-chain', 2, 3, 15.0)

        # Save profile
        profile.save()

        # Reload profile
        reloaded_profile = TargetProfile.load("192.168.45.100")
        reloaded_tracker = SuccessTracker(reloaded_profile)

        # Verify data persisted
        assert 'test-task' in reloaded_tracker.task_outcomes
        assert 'test-chain' in reloaded_tracker.chain_completions
        assert len(reloaded_tracker.task_outcomes['test-task']) == 1
        assert reloaded_tracker.chain_completions['test-chain'][0]['completion_rate'] == pytest.approx(0.667, abs=0.01)
