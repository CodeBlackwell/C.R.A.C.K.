"""
Tests for Lockout Manager

Business Value Focus:
- Prevent account lockouts during password spraying
- Policy-aware timing calculations
- Safe spray planning

Test Priority: TIER 1 - CRITICAL (Operational Safety)
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import MagicMock, patch
from tools.post.bloodtrail.autospray.lockout_manager import (
    LockoutManager,
    SprayWindow,
)


# =============================================================================
# SprayWindow Tests
# =============================================================================

class TestSprayWindow:
    """Tests for SprayWindow dataclass"""

    def test_basic_creation(self):
        """
        BV: Create SprayWindow with required fields

        Scenario:
          Given: Round info and passwords
          When: Creating SprayWindow
          Then: Object created with fields
        """
        window = SprayWindow(
            round_number=1,
            passwords=["Password1", "Password2"],
            max_attempts=3,
            delay_seconds=1800,
        )

        assert window.round_number == 1
        assert window.max_attempts == 3
        assert window.delay_seconds == 1800

    def test_password_count_property(self):
        """
        BV: Password count calculated correctly

        Scenario:
          Given: SprayWindow with 3 passwords
          When: Getting password_count
          Then: Returns 3
        """
        window = SprayWindow(
            round_number=1,
            passwords=["P1", "P2", "P3"],
            max_attempts=5,
            delay_seconds=0,
        )

        assert window.password_count == 3

    def test_mark_started(self):
        """
        BV: Mark round as started

        Scenario:
          Given: SprayWindow
          When: Calling mark_started()
          Then: start_time set
        """
        window = SprayWindow(
            round_number=1,
            passwords=["P1"],
            max_attempts=5,
            delay_seconds=0,
        )

        assert window.start_time is None
        window.mark_started()
        assert window.start_time is not None
        assert isinstance(window.start_time, datetime)

    def test_mark_completed(self):
        """
        BV: Mark round as completed

        Scenario:
          Given: SprayWindow
          When: Calling mark_completed()
          Then: end_time set
        """
        window = SprayWindow(
            round_number=1,
            passwords=["P1"],
            max_attempts=5,
            delay_seconds=0,
        )

        assert window.end_time is None
        window.mark_completed()
        assert window.end_time is not None
        assert isinstance(window.end_time, datetime)

    def test_times_optional(self):
        """
        BV: start/end times optional

        Scenario:
          Given: New SprayWindow
          When: Checking times
          Then: Both None
        """
        window = SprayWindow(
            round_number=1,
            passwords=["P1"],
            max_attempts=5,
            delay_seconds=0,
        )

        assert window.start_time is None
        assert window.end_time is None


# =============================================================================
# LockoutManager Initialization Tests
# =============================================================================

class TestLockoutManagerInit:
    """Tests for LockoutManager initialization"""

    def test_default_values(self):
        """
        BV: Default safety margin

        Scenario:
          Given: New LockoutManager
          When: Checking defaults
          Then: safety_margin is 2
        """
        manager = LockoutManager()

        assert manager.safety_margin == 2
        assert manager.override_mode is False

    def test_with_policy(self):
        """
        BV: Initialize with policy

        Scenario:
          Given: Mock policy
          When: Creating LockoutManager
          Then: Uses policy values
        """
        policy = MagicMock()
        policy.lockout_threshold = 5
        policy.observation_window = 30

        manager = LockoutManager(policy=policy)

        assert manager.lockout_threshold == 5
        assert manager.observation_window_minutes == 30

    def test_manual_override(self):
        """
        BV: Manual values override policy

        Scenario:
          Given: Policy and manual values
          When: Creating LockoutManager
          Then: Manual values used
        """
        policy = MagicMock()
        policy.lockout_threshold = 5
        policy.observation_window = 30

        manager = LockoutManager(
            policy=policy,
            manual_threshold=3,
            manual_window_minutes=15,
        )

        assert manager.lockout_threshold == 3
        assert manager.observation_window_minutes == 15


# =============================================================================
# Safe Attempts Tests
# =============================================================================

class TestSafeAttempts:
    """Tests for safe_attempts calculation"""

    def test_safe_attempts_with_threshold(self):
        """
        BV: Calculate safe attempts from threshold

        Scenario:
          Given: Threshold of 5, margin of 2
          When: Getting safe_attempts
          Then: Returns 3 (5-2)
        """
        manager = LockoutManager(
            manual_threshold=5,
            safety_margin=2,
        )

        assert manager.safe_attempts == 3

    def test_safe_attempts_no_lockout(self):
        """
        BV: No lockout returns 999

        Scenario:
          Given: Threshold of 0
          When: Getting safe_attempts
          Then: Returns 999
        """
        manager = LockoutManager(manual_threshold=0)

        assert manager.safe_attempts == 999

    def test_safe_attempts_minimum_1(self):
        """
        BV: Safe attempts minimum is 1

        Scenario:
          Given: Threshold of 2, margin of 2
          When: Getting safe_attempts
          Then: Returns 1 (not 0)
        """
        manager = LockoutManager(
            manual_threshold=2,
            safety_margin=2,
        )

        assert manager.safe_attempts == 1

    def test_safe_attempts_override_mode(self):
        """
        BV: Override mode returns 999

        Scenario:
          Given: Override mode enabled
          When: Getting safe_attempts
          Then: Returns 999
        """
        manager = LockoutManager(
            manual_threshold=5,
            override_mode=True,
        )

        assert manager.safe_attempts == 999


# =============================================================================
# Delay Tests
# =============================================================================

class TestDelayCalculation:
    """Tests for delay_seconds calculation"""

    def test_delay_from_window(self):
        """
        BV: Delay from observation window

        Scenario:
          Given: 30 minute window
          When: Getting delay_seconds
          Then: Returns 1800 (30*60)
        """
        manager = LockoutManager(manual_window_minutes=30)

        assert manager.delay_seconds == 1800

    def test_delay_override_mode(self):
        """
        BV: Override mode has no delay

        Scenario:
          Given: Override mode
          When: Getting delay_seconds
          Then: Returns 0
        """
        manager = LockoutManager(
            manual_window_minutes=30,
            override_mode=True,
        )

        assert manager.delay_seconds == 0


# =============================================================================
# Can Spray Tests
# =============================================================================

class TestCanSpray:
    """Tests for can_spray method"""

    def test_can_spray_first_time(self):
        """
        BV: Can spray on first call

        Scenario:
          Given: Fresh manager
          When: Calling can_spray()
          Then: Returns (True, 0)
        """
        manager = LockoutManager(manual_threshold=5)

        can, wait = manager.can_spray()

        assert can is True
        assert wait == 0

    def test_can_spray_override_mode(self):
        """
        BV: Override mode always allows spray

        Scenario:
          Given: Override mode after spray
          When: Calling can_spray()
          Then: Returns (True, 0)
        """
        manager = LockoutManager(
            manual_threshold=5,
            override_mode=True,
        )
        manager.record_spray_round()

        can, wait = manager.can_spray()

        assert can is True
        assert wait == 0

    def test_cannot_spray_immediately(self):
        """
        BV: Must wait after spray round

        Scenario:
          Given: Just sprayed
          When: Calling can_spray()
          Then: Returns (False, seconds)
        """
        manager = LockoutManager(
            manual_threshold=5,
            manual_window_minutes=30,
        )
        manager.record_spray_round()

        can, wait = manager.can_spray()

        assert can is False
        assert wait > 0
        assert wait <= 1800

    def test_can_spray_after_delay(self):
        """
        BV: Can spray after delay elapsed

        Scenario:
          Given: Delay has passed
          When: Calling can_spray()
          Then: Returns (True, 0)
        """
        manager = LockoutManager(
            manual_threshold=5,
            manual_window_minutes=1,  # 1 minute window
        )

        # Simulate spray 2 minutes ago
        manager._last_spray_time = datetime.now() - timedelta(minutes=2)

        can, wait = manager.can_spray()

        assert can is True
        assert wait == 0


# =============================================================================
# Spray Plan Tests
# =============================================================================

class TestSprayPlan:
    """Tests for get_spray_plan method"""

    def test_single_round_plan(self):
        """
        BV: Single round for few passwords

        Scenario:
          Given: 2 passwords, 5 safe attempts
          When: Getting spray plan
          Then: Returns 1 round
        """
        manager = LockoutManager(
            manual_threshold=7,  # safe_attempts = 5
            safety_margin=2,
        )

        plan = manager.get_spray_plan(["P1", "P2"])

        assert len(plan) == 1
        assert plan[0].password_count == 2

    def test_multiple_rounds_plan(self):
        """
        BV: Multiple rounds for many passwords

        Scenario:
          Given: 10 passwords, 3 safe attempts
          When: Getting spray plan
          Then: Returns 4 rounds
        """
        manager = LockoutManager(
            manual_threshold=5,  # safe_attempts = 3
            safety_margin=2,
        )

        passwords = [f"P{i}" for i in range(10)]
        plan = manager.get_spray_plan(passwords)

        assert len(plan) == 4  # ceil(10/3) = 4 rounds

    def test_last_round_no_delay(self):
        """
        BV: Last round has no delay

        Scenario:
          Given: Plan with multiple rounds
          When: Checking last round
          Then: delay_seconds is 0
        """
        manager = LockoutManager(
            manual_threshold=4,
            manual_window_minutes=30,
        )

        passwords = [f"P{i}" for i in range(5)]
        plan = manager.get_spray_plan(passwords)

        # First round has delay
        assert plan[0].delay_seconds > 0

        # Last round has no delay
        assert plan[-1].delay_seconds == 0

    def test_empty_passwords(self):
        """
        BV: Empty passwords returns empty plan

        Scenario:
          Given: Empty password list
          When: Getting spray plan
          Then: Returns empty list
        """
        manager = LockoutManager(manual_threshold=5)

        plan = manager.get_spray_plan([])

        assert plan == []


# =============================================================================
# Estimated Duration Tests
# =============================================================================

class TestEstimatedDuration:
    """Tests for get_estimated_duration method"""

    def test_duration_with_delays(self):
        """
        BV: Include delay time in duration

        Scenario:
          Given: 10 passwords, 3 safe attempts, 30 min window
          When: Getting estimated duration
          Then: Includes delays
        """
        manager = LockoutManager(
            manual_threshold=5,  # safe_attempts = 3
            manual_window_minutes=30,
        )

        duration = manager.get_estimated_duration(10)

        # 4 rounds, 3 delays of 30 min each = 90 min + spray time
        assert duration.total_seconds() > 0
        assert duration.total_seconds() >= 90 * 60

    def test_duration_override_mode(self):
        """
        BV: Override mode has no duration

        Scenario:
          Given: Override mode
          When: Getting duration
          Then: Returns 0
        """
        manager = LockoutManager(
            manual_threshold=5,
            override_mode=True,
        )

        duration = manager.get_estimated_duration(10)

        assert duration.total_seconds() == 0

    def test_duration_no_passwords(self):
        """
        BV: No passwords = no duration

        Scenario:
          Given: 0 passwords
          When: Getting duration
          Then: Returns 0
        """
        manager = LockoutManager(manual_threshold=5)

        duration = manager.get_estimated_duration(0)

        assert duration.total_seconds() == 0


# =============================================================================
# Format Display Tests
# =============================================================================

class TestFormatDisplay:
    """Tests for format_plan_display method"""

    def test_format_includes_basics(self):
        """
        BV: Display includes key info

        Scenario:
          Given: Spray plan
          When: Formatting display
          Then: Includes passwords, users, threshold
        """
        manager = LockoutManager(
            manual_threshold=5,
            manual_window_minutes=30,
        )

        output = manager.format_plan_display(["P1", "P2"], user_count=10)

        assert "Total passwords:" in output
        assert "Target users:" in output
        assert "Lockout threshold:" in output
        assert "Safe per round:" in output

    def test_format_shows_rounds(self):
        """
        BV: Display shows each round

        Scenario:
          Given: Plan with 2 rounds
          When: Formatting display
          Then: Shows Round 1 and Round 2
        """
        manager = LockoutManager(
            manual_threshold=3,
            manual_window_minutes=30,
        )

        output = manager.format_plan_display(["P1", "P2", "P3", "P4"], user_count=5)

        assert "Round 1" in output
        assert "Round 2" in output

    def test_format_empty_passwords(self):
        """
        BV: Empty passwords message

        Scenario:
          Given: Empty password list
          When: Formatting display
          Then: Shows message
        """
        manager = LockoutManager(manual_threshold=5)

        output = manager.format_plan_display([], user_count=5)

        assert "No passwords to spray" in output

    def test_format_override_warning(self):
        """
        BV: Override mode shows warning

        Scenario:
          Given: Override mode
          When: Formatting display
          Then: Shows warning
        """
        manager = LockoutManager(
            manual_threshold=5,
            override_mode=True,
        )

        output = manager.format_plan_display(["P1"], user_count=5)

        assert "WARNING" in output
        assert "override" in output.lower()


# =============================================================================
# State Management Tests
# =============================================================================

class TestStateManagement:
    """Tests for state management"""

    def test_record_spray_round(self):
        """
        BV: Recording increments round

        Scenario:
          Given: Manager with no sprays
          When: Recording spray round
          Then: Round counter increments
        """
        manager = LockoutManager(manual_threshold=5)

        assert manager._current_round == 0

        manager.record_spray_round()

        assert manager._current_round == 1
        assert len(manager._spray_history) == 1

    def test_reset_clears_state(self):
        """
        BV: Reset clears all state

        Scenario:
          Given: Manager with spray history
          When: Calling reset()
          Then: State cleared
        """
        manager = LockoutManager(manual_threshold=5)
        manager.record_spray_round()
        manager.record_spray_round()

        assert manager._current_round == 2

        manager.reset()

        assert manager._current_round == 0
        assert len(manager._spray_history) == 0
        assert manager._last_spray_time is None

    def test_has_policy_true(self):
        """
        BV: has_policy when threshold > 0

        Scenario:
          Given: Manager with threshold
          When: Checking has_policy
          Then: Returns True
        """
        manager = LockoutManager(manual_threshold=5)

        assert manager.has_policy is True

    def test_has_policy_false(self):
        """
        BV: has_policy when no threshold

        Scenario:
          Given: Manager with threshold=0
          When: Checking has_policy
          Then: Returns False
        """
        manager = LockoutManager(manual_threshold=0)

        assert manager.has_policy is False


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Edge case handling tests"""

    def test_threshold_1(self):
        """
        BV: Threshold of 1 is valid

        Scenario:
          Given: Threshold of 1
          When: Getting safe_attempts
          Then: Returns 1 (minimum)
        """
        manager = LockoutManager(
            manual_threshold=1,
            safety_margin=2,
        )

        assert manager.safe_attempts == 1

    def test_large_password_list(self):
        """
        BV: Handle large password list

        Scenario:
          Given: 1000 passwords
          When: Getting spray plan
          Then: Creates many rounds without error
        """
        manager = LockoutManager(
            manual_threshold=5,
            manual_window_minutes=30,
        )

        passwords = [f"P{i}" for i in range(1000)]
        plan = manager.get_spray_plan(passwords)

        # With safe_attempts=3, should be ~334 rounds
        assert len(plan) > 300
        assert len(plan) < 400

    def test_no_policy_defaults(self):
        """
        BV: No policy uses defaults

        Scenario:
          Given: Manager with no policy or manual
          When: Checking values
          Then: Uses defaults
        """
        manager = LockoutManager()

        assert manager.lockout_threshold == 0
        assert manager.observation_window_minutes == 30
        assert manager.safe_attempts == 999
