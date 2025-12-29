"""
Tests for Password Policy Parser

Business Value Focus:
- Parse Windows 'net accounts' output for safe spraying
- Calculate safe spray parameters
- Handle edge cases in policy output

Test Priority: TIER 2 - HIGH (AD Security)
"""

import pytest
from tools.post.bloodtrail.policy_parser import (
    PasswordPolicy,
    parse_net_accounts,
    format_policy_display,
    _extract_int,
)


# =============================================================================
# Sample Net Accounts Output
# =============================================================================

NET_ACCOUNTS_STANDARD = """
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          1
Maximum password age (days):                          42
Minimum password length:                              7
Length of password history maintained:                24
Lockout threshold:                                    5
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        PRIMARY
The command completed successfully.
"""

NET_ACCOUNTS_NO_LOCKOUT = """
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          0
Maximum password age (days):                          Unlimited
Minimum password length:                              0
Length of password history maintained:                None
Lockout threshold:                                    Never
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        SERVER
The command completed successfully.
"""

NET_ACCOUNTS_STRICT = """
Force user logoff how long after time expires?:       60
Minimum password age (days):                          7
Maximum password age (days):                          30
Minimum password length:                              14
Length of password history maintained:                48
Lockout threshold:                                    3
Lockout duration (minutes):                           60
Lockout observation window (minutes):                 60
Computer role:                                        PRIMARY
The command completed successfully.
"""

NET_ACCOUNTS_DOMAIN = """
Force user logoff how long after time expires?:       Never
Minimum password age (days):                          1
Maximum password age (days):                          42
Minimum password length:                              7
Length of password history maintained:                24
Lockout threshold:                                    0
Lockout duration (minutes):                           30
Lockout observation window (minutes):                 30
Computer role:                                        BACKUP
The command completed successfully.
"""


# =============================================================================
# PasswordPolicy Dataclass Tests
# =============================================================================

class TestPasswordPolicyDataclass:
    """Tests for PasswordPolicy dataclass"""

    def test_default_values(self):
        """
        BV: Default policy has sensible defaults

        Scenario:
          Given: New PasswordPolicy with no args
          When: Checking default values
          Then: Has conservative defaults
        """
        policy = PasswordPolicy()

        assert policy.lockout_threshold == 0
        assert policy.lockout_duration == 30
        assert policy.observation_window == 30
        assert policy.min_length == 0

    def test_safe_spray_attempts_with_threshold(self):
        """
        BV: Calculate safe attempts from threshold

        Scenario:
          Given: Policy with lockout_threshold=5
          When: Getting safe_spray_attempts
          Then: Returns 4 (threshold - 1)
        """
        policy = PasswordPolicy(lockout_threshold=5)

        assert policy.safe_spray_attempts == 4

    def test_safe_spray_attempts_threshold_3(self):
        """
        BV: Safe attempts with threshold 3

        Scenario:
          Given: Policy with lockout_threshold=3
          When: Getting safe_spray_attempts
          Then: Returns 2
        """
        policy = PasswordPolicy(lockout_threshold=3)

        assert policy.safe_spray_attempts == 2

    def test_safe_spray_attempts_no_lockout(self):
        """
        BV: No lockout returns high value

        Scenario:
          Given: Policy with lockout_threshold=0
          When: Getting safe_spray_attempts
          Then: Returns 999
        """
        policy = PasswordPolicy(lockout_threshold=0)

        assert policy.safe_spray_attempts == 999

    def test_safe_spray_attempts_threshold_1(self):
        """
        BV: Threshold 1 returns minimum of 1

        Scenario:
          Given: Policy with lockout_threshold=1
          When: Getting safe_spray_attempts
          Then: Returns 1 (minimum)
        """
        policy = PasswordPolicy(lockout_threshold=1)

        assert policy.safe_spray_attempts == 1

    def test_spray_delay_uses_observation_window(self):
        """
        BV: Delay uses observation window

        Scenario:
          Given: Policy with observation_window=45
          When: Getting spray_delay_minutes
          Then: Returns 45
        """
        policy = PasswordPolicy(observation_window=45)

        assert policy.spray_delay_minutes == 45

    def test_spray_delay_fallback_to_lockout_duration(self):
        """
        BV: Delay falls back to lockout duration

        Scenario:
          Given: Policy with observation_window=0, lockout_duration=60
          When: Getting spray_delay_minutes
          Then: Returns 60
        """
        policy = PasswordPolicy(observation_window=0, lockout_duration=60)

        assert policy.spray_delay_minutes == 60

    def test_spray_delay_default(self):
        """
        BV: Default delay when both are zero

        Scenario:
          Given: Policy with both windows at 0
          When: Getting spray_delay_minutes
          Then: Returns conservative default (30)
        """
        policy = PasswordPolicy(observation_window=0, lockout_duration=0)

        assert policy.spray_delay_minutes == 30

    def test_has_lockout_true(self):
        """
        BV: has_lockout detects lockout policy

        Scenario:
          Given: Policy with lockout_threshold > 0
          When: Checking has_lockout
          Then: Returns True
        """
        policy = PasswordPolicy(lockout_threshold=5)

        assert policy.has_lockout is True

    def test_has_lockout_false(self):
        """
        BV: has_lockout detects no lockout

        Scenario:
          Given: Policy with lockout_threshold=0
          When: Checking has_lockout
          Then: Returns False
        """
        policy = PasswordPolicy(lockout_threshold=0)

        assert policy.has_lockout is False

    def test_to_dict(self):
        """
        BV: Convert policy to dict for Neo4j

        Scenario:
          Given: PasswordPolicy with values
          When: Calling to_dict()
          Then: Returns dict with all fields
        """
        policy = PasswordPolicy(
            lockout_threshold=5,
            lockout_duration=30,
            observation_window=30,
            min_length=7,
            max_age=42,
            min_age=1,
            history=24,
        )

        result = policy.to_dict()

        assert result["lockout_threshold"] == 5
        assert result["lockout_duration"] == 30
        assert result["min_length"] == 7
        assert result["history"] == 24

    def test_from_dict(self):
        """
        BV: Create policy from dict

        Scenario:
          Given: Dict with policy values
          When: Calling from_dict()
          Then: Returns PasswordPolicy with values
        """
        data = {
            "lockout_threshold": 5,
            "lockout_duration": 30,
            "observation_window": 30,
            "min_length": 7,
            "max_age": 42,
            "min_age": 1,
            "history": 24,
        }

        policy = PasswordPolicy.from_dict(data)

        assert policy.lockout_threshold == 5
        assert policy.min_length == 7
        assert policy.history == 24

    def test_from_dict_handles_missing_keys(self):
        """
        BV: from_dict handles partial data

        Scenario:
          Given: Dict with some missing keys
          When: Calling from_dict()
          Then: Uses defaults for missing keys
        """
        data = {"lockout_threshold": 10}

        policy = PasswordPolicy.from_dict(data)

        assert policy.lockout_threshold == 10
        assert policy.lockout_duration == 30  # default
        assert policy.min_length == 0  # default


# =============================================================================
# Extract Int Function Tests
# =============================================================================

class TestExtractInt:
    """Tests for _extract_int helper function"""

    def test_extract_numeric_value(self):
        """
        BV: Extract numeric value from text

        Scenario:
          Given: Text with number
          When: Calling _extract_int()
          Then: Returns the number
        """
        text = "Lockout threshold: 5"
        result = _extract_int(r'Lockout threshold[:\s]+(\d+)', text)

        assert result == 5

    def test_extract_never_value(self):
        """
        BV: Handle 'Never' as 0

        Scenario:
          Given: Text with 'Never'
          When: Calling _extract_int()
          Then: Returns 0
        """
        text = "Lockout threshold: Never"
        result = _extract_int(r'Lockout threshold[:\s]+(\w+)', text)

        assert result == 0

    def test_extract_unlimited_value(self):
        """
        BV: Handle 'Unlimited' as 0

        Scenario:
          Given: Text with 'Unlimited'
          When: Calling _extract_int()
          Then: Returns 0
        """
        text = "Maximum password age: Unlimited"
        result = _extract_int(r'Maximum password age[:\s]+(\w+)', text)

        assert result == 0

    def test_extract_none_value(self):
        """
        BV: Handle 'None' as 0

        Scenario:
          Given: Text with 'None'
          When: Calling _extract_int()
          Then: Returns 0
        """
        text = "Password history: None"
        result = _extract_int(r'Password history[:\s]+(\w+)', text)

        assert result == 0

    def test_extract_not_found_returns_default(self):
        """
        BV: Return default when not found

        Scenario:
          Given: Text without match
          When: Calling _extract_int()
          Then: Returns default value
        """
        text = "Some other text"
        result = _extract_int(r'Lockout threshold[:\s]+(\d+)', text, default=99)

        assert result == 99


# =============================================================================
# Parse Net Accounts Tests
# =============================================================================

class TestParseNetAccounts:
    """Tests for parse_net_accounts function"""

    def test_parse_standard_policy(self):
        """
        BV: Parse standard domain policy

        Scenario:
          Given: Standard net accounts output
          When: Calling parse_net_accounts()
          Then: Extracts all values
        """
        policy = parse_net_accounts(NET_ACCOUNTS_STANDARD)

        assert policy.lockout_threshold == 5
        assert policy.lockout_duration == 30
        assert policy.observation_window == 30
        assert policy.min_length == 7
        assert policy.max_age == 42
        assert policy.min_age == 1
        assert policy.history == 24

    def test_parse_no_lockout_policy(self):
        """
        BV: Parse policy with no lockout

        Scenario:
          Given: Net accounts with 'Never' lockout
          When: Calling parse_net_accounts()
          Then: lockout_threshold is 0
        """
        policy = parse_net_accounts(NET_ACCOUNTS_NO_LOCKOUT)

        assert policy.lockout_threshold == 0
        assert policy.has_lockout is False
        assert policy.safe_spray_attempts == 999

    def test_parse_strict_policy(self):
        """
        BV: Parse strict security policy

        Scenario:
          Given: Strict enterprise policy
          When: Calling parse_net_accounts()
          Then: Extracts strict values
        """
        policy = parse_net_accounts(NET_ACCOUNTS_STRICT)

        assert policy.lockout_threshold == 3
        assert policy.min_length == 14
        assert policy.history == 48
        assert policy.safe_spray_attempts == 2

    def test_parse_domain_policy(self):
        """
        BV: Parse domain controller output

        Scenario:
          Given: Domain controller net accounts
          When: Calling parse_net_accounts()
          Then: Extracts values correctly
        """
        policy = parse_net_accounts(NET_ACCOUNTS_DOMAIN)

        assert policy.lockout_threshold == 0
        assert policy.min_age == 1
        assert policy.max_age == 42

    def test_parse_empty_output(self):
        """
        BV: Handle empty output

        Scenario:
          Given: Empty string
          When: Calling parse_net_accounts()
          Then: Returns defaults
        """
        policy = parse_net_accounts("")

        assert policy.lockout_threshold == 0
        assert policy.lockout_duration == 30

    def test_parse_garbage_output(self):
        """
        BV: Handle garbage output

        Scenario:
          Given: Non-matching text
          When: Calling parse_net_accounts()
          Then: Returns defaults without error
        """
        policy = parse_net_accounts("This is not net accounts output")

        assert policy.lockout_threshold == 0
        assert policy.min_length == 0


# =============================================================================
# Format Policy Display Tests
# =============================================================================

class TestFormatPolicyDisplay:
    """Tests for format_policy_display function"""

    def test_format_standard_policy(self):
        """
        BV: Format policy for display

        Scenario:
          Given: Standard policy
          When: Calling format_policy_display()
          Then: Returns formatted string
        """
        policy = PasswordPolicy(
            lockout_threshold=5,
            lockout_duration=30,
            observation_window=30,
            min_length=7,
        )

        output = format_policy_display(policy)

        assert "Password Policy" in output
        assert "5 attempts" in output
        assert "30 minutes" in output
        assert "Safe Spray Parameters" in output
        assert "Attempts per round" in output

    def test_format_no_lockout_warning(self):
        """
        BV: Show warning for no lockout

        Scenario:
          Given: Policy with no lockout
          When: Calling format_policy_display()
          Then: Shows warning
        """
        policy = PasswordPolicy(lockout_threshold=0)

        output = format_policy_display(policy)

        assert "WARNING" in output
        assert "No lockout policy" in output

    def test_format_shows_safe_attempts(self):
        """
        BV: Display safe spray attempts

        Scenario:
          Given: Policy with threshold 5
          When: Calling format_policy_display()
          Then: Shows 4 attempts
        """
        policy = PasswordPolicy(lockout_threshold=5)

        output = format_policy_display(policy)

        assert "4" in output  # 5-1 = 4 safe attempts


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """End-to-end integration tests"""

    def test_parse_and_use_for_spraying(self):
        """
        BV: Parse and calculate spray parameters

        Scenario:
          Given: Net accounts output
          When: Parsing and getting spray params
          Then: Returns safe values for spraying
        """
        policy = parse_net_accounts(NET_ACCOUNTS_STANDARD)

        # Verify we can spray safely
        assert policy.safe_spray_attempts == 4  # threshold 5 - 1
        assert policy.spray_delay_minutes == 30  # observation window
        assert policy.has_lockout is True

    def test_roundtrip_dict_conversion(self):
        """
        BV: Dict conversion round-trips

        Scenario:
          Given: PasswordPolicy
          When: Converting to/from dict
          Then: Values preserved
        """
        original = PasswordPolicy(
            lockout_threshold=5,
            lockout_duration=30,
            observation_window=30,
            min_length=7,
            max_age=42,
            min_age=1,
            history=24,
        )

        # Convert to dict and back
        data = original.to_dict()
        restored = PasswordPolicy.from_dict(data)

        assert restored.lockout_threshold == original.lockout_threshold
        assert restored.min_length == original.min_length
        assert restored.history == original.history
        assert restored.safe_spray_attempts == original.safe_spray_attempts
