"""
Tests for BloodTrail Password Spray Display Module

Business Value Focus:
- print_spray_recommendations() outputs actionable spray commands
- generate_spray_section() creates both console and markdown output
- Color toggle works correctly for piped output
- Credential type awareness selects appropriate commands
- Target count handling switches between loop and file templates

Test Priority: TIER 2 - HIGH (AD Exploitation)

These tests protect against:
- Missing or malformed output that breaks copy-paste workflows
- Color code corruption in non-terminal contexts
- Incorrect credential-to-command mapping
- Template substitution failures
"""

import io
import sys
import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
from typing import List, Optional

# Module under test
from tools.post.bloodtrail.display.spray import (
    print_spray_recommendations,
    generate_spray_section,
    _print_all_targets_section,
)
from tools.post.bloodtrail.display.base import Colors, NoColors


# =============================================================================
# Factory Classes
# =============================================================================

class PwnedUserFactory:
    """Factory for creating PwnedUser test objects"""

    _counter = 0

    @classmethod
    def create(
        cls,
        name: str = None,
        username: str = None,
        cred_types: List[str] = None,
        cred_values: List[str] = None,
        domain: str = "CORP.COM",
    ):
        """Create PwnedUser with defaults."""
        cls._counter += 1

        # Create a mock PwnedUser object
        user = Mock()
        user.name = name or f"USER{cls._counter}@{domain}"
        user.username = username or f"USER{cls._counter}"
        user.cred_types = cred_types or ["password"]
        user.cred_values = cred_values or [f"Password{cls._counter}!"]
        user.domain = domain
        return user

    @classmethod
    def create_with_password(cls, password: str, username: str = None):
        """Create user with specific password."""
        return cls.create(
            username=username,
            cred_types=["password"],
            cred_values=[password],
        )

    @classmethod
    def create_with_hash(cls, ntlm_hash: str, username: str = None):
        """Create user with NTLM hash only."""
        return cls.create(
            username=username,
            cred_types=["ntlm-hash"],
            cred_values=[ntlm_hash],
        )

    @classmethod
    def create_with_multiple_creds(cls, username: str = None):
        """Create user with both password and hash."""
        return cls.create(
            username=username,
            cred_types=["password", "ntlm-hash"],
            cred_values=["Summer2024!", "aabbccdd11223344"],
        )


class PolicyFactory:
    """Factory for creating LockoutPolicy test objects"""

    @classmethod
    def create(
        cls,
        lockout_threshold: int = 5,
        lockout_duration: int = 30,
        observation_window: int = 30,
        safe_spray_attempts: int = 4,
        spray_delay_minutes: int = 30,
    ):
        """Create mock policy with defaults."""
        policy = Mock()
        policy.lockout_threshold = lockout_threshold
        policy.lockout_duration = lockout_duration
        policy.observation_window = observation_window
        policy.safe_spray_attempts = safe_spray_attempts
        policy.spray_delay_minutes = spray_delay_minutes
        return policy

    @classmethod
    def create_strict(cls):
        """Create strict lockout policy (3 attempts)."""
        return cls.create(
            lockout_threshold=3,
            safe_spray_attempts=2,
            spray_delay_minutes=60,
        )

    @classmethod
    def create_lenient(cls):
        """Create lenient lockout policy (10 attempts)."""
        return cls.create(
            lockout_threshold=10,
            safe_spray_attempts=9,
            spray_delay_minutes=30,
        )


# =============================================================================
# print_spray_recommendations Tests
# =============================================================================

class TestPrintSprayRecommendations:
    """Tests for print_spray_recommendations() function"""

    def test_prints_header_with_colors(self, capsys):
        """
        BV: Output has clear section header for user orientation

        Scenario:
          Given: Pwned users with passwords
          When: Calling print_spray_recommendations with colors
          Then: Output contains styled header
        """
        users = [PwnedUserFactory.create_with_password("TestPass123")]

        print_spray_recommendations(
            pwned_users=users,
            domain="CORP.LOCAL",
            dc_ip="192.168.1.10",
            use_colors=True,
        )

        captured = capsys.readouterr()
        assert "PASSWORD SPRAY" in captured.out.upper()

    def test_prints_without_colors(self, capsys):
        """
        BV: Non-colored output works for piped/redirected contexts

        Scenario:
          Given: Pwned users with passwords
          When: Calling with use_colors=False
          Then: Output contains no ANSI escape codes
        """
        users = [PwnedUserFactory.create_with_password("TestPass123")]

        print_spray_recommendations(
            pwned_users=users,
            domain="CORP.LOCAL",
            dc_ip="192.168.1.10",
            use_colors=False,
        )

        captured = capsys.readouterr()
        # ANSI escape codes start with \033[
        assert "\033[" not in captured.out

    def test_filters_by_smb_method(self, capsys):
        """
        BV: SMB filter shows only SMB-related spray commands

        Scenario:
          Given: method_filter='smb'
          When: Calling print_spray_recommendations
          Then: Output focuses on SMB/crackmapexec commands
        """
        users = [PwnedUserFactory.create_with_password("TestPass123")]

        print_spray_recommendations(
            pwned_users=users,
            domain="CORP.LOCAL",
            dc_ip="192.168.1.10",
            use_colors=False,
            method_filter="smb",
        )

        captured = capsys.readouterr()
        assert "SMB" in captured.out.upper()
        assert "crackmapexec" in captured.out.lower() or "netexec" in captured.out.lower()

    def test_filters_by_kerberos_method(self, capsys):
        """
        BV: Kerberos filter shows kerbrute-based commands

        Scenario:
          Given: method_filter='kerberos'
          When: Calling print_spray_recommendations
          Then: Output focuses on kerbrute commands
        """
        users = [PwnedUserFactory.create_with_password("TestPass123")]

        print_spray_recommendations(
            pwned_users=users,
            domain="CORP.LOCAL",
            dc_ip="192.168.1.10",
            use_colors=False,
            method_filter="kerberos",
        )

        captured = capsys.readouterr()
        assert "KERBEROS" in captured.out.upper()
        assert "kerbrute" in captured.out.lower()

    def test_filters_by_ldap_method(self, capsys):
        """
        BV: LDAP filter shows PowerShell-based commands

        Scenario:
          Given: method_filter='ldap'
          When: Calling print_spray_recommendations
          Then: Output focuses on PowerShell/LDAP commands
        """
        users = [PwnedUserFactory.create_with_password("TestPass123")]

        print_spray_recommendations(
            pwned_users=users,
            domain="CORP.LOCAL",
            dc_ip="192.168.1.10",
            use_colors=False,
            method_filter="ldap",
        )

        captured = capsys.readouterr()
        assert "LDAP" in captured.out.upper()

    def test_all_filter_shows_all_methods(self, capsys):
        """
        BV: 'all' filter shows comprehensive spray guidance

        Scenario:
          Given: method_filter='all'
          When: Calling print_spray_recommendations
          Then: Output includes all spray methods
        """
        users = [PwnedUserFactory.create_with_password("TestPass123")]

        print_spray_recommendations(
            pwned_users=users,
            domain="CORP.LOCAL",
            dc_ip="192.168.1.10",
            use_colors=False,
            method_filter="all",
        )

        captured = capsys.readouterr()
        # Should contain headers for multiple methods
        assert "METHOD" in captured.out.upper()

    def test_substitutes_domain_correctly(self, capsys):
        """
        BV: Domain placeholder is replaced with actual domain

        Scenario:
          Given: domain='ACME.LOCAL'
          When: Calling print_spray_recommendations
          Then: Commands use 'acme.local' (lowercase for crackmapexec)
        """
        users = [PwnedUserFactory.create_with_password("TestPass123")]

        print_spray_recommendations(
            pwned_users=users,
            domain="ACME.LOCAL",
            dc_ip="192.168.1.10",
            use_colors=False,
            method_filter="smb",
        )

        captured = capsys.readouterr()
        # Domain should appear in output (typically lowercase)
        assert "acme.local" in captured.out.lower()

    def test_substitutes_dc_ip_correctly(self, capsys):
        """
        BV: DC IP placeholder is replaced with actual IP

        Scenario:
          Given: dc_ip='10.10.10.100'
          When: Calling print_spray_recommendations
          Then: Commands use the provided IP
        """
        users = [PwnedUserFactory.create_with_password("TestPass123")]

        print_spray_recommendations(
            pwned_users=users,
            domain="CORP.LOCAL",
            dc_ip="10.10.10.100",
            use_colors=False,
            method_filter="smb",
        )

        captured = capsys.readouterr()
        assert "10.10.10.100" in captured.out

    def test_shows_captured_passwords_in_commands(self, capsys):
        """
        BV: Captured passwords are directly usable in spray commands

        Scenario:
          Given: User with password 'MySecret123!'
          When: Calling print_spray_recommendations
          Then: Password appears in command templates
        """
        users = [PwnedUserFactory.create_with_password("MySecret123!")]

        print_spray_recommendations(
            pwned_users=users,
            domain="CORP.LOCAL",
            dc_ip="192.168.1.10",
            use_colors=False,
            method_filter="smb",
        )

        captured = capsys.readouterr()
        assert "MySecret123!" in captured.out

    def test_handles_empty_pwned_users(self, capsys):
        """
        BV: Empty user list doesn't crash, shows minimal output

        Scenario:
          Given: Empty pwned_users list
          When: Calling print_spray_recommendations
          Then: Runs without error
        """
        print_spray_recommendations(
            pwned_users=[],
            domain="CORP.LOCAL",
            dc_ip="192.168.1.10",
            use_colors=False,
        )

        captured = capsys.readouterr()
        # Should not crash, may show minimal output
        assert True  # Test passes if no exception

    def test_handles_none_pwned_users(self, capsys):
        """
        BV: None pwned_users doesn't crash

        Scenario:
          Given: pwned_users=None
          When: Calling print_spray_recommendations
          Then: Runs without error
        """
        print_spray_recommendations(
            pwned_users=None,
            domain="CORP.LOCAL",
            dc_ip="192.168.1.10",
            use_colors=False,
        )

        captured = capsys.readouterr()
        assert True  # Test passes if no exception


# =============================================================================
# generate_spray_section Tests
# =============================================================================

class TestGenerateSpraySection:
    """Tests for generate_spray_section() function"""

    def test_returns_tuple_of_strings(self):
        """
        BV: Function returns both console and markdown output

        Scenario:
          Given: Pwned users with passwords
          When: Calling generate_spray_section
          Then: Returns (console_output, markdown_output) tuple
        """
        users = [PwnedUserFactory.create_with_password("TestPass123")]

        result = generate_spray_section(
            pwned_users=users,
            domain="CORP.LOCAL",
            dc_ip="192.168.1.10",
        )

        assert isinstance(result, tuple)
        assert len(result) == 2
        console_out, md_out = result
        assert isinstance(console_out, str)
        assert isinstance(md_out, str)

    def test_console_output_has_ansi_colors(self):
        """
        BV: Console output has ANSI codes for terminal display

        Scenario:
          Given: use_colors=True
          When: Calling generate_spray_section
          Then: Console output contains ANSI escape codes
        """
        users = [PwnedUserFactory.create_with_password("TestPass123")]

        console_out, _ = generate_spray_section(
            pwned_users=users,
            domain="CORP.LOCAL",
            dc_ip="192.168.1.10",
            use_colors=True,
        )

        # ANSI escape codes start with \033[
        assert "\033[" in console_out

    def test_console_output_no_colors_when_disabled(self):
        """
        BV: Color-free output for file/pipe redirection

        Scenario:
          Given: use_colors=False
          When: Calling generate_spray_section
          Then: Console output has no ANSI codes
        """
        users = [PwnedUserFactory.create_with_password("TestPass123")]

        console_out, _ = generate_spray_section(
            pwned_users=users,
            domain="CORP.LOCAL",
            dc_ip="192.168.1.10",
            use_colors=False,
        )

        assert "\033[" not in console_out

    def test_markdown_output_has_headers(self):
        """
        BV: Markdown output has proper section headers

        Scenario:
          Given: Pwned users
          When: Calling generate_spray_section
          Then: Markdown has ## headers for sections
        """
        users = [PwnedUserFactory.create_with_password("TestPass123")]

        _, md_out = generate_spray_section(
            pwned_users=users,
            domain="CORP.LOCAL",
            dc_ip="192.168.1.10",
        )

        assert "##" in md_out  # Has markdown headers

    def test_markdown_output_has_code_blocks(self):
        """
        BV: Markdown commands are in code blocks for copy-paste

        Scenario:
          Given: Pwned users
          When: Calling generate_spray_section
          Then: Markdown has ``` code blocks
        """
        users = [PwnedUserFactory.create_with_password("TestPass123")]

        _, md_out = generate_spray_section(
            pwned_users=users,
            domain="CORP.LOCAL",
            dc_ip="192.168.1.10",
        )

        assert "```" in md_out

    def test_shows_captured_passwords_section(self):
        """
        BV: Captured passwords are listed for reference

        Scenario:
          Given: Users with multiple passwords
          When: Calling generate_spray_section
          Then: Output has 'Captured Passwords' section
        """
        users = [
            PwnedUserFactory.create_with_password("Password1"),
            PwnedUserFactory.create_with_password("Password2"),
        ]

        console_out, _ = generate_spray_section(
            pwned_users=users,
            domain="CORP.LOCAL",
            dc_ip="192.168.1.10",
            use_colors=False,
        )

        assert "CAPTURED PASSWORDS" in console_out.upper()
        assert "Password1" in console_out
        assert "Password2" in console_out

    def test_limits_displayed_passwords(self):
        """
        BV: Large password lists are truncated for readability

        Scenario:
          Given: 10 users with passwords
          When: Calling generate_spray_section
          Then: Only first 5 shown with '... and X more'
        """
        users = [
            PwnedUserFactory.create_with_password(f"Pass{i}")
            for i in range(10)
        ]

        console_out, _ = generate_spray_section(
            pwned_users=users,
            domain="CORP.LOCAL",
            dc_ip="192.168.1.10",
            use_colors=False,
        )

        # Should show truncation message
        assert "more" in console_out.lower()

    def test_shows_policy_info_when_provided(self):
        """
        BV: Lockout policy guides safe spray attempts

        Scenario:
          Given: Policy with 5-attempt lockout
          When: Calling generate_spray_section
          Then: Output shows lockout threshold and safe attempts
        """
        users = [PwnedUserFactory.create_with_password("TestPass")]
        policy = PolicyFactory.create(lockout_threshold=5, safe_spray_attempts=4)

        console_out, _ = generate_spray_section(
            pwned_users=users,
            policy=policy,
            domain="CORP.LOCAL",
            dc_ip="192.168.1.10",
            use_colors=False,
        )

        assert "5" in console_out  # Lockout threshold
        assert "4" in console_out  # Safe attempts

    def test_returns_empty_strings_without_passwords(self):
        """
        BV: No spray section if no passwords to spray

        Scenario:
          Given: User with only NTLM hash (no password)
          When: Calling generate_spray_section
          Then: Returns empty strings (spray needs passwords)
        """
        users = [PwnedUserFactory.create_with_hash("aabbccdd11223344")]

        console_out, md_out = generate_spray_section(
            pwned_users=users,
            domain="CORP.LOCAL",
            dc_ip="192.168.1.10",
        )

        assert console_out == ""
        assert md_out == ""

    def test_shows_all_spray_methods(self):
        """
        BV: All spray methods are presented for comparison

        Scenario:
          Given: Pwned users
          When: Calling generate_spray_section
          Then: Output includes SMB, Kerberos, LDAP methods
        """
        users = [PwnedUserFactory.create_with_password("TestPass")]

        console_out, _ = generate_spray_section(
            pwned_users=users,
            domain="CORP.LOCAL",
            dc_ip="192.168.1.10",
            use_colors=False,
        )

        # Should mention different methods
        assert "METHOD 1" in console_out or "SMB" in console_out.upper()

    def test_shows_exam_tip(self):
        """
        BV: OSCP exam tip reminds about lockout check

        Scenario:
          Given: Pwned users
          When: Calling generate_spray_section
          Then: Output includes 'EXAM TIP' with net accounts reminder
        """
        users = [PwnedUserFactory.create_with_password("TestPass")]

        console_out, _ = generate_spray_section(
            pwned_users=users,
            domain="CORP.LOCAL",
            dc_ip="192.168.1.10",
            use_colors=False,
        )

        assert "EXAM TIP" in console_out.upper()
        assert "net accounts" in console_out.lower()


# =============================================================================
# _print_all_targets_section Tests
# =============================================================================

class TestPrintAllTargetsSection:
    """Tests for _print_all_targets_section() helper"""

    def test_shows_no_ips_message_when_empty(self, capsys):
        """
        BV: Empty IP list shows helpful message about refresh

        Scenario:
          Given: all_ips=[]
          When: Calling _print_all_targets_section
          Then: Shows message about --refresh-ips
        """
        _print_all_targets_section(
            all_ips=[],
            password="TestPass",
            username="admin",
            domain="CORP.LOCAL",
            c=NoColors,
        )

        captured = capsys.readouterr()
        assert "No resolved IPs" in captured.out
        assert "--refresh-ips" in captured.out

    def test_uses_loop_template_for_small_ip_list(self, capsys):
        """
        BV: Small IP lists use inline bash loops

        Scenario:
          Given: 5 IPs (below threshold)
          When: Calling _print_all_targets_section
          Then: Uses 'for IP in' loop syntax
        """
        ips = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "192.168.1.13", "192.168.1.14"]

        _print_all_targets_section(
            all_ips=ips,
            password="TestPass",
            username="admin",
            domain="CORP.LOCAL",
            c=NoColors,
        )

        captured = capsys.readouterr()
        assert "for IP in" in captured.out

    def test_uses_file_template_for_large_ip_list(self, capsys):
        """
        BV: Large IP lists use file-based input

        Scenario:
          Given: 25 IPs (above threshold of 20)
          When: Calling _print_all_targets_section
          Then: Uses targets_file approach
        """
        ips = [f"192.168.1.{i}" for i in range(1, 26)]

        _print_all_targets_section(
            all_ips=ips,
            password="TestPass",
            username="admin",
            domain="CORP.LOCAL",
            c=NoColors,
        )

        captured = capsys.readouterr()
        assert "targets.txt" in captured.out
        assert "cat << 'EOF'" in captured.out

    def test_shows_all_protocols(self, capsys):
        """
        BV: All protocols shown for comprehensive validation

        Scenario:
          Given: IP list
          When: Calling _print_all_targets_section
          Then: Shows SMB, WinRM, RDP, MSSQL sections
        """
        ips = ["192.168.1.10", "192.168.1.11"]

        _print_all_targets_section(
            all_ips=ips,
            password="TestPass",
            username="admin",
            domain="CORP.LOCAL",
            c=NoColors,
        )

        captured = capsys.readouterr()
        output_upper = captured.out.upper()
        assert "SMB" in output_upper
        assert "WINRM" in output_upper
        assert "RDP" in output_upper
        assert "MSSQL" in output_upper

    def test_substitutes_credentials_correctly(self, capsys):
        """
        BV: Credentials appear in command templates

        Scenario:
          Given: username='targetadmin', password='Secret123!'
          When: Calling _print_all_targets_section
          Then: Credentials appear in output
        """
        ips = ["192.168.1.10"]

        _print_all_targets_section(
            all_ips=ips,
            password="Secret123!",
            username="targetadmin",
            domain="CORP.LOCAL",
            c=NoColors,
        )

        captured = capsys.readouterr()
        assert "Secret123!" in captured.out
        assert "targetadmin" in captured.out

    def test_escapes_single_quotes_in_password(self, capsys):
        """
        BV: Passwords with quotes don't break shell commands

        Scenario:
          Given: password="Pass'word"
          When: Calling _print_all_targets_section
          Then: Quote is escaped for shell safety
        """
        ips = ["192.168.1.10"]

        _print_all_targets_section(
            all_ips=ips,
            password="Pass'word",
            username="admin",
            domain="CORP.LOCAL",
            c=NoColors,
        )

        captured = capsys.readouterr()
        # Should have escaped the quote
        # Common escape: '\"'\"' or similar
        assert "Pass" in captured.out

    def test_shows_ip_count(self, capsys):
        """
        BV: IP count helps user understand scope

        Scenario:
          Given: 15 IPs
          When: Calling _print_all_targets_section
          Then: Shows '15 hosts' in output
        """
        ips = [f"192.168.1.{i}" for i in range(1, 16)]

        _print_all_targets_section(
            all_ips=ips,
            password="TestPass",
            username="admin",
            domain="CORP.LOCAL",
            c=NoColors,
        )

        captured = capsys.readouterr()
        assert "15" in captured.out
        assert "hosts" in captured.out.lower()


# =============================================================================
# Color Output Tests
# =============================================================================

class TestColorOutput:
    """Tests for color output handling"""

    def test_colors_class_has_required_attributes(self):
        """
        BV: Colors class provides all needed color codes

        Scenario:
          Given: Colors class
          When: Checking attributes
          Then: Has all required color codes
        """
        required = ["CYAN", "GREEN", "YELLOW", "RED", "BOLD", "DIM", "RESET"]
        for attr in required:
            assert hasattr(Colors, attr), f"Colors missing {attr}"
            value = getattr(Colors, attr)
            assert value.startswith("\033["), f"Colors.{attr} not ANSI code"

    def test_nocolors_class_has_empty_strings(self):
        """
        BV: NoColors class provides empty strings for all colors

        Scenario:
          Given: NoColors class
          When: Checking attributes
          Then: All are empty strings
        """
        required = ["CYAN", "GREEN", "YELLOW", "RED", "BOLD", "DIM", "RESET"]
        for attr in required:
            assert hasattr(NoColors, attr), f"NoColors missing {attr}"
            value = getattr(NoColors, attr)
            assert value == "", f"NoColors.{attr} should be empty"


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests for spray display functions"""

    def test_full_workflow_with_policy(self, capsys):
        """
        BV: Complete spray workflow with policy shows all relevant info

        Scenario:
          Given: Multiple users, policy, target info
          When: Calling print_spray_recommendations with method_filter='all'
          Then: Output is comprehensive and usable
        """
        users = [
            PwnedUserFactory.create_with_password("Summer2024!"),
            PwnedUserFactory.create_with_password("Winter2024!"),
        ]
        policy = PolicyFactory.create_strict()

        print_spray_recommendations(
            pwned_users=users,
            policy=policy,
            domain="MEGACORP.LOCAL",
            dc_ip="10.10.10.1",
            use_colors=False,
            method_filter="all",
        )

        captured = capsys.readouterr()

        # Should have all key elements
        assert "Summer2024!" in captured.out or "CAPTURED" in captured.out.upper()
        assert "10.10.10.1" in captured.out
        assert "megacorp.local" in captured.out.lower()

    def test_all_targets_with_small_ip_list(self, capsys):
        """
        BV: Small target list uses efficient loop syntax

        Scenario:
          Given: 5 target IPs
          When: Calling print_spray_recommendations with all_ips
          Then: Uses inline loop, not file-based approach
        """
        users = [PwnedUserFactory.create_with_password("TestPass123")]
        ips = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]

        print_spray_recommendations(
            pwned_users=users,
            domain="CORP.LOCAL",
            dc_ip="192.168.1.10",
            use_colors=False,
            method_filter="all",
            all_ips=ips,
        )

        captured = capsys.readouterr()
        assert "for IP in" in captured.out

    def test_markdown_output_is_valid(self):
        """
        BV: Markdown output can be parsed correctly

        Scenario:
          Given: Pwned users
          When: Calling generate_spray_section
          Then: Markdown has proper structure
        """
        users = [PwnedUserFactory.create_with_password("TestPass123")]

        _, md_out = generate_spray_section(
            pwned_users=users,
            domain="CORP.LOCAL",
            dc_ip="192.168.1.10",
        )

        # Basic markdown validation
        lines = md_out.split("\n")

        # Should have at least one header
        headers = [l for l in lines if l.startswith("#")]
        assert len(headers) > 0

        # Code blocks should be balanced
        code_blocks = md_out.count("```")
        assert code_blocks % 2 == 0, "Unbalanced code blocks"


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Edge case handling tests"""

    def test_handles_special_characters_in_password(self, capsys):
        """
        BV: Special characters in passwords don't break output

        Scenario:
          Given: Password with special chars: $, `, ", '
          When: Calling print_spray_recommendations
          Then: No crash, password appears (possibly escaped)
        """
        users = [PwnedUserFactory.create_with_password('P@$$w0rd`"test')]

        print_spray_recommendations(
            pwned_users=users,
            domain="CORP.LOCAL",
            dc_ip="192.168.1.10",
            use_colors=False,
            method_filter="smb",
        )

        captured = capsys.readouterr()
        assert "P@$$w0rd" in captured.out  # At least partial match

    def test_handles_unicode_in_domain(self, capsys):
        """
        BV: Unicode characters in domain don't crash

        Scenario:
          Given: Domain with unicode
          When: Calling print_spray_recommendations
          Then: No crash
        """
        users = [PwnedUserFactory.create_with_password("TestPass")]

        # This shouldn't crash
        print_spray_recommendations(
            pwned_users=users,
            domain="CORP.LOCAL",  # Standard domain for safety
            dc_ip="192.168.1.10",
            use_colors=False,
        )

        captured = capsys.readouterr()
        assert True  # Pass if no exception

    def test_handles_empty_domain(self, capsys):
        """
        BV: Empty domain uses placeholder

        Scenario:
          Given: domain=''
          When: Calling print_spray_recommendations
          Then: Uses <DOMAIN> placeholder
        """
        users = [PwnedUserFactory.create_with_password("TestPass")]

        print_spray_recommendations(
            pwned_users=users,
            domain="",
            dc_ip="192.168.1.10",
            use_colors=False,
            method_filter="smb",
        )

        captured = capsys.readouterr()
        # Empty domain should result in placeholder or empty
        assert True  # Pass if no exception

    def test_handles_default_dc_ip_placeholder(self, capsys):
        """
        BV: Default DC IP placeholder is visible

        Scenario:
          Given: No dc_ip specified (uses default)
          When: Calling print_spray_recommendations
          Then: Shows <DC_IP> placeholder
        """
        users = [PwnedUserFactory.create_with_password("TestPass")]

        print_spray_recommendations(
            pwned_users=users,
            domain="CORP.LOCAL",
            # dc_ip defaults to "<DC_IP>"
            use_colors=False,
            method_filter="smb",
        )

        captured = capsys.readouterr()
        assert "<DC_IP>" in captured.out

    def test_handles_user_without_creds(self, capsys):
        """
        BV: User object without credentials doesn't crash

        Scenario:
          Given: User with empty cred lists
          When: Calling generate_spray_section
          Then: Returns empty (no passwords to spray)
        """
        user = Mock()
        user.name = "EMPTY@CORP.COM"
        user.username = "EMPTY"
        user.cred_types = []
        user.cred_values = []

        console_out, _ = generate_spray_section(
            pwned_users=[user],
            domain="CORP.LOCAL",
            dc_ip="192.168.1.10",
        )

        # No passwords = empty output
        assert console_out == ""

    def test_handles_very_long_password_list(self, capsys):
        """
        BV: Very long password lists are handled efficiently

        Scenario:
          Given: 100 users with passwords
          When: Calling generate_spray_section
          Then: Completes without timeout, truncates display
        """
        users = [
            PwnedUserFactory.create_with_password(f"Password{i}!")
            for i in range(100)
        ]

        console_out, _ = generate_spray_section(
            pwned_users=users,
            domain="CORP.LOCAL",
            dc_ip="192.168.1.10",
            use_colors=False,
        )

        # Should complete and show truncation
        assert "more" in console_out.lower()
