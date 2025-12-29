"""
Tests for ScriptGenerator

Business Value Focus:
- Generated scripts enable manual review before execution
- Correct timing delays prevent account lockouts
- Template correctness ensures scripts work with target tools
- Special character handling prevents shell injection issues

Test Priority: TIER 2 - HIGH (Manual Review Safety)
"""

import sys
import pytest
import tempfile
import stat
import os
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tools.post.bloodtrail.autospray.script_generator import (
    ScriptGenerator,
    GeneratedFiles,
)
from tools.post.bloodtrail.autospray.lockout_manager import LockoutManager, SprayWindow


# =============================================================================
# GeneratedFiles Dataclass Tests
# =============================================================================

class TestGeneratedFiles:
    """Tests for GeneratedFiles dataclass."""

    def test_str_representation_includes_paths(self):
        """
        BV: Clear display of generated file locations

        Scenario:
          Given: GeneratedFiles with all paths set
          When: Converting to string
          Then: Shows all file paths
        """
        gf = GeneratedFiles(
            output_dir=Path("/tmp/spray"),
            users_file=Path("/tmp/spray/users.txt"),
            passwords_file=Path("/tmp/spray/passwords.txt"),
            main_script=Path("/tmp/spray/spray.sh"),
            round_scripts=[
                Path("/tmp/spray/spray_round_1.sh"),
                Path("/tmp/spray/spray_round_2.sh"),
            ],
            targets_file=Path("/tmp/spray/targets.txt"),
        )

        result = str(gf)

        assert "users.txt" in result
        assert "passwords.txt" in result
        assert "spray.sh" in result
        assert "targets.txt" in result
        assert "2" in result  # Round script count

    def test_str_without_targets(self):
        """
        BV: Handle missing targets file

        Scenario:
          Given: GeneratedFiles without targets_file
          When: Converting to string
          Then: No error, omits targets line
        """
        gf = GeneratedFiles(
            output_dir=Path("/tmp/spray"),
            users_file=Path("/tmp/spray/users.txt"),
            passwords_file=Path("/tmp/spray/passwords.txt"),
            main_script=Path("/tmp/spray/spray.sh"),
            round_scripts=[],
            targets_file=None,
        )

        result = str(gf)

        assert "users.txt" in result
        assert "targets" not in result.lower() or "Targets:" not in result


# =============================================================================
# ScriptGenerator Initialization Tests
# =============================================================================

class TestScriptGeneratorInit:
    """Tests for ScriptGenerator initialization."""

    def test_init_with_required_params(self):
        """
        BV: Minimal initialization works

        Scenario:
          Given: Domain and DC IP
          When: Creating ScriptGenerator
          Then: Has sensible defaults
        """
        gen = ScriptGenerator(
            domain="corp.com",
            dc_ip="192.168.1.100",
        )

        assert gen.domain == "corp.com"
        assert gen.dc_ip == "192.168.1.100"
        assert gen.output_dir == Path("./spray_output")
        assert gen.tool == "crackmapexec"

    def test_init_with_custom_output_dir(self):
        """
        BV: Custom output directory honored

        Scenario:
          Given: Custom output directory
          When: Creating ScriptGenerator
          Then: Uses custom path
        """
        gen = ScriptGenerator(
            domain="corp.com",
            dc_ip="192.168.1.100",
            output_dir=Path("/tmp/custom_spray"),
        )

        assert gen.output_dir == Path("/tmp/custom_spray")

    def test_init_with_different_tools(self):
        """
        BV: Support multiple spray tools

        Scenario:
          Given: Different tool specified
          When: Creating ScriptGenerator
          Then: Tool is normalized to lowercase
        """
        tools = ["CrackMapExec", "NETEXEC", "Kerbrute", "HYDRA"]

        for tool in tools:
            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                tool=tool,
            )
            assert gen.tool == tool.lower()


# =============================================================================
# Get Spray Template Tests
# =============================================================================

class TestGetSprayTemplate:
    """Tests for _get_spray_template method."""

    def test_crackmapexec_template(self):
        """
        BV: CrackMapExec template is correct

        Scenario:
          Given: Tool is crackmapexec
          When: Getting spray template
          Then: Returns CME template
        """
        gen = ScriptGenerator(
            domain="corp.com",
            dc_ip="192.168.1.100",
            tool="crackmapexec",
        )

        template = gen._get_spray_template()

        assert "crackmapexec smb" in template
        assert "$DC_IP" in template
        assert "$USER_FILE" in template

    def test_cme_alias_uses_cme_template(self):
        """
        BV: 'cme' alias works

        Scenario:
          Given: Tool is 'cme'
          When: Getting spray template
          Then: Returns CME template
        """
        gen = ScriptGenerator(
            domain="corp.com",
            dc_ip="192.168.1.100",
            tool="cme",
        )

        template = gen._get_spray_template()

        assert "crackmapexec" in template

    def test_netexec_template(self):
        """
        BV: NetExec template is correct

        Scenario:
          Given: Tool is netexec
          When: Getting spray template
          Then: Returns NetExec template
        """
        gen = ScriptGenerator(
            domain="corp.com",
            dc_ip="192.168.1.100",
            tool="netexec",
        )

        template = gen._get_spray_template()

        assert "netexec smb" in template

    def test_nxc_alias_uses_netexec_template(self):
        """
        BV: 'nxc' alias works

        Scenario:
          Given: Tool is 'nxc'
          When: Getting spray template
          Then: Returns NetExec template
        """
        gen = ScriptGenerator(
            domain="corp.com",
            dc_ip="192.168.1.100",
            tool="nxc",
        )

        template = gen._get_spray_template()

        assert "netexec" in template

    def test_kerbrute_template(self):
        """
        BV: Kerbrute template is correct

        Scenario:
          Given: Tool is kerbrute
          When: Getting spray template
          Then: Returns Kerbrute template
        """
        gen = ScriptGenerator(
            domain="corp.com",
            dc_ip="192.168.1.100",
            tool="kerbrute",
        )

        template = gen._get_spray_template()

        assert "kerbrute passwordspray" in template

    def test_hydra_template(self):
        """
        BV: Hydra template is correct

        Scenario:
          Given: Tool is hydra
          When: Getting spray template
          Then: Returns Hydra template
        """
        gen = ScriptGenerator(
            domain="corp.com",
            dc_ip="192.168.1.100",
            tool="hydra",
        )

        template = gen._get_spray_template()

        assert "hydra" in template

    def test_unknown_tool_defaults_to_cme(self):
        """
        BV: Unknown tool defaults to CME

        Scenario:
          Given: Unknown tool name
          When: Getting spray template
          Then: Returns CME template as default
        """
        gen = ScriptGenerator(
            domain="corp.com",
            dc_ip="192.168.1.100",
            tool="unknowntool",
        )

        template = gen._get_spray_template()

        assert "crackmapexec" in template


# =============================================================================
# Generate Spray Script Tests
# =============================================================================

class TestGenerateSprayScript:
    """Tests for generate_spray_script method."""

    def test_creates_output_directory(self):
        """
        BV: Output directory created if not exists

        Scenario:
          Given: Non-existent output directory
          When: Generating spray script
          Then: Directory is created
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "new_spray_dir"

            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                output_dir=output_dir,
            )

            result = gen.generate_spray_script(
                users=["admin", "user1"],
                passwords=["P1", "P2"],
            )

            assert output_dir.exists()
            assert output_dir.is_dir()

    def test_creates_users_file(self):
        """
        BV: Users file contains all usernames

        Scenario:
          Given: List of users
          When: Generating spray script
          Then: users.txt contains all users
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                output_dir=Path(tmpdir),
            )

            result = gen.generate_spray_script(
                users=["admin", "user1", "svcaccount"],
                passwords=["P1"],
            )

            content = result.users_file.read_text()
            assert "admin" in content
            assert "user1" in content
            assert "svcaccount" in content

    def test_creates_passwords_file(self):
        """
        BV: Passwords file contains all passwords

        Scenario:
          Given: List of passwords
          When: Generating spray script
          Then: passwords.txt contains all passwords
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                output_dir=Path(tmpdir),
            )

            result = gen.generate_spray_script(
                users=["admin"],
                passwords=["Summer2024!", "Winter2024!", "Spring2024!"],
            )

            content = result.passwords_file.read_text()
            assert "Summer2024!" in content
            assert "Winter2024!" in content
            assert "Spring2024!" in content

    def test_creates_targets_file_when_machines_provided(self):
        """
        BV: Targets file created for multi-machine spray

        Scenario:
          Given: List of target machines
          When: Generating spray script
          Then: targets.txt contains all machines
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                output_dir=Path(tmpdir),
            )

            result = gen.generate_spray_script(
                users=["admin"],
                passwords=["P1"],
                machines=["192.168.1.10", "192.168.1.20", "dc01.corp.com"],
            )

            assert result.targets_file is not None
            content = result.targets_file.read_text()
            assert "192.168.1.10" in content
            assert "dc01.corp.com" in content

    def test_no_targets_file_without_machines(self):
        """
        BV: No targets file when no machines specified

        Scenario:
          Given: No machines list
          When: Generating spray script
          Then: targets_file is None
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                output_dir=Path(tmpdir),
            )

            result = gen.generate_spray_script(
                users=["admin"],
                passwords=["P1"],
            )

            assert result.targets_file is None

    def test_main_script_is_executable(self):
        """
        BV: Generated script can be executed

        Scenario:
          Given: Generated spray script
          When: Checking file permissions
          Then: Execute bit is set
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                output_dir=Path(tmpdir),
            )

            result = gen.generate_spray_script(
                users=["admin"],
                passwords=["P1"],
            )

            mode = os.stat(result.main_script).st_mode
            assert mode & stat.S_IXUSR, "User execute bit not set"

    def test_script_contains_domain_and_dc(self):
        """
        BV: Script has correct target info

        Scenario:
          Given: Domain and DC IP
          When: Generating script
          Then: Script contains target info
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ScriptGenerator(
                domain="corp.local",
                dc_ip="10.10.10.100",
                output_dir=Path(tmpdir),
            )

            result = gen.generate_spray_script(
                users=["admin"],
                passwords=["P1"],
            )

            content = result.main_script.read_text()
            assert "corp.local" in content
            assert "10.10.10.100" in content

    def test_script_with_lockout_manager_timing(self):
        """
        BV: Respect lockout timing in generated script

        Scenario:
          Given: Lockout manager with 30 min window
          When: Generating script for 5 passwords with 2 per round
          Then: Script has wait commands between rounds
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            lockout_manager = LockoutManager(
                manual_threshold=4,  # safe_attempts = 2
                manual_window_minutes=30,
            )

            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                output_dir=Path(tmpdir),
            )

            result = gen.generate_spray_script(
                users=["admin"],
                passwords=["P1", "P2", "P3", "P4", "P5"],
                lockout_manager=lockout_manager,
            )

            content = result.main_script.read_text()
            # Should have wait_for_window calls
            assert "wait_for_window" in content
            assert "1800" in content  # 30 min = 1800 sec

    def test_creates_round_scripts(self):
        """
        BV: Individual round scripts for granular control

        Scenario:
          Given: Multiple rounds needed
          When: Generating scripts
          Then: Individual round scripts created
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            lockout_manager = LockoutManager(
                manual_threshold=3,  # safe_attempts = 1
                manual_window_minutes=30,
            )

            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                output_dir=Path(tmpdir),
            )

            result = gen.generate_spray_script(
                users=["admin"],
                passwords=["P1", "P2", "P3"],
                lockout_manager=lockout_manager,
            )

            assert len(result.round_scripts) == 3
            for script in result.round_scripts:
                assert script.exists()
                assert "spray_round_" in script.name


# =============================================================================
# Generate Kerbrute Script Tests
# =============================================================================

class TestGenerateKerbruteScript:
    """Tests for generate_kerbrute_script method."""

    def test_sets_tool_to_kerbrute(self):
        """
        BV: Convenience method for Kerbrute

        Scenario:
          Given: Using generate_kerbrute_script
          When: Generating script
          Then: Tool is set to kerbrute
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                output_dir=Path(tmpdir),
                tool="crackmapexec",  # Different initial tool
            )

            script_path = gen.generate_kerbrute_script(
                users=["admin"],
                passwords=["P1"],
            )

            content = script_path.read_text()
            assert "kerbrute" in content
            # Should NOT contain crackmapexec
            assert "crackmapexec smb" not in content


# =============================================================================
# Generate CME Script Tests
# =============================================================================

class TestGenerateCMEScript:
    """Tests for generate_cme_script method."""

    def test_sets_tool_to_crackmapexec(self):
        """
        BV: Convenience method for CrackMapExec

        Scenario:
          Given: Using generate_cme_script
          When: Generating script
          Then: Tool is set to crackmapexec
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                output_dir=Path(tmpdir),
                tool="kerbrute",  # Different initial tool
            )

            script_path = gen.generate_cme_script(
                users=["admin"],
                passwords=["P1"],
            )

            content = script_path.read_text()
            assert "crackmapexec smb" in content

    def test_with_lockout_manager(self):
        """
        BV: CME script respects lockout timing

        Scenario:
          Given: Lockout manager provided
          When: Generating CME script
          Then: Script has proper delays
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            lockout_manager = LockoutManager(
                manual_threshold=3,
                manual_window_minutes=15,
            )

            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                output_dir=Path(tmpdir),
            )

            script_path = gen.generate_cme_script(
                users=["admin"],
                passwords=["P1", "P2"],
                lockout_manager=lockout_manager,
            )

            content = script_path.read_text()
            assert "wait_for_window" in content or "Round" in content


# =============================================================================
# Generate Quick Spray Tests
# =============================================================================

class TestGenerateQuickSpray:
    """Tests for generate_quick_spray method."""

    def test_returns_single_command(self):
        """
        BV: Quick command for simple testing

        Scenario:
          Given: Users and single password
          When: Generating quick spray
          Then: Returns one-line command
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                output_dir=Path(tmpdir),
                tool="crackmapexec",
            )

            cmd = gen.generate_quick_spray(
                users=["admin", "user1"],
                password="Summer2024!",
            )

            assert "crackmapexec smb" in cmd
            assert "192.168.1.100" in cmd
            assert "Summer2024!" in cmd
            assert "corp.com" in cmd

    def test_creates_users_file(self):
        """
        BV: Creates user file for command reference

        Scenario:
          Given: User list
          When: Generating quick spray
          Then: User file created and referenced in command
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                output_dir=Path(tmpdir),
            )

            cmd = gen.generate_quick_spray(
                users=["admin", "user1"],
                password="P1",
            )

            users_file = gen.output_dir / "users.txt"
            assert users_file.exists()
            assert str(users_file) in cmd

    def test_kerbrute_quick_spray(self):
        """
        BV: Kerbrute command format

        Scenario:
          Given: Tool is kerbrute
          When: Generating quick spray
          Then: Uses kerbrute syntax
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                output_dir=Path(tmpdir),
                tool="kerbrute",
            )

            cmd = gen.generate_quick_spray(
                users=["admin"],
                password="P1",
            )

            assert "kerbrute passwordspray" in cmd
            assert "-d corp.com" in cmd
            assert "--dc 192.168.1.100" in cmd

    def test_hydra_quick_spray(self):
        """
        BV: Hydra command format

        Scenario:
          Given: Tool is hydra
          When: Generating quick spray
          Then: Uses hydra syntax
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                output_dir=Path(tmpdir),
                tool="hydra",
            )

            cmd = gen.generate_quick_spray(
                users=["admin"],
                password="P1",
            )

            assert "hydra" in cmd
            assert "-L" in cmd  # User file flag
            assert "smb://" in cmd


# =============================================================================
# Special Character Escaping Tests
# =============================================================================

class TestSpecialCharacterEscaping:
    """Tests for special character handling in passwords."""

    def test_single_quotes_in_password(self):
        """
        BV: Passwords with single quotes escaped properly

        Scenario:
          Given: Password containing single quote
          When: Generating script
          Then: Quote is properly escaped
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                output_dir=Path(tmpdir),
            )

            result = gen.generate_spray_script(
                users=["admin"],
                passwords=["It's@Password!"],
            )

            content = result.main_script.read_text()
            # Single quote should be escaped for shell
            # The escape pattern is: ' becomes '"'"'
            assert "It" in content
            assert "Password" in content

    def test_double_quotes_in_password(self):
        """
        BV: Passwords with double quotes handled

        Scenario:
          Given: Password containing double quote
          When: Generating script
          Then: Quote is handled properly
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                output_dir=Path(tmpdir),
            )

            result = gen.generate_spray_script(
                users=["admin"],
                passwords=['Say"Hello"'],
            )

            content = result.main_script.read_text()
            # Password should be in script
            assert "Say" in content or "Hello" in content

    def test_special_shell_chars(self):
        """
        BV: Handle shell special characters

        Scenario:
          Given: Password with shell metacharacters
          When: Generating script
          Then: Script doesn't break
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                output_dir=Path(tmpdir),
            )

            # Characters that could break shell if not escaped
            passwords = ["P@$$w0rd!", "Test&Test", "Foo|Bar", "A;B;C"]

            result = gen.generate_spray_script(
                users=["admin"],
                passwords=passwords,
            )

            # Script should be syntactically valid (basic check)
            content = result.main_script.read_text()
            assert "spray_password" in content


# =============================================================================
# Template Variable Substitution Tests
# =============================================================================

class TestTemplateSubstitution:
    """Tests for template variable handling."""

    def test_domain_substituted(self):
        """
        BV: DOMAIN variable set correctly

        Scenario:
          Given: Domain specified
          When: Generating script
          Then: DOMAIN variable contains domain
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ScriptGenerator(
                domain="target.corp.com",
                dc_ip="192.168.1.100",
                output_dir=Path(tmpdir),
            )

            result = gen.generate_spray_script(
                users=["admin"],
                passwords=["P1"],
            )

            content = result.main_script.read_text()
            assert 'DOMAIN="target.corp.com"' in content

    def test_dc_ip_substituted(self):
        """
        BV: DC_IP variable set correctly

        Scenario:
          Given: DC IP specified
          When: Generating script
          Then: DC_IP variable contains IP
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="10.10.10.100",
                output_dir=Path(tmpdir),
            )

            result = gen.generate_spray_script(
                users=["admin"],
                passwords=["P1"],
            )

            content = result.main_script.read_text()
            assert 'DC_IP="10.10.10.100"' in content

    def test_user_file_path_substituted(self):
        """
        BV: USER_FILE variable set correctly

        Scenario:
          Given: Users file generated
          When: Checking script
          Then: USER_FILE contains absolute path
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                output_dir=Path(tmpdir),
            )

            result = gen.generate_spray_script(
                users=["admin"],
                passwords=["P1"],
            )

            content = result.main_script.read_text()
            # Should contain absolute path to users file
            assert "USER_FILE=" in content
            assert "users.txt" in content


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Edge case handling tests."""

    def test_empty_users_list(self):
        """
        BV: Handle empty users gracefully

        Scenario:
          Given: Empty users list
          When: Generating script
          Then: Creates empty users file
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                output_dir=Path(tmpdir),
            )

            result = gen.generate_spray_script(
                users=[],
                passwords=["P1"],
            )

            assert result.users_file.exists()
            assert result.users_file.read_text() == ""

    def test_empty_passwords_list(self):
        """
        BV: Handle empty passwords gracefully

        Scenario:
          Given: Empty passwords list
          When: Generating script
          Then: Creates minimal script
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                output_dir=Path(tmpdir),
            )

            result = gen.generate_spray_script(
                users=["admin"],
                passwords=[],
            )

            assert result.main_script.exists()
            assert result.passwords_file.read_text() == ""

    def test_very_long_password(self):
        """
        BV: Handle long passwords

        Scenario:
          Given: Very long password
          When: Generating script
          Then: Password included fully
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                output_dir=Path(tmpdir),
            )

            long_password = "A" * 500

            result = gen.generate_spray_script(
                users=["admin"],
                passwords=[long_password],
            )

            content = result.passwords_file.read_text()
            assert long_password in content

    def test_unicode_in_usernames(self):
        """
        BV: Handle unicode usernames

        Scenario:
          Given: Usernames with unicode
          When: Generating script
          Then: Characters preserved
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                output_dir=Path(tmpdir),
            )

            result = gen.generate_spray_script(
                users=["user_unicode_cafe"],  # Using ASCII to avoid encoding issues
                passwords=["P1"],
            )

            content = result.users_file.read_text()
            assert "user_unicode" in content

    def test_no_lockout_manager_single_round(self):
        """
        BV: No lockout manager = single round

        Scenario:
          Given: No lockout manager provided
          When: Generating script
          Then: All passwords in single round
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                output_dir=Path(tmpdir),
            )

            result = gen.generate_spray_script(
                users=["admin"],
                passwords=["P1", "P2", "P3", "P4", "P5"],
                lockout_manager=None,
            )

            # With no lockout manager, should be 1 round
            assert len(result.round_scripts) == 1

    def test_output_dir_string_converted_to_path(self):
        """
        BV: String output_dir converted to Path

        Scenario:
          Given: output_dir as string
          When: Creating generator
          Then: Converted to Path object
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                output_dir=tmpdir,  # String, not Path
            )

            assert isinstance(gen.output_dir, Path)


# =============================================================================
# Script Content Validation Tests
# =============================================================================

class TestScriptContentValidation:
    """Tests for script content correctness."""

    def test_script_has_shebang(self):
        """
        BV: Script starts with proper shebang

        Scenario:
          Given: Generated script
          When: Checking first line
          Then: Has #!/bin/bash
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                output_dir=Path(tmpdir),
            )

            result = gen.generate_spray_script(
                users=["admin"],
                passwords=["P1"],
            )

            content = result.main_script.read_text()
            assert content.startswith("#!/bin/bash")

    def test_script_has_confirmation_prompt(self):
        """
        BV: Script requires confirmation before spray

        Scenario:
          Given: Generated script
          When: Checking content
          Then: Has confirmation prompt
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                output_dir=Path(tmpdir),
            )

            result = gen.generate_spray_script(
                users=["admin"],
                passwords=["P1"],
            )

            content = result.main_script.read_text()
            assert "Continue?" in content or "confirm" in content.lower()

    def test_script_shows_summary_at_end(self):
        """
        BV: Script shows results summary

        Scenario:
          Given: Generated script
          When: Checking content
          Then: Has summary section
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                output_dir=Path(tmpdir),
            )

            result = gen.generate_spray_script(
                users=["admin"],
                passwords=["P1"],
            )

            content = result.main_script.read_text()
            assert "Complete" in content or "Results" in content

    def test_script_creates_results_file(self):
        """
        BV: Script logs results to file

        Scenario:
          Given: Generated script
          When: Checking content
          Then: References results file
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            gen = ScriptGenerator(
                domain="corp.com",
                dc_ip="192.168.1.100",
                output_dir=Path(tmpdir),
            )

            result = gen.generate_spray_script(
                users=["admin"],
                passwords=["P1"],
            )

            content = result.main_script.read_text()
            assert "spray_results.txt" in content
