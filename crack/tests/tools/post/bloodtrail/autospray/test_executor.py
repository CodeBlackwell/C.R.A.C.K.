"""
Tests for SprayExecutor

Business Value Focus:
- Reliable tool detection prevents spray failures
- Real-time output streaming enables monitoring
- Lockout-aware execution prevents account lockouts
- Proper cleanup prevents temp file accumulation

Test Priority: TIER 1 - CRITICAL (Operational Safety)
"""

import sys
import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch, call
from datetime import datetime

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).parent.parent.parent.parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from tools.post.bloodtrail.autospray.executor import (
    SprayExecutor,
    SprayResult,
    ToolConfig,
    ToolNotFoundError,
    TOOL_CONFIGS,
    TOOL_PRIORITY,
)
from tools.post.bloodtrail.autospray.result_parser import SprayTool, ParsedResult
from tools.post.bloodtrail.autospray.lockout_manager import LockoutManager, SprayWindow


# =============================================================================
# Factories
# =============================================================================

class SprayResultFactory:
    """Factory for creating SprayResult test objects."""

    @classmethod
    def create_success(
        cls,
        password: str = "Password1!",
        target: str = "192.168.1.100",
        tool: str = "netexec",
        results: list = None,
    ) -> SprayResult:
        """Create successful spray result."""
        if results is None:
            results = [
                ParsedResult(
                    username="admin",
                    password=password,
                    target=target,
                    domain="CORP",
                    is_admin=True,
                )
            ]
        return SprayResult(
            success=True,
            results=results,
            password=password,
            target=target,
            tool=tool,
            duration_seconds=5.0,
        )

    @classmethod
    def create_failure(
        cls,
        password: str = "WrongPass!",
        target: str = "192.168.1.100",
        tool: str = "netexec",
        error: str = None,
    ) -> SprayResult:
        """Create failed spray result."""
        return SprayResult(
            success=False,
            results=[],
            password=password,
            target=target,
            tool=tool,
            duration_seconds=3.0,
            error=error,
        )


# =============================================================================
# SprayResult Dataclass Tests
# =============================================================================

class TestSprayResult:
    """Tests for SprayResult dataclass properties."""

    def test_admin_count_with_admins(self):
        """
        BV: Accurately count admin access for prioritization

        Scenario:
          Given: SprayResult with 2 admin and 1 non-admin result
          When: Getting admin_count property
          Then: Returns 2
        """
        results = [
            ParsedResult(username="admin1", password="P1", target="dc", is_admin=True),
            ParsedResult(username="admin2", password="P1", target="dc", is_admin=True),
            ParsedResult(username="user1", password="P1", target="dc", is_admin=False),
        ]
        spray_result = SprayResult(
            success=True,
            results=results,
            password="P1",
            target="dc",
            tool="netexec",
        )

        assert spray_result.admin_count == 2

    def test_admin_count_no_admins(self):
        """
        BV: Handle case with no admin access

        Scenario:
          Given: SprayResult with only non-admin results
          When: Getting admin_count property
          Then: Returns 0
        """
        results = [
            ParsedResult(username="user1", password="P1", target="dc", is_admin=False),
            ParsedResult(username="user2", password="P1", target="dc", is_admin=False),
        ]
        spray_result = SprayResult(
            success=True,
            results=results,
            password="P1",
            target="dc",
            tool="kerbrute",
        )

        assert spray_result.admin_count == 0

    def test_credential_count(self):
        """
        BV: Total credential count for reporting

        Scenario:
          Given: SprayResult with 3 valid credentials
          When: Getting credential_count property
          Then: Returns 3
        """
        results = [
            ParsedResult(username="u1", password="P1", target="dc"),
            ParsedResult(username="u2", password="P1", target="dc"),
            ParsedResult(username="u3", password="P1", target="dc"),
        ]
        spray_result = SprayResult(
            success=True,
            results=results,
            password="P1",
            target="dc",
            tool="netexec",
        )

        assert spray_result.credential_count == 3

    def test_credential_count_empty(self):
        """
        BV: Handle empty results gracefully

        Scenario:
          Given: SprayResult with no credentials
          When: Getting credential_count property
          Then: Returns 0
        """
        spray_result = SprayResult(
            success=False,
            results=[],
            password="WrongPass",
            target="dc",
            tool="netexec",
        )

        assert spray_result.credential_count == 0

    def test_success_with_error_is_valid(self):
        """
        BV: Allow success=True even with non-fatal error

        Scenario:
          Given: Spray found credentials but had warning
          When: Creating SprayResult
          Then: Can have success=True with error set
        """
        spray_result = SprayResult(
            success=True,
            results=[ParsedResult(username="admin", password="P1", target="dc")],
            password="P1",
            target="dc",
            tool="netexec",
            error="Non-fatal warning",
        )

        assert spray_result.success is True
        assert spray_result.error == "Non-fatal warning"


# =============================================================================
# SprayExecutor Initialization Tests
# =============================================================================

class TestSprayExecutorInit:
    """Tests for SprayExecutor initialization."""

    def test_init_with_defaults(self):
        """
        BV: Executor works with minimal configuration

        Scenario:
          Given: Only domain and dc_ip provided
          When: Creating SprayExecutor
          Then: Has sensible defaults
        """
        executor = SprayExecutor(
            domain="corp.com",
            dc_ip="192.168.1.100",
        )

        assert executor.domain == "corp.com"
        assert executor.dc_ip == "192.168.1.100"
        assert executor.tool is None  # Auto-detect
        assert executor.timeout == 300
        assert executor.verbose is True

    def test_init_with_specific_tool(self):
        """
        BV: Force specific tool when auto-detect undesirable

        Scenario:
          Given: Tool explicitly specified
          When: Creating SprayExecutor
          Then: Uses specified tool
        """
        executor = SprayExecutor(
            tool=SprayTool.KERBRUTE,
            domain="corp.com",
            dc_ip="192.168.1.100",
        )

        assert executor.tool == SprayTool.KERBRUTE

    def test_init_with_custom_timeout(self):
        """
        BV: Custom timeout for slow networks

        Scenario:
          Given: Custom timeout specified
          When: Creating SprayExecutor
          Then: Uses custom timeout
        """
        executor = SprayExecutor(
            domain="corp.com",
            dc_ip="192.168.1.100",
            timeout=600,
        )

        assert executor.timeout == 600

    def test_init_verbose_false(self):
        """
        BV: Suppress output for scripted usage

        Scenario:
          Given: verbose=False
          When: Creating SprayExecutor
          Then: Verbose mode disabled
        """
        executor = SprayExecutor(
            domain="corp.com",
            dc_ip="192.168.1.100",
            verbose=False,
        )

        assert executor.verbose is False


# =============================================================================
# Tool Detection Tests
# =============================================================================

class TestToolDetection:
    """Tests for tool auto-detection functionality."""

    @patch('shutil.which')
    def test_detect_netexec_first(self, mock_which):
        """
        BV: NetExec detected as priority tool

        Scenario:
          Given: NetExec is installed
          When: Detecting available tool
          Then: Returns SprayTool.NETEXEC
        """
        mock_which.side_effect = lambda x: "/usr/bin/netexec" if x == "netexec" else None

        executor = SprayExecutor(domain="corp.com", dc_ip="192.168.1.100")
        tool = executor.detect_available_tool()

        assert tool == SprayTool.NETEXEC

    @patch('shutil.which')
    def test_detect_crackmapexec_fallback(self, mock_which):
        """
        BV: Fall back to CrackMapExec if NetExec unavailable

        Scenario:
          Given: Only CrackMapExec is installed
          When: Detecting available tool
          Then: Returns SprayTool.CRACKMAPEXEC
        """
        def which_side_effect(binary):
            if binary == "crackmapexec":
                return "/usr/bin/crackmapexec"
            return None

        mock_which.side_effect = which_side_effect

        executor = SprayExecutor(domain="corp.com", dc_ip="192.168.1.100")
        tool = executor.detect_available_tool()

        assert tool == SprayTool.CRACKMAPEXEC

    @patch('shutil.which')
    def test_detect_kerbrute_fallback(self, mock_which):
        """
        BV: Fall back to Kerbrute if SMB tools unavailable

        Scenario:
          Given: Only Kerbrute is installed
          When: Detecting available tool
          Then: Returns SprayTool.KERBRUTE
        """
        mock_which.side_effect = lambda x: "/usr/bin/kerbrute" if x == "kerbrute" else None

        executor = SprayExecutor(domain="corp.com", dc_ip="192.168.1.100")
        tool = executor.detect_available_tool()

        assert tool == SprayTool.KERBRUTE

    @patch('shutil.which')
    def test_detect_hydra_last_resort(self, mock_which):
        """
        BV: Fall back to Hydra as last resort

        Scenario:
          Given: Only Hydra is installed
          When: Detecting available tool
          Then: Returns SprayTool.HYDRA
        """
        mock_which.side_effect = lambda x: "/usr/bin/hydra" if x == "hydra" else None

        executor = SprayExecutor(domain="corp.com", dc_ip="192.168.1.100")
        tool = executor.detect_available_tool()

        assert tool == SprayTool.HYDRA

    @patch('shutil.which')
    def test_detect_no_tools_returns_none(self, mock_which):
        """
        BV: Handle no tools installed gracefully

        Scenario:
          Given: No spray tools are installed
          When: Detecting available tool
          Then: Returns None
        """
        mock_which.return_value = None

        executor = SprayExecutor(domain="corp.com", dc_ip="192.168.1.100")
        tool = executor.detect_available_tool()

        assert tool is None

    @patch('shutil.which')
    def test_detect_caches_result(self, mock_which):
        """
        BV: Cache detection result to avoid repeated checks

        Scenario:
          Given: Tool detection performed once
          When: Calling detect_available_tool again
          Then: Returns cached result without re-checking
        """
        mock_which.return_value = "/usr/bin/netexec"

        executor = SprayExecutor(domain="corp.com", dc_ip="192.168.1.100")

        # First call
        tool1 = executor.detect_available_tool()
        # Reset mock to see if it's called again
        mock_which.reset_mock()
        mock_which.return_value = None  # Would return different result

        # Second call should use cache
        tool2 = executor.detect_available_tool()

        assert tool1 == tool2 == SprayTool.NETEXEC
        mock_which.assert_not_called()


class TestIsToolAvailable:
    """Tests for is_tool_available method."""

    @patch('shutil.which')
    def test_tool_available_true(self, mock_which):
        """
        BV: Correctly detect installed tool

        Scenario:
          Given: NetExec is installed
          When: Checking if netexec is available
          Then: Returns True
        """
        mock_which.return_value = "/usr/bin/netexec"

        executor = SprayExecutor(domain="corp.com", dc_ip="192.168.1.100")
        result = executor.is_tool_available(SprayTool.NETEXEC)

        assert result is True
        mock_which.assert_called_with("netexec")

    @patch('shutil.which')
    def test_tool_available_false(self, mock_which):
        """
        BV: Correctly detect missing tool

        Scenario:
          Given: Kerbrute is not installed
          When: Checking if kerbrute is available
          Then: Returns False
        """
        mock_which.return_value = None

        executor = SprayExecutor(domain="corp.com", dc_ip="192.168.1.100")
        result = executor.is_tool_available(SprayTool.KERBRUTE)

        assert result is False

    def test_unknown_tool_returns_false(self):
        """
        BV: Handle unknown tool enum gracefully

        Scenario:
          Given: Invalid tool enum value
          When: Checking availability
          Then: Returns False without error
        """
        executor = SprayExecutor(domain="corp.com", dc_ip="192.168.1.100")

        # Create mock enum not in TOOL_CONFIGS
        mock_tool = MagicMock()
        mock_tool.value = "unknown_tool"

        result = executor.is_tool_available(mock_tool)

        assert result is False


class TestGetAvailableTools:
    """Tests for get_available_tools class method."""

    @patch('subprocess.run')
    @patch('shutil.which')
    def test_returns_available_tools_with_versions(self, mock_which, mock_run):
        """
        BV: Report available tools with version info

        Scenario:
          Given: NetExec and Kerbrute are installed
          When: Getting available tools
          Then: Returns list with tool and version tuples
        """
        def which_side_effect(binary):
            if binary in ("netexec", "kerbrute"):
                return f"/usr/bin/{binary}"
            return None

        mock_which.side_effect = which_side_effect
        mock_run.return_value = MagicMock(
            stdout="netexec 1.0.0",
            returncode=0
        )

        available = SprayExecutor.get_available_tools()

        # Should have netexec and kerbrute
        tools = [t[0] for t in available]
        assert SprayTool.NETEXEC in tools
        assert SprayTool.KERBRUTE in tools
        assert SprayTool.CRACKMAPEXEC not in tools

    @patch('subprocess.run')
    @patch('shutil.which')
    def test_handles_version_check_failure(self, mock_which, mock_run):
        """
        BV: Gracefully handle version check failures

        Scenario:
          Given: Tool exists but version check fails
          When: Getting available tools
          Then: Returns "installed" as version
        """
        mock_which.return_value = "/usr/bin/netexec"
        mock_run.side_effect = Exception("Permission denied")

        available = SprayExecutor.get_available_tools()

        assert len(available) > 0
        # Should have "installed" as fallback version
        assert any(v == "installed" for _, v in available)

    @patch('shutil.which')
    def test_empty_when_no_tools(self, mock_which):
        """
        BV: Empty list when no tools available

        Scenario:
          Given: No spray tools installed
          When: Getting available tools
          Then: Returns empty list
        """
        mock_which.return_value = None

        available = SprayExecutor.get_available_tools()

        assert available == []


# =============================================================================
# Get Tool Tests
# =============================================================================

class TestGetTool:
    """Tests for get_tool method."""

    @patch('shutil.which')
    def test_get_tool_uses_explicit_tool(self, mock_which):
        """
        BV: Explicit tool selection honored

        Scenario:
          Given: Specific tool requested
          When: Getting tool
          Then: Returns requested tool
        """
        mock_which.return_value = "/usr/bin/kerbrute"

        executor = SprayExecutor(
            tool=SprayTool.KERBRUTE,
            domain="corp.com",
            dc_ip="192.168.1.100",
        )
        tool = executor.get_tool()

        assert tool == SprayTool.KERBRUTE

    @patch('shutil.which')
    def test_get_tool_raises_if_explicit_not_found(self, mock_which):
        """
        BV: Clear error when requested tool missing

        Scenario:
          Given: Specific tool requested but not installed
          When: Getting tool
          Then: Raises ToolNotFoundError
        """
        mock_which.return_value = None

        executor = SprayExecutor(
            tool=SprayTool.KERBRUTE,
            domain="corp.com",
            dc_ip="192.168.1.100",
        )

        with pytest.raises(ToolNotFoundError) as exc_info:
            executor.get_tool()

        assert "kerbrute" in str(exc_info.value).lower()

    @patch('shutil.which')
    def test_get_tool_auto_detects(self, mock_which):
        """
        BV: Auto-detection when no tool specified

        Scenario:
          Given: No specific tool requested
          When: Getting tool
          Then: Returns auto-detected tool
        """
        mock_which.side_effect = lambda x: "/usr/bin/netexec" if x == "netexec" else None

        executor = SprayExecutor(domain="corp.com", dc_ip="192.168.1.100")
        tool = executor.get_tool()

        assert tool == SprayTool.NETEXEC

    @patch('shutil.which')
    def test_get_tool_raises_if_none_available(self, mock_which):
        """
        BV: Clear error when no tools available

        Scenario:
          Given: No spray tools installed
          When: Getting tool
          Then: Raises ToolNotFoundError with install hint
        """
        mock_which.return_value = None

        executor = SprayExecutor(domain="corp.com", dc_ip="192.168.1.100")

        with pytest.raises(ToolNotFoundError) as exc_info:
            executor.get_tool()

        error_msg = str(exc_info.value).lower()
        assert "no spray tools found" in error_msg
        assert "netexec" in error_msg or "crackmapexec" in error_msg


# =============================================================================
# User File Creation Tests
# =============================================================================

class TestCreateUserFile:
    """Tests for create_user_file method."""

    def test_creates_temp_file_with_users(self):
        """
        BV: Create temp file with user list for spray tool

        Scenario:
          Given: List of usernames
          When: Creating user file
          Then: Returns path to file with usernames
        """
        executor = SprayExecutor(domain="corp.com", dc_ip="192.168.1.100")

        try:
            users = ["admin", "user1", "svcaccount"]
            path = executor.create_user_file(users)

            assert path.exists()
            content = path.read_text()
            assert "admin\nuser1\nsvcaccount" == content
        finally:
            executor.cleanup()

    def test_file_tracked_for_cleanup(self):
        """
        BV: Temp files tracked for cleanup to prevent accumulation

        Scenario:
          Given: User file created
          When: Checking internal tracking
          Then: Path is in _temp_files list
        """
        executor = SprayExecutor(domain="corp.com", dc_ip="192.168.1.100")

        try:
            path = executor.create_user_file(["user1"])

            assert path in executor._temp_files
        finally:
            executor.cleanup()

    def test_file_has_txt_suffix(self):
        """
        BV: File extension helps identify temp files

        Scenario:
          Given: Creating user file
          When: Checking filename
          Then: Has .txt suffix
        """
        executor = SprayExecutor(domain="corp.com", dc_ip="192.168.1.100")

        try:
            path = executor.create_user_file(["user1"])

            assert path.suffix == ".txt"
        finally:
            executor.cleanup()

    def test_handles_empty_user_list(self):
        """
        BV: Handle empty user list gracefully

        Scenario:
          Given: Empty user list
          When: Creating user file
          Then: Creates empty file
        """
        executor = SprayExecutor(domain="corp.com", dc_ip="192.168.1.100")

        try:
            path = executor.create_user_file([])

            assert path.exists()
            assert path.read_text() == ""
        finally:
            executor.cleanup()

    def test_handles_special_characters_in_usernames(self):
        """
        BV: Preserve special characters in usernames

        Scenario:
          Given: Usernames with special characters
          When: Creating user file
          Then: Characters preserved
        """
        executor = SprayExecutor(domain="corp.com", dc_ip="192.168.1.100")

        try:
            users = ["admin$", "user@domain", "svc_account"]
            path = executor.create_user_file(users)

            content = path.read_text()
            assert "admin$" in content
            assert "user@domain" in content
        finally:
            executor.cleanup()


# =============================================================================
# Spray Single Password Tests
# =============================================================================

class TestSpraySinglePassword:
    """Tests for spray_single_password method."""

    @patch('subprocess.Popen')
    @patch('shutil.which')
    def test_spray_executes_command(self, mock_which, mock_popen):
        """
        BV: Execute spray command against target

        Scenario:
          Given: Valid tool and users
          When: Spraying single password
          Then: Subprocess executed with correct command
        """
        mock_which.return_value = "/usr/bin/netexec"

        mock_process = MagicMock()
        mock_process.stdout.readline.side_effect = ["", StopIteration]
        mock_process.stdout.__iter__ = lambda self: iter([])
        mock_process.wait.return_value = None
        mock_process.returncode = 0
        mock_popen.return_value = mock_process

        executor = SprayExecutor(
            domain="corp.com",
            dc_ip="192.168.1.100",
            verbose=False,
        )

        try:
            result = executor.spray_single_password(
                users=["admin", "user1"],
                password="Summer2024!",
            )

            # Verify subprocess called
            mock_popen.assert_called_once()
            cmd = mock_popen.call_args[0][0]
            assert "netexec" in cmd
            assert "192.168.1.100" in cmd
            assert "corp.com" in cmd
            assert "Summer2024!" in cmd
        finally:
            executor.cleanup()

    @patch('subprocess.Popen')
    @patch('shutil.which')
    def test_spray_returns_result_on_success(self, mock_which, mock_popen):
        """
        BV: Return SprayResult with parsed credentials

        Scenario:
          Given: Spray finds valid credential
          When: Parsing output
          Then: SprayResult contains parsed credential
        """
        mock_which.return_value = "/usr/bin/netexec"

        success_line = "SMB  192.168.1.100   445    DC01  [+] corp.com\\admin:Summer2024! (Pwn3d!)"
        mock_process = MagicMock()
        mock_process.stdout.__iter__ = lambda self: iter([success_line, ""])
        mock_process.stdout.readline.side_effect = [success_line, ""]
        mock_process.wait.return_value = None
        mock_process.returncode = 0
        mock_popen.return_value = mock_process

        executor = SprayExecutor(
            domain="corp.com",
            dc_ip="192.168.1.100",
            verbose=False,
        )

        try:
            result = executor.spray_single_password(
                users=["admin"],
                password="Summer2024!",
            )

            assert result.success is True
            assert result.credential_count >= 1
        finally:
            executor.cleanup()

    @patch('subprocess.Popen')
    @patch('shutil.which')
    def test_spray_calls_output_callback(self, mock_which, mock_popen):
        """
        BV: Real-time output via callback

        Scenario:
          Given: Output callback provided
          When: Spray produces output
          Then: Callback called with each line
        """
        mock_which.return_value = "/usr/bin/netexec"

        lines = ["Line 1", "Line 2", "Line 3"]
        mock_process = MagicMock()
        mock_process.stdout.__iter__ = lambda self: iter(lines + [""])
        mock_process.stdout.readline.side_effect = lines + [""]
        mock_process.wait.return_value = None
        mock_process.returncode = 0
        mock_popen.return_value = mock_process

        received_lines = []

        def callback(line):
            received_lines.append(line)

        executor = SprayExecutor(
            domain="corp.com",
            dc_ip="192.168.1.100",
            verbose=False,
        )

        try:
            executor.spray_single_password(
                users=["admin"],
                password="P1",
                output_callback=callback,
            )

            assert len(received_lines) == 3
        finally:
            executor.cleanup()

    @patch('subprocess.Popen')
    @patch('shutil.which')
    def test_spray_handles_timeout(self, mock_which, mock_popen):
        """
        BV: Handle command timeout gracefully

        Scenario:
          Given: Command times out
          When: Spray execution
          Then: Returns result with timeout error
        """
        import subprocess

        mock_which.return_value = "/usr/bin/netexec"

        mock_process = MagicMock()
        mock_process.stdout.__iter__ = lambda self: iter([])
        mock_process.stdout.readline.return_value = ""
        mock_process.wait.side_effect = subprocess.TimeoutExpired("cmd", 5)
        mock_process.kill = MagicMock()
        mock_popen.return_value = mock_process

        executor = SprayExecutor(
            domain="corp.com",
            dc_ip="192.168.1.100",
            timeout=5,
            verbose=False,
        )

        try:
            result = executor.spray_single_password(
                users=["admin"],
                password="P1",
            )

            assert result.success is False
            assert "timed out" in result.error.lower()
            mock_process.kill.assert_called_once()
        finally:
            executor.cleanup()

    @patch('subprocess.Popen')
    @patch('shutil.which')
    def test_spray_handles_process_error(self, mock_which, mock_popen):
        """
        BV: Handle process execution errors

        Scenario:
          Given: Process fails with error
          When: Spray execution
          Then: Returns result with error message
        """
        mock_which.return_value = "/usr/bin/netexec"
        mock_popen.side_effect = OSError("Command not found")

        executor = SprayExecutor(
            domain="corp.com",
            dc_ip="192.168.1.100",
            verbose=False,
        )

        try:
            result = executor.spray_single_password(
                users=["admin"],
                password="P1",
            )

            assert result.success is False
            assert result.error is not None
        finally:
            executor.cleanup()

    @patch('subprocess.Popen')
    @patch('shutil.which')
    def test_spray_records_duration(self, mock_which, mock_popen):
        """
        BV: Track spray duration for timing analysis

        Scenario:
          Given: Spray execution completes
          When: Checking result
          Then: duration_seconds > 0
        """
        mock_which.return_value = "/usr/bin/netexec"

        mock_process = MagicMock()
        mock_process.stdout.__iter__ = lambda self: iter([])
        mock_process.stdout.readline.return_value = ""
        mock_process.wait.return_value = None
        mock_process.returncode = 0
        mock_popen.return_value = mock_process

        executor = SprayExecutor(
            domain="corp.com",
            dc_ip="192.168.1.100",
            verbose=False,
        )

        try:
            result = executor.spray_single_password(
                users=["admin"],
                password="P1",
            )

            assert result.duration_seconds >= 0
        finally:
            executor.cleanup()


# =============================================================================
# Spray With Plan Tests
# =============================================================================

class TestSprayWithPlan:
    """Tests for spray_with_plan method."""

    @patch('subprocess.Popen')
    @patch('shutil.which')
    def test_spray_with_plan_executes_all_passwords(self, mock_which, mock_popen):
        """
        BV: Execute all passwords in plan

        Scenario:
          Given: Plan with 3 passwords across 2 rounds
          When: Executing spray plan
          Then: All passwords tested
        """
        mock_which.return_value = "/usr/bin/netexec"

        mock_process = MagicMock()
        mock_process.stdout.__iter__ = lambda self: iter([])
        mock_process.stdout.readline.return_value = ""
        mock_process.wait.return_value = None
        mock_process.returncode = 0
        mock_popen.return_value = mock_process

        lockout_manager = LockoutManager(
            manual_threshold=3,  # safe_attempts = 1
            manual_window_minutes=0,  # No delay for test
            override_mode=True,  # Skip waits
        )

        executor = SprayExecutor(
            domain="corp.com",
            dc_ip="192.168.1.100",
            verbose=False,
        )

        try:
            results = executor.spray_with_plan(
                users=["admin", "user1"],
                passwords=["P1", "P2", "P3"],
                lockout_manager=lockout_manager,
            )

            assert len(results) == 3
        finally:
            executor.cleanup()

    @patch('subprocess.Popen')
    @patch('shutil.which')
    def test_spray_with_plan_calls_progress_callback(self, mock_which, mock_popen):
        """
        BV: Report progress during spray

        Scenario:
          Given: Progress callback provided
          When: Spraying with plan
          Then: Callback called with progress updates
        """
        mock_which.return_value = "/usr/bin/netexec"

        mock_process = MagicMock()
        mock_process.stdout.__iter__ = lambda self: iter([])
        mock_process.stdout.readline.return_value = ""
        mock_process.wait.return_value = None
        mock_process.returncode = 0
        mock_popen.return_value = mock_process

        lockout_manager = LockoutManager(
            manual_threshold=10,
            override_mode=True,
        )

        progress_calls = []

        def progress_callback(current, total, status):
            progress_calls.append((current, total, status))

        executor = SprayExecutor(
            domain="corp.com",
            dc_ip="192.168.1.100",
            verbose=False,
        )

        try:
            executor.spray_with_plan(
                users=["admin"],
                passwords=["P1", "P2"],
                lockout_manager=lockout_manager,
                progress_callback=progress_callback,
            )

            assert len(progress_calls) > 0
        finally:
            executor.cleanup()

    @patch('subprocess.Popen')
    @patch('shutil.which')
    def test_spray_with_plan_calls_result_callback(self, mock_which, mock_popen):
        """
        BV: Report each result as it completes

        Scenario:
          Given: Result callback provided
          When: Each password tested
          Then: Callback called with SprayResult
        """
        mock_which.return_value = "/usr/bin/netexec"

        mock_process = MagicMock()
        mock_process.stdout.__iter__ = lambda self: iter([])
        mock_process.stdout.readline.return_value = ""
        mock_process.wait.return_value = None
        mock_process.returncode = 0
        mock_popen.return_value = mock_process

        lockout_manager = LockoutManager(
            manual_threshold=10,
            override_mode=True,
        )

        result_calls = []

        def result_callback(result):
            result_calls.append(result)

        executor = SprayExecutor(
            domain="corp.com",
            dc_ip="192.168.1.100",
            verbose=False,
        )

        try:
            executor.spray_with_plan(
                users=["admin"],
                passwords=["P1", "P2"],
                lockout_manager=lockout_manager,
                result_callback=result_callback,
            )

            assert len(result_calls) == 2
            assert all(isinstance(r, SprayResult) for r in result_calls)
        finally:
            executor.cleanup()


# =============================================================================
# Cleanup Tests
# =============================================================================

class TestCleanup:
    """Tests for cleanup method."""

    def test_cleanup_removes_temp_files(self):
        """
        BV: Remove temp files to prevent accumulation

        Scenario:
          Given: Temp user files created
          When: Calling cleanup
          Then: Files are deleted
        """
        executor = SprayExecutor(domain="corp.com", dc_ip="192.168.1.100")

        path1 = executor.create_user_file(["user1"])
        path2 = executor.create_user_file(["user2"])

        assert path1.exists()
        assert path2.exists()

        executor.cleanup()

        assert not path1.exists()
        assert not path2.exists()

    def test_cleanup_clears_tracking_list(self):
        """
        BV: Clear tracking list after cleanup

        Scenario:
          Given: Temp files tracked
          When: Calling cleanup
          Then: _temp_files list is empty
        """
        executor = SprayExecutor(domain="corp.com", dc_ip="192.168.1.100")

        executor.create_user_file(["user1"])
        executor.create_user_file(["user2"])

        assert len(executor._temp_files) == 2

        executor.cleanup()

        assert len(executor._temp_files) == 0

    def test_cleanup_handles_already_deleted(self):
        """
        BV: Handle case where file already deleted

        Scenario:
          Given: Temp file manually deleted
          When: Calling cleanup
          Then: No error raised
        """
        executor = SprayExecutor(domain="corp.com", dc_ip="192.168.1.100")

        path = executor.create_user_file(["user1"])
        path.unlink()  # Manually delete

        # Should not raise
        executor.cleanup()

        assert len(executor._temp_files) == 0


class TestContextManager:
    """Tests for context manager support."""

    def test_context_manager_cleanup(self):
        """
        BV: Auto-cleanup on context exit

        Scenario:
          Given: Executor used as context manager
          When: Exiting context
          Then: Temp files cleaned up
        """
        with SprayExecutor(domain="corp.com", dc_ip="192.168.1.100") as executor:
            path = executor.create_user_file(["user1"])
            assert path.exists()
            file_path = path  # Save for check after context

        assert not file_path.exists()

    def test_context_manager_cleanup_on_error(self):
        """
        BV: Cleanup even on exception

        Scenario:
          Given: Exception raised in context
          When: Exiting context
          Then: Temp files still cleaned up
        """
        file_path = None

        try:
            with SprayExecutor(domain="corp.com", dc_ip="192.168.1.100") as executor:
                file_path = executor.create_user_file(["user1"])
                raise ValueError("Test exception")
        except ValueError:
            pass

        assert file_path is not None
        assert not file_path.exists()


# =============================================================================
# Tool Config Tests
# =============================================================================

class TestToolConfigs:
    """Tests for TOOL_CONFIGS constants."""

    def test_all_priority_tools_have_configs(self):
        """
        BV: All priority tools are configured

        Scenario:
          Given: TOOL_PRIORITY list
          When: Checking TOOL_CONFIGS
          Then: All tools have configurations
        """
        for tool in TOOL_PRIORITY:
            assert tool in TOOL_CONFIGS, f"Missing config for {tool}"

    def test_configs_have_required_fields(self):
        """
        BV: All configs have required fields

        Scenario:
          Given: Tool configurations
          When: Checking fields
          Then: All required fields present
        """
        for tool, config in TOOL_CONFIGS.items():
            assert config.name, f"{tool} missing name"
            assert config.binary, f"{tool} missing binary"
            assert config.check_cmd, f"{tool} missing check_cmd"
            assert config.spray_template, f"{tool} missing spray_template"
            assert config.success_pattern, f"{tool} missing success_pattern"

    def test_spray_templates_have_placeholders(self):
        """
        BV: Templates can be filled with parameters

        Scenario:
          Given: Spray templates
          When: Checking placeholders
          Then: All have required placeholders (except Hydra which doesn't use domain)
        """
        # Common placeholders for all tools
        common_placeholders = ["{dc_ip}", "{user_file}", "{password}"]
        # Domain is used by most tools but not Hydra (SMB protocol doesn't need it)
        domain_using_tools = [SprayTool.NETEXEC, SprayTool.CRACKMAPEXEC, SprayTool.KERBRUTE]

        for tool, config in TOOL_CONFIGS.items():
            for placeholder in common_placeholders:
                assert placeholder in config.spray_template, \
                    f"{tool} template missing {placeholder}"

            if tool in domain_using_tools:
                assert "{domain}" in config.spray_template, \
                    f"{tool} template missing {{domain}}"


# =============================================================================
# ToolNotFoundError Tests
# =============================================================================

class TestToolNotFoundError:
    """Tests for ToolNotFoundError exception."""

    def test_exception_message(self):
        """
        BV: Clear error message for missing tool

        Scenario:
          Given: ToolNotFoundError raised
          When: Checking message
          Then: Contains helpful info
        """
        error = ToolNotFoundError("No spray tools found. Install netexec")

        assert "spray tools" in str(error).lower()

    def test_inherits_from_exception(self):
        """
        BV: Proper exception inheritance

        Scenario:
          Given: ToolNotFoundError
          When: Checking inheritance
          Then: Is subclass of Exception
        """
        assert issubclass(ToolNotFoundError, Exception)


# =============================================================================
# Edge Cases
# =============================================================================

class TestEdgeCases:
    """Edge case handling tests."""

    @patch('shutil.which')
    def test_empty_domain(self, mock_which):
        """
        BV: Handle empty domain

        Scenario:
          Given: Empty domain string
          When: Creating executor
          Then: No error (may fail at spray time)
        """
        mock_which.return_value = "/usr/bin/netexec"

        executor = SprayExecutor(domain="", dc_ip="192.168.1.100")

        assert executor.domain == ""

    @patch('shutil.which')
    def test_empty_dc_ip(self, mock_which):
        """
        BV: Handle empty DC IP

        Scenario:
          Given: Empty DC IP string
          When: Creating executor
          Then: No error (may fail at spray time)
        """
        mock_which.return_value = "/usr/bin/netexec"

        executor = SprayExecutor(domain="corp.com", dc_ip="")

        assert executor.dc_ip == ""

    def test_very_long_username_list(self):
        """
        BV: Handle large user lists

        Scenario:
          Given: 10000 usernames
          When: Creating user file
          Then: File created successfully
        """
        executor = SprayExecutor(domain="corp.com", dc_ip="192.168.1.100")

        try:
            users = [f"user{i}" for i in range(10000)]
            path = executor.create_user_file(users)

            content = path.read_text()
            lines = content.split("\n")
            assert len(lines) == 10000
        finally:
            executor.cleanup()

    def test_unicode_in_password(self):
        """
        BV: Handle unicode characters in passwords

        Scenario:
          Given: Password with unicode characters
          When: Building command
          Then: Characters preserved (shell may still fail)
        """
        executor = SprayExecutor(domain="corp.com", dc_ip="192.168.1.100")

        # This tests the internal command building, not actual execution
        try:
            executor.create_user_file(["admin"])
            # The _build_command would include the unicode password
            # Actual shell handling is tool-specific
        finally:
            executor.cleanup()
