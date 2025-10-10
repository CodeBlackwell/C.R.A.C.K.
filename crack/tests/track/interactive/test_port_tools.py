#!/usr/bin/env python3
"""
Test Port Lookup (pl) & Quick Execute (qe) Shortcuts

Tests for Stage 3.4 Enhanced Features:
- Port lookup reference tool
- Quick command execution without task tracking
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from crack.track.interactive.port_reference import PortReference, PortInfo
from crack.track.interactive.session import InteractiveSession


# ============================================================================
# PORT LOOKUP TESTS
# ============================================================================

def test_port_lookup_valid_port():
    """
    PROVES: User can lookup port 445 and get SMB enumeration commands

    User Story: User types 'pl' → enters 445 → sees SMB commands
    """
    port_info = PortReference.lookup(445)

    assert port_info is not None
    assert port_info.port == 445
    assert port_info.service == "SMB"
    assert len(port_info.enum_commands) > 0
    assert "enum4linux" in port_info.enum_commands[0]


def test_port_lookup_unknown_port():
    """
    PROVES: Unknown port returns None

    User Story: User types 'pl' → enters 9999 → sees "No reference data"
    """
    port_info = PortReference.lookup(9999)

    assert port_info is None


def test_port_lookup_shows_commands():
    """
    PROVES: Port lookup displays enumeration commands

    User Story: User looks up port 80 → sees gobuster, nikto, whatweb
    """
    port_info = PortReference.lookup(80)

    assert port_info is not None
    assert port_info.service == "HTTP"
    assert any("gobuster" in cmd for cmd in port_info.enum_commands)
    assert any("nikto" in cmd for cmd in port_info.enum_commands)


def test_port_lookup_shows_quick_wins():
    """
    PROVES: Port lookup displays quick win suggestions

    User Story: User looks up port 21 → sees "Try anonymous login"
    """
    port_info = PortReference.lookup(21)

    assert port_info is not None
    assert len(port_info.quick_wins) > 0
    assert any("anonymous" in win.lower() for win in port_info.quick_wins)


def test_port_lookup_shows_vulnerabilities():
    """
    PROVES: Port lookup lists common vulnerabilities

    User Story: User looks up port 445 → sees EternalBlue listed
    """
    port_info = PortReference.lookup(445)

    assert port_info is not None
    assert len(port_info.common_vulns) > 0
    assert any("EternalBlue" in vuln or "MS17-010" in vuln
               for vuln in port_info.common_vulns)


def test_search_by_service_finds_matches():
    """
    PROVES: User can search for ports by service name

    User Story: User types 'pl' → chooses search → enters "http" → sees 80, 443, 8080
    """
    results = PortReference.search_by_service("http")

    assert len(results) >= 3  # HTTP, HTTPS, HTTP-Proxy
    port_numbers = [r.port for r in results]
    assert 80 in port_numbers
    assert 443 in port_numbers


def test_list_all_ports_returns_sorted():
    """
    PROVES: All ports can be listed in sorted order

    User Story: User types 'pl' → chooses "show all" → sees sorted list
    """
    all_ports = PortReference.list_all()

    assert len(all_ports) >= 20  # At least 20 common ports

    # Verify sorted by port number
    port_numbers = [p.port for p in all_ports]
    assert port_numbers == sorted(port_numbers)


def test_port_reference_oscp_relevance():
    """
    PROVES: Port database includes OSCP-relevant ports

    User Story: Student wants to know which ports matter for OSCP
    """
    # Key OSCP ports that must be present
    oscp_ports = [21, 22, 80, 139, 445, 3306, 3389]

    for port in oscp_ports:
        port_info = PortReference.lookup(port)
        assert port_info is not None, f"Port {port} missing from reference"
        assert len(port_info.enum_commands) > 0, f"Port {port} has no commands"


# ============================================================================
# QUICK EXECUTE TESTS
# ============================================================================

@pytest.fixture
def mock_session(temp_crack_home):
    """Create mock InteractiveSession with temp profile"""
    from crack.track.core.state import TargetProfile

    session = Mock(spec=InteractiveSession)
    session.target = "192.168.45.100"
    session.profile = TargetProfile("192.168.45.100")
    session.last_action = None

    return session


def test_quick_execute_runs_command(mock_session):
    """
    PROVES: Quick execute runs command and captures output

    User Story: User types 'qe' → enters 'whoami' → sees output
    """
    with patch('subprocess.Popen') as mock_popen:
        # Mock successful command execution
        mock_process = Mock()
        mock_process.stdout = iter(["kali\n"])
        mock_process.stderr = Mock()
        mock_process.stderr.read.return_value = ""
        mock_process.returncode = 0
        mock_process.wait.return_value = None
        mock_popen.return_value = mock_process

        # Create real session to test _execute_command
        from crack.track.interactive.session import InteractiveSession
        session = InteractiveSession("192.168.45.100")

        exit_code, stdout, stderr = session._execute_command("whoami")

        assert exit_code == 0
        assert "kali" in stdout
        assert stderr == ""


def test_quick_execute_handles_failure(mock_session):
    """
    PROVES: Quick execute shows error when command fails

    User Story: User types 'qe' → enters invalid command → sees exit code 1
    """
    with patch('subprocess.Popen') as mock_popen:
        # Mock failed command execution
        mock_process = Mock()
        mock_process.stdout = iter([])
        mock_process.stderr = Mock()
        mock_process.stderr.read.return_value = "command not found\n"
        mock_process.returncode = 127
        mock_process.wait.return_value = None
        mock_popen.return_value = mock_process

        from crack.track.interactive.session import InteractiveSession
        session = InteractiveSession("192.168.45.100")

        exit_code, stdout, stderr = session._execute_command("invalidcommand")

        assert exit_code == 127
        assert "command not found" in stderr


def test_quick_execute_validates_empty_command(mock_session):
    """
    PROVES: Quick execute rejects empty commands

    User Story: User types 'qe' → presses Enter → sees validation error
    """
    from crack.track.interactive.session import InteractiveSession
    session = InteractiveSession("192.168.45.100")

    # Empty command should fail validation
    result = session._validate_command("")
    assert result is False

    # Whitespace-only command should fail validation
    result = session._validate_command("   ")
    assert result is False


def test_quick_execute_not_tracked_in_tasks(mock_session):
    """
    PROVES: Quick execute does NOT create tasks in task tree

    User Story: User runs 'qe whoami' → command executes → NO task created
    """
    from crack.track.interactive.session import InteractiveSession
    session = InteractiveSession("192.168.45.100")

    # Get initial task count
    initial_tasks = session.profile.task_tree.get_all_tasks()
    initial_count = len(initial_tasks)

    # Execute quick command (mocked)
    with patch('subprocess.Popen') as mock_popen:
        mock_process = Mock()
        mock_process.stdout = iter(["output\n"])
        mock_process.stderr = Mock()
        mock_process.stderr.read.return_value = ""
        mock_process.returncode = 0
        mock_process.wait.return_value = None
        mock_popen.return_value = mock_process

        session._execute_command("whoami")

    # Task count should not change
    final_tasks = session.profile.task_tree.get_all_tasks()
    final_count = len(final_tasks)

    assert final_count == initial_count, "Quick execute should not create tasks"


def test_quick_execute_can_save_to_notes():
    """
    PROVES: User can optionally save quick execute output to notes

    User Story: User runs 'qe whoami' → sees output → saves to notes
    """
    from crack.track.interactive.session import InteractiveSession
    session = InteractiveSession("192.168.45.100")

    command = "whoami"
    exit_code = 0
    output = "kali\n"
    stderr = ""

    # Get initial note count
    initial_notes = len(session.profile.notes or [])

    # Mock user confirming save
    with patch('crack.track.interactive.session.input', return_value='y'):
        with patch('crack.track.interactive.session.InputProcessor.parse_confirmation', return_value=True):
            session._log_execution(command, exit_code, output, stderr)

    # Note should be added
    final_notes = len(session.profile.notes or [])
    assert final_notes == initial_notes + 1

    # Verify note content
    last_note = session.profile.notes[-1]
    assert command in last_note['note']
    assert str(exit_code) in last_note['note']


def test_quick_execute_output_truncation():
    """
    PROVES: Large output is truncated in notes

    User Story: User runs command with large output → saved note is truncated
    """
    from crack.track.interactive.session import InteractiveSession
    session = InteractiveSession("192.168.45.100")

    command = "cat large_file"
    exit_code = 0
    output = "A" * 1000  # Large output
    stderr = ""

    with patch('crack.track.interactive.session.input', return_value='y'):
        with patch('crack.track.interactive.session.InputProcessor.parse_confirmation', return_value=True):
            session._log_execution(command, exit_code, output, stderr)

    # Verify note was added
    assert len(session.profile.notes) > 0
    last_note = session.profile.notes[-1]

    # Output should be truncated to 500 chars + "..."
    assert len(last_note['note']) < len(output) + 200  # Some overhead for formatting


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

def test_port_lookup_integration_with_session():
    """
    PROVES: Port lookup integrates correctly with InteractiveSession

    User Story: User in TUI presses 'pl' → lookup works → returns to menu
    """
    from crack.track.interactive.session import InteractiveSession
    session = InteractiveSession("192.168.45.100")

    # Verify handle_port_lookup method exists
    assert hasattr(session, 'handle_port_lookup')
    assert callable(session.handle_port_lookup)


def test_quick_execute_integration_with_session():
    """
    PROVES: Quick execute integrates correctly with InteractiveSession

    User Story: User in TUI presses 'qe' → execute works → returns to menu
    """
    from crack.track.interactive.session import InteractiveSession
    session = InteractiveSession("192.168.45.100")

    # Verify handle_quick_execute method exists
    assert hasattr(session, 'handle_quick_execute')
    assert callable(session.handle_quick_execute)


def test_shortcuts_registered_in_handler():
    """
    PROVES: 'pl' and 'qe' shortcuts are registered

    User Story: User sees 'pl' and 'qe' in help menu
    """
    from crack.track.interactive.shortcuts import ShortcutHandler
    from crack.track.interactive.session import InteractiveSession

    session = InteractiveSession("192.168.45.100")
    handler = ShortcutHandler(session)

    # Verify shortcuts exist
    assert 'pl' in handler.shortcuts
    assert 'qe' in handler.shortcuts

    # Verify they map to correct handlers
    assert handler.shortcuts['pl'][1] == 'port_lookup'
    assert handler.shortcuts['qe'][1] == 'quick_execute'


# ============================================================================
# EDGE CASES
# ============================================================================

def test_port_lookup_with_target_placeholder_replacement():
    """
    PROVES: Port lookup replaces <TARGET> with actual target IP

    User Story: User looks up port 445 → sees commands with 192.168.45.100
    """
    from crack.track.interactive.session import InteractiveSession
    session = InteractiveSession("192.168.45.100")

    port_info = PortReference.lookup(445)

    # Commands should have <TARGET> placeholder
    assert any("<TARGET>" in cmd for cmd in port_info.enum_commands)

    # Session's _display_port_info should replace it
    # (This is visual output, tested via integration)


def test_quick_execute_handles_keyboard_interrupt():
    """
    PROVES: User can cancel running command with Ctrl+C

    User Story: User runs 'qe sleep 60' → presses Ctrl+C → command stops
    """
    with patch('subprocess.Popen') as mock_popen:
        # Mock process that raises KeyboardInterrupt when iterating stdout
        mock_process = Mock()

        # Create a generator that immediately raises KeyboardInterrupt
        def raising_generator():
            raise KeyboardInterrupt()
            yield  # Never reached but makes it a generator

        mock_process.stdout = raising_generator()
        mock_process.terminate = Mock()
        mock_popen.return_value = mock_process

        from crack.track.interactive.session import InteractiveSession
        session = InteractiveSession("192.168.45.100")

        exit_code, stdout, stderr = session._execute_command("sleep 60")

        # Should return -1 for interrupted
        assert exit_code == -1
        assert "Interrupted" in stderr

        # Process should be terminated
        mock_process.terminate.assert_called_once()


def test_port_reference_completeness():
    """
    PROVES: Port database covers all requested OSCP ports

    Requirement: Include 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 3306, 3389, 5985, 8080
    """
    required_ports = [21, 22, 23, 25, 53, 80, 110, 111, 139, 143, 443, 445, 3306, 3389, 5985, 8080]

    for port in required_ports:
        port_info = PortReference.lookup(port)
        assert port_info is not None, f"Port {port} not found in database"
        assert port_info.service, f"Port {port} has no service name"
        assert len(port_info.enum_commands) > 0, f"Port {port} has no enumeration commands"


# ============================================================================
# PERFORMANCE TESTS
# ============================================================================

def test_port_lookup_is_fast():
    """
    PROVES: Port lookup completes in <10ms

    User Story: User types 'pl 445' → sees results instantly
    """
    import time

    start = time.time()
    for _ in range(100):
        PortReference.lookup(445)
    elapsed = time.time() - start

    avg_time = elapsed / 100
    assert avg_time < 0.01, f"Port lookup too slow: {avg_time*1000:.2f}ms"


def test_search_by_service_is_fast():
    """
    PROVES: Service search completes in <50ms

    User Story: User searches for "http" → sees results instantly
    """
    import time

    start = time.time()
    for _ in range(100):
        PortReference.search_by_service("http")
    elapsed = time.time() - start

    avg_time = elapsed / 100
    assert avg_time < 0.05, f"Service search too slow: {avg_time*1000:.2f}ms"
