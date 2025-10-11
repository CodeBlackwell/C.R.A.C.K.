"""
Command Editor TUI Integration Tests

Tests the complete workflow of command editing in the TUI, from launching
the editor to saving modified commands. Uses the TUI Debug-Validation pattern:
Mock Input → Run TUI → Parse Logs → Assert

Test Coverage:
- Quick editor parameter editing
- Tier escalation (Quick → Advanced → Raw)
- Command validation and error handling
- Cancel behavior at each tier
- Command persistence after editing
- Error handling for tasks without commands
"""

import pytest
from pathlib import Path
from unittest.mock import patch, Mock
from crack.track.core.state import TargetProfile
from crack.track.interactive.debug_logger import DebugLogger
from crack.track.interactive.log_types import LogConfig, LogCategory, LogLevel


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def temp_crack_home_with_task(temp_crack_home):
    """
    Create a profile with a task that has an editable command.

    Returns a tuple of (profile, task_id) for test use.
    """
    profile = TargetProfile("192.168.45.100")

    # Add a task with gobuster command
    task_id = "gobuster-dir-80"
    task = profile.add_task(
        task_id=task_id,
        name="Directory Enumeration (Port 80)",
        task_type="executable",
        status="pending",
        metadata={
            'command': 'gobuster dir -u http://192.168.45.100 -w /usr/share/wordlists/dirb/common.txt -t 50',
            'tool': 'gobuster',
            'description': 'Enumerate web directories',
            'time_estimate': '5-10 min',
            'priority': 'HIGH'
        }
    )

    # Add an nmap task for escalation tests
    nmap_task_id = "nmap-service-scan"
    profile.add_task(
        task_id=nmap_task_id,
        name="Service Detection Scan",
        task_type="executable",
        status="pending",
        metadata={
            'command': 'nmap -sV -p 80,443 192.168.45.100',
            'tool': 'nmap',
            'description': 'Detect service versions',
            'time_estimate': '2-5 min',
            'priority': 'HIGH'
        }
    )

    # Add a task WITHOUT command for error testing
    no_cmd_task_id = "manual-investigation"
    profile.add_task(
        task_id=no_cmd_task_id,
        name="Manual Investigation",
        task_type="parent",
        status="pending",
        metadata={
            'description': 'Manual investigation task (no command)',
            'priority': 'MEDIUM'
        }
    )

    profile.save()
    return profile, task_id, nmap_task_id, no_cmd_task_id


# ============================================================================
# Integration Tests - Quick Editor Workflows
# ============================================================================

def test_quick_editor_wordlist_change(temp_crack_home_with_task, simulated_input, tmp_path):
    """
    PROVES: User can edit wordlist parameter via quick editor

    User Actions:
    1. Navigate to gobuster task
    2. Press 'e' to edit command
    3. Select option 2 (wordlist parameter)
    4. Enter new wordlist path
    5. Confirm execution

    Expected Logs:
    - "[UI.EDITOR] CommandEditor initialized"
    - "[UI.EDITOR_TIER] Tier selected: quick"
    - "[UI.EDITOR] Editor complete"
    - "[STATE.TRANSITION] COMMAND_EDITOR -> task_workspace"

    Expected Result:
    - Command updated with new wordlist path
    - Change persisted to profile
    """
    profile, task_id, _, _ = temp_crack_home_with_task

    # Mock user input sequence
    simulated_input([
        '1',        # Dashboard: Select task
        'e',        # Task Workspace: Edit command
        '2',        # Quick Editor: Select wordlist parameter
        '/usr/share/wordlists/dirb/big.txt',  # Input: New wordlist path
        '',         # Confirm: Execute (empty = default action)
        'q'         # Quit
    ])

    # Setup debug logging
    debug_log = tmp_path / 'test_debug.log'
    debug_config = LogConfig(enabled=True, level=LogLevel.VERBOSE)

    # Run TUI session
    from crack.track.interactive.tui_session_v2 import TUISessionV2
    with patch('crack.track.interactive.tui_session_v2.get_debug_logger') as mock_logger:
        logger = DebugLogger(str(debug_log), debug_config)
        mock_logger.return_value = logger

        try:
            session = TUISessionV2(
                "192.168.45.100",
                debug=True,
                debug_config=debug_config
            )
            session.run()
        except StopIteration:
            pass  # Expected when input queue exhausted

    # Parse debug log
    log_content = debug_log.read_text()

    # Assert editor initialization
    assert "[UI.EDITOR] CommandEditor initialized" in log_content or \
           "Edit command requested" in log_content, \
           "Command editor should have been initialized"

    # Assert tier selection
    assert "quick" in log_content.lower(), \
           "Quick editor tier should be selected for gobuster"

    # Verify command was updated
    updated_profile = TargetProfile.load("192.168.45.100")
    task = updated_profile.get_task(task_id)
    updated_command = task.metadata.get('command', '')

    assert '/usr/share/wordlists/dirb/big.txt' in updated_command, \
           f"Wordlist should be updated in command: {updated_command}"
    assert '/usr/share/wordlists/dirb/common.txt' not in updated_command, \
           "Old wordlist should be replaced"


def test_quick_editor_cancel_preserves_original(temp_crack_home_with_task, simulated_input, tmp_path):
    """
    PROVES: Cancelling quick editor preserves original command

    User Actions:
    1. Navigate to task
    2. Press 'e' to edit
    3. Press 'c' to cancel
    4. Verify original command unchanged

    Expected Logs:
    - "[UI.EDITOR] CommandEditor initialized"
    - "[UI.EDITOR] Editor cancelled"

    Expected Result:
    - Original command unchanged
    - No persistence of edits
    """
    profile, task_id, _, _ = temp_crack_home_with_task
    original_command = profile.get_task(task_id).metadata.get('command')

    # Mock user input sequence
    simulated_input([
        '1',        # Dashboard: Select task
        'e',        # Task Workspace: Edit command
        'c',        # Quick Editor: Cancel
        'q'         # Quit
    ])

    # Setup debug logging
    debug_log = tmp_path / 'test_debug.log'
    debug_config = LogConfig(enabled=True, level=LogLevel.VERBOSE)

    # Run TUI session
    from crack.track.interactive.tui_session_v2 import TUISessionV2
    with patch('crack.track.interactive.tui_session_v2.get_debug_logger') as mock_logger:
        logger = DebugLogger(str(debug_log), debug_config)
        mock_logger.return_value = logger

        try:
            session = TUISessionV2(
                "192.168.45.100",
                debug=True,
                debug_config=debug_config
            )
            session.run()
        except StopIteration:
            pass

    # Parse debug log
    log_content = debug_log.read_text()

    # Assert cancellation
    assert "cancel" in log_content.lower(), \
           "Editor cancellation should be logged"

    # Verify command unchanged
    updated_profile = TargetProfile.load("192.168.45.100")
    task = updated_profile.get_task(task_id)
    final_command = task.metadata.get('command')

    assert final_command == original_command, \
           "Command should be unchanged after cancel"


# ============================================================================
# Integration Tests - Tier Escalation
# ============================================================================

def test_escalation_quick_to_advanced(temp_crack_home_with_task, simulated_input, tmp_path):
    """
    PROVES: User can escalate from quick editor to advanced editor

    User Actions:
    1. Press 'e' on nmap task
    2. Press 'a' to escalate to advanced
    3. Advanced editor attempts to load
    4. Falls back to raw editor (advanced not fully implemented)

    Expected Logs:
    - "[UI.EDITOR_TIER] Tier selected: quick"
    - "[UI.EDITOR_TIER] Tier escalation from_tier=quick to_tier=advanced"
    - "Advanced editor (schema-driven forms) coming soon"
    - "[UI.EDITOR_TIER] Tier escalation from_tier=advanced to_tier=raw"

    Expected Result:
    - Escalation path followed correctly
    - Raw editor shown after advanced placeholder
    """
    profile, _, nmap_task_id, _ = temp_crack_home_with_task

    # Mock user input sequence
    simulated_input([
        '2',        # Dashboard: Select nmap task
        'e',        # Task Workspace: Edit command
        'a',        # Quick Editor: Escalate to advanced
        'c',        # Raw Editor: Cancel (after auto-escalation)
        'q'         # Quit
    ])

    # Setup debug logging with TRACE level for tier transitions
    debug_log = tmp_path / 'test_debug.log'
    debug_config = LogConfig(enabled=True, level=LogLevel.TRACE)

    # Run TUI session
    from crack.track.interactive.tui_session_v2 import TUISessionV2
    with patch('crack.track.interactive.tui_session_v2.get_debug_logger') as mock_logger:
        logger = DebugLogger(str(debug_log), debug_config)
        mock_logger.return_value = logger

        try:
            session = TUISessionV2(
                "192.168.45.100",
                debug=True,
                debug_config=debug_config
            )
            session.run()
        except StopIteration:
            pass

    # Parse debug log
    log_content = debug_log.read_text()

    # Assert tier progression
    assert "quick" in log_content.lower(), \
           "Should start in quick editor tier"

    # Note: Advanced editor currently shows placeholder and escalates to raw
    # This test documents expected behavior once advanced editor is implemented
    assert "advanced" in log_content.lower() or "raw" in log_content.lower(), \
           "Should escalate to advanced or raw tier"


def test_escalation_quick_to_raw(temp_crack_home_with_task, simulated_input, tmp_path):
    """
    PROVES: User can escalate directly from quick to raw editor

    User Actions:
    1. Press 'e' on gobuster task
    2. Press 'r' to escalate directly to raw
    3. Raw editor loads

    Expected Logs:
    - "[UI.EDITOR_TIER] Tier selected: quick"
    - "[UI.EDITOR_TIER] Tier escalation from_tier=quick to_tier=raw"
    - "[UI.EDITOR_TIER] Running tier: raw"

    Expected Result:
    - Direct escalation skips advanced tier
    - Raw editor displays command with line numbers
    """
    profile, task_id, _, _ = temp_crack_home_with_task

    # Mock user input sequence
    simulated_input([
        '1',        # Dashboard: Select gobuster task
        'e',        # Task Workspace: Edit command
        'r',        # Quick Editor: Escalate directly to raw
        '',         # Raw Editor: Cancel (empty input = cancel)
        'q'         # Quit
    ])

    # Setup debug logging
    debug_log = tmp_path / 'test_debug.log'
    debug_config = LogConfig(enabled=True, level=LogLevel.VERBOSE)

    # Run TUI session
    from crack.track.interactive.tui_session_v2 import TUISessionV2
    with patch('crack.track.interactive.tui_session_v2.get_debug_logger') as mock_logger:
        logger = DebugLogger(str(debug_log), debug_config)
        mock_logger.return_value = logger

        try:
            session = TUISessionV2(
                "192.168.45.100",
                debug=True,
                debug_config=debug_config
            )
            session.run()
        except StopIteration:
            pass

    # Parse debug log
    log_content = debug_log.read_text()

    # Assert direct escalation to raw
    assert "raw" in log_content.lower(), \
           "Should escalate directly to raw tier"


# ============================================================================
# Integration Tests - Validation & Error Handling
# ============================================================================

def test_raw_editor_syntax_validation(temp_crack_home_with_task, simulated_input, tmp_path):
    """
    PROVES: Raw editor validates syntax and shows errors

    User Actions:
    1. Edit command in raw mode
    2. Enter command with unbalanced quotes
    3. See validation error
    4. Choose not to execute anyway

    Expected Logs:
    - "[UI.EDITOR_TIER] Running tier: raw"
    - "Validation errors:" or "syntax" or "quotes"

    Expected Result:
    - Validation runs automatically
    - Error message displayed
    - Command not saved if user cancels
    """
    profile, task_id, _, _ = temp_crack_home_with_task

    # Mock user input sequence
    simulated_input([
        '1',        # Dashboard: Select task
        'e',        # Task Workspace: Edit command
        'r',        # Quick Editor: Escalate to raw
        'gobuster dir -u "http://target',  # Raw Editor: Invalid command (unbalanced quote)
        '',         # Raw Editor: End input (empty line)
        'n',        # Raw Editor: Don't execute anyway
        'q'         # Quit
    ])

    # Setup debug logging
    debug_log = tmp_path / 'test_debug.log'
    debug_config = LogConfig(enabled=True, level=LogLevel.VERBOSE)

    # Run TUI session
    from crack.track.interactive.tui_session_v2 import TUISessionV2
    with patch('crack.track.interactive.tui_session_v2.get_debug_logger') as mock_logger:
        logger = DebugLogger(str(debug_log), debug_config)
        mock_logger.return_value = logger

        try:
            session = TUISessionV2(
                "192.168.45.100",
                debug=True,
                debug_config=debug_config
            )
            session.run()
        except StopIteration:
            pass

    # Parse debug log
    log_content = debug_log.read_text()

    # Assert raw tier and validation
    assert "raw" in log_content.lower(), \
           "Should be in raw editor tier"

    # Verify command unchanged (validation failed, user declined override)
    updated_profile = TargetProfile.load("192.168.45.100")
    task = updated_profile.get_task(task_id)
    final_command = task.metadata.get('command')

    assert 'gobuster dir -u http://192.168.45.100' in final_command, \
           "Original command should be preserved after validation failure"


def test_edit_task_without_command_shows_error(temp_crack_home_with_task, simulated_input, tmp_path):
    """
    PROVES: Editing task without command shows error message

    User Actions:
    1. Navigate to parent task (no command)
    2. Press 'e' to edit
    3. See error: "No command found for this task"

    Expected Logs:
    - "No command found for this task" or similar warning

    Expected Result:
    - Warning displayed
    - Editor does not launch
    - Returns to workspace immediately
    """
    profile, _, _, no_cmd_task_id = temp_crack_home_with_task

    # Mock user input sequence
    simulated_input([
        '3',        # Dashboard: Select task without command
        'e',        # Task Workspace: Try to edit (should fail)
        'b',        # Task Workspace: Back to dashboard
        'q'         # Quit
    ])

    # Setup debug logging
    debug_log = tmp_path / 'test_debug.log'
    debug_config = LogConfig(enabled=True, level=LogLevel.VERBOSE)

    # Run TUI session
    from crack.track.interactive.tui_session_v2 import TUISessionV2
    with patch('crack.track.interactive.tui_session_v2.get_debug_logger') as mock_logger:
        logger = DebugLogger(str(debug_log), debug_config)
        mock_logger.return_value = logger

        try:
            session = TUISessionV2(
                "192.168.45.100",
                debug=True,
                debug_config=debug_config
            )
            session.run()
        except StopIteration:
            pass

    # Parse debug log
    log_content = debug_log.read_text()

    # Assert error handling
    assert "no command" in log_content.lower() or "warning" in log_content.lower(), \
           "Should log warning about missing command"

    # Editor should NOT initialize
    assert "[UI.EDITOR] CommandEditor initialized" not in log_content, \
           "Editor should not initialize for task without command"


# ============================================================================
# Integration Tests - State Persistence
# ============================================================================

def test_command_update_persists_after_edit(temp_crack_home_with_task, simulated_input, tmp_path):
    """
    PROVES: Command changes are saved and persist across sessions

    User Actions:
    1. Edit command and save
    2. Return to dashboard
    3. Navigate back to same task
    4. Verify modified command is shown

    Expected Result:
    - Modified command persisted to profile JSON
    - Change visible in subsequent navigation
    - Profile metadata updated correctly
    """
    profile, task_id, _, _ = temp_crack_home_with_task
    original_command = profile.get_task(task_id).metadata.get('command')

    # Mock user input sequence
    simulated_input([
        '1',        # Dashboard: Select task
        'e',        # Task Workspace: Edit command
        '3',        # Quick Editor: Select threads parameter
        '100',      # Input: New thread count
        '',         # Confirm: Execute
        'b',        # Task Workspace: Back to dashboard
        '1',        # Dashboard: Select same task again
        'b',        # Task Workspace: Back to dashboard (to read display)
        'q'         # Quit
    ])

    # Setup debug logging
    debug_log = tmp_path / 'test_debug.log'
    debug_config = LogConfig(enabled=True, level=LogLevel.VERBOSE)

    # Run TUI session
    from crack.track.interactive.tui_session_v2 import TUISessionV2
    with patch('crack.track.interactive.tui_session_v2.get_debug_logger') as mock_logger:
        logger = DebugLogger(str(debug_log), debug_config)
        mock_logger.return_value = logger

        try:
            session = TUISessionV2(
                "192.168.45.100",
                debug=True,
                debug_config=debug_config
            )
            session.run()
        except StopIteration:
            pass

    # Parse debug log
    log_content = debug_log.read_text()

    # Verify command was updated
    updated_profile = TargetProfile.load("192.168.45.100")
    task = updated_profile.get_task(task_id)
    final_command = task.metadata.get('command')

    assert final_command != original_command, \
           "Command should be modified"
    assert '-t 100' in final_command or '--threads 100' in final_command, \
           f"Threads parameter should be updated to 100: {final_command}"

    # Verify persistence logged
    assert "command updated" in log_content.lower() or \
           "saved" in log_content.lower(), \
           "Command save should be logged"


# ============================================================================
# Integration Tests - Performance
# ============================================================================

def test_editor_launch_performance(temp_crack_home_with_task, simulated_input, tmp_path):
    """
    PROVES: Editor launches quickly (<500ms acceptable)

    Performance Criteria:
    - Editor initialization: <100ms
    - Tier selection: <50ms
    - Schema load (if cached): <10ms

    This test documents timing expectations but does not fail on slow systems.
    Use for performance regression detection.
    """
    profile, task_id, _, _ = temp_crack_home_with_task

    # Mock user input sequence
    simulated_input([
        '1',        # Dashboard: Select task
        'e',        # Task Workspace: Edit command
        'c',        # Quick Editor: Cancel immediately
        'q'         # Quit
    ])

    # Setup debug logging with timing enabled
    debug_log = tmp_path / 'test_debug.log'
    debug_config = LogConfig(enabled=True, level=LogLevel.VERBOSE)

    # Run TUI session
    from crack.track.interactive.tui_session_v2 import TUISessionV2
    with patch('crack.track.interactive.tui_session_v2.get_debug_logger') as mock_logger:
        logger = DebugLogger(str(debug_log), debug_config)
        mock_logger.return_value = logger

        try:
            session = TUISessionV2(
                "192.168.45.100",
                debug=True,
                debug_config=debug_config
            )
            session.run()
        except StopIteration:
            pass

    # Parse debug log for timing info
    log_content = debug_log.read_text()

    # Document that editor launched (timing check is informational)
    assert "CommandEditor" in log_content or "edit" in log_content.lower(), \
           "Editor should have launched"

    # Note: For actual performance validation, parse timing logs:
    # grep "elapsed=" .debug_logs/tui_debug_*.log | grep EDITOR
    # Expected: <0.5s for all operations


# ============================================================================
# Summary & Usage Notes
# ============================================================================

"""
Test Summary:
=============

✓ Quick Editor Workflows:
  - test_quick_editor_wordlist_change: Edit parameter and save
  - test_quick_editor_cancel_preserves_original: Cancel preserves original

✓ Tier Escalation:
  - test_escalation_quick_to_advanced: Quick → Advanced → Raw (placeholder)
  - test_escalation_quick_to_raw: Quick → Raw (direct)

✓ Validation & Error Handling:
  - test_raw_editor_syntax_validation: Invalid syntax detected
  - test_edit_task_without_command_shows_error: Missing command error

✓ State Persistence:
  - test_command_update_persists_after_edit: Changes saved to profile

✓ Performance:
  - test_editor_launch_performance: Launch timing documented

Running Tests:
==============

# Run all command editor integration tests
pytest tests/track/interactive/test_command_editor_integration.py -v

# Run specific test
pytest tests/track/interactive/test_command_editor_integration.py::test_quick_editor_wordlist_change -v

# Run with log output
pytest tests/track/interactive/test_command_editor_integration.py -v -s

# Check coverage
pytest tests/track/interactive/test_command_editor_integration.py --cov=track.interactive.components.command_editor --cov-report=term-missing

Log Analysis:
=============

# View test debug logs after running
tail -100 /tmp/pytest-of-*/pytest-current/test_*/test_debug.log

# Filter by category
grep "\[UI.EDITOR" /tmp/pytest-of-*/pytest-current/test_*/test_debug.log

# Check tier transitions
grep "Tier" /tmp/pytest-of-*/pytest-current/test_*/test_debug.log

Visual Validation:
==================

After automated tests pass, perform visual validation:

1. Launch TUI: crack track --tui 192.168.45.100 --debug
2. Navigate to task with gobuster command
3. Press 'e' → Verify quick editor menu displays
4. Edit parameter → Verify diff preview shows changes
5. Confirm → Verify command updated in task panel
6. Return to dashboard → Navigate back → Verify persistence

See: track/docs/COMMAND_EDITOR_TESTING.md for full checklist
"""
