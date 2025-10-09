"""
Tests for privilege escalation alternative commands

VALUE: Validates that privilege escalation alternatives are executable
       and useful during OSCP exam scenarios

User scenario: Student needs manual enumeration alternatives when
               LinPEAS/automated tools fail or are detected
"""

import pytest
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from alternatives.commands.privilege_escalation import ALTERNATIVES


def generate_privesc_tests():
    """Generate parameterized tests from all privilege escalation alternatives"""
    for cmd in ALTERNATIVES:
        yield pytest.param(cmd, id=cmd.id)


@pytest.mark.parametrize('alt_cmd', generate_privesc_tests())
def test_privesc_alternative_exam_ready(alt_cmd):
    """
    VALUE: Validates command is executable and useful during OSCP exam

    User scenario: Student has shell access but automated tools blocked/failing
                   Need manual commands to enumerate privilege escalation vectors
    """
    # Verify essential metadata present
    assert alt_cmd.id, "Command must have unique ID"
    assert alt_cmd.name, "Command must have human-readable name"
    assert alt_cmd.command_template, "Command must have executable template"
    assert alt_cmd.description, "Command must have description"

    # Verify OSCP relevance
    assert alt_cmd.category == 'privilege-escalation', \
        "All commands in this file must be privilege-escalation category"

    assert any('OSCP:' in tag for tag in alt_cmd.tags), \
        "Command must have OSCP relevance tag"

    assert 'MANUAL' in alt_cmd.tags or 'NO_TOOLS' in alt_cmd.tags, \
        "Command must be tagged as manual or no-tools-needed"

    # Verify actionable output
    assert alt_cmd.success_indicators, \
        "Must define what success looks like for student"

    assert alt_cmd.next_steps, \
        "Must guide student on what to do with results"

    # Verify no variables (these are simple enumeration commands)
    assert len(alt_cmd.variables) == 0, \
        "Privilege escalation enum should not require variables"


@pytest.mark.parametrize('cmd_id,expected_pattern', [
    ('alt-find-suid', 'find.*-perm.*-u=s'),
    ('alt-sudo-list', 'sudo -l'),
    ('alt-linux-capabilities', 'getcap'),
    ('alt-kernel-version-check', 'uname.*cat /proc/version'),
    ('alt-cron-enumeration', 'crontab'),
    ('alt-nfs-no-root-squash', '/etc/exports'),
])
def test_command_patterns_valid(cmd_id, expected_pattern):
    """
    VALUE: Ensures commands use correct syntax for OSCP exam execution

    User scenario: Student copies command from CRACK Track and executes on target
                   Command must work first time without debugging
    """
    import re

    cmd = next((c for c in ALTERNATIVES if c.id == cmd_id), None)
    assert cmd is not None, f"Command {cmd_id} not found"

    assert re.search(expected_pattern, cmd.command_template), \
        f"Command {cmd_id} doesn't match expected pattern {expected_pattern}"


def test_no_duplicate_commands():
    """
    VALUE: Prevents duplicate alternatives that confuse students

    User scenario: Student browses alternatives and sees same command twice
    """
    command_templates = [cmd.command_template for cmd in ALTERNATIVES]
    unique_templates = set(command_templates)

    assert len(command_templates) == len(unique_templates), \
        f"Duplicate command templates found: {len(command_templates)} total, {len(unique_templates)} unique"


def test_all_commands_have_flag_explanations():
    """
    VALUE: Educational - every flag explained for learning

    User scenario: Student wants to understand WHY each flag is used
                   (OSCP exam preparation requires understanding, not just copy-paste)
    """
    for cmd in ALTERNATIVES:
        # Simple commands may not need flag explanations
        if ' -' in cmd.command_template or ' --' in cmd.command_template:
            assert cmd.flag_explanations, \
                f"Command {cmd.id} has flags but no explanations"


@pytest.mark.parametrize('alt_cmd', generate_privesc_tests())
def test_quick_win_commands_tagged(alt_cmd):
    """
    VALUE: Quick wins clearly marked for exam time optimization

    User scenario: Student has limited exam time - needs to prioritize
                   high-value quick checks (sudo -l, SUID, etc.)
    """
    quick_win_commands = ['sudo', 'uname', '/etc/exports', 'crontab']

    is_quick_win_command = any(qw in alt_cmd.command_template for qw in quick_win_commands)
    has_quick_win_tag = 'QUICK_WIN' in alt_cmd.tags

    if is_quick_win_command:
        assert has_quick_win_tag, \
            f"Command {alt_cmd.id} is a quick win but not tagged as such"


def test_os_type_consistency():
    """
    VALUE: Ensures OS type correctly specified for filtering

    User scenario: Student filters commands by OS (Linux vs Windows)
    """
    for cmd in ALTERNATIVES:
        assert cmd.os_type in ['linux', 'windows', 'both'], \
            f"Command {cmd.id} has invalid os_type: {cmd.os_type}"

        # Linux commands should have LINUX tag
        if cmd.os_type == 'linux':
            assert 'LINUX' in cmd.tags, \
                f"Linux command {cmd.id} missing LINUX tag"


@pytest.mark.parametrize('cmd_id,min_success_indicators', [
    ('alt-find-suid', 2),
    ('alt-sudo-list', 2),
    ('alt-linux-capabilities', 2),
    ('alt-kernel-version-check', 2),
    ('alt-cron-enumeration', 2),
    ('alt-nfs-no-root-squash', 2),
])
def test_sufficient_success_indicators(cmd_id, min_success_indicators):
    """
    VALUE: Students know what to look for in command output

    User scenario: Student runs command and needs to recognize successful results
    """
    cmd = next((c for c in ALTERNATIVES if c.id == cmd_id), None)
    assert cmd is not None

    assert len(cmd.success_indicators) >= min_success_indicators, \
        f"Command {cmd_id} has insufficient success indicators " \
        f"({len(cmd.success_indicators)} < {min_success_indicators})"


@pytest.mark.parametrize('cmd_id,expected_notes_keywords', [
    ('alt-find-suid', ['GTFOBins']),
    ('alt-sudo-list', ['instant', 'NOPASSWD']),
    ('alt-linux-capabilities', ['permission', 'SUID']),
    ('alt-kernel-version-check', ['exploit', 'kernel']),
    ('alt-cron-enumeration', ['root', 'writable']),
    ('alt-nfs-no-root-squash', ['OSCP', 'SUID']),
])
def test_notes_provide_context(cmd_id, expected_notes_keywords):
    """
    VALUE: Notes provide critical OSCP exam context

    User scenario: Student needs to understand why this command matters
    """
    cmd = next((c for c in ALTERNATIVES if c.id == cmd_id), None)
    assert cmd is not None
    assert cmd.notes, f"Command {cmd_id} missing notes"

    notes_lower = cmd.notes.lower()
    for keyword in expected_notes_keywords:
        assert keyword.lower() in notes_lower, \
            f"Command {cmd_id} notes missing critical keyword '{keyword}'"


def test_all_commands_have_next_steps():
    """
    VALUE: Guides student on attack chain progression

    User scenario: Student finds privesc vector, needs to know exploitation steps
    """
    for cmd in ALTERNATIVES:
        assert cmd.next_steps, \
            f"Command {cmd.id} must have next_steps"
        assert len(cmd.next_steps) >= 2, \
            f"Command {cmd.id} needs at least 2 next steps for guidance"


def test_parent_task_pattern_set():
    """
    VALUE: Ensures commands appear in correct task tree context

    User scenario: Student browning CRACK Track sees relevant alternatives
    """
    for cmd in ALTERNATIVES:
        assert cmd.parent_task_pattern, \
            f"Command {cmd.id} must have parent_task_pattern"

        # Privilege escalation commands should match privesc pattern
        assert 'privesc' in cmd.parent_task_pattern.lower(), \
            f"Command {cmd.id} parent_task_pattern should reference privilege escalation"
