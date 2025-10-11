"""
Test CommandValidator - Comprehensive validation tests

Tests cover:
- Syntax validation (5 tests)
- Path validation (5 tests)
- Flag compatibility (5 tests)
- Runtime estimation (3 tests)
- Security checks (2 tests)

Total: 20 tests
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, mock_open

from crack.track.interactive.components.command_editor.validator import (
    CommandValidator,
    ValidationResult,
    ValidationWarning,
    ParsedCommand,
)


# ============================================================================
# SYNTAX VALIDATION TESTS (5 tests)
# ============================================================================

def test_validate_syntax_balanced_quotes():
    """
    PROVES: Validator detects unbalanced quotes

    Command with unbalanced quotes should fail validation
    """
    # Unbalanced single quotes
    command = "echo 'hello world"
    result = CommandValidator.validate_syntax(command)

    assert not result.is_valid
    assert "Unbalanced single quotes" in result.errors

    # Unbalanced double quotes
    command = 'echo "hello world'
    result = CommandValidator.validate_syntax(command)

    assert not result.is_valid
    assert "Unbalanced double quotes" in result.errors

    # Balanced quotes (should pass)
    command = "echo 'hello' \"world\""
    result = CommandValidator.validate_syntax(command)

    assert result.is_valid
    assert len(result.errors) == 0


def test_validate_syntax_balanced_parentheses():
    """
    PROVES: Validator detects unbalanced parentheses

    Command with unbalanced parens should fail validation
    """
    # Unclosed parenthesis
    command = "bash -c '(echo hello"
    result = CommandValidator.validate_syntax(command)

    assert not result.is_valid
    assert any("Unbalanced parentheses" in err for err in result.errors)

    # Closing before opening
    command = "bash -c ')echo hello'"
    result = CommandValidator.validate_syntax(command)

    assert not result.is_valid
    assert "closing before opening" in result.errors[0].lower()

    # Balanced parentheses (should pass)
    command = "bash -c '(echo hello)'"
    result = CommandValidator.validate_syntax(command)

    assert result.is_valid


def test_validate_syntax_line_continuations():
    """
    PROVES: Validator warns about missing line continuations

    Multi-line commands without backslashes get warnings
    """
    # Missing continuation backslash
    command = "gobuster dir -u http://target\n-w /path/wordlist.txt"
    result = CommandValidator.validate_syntax(command)

    assert result.is_valid  # Not blocking, just warning
    assert len(result.warnings) > 0
    assert "continuation backslash" in result.warnings[0].lower()

    # Proper continuation (no warning)
    command = "gobuster dir -u http://target \\\n-w /path/wordlist.txt"
    result = CommandValidator.validate_syntax(command)

    assert result.is_valid
    # No warnings about missing backslash


def test_validate_syntax_empty_command():
    """
    PROVES: Validator rejects empty commands

    Empty or whitespace-only commands fail
    """
    # Empty string
    result = CommandValidator.validate_syntax("")
    assert not result.is_valid
    assert "Command is empty" in result.errors

    # Whitespace only
    result = CommandValidator.validate_syntax("   \n\t  ")
    assert not result.is_valid
    assert "Command is empty" in result.errors


def test_validate_syntax_trailing_backslash():
    """
    PROVES: Validator warns about invalid trailing backslash

    Backslash at end without continuation is warned
    """
    command = "echo hello\\"
    result = CommandValidator.validate_syntax(command)

    assert result.is_valid  # Warning, not error
    assert len(result.warnings) > 0
    assert "trailing backslash" in result.warnings[0].lower()


# ============================================================================
# PATH VALIDATION TESTS (5 tests)
# ============================================================================

def test_validate_paths_missing_wordlist():
    """
    PROVES: Validator detects missing wordlist files

    Commands with non-existent wordlists get warnings
    """
    command = "gobuster dir -u http://target -w /nonexistent/wordlist.txt"
    warnings = CommandValidator.validate_paths(command)

    assert len(warnings) > 0
    assert any("does not exist" in w.message.lower() for w in warnings)
    assert any("/nonexistent/wordlist.txt" in w.message for w in warnings)


def test_validate_paths_output_file_creation():
    """
    PROVES: Validator allows output file creation

    Output files that don't exist yet are marked as info, not error
    """
    command = "nmap -oA /tmp/scan_output 192.168.1.1"
    warnings = CommandValidator.validate_paths(command)

    # Should have info message about file creation, not error
    assert len(warnings) > 0
    info_warnings = [w for w in warnings if w.severity == "info"]
    assert len(info_warnings) > 0
    assert "will be created" in info_warnings[0].message.lower()


def test_validate_paths_output_directory_missing():
    """
    PROVES: Validator errors when output directory doesn't exist

    If parent directory for output doesn't exist, it's an error
    """
    command = "nmap -oA /nonexistent/dir/scan_output 192.168.1.1"
    warnings = CommandValidator.validate_paths(command)

    error_warnings = [w for w in warnings if w.severity == "error"]
    assert len(error_warnings) > 0
    assert "directory does not exist" in error_warnings[0].message.lower()


def test_validate_paths_existing_file(tmp_path):
    """
    PROVES: Validator accepts existing file paths

    Commands with valid file paths pass without warnings
    """
    # Create temporary wordlist
    wordlist = tmp_path / "wordlist.txt"
    wordlist.write_text("test\nwords\n")

    command = f"gobuster dir -u http://target -w {wordlist}"
    warnings = CommandValidator.validate_paths(command)

    # No warnings for existing file
    missing_warnings = [w for w in warnings if "does not exist" in w.message.lower()]
    assert len(missing_warnings) == 0


def test_validate_paths_symbolic_link(tmp_path):
    """
    PROVES: Validator detects and reports symbolic links

    Commands with symlinks get info messages
    """
    # Create file and symlink
    real_file = tmp_path / "real_wordlist.txt"
    real_file.write_text("test\n")

    symlink = tmp_path / "link_wordlist.txt"
    symlink.symlink_to(real_file)

    command = f"gobuster dir -u http://target -w {symlink}"
    warnings = CommandValidator.validate_paths(command)

    # Should detect symlink
    symlink_warnings = [w for w in warnings if "symbolic link" in w.message.lower()]
    assert len(symlink_warnings) > 0


# ============================================================================
# FLAG COMPATIBILITY TESTS (5 tests)
# ============================================================================

def test_validate_flags_nmap_scan_type_conflict():
    """
    PROVES: Validator detects nmap scan type conflicts

    -sS (SYN) and -sT (Connect) are incompatible
    """
    parsed = ParsedCommand(
        tool="nmap",
        subcommand=None,
        flags={"sS": True, "sT": True},
        parameters={},
        arguments=["192.168.1.1"]
    )

    result = CommandValidator.validate_flags(parsed)

    assert not result.is_valid
    assert any("-sS" in err and "-sT" in err for err in result.errors)


def test_validate_flags_nmap_missing_target():
    """
    PROVES: Validator detects missing nmap target

    Nmap requires a target specification
    """
    parsed = ParsedCommand(
        tool="nmap",
        subcommand=None,
        flags={"sV": True},
        parameters={"p": "80"},
        arguments=[]
    )

    result = CommandValidator.validate_flags(parsed)

    assert not result.is_valid
    assert "no target" in result.errors[0].lower()


def test_validate_flags_gobuster_missing_required():
    """
    PROVES: Validator detects missing gobuster required flags

    Gobuster requires -u (URL) and -w (wordlist)
    """
    # Missing URL
    parsed = ParsedCommand(
        tool="gobuster",
        subcommand="dir",
        flags={},
        parameters={"w": "/path/wordlist.txt"},
        arguments=[]
    )

    result = CommandValidator.validate_flags(parsed)

    assert not result.is_valid
    assert any("-u" in err for err in result.errors)

    # Missing wordlist
    parsed = ParsedCommand(
        tool="gobuster",
        subcommand="dir",
        flags={},
        parameters={"u": "http://target"},
        arguments=[]
    )

    result = CommandValidator.validate_flags(parsed)

    assert not result.is_valid
    assert any("-w" in err for err in result.errors)


def test_validate_flags_hydra_missing_credentials():
    """
    PROVES: Validator detects missing hydra credential specification

    Hydra requires username (-l/-L) and password (-p/-P)
    """
    # Missing username
    parsed = ParsedCommand(
        tool="hydra",
        subcommand=None,
        flags={},
        parameters={"p": "password"},
        arguments=["ssh://target"]
    )

    result = CommandValidator.validate_flags(parsed)

    assert not result.is_valid
    assert any("username" in err.lower() for err in result.errors)

    # Missing password
    parsed = ParsedCommand(
        tool="hydra",
        subcommand=None,
        flags={},
        parameters={"l": "admin"},
        arguments=["ssh://target"]
    )

    result = CommandValidator.validate_flags(parsed)

    assert not result.is_valid
    assert any("password" in err.lower() for err in result.errors)


def test_validate_flags_valid_commands():
    """
    PROVES: Validator accepts valid tool configurations

    Well-formed commands pass validation without errors
    """
    # Valid nmap
    parsed = ParsedCommand(
        tool="nmap",
        subcommand=None,
        flags={"sV": True},
        parameters={"p": "80,443"},
        arguments=["192.168.1.1"]
    )

    result = CommandValidator.validate_flags(parsed)
    assert result.is_valid

    # Valid gobuster
    parsed = ParsedCommand(
        tool="gobuster",
        subcommand="dir",
        flags={},
        parameters={"u": "http://target", "w": "/path/wordlist.txt"},
        arguments=[]
    )

    result = CommandValidator.validate_flags(parsed)
    assert result.is_valid


# ============================================================================
# RUNTIME ESTIMATION TESTS (3 tests)
# ============================================================================

def test_estimate_runtime_gobuster_wordlist_size(tmp_path):
    """
    PROVES: Runtime estimation accounts for wordlist size

    Larger wordlists increase estimated runtime
    """
    # Create small wordlist
    small_wordlist = tmp_path / "small.txt"
    small_wordlist.write_text("\n".join(["word"] * 100))

    # Create large wordlist
    large_wordlist = tmp_path / "large.txt"
    large_wordlist.write_text("\n".join(["word"] * 10000))

    small_cmd = f"gobuster dir -u http://target -w {small_wordlist}"
    large_cmd = f"gobuster dir -u http://target -w {large_wordlist}"

    small_time = CommandValidator.estimate_runtime(small_cmd, "gobuster")
    large_time = CommandValidator.estimate_runtime(large_cmd, "gobuster")

    assert large_time > small_time


def test_estimate_runtime_nmap_port_range():
    """
    PROVES: Runtime estimation accounts for port range

    Scanning more ports increases estimated runtime
    """
    small_cmd = "nmap -p 80 192.168.1.1"
    large_cmd = "nmap -p 1-65535 192.168.1.1"

    small_time = CommandValidator.estimate_runtime(small_cmd, "nmap")
    large_time = CommandValidator.estimate_runtime(large_cmd, "nmap")

    assert large_time > small_time


def test_estimate_runtime_nmap_timing_template():
    """
    PROVES: Runtime estimation accounts for timing template

    Faster timing templates (-T4, -T5) reduce estimated runtime
    """
    slow_cmd = "nmap -T2 -p 80 192.168.1.1"
    fast_cmd = "nmap -T4 -p 80 192.168.1.1"

    slow_time = CommandValidator.estimate_runtime(slow_cmd, "nmap")
    fast_time = CommandValidator.estimate_runtime(fast_cmd, "nmap")

    assert slow_time > fast_time


# ============================================================================
# SECURITY CHECKS TESTS (2 tests)
# ============================================================================

def test_validate_security_dangerous_rm_patterns():
    """
    PROVES: Validator detects dangerous rm -rf commands

    Commands with rm -rf / or * are flagged as security risks
    """
    dangerous_commands = [
        "rm -rf /",
        "rm -rf /*",
        "rm -rf *",
    ]

    for cmd in dangerous_commands:
        warnings = CommandValidator.validate_security(cmd)
        assert len(warnings) > 0
        assert any(w.type == "security_risk" for w in warnings)
        assert any(w.severity == "error" for w in warnings)


def test_validate_security_etc_writes():
    """
    PROVES: Validator detects attempts to write to /etc

    Commands writing to /etc are flagged as security risks
    """
    dangerous_commands = [
        "echo 'bad' > /etc/passwd",
        "cat malicious >> /etc/hosts",
        "tee /etc/shadow < exploit.txt",
    ]

    for cmd in dangerous_commands:
        warnings = CommandValidator.validate_security(cmd)

        security_warnings = [w for w in warnings if w.type == "security_risk"]
        assert len(security_warnings) > 0
        assert any("/etc" in w.message for w in security_warnings)
        assert any(w.severity == "error" for w in security_warnings)
