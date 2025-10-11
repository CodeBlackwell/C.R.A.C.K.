"""
Tests for CommandFormatter Component

VALUE: Proves commands can be formatted, highlighted, and diffed correctly

Test Strategy:
- Round-trip parsing (parse → format → parse = same result)
- Multi-line formatting for long commands
- Diff highlighting for modifications
- Edge cases (special chars, long commands, quotes)
"""

import pytest
from crack.track.interactive.components.command_editor.formatter import (
    CommandFormatter,
    ParsedCommand
)


# ==================== ROUND-TRIP TESTS ====================

def test_format_gobuster_command():
    """
    PROVES: Gobuster commands format correctly with proper flag order

    User Actions:
    1. Parse gobuster command
    2. Format back to string
    3. Verify executable and flags ordered correctly
    """
    parsed = ParsedCommand(
        tool="gobuster",
        subcommand="dir",
        flags={},
        parameters={'u': 'http://192.168.45.100', 'w': '/usr/share/wordlists/dirb/common.txt'},
        arguments=[]
    )

    result = CommandFormatter.format_command(parsed)

    assert result == "gobuster dir -u http://192.168.45.100 -w /usr/share/wordlists/dirb/common.txt"
    assert result.startswith("gobuster dir")
    assert "-u" in result
    assert "-w" in result


def test_format_nmap_command_with_flags():
    """
    PROVES: Nmap commands with boolean flags format correctly

    User Actions:
    1. Parse nmap with flags (-sS, -sV)
    2. Format back to string
    3. Verify flags and parameters preserved
    """
    parsed = ParsedCommand(
        tool="nmap",
        subcommand=None,
        flags={'sS': True, 'sV': True},
        parameters={'p': '80,443', 'oA': 'scan_results'},
        arguments=['192.168.45.100']
    )

    result = CommandFormatter.format_command(parsed)

    assert result.startswith("nmap")
    assert "-sS" in result
    assert "-sV" in result
    assert "-p 80,443" in result
    assert "-oA scan_results" in result
    assert result.endswith("192.168.45.100")


def test_format_command_with_quoted_arguments():
    """
    PROVES: Commands with spaces in arguments get quoted correctly

    User Actions:
    1. Parse command with spaces in path
    2. Format back to string
    3. Verify quotes added to preserve spaces
    """
    parsed = ParsedCommand(
        tool="gobuster",
        subcommand="dir",
        flags={},
        parameters={'u': 'http://target', 'w': '/path with spaces/wordlist.txt'},
        arguments=[]
    )

    result = CommandFormatter.format_command(parsed)

    assert '"/path with spaces/wordlist.txt"' in result
    assert result.count('"') == 2  # Properly quoted


# ==================== MULTI-LINE FORMATTING TESTS ====================

def test_multiline_formatting_long_command():
    """
    PROVES: Long commands format across multiple lines with backslashes

    User Actions:
    1. Parse long command (>80 chars)
    2. Format with multi_line=True
    3. Verify backslashes and line breaks added
    """
    parsed = ParsedCommand(
        tool="gobuster",
        subcommand="dir",
        flags={'v': True, 'e': True},
        parameters={
            'u': 'http://very-long-domain-name.example.com/very/long/path',
            'w': '/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt',
            'x': 'php,html,txt,xml,js',
            'o': 'scan_results_with_very_long_filename.txt'
        },
        arguments=[]
    )

    result = CommandFormatter.format_command(parsed, multi_line=True)

    assert ' \\\n' in result  # Backslash continuation
    assert result.count('\n') > 0  # Multiple lines
    assert result.startswith("gobuster")
    # Verify continuation lines are indented
    lines = result.split('\n')
    assert any(line.startswith('    ') for line in lines[1:])


def test_multiline_preserves_command_structure():
    """
    PROVES: Multi-line format preserves command execution correctness

    User Actions:
    1. Format long command as multi-line
    2. Remove backslashes and newlines
    3. Verify matches single-line version
    """
    parsed = ParsedCommand(
        tool="nmap",
        subcommand=None,
        flags={'sS': True, 'sV': True, 'A': True},
        parameters={
            'p': '1-65535',
            'T': '4',
            'oA': 'full_scan_results'
        },
        arguments=['192.168.45.100']
    )

    single_line = CommandFormatter.format_command(parsed, multi_line=False)
    multi_line = CommandFormatter.format_command(parsed, multi_line=True)

    # Remove formatting to compare
    multi_line_stripped = multi_line.replace(' \\\n', ' ').replace('\n', ' ')
    # Normalize whitespace
    multi_line_stripped = ' '.join(multi_line_stripped.split())

    assert single_line == multi_line_stripped


# ==================== DIFF DISPLAY TESTS ====================

def test_diff_shows_parameter_change():
    """
    PROVES: Diff highlights changed parameters correctly

    User Actions:
    1. Format original command
    2. Modify parameter value
    3. Generate diff
    4. Verify red (removed) and green (added) markup
    """
    original = "gobuster dir -u http://target -w /path/old.txt"
    modified = "gobuster dir -u http://target -w /path/new.txt"

    diff = CommandFormatter.show_diff(original, modified)

    assert '[red]-' in diff  # Removed line
    assert '[green]+' in diff  # Added line
    assert 'old.txt' in diff
    assert 'new.txt' in diff


def test_diff_shows_flag_addition():
    """
    PROVES: Diff highlights added flags correctly

    User Actions:
    1. Format original command without flag
    2. Add verbose flag
    3. Generate diff
    4. Verify addition highlighted
    """
    original = "nmap -p 80 192.168.45.100"
    modified = "nmap -sV -p 80 192.168.45.100"

    diff = CommandFormatter.show_diff(original, modified)

    assert '[red]-' in diff
    assert '[green]+' in diff
    assert '-sV' in diff


def test_diff_handles_no_changes():
    """
    PROVES: Diff shows helpful message when commands are identical

    User Actions:
    1. Format command
    2. Compare to itself
    3. Verify "No changes" message
    """
    command = "gobuster dir -u http://target -w /path/wordlist.txt"

    diff = CommandFormatter.show_diff(command, command)

    assert diff == '[dim]No changes detected[/dim]'


# ==================== EDGE CASES TESTS ====================

def test_format_handles_long_flag_names():
    """
    PROVES: Commands with long flags (--flag) format correctly

    User Actions:
    1. Parse command with long flags
    2. Format back to string
    3. Verify double-dash prefix preserved
    """
    parsed = ParsedCommand(
        tool="sqlmap",
        subcommand=None,
        flags={'verbose': True},
        parameters={'dbs': '', 'tables': ''},  # sqlmap uses --dbs (no value)
        arguments=[]
    )

    result = CommandFormatter.format_command(parsed)

    assert "--verbose" in result
    assert result.count('--') >= 1


def test_format_handles_special_characters():
    """
    PROVES: Special characters in values are preserved correctly

    User Actions:
    1. Parse command with special chars ($, &, |, etc.)
    2. Format back to string
    3. Verify special chars preserved (not escaped or lost)
    """
    parsed = ParsedCommand(
        tool="hydra",
        subcommand=None,
        flags={},
        parameters={
            'l': 'admin',
            'p': 'P@ssw0rd!',
            't': '4'
        },
        arguments=['ssh://192.168.45.100']
    )

    result = CommandFormatter.format_command(parsed)

    assert 'P@ssw0rd!' in result
    assert 'ssh://192.168.45.100' in result


# ==================== SYNTAX HIGHLIGHTING TESTS ====================

def test_highlight_syntax_tool_name():
    """
    PROVES: Tool name highlighted correctly

    User Actions:
    1. Parse command
    2. Apply syntax highlighting
    3. Verify tool name has cyan markup
    """
    command = "gobuster dir -u http://target"

    result = CommandFormatter.highlight_syntax(command)

    assert '[cyan bold]gobuster[/cyan bold]' in result


def test_highlight_syntax_flags():
    """
    PROVES: Flags highlighted correctly

    User Actions:
    1. Parse command with flags
    2. Apply syntax highlighting
    3. Verify flags have yellow markup
    """
    command = "nmap -sS -sV -p 80 192.168.45.100"

    result = CommandFormatter.highlight_syntax(command)

    assert '[yellow]-sS[/yellow]' in result
    assert '[yellow]-sV[/yellow]' in result
    assert '[yellow]-p[/yellow]' in result


def test_highlight_syntax_urls_and_paths():
    """
    PROVES: URLs and file paths highlighted correctly

    User Actions:
    1. Parse command with URL and path
    2. Apply syntax highlighting
    3. Verify URLs magenta, paths blue
    """
    command = "gobuster dir -u http://192.168.45.100 -w /usr/share/wordlists/common.txt -o results.txt"

    result = CommandFormatter.highlight_syntax(command)

    assert '[magenta]http://192.168.45.100[/magenta]' in result
    assert '[blue]/usr/share/wordlists/common.txt[/blue]' in result
    assert '[blue]results.txt[/blue]' in result


# ==================== INTEGRATION TEST ====================

def test_full_workflow_format_highlight_diff():
    """
    PROVES: Complete workflow works end-to-end

    User Actions:
    1. Parse command
    2. Format to string
    3. Apply syntax highlighting
    4. Modify and generate diff
    5. Verify all steps produce expected output
    """
    # Step 1: Parse
    parsed = ParsedCommand(
        tool="gobuster",
        subcommand="dir",
        flags={'v': True},
        parameters={'u': 'http://target', 'w': '/path/wordlist.txt'},
        arguments=[]
    )

    # Step 2: Format
    formatted = CommandFormatter.format_command(parsed)
    assert "gobuster dir" in formatted
    assert "-v" in formatted

    # Step 3: Highlight
    highlighted = CommandFormatter.highlight_syntax(formatted)
    assert '[cyan bold]gobuster[/cyan bold]' in highlighted
    assert '[yellow]-v[/yellow]' in highlighted

    # Step 4: Modify and diff
    parsed.parameters['w'] = '/new/wordlist.txt'
    modified = CommandFormatter.format_command(parsed)
    diff = CommandFormatter.show_diff(formatted, modified)

    assert '[red]-' in diff
    assert '[green]+' in diff
    assert '/path/wordlist.txt' in diff
    assert '/new/wordlist.txt' in diff
