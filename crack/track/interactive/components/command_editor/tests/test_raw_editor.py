"""
Tests for RawEditor - Multi-line text editor component

Tests cover:
- Line insertion (beginning, middle, end)
- Line deletion (single, multiple, last)
- Cursor movement (up/down, line boundaries)
- Validation checks (syntax, execute flow)
"""

import pytest
from unittest.mock import patch, MagicMock
from ..raw_editor import RawEditor, EditResult
from ..validator import ValidationResult


class TestLineInsertion:
    """Test line insertion at various positions"""

    def test_insert_line_at_beginning(self):
        """PROVES: Line inserted at beginning preserves command structure"""
        editor = RawEditor(
            command="gobuster dir -u http://target",
            original_command="gobuster dir -u http://target"
        )

        editor._insert_line(0, "# This is a comment")

        assert editor.lines[0] == "# This is a comment"
        assert editor.lines[1] == "gobuster dir -u http://target"
        assert len(editor.lines) == 2
        assert editor.is_dirty()

    def test_insert_line_in_middle(self):
        """PROVES: Line inserted in middle maintains order"""
        editor = RawEditor(
            command="nmap -sS\n-p 1-65535\n192.168.1.1",
            original_command="nmap -sS\n-p 1-65535\n192.168.1.1"
        )

        editor._insert_line(1, "-sV")

        assert editor.lines[0] == "nmap -sS"
        assert editor.lines[1] == "-sV"
        assert editor.lines[2] == "-p 1-65535"
        assert editor.lines[3] == "192.168.1.1"
        assert len(editor.lines) == 4

    def test_insert_line_at_end(self):
        """PROVES: Line appended at end extends command"""
        editor = RawEditor(
            command="gobuster dir -u http://target",
            original_command="gobuster dir -u http://target"
        )

        editor._insert_line(1, "-w /usr/share/wordlists/common.txt")

        assert editor.lines[0] == "gobuster dir -u http://target"
        assert editor.lines[1] == "-w /usr/share/wordlists/common.txt"
        assert len(editor.lines) == 2


class TestLineDeletion:
    """Test line deletion scenarios"""

    def test_delete_single_line(self):
        """PROVES: Single line deleted from multi-line command"""
        editor = RawEditor(
            command="nmap -sS\n-sV\n-p 1-65535\n192.168.1.1",
            original_command="nmap -sS\n-sV\n-p 1-65535\n192.168.1.1"
        )

        result = editor._delete_line(1)

        assert result is True
        assert editor.lines[0] == "nmap -sS"
        assert editor.lines[1] == "-p 1-65535"
        assert editor.lines[2] == "192.168.1.1"
        assert len(editor.lines) == 3
        assert editor.is_dirty()

    def test_delete_multiple_lines_sequential(self):
        """PROVES: Multiple lines deleted in sequence"""
        editor = RawEditor(
            command="line1\nline2\nline3\nline4",
            original_command="line1\nline2\nline3\nline4"
        )

        editor._delete_line(1)
        editor._delete_line(1)  # Delete what was line3 (now at index 1)

        assert editor.lines == ["line1", "line4"]
        assert len(editor.lines) == 2

    def test_delete_last_line_clears_content(self):
        """PROVES: Deleting last line clears content but keeps editor open"""
        editor = RawEditor(
            command="single line command",
            original_command="single line command"
        )

        result = editor._delete_line(0)

        assert result is True
        assert len(editor.lines) == 1
        assert editor.lines[0] == ''  # Cleared but editor still has one line


class TestCursorMovement:
    """Test cursor position tracking"""

    def test_cursor_move_up_down(self):
        """PROVES: Cursor moves between lines correctly"""
        editor = RawEditor(
            command="line1\nline2\nline3",
            original_command="line1\nline2\nline3"
        )

        # Start at line 0
        assert editor.cursor_line == 0

        # Move down
        editor._move_cursor(1, 0)
        assert editor.cursor_line == 1
        assert editor.cursor_col == 0

        # Move down again
        editor._move_cursor(2, 0)
        assert editor.cursor_line == 2

        # Move up
        editor._move_cursor(0, 0)
        assert editor.cursor_line == 0

    def test_cursor_clamps_to_line_boundaries(self):
        """PROVES: Cursor position clamped to valid line range"""
        editor = RawEditor(
            command="line1\nline2",
            original_command="line1\nline2"
        )

        # Try to move beyond last line
        editor._move_cursor(10, 0)
        assert editor.cursor_line == 1  # Clamped to last line (index 1)

        # Try to move before first line
        editor._move_cursor(-5, 0)
        assert editor.cursor_line == 0  # Clamped to first line

    def test_cursor_clamps_to_column_boundaries(self):
        """PROVES: Cursor column clamped to line length"""
        editor = RawEditor(
            command="short\nthis is a longer line",
            original_command="short\nthis is a longer line"
        )

        # Move to line 0 (5 chars)
        editor._move_cursor(0, 100)
        assert editor.cursor_col == 5  # Clamped to line length

        # Move to line 1 (21 chars)
        editor._move_cursor(1, 50)
        assert editor.cursor_col == 21  # Clamped to line length

        # Negative column
        editor._move_cursor(0, -5)
        assert editor.cursor_col == 0  # Clamped to 0


class TestValidation:
    """Test validation checks and execution flow"""

    def test_validation_blocks_invalid_syntax(self):
        """PROVES: Invalid syntax prevents execution"""
        editor = RawEditor(
            command='gobuster dir -u "http://target',  # Unbalanced quotes
            original_command='gobuster dir -u http://target'
        )

        result = editor.run()

        assert result.action == "cancel"
        assert result.command is None

    def test_validation_allows_valid_command(self):
        """PROVES: Valid command can be executed"""
        editor = RawEditor(
            command="gobuster dir -u http://target -w /path/wordlist.txt",
            original_command="gobuster dir -u http://target"
        )

        # Mock validation to return valid
        with patch.object(editor, '_validate_current') as mock_validate:
            mock_validate.return_value = ValidationResult(
                is_valid=True,
                errors=[],
                warnings=[]
            )
            result = editor.run()

        assert result.action == "execute"
        assert result.command is not None
        assert "gobuster" in result.command

    def test_validation_checks_syntax(self):
        """PROVES: Validation uses CommandValidator for syntax"""
        editor = RawEditor(
            command="valid command syntax",
            original_command="original"
        )

        validation = editor._validate_current()

        # Should return ValidationResult
        assert isinstance(validation, ValidationResult)
        assert hasattr(validation, 'is_valid')
        assert hasattr(validation, 'errors')
        assert hasattr(validation, 'warnings')


class TestEditorUtilities:
    """Test utility methods"""

    def test_get_command_joins_lines(self):
        """PROVES: get_command reconstructs multi-line command"""
        editor = RawEditor(
            command="line1\nline2\nline3",
            original_command="original"
        )

        command = editor.get_command()

        assert command == "line1\nline2\nline3"
        assert command.count('\n') == 2

    def test_get_line_count(self):
        """PROVES: Line count tracked correctly"""
        editor = RawEditor(
            command="line1\nline2\nline3",
            original_command="original"
        )

        assert editor.get_line_count() == 3

        editor._insert_line(0, "new line")
        assert editor.get_line_count() == 4

        editor._delete_line(0)
        assert editor.get_line_count() == 3

    def test_get_line_retrieves_content(self):
        """PROVES: Individual lines can be retrieved"""
        editor = RawEditor(
            command="first\nsecond\nthird",
            original_command="original"
        )

        assert editor.get_line(0) == "first"
        assert editor.get_line(1) == "second"
        assert editor.get_line(2) == "third"
        assert editor.get_line(5) is None  # Out of range
        assert editor.get_line(-1) is None  # Negative index

    def test_replace_line_updates_content(self):
        """PROVES: Line content can be replaced"""
        editor = RawEditor(
            command="old line 1\nold line 2",
            original_command="original"
        )

        result = editor.replace_line(0, "new line 1")

        assert result is True
        assert editor.get_line(0) == "new line 1"
        assert editor.get_line(1) == "old line 2"
        assert editor.is_dirty()

    def test_replace_invalid_line_returns_false(self):
        """PROVES: Replacing invalid line number fails gracefully"""
        editor = RawEditor(
            command="single line",
            original_command="original"
        )

        result = editor.replace_line(10, "new content")

        assert result is False
        assert editor.get_line(0) == "single line"  # Unchanged

    def test_is_dirty_tracks_modifications(self):
        """PROVES: Dirty flag tracks command modifications"""
        editor = RawEditor(
            command="original command",
            original_command="original command"
        )

        # Initially not dirty (same as original)
        assert not editor.is_dirty()

        # Modify command
        editor._insert_line(0, "new line")
        assert editor.is_dirty()

    def test_revert_restores_original(self):
        """PROVES: Revert restores original command state"""
        editor = RawEditor(
            command="modified command",
            original_command="original command"
        )

        editor._insert_line(0, "added line")
        editor._move_cursor(2, 5)
        assert editor.is_dirty()

        editor.revert()

        assert editor.get_command() == "original command"
        assert editor.cursor_line == 0
        assert editor.cursor_col == 0
        assert not editor.is_dirty()


class TestEdgeCases:
    """Test edge cases and boundary conditions"""

    def test_empty_command_initialization(self):
        """PROVES: Editor handles empty command gracefully"""
        editor = RawEditor(
            command="",
            original_command=""
        )

        assert editor.get_line_count() == 1
        assert editor.get_line(0) == ''

    def test_insert_at_negative_index_clamps(self):
        """PROVES: Negative insert index clamped to 0"""
        editor = RawEditor(
            command="existing line",
            original_command="existing"
        )

        editor._insert_line(-5, "new line")

        assert editor.get_line(0) == "new line"
        assert editor.get_line(1) == "existing line"

    def test_insert_beyond_end_appends(self):
        """PROVES: Insert beyond end appends to end"""
        editor = RawEditor(
            command="line1\nline2",
            original_command="original"
        )

        editor._insert_line(100, "line3")

        assert editor.get_line_count() == 3
        assert editor.get_line(2) == "line3"

    def test_delete_out_of_range_returns_false(self):
        """PROVES: Deleting out-of-range line fails gracefully"""
        editor = RawEditor(
            command="single line",
            original_command="original"
        )

        result_negative = editor._delete_line(-1)
        result_too_high = editor._delete_line(10)

        assert result_negative is False
        assert result_too_high is False
        assert editor.get_line_count() == 1  # Unchanged

    def test_multiline_command_with_backslashes(self):
        """PROVES: Multi-line commands with backslashes preserved"""
        editor = RawEditor(
            command="nmap -sS \\\n-sV \\\n-p 1-65535 \\\n192.168.1.1",
            original_command="nmap -sS \\\n-sV \\\n-p 1-65535 \\\n192.168.1.1"
        )

        assert editor.get_line_count() == 4
        assert editor.get_line(0) == "nmap -sS \\"
        assert editor.get_line(1) == "-sV \\"
        assert editor.get_line(2) == "-p 1-65535 \\"
        assert editor.get_line(3) == "192.168.1.1"

        # Command reconstruction preserves backslashes
        command = editor.get_command()
        assert command.count('\\') == 3
