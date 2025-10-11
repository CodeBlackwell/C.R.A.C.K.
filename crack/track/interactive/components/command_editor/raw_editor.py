"""
RawEditor - Multi-line text editor for command editing

Pure logic component for raw text editing with line manipulation,
cursor tracking, and validation. NO TUI rendering.
"""

from dataclasses import dataclass
from typing import Optional, List
from .validator import ValidationResult, CommandValidator


@dataclass
class EditResult:
    """Result of edit operation"""
    command: Optional[str]
    action: str  # "execute", "escalate", "cancel"
    next_tier: Optional[str] = None
    save_behavior: Optional[str] = None


class RawEditor:
    """Multi-line command editor with validation

    Pure logic component - no TUI rendering, returns data structures.
    Provides line insertion/deletion, cursor tracking, and validation.
    """

    def __init__(self, command: str, original_command: str):
        """Initialize editor with command

        Args:
            command: Current command string (may have edits)
            original_command: Original command string (for diff/revert)
        """
        self.lines = command.split('\n') if command else ['']
        self.original = original_command
        self.cursor_line = 0
        self.cursor_col = 0
        self._dirty = False  # Track if command has been modified

    def run(self) -> EditResult:
        """Main raw edit flow (NO TUI rendering)

        Returns:
            EditResult with final command and action
        """
        # Validate current command
        validation = self._validate_current()

        if not validation.is_valid:
            # Cannot execute invalid command
            return EditResult(
                command=None,
                action="cancel"
            )

        # If valid, return for execution
        return EditResult(
            command=self.get_command(),
            action="execute"
        )

    def _insert_line(self, line_num: int, text: str) -> None:
        """Insert new line at position

        Args:
            line_num: Line number (0-indexed) where to insert
            text: Text content for new line
        """
        if line_num < 0:
            line_num = 0
        elif line_num > len(self.lines):
            line_num = len(self.lines)

        self.lines.insert(line_num, text)
        self._dirty = True

    def _delete_line(self, line_num: int) -> bool:
        """Delete line at position

        Args:
            line_num: Line number (0-indexed) to delete

        Returns:
            True if line was deleted, False if invalid line number
        """
        if line_num < 0 or line_num >= len(self.lines):
            return False

        # Don't allow deleting the last line if it would leave editor empty
        if len(self.lines) == 1:
            self.lines[0] = ''  # Clear content instead
        else:
            del self.lines[line_num]

        self._dirty = True
        return True

    def _move_cursor(self, line: int, col: int) -> None:
        """Move cursor to specified position

        Args:
            line: Target line number (0-indexed)
            col: Target column number (0-indexed)
        """
        # Clamp line to valid range
        if line < 0:
            line = 0
        elif line >= len(self.lines):
            line = len(self.lines) - 1

        # Clamp column to line length
        max_col = len(self.lines[line]) if line < len(self.lines) else 0
        if col < 0:
            col = 0
        elif col > max_col:
            col = max_col

        self.cursor_line = line
        self.cursor_col = col

    def _validate_current(self) -> ValidationResult:
        """Validate current command

        Returns:
            ValidationResult with errors and warnings
        """
        command = self.get_command()

        # Use CommandValidator for syntax validation
        return CommandValidator.validate_syntax(command)

    def get_command(self) -> str:
        """Return current command as single string

        Returns:
            Command with lines joined by newlines
        """
        return '\n'.join(self.lines)

    def get_line_count(self) -> int:
        """Return number of lines in editor

        Returns:
            Line count
        """
        return len(self.lines)

    def get_line(self, line_num: int) -> Optional[str]:
        """Get line content by line number

        Args:
            line_num: Line number (0-indexed)

        Returns:
            Line content or None if invalid line number
        """
        if 0 <= line_num < len(self.lines):
            return self.lines[line_num]
        return None

    def replace_line(self, line_num: int, text: str) -> bool:
        """Replace line content at position

        Args:
            line_num: Line number (0-indexed) to replace
            text: New text content

        Returns:
            True if line was replaced, False if invalid line number
        """
        if line_num < 0 or line_num >= len(self.lines):
            return False

        self.lines[line_num] = text
        self._dirty = True
        return True

    def is_dirty(self) -> bool:
        """Check if command has been modified

        Returns:
            True if command differs from original
        """
        return self._dirty or self.get_command() != self.original

    def revert(self) -> None:
        """Revert to original command"""
        self.lines = self.original.split('\n') if self.original else ['']
        self.cursor_line = 0
        self.cursor_col = 0
        self._dirty = False
