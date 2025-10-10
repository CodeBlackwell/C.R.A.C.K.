"""
Hotkey Input Handler - Vim-style instant key execution

Single-key shortcuts execute immediately (no ENTER required).
Press ':' to enter command mode for multi-character input.

Uses termios + tty for raw mode terminal control (Unix/Linux only).
"""

import sys
import tty
import termios
import time
from typing import Optional


class HotkeyInputHandler:
    """
    Instant single-key input handler with vim-style command mode

    Features:
    - Single keys execute instantly (h, s, t, 1, 2, q, etc.)
    - ':' activates command mode for multi-char input
    - Number buffering for multi-digit choices (12, 15, etc.)
    - Graceful fallback if raw mode unavailable
    """

    def __init__(self, debug_logger=None):
        """
        Initialize hotkey handler

        Args:
            debug_logger: Optional DebugLogger instance for tracking
        """
        self.debug_logger = debug_logger
        self.original_settings = None
        self.in_raw_mode = False

        if self.debug_logger:
            self.debug_logger.debug("HotkeyInputHandler initialized")

    def read_key(self, timeout: float = None) -> Optional[str]:
        """
        Read single key instantly (no ENTER required)

        Args:
            timeout: Optional timeout in seconds (None = block forever)

        Returns:
            Single character string, or None on timeout/error
        """
        if not sys.stdin.isatty():
            if self.debug_logger:
                self.debug_logger.warning("stdin is not a TTY - falling back to line input")
            # Fallback: not a TTY
            return self._fallback_read_line()

        try:
            # Enter raw mode
            self._set_raw_mode()

            if self.debug_logger:
                self.debug_logger.debug(f"Reading single key (timeout={timeout})")

            # Read single character
            if timeout:
                # TODO: Implement timeout with select.select()
                # For now, just block
                key = sys.stdin.read(1)
            else:
                key = sys.stdin.read(1)

            if self.debug_logger:
                # Log key with repr to show special chars
                self.debug_logger.debug(f"Key pressed: {repr(key)} (ord={ord(key) if key else 'None'})")

            # Handle special keys
            if key == '\x03':  # Ctrl+C
                if self.debug_logger:
                    self.debug_logger.warning("Ctrl+C detected in hotkey mode")
                raise KeyboardInterrupt

            if key == '\x04':  # Ctrl+D (EOF)
                if self.debug_logger:
                    self.debug_logger.warning("Ctrl+D (EOF) detected")
                return None

            return key

        except Exception as e:
            if self.debug_logger:
                self.debug_logger.exception(f"Error reading key: {e}")
            return None
        finally:
            # Always restore terminal mode
            self._restore_mode()

    def read_command(self, prompt: str = ":") -> str:
        """
        Read multi-character command (vim-style command mode)

        Args:
            prompt: Prompt to display (default: ":")

        Returns:
            Command string (without the leading ':')
        """
        if self.debug_logger:
            self.debug_logger.debug(f"Entering command mode with prompt: '{prompt}'")

        # Restore normal mode for line input
        self._restore_mode()

        try:
            # Show prompt
            sys.stdout.write(prompt)
            sys.stdout.flush()

            # Read line (requires ENTER)
            command = input().strip()

            if self.debug_logger:
                self.debug_logger.debug(f"Command entered: '{command}'")

            return command

        except (EOFError, KeyboardInterrupt) as e:
            if self.debug_logger:
                self.debug_logger.warning(f"Command input interrupted: {e}")
            return ""

    def read_number(self, first_digit: str, timeout: float = 0.5) -> str:
        """
        Read multi-digit number with timeout

        Args:
            first_digit: First digit already pressed
            timeout: Timeout for additional digits (seconds)

        Returns:
            Complete number string (e.g., "12", "5")
        """
        if self.debug_logger:
            self.debug_logger.debug(f"Reading multi-digit number, first digit: '{first_digit}'")

        buffer = first_digit
        start_time = time.time()

        try:
            self._set_raw_mode()

            while True:
                elapsed = time.time() - start_time
                remaining = timeout - elapsed

                if remaining <= 0:
                    if self.debug_logger:
                        self.debug_logger.debug(f"Number input timeout, returning: '{buffer}'")
                    break

                # Check if input available (non-blocking read with select would be better)
                # For now, use a small blocking read with exception handling
                import select
                if sys.stdin in select.select([sys.stdin], [], [], remaining)[0]:
                    key = sys.stdin.read(1)

                    if self.debug_logger:
                        self.debug_logger.debug(f"Additional key: {repr(key)}")

                    if key.isdigit():
                        buffer += key
                    else:
                        # Non-digit = end of number
                        if self.debug_logger:
                            self.debug_logger.debug(f"Non-digit detected, number complete: '{buffer}'")
                        break
                else:
                    # Timeout - no more input
                    break

            return buffer

        except Exception as e:
            if self.debug_logger:
                self.debug_logger.exception(f"Error reading number: {e}")
            return buffer
        finally:
            self._restore_mode()

    def _set_raw_mode(self):
        """Put terminal in raw mode (single-char input, no echo)"""
        if self.in_raw_mode:
            return

        try:
            self.original_settings = termios.tcgetattr(sys.stdin)
            tty.setraw(sys.stdin.fileno())
            self.in_raw_mode = True

            if self.debug_logger:
                self.debug_logger.debug("Terminal set to raw mode")

        except Exception as e:
            if self.debug_logger:
                self.debug_logger.warning(f"Failed to set raw mode: {e}")

    def _restore_mode(self):
        """Restore terminal to normal mode"""
        if not self.in_raw_mode or not self.original_settings:
            return

        try:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, self.original_settings)
            self.in_raw_mode = False

            if self.debug_logger:
                self.debug_logger.debug("Terminal mode restored")

        except Exception as e:
            if self.debug_logger:
                self.debug_logger.warning(f"Failed to restore terminal mode: {e}")

    def _fallback_read_line(self) -> Optional[str]:
        """Fallback to line-based input when raw mode unavailable"""
        if self.debug_logger:
            self.debug_logger.debug("Using fallback line-based input")

        try:
            return input().strip()
        except (EOFError, KeyboardInterrupt):
            return None

    def __del__(self):
        """Ensure terminal mode is restored on cleanup"""
        self._restore_mode()
