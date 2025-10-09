"""
TUI Input Handler - Non-blocking keyboard input for TUI mode

Handles user input while maintaining Rich Live display updates.
Uses threading to avoid blocking the Live refresh loop.
"""

import sys
import select
import threading
from typing import Optional, Callable
from queue import Queue, Empty


class TUIInputHandler:
    """Handle keyboard input for TUI without blocking Live display"""

    def __init__(self):
        """Initialize input handler"""
        self.input_queue = Queue()
        self.running = False
        self.input_thread = None
        self._prompt = "Choice [or shortcut]: "

    def start(self):
        """Start input thread"""
        if self.running:
            return

        self.running = True
        self.input_thread = threading.Thread(target=self._input_loop, daemon=True)
        self.input_thread.start()

    def stop(self):
        """Stop input thread"""
        self.running = False
        if self.input_thread:
            self.input_thread.join(timeout=1.0)

    def _input_loop(self):
        """Background thread for reading input"""
        while self.running:
            try:
                # Check if input is available (non-blocking)
                if sys.stdin in select.select([sys.stdin], [], [], 0.1)[0]:
                    line = sys.stdin.readline().strip()
                    if line:
                        self.input_queue.put(line)
            except (OSError, ValueError):
                # Handle stdin issues gracefully
                break

    def get_input(self, timeout: float = 0.1) -> Optional[str]:
        """
        Get input from queue (non-blocking)

        Args:
            timeout: How long to wait for input (seconds)

        Returns:
            Input string or None if no input available
        """
        try:
            return self.input_queue.get(timeout=timeout)
        except Empty:
            return None

    def clear_queue(self):
        """Clear any pending input"""
        while not self.input_queue.empty():
            try:
                self.input_queue.get_nowait()
            except Empty:
                break

    def set_prompt(self, prompt: str):
        """Set input prompt text"""
        self._prompt = prompt

    def get_prompt(self) -> str:
        """Get current prompt text"""
        return self._prompt

    def has_input(self) -> bool:
        """Check if input is available"""
        return not self.input_queue.empty()


class SimpleInputHandler:
    """
    Fallback input handler using blocking input

    Used when non-blocking input not available (e.g., not a TTY)
    """

    def __init__(self):
        """Initialize simple handler"""
        self._prompt = ""  # Prompt shown in TUI panel, not here

    def start(self):
        """No-op for compatibility"""
        pass

    def stop(self):
        """No-op for compatibility"""
        pass

    def get_input(self, timeout: float = None) -> Optional[str]:
        """
        Get input using built-in input() (blocking)

        Args:
            timeout: Ignored (blocking mode)

        Returns:
            Input string or None on EOF
        """
        try:
            # Don't show prompt here - it's shown in TUI panel
            return input().strip()
        except EOFError:
            return None
        except KeyboardInterrupt:
            return None

    def clear_queue(self):
        """No-op for compatibility"""
        pass

    def set_prompt(self, prompt: str):
        """Set input prompt text"""
        self._prompt = prompt

    def get_prompt(self) -> str:
        """Get current prompt text"""
        return self._prompt

    def has_input(self) -> bool:
        """Always returns False (blocking mode)"""
        return False


def create_input_handler() -> TUIInputHandler:
    """
    Create appropriate input handler for environment

    Returns:
        TUIInputHandler or SimpleInputHandler depending on environment
    """
    # Check if we can use non-blocking input
    if sys.stdin.isatty():
        try:
            # Test if select works
            select.select([sys.stdin], [], [], 0)
            return TUIInputHandler()
        except:
            pass

    # Fallback to simple blocking input
    return SimpleInputHandler()
