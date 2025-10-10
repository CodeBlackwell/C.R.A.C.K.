"""
Terminal Resize Handler for CRACK Track TUI

Handles terminal size changes gracefully with minimum size enforcement.
Designed as a standalone utility class with callback-based architecture.

Thread-safe signal handling for SIGWINCH (terminal resize events).
"""

import signal
import shutil
import threading
from typing import Callable, Tuple, Optional, Dict, Any


class TerminalSizeError(Exception):
    """Raised when terminal size is below minimum requirements."""
    pass


class ResizeHandler:
    """
    Terminal resize handler with minimum size validation.

    Provides thread-safe SIGWINCH signal handling and dynamic layout
    recalculation for Rich-based TUIs.

    Attributes:
        MIN_WIDTH (int): Minimum terminal width (80 columns)
        MIN_HEIGHT (int): Minimum terminal height (24 rows)
        callback (Optional[Callable]): Function called on resize with (width, height)
        _lock (threading.Lock): Thread-safety lock for signal handlers
        _last_size (Tuple[int, int]): Cached terminal size to avoid redundant callbacks

    Example:
        >>> handler = ResizeHandler()
        >>> handler.setup_handler(lambda w, h: print(f"Resized to {w}x{h}"))
        >>> width, height = handler.get_terminal_size()
        >>> handler.check_minimum_size()
    """

    # Minimum terminal dimensions (standard VT100 compatibility)
    MIN_WIDTH = 80
    MIN_HEIGHT = 24

    def __init__(self):
        """Initialize resize handler with default state."""
        self.callback: Optional[Callable[[int, int], None]] = None
        self._lock = threading.Lock()
        self._last_size: Tuple[int, int] = (0, 0)

    def setup_handler(self, callback: Callable[[int, int], None]) -> None:
        """
        Register SIGWINCH signal handler for terminal resize events.

        Args:
            callback: Function to call on resize, receives (width, height) as args.
                     Should be fast (executed in signal handler context).

        Raises:
            ValueError: If callback is not callable

        Example:
            >>> def on_resize(width, height):
            ...     print(f"Terminal resized to {width}x{height}")
            >>> handler.setup_handler(on_resize)

        Note:
            Signal handlers run asynchronously and can interrupt any code.
            Callback should avoid blocking operations or complex logic.
        """
        if not callable(callback):
            raise ValueError("Callback must be callable")

        self.callback = callback

        # Register SIGWINCH handler (only on Unix-like systems)
        # SIGWINCH = terminal window size change
        signal.signal(signal.SIGWINCH, self.on_resize)

    def on_resize(self, signum: int, frame) -> None:
        """
        Signal handler called when terminal size changes.

        Args:
            signum: Signal number (should be signal.SIGWINCH)
            frame: Current stack frame (required by signal.signal interface)

        Thread-safe with lock to prevent race conditions. Only triggers
        callback if size actually changed (debounces redundant signals).

        Note:
            Called automatically by OS when terminal is resized.
            Do not call directly - use get_terminal_size() instead.
        """
        with self._lock:
            try:
                width, height = self.get_terminal_size()

                # Debounce: Only trigger callback if size actually changed
                if (width, height) != self._last_size:
                    self._last_size = (width, height)

                    if self.callback:
                        self.callback(width, height)
            except Exception:
                # Suppress exceptions in signal handler to avoid crashes
                # Signal handlers should never raise exceptions
                pass

    def get_terminal_size(self) -> Tuple[int, int]:
        """
        Get current terminal dimensions.

        Returns:
            Tuple of (width, height) in character cells

        Example:
            >>> handler = ResizeHandler()
            >>> width, height = handler.get_terminal_size()
            >>> print(f"Terminal is {width} columns × {height} rows")

        Note:
            Uses shutil.get_terminal_size() with fallback to 80x24.
            Safe to call from signal handlers (non-blocking).
        """
        size = shutil.get_terminal_size(fallback=(self.MIN_WIDTH, self.MIN_HEIGHT))
        return size.columns, size.lines

    def check_minimum_size(self) -> None:
        """
        Validate terminal meets minimum size requirements.

        Raises:
            TerminalSizeError: If terminal is smaller than MIN_WIDTH × MIN_HEIGHT

        Example:
            >>> handler = ResizeHandler()
            >>> try:
            ...     handler.check_minimum_size()
            ... except TerminalSizeError as e:
            ...     print(f"Terminal too small: {e}")

        Note:
            Should be called before rendering TUI to ensure usable display.
            Message includes resize instructions and fallback options.
        """
        width, height = self.get_terminal_size()

        if width < self.MIN_WIDTH or height < self.MIN_HEIGHT:
            raise TerminalSizeError(
                f"Terminal size {width}x{height} is below minimum {self.MIN_WIDTH}x{self.MIN_HEIGHT}.\n"
                f"Please resize your terminal to at least {self.MIN_WIDTH} columns × {self.MIN_HEIGHT} rows.\n"
                f"Alternatively, use basic CLI mode: crack track <target> (without --tui flag)"
            )

    def calculate_panel_sizes(
        self,
        width: int,
        height: int,
        header_height: int = 3,
        footer_height: int = 2
    ) -> Dict[str, Any]:
        """
        Calculate optimal panel dimensions for given terminal size.

        Args:
            width: Terminal width in columns
            height: Terminal height in rows
            header_height: Reserved rows for header/title (default: 3)
            footer_height: Reserved rows for footer/status (default: 2)

        Returns:
            Dictionary with panel dimension recommendations:
                - content_height: Available height for main content
                - content_width: Available width for main content
                - split_top_height: Height for top panel in vertical split
                - split_bottom_height: Height for bottom panel in vertical split
                - menu_width: Suggested width for side menus

        Example:
            >>> handler = ResizeHandler()
            >>> sizes = handler.calculate_panel_sizes(120, 40)
            >>> print(sizes['content_height'])  # 35 (40 - 3 - 2)
            >>> print(sizes['split_top_height'])  # 14 (40% of 35)

        Note:
            Follows Rich Layout conventions:
            - Vertical splits: 40/60 ratio (top/bottom)
            - Side menus: 25% of width
            - Minimum 1 row/column for each component
        """
        # Calculate available space after headers/footers
        content_height = max(1, height - header_height - footer_height)
        content_width = max(1, width - 2)  # Account for panel borders

        # Vertical split: 40% top, 60% bottom (common for detail/output views)
        split_top_height = max(1, int(content_height * 0.4))
        split_bottom_height = max(1, content_height - split_top_height)

        # Side menu: 25% of width (minimum 20 columns for readability)
        menu_width = max(20, int(width * 0.25))

        return {
            'content_height': content_height,
            'content_width': content_width,
            'split_top_height': split_top_height,
            'split_bottom_height': split_bottom_height,
            'menu_width': menu_width,
            'total_width': width,
            'total_height': height
        }

    def unregister_handler(self) -> None:
        """
        Remove SIGWINCH handler and reset callback.

        Call when exiting TUI mode to restore default signal handling.

        Example:
            >>> handler = ResizeHandler()
            >>> handler.setup_handler(my_callback)
            >>> # ... use TUI ...
            >>> handler.unregister_handler()  # Clean up before exit
        """
        # Restore default SIGWINCH handler
        signal.signal(signal.SIGWINCH, signal.SIG_DFL)
        self.callback = None
        self._last_size = (0, 0)
