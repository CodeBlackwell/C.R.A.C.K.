"""
Loading Indicator Components for CRACK Track TUI

Provides visual feedback for long-running operations:
1. Spinner - Animated spinner with message
2. ProgressBar - Progress bar with percentage
3. TimeCounter - Elapsed time tracking

All components are thread-safe and support graceful cancellation (Ctrl+C).
"""

import threading
import time
from typing import Optional
from rich.console import Console
from rich.spinner import Spinner as RichSpinner
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn, TimeElapsedColumn
from rich.live import Live


class Spinner:
    """Animated spinner for indefinite operations

    Thread-safe spinner that runs in background with custom message.
    Supports graceful stop and Ctrl+C handling.

    Example:
        spinner = Spinner()
        spinner.start("Loading data...")
        # ... long operation ...
        spinner.stop()
    """

    def __init__(self, console: Optional[Console] = None):
        """Initialize spinner

        Args:
            console: Rich Console instance (creates new if None)
        """
        self.console = console or Console()
        self._live: Optional[Live] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_flag = threading.Event()
        self._message = ""

    def start(self, message: str = "Loading...") -> None:
        """Start animated spinner

        Args:
            message: Message to display next to spinner
        """
        if self._thread and self._thread.is_alive():
            return  # Already running

        self._message = message
        self._stop_flag.clear()

        # Create Rich spinner with custom frames: ⣾ ⣽ ⣻ ⢿ ⡿ ⣟ ⣯ ⣷
        spinner = RichSpinner("dots2", text=self._message, style="cyan")
        self._live = Live(spinner, console=self.console, refresh_per_second=10)

        # Start in background thread
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        """Background thread runner"""
        try:
            self._live.start()
            while not self._stop_flag.is_set():
                time.sleep(0.1)
        except KeyboardInterrupt:
            pass  # Graceful Ctrl+C handling
        finally:
            if self._live:
                self._live.stop()

    def stop(self) -> None:
        """Stop spinner gracefully"""
        if self._thread and self._thread.is_alive():
            self._stop_flag.set()
            self._thread.join(timeout=1.0)

        if self._live:
            try:
                self._live.stop()
            except:
                pass  # Already stopped
            self._live = None

    def __enter__(self):
        """Context manager support"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager cleanup"""
        self.stop()


class ProgressBar:
    """Progress bar with percentage for definite operations

    Thread-safe progress bar that shows completion percentage and status message.
    Supports graceful cancellation and automatic cleanup.

    Example:
        progress = ProgressBar()
        progress.start(total=100, message="Processing files...")
        for i in range(100):
            progress.update(i + 1, message=f"Processing file {i+1}")
        progress.finish()
    """

    def __init__(self, console: Optional[Console] = None):
        """Initialize progress bar

        Args:
            console: Rich Console instance (creates new if None)
        """
        self.console = console or Console()
        self._progress: Optional[Progress] = None
        self._task_id: Optional[int] = None
        self._total: int = 100
        self._live: Optional[Live] = None
        self._lock = threading.Lock()

    def start(self, total: int = 100, message: str = "Processing...") -> None:
        """Start progress bar

        Args:
            total: Total number of items/steps
            message: Initial status message
        """
        with self._lock:
            if self._progress:
                return  # Already running

            # Create Rich progress bar with columns
            self._progress = Progress(
                SpinnerColumn(),
                TextColumn("[bold cyan]{task.description}[/]"),
                BarColumn(complete_style="green", finished_style="green"),
                TaskProgressColumn(),
                TimeElapsedColumn(),
                console=self.console
            )

            self._total = total
            self._task_id = self._progress.add_task(message, total=total)

            # Start live display
            self._live = Live(self._progress, console=self.console, refresh_per_second=10)
            self._live.start()

    def update(self, current: int, message: Optional[str] = None) -> None:
        """Update progress bar

        Args:
            current: Current progress value (0 to total)
            message: Optional status message to display
        """
        with self._lock:
            if not self._progress or self._task_id is None:
                return

            # Update progress
            self._progress.update(
                self._task_id,
                completed=current,
                description=message if message else self._progress.tasks[self._task_id].description
            )

    def finish(self, message: str = "Complete") -> None:
        """Complete and close progress bar

        Args:
            message: Final completion message
        """
        with self._lock:
            if self._progress and self._task_id is not None:
                self._progress.update(self._task_id, completed=self._total, description=message)

            if self._live:
                time.sleep(0.5)  # Brief pause to show completion
                try:
                    self._live.stop()
                except:
                    pass
                self._live = None

            self._progress = None
            self._task_id = None

    def __enter__(self):
        """Context manager support"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager cleanup"""
        if exc_type is KeyboardInterrupt:
            self.finish(message="Cancelled")
        else:
            self.finish()


class TimeCounter:
    """Elapsed time counter for operation tracking

    Simple time tracker that records start time and provides formatted elapsed duration.
    Thread-safe with accurate timing even under load.

    Example:
        counter = TimeCounter()
        counter.start()
        # ... long operation ...
        print(f"Elapsed: {counter.elapsed()}")  # Output: "02:35"
    """

    def __init__(self):
        """Initialize time counter"""
        self._start_time: Optional[float] = None
        self._lock = threading.Lock()

    def start(self) -> None:
        """Begin timing"""
        with self._lock:
            self._start_time = time.time()

    def elapsed(self) -> str:
        """Get formatted elapsed time

        Returns:
            Formatted time string in MM:SS format (e.g., "02:35")
        """
        with self._lock:
            if self._start_time is None:
                return "00:00"

            elapsed_seconds = time.time() - self._start_time
            minutes = int(elapsed_seconds // 60)
            seconds = int(elapsed_seconds % 60)

            return f"{minutes:02d}:{seconds:02d}"

    def elapsed_seconds(self) -> float:
        """Get raw elapsed time in seconds

        Returns:
            Elapsed time in seconds (0.0 if not started)
        """
        with self._lock:
            if self._start_time is None:
                return 0.0
            return time.time() - self._start_time

    def reset(self) -> None:
        """Reset counter to zero"""
        with self._lock:
            self._start_time = None

    def __enter__(self):
        """Context manager support"""
        self.start()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager cleanup - no action needed"""
        pass


class CancellationToken:
    """Thread-safe cancellation flag for long operations

    Provides a shared flag that can be checked by long-running operations
    to detect Ctrl+C or manual cancellation requests.

    Example:
        token = CancellationToken()

        def long_operation(token):
            for i in range(1000):
                if token.is_cancelled():
                    return "Cancelled"
                # ... do work ...
            return "Complete"

        try:
            result = long_operation(token)
        except KeyboardInterrupt:
            token.cancel()
            result = "Interrupted"
    """

    def __init__(self):
        """Initialize cancellation token"""
        self._cancelled = threading.Event()

    def cancel(self) -> None:
        """Set cancellation flag"""
        self._cancelled.set()

    def is_cancelled(self) -> bool:
        """Check if cancellation has been requested

        Returns:
            True if cancelled, False otherwise
        """
        return self._cancelled.is_set()

    def reset(self) -> None:
        """Clear cancellation flag"""
        self._cancelled.clear()


class LoadingIndicator:
    """Unified loading indicator with spinner and progress bar modes

    Provides a simple, unified interface for showing loading feedback.
    Automatically switches between spinner (indefinite) and progress bar (definite) modes.

    Features:
    - Animated spinner with custom frames: ⣾ ⣽ ⣻ ⢿ ⡿ ⣟ ⣯ ⣷
    - Progress bar format: [████████░░] 80% - Message...
    - Time elapsed counter
    - Thread-safe updates from background threads
    - Context manager support
    - Graceful Ctrl+C cancellation

    Example (Spinner):
        with LoadingIndicator.spinner("Scanning ports...") as loader:
            # long operation
            loader.update("Found 5 open ports...")

    Example (Progress):
        with LoadingIndicator.progress(100, "Processing files...") as loader:
            for i in range(100):
                loader.update(i + 1, f"Processing file {i+1}")
    """

    def __init__(self, console: Optional[Console] = None):
        """Initialize loading indicator

        Args:
            console: Rich Console instance (creates new if None)
        """
        self.console = console or Console()
        self._mode: Optional[str] = None  # 'spinner' or 'progress'
        self._spinner: Optional[Spinner] = None
        self._progress_bar: Optional[ProgressBar] = None
        self._time_counter = TimeCounter()

    @classmethod
    def spinner(cls, message: str = "Loading...", console: Optional[Console] = None) -> 'LoadingIndicator':
        """Create spinner mode loading indicator

        Args:
            message: Message to display next to spinner
            console: Optional Rich Console instance

        Returns:
            LoadingIndicator instance in spinner mode
        """
        loader = cls(console=console)
        loader.show_spinner(message)
        return loader

    @classmethod
    def progress(cls, total: int = 100, message: str = "Processing...", console: Optional[Console] = None) -> 'LoadingIndicator':
        """Create progress bar mode loading indicator

        Args:
            total: Total number of items/steps
            message: Initial status message
            console: Optional Rich Console instance

        Returns:
            LoadingIndicator instance in progress bar mode
        """
        loader = cls(console=console)
        loader.show_progress(total, message)
        return loader

    def show_spinner(self, message: str = "Loading...") -> None:
        """Start animated spinner

        Args:
            message: Message to display next to spinner
        """
        self.stop()  # Stop any existing indicator
        self._mode = 'spinner'
        self._spinner = Spinner(console=self.console)
        self._spinner.start(message)
        self._time_counter.start()

    def show_progress(self, total: int = 100, message: str = "Processing...") -> None:
        """Start progress bar

        Args:
            total: Total number of items/steps
            message: Initial status message
        """
        self.stop()  # Stop any existing indicator
        self._mode = 'progress'
        self._progress_bar = ProgressBar(console=self.console)
        self._progress_bar.start(total=total, message=message)
        self._time_counter.start()

    def update(self, current: Optional[int] = None, message: Optional[str] = None) -> None:
        """Update loading indicator

        Args:
            current: Current progress value (only for progress bar mode)
            message: Updated message to display

        Examples:
            # Spinner mode - update message only
            loader.update(message="Found 5 ports...")

            # Progress bar mode - update progress and message
            loader.update(50, "Processing item 50/100...")
        """
        if self._mode == 'spinner' and self._spinner:
            # Spinner mode - restart with new message if provided
            if message:
                self._spinner.stop()
                self._spinner.start(message)

        elif self._mode == 'progress' and self._progress_bar:
            # Progress bar mode - update current value and/or message
            if current is not None:
                self._progress_bar.update(current, message)
            elif message:
                # Update message only (keep current progress)
                self._progress_bar.update(0, message)

    def stop(self) -> None:
        """Stop and clean up loading indicator"""
        if self._spinner:
            self._spinner.stop()
            self._spinner = None

        if self._progress_bar:
            self._progress_bar.finish()
            self._progress_bar = None

        self._mode = None

    def elapsed(self) -> str:
        """Get elapsed time since start

        Returns:
            Formatted time string (MM:SS)
        """
        return self._time_counter.elapsed()

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - clean up and handle cancellation"""
        if exc_type is KeyboardInterrupt:
            # Graceful Ctrl+C handling
            if self._mode == 'progress' and self._progress_bar:
                self._progress_bar.finish(message="Cancelled")
            else:
                self.stop()
        else:
            self.stop()
