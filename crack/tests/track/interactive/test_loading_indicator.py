"""
Tests for Loading Indicator Components

Validates all loading indicator functionality:
- Spinner animation
- Progress bar updates
- Time counter tracking
- Thread safety
- Context manager support
- Cancellation handling
"""

import time
import threading
import pytest
from unittest.mock import MagicMock, patch
from crack.track.interactive.components.loading_indicator import (
    Spinner,
    ProgressBar,
    TimeCounter,
    CancellationToken,
    LoadingIndicator
)


class TestSpinner:
    """Test Spinner component"""

    def test_spinner_start_stop(self):
        """Spinner should start and stop cleanly"""
        spinner = Spinner()
        spinner.start("Testing...")
        time.sleep(0.2)  # Let it animate
        spinner.stop()
        # No exception = success

    def test_spinner_context_manager(self):
        """Spinner should work as context manager"""
        with Spinner() as spinner:
            spinner.start("Loading...")
            time.sleep(0.1)
        # Auto-cleanup on exit

    def test_spinner_message_update(self):
        """Spinner should update message on restart"""
        spinner = Spinner()
        spinner.start("Message 1")
        time.sleep(0.1)
        spinner.stop()
        spinner.start("Message 2")
        time.sleep(0.1)
        spinner.stop()

    def test_spinner_double_start_ignored(self):
        """Starting already running spinner should be no-op"""
        spinner = Spinner()
        spinner.start("Message 1")
        time.sleep(0.1)
        spinner.start("Message 2")  # Should be ignored
        time.sleep(0.1)
        spinner.stop()

    def test_spinner_thread_safety(self):
        """Spinner should be thread-safe"""
        spinner = Spinner()
        spinner.start("Processing...")

        def update_from_thread():
            time.sleep(0.05)
            spinner.stop()

        thread = threading.Thread(target=update_from_thread)
        thread.start()
        thread.join(timeout=1.0)

        assert not thread.is_alive()


class TestProgressBar:
    """Test ProgressBar component"""

    def test_progress_bar_start_finish(self):
        """Progress bar should start and finish cleanly"""
        progress = ProgressBar()
        progress.start(total=10, message="Processing...")
        progress.update(5, "Halfway done...")
        progress.update(10, "Complete!")
        progress.finish()

    def test_progress_bar_context_manager(self):
        """Progress bar should work as context manager"""
        with ProgressBar() as progress:
            progress.start(total=5)
            for i in range(5):
                progress.update(i + 1)
                time.sleep(0.01)
        # Auto-finish on exit

    def test_progress_bar_percentage_calculation(self):
        """Progress bar should calculate percentage correctly"""
        progress = ProgressBar()
        progress.start(total=100, message="Testing...")

        # Update to 50%
        progress.update(50, "50% done")
        time.sleep(0.1)

        # Update to 100%
        progress.update(100, "100% done")
        time.sleep(0.1)

        progress.finish()

    def test_progress_bar_message_only_update(self):
        """Progress bar should support message-only updates"""
        progress = ProgressBar()
        progress.start(total=10, message="Starting...")

        progress.update(5, "Still processing...")
        progress.update(5, "Almost there...")  # Same progress, new message

        progress.finish()

    def test_progress_bar_thread_safety(self):
        """Progress bar should be thread-safe"""
        progress = ProgressBar()
        progress.start(total=100, message="Processing...")

        def update_from_thread(value):
            time.sleep(0.01)
            progress.update(value)

        threads = []
        for i in range(10):
            thread = threading.Thread(target=update_from_thread, args=(i * 10,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join(timeout=1.0)

        progress.finish()

        # All threads should complete
        assert all(not t.is_alive() for t in threads)

    def test_progress_bar_double_start_ignored(self):
        """Starting already running progress bar should be no-op"""
        progress = ProgressBar()
        progress.start(total=10)
        time.sleep(0.05)
        progress.start(total=20)  # Should be ignored
        progress.finish()


class TestTimeCounter:
    """Test TimeCounter component"""

    def test_time_counter_basic(self):
        """Time counter should track elapsed time"""
        counter = TimeCounter()
        counter.start()
        time.sleep(0.2)
        elapsed = counter.elapsed()

        # Should be "00:00" format
        assert ":" in elapsed
        parts = elapsed.split(":")
        assert len(parts) == 2
        assert parts[0].isdigit()
        assert parts[1].isdigit()

    def test_time_counter_elapsed_seconds(self):
        """Time counter should provide raw seconds"""
        counter = TimeCounter()
        counter.start()
        time.sleep(0.15)
        elapsed_secs = counter.elapsed_seconds()

        # Should be approximately 0.15 seconds
        assert 0.1 <= elapsed_secs <= 0.3

    def test_time_counter_reset(self):
        """Time counter should reset to zero"""
        counter = TimeCounter()
        counter.start()
        time.sleep(0.1)
        counter.reset()

        elapsed = counter.elapsed()
        assert elapsed == "00:00"

        elapsed_secs = counter.elapsed_seconds()
        assert elapsed_secs == 0.0

    def test_time_counter_context_manager(self):
        """Time counter should work as context manager"""
        with TimeCounter() as counter:
            time.sleep(1.1)  # Sleep long enough to register at least 1 second
            elapsed = counter.elapsed()
            assert elapsed != "00:00"
            assert ":" in elapsed  # Should be in MM:SS format

    def test_time_counter_format_accuracy(self):
        """Time counter should format minutes and seconds correctly"""
        counter = TimeCounter()
        counter.start()

        # Wait just over 1 second
        time.sleep(1.1)
        elapsed = counter.elapsed()

        # Should be "00:01" or "00:02" depending on timing
        minutes, seconds = elapsed.split(":")
        assert minutes == "00"
        assert seconds in ["01", "02"]


class TestCancellationToken:
    """Test CancellationToken component"""

    def test_cancellation_token_initial_state(self):
        """Cancellation token should start in non-cancelled state"""
        token = CancellationToken()
        assert not token.is_cancelled()

    def test_cancellation_token_cancel(self):
        """Cancellation token should detect cancellation"""
        token = CancellationToken()
        token.cancel()
        assert token.is_cancelled()

    def test_cancellation_token_reset(self):
        """Cancellation token should reset to non-cancelled"""
        token = CancellationToken()
        token.cancel()
        assert token.is_cancelled()

        token.reset()
        assert not token.is_cancelled()

    def test_cancellation_token_in_loop(self):
        """Cancellation token should stop long operations"""
        token = CancellationToken()

        iterations = 0
        for i in range(1000):
            if token.is_cancelled():
                break
            iterations += 1
            if i == 10:
                token.cancel()

        # Should stop around iteration 11
        assert iterations < 20

    def test_cancellation_token_thread_safety(self):
        """Cancellation token should be thread-safe"""
        token = CancellationToken()

        def worker():
            while not token.is_cancelled():
                time.sleep(0.01)

        thread = threading.Thread(target=worker)
        thread.start()

        time.sleep(0.05)
        token.cancel()

        thread.join(timeout=1.0)
        assert not thread.is_alive()


class TestLoadingIndicator:
    """Test unified LoadingIndicator class"""

    def test_loading_indicator_spinner_mode(self):
        """LoadingIndicator should work in spinner mode"""
        with LoadingIndicator.spinner("Loading...") as loader:
            time.sleep(0.1)
            loader.update(message="Still loading...")
            time.sleep(0.1)

    def test_loading_indicator_progress_mode(self):
        """LoadingIndicator should work in progress mode"""
        with LoadingIndicator.progress(10, "Processing...") as loader:
            for i in range(10):
                loader.update(i + 1, f"Item {i+1}/10")
                time.sleep(0.01)

    def test_loading_indicator_show_spinner(self):
        """LoadingIndicator.show_spinner should start spinner"""
        loader = LoadingIndicator()
        loader.show_spinner("Testing...")
        time.sleep(0.1)
        loader.stop()

    def test_loading_indicator_show_progress(self):
        """LoadingIndicator.show_progress should start progress bar"""
        loader = LoadingIndicator()
        loader.show_progress(100, "Processing...")
        loader.update(50, "Halfway...")
        loader.update(100, "Done!")
        loader.stop()

    def test_loading_indicator_mode_switch(self):
        """LoadingIndicator should switch between modes cleanly"""
        loader = LoadingIndicator()

        # Start with spinner
        loader.show_spinner("Loading...")
        time.sleep(0.05)

        # Switch to progress
        loader.show_progress(10, "Processing...")
        loader.update(5)
        time.sleep(0.05)

        # Switch back to spinner
        loader.show_spinner("Finalizing...")
        time.sleep(0.05)

        loader.stop()

    def test_loading_indicator_elapsed_time(self):
        """LoadingIndicator should track elapsed time"""
        loader = LoadingIndicator()
        loader.show_spinner("Processing...")
        time.sleep(0.15)

        elapsed = loader.elapsed()
        assert ":" in elapsed

        loader.stop()

    def test_loading_indicator_context_manager_keyboard_interrupt(self):
        """LoadingIndicator should handle Ctrl+C gracefully"""
        loader = LoadingIndicator()

        # Simulate KeyboardInterrupt in context manager
        try:
            with loader:
                loader.show_progress(10, "Processing...")
                loader.update(5)
                raise KeyboardInterrupt()
        except KeyboardInterrupt:
            pass  # Expected

        # Should clean up automatically

    def test_loading_indicator_update_spinner_message(self):
        """LoadingIndicator should update spinner message"""
        loader = LoadingIndicator()
        loader.show_spinner("Message 1")
        time.sleep(0.05)

        loader.update(message="Message 2")
        time.sleep(0.05)

        loader.update(message="Message 3")
        time.sleep(0.05)

        loader.stop()

    def test_loading_indicator_update_progress_value(self):
        """LoadingIndicator should update progress value and message"""
        loader = LoadingIndicator()
        loader.show_progress(100, "Starting...")

        loader.update(25, "25% complete")
        loader.update(50, "50% complete")
        loader.update(75, "75% complete")
        loader.update(100, "100% complete")

        loader.stop()

    def test_loading_indicator_classmethod_constructors(self):
        """LoadingIndicator class methods should create instances correctly"""
        # Test spinner constructor
        spinner_loader = LoadingIndicator.spinner("Test spinner")
        assert spinner_loader._mode == 'spinner'
        spinner_loader.stop()

        # Test progress constructor
        progress_loader = LoadingIndicator.progress(50, "Test progress")
        assert progress_loader._mode == 'progress'
        progress_loader.stop()


class TestIntegrationScenarios:
    """Test real-world usage scenarios"""

    def test_port_scanning_simulation(self):
        """Simulate port scanning with progress feedback"""
        # Scan specific port range that includes common ports
        ports_to_scan = list(range(1, 100)) + list(range(8000, 8100))
        total_ports = len(ports_to_scan)

        with LoadingIndicator.progress(total_ports, "Scanning ports...") as loader:
            open_ports = []

            for i, port in enumerate(ports_to_scan):
                # Simulate scanning (faster to avoid long test)
                time.sleep(0.001)

                # Simulate finding open port
                if port in [22, 80, 8080]:
                    open_ports.append(port)
                    loader.update(i + 1, f"Found port {port} open")
                else:
                    loader.update(i + 1, f"Scanning port {port}...")

        assert len(open_ports) == 3
        assert 22 in open_ports
        assert 80 in open_ports
        assert 8080 in open_ports

    def test_file_processing_simulation(self):
        """Simulate file processing with spinner feedback"""
        with LoadingIndicator.spinner("Processing files...") as loader:
            for i in range(5):
                time.sleep(0.02)
                loader.update(message=f"Processing file {i+1}/5...")

        # Should complete without errors

    def test_mixed_mode_workflow(self):
        """Test switching between spinner and progress during workflow"""
        loader = LoadingIndicator()

        # Step 1: Initial loading (unknown duration)
        loader.show_spinner("Initializing...")
        time.sleep(0.05)

        # Step 2: Processing with known count
        loader.show_progress(10, "Processing items...")
        for i in range(10):
            loader.update(i + 1, f"Item {i+1}/10")
            time.sleep(0.01)

        # Step 3: Final cleanup (unknown duration)
        loader.show_spinner("Cleaning up...")
        time.sleep(0.05)

        loader.stop()

    def test_cancellation_with_token(self):
        """Test cancellation token integration"""
        token = CancellationToken()

        with LoadingIndicator.progress(100, "Processing...") as loader:
            for i in range(100):
                if token.is_cancelled():
                    loader.update(i, "Cancelled!")
                    break

                loader.update(i + 1, f"Item {i+1}/100")
                time.sleep(0.01)

                # Simulate cancel after 20 items
                if i == 19:
                    token.cancel()

        assert token.is_cancelled()
