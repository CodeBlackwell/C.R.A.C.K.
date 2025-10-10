#!/usr/bin/env python3
"""
Loading Indicator Demo - CRACK Track TUI

Demonstrates all loading indicator features:
- Animated spinner with custom frames
- Progress bar with percentage
- Time elapsed tracking
- Thread-safe updates
- Context manager support
- Graceful cancellation

Usage:
    python3 -m track.interactive.components.loading_indicator_demo
"""

import time
from crack.track.interactive.components.loading_indicator import (
    LoadingIndicator,
    Spinner,
    ProgressBar,
    TimeCounter,
    CancellationToken
)


def demo_spinner():
    """Demo 1: Animated spinner for indefinite operations"""
    print("\n" + "=" * 70)
    print("DEMO 1: Spinner (Indefinite Operation)")
    print("=" * 70)
    print("Custom frames: ⣾ ⣽ ⣻ ⢿ ⡿ ⣟ ⣯ ⣷\n")

    with LoadingIndicator.spinner("Initializing...") as loader:
        time.sleep(1.5)

        loader.update(message="Loading configuration...")
        time.sleep(1.5)

        loader.update(message="Connecting to target...")
        time.sleep(1.5)

        loader.update(message="Finalizing setup...")
        time.sleep(1.0)

    print("\n✓ Spinner demo complete\n")


def demo_progress_bar():
    """Demo 2: Progress bar for definite operations"""
    print("\n" + "=" * 70)
    print("DEMO 2: Progress Bar (Definite Operation)")
    print("=" * 70)
    print("Format: [████████░░] 80% - Message...\n")

    total = 50
    with LoadingIndicator.progress(total, "Scanning ports...") as loader:
        for i in range(total):
            time.sleep(0.05)

            if i % 10 == 0:
                loader.update(i + 1, f"Scanning port {i + 1}/{total}...")
            else:
                loader.update(i + 1)

    print("\n✓ Progress bar demo complete\n")


def demo_time_tracking():
    """Demo 3: Time elapsed counter"""
    print("\n" + "=" * 70)
    print("DEMO 3: Time Elapsed Counter")
    print("=" * 70)
    print("Tracks operation duration in MM:SS format\n")

    counter = TimeCounter()
    counter.start()

    with LoadingIndicator.spinner("Processing...") as loader:
        for i in range(5):
            time.sleep(0.6)
            elapsed = counter.elapsed()
            loader.update(message=f"Processing... (elapsed: {elapsed})")

    elapsed = counter.elapsed()
    print(f"\n✓ Time tracking demo complete (Total: {elapsed})\n")


def demo_cancellation():
    """Demo 4: Graceful cancellation with token"""
    print("\n" + "=" * 70)
    print("DEMO 4: Cancellation Support")
    print("=" * 70)
    print("Press Ctrl+C to cancel (gracefully handled)\n")

    token = CancellationToken()

    try:
        with LoadingIndicator.progress(100, "Long operation...") as loader:
            for i in range(100):
                if token.is_cancelled():
                    loader.update(i, "Cancelled by user")
                    break

                time.sleep(0.05)
                loader.update(i + 1, f"Processing item {i + 1}/100...")

    except KeyboardInterrupt:
        token.cancel()
        print("\n✓ Cancellation handled gracefully\n")
    else:
        print("\n✓ Completed without cancellation\n")


def demo_mode_switching():
    """Demo 5: Switching between spinner and progress"""
    print("\n" + "=" * 70)
    print("DEMO 5: Mode Switching")
    print("=" * 70)
    print("Dynamically switch between spinner and progress bar\n")

    loader = LoadingIndicator()

    # Phase 1: Unknown duration (spinner)
    loader.show_spinner("Initializing scan...")
    time.sleep(1.5)

    # Phase 2: Known duration (progress)
    loader.show_progress(20, "Scanning 20 targets...")
    for i in range(20):
        time.sleep(0.08)
        loader.update(i + 1, f"Target {i + 1}/20")

    # Phase 3: Unknown duration (spinner)
    loader.show_spinner("Analyzing results...")
    time.sleep(1.5)

    # Phase 4: Known duration (progress)
    loader.show_progress(10, "Generating report...")
    for i in range(10):
        time.sleep(0.1)
        loader.update(i + 1, f"Section {i + 1}/10")

    loader.stop()
    print("\n✓ Mode switching demo complete\n")


def demo_thread_safety():
    """Demo 6: Thread-safe updates from background"""
    print("\n" + "=" * 70)
    print("DEMO 6: Thread-Safe Updates")
    print("=" * 70)
    print("Updates from background threads work safely\n")

    import threading

    results = {'count': 0}

    def background_work(loader, results):
        """Simulate background processing"""
        for i in range(30):
            time.sleep(0.1)
            results['count'] = i + 1
            loader.update(i + 1, f"Background task {i + 1}/30")

    with LoadingIndicator.progress(30, "Background processing...") as loader:
        thread = threading.Thread(target=background_work, args=(loader, results))
        thread.start()
        thread.join()

    print(f"\n✓ Thread-safe demo complete (processed {results['count']} items)\n")


def demo_real_world_scenario():
    """Demo 7: Real-world port scanning simulation"""
    print("\n" + "=" * 70)
    print("DEMO 7: Real-World Scenario - Port Scanning")
    print("=" * 70)
    print("Simulates actual pentesting workflow\n")

    ports_to_scan = list(range(1, 1001))
    open_ports = []

    with LoadingIndicator.progress(len(ports_to_scan), "Scanning ports...") as loader:
        for i, port in enumerate(ports_to_scan):
            time.sleep(0.003)  # Simulate scan time

            # Simulate finding open ports
            if port in [22, 80, 443, 8080, 3306]:
                open_ports.append(port)
                loader.update(i + 1, f"[OPEN] Port {port}/tcp")
            else:
                if i % 50 == 0:  # Update message every 50 ports
                    loader.update(i + 1, f"Scanned {i + 1}/{len(ports_to_scan)} ports...")
                else:
                    loader.update(i + 1)

    print(f"\n✓ Scan complete: Found {len(open_ports)} open ports: {open_ports}\n")


def main():
    """Run all demos"""
    print("\n" + "=" * 70)
    print("CRACK Track Loading Indicator - Component Demo")
    print("=" * 70)
    print("\nDemonstrating all features of the loading indicator system...")

    try:
        demo_spinner()
        time.sleep(0.5)

        demo_progress_bar()
        time.sleep(0.5)

        demo_time_tracking()
        time.sleep(0.5)

        demo_mode_switching()
        time.sleep(0.5)

        demo_thread_safety()
        time.sleep(0.5)

        demo_real_world_scenario()
        time.sleep(0.5)

        # Cancellation demo last (user can skip)
        print("Final demo: Cancellation (optional - press Ctrl+C to test)")
        time.sleep(1.5)
        demo_cancellation()

    except KeyboardInterrupt:
        print("\n\n✗ Demo interrupted by user (Ctrl+C)\n")
        return

    print("\n" + "=" * 70)
    print("All demos complete!")
    print("=" * 70)
    print("\nKey Features Demonstrated:")
    print("  ✓ Animated spinner with custom frames (⣾ ⣽ ⣻ ⢿ ⡿ ⣟ ⣯ ⣷)")
    print("  ✓ Progress bar with percentage tracking")
    print("  ✓ Time elapsed counter (MM:SS format)")
    print("  ✓ Thread-safe updates from background threads")
    print("  ✓ Context manager support (auto-cleanup)")
    print("  ✓ Graceful cancellation (Ctrl+C handling)")
    print("  ✓ Dynamic mode switching (spinner ↔ progress)")
    print("  ✓ Real-world pentesting scenarios")
    print("\nComponent is ready for TUI integration!\n")


if __name__ == '__main__':
    main()
