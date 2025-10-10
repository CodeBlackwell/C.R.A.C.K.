#!/usr/bin/env python3
"""
Error Handler Demo - Standalone demonstration of ErrorHandler component

Shows various error scenarios and how ErrorHandler displays them with
actionable suggestions.

Usage:
    python3 error_handler_demo.py
"""

import subprocess
from error_handler import ErrorHandler, ErrorType, CommonErrors


def demo_file_error():
    """Demo: File not found error"""
    print("\n" + "="*70)
    print("DEMO 1: File Not Found Error")
    print("="*70)

    handler = ErrorHandler()

    try:
        with open('/nonexistent/config.json', 'r') as f:
            pass
    except Exception as e:
        handler.handle_exception(e, context="loading configuration")

    input("\nPress Enter to continue...")


def demo_permission_error():
    """Demo: Permission denied error"""
    print("\n" + "="*70)
    print("DEMO 2: Permission Denied Error")
    print("="*70)

    handler = ErrorHandler()

    try:
        with open('/etc/shadow', 'w') as f:
            f.write('hack')
    except Exception as e:
        handler.handle_exception(e, context="attempting privileged file access")

    input("\nPress Enter to continue...")


def demo_network_error():
    """Demo: Network unreachable error (simulated)"""
    print("\n" + "="*70)
    print("DEMO 3: Network Unreachable Error")
    print("="*70)

    handler = ErrorHandler()

    # Simulate network error
    handler.show_error(
        ErrorType.NETWORK,
        "Network is unreachable when connecting to 192.168.45.100",
        None  # Use default suggestions
    )

    input("\nPress Enter to continue...")


def demo_oscp_nmap_error():
    """Demo: OSCP-specific nmap error"""
    print("\n" + "="*70)
    print("DEMO 4: OSCP-Specific Error (nmap not found)")
    print("="*70)

    handler = ErrorHandler()

    # Simulate nmap not found (OSCP pattern detection)
    handler.show_error(
        ErrorType.EXECUTION,
        "nmap: command not found",
        None  # Should auto-detect OSCP pattern
    )

    input("\nPress Enter to continue...")


def demo_oscp_permission_error():
    """Demo: OSCP raw socket permission error"""
    print("\n" + "="*70)
    print("DEMO 5: OSCP-Specific Error (raw socket permission)")
    print("="*70)

    handler = ErrorHandler()

    # Simulate raw socket permission denied (OSCP pattern)
    handler.show_error(
        ErrorType.PERMISSION,
        "raw socket operation not permitted - need root privileges",
        None  # Should auto-detect OSCP pattern
    )

    input("\nPress Enter to continue...")


def demo_oscp_vpn_error():
    """Demo: OSCP VPN connection error"""
    print("\n" + "="*70)
    print("DEMO 6: OSCP-Specific Error (VPN connection)")
    print("="*70)

    handler = ErrorHandler()

    # Simulate network unreachable (VPN issue)
    handler.show_error(
        ErrorType.NETWORK,
        "Network is unreachable: no route to host 192.168.45.100",
        None  # Should auto-detect OSCP pattern
    )

    input("\nPress Enter to continue...")


def demo_common_errors():
    """Demo: Using CommonErrors helper"""
    print("\n" + "="*70)
    print("DEMO 7: Using CommonErrors Helper Functions")
    print("="*70)

    handler = ErrorHandler()

    # File not found
    CommonErrors.file_not_found(handler, "/etc/nonexistent.conf")
    input("\nPress Enter for next error...")

    # Config corrupted
    CommonErrors.config_corrupted(handler)
    input("\nPress Enter for next error...")

    # Command not found
    CommonErrors.command_not_found(handler, "gobuster")

    input("\nPress Enter to continue...")


def demo_error_history():
    """Demo: Error history tracking"""
    print("\n" + "="*70)
    print("DEMO 8: Error History Tracking")
    print("="*70)

    handler = ErrorHandler(max_history=5)

    # Generate multiple errors
    print("\nGenerating 7 errors (max_history=5)...\n")

    for i in range(7):
        handler.show_error(
            ErrorType.EXECUTION,
            f"Simulated error #{i+1}",
            [f"This is suggestion for error {i+1}"]
        )

    print("\n" + "="*60)
    print("Error History (should only show last 5):")
    print("="*60)

    history = handler.get_error_history()
    for idx, error in enumerate(history, 1):
        print(f"{idx}. [{error['type']}] {error['message']} - {error['timestamp']}")

    print(f"\nTotal errors in history: {len(history)}")

    input("\nPress Enter to continue...")


def demo_categorize_auto():
    """Demo: Automatic error categorization"""
    print("\n" + "="*70)
    print("DEMO 9: Automatic Error Categorization")
    print("="*70)

    handler = ErrorHandler()

    # Various exception types
    errors = [
        FileNotFoundError("Config file not found"),
        PermissionError("Permission denied: /etc/shadow"),
        ValueError("Invalid input format"),
        subprocess.CalledProcessError(1, 'nmap', output='command failed'),
        ConnectionError("Network unreachable"),
    ]

    print("\nAuto-categorizing exceptions:\n")
    for exc in errors:
        error_type = handler.categorize_error(exc)
        print(f"{exc.__class__.__name__:30s} -> {error_type.name}")

    input("\nPress Enter to continue...")


def main():
    """Run all demos"""
    print("\n" + "="*70)
    print("  CRACK Track TUI - Error Handler Component Demo")
    print("="*70)
    print("\nThis demo showcases the ErrorHandler component's capabilities:")
    print("- Error categorization (FILE, PERMISSION, NETWORK, etc.)")
    print("- Actionable recovery suggestions")
    print("- OSCP-specific error patterns")
    print("- Error history tracking")
    print("- Rich Panel formatting")

    demos = [
        ("File Not Found", demo_file_error),
        ("Permission Denied", demo_permission_error),
        ("Network Unreachable", demo_network_error),
        ("OSCP: nmap not found", demo_oscp_nmap_error),
        ("OSCP: raw socket permission", demo_oscp_permission_error),
        ("OSCP: VPN connection", demo_oscp_vpn_error),
        ("CommonErrors helpers", demo_common_errors),
        ("Error history tracking", demo_error_history),
        ("Auto-categorization", demo_categorize_auto),
    ]

    while True:
        print("\n" + "="*70)
        print("Select a demo to run:")
        print("="*70)
        for idx, (name, _) in enumerate(demos, 1):
            print(f"  {idx}. {name}")
        print(f"  {len(demos)+1}. Run all demos")
        print("  0. Exit")

        choice = input("\nEnter choice: ").strip()

        if choice == '0':
            print("\nExiting demo. Goodbye!")
            break
        elif choice == str(len(demos) + 1):
            # Run all
            for name, demo_func in demos:
                demo_func()
            print("\n" + "="*70)
            print("All demos completed!")
            print("="*70)
            input("\nPress Enter to return to menu...")
        elif choice.isdigit() and 1 <= int(choice) <= len(demos):
            demos[int(choice) - 1][1]()
        else:
            print("[red]Invalid choice. Try again.[/]")


if __name__ == '__main__':
    main()
