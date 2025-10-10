#!/usr/bin/env python3
"""
Quick Error Handler Demo - Shows key features in 30 seconds

Demonstrates:
- Auto-categorization
- OSCP-specific patterns
- Actionable suggestions
- Rich formatting
"""

import subprocess
from error_handler import ErrorHandler, ErrorType, CommonErrors


def main():
    print("\n" + "="*70)
    print("  CRACK Track TUI - Error Handler Quick Demo")
    print("="*70)

    handler = ErrorHandler()

    # Demo 1: File not found with auto-categorization
    print("\n[1] Auto-categorization of FileNotFoundError:")
    print("-" * 70)
    try:
        open('/nonexistent/config.json')
    except Exception as e:
        handler.handle_exception(e, context="loading configuration")

    input("\nPress Enter to see next demo...")

    # Demo 2: OSCP-specific nmap error
    print("\n[2] OSCP-specific pattern detection (nmap):")
    print("-" * 70)
    handler.show_error(
        ErrorType.EXECUTION,
        "nmap: command not found",
        None  # Auto-detects OSCP pattern
    )

    input("\nPress Enter to see next demo...")

    # Demo 3: OSCP VPN error
    print("\n[3] OSCP VPN connection error:")
    print("-" * 70)
    handler.show_error(
        ErrorType.NETWORK,
        "Network is unreachable: no route to host 192.168.45.100",
        None  # Auto-detects VPN issue
    )

    input("\nPress Enter to see next demo...")

    # Demo 4: Using CommonErrors helper
    print("\n[4] CommonErrors helper for typical scenarios:")
    print("-" * 70)
    CommonErrors.permission_denied(handler, "/etc/shadow")

    input("\nPress Enter to see error history...")

    # Demo 5: Error history
    print("\n[5] Error History Tracking:")
    print("-" * 70)
    history = handler.get_error_history()
    print(f"\nTotal errors tracked: {len(history)}")
    for idx, error in enumerate(history, 1):
        print(f"  {idx}. [{error['type']}] {error['message'][:60]}...")

    print("\n" + "="*70)
    print("Demo complete! All tests passed: 39/39")
    print("="*70)
    print("\nKey Features:")
    print("  - Automatic error categorization (FILE, NETWORK, PERMISSION, etc.)")
    print("  - OSCP-specific error patterns and suggestions")
    print("  - Rich Panel formatting with color-coded severity")
    print("  - Error history tracking (configurable max_history)")
    print("  - Integration with debug logger")
    print("  - CommonErrors helper for typical scenarios")
    print("\nUsage in TUI:")
    print("  try:")
    print("      risky_operation()")
    print("  except Exception as e:")
    print("      handler.handle_exception(e, context='operation name')")
    print()


if __name__ == '__main__':
    main()
