#!/usr/bin/env python3
"""
Clear test checkpoints for 192.168.1.100
Run this to reset before testing again
"""

from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from track.interactive.state.checkpoint_manager import CheckpointManager

def main():
    mgr = CheckpointManager()
    target = "192.168.1.100"

    print(f"Checking checkpoints for target: {target}\n")

    checkpoints = mgr.list_checkpoints(target)

    if not checkpoints:
        print("✓ No checkpoints found. Nothing to clear.")
        return

    print(f"Found {len(checkpoints)} checkpoint(s):")
    for cp in checkpoints:
        print(f"  • {cp['task_id']}/{cp['stage_id']} - {cp['status']}")

    print()
    response = input("Clear all checkpoints? [Y/n]: ").strip()

    if not response or response.lower() == 'y':
        count = mgr.clear_all_checkpoints(target)
        print(f"\n✓ Cleared {count} checkpoint(s)")
    else:
        print("Cancelled. No checkpoints cleared.")

if __name__ == "__main__":
    main()
