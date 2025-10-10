#!/usr/bin/env python3
"""
Create test checkpoints for verifying checkpoint detection integration
Run this before testing: crack track --resume 192.168.1.100
"""

from pathlib import Path
import sys

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from track.interactive.state.checkpoint_manager import CheckpointManager
from datetime import datetime

def main():
    # Create checkpoint manager
    mgr = CheckpointManager()

    # Create test checkpoints for target 192.168.1.100
    target = "192.168.1.100"

    print(f"Creating test checkpoints for target: {target}")
    print(f"Checkpoint directory: {mgr.DEFAULT_DIR}\n")

    # Checkpoint 1: gobuster interrupted mid-execution
    print("Creating checkpoint 1: gobuster-80 (running)")
    mgr.save_checkpoint(
        task_id="gobuster-80",
        stage_id="directory-scan",
        state_data={
            "command": "gobuster dir -u http://192.168.1.100 -w /usr/share/wordlists/dirb/common.txt",
            "partial_output": "/admin (Status: 200)\n/backup (Status: 200)\n/config (Status: 403)\n",
            "status": "running",
            "metadata": {"target": target}
        },
        target=target
    )

    # Checkpoint 2: nikto paused
    print("Creating checkpoint 2: nikto-80 (paused)")
    mgr.save_checkpoint(
        task_id="nikto-80",
        stage_id="vulnerability-scan",
        state_data={
            "command": "nikto -h http://192.168.1.100 -port 80",
            "partial_output": "Nikto v2.1.6\n+ Target IP: 192.168.1.100\n+ Target Hostname: 192.168.1.100\n+ Target Port: 80\n",
            "status": "paused",
            "metadata": {"target": target}
        },
        target=target
    )

    # Checkpoint 3: enum4linux errored
    print("Creating checkpoint 3: enum4linux-445 (error)")
    mgr.save_checkpoint(
        task_id="enum4linux-445",
        stage_id="smb-enumeration",
        state_data={
            "command": "enum4linux -a 192.168.1.100",
            "partial_output": "Starting enum4linux v0.8.9\nConnection refused\n",
            "status": "error",
            "metadata": {"target": target}
        },
        target=target
    )

    print("\n" + "="*60)
    print("✓ Successfully created 3 test checkpoints")
    print("="*60)

    print("\nCheckpoints created:")
    for cp in mgr.list_checkpoints(target):
        print(f"  • {cp['task_id']}/{cp['stage_id']}")
        print(f"    Status: {cp['status']}")
        print(f"    Command: {cp['command']}")
        print(f"    Timestamp: {cp['timestamp']}")
        print()

    print("\n" + "="*60)
    print("Next step: Run the following command to test:")
    print("  crack track --resume 192.168.1.100")
    print("="*60)

if __name__ == "__main__":
    main()
