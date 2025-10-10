#!/usr/bin/env python3
"""
Checkpoint Manager Usage Examples

Demonstrates checkpoint-based crash recovery for multi-stage task execution.
"""

import time
from crack.track.interactive.state.checkpoint_manager import CheckpointManager


def demo_basic_checkpoint():
    """Example 1: Basic checkpoint save and load"""
    print("=" * 60)
    print("DEMO 1: Basic Checkpoint Save/Load")
    print("=" * 60)

    mgr = CheckpointManager()

    # Simulate long-running task with checkpoint
    state_data = {
        'command': 'gobuster dir -u http://target -w wordlist.txt',
        'partial_output': 'Found: /admin\nFound: /backup\nScanning...\n',
        'status': 'running',
        'metadata': {
            'target': '192.168.45.100',
            'lines_processed': 1500,
            'started_at': time.time()
        }
    }

    print("\n1. Saving checkpoint for gobuster-80...")
    mgr.save_checkpoint(
        task_id='gobuster-80',
        stage_id='directory-scan',
        state_data=state_data,
        target='192.168.45.100'
    )
    print("   ✓ Checkpoint saved")

    print("\n2. Loading checkpoint...")
    loaded_state = mgr.load_checkpoint(
        task_id='gobuster-80',
        stage_id='directory-scan',
        target='192.168.45.100'
    )

    if loaded_state:
        print(f"   ✓ Loaded checkpoint")
        print(f"   Command: {loaded_state['command']}")
        print(f"   Status: {loaded_state['status']}")
        print(f"   Lines processed: {loaded_state['metadata']['lines_processed']}")

    print("\n3. Clearing checkpoint after task completes...")
    mgr.clear_checkpoint(
        task_id='gobuster-80',
        stage_id='directory-scan',
        target='192.168.45.100'
    )
    print("   ✓ Checkpoint cleared")


def demo_interrupted_session_detection():
    """Example 2: Detecting interrupted sessions on startup"""
    print("\n" + "=" * 60)
    print("DEMO 2: Interrupted Session Detection")
    print("=" * 60)

    mgr = CheckpointManager()

    # Simulate crash during multiple tasks
    print("\n1. Creating checkpoints for multiple tasks (simulating crash)...")

    tasks = [
        ('gobuster-80', 'directory-scan', 'gobuster dir -u http://target -w wordlist.txt'),
        ('nmap-443', 'ssl-scan', 'nmap --script ssl-enum-ciphers -p 443 target'),
        ('sqlmap-login', 'injection-test', 'sqlmap -u http://target/login.php --forms'),
    ]

    for task_id, stage_id, command in tasks:
        state_data = {
            'command': command,
            'partial_output': 'Running...\n',
            'status': 'running',
            'metadata': {'target': '192.168.45.200'}
        }
        mgr.save_checkpoint(task_id, stage_id, state_data, '192.168.45.200')
        print(f"   ✓ Saved checkpoint: {task_id}/{stage_id}")

    # Simulate application restart
    print("\n2. Application restarted. Checking for interrupted sessions...")
    interrupted = mgr.detect_interrupted_session('192.168.45.200')

    if interrupted:
        print(f"\n   Found {len(interrupted)} interrupted task(s):")
        for task in interrupted:
            print(f"   - {task['task_id']}/{task['stage_id']}")
            print(f"     Status: {task['status']}")
            print(f"     Timestamp: {task['timestamp']}")

    # Cleanup
    print("\n3. Clearing all interrupted checkpoints...")
    count = mgr.clear_all_checkpoints('192.168.45.200')
    print(f"   ✓ Cleared {count} checkpoint(s)")


def demo_checkpoint_validation():
    """Example 3: Checkpoint validation"""
    print("\n" + "=" * 60)
    print("DEMO 3: Checkpoint Validation")
    print("=" * 60)

    mgr = CheckpointManager()

    print("\n1. Valid checkpoint data:")
    valid_data = {
        'command': 'nmap -sV target',
        'status': 'running',
        'partial_output': 'Scanning...'
    }
    is_valid = mgr.validate_checkpoint(valid_data)
    print(f"   Result: {is_valid} ✓")

    print("\n2. Invalid checkpoint (missing 'command'):")
    invalid_data = {
        'status': 'running'
    }
    is_valid = mgr.validate_checkpoint(invalid_data)
    print(f"   Result: {is_valid} ✗")

    print("\n3. Invalid checkpoint (invalid status):")
    invalid_status = {
        'command': 'test',
        'status': 'invalid_status'
    }
    is_valid = mgr.validate_checkpoint(invalid_status)
    print(f"   Result: {is_valid} ✗")


def demo_listing_checkpoints():
    """Example 4: Listing all checkpoints for a target"""
    print("\n" + "=" * 60)
    print("DEMO 4: Listing Checkpoints")
    print("=" * 60)

    mgr = CheckpointManager()

    # Create multiple checkpoints
    print("\n1. Creating checkpoints for various tasks...")
    tasks = [
        ('gobuster-80', 'stage-1', 'gobuster dir -u http://target -w wordlist.txt', 'running'),
        ('nmap-scan', 'stage-1', 'nmap -sV -sC target -oA results', 'paused'),
        ('sqlmap-test', 'stage-2', 'sqlmap -u http://target/page.php?id=1 --batch', 'error'),
    ]

    for task_id, stage_id, command, status in tasks:
        state_data = {
            'command': command,
            'status': status,
            'metadata': {'target': '192.168.45.150'}
        }
        mgr.save_checkpoint(task_id, stage_id, state_data, '192.168.45.150')

    print("\n2. Listing all checkpoints for 192.168.45.150:")
    checkpoints = mgr.list_checkpoints('192.168.45.150')

    print(f"\n   Found {len(checkpoints)} checkpoint(s):\n")
    for cp in checkpoints:
        print(f"   Task: {cp['task_id']}/{cp['stage_id']}")
        print(f"   Status: {cp['status']}")
        print(f"   Command: {cp['command'][:60]}...")
        print(f"   Timestamp: {cp['timestamp']}")
        print()

    # Cleanup
    print("3. Cleaning up...")
    mgr.clear_all_checkpoints('192.168.45.150')
    print("   ✓ All checkpoints cleared")


def demo_multi_stage_task_execution():
    """Example 5: Multi-stage task with checkpoints"""
    print("\n" + "=" * 60)
    print("DEMO 5: Multi-Stage Task Execution with Checkpoints")
    print("=" * 60)

    mgr = CheckpointManager()
    target = '192.168.45.250'
    task_id = 'gobuster-80'

    stages = [
        ('stage-1', 'gobuster dir -u http://target -w common.txt'),
        ('stage-2', 'gobuster dir -u http://target/admin -w common.txt'),
        ('stage-3', 'gobuster dir -u http://target/backup -w extensions.txt'),
    ]

    print("\nSimulating multi-stage directory enumeration:")

    for stage_id, command in stages:
        print(f"\n  Stage: {stage_id}")
        print(f"  Command: {command}")

        # Save checkpoint at start of stage
        state_data = {
            'command': command,
            'status': 'running',
            'partial_output': '',
            'metadata': {'target': target}
        }
        mgr.save_checkpoint(task_id, stage_id, state_data, target)
        print(f"  ✓ Checkpoint saved")

        # Simulate work
        time.sleep(0.1)

        # Update checkpoint with progress
        state_data['partial_output'] = f'Found: /{stage_id}/admin\nFound: /{stage_id}/config\n'
        state_data['status'] = 'completed'
        mgr.save_checkpoint(task_id, stage_id, state_data, target)
        print(f"  ✓ Stage completed")

        # Clear checkpoint when stage completes
        mgr.clear_checkpoint(task_id, stage_id, target)
        print(f"  ✓ Checkpoint cleared")

    print("\n  All stages completed successfully!")


def main():
    """Run all demos"""
    print("\n╔══════════════════════════════════════════════════════════╗")
    print("║     CHECKPOINT MANAGER DEMONSTRATION                     ║")
    print("║     Crash Recovery for Multi-Stage Task Execution        ║")
    print("╚══════════════════════════════════════════════════════════╝")

    demo_basic_checkpoint()
    demo_interrupted_session_detection()
    demo_checkpoint_validation()
    demo_listing_checkpoints()
    demo_multi_stage_task_execution()

    print("\n" + "=" * 60)
    print("DEMOS COMPLETE")
    print("=" * 60)
    print("\nCheckpoint storage location: ~/.crack/checkpoints/")
    print("Checkpoints auto-expire after 7 days")


if __name__ == '__main__':
    main()
