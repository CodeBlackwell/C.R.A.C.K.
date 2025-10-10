"""
Checkpoint Manager for crash recovery and state persistence during multi-stage task execution

Provides crash recovery for long-running tasks by saving intermediate state checkpoints.
Checkpoints are stored in ~/.crack/checkpoints/ and auto-expire after 7 days.

Example:
    mgr = CheckpointManager()

    # Save checkpoint during task execution
    mgr.save_checkpoint(
        task_id="gobuster-80",
        stage_id="directory-scan",
        state_data={
            "command": "gobuster dir -u http://target -w wordlist.txt",
            "partial_output": "Found: /admin\nFound: /backup\n...",
            "status": "running",
            "lines_processed": 1500
        }
    )

    # Detect interrupted sessions on startup
    interrupted = mgr.detect_interrupted_session("192.168.45.100")
    if interrupted:
        # Offer user resume option
        state = mgr.load_checkpoint(interrupted[0]['task_id'], interrupted[0]['stage_id'])

    # Clear checkpoint when task completes
    mgr.clear_checkpoint("gobuster-80", "directory-scan")
"""

import json
import os
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional


class CheckpointManager:
    """Manage execution checkpoints for crash recovery and state persistence"""

    DEFAULT_DIR = Path.home() / ".crack" / "checkpoints"
    CHECKPOINT_EXPIRY_DAYS = 7

    # Schema version for backward compatibility
    SCHEMA_VERSION = 1

    # File lock for thread-safe operations
    _lock = threading.Lock()

    def __init__(self):
        """Initialize checkpoint manager and ensure directory exists"""
        self._ensure_directory()

    @classmethod
    def _ensure_directory(cls):
        """Create checkpoint directory if it doesn't exist"""
        cls.DEFAULT_DIR.mkdir(parents=True, exist_ok=True)

    @classmethod
    def _get_checkpoint_path(cls, target: str, task_id: str, stage_id: str) -> Path:
        """Get path to checkpoint file

        Args:
            target: Target IP or hostname
            task_id: Task identifier (e.g., 'gobuster-80')
            stage_id: Stage identifier (e.g., 'directory-scan')

        Returns:
            Path to checkpoint JSON file
        """
        cls._ensure_directory()
        # Sanitize components for safe filename
        safe_target = target.replace('/', '_').replace(':', '_').replace('.', '_')
        safe_task = task_id.replace('/', '_').replace(':', '_')
        safe_stage = stage_id.replace('/', '_').replace(':', '_')

        filename = f"{safe_target}_{safe_task}_{safe_stage}.json"
        return cls.DEFAULT_DIR / filename

    @classmethod
    def _sanitize_filename_component(cls, component: str) -> str:
        """Sanitize a string for use in filename

        Args:
            component: String to sanitize

        Returns:
            Safe string for filename
        """
        return component.replace('/', '_').replace(':', '_').replace('.', '_')

    def save_checkpoint(
        self,
        task_id: str,
        stage_id: str,
        state_data: Dict[str, Any],
        target: Optional[str] = None
    ) -> bool:
        """Save execution checkpoint

        Args:
            task_id: Task identifier (e.g., 'gobuster-80')
            stage_id: Stage identifier (e.g., 'directory-scan')
            state_data: State data dictionary containing:
                - command: str - Command being executed
                - partial_output: str - Output captured so far
                - status: str - Current status (running, paused, error)
                - metadata: Dict - Additional metadata (optional)
            target: Target IP/hostname (extracted from state_data if not provided)

        Returns:
            True if save successful, False otherwise

        Example:
            mgr.save_checkpoint(
                task_id="gobuster-80",
                stage_id="stage-1",
                state_data={
                    "command": "gobuster dir -u http://target -w wordlist.txt",
                    "partial_output": "Found: /admin\\n",
                    "status": "running",
                    "metadata": {"target": "192.168.45.100"}
                }
            )
        """
        # Extract target from state_data if not provided
        if not target:
            if 'metadata' in state_data and 'target' in state_data['metadata']:
                target = state_data['metadata']['target']
            else:
                raise ValueError("Target must be provided or present in state_data['metadata']['target']")

        # Validate required fields
        if not self.validate_checkpoint(state_data):
            return False

        # Build checkpoint structure
        checkpoint = {
            'schema_version': self.SCHEMA_VERSION,
            'timestamp': datetime.now().isoformat(),
            'target': target,
            'task_id': task_id,
            'stage_id': stage_id,
            'state': state_data
        }

        # Thread-safe write
        with self._lock:
            try:
                path = self._get_checkpoint_path(target, task_id, stage_id)
                with open(path, 'w') as f:
                    json.dump(checkpoint, f, indent=2)
                return True
            except (IOError, OSError) as e:
                # Graceful failure - log but don't crash
                print(f"Warning: Failed to save checkpoint: {e}")
                return False

    def load_checkpoint(
        self,
        task_id: str,
        stage_id: str,
        target: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """Load execution checkpoint

        Args:
            task_id: Task identifier
            stage_id: Stage identifier
            target: Target IP/hostname (required for lookup)

        Returns:
            Checkpoint data dictionary or None if not found/corrupted

        Example:
            state = mgr.load_checkpoint("gobuster-80", "stage-1", "192.168.45.100")
            if state:
                command = state['command']
                output = state['partial_output']
        """
        if not target:
            raise ValueError("Target is required to load checkpoint")

        with self._lock:
            try:
                path = self._get_checkpoint_path(target, task_id, stage_id)
                if not path.exists():
                    return None

                with open(path, 'r') as f:
                    checkpoint = json.load(f)

                # Validate schema
                if checkpoint.get('schema_version') != self.SCHEMA_VERSION:
                    print(f"Warning: Checkpoint schema mismatch. Expected {self.SCHEMA_VERSION}, got {checkpoint.get('schema_version')}")
                    # Continue anyway for backward compatibility

                # Return state data only (not the wrapper)
                return checkpoint.get('state')

            except (IOError, OSError, json.JSONDecodeError) as e:
                # Corrupt checkpoint - handle gracefully
                print(f"Warning: Failed to load checkpoint (possibly corrupt): {e}")
                # Try to delete corrupt file
                try:
                    path.unlink()
                except Exception:
                    pass
                return None

    def detect_interrupted_session(self, target: str) -> List[Dict[str, str]]:
        """Detect incomplete checkpoints for a target (indicates crash/interruption)

        Args:
            target: Target IP or hostname

        Returns:
            List of interrupted checkpoint info dictionaries containing:
                - task_id: str
                - stage_id: str
                - timestamp: str
                - status: str

        Example:
            interrupted = mgr.detect_interrupted_session("192.168.45.100")
            if interrupted:
                print(f"Found {len(interrupted)} interrupted tasks")
                for task in interrupted:
                    print(f"  - {task['task_id']}/{task['stage_id']} from {task['timestamp']}")
        """
        self._ensure_directory()

        # Clean expired checkpoints first
        self._cleanup_expired_checkpoints()

        interrupted = []
        safe_target = self._sanitize_filename_component(target)

        with self._lock:
            try:
                # Find all checkpoints for this target
                pattern = f"{safe_target}_*.json"
                for path in self.DEFAULT_DIR.glob(pattern):
                    try:
                        with open(path, 'r') as f:
                            checkpoint = json.load(f)

                        # Extract info
                        interrupted.append({
                            'task_id': checkpoint.get('task_id', 'unknown'),
                            'stage_id': checkpoint.get('stage_id', 'unknown'),
                            'timestamp': checkpoint.get('timestamp', 'unknown'),
                            'status': checkpoint.get('state', {}).get('status', 'unknown')
                        })
                    except (IOError, json.JSONDecodeError):
                        # Skip corrupt checkpoints
                        continue

            except Exception as e:
                print(f"Warning: Error detecting interrupted sessions: {e}")

        # Sort by timestamp (most recent first)
        interrupted.sort(key=lambda x: x['timestamp'], reverse=True)
        return interrupted

    def validate_checkpoint(self, data: Dict[str, Any]) -> bool:
        """Validate checkpoint data schema

        Args:
            data: State data dictionary

        Returns:
            True if valid, False otherwise

        Required fields:
            - command: str
            - status: str (one of: running, paused, error, completed)

        Optional fields:
            - partial_output: str
            - metadata: Dict
        """
        # Required fields
        if 'command' not in data:
            print("Warning: Checkpoint missing 'command' field")
            return False

        if 'status' not in data:
            print("Warning: Checkpoint missing 'status' field")
            return False

        # Validate status value
        valid_statuses = ['running', 'paused', 'error', 'completed']
        if data['status'] not in valid_statuses:
            print(f"Warning: Invalid status '{data['status']}'. Must be one of: {valid_statuses}")
            return False

        return True

    def clear_checkpoint(
        self,
        task_id: str,
        stage_id: str,
        target: Optional[str] = None
    ) -> bool:
        """Remove completed checkpoint

        Args:
            task_id: Task identifier
            stage_id: Stage identifier
            target: Target IP/hostname (required)

        Returns:
            True if removed successfully, False if not found or error

        Example:
            mgr.clear_checkpoint("gobuster-80", "stage-1", "192.168.45.100")
        """
        if not target:
            raise ValueError("Target is required to clear checkpoint")

        with self._lock:
            try:
                path = self._get_checkpoint_path(target, task_id, stage_id)
                if path.exists():
                    path.unlink()
                    return True
                return False
            except (IOError, OSError) as e:
                print(f"Warning: Failed to clear checkpoint: {e}")
                return False

    def list_checkpoints(self, target: str) -> List[Dict[str, Any]]:
        """Get all checkpoints for a target

        Args:
            target: Target IP or hostname

        Returns:
            List of checkpoint summary dictionaries containing:
                - task_id: str
                - stage_id: str
                - timestamp: str
                - status: str
                - command: str (truncated to 80 chars)

        Example:
            checkpoints = mgr.list_checkpoints("192.168.45.100")
            for cp in checkpoints:
                print(f"{cp['task_id']}/{cp['stage_id']}: {cp['status']} - {cp['command']}")
        """
        self._ensure_directory()

        # Clean expired first
        self._cleanup_expired_checkpoints()

        checkpoints = []
        safe_target = self._sanitize_filename_component(target)

        with self._lock:
            try:
                pattern = f"{safe_target}_*.json"
                for path in self.DEFAULT_DIR.glob(pattern):
                    try:
                        with open(path, 'r') as f:
                            checkpoint = json.load(f)

                        state = checkpoint.get('state', {})
                        command = state.get('command', 'N/A')

                        # Truncate long commands
                        if len(command) > 80:
                            command = command[:77] + '...'

                        checkpoints.append({
                            'task_id': checkpoint.get('task_id', 'unknown'),
                            'stage_id': checkpoint.get('stage_id', 'unknown'),
                            'timestamp': checkpoint.get('timestamp', 'unknown'),
                            'status': state.get('status', 'unknown'),
                            'command': command
                        })
                    except (IOError, json.JSONDecodeError):
                        # Skip corrupt checkpoints
                        continue

            except Exception as e:
                print(f"Warning: Error listing checkpoints: {e}")

        # Sort by timestamp (most recent first)
        checkpoints.sort(key=lambda x: x['timestamp'], reverse=True)
        return checkpoints

    def _cleanup_expired_checkpoints(self):
        """Remove checkpoints older than CHECKPOINT_EXPIRY_DAYS

        Internal method called automatically by detect_interrupted_session()
        and list_checkpoints() to maintain checkpoint directory.
        """
        self._ensure_directory()

        cutoff_date = datetime.now() - timedelta(days=self.CHECKPOINT_EXPIRY_DAYS)

        try:
            for path in self.DEFAULT_DIR.glob("*.json"):
                try:
                    with open(path, 'r') as f:
                        checkpoint = json.load(f)

                    # Parse timestamp
                    timestamp_str = checkpoint.get('timestamp')
                    if not timestamp_str:
                        # No timestamp - delete it
                        path.unlink()
                        continue

                    checkpoint_time = datetime.fromisoformat(timestamp_str)

                    # Delete if expired
                    if checkpoint_time < cutoff_date:
                        path.unlink()

                except (IOError, json.JSONDecodeError, ValueError):
                    # Corrupt or invalid - delete it
                    try:
                        path.unlink()
                    except Exception:
                        pass

        except Exception as e:
            # Non-fatal - just log warning
            print(f"Warning: Error during checkpoint cleanup: {e}")

    def clear_all_checkpoints(self, target: str) -> int:
        """Clear all checkpoints for a target

        Args:
            target: Target IP or hostname

        Returns:
            Number of checkpoints cleared

        Example:
            count = mgr.clear_all_checkpoints("192.168.45.100")
            print(f"Cleared {count} checkpoints")
        """
        self._ensure_directory()

        count = 0
        safe_target = self._sanitize_filename_component(target)

        with self._lock:
            try:
                pattern = f"{safe_target}_*.json"
                for path in self.DEFAULT_DIR.glob(pattern):
                    try:
                        path.unlink()
                        count += 1
                    except (IOError, OSError):
                        continue
            except Exception as e:
                print(f"Warning: Error clearing checkpoints: {e}")

        return count
