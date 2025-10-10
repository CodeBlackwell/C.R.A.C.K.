"""
Unit tests for CheckpointManager

Tests crash recovery, state persistence, validation, and cleanup functionality.
"""

import json
import os
import pytest
import tempfile
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from crack.track.interactive.state.checkpoint_manager import CheckpointManager


@pytest.fixture
def temp_checkpoint_dir():
    """Create temporary checkpoint directory for testing"""
    with tempfile.TemporaryDirectory() as tmpdir:
        temp_path = Path(tmpdir) / "checkpoints"
        temp_path.mkdir(parents=True, exist_ok=True)

        # Patch the DEFAULT_DIR
        with patch.object(CheckpointManager, 'DEFAULT_DIR', temp_path):
            yield temp_path


@pytest.fixture
def checkpoint_manager(temp_checkpoint_dir):
    """Create CheckpointManager instance with temp directory"""
    return CheckpointManager()


class TestCheckpointManagerBasics:
    """Test basic checkpoint operations"""

    def test_save_checkpoint_success(self, checkpoint_manager, temp_checkpoint_dir):
        """Test saving a valid checkpoint"""
        state_data = {
            'command': 'gobuster dir -u http://target -w wordlist.txt',
            'partial_output': 'Found: /admin\nFound: /backup\n',
            'status': 'running',
            'metadata': {'target': '192.168.45.100', 'lines_processed': 1500}
        }

        result = checkpoint_manager.save_checkpoint(
            task_id='gobuster-80',
            stage_id='directory-scan',
            state_data=state_data,
            target='192.168.45.100'
        )

        assert result is True

        # Verify file exists
        checkpoint_files = list(temp_checkpoint_dir.glob('*.json'))
        assert len(checkpoint_files) == 1

    def test_save_checkpoint_target_from_metadata(self, checkpoint_manager):
        """Test saving checkpoint with target extracted from metadata"""
        state_data = {
            'command': 'nmap -sV target',
            'status': 'running',
            'metadata': {'target': '192.168.45.200'}
        }

        result = checkpoint_manager.save_checkpoint(
            task_id='nmap-scan',
            stage_id='service-detection',
            state_data=state_data
        )

        assert result is True

    def test_save_checkpoint_missing_target(self, checkpoint_manager):
        """Test saving checkpoint without target raises error"""
        state_data = {
            'command': 'test command',
            'status': 'running'
        }

        with pytest.raises(ValueError, match='Target must be provided'):
            checkpoint_manager.save_checkpoint(
                task_id='test-task',
                stage_id='test-stage',
                state_data=state_data
            )

    def test_load_checkpoint_success(self, checkpoint_manager):
        """Test loading a saved checkpoint"""
        state_data = {
            'command': 'gobuster dir -u http://target -w wordlist.txt',
            'partial_output': 'Found: /admin\n',
            'status': 'running',
            'metadata': {'target': '192.168.45.100'}
        }

        checkpoint_manager.save_checkpoint(
            task_id='gobuster-80',
            stage_id='directory-scan',
            state_data=state_data,
            target='192.168.45.100'
        )

        loaded_state = checkpoint_manager.load_checkpoint(
            task_id='gobuster-80',
            stage_id='directory-scan',
            target='192.168.45.100'
        )

        assert loaded_state is not None
        assert loaded_state['command'] == state_data['command']
        assert loaded_state['partial_output'] == state_data['partial_output']
        assert loaded_state['status'] == 'running'
        assert loaded_state['metadata']['target'] == '192.168.45.100'

    def test_load_checkpoint_not_found(self, checkpoint_manager):
        """Test loading non-existent checkpoint returns None"""
        loaded_state = checkpoint_manager.load_checkpoint(
            task_id='nonexistent',
            stage_id='stage-1',
            target='192.168.45.100'
        )

        assert loaded_state is None

    def test_load_checkpoint_missing_target(self, checkpoint_manager):
        """Test loading checkpoint without target raises error"""
        with pytest.raises(ValueError, match='Target is required'):
            checkpoint_manager.load_checkpoint(
                task_id='test-task',
                stage_id='test-stage'
            )

    def test_clear_checkpoint_success(self, checkpoint_manager):
        """Test clearing a checkpoint"""
        state_data = {
            'command': 'test command',
            'status': 'running',
            'metadata': {'target': '192.168.45.100'}
        }

        checkpoint_manager.save_checkpoint(
            task_id='test-task',
            stage_id='test-stage',
            state_data=state_data,
            target='192.168.45.100'
        )

        result = checkpoint_manager.clear_checkpoint(
            task_id='test-task',
            stage_id='test-stage',
            target='192.168.45.100'
        )

        assert result is True

        # Verify it's gone
        loaded = checkpoint_manager.load_checkpoint(
            task_id='test-task',
            stage_id='test-stage',
            target='192.168.45.100'
        )
        assert loaded is None

    def test_clear_checkpoint_not_found(self, checkpoint_manager):
        """Test clearing non-existent checkpoint returns False"""
        result = checkpoint_manager.clear_checkpoint(
            task_id='nonexistent',
            stage_id='stage-1',
            target='192.168.45.100'
        )

        assert result is False


class TestCheckpointValidation:
    """Test checkpoint data validation"""

    def test_validate_checkpoint_valid(self, checkpoint_manager):
        """Test validation of valid checkpoint data"""
        state_data = {
            'command': 'gobuster dir -u http://target -w wordlist.txt',
            'status': 'running',
            'partial_output': 'Found: /admin\n',
            'metadata': {'target': '192.168.45.100'}
        }

        result = checkpoint_manager.validate_checkpoint(state_data)
        assert result is True

    def test_validate_checkpoint_minimal(self, checkpoint_manager):
        """Test validation with minimal required fields"""
        state_data = {
            'command': 'test command',
            'status': 'paused'
        }

        result = checkpoint_manager.validate_checkpoint(state_data)
        assert result is True

    def test_validate_checkpoint_missing_command(self, checkpoint_manager):
        """Test validation fails without command field"""
        state_data = {
            'status': 'running'
        }

        result = checkpoint_manager.validate_checkpoint(state_data)
        assert result is False

    def test_validate_checkpoint_missing_status(self, checkpoint_manager):
        """Test validation fails without status field"""
        state_data = {
            'command': 'test command'
        }

        result = checkpoint_manager.validate_checkpoint(state_data)
        assert result is False

    def test_validate_checkpoint_invalid_status(self, checkpoint_manager):
        """Test validation fails with invalid status value"""
        state_data = {
            'command': 'test command',
            'status': 'invalid_status'
        }

        result = checkpoint_manager.validate_checkpoint(state_data)
        assert result is False

    def test_validate_checkpoint_all_valid_statuses(self, checkpoint_manager):
        """Test all valid status values"""
        valid_statuses = ['running', 'paused', 'error', 'completed']

        for status in valid_statuses:
            state_data = {
                'command': 'test command',
                'status': status
            }
            result = checkpoint_manager.validate_checkpoint(state_data)
            assert result is True, f"Status '{status}' should be valid"


class TestInterruptedSessionDetection:
    """Test detection of interrupted sessions"""

    def test_detect_interrupted_session_single(self, checkpoint_manager):
        """Test detecting a single interrupted session"""
        state_data = {
            'command': 'gobuster dir -u http://target -w wordlist.txt',
            'status': 'running',
            'metadata': {'target': '192.168.45.100'}
        }

        checkpoint_manager.save_checkpoint(
            task_id='gobuster-80',
            stage_id='directory-scan',
            state_data=state_data,
            target='192.168.45.100'
        )

        interrupted = checkpoint_manager.detect_interrupted_session('192.168.45.100')

        assert len(interrupted) == 1
        assert interrupted[0]['task_id'] == 'gobuster-80'
        assert interrupted[0]['stage_id'] == 'directory-scan'
        assert interrupted[0]['status'] == 'running'
        assert 'timestamp' in interrupted[0]

    def test_detect_interrupted_session_multiple(self, checkpoint_manager):
        """Test detecting multiple interrupted sessions"""
        # Create multiple checkpoints for same target
        for i in range(3):
            state_data = {
                'command': f'command-{i}',
                'status': 'running',
                'metadata': {'target': '192.168.45.100'}
            }
            checkpoint_manager.save_checkpoint(
                task_id=f'task-{i}',
                stage_id=f'stage-{i}',
                state_data=state_data,
                target='192.168.45.100'
            )

        interrupted = checkpoint_manager.detect_interrupted_session('192.168.45.100')

        assert len(interrupted) == 3

    def test_detect_interrupted_session_none(self, checkpoint_manager):
        """Test no interrupted sessions for clean target"""
        interrupted = checkpoint_manager.detect_interrupted_session('192.168.45.200')

        assert len(interrupted) == 0

    def test_detect_interrupted_session_different_targets(self, checkpoint_manager):
        """Test interrupted sessions isolated by target"""
        # Create checkpoints for two targets
        state_data_1 = {
            'command': 'command-1',
            'status': 'running',
            'metadata': {'target': '192.168.45.100'}
        }
        checkpoint_manager.save_checkpoint(
            task_id='task-1',
            stage_id='stage-1',
            state_data=state_data_1,
            target='192.168.45.100'
        )

        state_data_2 = {
            'command': 'command-2',
            'status': 'running',
            'metadata': {'target': '192.168.45.200'}
        }
        checkpoint_manager.save_checkpoint(
            task_id='task-2',
            stage_id='stage-2',
            state_data=state_data_2,
            target='192.168.45.200'
        )

        # Check each target sees only its own
        interrupted_100 = checkpoint_manager.detect_interrupted_session('192.168.45.100')
        interrupted_200 = checkpoint_manager.detect_interrupted_session('192.168.45.200')

        assert len(interrupted_100) == 1
        assert interrupted_100[0]['task_id'] == 'task-1'

        assert len(interrupted_200) == 1
        assert interrupted_200[0]['task_id'] == 'task-2'


class TestListCheckpoints:
    """Test listing checkpoints"""

    def test_list_checkpoints_empty(self, checkpoint_manager):
        """Test listing checkpoints when none exist"""
        checkpoints = checkpoint_manager.list_checkpoints('192.168.45.100')

        assert len(checkpoints) == 0

    def test_list_checkpoints_single(self, checkpoint_manager):
        """Test listing single checkpoint"""
        state_data = {
            'command': 'gobuster dir -u http://target -w wordlist.txt',
            'status': 'running',
            'metadata': {'target': '192.168.45.100'}
        }

        checkpoint_manager.save_checkpoint(
            task_id='gobuster-80',
            stage_id='directory-scan',
            state_data=state_data,
            target='192.168.45.100'
        )

        checkpoints = checkpoint_manager.list_checkpoints('192.168.45.100')

        assert len(checkpoints) == 1
        assert checkpoints[0]['task_id'] == 'gobuster-80'
        assert checkpoints[0]['stage_id'] == 'directory-scan'
        assert checkpoints[0]['status'] == 'running'
        assert 'gobuster dir' in checkpoints[0]['command']

    def test_list_checkpoints_command_truncation(self, checkpoint_manager):
        """Test long commands are truncated in listing"""
        long_command = 'x' * 200
        state_data = {
            'command': long_command,
            'status': 'running',
            'metadata': {'target': '192.168.45.100'}
        }

        checkpoint_manager.save_checkpoint(
            task_id='long-task',
            stage_id='stage-1',
            state_data=state_data,
            target='192.168.45.100'
        )

        checkpoints = checkpoint_manager.list_checkpoints('192.168.45.100')

        assert len(checkpoints) == 1
        assert len(checkpoints[0]['command']) <= 80
        assert checkpoints[0]['command'].endswith('...')

    def test_list_checkpoints_sorted_by_timestamp(self, checkpoint_manager):
        """Test checkpoints are sorted by timestamp (most recent first)"""
        # Create checkpoints with small delay to ensure different timestamps
        for i in range(3):
            state_data = {
                'command': f'command-{i}',
                'status': 'running',
                'metadata': {'target': '192.168.45.100'}
            }
            checkpoint_manager.save_checkpoint(
                task_id=f'task-{i}',
                stage_id='stage-1',
                state_data=state_data,
                target='192.168.45.100'
            )
            time.sleep(0.01)  # Small delay to ensure timestamp difference

        checkpoints = checkpoint_manager.list_checkpoints('192.168.45.100')

        # Should be reverse chronological (most recent first)
        assert checkpoints[0]['task_id'] == 'task-2'
        assert checkpoints[1]['task_id'] == 'task-1'
        assert checkpoints[2]['task_id'] == 'task-0'


class TestClearAllCheckpoints:
    """Test clearing all checkpoints for a target"""

    def test_clear_all_checkpoints_success(self, checkpoint_manager):
        """Test clearing all checkpoints for a target"""
        # Create multiple checkpoints
        for i in range(3):
            state_data = {
                'command': f'command-{i}',
                'status': 'running',
                'metadata': {'target': '192.168.45.100'}
            }
            checkpoint_manager.save_checkpoint(
                task_id=f'task-{i}',
                stage_id='stage-1',
                state_data=state_data,
                target='192.168.45.100'
            )

        # Clear all
        count = checkpoint_manager.clear_all_checkpoints('192.168.45.100')

        assert count == 3

        # Verify all gone
        checkpoints = checkpoint_manager.list_checkpoints('192.168.45.100')
        assert len(checkpoints) == 0

    def test_clear_all_checkpoints_empty(self, checkpoint_manager):
        """Test clearing checkpoints when none exist"""
        count = checkpoint_manager.clear_all_checkpoints('192.168.45.100')

        assert count == 0

    def test_clear_all_checkpoints_target_isolation(self, checkpoint_manager):
        """Test clearing only affects specified target"""
        # Create checkpoints for two targets
        for i in range(2):
            state_data_100 = {
                'command': f'command-100-{i}',
                'status': 'running',
                'metadata': {'target': '192.168.45.100'}
            }
            checkpoint_manager.save_checkpoint(
                task_id=f'task-100-{i}',
                stage_id='stage-1',
                state_data=state_data_100,
                target='192.168.45.100'
            )

            state_data_200 = {
                'command': f'command-200-{i}',
                'status': 'running',
                'metadata': {'target': '192.168.45.200'}
            }
            checkpoint_manager.save_checkpoint(
                task_id=f'task-200-{i}',
                stage_id='stage-1',
                state_data=state_data_200,
                target='192.168.45.200'
            )

        # Clear only target 100
        count = checkpoint_manager.clear_all_checkpoints('192.168.45.100')

        assert count == 2

        # Verify 100 is gone but 200 remains
        checkpoints_100 = checkpoint_manager.list_checkpoints('192.168.45.100')
        checkpoints_200 = checkpoint_manager.list_checkpoints('192.168.45.200')

        assert len(checkpoints_100) == 0
        assert len(checkpoints_200) == 2


class TestCheckpointExpiry:
    """Test automatic checkpoint expiry"""

    def test_cleanup_expired_checkpoints(self, checkpoint_manager, temp_checkpoint_dir):
        """Test expired checkpoints are removed"""
        # Create an expired checkpoint by manually crafting JSON with old timestamp
        old_timestamp = (datetime.now() - timedelta(days=8)).isoformat()

        checkpoint_data = {
            'schema_version': 1,
            'timestamp': old_timestamp,
            'target': '192.168.45.100',
            'task_id': 'old-task',
            'stage_id': 'stage-1',
            'state': {
                'command': 'old command',
                'status': 'running'
            }
        }

        # Write directly to file
        checkpoint_path = temp_checkpoint_dir / '192_168_45_100_old-task_stage-1.json'
        with open(checkpoint_path, 'w') as f:
            json.dump(checkpoint_data, f)

        # Trigger cleanup by listing checkpoints
        checkpoints = checkpoint_manager.list_checkpoints('192.168.45.100')

        # Should be empty (expired checkpoint removed)
        assert len(checkpoints) == 0

    def test_cleanup_keeps_recent_checkpoints(self, checkpoint_manager):
        """Test recent checkpoints are not removed"""
        state_data = {
            'command': 'recent command',
            'status': 'running',
            'metadata': {'target': '192.168.45.100'}
        }

        checkpoint_manager.save_checkpoint(
            task_id='recent-task',
            stage_id='stage-1',
            state_data=state_data,
            target='192.168.45.100'
        )

        # Trigger cleanup
        checkpoints = checkpoint_manager.list_checkpoints('192.168.45.100')

        # Should still be there
        assert len(checkpoints) == 1


class TestCorruptCheckpointHandling:
    """Test graceful handling of corrupt checkpoint files"""

    def test_load_corrupt_json(self, checkpoint_manager, temp_checkpoint_dir):
        """Test loading corrupt JSON file returns None"""
        # Create corrupt JSON file
        corrupt_path = temp_checkpoint_dir / '192_168_45_100_corrupt-task_stage-1.json'
        with open(corrupt_path, 'w') as f:
            f.write('{ "invalid json"')

        loaded = checkpoint_manager.load_checkpoint(
            task_id='corrupt-task',
            stage_id='stage-1',
            target='192.168.45.100'
        )

        assert loaded is None

        # Verify corrupt file was deleted
        assert not corrupt_path.exists()

    def test_detect_interrupted_skips_corrupt(self, checkpoint_manager, temp_checkpoint_dir):
        """Test interrupted session detection skips corrupt files"""
        # Create one valid and one corrupt checkpoint
        state_data = {
            'command': 'valid command',
            'status': 'running',
            'metadata': {'target': '192.168.45.100'}
        }
        checkpoint_manager.save_checkpoint(
            task_id='valid-task',
            stage_id='stage-1',
            state_data=state_data,
            target='192.168.45.100'
        )

        corrupt_path = temp_checkpoint_dir / '192_168_45_100_corrupt-task_stage-1.json'
        with open(corrupt_path, 'w') as f:
            f.write('corrupt data')

        interrupted = checkpoint_manager.detect_interrupted_session('192.168.45.100')

        # Should only find the valid one
        assert len(interrupted) == 1
        assert interrupted[0]['task_id'] == 'valid-task'


class TestThreadSafety:
    """Test thread-safe file operations"""

    def test_concurrent_saves(self, checkpoint_manager):
        """Test concurrent checkpoint saves don't corrupt data"""
        def save_checkpoint(task_id):
            state_data = {
                'command': f'command-{task_id}',
                'status': 'running',
                'metadata': {'target': '192.168.45.100'}
            }
            checkpoint_manager.save_checkpoint(
                task_id=task_id,
                stage_id='stage-1',
                state_data=state_data,
                target='192.168.45.100'
            )

        # Create multiple threads saving different checkpoints
        threads = []
        for i in range(5):
            t = threading.Thread(target=save_checkpoint, args=(f'task-{i}',))
            threads.append(t)
            t.start()

        # Wait for all threads
        for t in threads:
            t.join()

        # Verify all checkpoints saved correctly
        checkpoints = checkpoint_manager.list_checkpoints('192.168.45.100')
        assert len(checkpoints) == 5


class TestFilenameSanitization:
    """Test filename sanitization for special characters"""

    def test_sanitize_special_characters_in_target(self, checkpoint_manager):
        """Test special characters in target are sanitized"""
        state_data = {
            'command': 'test command',
            'status': 'running',
            'metadata': {'target': '192.168.45.100:8080'}
        }

        result = checkpoint_manager.save_checkpoint(
            task_id='test-task',
            stage_id='stage-1',
            state_data=state_data,
            target='192.168.45.100:8080'
        )

        assert result is True

        # Should be able to load it back
        loaded = checkpoint_manager.load_checkpoint(
            task_id='test-task',
            stage_id='stage-1',
            target='192.168.45.100:8080'
        )

        assert loaded is not None

    def test_sanitize_special_characters_in_task_id(self, checkpoint_manager):
        """Test special characters in task_id are sanitized"""
        state_data = {
            'command': 'test command',
            'status': 'running',
            'metadata': {'target': '192.168.45.100'}
        }

        result = checkpoint_manager.save_checkpoint(
            task_id='task/with/slashes',
            stage_id='stage-1',
            state_data=state_data,
            target='192.168.45.100'
        )

        assert result is True

        loaded = checkpoint_manager.load_checkpoint(
            task_id='task/with/slashes',
            stage_id='stage-1',
            target='192.168.45.100'
        )

        assert loaded is not None
