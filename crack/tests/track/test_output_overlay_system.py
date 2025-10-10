"""
Smoke tests for Output Overlay System

Tests basic functionality of:
- TaskNode execution history storage
- OutputOverlay context collection
- ConsoleInjection command execution

Full integration tests should be done manually via TUI.
"""

import pytest
from crack.track.core.task_tree import TaskNode
from crack.track.core.state import TargetProfile


class TestExecutionHistory:
    """Test execution history storage in TaskNode"""

    def test_add_execution_creates_history(self):
        """PROVES: add_execution() creates execution record"""
        task = TaskNode(task_id='test-task', name='Test Task')

        # Add execution
        task.add_execution(
            command='echo "test"',
            output_lines=['test'],
            exit_code=0,
            duration=0.5
        )

        # Verify history created
        history = task.get_execution_history()
        assert len(history) == 1

        # Verify record structure
        record = history[0]
        assert record['command'] == 'echo "test"'
        assert record['output_lines'] == ['test']
        assert record['exit_code'] == 0
        assert record['duration'] == 0.5
        assert 'timestamp' in record
        assert 'context_label' in record

    def test_execution_history_limits_to_max(self):
        """PROVES: Execution history respects max_history limit"""
        task = TaskNode(task_id='test-task', name='Test Task')

        # Add 15 executions (max is 10 by default)
        for i in range(15):
            task.add_execution(
                command=f'echo {i}',
                output_lines=[str(i)],
                exit_code=0,
                duration=0.1,
                max_history=10
            )

        # Verify only last 10 kept
        history = task.get_execution_history()
        assert len(history) == 10

        # Verify most recent is first
        assert history[0]['output_lines'] == ['14']

    def test_get_latest_execution_returns_most_recent(self):
        """PROVES: get_latest_execution() returns most recent execution"""
        task = TaskNode(task_id='test-task', name='Test Task')

        # Add multiple executions
        task.add_execution(
            command='echo 1',
            output_lines=['1'],
            exit_code=0,
            duration=0.1
        )

        task.add_execution(
            command='echo 2',
            output_lines=['2'],
            exit_code=0,
            duration=0.2
        )

        # Verify latest is returned
        latest = task.get_latest_execution()
        assert latest is not None
        assert latest['output_lines'] == ['2']
        assert latest['command'] == 'echo 2'

    def test_execution_history_persists_to_json(self):
        """PROVES: Execution history serializes/deserializes correctly"""
        task = TaskNode(task_id='test-task', name='Test Task')

        task.add_execution(
            command='ls -la',
            output_lines=['file1.txt', 'file2.txt'],
            exit_code=0,
            duration=1.5
        )

        # Serialize to dict
        task_dict = task.to_dict()

        # Verify execution_history in dict
        assert 'execution_history' in task_dict['metadata']
        assert len(task_dict['metadata']['execution_history']) == 1

        # Deserialize from dict
        restored_task = TaskNode.from_dict(task_dict)

        # Verify history restored
        history = restored_task.get_execution_history()
        assert len(history) == 1
        assert history[0]['command'] == 'ls -la'
        assert history[0]['output_lines'] == ['file1.txt', 'file2.txt']


class TestOutputOverlayContextCollection:
    """Test OutputOverlay context collection from profile"""

    def test_collect_contexts_from_profile(self, temp_crack_home):
        """PROVES: OutputOverlay collects contexts from all tasks with executions"""
        from crack.track.interactive.overlays.output_overlay import OutputOverlay

        # Create profile with tasks
        profile = TargetProfile('192.168.45.100')

        # Create tasks with executions
        task1 = TaskNode(task_id='nmap-scan', name='Nmap Full Scan')
        task1.add_execution(
            command='nmap -p- 192.168.45.100',
            output_lines=['PORT STATE SERVICE', '80 open http'],
            exit_code=0,
            duration=30.5
        )

        task2 = TaskNode(task_id='gobuster-80', name='Gobuster HTTP')
        task2.add_execution(
            command='gobuster dir -u http://192.168.45.100',
            output_lines=['/admin (Status: 200)'],
            exit_code=0,
            duration=45.2
        )

        # Add tasks to profile
        profile.task_tree.add_child(task1)
        profile.task_tree.add_child(task2)

        # Collect contexts
        contexts = OutputOverlay._collect_contexts(profile)

        # Verify contexts collected
        assert len(contexts) == 2

        # Verify context structure
        context_labels = [ctx['context_label'] for ctx in contexts]
        assert any('nmap-scan' in label for label in context_labels)
        assert any('gobuster-80' in label for label in context_labels)

        # Verify sorted by timestamp (most recent first)
        # Second task added later, should be first
        assert 'gobuster-80' in contexts[0]['task_id']


class TestConsoleInjection:
    """Test ConsoleInjection command execution"""

    def test_execute_command_captures_output(self):
        """PROVES: ConsoleInjection executes commands and captures output"""
        from crack.track.interactive.overlays.console_injection import ConsoleInjection

        # Execute simple command
        output_lines, exit_code, duration = ConsoleInjection._execute_command('echo "test"')

        # Verify execution
        assert exit_code == 0
        assert len(output_lines) > 0
        assert 'test' in output_lines[0]
        assert duration > 0

    def test_execute_command_handles_errors(self):
        """PROVES: ConsoleInjection handles command errors gracefully"""
        from crack.track.interactive.overlays.console_injection import ConsoleInjection

        # Execute failing command
        output_lines, exit_code, duration = ConsoleInjection._execute_command('false')

        # Verify error captured
        assert exit_code != 0
        assert duration > 0

    def test_get_or_create_injection_task(self, temp_crack_home):
        """PROVES: ConsoleInjection creates special task for injection commands"""
        from crack.track.interactive.overlays.console_injection import ConsoleInjection

        profile = TargetProfile('192.168.45.100')

        # Get/create injection task
        task = ConsoleInjection._get_or_create_injection_task(profile)

        # Verify task created
        assert task.id == 'console-injection'
        assert task.type == 'manual'
        assert task.status == 'completed'

        # Verify task added to profile
        found_task = profile.get_task('console-injection')
        assert found_task is not None
        assert found_task.id == 'console-injection'


# Pytest fixtures
@pytest.fixture
def temp_crack_home(tmp_path, monkeypatch):
    """Create temporary ~/.crack directory for testing"""
    crack_home = tmp_path / '.crack' / 'targets'
    crack_home.mkdir(parents=True)

    # Patch storage to use temp directory
    from crack.track.core.storage import Storage
    monkeypatch.setattr(Storage, 'DEFAULT_DIR', crack_home)

    return crack_home
