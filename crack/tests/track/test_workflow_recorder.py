"""
Test Workflow Recorder - Record and replay task sequences

Tests prove the workflow recorder can:
- Record task sequences during execution
- Extract variables from commands
- Save workflows to disk
- Replay workflows on different targets
- Handle variable substitution correctly
"""

import pytest
import json
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime

from crack.track.interactive.session import InteractiveSession
from crack.track.core.state import TargetProfile
from crack.track.core.task_tree import TaskNode


class TestWorkflowRecording:
    """Test workflow recording functionality"""

    def test_start_recording(self, temp_crack_home, mock_profile):
        """PROVES: Can start recording workflow"""
        session = InteractiveSession(mock_profile.target)

        # Start recording
        session._start_recording('web-enum')

        # Verify state
        assert session.recording is True
        assert session.recording_name == 'web-enum'
        assert session.recording_start is not None
        assert session.recorded_tasks == []

    def test_stop_recording_saves_workflow(self, temp_crack_home, mock_profile):
        """PROVES: Stopping recording saves workflow to disk"""
        session = InteractiveSession(mock_profile.target)

        # Start recording
        session._start_recording('test-workflow')

        # Add a mock recorded task
        session.recorded_tasks.append({
            'name': 'Test task',
            'command': 'echo test',
            'order': 1,
            'variables': [],
            'estimated_time': 5,
            'tags': ['QUICK_WIN']
        })

        # Stop recording (mock input for description)
        with patch('builtins.input', return_value='Test workflow'):
            session._stop_recording()

        # Verify workflow saved
        workflow_path = Path.home() / '.crack' / 'workflows' / 'test-workflow.workflow.json'
        assert workflow_path.exists()

        # Load and verify
        workflow = json.loads(workflow_path.read_text())
        assert workflow['name'] == 'test-workflow'
        assert workflow['description'] == 'Test workflow'
        assert len(workflow['tasks']) == 1
        assert workflow['stats']['total_tasks'] == 1

    def test_record_task_during_execution(self, temp_crack_home, mock_profile):
        """PROVES: Tasks are recorded during execution when recording active"""
        session = InteractiveSession(mock_profile.target)

        # Create a task
        task = TaskNode('test-task', 'Test Task', 'command')
        task.metadata = {
            'command': f'whatweb {mock_profile.target}',
            'estimated_time': 30,
            'tags': ['OSCP:HIGH']
        }

        # Start recording
        session._start_recording('test')

        # Record task
        session._record_task(task)

        # Verify task was recorded
        assert len(session.recorded_tasks) == 1
        assert session.recorded_tasks[0]['name'] == 'Test Task'
        assert '<TARGET>' in session.recorded_tasks[0]['command']

    def test_no_recording_when_not_active(self, temp_crack_home, mock_profile):
        """PROVES: Tasks not recorded when recording inactive"""
        session = InteractiveSession(mock_profile.target)

        # Create a task
        task = TaskNode('test-task', 'Test Task', 'command')
        task.metadata = {'command': 'echo test'}

        # Try to record (should do nothing)
        session._record_task(task)

        # Verify nothing recorded
        assert not hasattr(session, 'recorded_tasks') or session.recorded_tasks == []


class TestVariableExtraction:
    """Test variable extraction and templatization"""

    def test_templatize_target_ip(self, temp_crack_home, mock_profile):
        """PROVES: Target IP replaced with <TARGET> placeholder"""
        session = InteractiveSession(mock_profile.target)

        command = f"nmap -sV {mock_profile.target}"
        templatized = session._templatize_command(command, mock_profile.target)

        assert '<TARGET>' in templatized
        assert mock_profile.target not in templatized
        assert templatized == "nmap -sV <TARGET>"

    def test_templatize_wordlist_path(self, temp_crack_home, mock_profile):
        """PROVES: Wordlist paths replaced with <WORDLIST>"""
        session = InteractiveSession(mock_profile.target)

        command = "gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt"
        templatized = session._templatize_command(command, mock_profile.target)

        assert '<WORDLIST>' in templatized
        assert '/usr/share/wordlists' not in templatized

    def test_templatize_ports(self, temp_crack_home, mock_profile):
        """PROVES: Common ports replaced with <PORT>"""
        session = InteractiveSession(mock_profile.target)

        command = f"curl http://{mock_profile.target}:80/admin"
        templatized = session._templatize_command(command, mock_profile.target)

        assert '<PORT>' in templatized
        assert ':80' not in templatized

    def test_templatize_attacker_ip(self, temp_crack_home, mock_profile):
        """PROVES: Attacker IPs replaced with <LHOST>"""
        session = InteractiveSession(mock_profile.target)

        command = "nc -lvnp 4444 192.168.45.200"
        templatized = session._templatize_command(command, mock_profile.target)

        assert '<LHOST>' in templatized
        assert '192.168.45.200' not in templatized

    def test_find_variables(self, temp_crack_home, mock_profile):
        """PROVES: Variables correctly extracted from template"""
        session = InteractiveSession(mock_profile.target)

        command = "nmap -sV <TARGET> -p <PORT> -oA <OUTPUT>"
        variables = session._find_variables(command)

        assert 'TARGET' in variables
        assert 'PORT' in variables
        assert 'OUTPUT' in variables
        assert len(variables) == 3

    def test_extract_variables_with_metadata(self, temp_crack_home, mock_profile):
        """PROVES: Variables extracted with descriptions and examples"""
        session = InteractiveSession(mock_profile.target)

        tasks = [
            {
                'name': 'Scan',
                'command': 'nmap <TARGET>',
                'variables': ['TARGET'],
                'order': 1
            }
        ]

        variables = session._extract_variables(tasks)

        assert 'TARGET' in variables
        assert variables['TARGET']['description'] == 'Target IP or hostname'
        assert variables['TARGET']['example'] == '192.168.45.100'
        assert variables['TARGET']['required'] is True


class TestWorkflowReplay:
    """Test workflow replay functionality"""

    def test_list_workflows(self, temp_crack_home, mock_profile):
        """PROVES: Lists all saved workflows"""
        session = InteractiveSession(mock_profile.target)

        # Create test workflow
        workflow_dir = Path.home() / '.crack' / 'workflows'
        workflow_dir.mkdir(parents=True, exist_ok=True)

        workflow = {
            'name': 'test-workflow',
            'description': 'Test',
            'tasks': [{'name': 'Task 1', 'command': 'echo test', 'order': 1}],
            'stats': {'total_tasks': 1, 'total_time': 5}
        }

        (workflow_dir / 'test-workflow.workflow.json').write_text(json.dumps(workflow))

        # Capture output
        import io
        import sys
        captured = io.StringIO()
        sys.stdout = captured

        session._list_workflows()

        sys.stdout = sys.__stdout__
        output = captured.getvalue()

        assert 'test-workflow' in output
        assert 'Task 1' not in output  # Only shows stats, not individual tasks

    def test_play_workflow_variable_substitution(self, temp_crack_home, mock_profile):
        """PROVES: Workflow replay substitutes variables correctly"""
        session = InteractiveSession(mock_profile.target)

        # Create workflow
        workflow_dir = Path.home() / '.crack' / 'workflows'
        workflow_dir.mkdir(parents=True, exist_ok=True)

        workflow = {
            'name': 'test',
            'description': 'Test',
            'tasks': [
                {
                    'name': 'Scan',
                    'command': 'nmap -sV <TARGET> -p <PORT>',
                    'order': 1,
                    'variables': ['TARGET', 'PORT']
                }
            ],
            'variables': {
                'TARGET': {'description': 'Target IP', 'example': '192.168.45.100', 'required': True},
                'PORT': {'description': 'Port', 'example': '80', 'required': True}
            },
            'stats': {'total_tasks': 1, 'total_time': 60}
        }

        workflow_path = workflow_dir / 'test.workflow.json'
        workflow_path.write_text(json.dumps(workflow))

        # Mock inputs: TARGET=192.168.45.100, PORT=80, confirm=Y
        with patch('builtins.input', side_effect=['192.168.45.100', '80', 'y']):
            with patch('subprocess.run') as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout='', stderr='')

                session._play_workflow('test')

                # Verify command was executed with substituted variables
                mock_run.assert_called_once()
                executed_cmd = mock_run.call_args[0][0]
                assert 'nmap -sV 192.168.45.100 -p 80' == executed_cmd

    def test_delete_workflow(self, temp_crack_home, mock_profile):
        """PROVES: Can delete saved workflow"""
        session = InteractiveSession(mock_profile.target)

        # Create workflow
        workflow_dir = Path.home() / '.crack' / 'workflows'
        workflow_dir.mkdir(parents=True, exist_ok=True)

        workflow_path = workflow_dir / 'delete-me.workflow.json'
        workflow_path.write_text(json.dumps({'name': 'delete-me'}))

        assert workflow_path.exists()

        # Delete with confirmation
        with patch('builtins.input', return_value='y'):
            session._delete_workflow('delete-me')

        assert not workflow_path.exists()

    def test_export_workflow(self, temp_crack_home, mock_profile):
        """PROVES: Can export workflow to custom path"""
        session = InteractiveSession(mock_profile.target)

        # Create workflow
        workflow_dir = Path.home() / '.crack' / 'workflows'
        workflow_dir.mkdir(parents=True, exist_ok=True)

        workflow = {'name': 'export-test', 'tasks': []}
        workflow_path = workflow_dir / 'export-test.workflow.json'
        workflow_path.write_text(json.dumps(workflow))

        # Export
        export_path = '/tmp/exported.json'
        with patch('builtins.input', return_value=export_path):
            session._export_workflow('export-test')

        # Verify export
        assert Path(export_path).exists()
        exported = json.loads(Path(export_path).read_text())
        assert exported['name'] == 'export-test'


class TestWorkflowValidation:
    """Test workflow validation and error handling"""

    def test_cannot_start_recording_twice(self, temp_crack_home, mock_profile):
        """PROVES: Cannot start recording when already recording"""
        session = InteractiveSession(mock_profile.target)

        session._start_recording('first')
        assert session.recording is True

        # Try to start again (should warn, not start)
        import io
        import sys
        captured = io.StringIO()
        sys.stdout = captured

        session._start_recording('second')

        sys.stdout = sys.__stdout__
        output = captured.getvalue()

        assert 'Already recording' in output
        assert session.recording_name == 'first'  # Unchanged

    def test_stop_recording_without_start(self, temp_crack_home, mock_profile):
        """PROVES: Stopping without recording shows warning"""
        session = InteractiveSession(mock_profile.target)

        import io
        import sys
        captured = io.StringIO()
        sys.stdout = captured

        session._stop_recording()

        sys.stdout = sys.__stdout__
        output = captured.getvalue()

        assert 'Not currently recording' in output

    def test_stop_recording_with_no_tasks(self, temp_crack_home, mock_profile):
        """PROVES: Stopping with no tasks shows warning"""
        session = InteractiveSession(mock_profile.target)

        session._start_recording('empty')

        import io
        import sys
        captured = io.StringIO()
        sys.stdout = captured

        session._stop_recording()

        sys.stdout = sys.__stdout__
        output = captured.getvalue()

        assert 'No tasks recorded' in output
        assert session.recording is False

    def test_play_nonexistent_workflow(self, temp_crack_home, mock_profile):
        """PROVES: Playing nonexistent workflow shows error"""
        session = InteractiveSession(mock_profile.target)

        import io
        import sys
        captured = io.StringIO()
        sys.stdout = captured

        session._play_workflow('nonexistent')

        sys.stdout = sys.__stdout__
        output = captured.getvalue()

        assert 'Workflow not found' in output


class TestIntegration:
    """Integration tests for complete workflow"""

    def test_complete_record_and_replay_workflow(self, temp_crack_home, mock_profile):
        """
        PROVES: Complete workflow - record tasks, save, replay on different target

        Workflow:
        1. Start recording
        2. Execute tasks (recorded)
        3. Stop recording (saves)
        4. Load workflow
        5. Replay on different target
        """
        session = InteractiveSession(mock_profile.target)

        # 1. Start recording
        session._start_recording('http-enum')

        # 2. Execute tasks (simulate)
        task1 = TaskNode('whatweb-80', 'Technology detection', 'command')
        task1.metadata = {
            'command': f'whatweb {mock_profile.target}',
            'estimated_time': 5,
            'tags': ['OSCP:HIGH']
        }

        task2 = TaskNode('gobuster-80', 'Directory brute-force', 'command')
        task2.metadata = {
            'command': f'gobuster dir -u http://{mock_profile.target} -w /usr/share/wordlists/dirb/common.txt',
            'estimated_time': 60,
            'tags': ['ENUM']
        }

        session._record_task(task1)
        session._record_task(task2)

        # 3. Stop and save
        with patch('builtins.input', return_value='HTTP enumeration workflow'):
            session._stop_recording()

        # 4. Verify workflow saved
        workflow_path = Path.home() / '.crack' / 'workflows' / 'http-enum.workflow.json'
        assert workflow_path.exists()

        workflow = json.loads(workflow_path.read_text())
        assert len(workflow['tasks']) == 2
        assert 'TARGET' in workflow['variables']
        assert 'WORDLIST' in workflow['variables']

        # 5. Replay on different target
        new_target = '192.168.45.200'
        with patch('builtins.input', side_effect=[new_target, '/usr/share/wordlists/dirb/common.txt', 'y']):
            with patch('subprocess.run') as mock_run:
                mock_run.return_value = Mock(returncode=0, stdout='', stderr='')

                session._play_workflow('http-enum')

                # Verify both commands executed with new target
                assert mock_run.call_count == 2

                # Check first command
                first_cmd = mock_run.call_args_list[0][0][0]
                assert new_target in first_cmd
                assert 'whatweb' in first_cmd

                # Check second command
                second_cmd = mock_run.call_args_list[1][0][0]
                assert new_target in second_cmd
                assert 'gobuster' in second_cmd


# Fixtures
@pytest.fixture
def temp_crack_home(tmp_path, monkeypatch):
    """Create temporary .crack home directory"""
    crack_home = tmp_path / '.crack'
    crack_home.mkdir()

    # Mock Path.home() to return tmp_path
    monkeypatch.setattr(Path, 'home', lambda: tmp_path)

    return crack_home


@pytest.fixture
def mock_profile():
    """Create mock target profile"""
    profile = TargetProfile('192.168.45.100')
    return profile
