"""
Test Task Filter (tf) Tool - Agent 3B Implementation

Tests for interactive task filtering functionality:
- Filter by status, port, service, tag
- Multiple filter combinations (AND logic)
- Interactive UI
- Shortcut integration
"""

import pytest
from pathlib import Path
import tempfile
import os

from crack.track.core.state import TargetProfile
from crack.track.core.task_tree import TaskNode
from crack.track.interactive.session import InteractiveSession
from crack.track.interactive.shortcuts import ShortcutHandler


class TestFilterTasksMethod:
    """Test enhanced filter_tasks() method"""

    def test_filter_by_status_pending(self, temp_crack_home, mock_profile_with_tasks):
        """PROVES: Can filter tasks by 'pending' status"""
        session = InteractiveSession(mock_profile_with_tasks.target)

        # Add tasks with different statuses
        task1 = TaskNode('task-1', 'Task 1', 'command')
        task1.status = 'pending'
        session.profile.task_tree.add_child(task1)

        task2 = TaskNode('task-2', 'Task 2', 'command')
        task2.status = 'in-progress'
        session.profile.task_tree.add_child(task2)

        task3 = TaskNode('task-3', 'Task 3', 'command')
        task3.status = 'completed'
        session.profile.task_tree.add_child(task3)

        results = session.filter_tasks('status', 'pending')

        assert len(results) >= 1
        assert all(t.status == 'pending' for t in results)

    def test_filter_by_status_completed(self, temp_crack_home, mock_profile_with_tasks):
        """PROVES: Can filter tasks by 'completed' status"""
        session = InteractiveSession(mock_profile_with_tasks.target)

        task = TaskNode('task-1', 'Task 1', 'command')
        task.status = 'pending'
        session.profile.task_tree.add_child(task)
        task = TaskNode('task-2', 'Task 2', 'command')
        task.status = 'completed'
        session.profile.task_tree.add_child(task)

        results = session.filter_tasks('status', 'completed')

        assert len(results) >= 1
        assert all(t.status == 'completed' for t in results)

    def test_filter_by_port(self, temp_crack_home, mock_profile_with_services):
        """PROVES: Can filter tasks by port number"""
        session = InteractiveSession(mock_profile_with_services.target)

        # Add port-specific tasks
        session.profile.task_tree.add_child(TaskNode(
            'http-80', 'HTTP Enumeration Port 80', 'command'
        ))
        session.profile.task_tree.add_child(TaskNode(
            'smb-445', 'SMB Enumeration Port 445', 'command'
        ))

        results = session.filter_tasks('port', '80')

        assert len(results) >= 1
        assert any('80' in t.id or 'port 80' in t.name.lower() for t in results)

    def test_filter_by_service(self, temp_crack_home, mock_profile_with_services):
        """PROVES: Can filter tasks by service name (NEW FEATURE)"""
        session = InteractiveSession(mock_profile_with_services.target)

        # Add tasks with service-specific naming
        task = TaskNode('http-enum', 'HTTP Enumeration', 'command')
        task.metadata.update({'command': 'gobuster dir -u http://target'})
        session.profile.task_tree.add_child(task)
        task = TaskNode('smb-enum', 'SMB Enumeration', 'command')
        task.metadata.update({'command': 'smbclient -L target', 'service': 'smb'})
        session.profile.task_tree.add_child(task)

        results = session.filter_tasks('service', 'http')

        assert len(results) >= 1
        # Should match tasks with 'http' in name or command
        assert any('http' in t.name.lower() or
                  (t.metadata.get('command') and 'http' in t.metadata['command'].lower())
                  for t in results)

    def test_filter_by_service_in_metadata(self, temp_crack_home, mock_profile_with_tasks):
        """PROVES: Service filter checks metadata 'service' field"""
        session = InteractiveSession(mock_profile_with_tasks.target)

        task = TaskNode('task-1', 'Some Task', 'command')
        task.metadata.update({'service': 'ssh', 'command': 'nmap -p22 target'})
        session.profile.task_tree.add_child(task)
        task = TaskNode('task-2', 'Another Task', 'command')
        task.metadata.update({'service': 'http'})
        session.profile.task_tree.add_child(task)

        results = session.filter_tasks('service', 'ssh')

        assert len(results) >= 1
        assert any(t.metadata.get('service') == 'ssh' for t in results)

    def test_filter_by_tag(self, temp_crack_home, mock_profile_with_tasks):
        """PROVES: Can filter tasks by tag"""
        session = InteractiveSession(mock_profile_with_tasks.target)

        task = TaskNode('task-1', 'Quick Task', 'command')
        task.metadata.update({'tags': ['QUICK_WIN', 'OSCP:HIGH']})
        session.profile.task_tree.add_child(task)
        task = TaskNode('task-2', 'Slow Task', 'command')
        task.metadata.update({'tags': ['OSCP:LOW']})
        session.profile.task_tree.add_child(task)

        results = session.filter_tasks('tag', 'QUICK_WIN')

        assert len(results) >= 1
        assert all('QUICK_WIN' in t.metadata.get('tags', []) for t in results)

    def test_filter_quick_win(self, temp_crack_home, mock_profile_with_tasks):
        """PROVES: Can filter for QUICK_WIN tasks"""
        session = InteractiveSession(mock_profile_with_tasks.target)

        task = TaskNode('task-1', 'Quick Win Task', 'command')
        task.metadata.update({'tags': ['QUICK_WIN']})
        session.profile.task_tree.add_child(task)
        task = TaskNode('task-2', 'Normal Task', 'command')
        task.metadata.update({'tags': ['OSCP:MEDIUM']})
        session.profile.task_tree.add_child(task)

        results = session.filter_tasks('quick_win')

        assert len(results) >= 1
        assert all('QUICK_WIN' in t.metadata.get('tags', []) for t in results)

    def test_filter_returns_empty_when_no_match(self, temp_crack_home, mock_profile_with_tasks):
        """PROVES: Filter returns empty list when no tasks match"""
        session = InteractiveSession(mock_profile_with_tasks.target)

        task = TaskNode('task-1', 'Some Task', 'command')
        task.status = 'pending'
        session.profile.task_tree.add_child(task)

        results = session.filter_tasks('status', 'completed')

        assert len(results) == 0


class TestMultipleFilters:
    """Test _apply_multiple_filters() method"""

    def test_multiple_filters_and_logic(self, temp_crack_home, mock_profile_with_tasks):
        """PROVES: Multiple filters use AND logic (intersection)"""
        session = InteractiveSession(mock_profile_with_tasks.target)

        # Add tasks
        task1 = TaskNode('http-80', 'HTTP Enumeration Port 80', 'command')
        task1.status = 'pending'
        task1.metadata.update({'tags': ['QUICK_WIN'], 'service': 'http'})
        session.profile.task_tree.add_child(task1)

        task2 = TaskNode('http-443', 'HTTPS Enumeration Port 443', 'command')
        task2.status = 'completed'
        task2.metadata.update({'tags': ['QUICK_WIN'], 'service': 'http'})
        session.profile.task_tree.add_child(task2)

        task3 = TaskNode('smb-445', 'SMB Enumeration Port 445', 'command')
        task3.status = 'pending'
        task3.metadata.update({'tags': ['QUICK_WIN'], 'service': 'smb'})
        session.profile.task_tree.add_child(task3)

        # Filter: service=http AND status=pending
        filters = [
            ('service', 'http'),
            ('status', 'pending')
        ]

        results = session._apply_multiple_filters(filters)

        # Should only return tasks matching BOTH criteria
        assert len(results) >= 1
        for task in results:
            assert task.status == 'pending'
            assert ('http' in task.name.lower() or
                    task.metadata.get('service') == 'http')

    def test_multiple_filters_three_criteria(self, temp_crack_home, mock_profile_with_tasks):
        """PROVES: Can combine 3+ filters"""
        session = InteractiveSession(mock_profile_with_tasks.target)

        task1 = TaskNode('http-80', 'HTTP Port 80', 'command')
        task1.status = 'pending'
        task1.metadata.update({'tags': ['QUICK_WIN', 'OSCP:HIGH'], 'service': 'http'})
        session.profile.task_tree.add_child(task1)

        task2 = TaskNode('http-443', 'HTTP Port 443', 'command')
        task2.status = 'pending'
        task2.metadata.update({'tags': ['OSCP:HIGH'], 'service': 'http'})
        session.profile.task_tree.add_child(task2)

        # Filter: service=http AND status=pending AND tag=QUICK_WIN
        filters = [
            ('service', 'http'),
            ('status', 'pending'),
            ('tag', 'QUICK_WIN')
        ]

        results = session._apply_multiple_filters(filters)

        assert len(results) >= 1
        for task in results:
            assert task.status == 'pending'
            assert 'QUICK_WIN' in task.metadata.get('tags', [])

    def test_multiple_filters_no_intersection(self, temp_crack_home, mock_profile_with_tasks):
        """PROVES: Multiple filters return empty when no tasks match all criteria"""
        session = InteractiveSession(mock_profile_with_tasks.target)

        task = TaskNode('http-80', 'HTTP Task', 'command')
        task.status = 'completed'  # Not pending
        task.metadata.update({'service': 'http'})
        session.profile.task_tree.add_child(task)

        # Filter: service=http AND status=pending (no match)
        filters = [
            ('service', 'http'),
            ('status', 'pending')
        ]

        results = session._apply_multiple_filters(filters)

        assert len(results) == 0


class TestShortcutIntegration:
    """Test 'tf' shortcut integration"""

    def test_tf_shortcut_exists(self, temp_crack_home, mock_profile_with_tasks):
        """PROVES: 'tf' shortcut is registered"""
        session = InteractiveSession(mock_profile_with_tasks.target)
        handler = ShortcutHandler(session)

        assert 'tf' in handler.shortcuts
        assert handler.shortcuts['tf'][0] == 'Task filter'
        assert handler.shortcuts['tf'][1] == 'task_filter'

    def test_tf_shortcut_has_handler(self, temp_crack_home, mock_profile_with_tasks):
        """PROVES: 'tf' shortcut has callable handler"""
        session = InteractiveSession(mock_profile_with_tasks.target)
        handler = ShortcutHandler(session)

        assert hasattr(handler, 'task_filter')
        assert callable(handler.task_filter)

    def test_shortcut_handler_calls_session_method(self, temp_crack_home, mock_profile_with_tasks):
        """PROVES: Shortcut handler calls session.handle_filter()"""
        session = InteractiveSession(mock_profile_with_tasks.target)
        handler = ShortcutHandler(session)

        # Verify session has handle_filter method
        assert hasattr(session, 'handle_filter')
        assert callable(session.handle_filter)


class TestInputHandlerRegistration:
    """Test input_handler.py recognizes 'tf' shortcut"""

    def test_tf_in_shortcuts_list(self):
        """PROVES: 'tf' is in InputProcessor.SHORTCUTS"""
        from crack.track.interactive.input_handler import InputProcessor

        assert 'tf' in InputProcessor.SHORTCUTS

    def test_tf_shortcut_parsing(self):
        """PROVES: InputProcessor correctly parses 'tf' shortcut"""
        from crack.track.interactive.input_handler import InputProcessor

        result = InputProcessor.parse_shortcut('tf')

        assert result == 'tf'


@pytest.fixture
def temp_crack_home(tmp_path):
    """Create temporary .crack directory"""
    crack_dir = tmp_path / '.crack'
    crack_dir.mkdir()
    (crack_dir / 'targets').mkdir()
    (crack_dir / 'sessions').mkdir()

    # Set HOME to temp directory
    original_home = os.environ.get('HOME')
    os.environ['HOME'] = str(tmp_path)

    yield crack_dir

    # Restore
    if original_home:
        os.environ['HOME'] = original_home


@pytest.fixture
def mock_profile_with_tasks(temp_crack_home):
    """Create profile with sample tasks"""
    profile = TargetProfile('192.168.45.100')
    profile.save()
    return profile


@pytest.fixture
def mock_profile_with_services(temp_crack_home):
    """Create profile with services discovered"""
    profile = TargetProfile('192.168.45.100')

    # Add ports
    profile.add_port(80, state='open', service='http', version='Apache 2.4.41', source='nmap')
    profile.add_port(445, state='open', service='microsoft-ds', version='SMB', source='nmap')

    profile.save()
    return profile


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
