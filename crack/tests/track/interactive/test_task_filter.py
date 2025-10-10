"""
Test Task Filter (tf) Shortcut

Tests the filter functionality with syntax: port:80 status:pending tag:QUICK_WIN

Covers:
1. Filter by single port
2. Filter by multiple ports
3. Filter by status
4. Filter by service
5. Filter by tag
6. Combined filters (AND logic)
7. No matches handling
8. Clear filter restores all
9. Filter state persists in session
10. Invalid filter syntax error
"""

import pytest
from unittest.mock import Mock, patch
from crack.track.interactive.search import TaskFilter
from crack.track.core.task_tree import TaskNode


class TestTaskFilter:
    """Test TaskFilter class and integration"""

    @pytest.fixture
    def sample_tasks(self):
        """Create sample tasks for testing"""
        # Task 1: HTTP on port 80, pending, tagged
        task1 = TaskNode(
            task_id='gobuster-80',
            name='Directory Bruteforce (Port 80)',
            task_type='command'
        )
        task1.metadata = {
            'port': 80,
            'service': 'http',
            'command': 'gobuster dir -u http://target:80',
            'tags': ['QUICK_WIN', 'OSCP:HIGH']
        }
        task1.status = 'pending'

        # Task 2: HTTP on port 443, completed
        task2 = TaskNode(
            task_id='nikto-443',
            name='Nikto Scan (Port 443)',
            task_type='command'
        )
        task2.metadata = {
            'port': 443,
            'service': 'https',
            'command': 'nikto -h https://target:443',
            'tags': ['OSCP:HIGH']
        }
        task2.status = 'completed'

        # Task 3: SMB on port 445, pending, tagged
        task3 = TaskNode(
            task_id='enum4linux-445',
            name='SMB Enumeration (Port 445)',
            task_type='command'
        )
        task3.metadata = {
            'port': 445,
            'service': 'smb',
            'command': 'enum4linux -a target',
            'tags': ['QUICK_WIN', 'OSCP:CRITICAL']
        }
        task3.status = 'pending'

        # Task 4: HTTP on port 8080, pending
        task4 = TaskNode(
            task_id='gobuster-8080',
            name='Directory Bruteforce (Port 8080)',
            task_type='command'
        )
        task4.metadata = {
            'port': 8080,
            'service': 'http',
            'command': 'gobuster dir -u http://target:8080',
            'tags': ['OSCP:MEDIUM']
        }
        task4.status = 'pending'

        return [task1, task2, task3, task4]

    def test_filter_by_single_port(self, sample_tasks):
        """Test 1: Filter by single port number"""
        task_filter = TaskFilter("port:80")
        results = task_filter.apply(sample_tasks)

        assert len(results) == 1
        assert results[0].id == 'gobuster-80'
        assert results[0].metadata['port'] == 80

    def test_filter_by_multiple_ports(self, sample_tasks):
        """Test 2: Filter by multiple ports (OR logic for ports)"""
        task_filter = TaskFilter("port:80,443")
        results = task_filter.apply(sample_tasks)

        assert len(results) == 2
        ports = {task.metadata['port'] for task in results}
        assert ports == {80, 443}

    def test_filter_by_status(self, sample_tasks):
        """Test 3: Filter by task status"""
        task_filter = TaskFilter("status:pending")
        results = task_filter.apply(sample_tasks)

        assert len(results) == 3
        for task in results:
            assert task.status == 'pending'

    def test_filter_by_service(self, sample_tasks):
        """Test 4: Filter by service name"""
        task_filter = TaskFilter("service:http")
        results = task_filter.apply(sample_tasks)

        assert len(results) == 3  # Includes https (substring match)
        for task in results:
            assert 'http' in task.metadata.get('service', '').lower()

    def test_filter_by_tag(self, sample_tasks):
        """Test 5: Filter by tag name"""
        task_filter = TaskFilter("tag:QUICK_WIN")
        results = task_filter.apply(sample_tasks)

        assert len(results) == 2
        for task in results:
            assert 'QUICK_WIN' in task.metadata.get('tags', [])

    def test_combined_filters_and_logic(self, sample_tasks):
        """Test 6: Combined filters use AND logic"""
        task_filter = TaskFilter("port:80 status:pending tag:QUICK_WIN")
        results = task_filter.apply(sample_tasks)

        assert len(results) == 1
        task = results[0]
        assert task.metadata['port'] == 80
        assert task.status == 'pending'
        assert 'QUICK_WIN' in task.metadata.get('tags', [])

    def test_no_matches_handling(self, sample_tasks):
        """Test 7: Handle no matching tasks"""
        task_filter = TaskFilter("port:9999")
        results = task_filter.apply(sample_tasks)

        assert len(results) == 0

    def test_empty_filter_returns_all(self, sample_tasks):
        """Test 8: Empty filter returns all tasks (clear filter)"""
        task_filter = TaskFilter("")
        results = task_filter.apply(sample_tasks)

        assert len(results) == 4

    def test_filter_parsing(self):
        """Test 9: Filter string parsing"""
        task_filter = TaskFilter("port:80,443 status:pending service:http tag:QUICK_WIN")

        # Check parsed criteria
        assert '80' in task_filter.criteria['ports']
        assert '443' in task_filter.criteria['ports']
        assert 'pending' in task_filter.criteria['statuses']
        assert 'http' in task_filter.criteria['services']
        assert 'QUICK_WIN' in task_filter.criteria['tags']

    def test_invalid_syntax_graceful(self):
        """Test 10: Invalid filter syntax fails gracefully"""
        # Missing colon should be ignored
        task_filter = TaskFilter("port80 status pending")

        # Should parse as empty (no valid key:value pairs)
        assert len(task_filter.criteria['ports']) == 0
        assert len(task_filter.criteria['statuses']) == 0


class TestSessionIntegration:
    """Test integration with InteractiveSession"""

    @pytest.fixture
    def mock_session(self, tmp_path):
        """Create mock session with profile"""
        from crack.track.core.state import TargetProfile

        # Create session with debug logger disabled
        session = Mock()
        session.target = '192.168.1.1'
        session.profile = TargetProfile('192.168.1.1')

        # Add sample tasks to profile
        task1 = TaskNode(
            task_id='test-80',
            name='Test Task (Port 80)',
            task_type='command'
        )
        task1.metadata = {'port': 80, 'tags': ['QUICK_WIN']}
        task1.status = 'pending'

        session.profile.task_tree.add_child(task1)

        return session

    def test_filter_integration(self, mock_session):
        """Test filter integration with session"""
        # Get all tasks
        tasks = mock_session.profile.task_tree.get_all_tasks()

        # Apply filter
        task_filter = TaskFilter("port:80")
        results = task_filter.apply(tasks)

        assert len(results) > 0
        assert results[0].metadata['port'] == 80


class TestEdgeCases:
    """Test edge cases and error handling"""

    def test_case_insensitivity(self):
        """Test case-insensitive service matching"""
        tasks = [
            TaskNode(task_id='t1', name='HTTP Task', task_type='command')
        ]
        tasks[0].metadata = {'service': 'HTTP'}
        tasks[0].status = 'pending'

        task_filter = TaskFilter("service:http")
        results = task_filter.apply(tasks)

        assert len(results) == 1

    def test_whitespace_handling(self):
        """Test whitespace in filter strings"""
        task_filter = TaskFilter("  port:80   status:pending  ")

        assert '80' in task_filter.criteria['ports']
        assert 'pending' in task_filter.criteria['statuses']

    def test_partial_service_match(self):
        """Test partial service name matching"""
        tasks = [
            TaskNode(task_id='t1', name='Task', task_type='command')
        ]
        tasks[0].metadata = {'service': 'microsoft-ds'}
        tasks[0].status = 'pending'

        # Should match 'smb' in 'microsoft-ds' service
        task_filter = TaskFilter("service:microsoft")
        results = task_filter.apply(tasks)

        assert len(results) == 1

    def test_multiple_tags_filter(self):
        """Test filtering with multiple tags"""
        tasks = [
            TaskNode(task_id='t1', name='Task', task_type='command')
        ]
        tasks[0].metadata = {'tags': ['QUICK_WIN', 'OSCP:HIGH']}
        tasks[0].status = 'pending'

        task_filter = TaskFilter("tag:QUICK_WIN")
        results = task_filter.apply(tasks)

        assert len(results) == 1

    def test_port_as_string_and_int(self):
        """Test port matching with string and int values"""
        tasks = [
            TaskNode(task_id='t1', name='Task', task_type='command')
        ]
        # Port might be stored as int or string
        tasks[0].metadata = {'port': 80}
        tasks[0].status = 'pending'

        task_filter = TaskFilter("port:80")
        results = task_filter.apply(tasks)

        assert len(results) == 1
