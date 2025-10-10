"""
Unit tests for TaskListPanel component

Tests all rendering states and filter/sort logic without integration.
"""

import pytest
from unittest.mock import Mock, MagicMock
from crack.track.interactive.panels.task_list_panel import TaskListPanel


class TestTaskListPanel:
    """Test suite for TaskListPanel"""

    @pytest.fixture
    def mock_profile_empty(self):
        """Mock profile with no tasks"""
        profile = Mock()
        profile.task_tree.get_all_tasks.return_value = []
        profile.target = "192.168.45.100"
        return profile

    @pytest.fixture
    def mock_profile_with_tasks(self):
        """Mock profile with sample tasks"""
        profile = Mock()

        # Create mock tasks
        tasks = []
        for i in range(25):  # 25 tasks for pagination testing
            task = Mock()
            task.id = f"task-{i}"
            task.name = f"Task {i}: Sample Enumeration"
            task.status = 'pending' if i % 3 == 0 else ('completed' if i % 3 == 1 else 'in-progress')
            task.metadata = {
                'port': 80 + (i % 5),
                'service': 'http' if i % 2 == 0 else 'ssh',
                'priority': 'HIGH' if i < 10 else ('MEDIUM' if i < 20 else 'LOW'),
                'tags': ['OSCP:HIGH', 'QUICK_WIN'] if i < 5 else ['WEB'],
                'time_estimate': f"{(i % 10) + 1} min",
                'command': f"gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt",
                'description': f"Sample task {i} for testing"
            }
            tasks.append(task)

        profile.task_tree.get_all_tasks.return_value = tasks
        profile.target = "192.168.45.100"
        return profile

    def test_render_empty_state_no_tasks(self, mock_profile_empty):
        """Test rendering when no tasks exist"""
        panel, choices = TaskListPanel.render(mock_profile_empty)

        # Should return Panel and choices
        assert panel is not None
        assert isinstance(choices, list)

        # Should have basic navigation choices
        choice_ids = [c['id'] for c in choices]
        assert 'back' in choice_ids
        assert 'filter' in choice_ids

    def test_render_empty_state_filtered(self, mock_profile_with_tasks):
        """Test rendering when all tasks filtered out"""
        filter_state = {
            'status': 'failed',  # No failed tasks in mock data
            'port': None,
            'service': None,
            'priority': None,
            'tags': []
        }

        panel, choices = TaskListPanel.render(
            mock_profile_with_tasks,
            filter_state=filter_state
        )

        # Should return empty state panel
        assert panel is not None
        assert isinstance(choices, list)

        # Should have clear-filters option
        choice_ids = [c['id'] for c in choices]
        assert 'clear-filters' in choice_ids

    def test_render_with_tasks_first_page(self, mock_profile_with_tasks):
        """Test rendering first page of tasks"""
        panel, choices = TaskListPanel.render(
            mock_profile_with_tasks,
            page=1,
            page_size=10
        )

        # Should return Panel and choices
        assert panel is not None
        assert isinstance(choices, list)

        # Should have pagination choices
        choice_ids = [c['id'] for c in choices]
        assert 'next-page' in choice_ids  # Should have next page
        assert 'prev-page' not in choice_ids  # No previous page on page 1

        # Should have task selection choices (1-10)
        task_choices = [c for c in choices if 'task' in c]
        assert len(task_choices) == 10  # Page size

    def test_render_with_tasks_second_page(self, mock_profile_with_tasks):
        """Test rendering second page of tasks"""
        panel, choices = TaskListPanel.render(
            mock_profile_with_tasks,
            page=2,
            page_size=10
        )

        # Should have both prev and next
        choice_ids = [c['id'] for c in choices]
        assert 'prev-page' in choice_ids
        assert 'next-page' in choice_ids

    def test_render_with_tasks_last_page(self, mock_profile_with_tasks):
        """Test rendering last page of tasks"""
        panel, choices = TaskListPanel.render(
            mock_profile_with_tasks,
            page=3,
            page_size=10
        )

        # Should have previous but not next
        choice_ids = [c['id'] for c in choices]
        assert 'prev-page' in choice_ids
        assert 'next-page' not in choice_ids

        # Last page should have 5 tasks (25 total, 10 per page)
        task_choices = [c for c in choices if 'task' in c]
        assert len(task_choices) == 5

    def test_filter_by_status(self, mock_profile_with_tasks):
        """Test status filtering"""
        filter_state = {
            'status': 'completed',
            'port': None,
            'service': None,
            'priority': None,
            'tags': []
        }

        panel, choices = TaskListPanel.render(
            mock_profile_with_tasks,
            filter_state=filter_state
        )

        # Count completed tasks in mock data (every 3rd task starting at 1)
        # 1, 4, 7, 10, 13, 16, 19, 22 = 8 tasks
        task_choices = [c for c in choices if 'task' in c]
        assert len(task_choices) == 8

    def test_filter_by_port(self, mock_profile_with_tasks):
        """Test port filtering"""
        filter_state = {
            'status': 'all',
            'port': 80,
            'service': None,
            'priority': None,
            'tags': []
        }

        panel, choices = TaskListPanel.render(
            mock_profile_with_tasks,
            filter_state=filter_state
        )

        # Tasks with port 80: i % 5 == 0 -> 0, 5, 10, 15, 20 = 5 tasks
        task_choices = [c for c in choices if 'task' in c]
        assert len(task_choices) == 5

    def test_filter_by_priority(self, mock_profile_with_tasks):
        """Test priority filtering"""
        filter_state = {
            'status': 'all',
            'port': None,
            'service': None,
            'priority': 'HIGH',
            'tags': []
        }

        panel, choices = TaskListPanel.render(
            mock_profile_with_tasks,
            filter_state=filter_state
        )

        # HIGH priority: i < 10 = 10 tasks
        task_choices = [c for c in choices if 'task' in c]
        assert len(task_choices) == 10

    def test_sort_by_priority(self, mock_profile_with_tasks):
        """Test sorting by priority"""
        # Get first page with priority sort
        panel, choices = TaskListPanel.render(
            mock_profile_with_tasks,
            sort_by='priority',
            page=1,
            page_size=10
        )

        # First 10 tasks should all be HIGH priority (tasks 0-9)
        task_choices = [c for c in choices if 'task' in c]
        assert len(task_choices) == 10

        # All should be HIGH priority
        for choice in task_choices:
            task = choice['task']
            assert task.metadata['priority'] == 'HIGH'

    def test_sort_by_name(self, mock_profile_with_tasks):
        """Test sorting by name"""
        panel, choices = TaskListPanel.render(
            mock_profile_with_tasks,
            sort_by='name',
            page=1,
            page_size=5
        )

        # Should sort alphabetically
        task_choices = [c for c in choices if 'task' in c]
        assert len(task_choices) == 5

        # Check first task is "Task 0" (alphabetically first)
        assert task_choices[0]['task'].name == "Task 0: Sample Enumeration"

    def test_extract_port_from_task(self):
        """Test port extraction logic"""
        # Test with metadata
        task = Mock()
        task.metadata = {'port': 80}
        assert TaskListPanel._extract_port_from_task(task) == 80

        # Test with task ID
        task = Mock()
        task.metadata = {}
        task.id = 'gobuster-8080'
        assert TaskListPanel._extract_port_from_task(task) == 8080

        # Test with no port
        task = Mock()
        task.metadata = {}
        task.id = 'general-recon'
        assert TaskListPanel._extract_port_from_task(task) is None

    def test_parse_time_estimate(self):
        """Test time estimate parsing"""
        # Minutes
        task = Mock()
        task.metadata = {'time_estimate': '5 min'}
        assert TaskListPanel._parse_time_estimate(task) == 5

        # Hours
        task = Mock()
        task.metadata = {'time_estimate': '2 hours'}
        assert TaskListPanel._parse_time_estimate(task) == 120

        # Range (takes first number)
        task = Mock()
        task.metadata = {'time_estimate': '2-5 min'}
        assert TaskListPanel._parse_time_estimate(task) == 2

        # Unknown
        task = Mock()
        task.metadata = {'time_estimate': 'Unknown'}
        assert TaskListPanel._parse_time_estimate(task) == 0

    def test_get_stage_info(self):
        """Test multi-stage indicator"""
        # Multi-stage task
        task = Mock()
        task.metadata = {'stages': 3, 'current_stage': 2}
        result = TaskListPanel._get_stage_info(task)
        assert '[2/3]' in result

        # Single-stage task
        task = Mock()
        task.metadata = {}
        result = TaskListPanel._get_stage_info(task)
        assert '-' in result

    def test_combined_filters(self, mock_profile_with_tasks):
        """Test multiple filters at once"""
        filter_state = {
            'status': 'pending',
            'port': None,
            'service': 'http',
            'priority': None,
            'tags': []
        }

        panel, choices = TaskListPanel.render(
            mock_profile_with_tasks,
            filter_state=filter_state
        )

        # Should filter to pending + http service
        # Pending: i % 3 == 0 -> 0, 3, 6, 9, 12, 15, 18, 21, 24 = 9 tasks
        # HTTP: i % 2 == 0 -> even indices
        # Intersection: 0, 6, 12, 18, 24 = 5 tasks
        task_choices = [c for c in choices if 'task' in c]
        assert len(task_choices) == 5

    def test_action_choices_structure(self, mock_profile_with_tasks):
        """Test that choices have correct structure"""
        panel, choices = TaskListPanel.render(mock_profile_with_tasks)

        # All choices should have id and label
        for choice in choices:
            assert 'id' in choice
            assert 'label' in choice

        # Task choices should have task reference
        task_choices = [c for c in choices if 'task' in c]
        for choice in task_choices:
            assert choice['task'] is not None

    def test_page_clamping(self, mock_profile_with_tasks):
        """Test that invalid page numbers are clamped"""
        # Page too high
        panel, choices = TaskListPanel.render(
            mock_profile_with_tasks,
            page=999,
            page_size=10
        )

        # Should show last page (page 3)
        choice_ids = [c['id'] for c in choices]
        assert 'prev-page' in choice_ids
        assert 'next-page' not in choice_ids

        # Page 0 should clamp to 1
        panel, choices = TaskListPanel.render(
            mock_profile_with_tasks,
            page=0,
            page_size=10
        )

        choice_ids = [c['id'] for c in choices]
        assert 'prev-page' not in choice_ids
        assert 'next-page' in choice_ids
