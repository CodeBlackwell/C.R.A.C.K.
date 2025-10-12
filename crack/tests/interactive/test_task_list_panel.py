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

        # Create mock root with no children
        root = Mock()
        root.id = "root"
        root.children = []
        root.get_all_tasks.return_value = []

        profile.task_tree = root
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
            task.children = []  # No subtasks for flat list tests
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

        # Create mock root with tasks as children
        root = Mock()
        root.id = "root"
        root.children = tasks
        root.get_all_tasks.return_value = tasks

        profile.task_tree = root
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
        from crack.track.interactive.themes import ThemeManager
        theme = ThemeManager()

        # Multi-stage task
        task = Mock()
        task.metadata = {'stages': 3, 'current_stage': 2}
        result = TaskListPanel._get_stage_info(task, theme)
        assert '[2/3]' in result

        # Single-stage task
        task = Mock()
        task.metadata = {}
        result = TaskListPanel._get_stage_info(task, theme)
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


class TestTaskListHierarchy:
    """Test suite for hierarchical task list features"""

    @pytest.fixture
    def mock_profile_with_hierarchy(self):
        """Mock profile with parent tasks and subtasks"""
        profile = Mock()

        # Create mock task tree with hierarchy
        parent1 = Mock()
        parent1.id = "parent-1"
        parent1.name = "HTTP Enumeration"
        parent1.status = "pending"
        parent1.children = []
        parent1.metadata = {
            'port': 80,
            'service': 'http',
            'priority': 'HIGH',
            'tags': ['WEB'],
            'time_estimate': '5 min'
        }

        subtask1a = Mock()
        subtask1a.id = "subtask-1a"
        subtask1a.name = "Run gobuster"
        subtask1a.status = "pending"
        subtask1a.children = []
        subtask1a.parent = parent1
        subtask1a.metadata = {
            'port': 80,
            'service': 'http',
            'priority': 'HIGH',
            'tags': ['WEB'],
            'time_estimate': '2 min'
        }

        subtask1b = Mock()
        subtask1b.id = "subtask-1b"
        subtask1b.name = "Run nikto"
        subtask1b.status = "pending"
        subtask1b.children = []
        subtask1b.parent = parent1
        subtask1b.metadata = {
            'port': 80,
            'service': 'http',
            'priority': 'HIGH',
            'tags': ['WEB'],
            'time_estimate': '3 min'
        }

        parent1.children = [subtask1a, subtask1b]

        parent2 = Mock()
        parent2.id = "parent-2"
        parent2.name = "SMB Enumeration"
        parent2.status = "pending"
        parent2.children = []
        parent2.metadata = {
            'port': 445,
            'service': 'smb',
            'priority': 'MEDIUM',
            'tags': ['FILE_SHARE'],
            'time_estimate': '10 min'
        }

        subtask2a = Mock()
        subtask2a.id = "subtask-2a"
        subtask2a.name = "Run enum4linux"
        subtask2a.status = "pending"
        subtask2a.children = []
        subtask2a.parent = parent2
        subtask2a.metadata = {
            'port': 445,
            'service': 'smb',
            'priority': 'MEDIUM',
            'tags': ['FILE_SHARE'],
            'time_estimate': '5 min'
        }

        parent2.children = [subtask2a]

        # Setup mock root
        root = Mock()
        root.id = "root"
        root.children = [parent1, parent2]

        # Mock get_all_tasks() to return all tasks (including subtasks)
        root.get_all_tasks.return_value = [parent1, subtask1a, subtask1b, parent2, subtask2a]

        profile.task_tree = root
        profile.target = "192.168.45.100"

        return profile, [parent1, subtask1a, subtask1b, parent2, subtask2a]

    def test_flat_view_shows_only_parents(self, mock_profile_with_hierarchy):
        """Test flat view filters to only parent tasks"""
        profile, all_tasks = mock_profile_with_hierarchy

        panel, choices = TaskListPanel.render(
            profile,
            show_hierarchy=False,
            page_size=10
        )

        # In flat view, only parent tasks should be selectable
        task_choices = [c for c in choices if 'task' in c]

        # Should have exactly 2 parent tasks
        assert len(task_choices) == 2

        # Check that only parent tasks are in choices
        task_ids = [c['task'].id for c in task_choices]
        assert "parent-1" in task_ids
        assert "parent-2" in task_ids
        assert "subtask-1a" not in task_ids
        assert "subtask-1b" not in task_ids
        assert "subtask-2a" not in task_ids

    def test_tree_view_shows_all_tasks(self, mock_profile_with_hierarchy):
        """Test tree view displays all tasks including subtasks"""
        profile, all_tasks = mock_profile_with_hierarchy

        panel, choices = TaskListPanel.render(
            profile,
            show_hierarchy=True,
            page_size=10
        )

        # Panel should render (contains all tasks visually)
        assert panel is not None

        # But choices should only contain parent tasks
        task_choices = [c for c in choices if 'task' in c]
        assert len(task_choices) == 2

    def test_tree_view_only_parents_selectable(self, mock_profile_with_hierarchy):
        """Test tree view only allows selecting parent tasks"""
        profile, all_tasks = mock_profile_with_hierarchy

        panel, choices = TaskListPanel.render(
            profile,
            show_hierarchy=True,
            page_size=10
        )

        # Only parent tasks should be selectable
        task_choices = [c for c in choices if 'task' in c]

        # Verify only parents
        task_ids = [c['task'].id for c in task_choices]
        assert "parent-1" in task_ids
        assert "parent-2" in task_ids
        assert "subtask-1a" not in task_ids
        assert "subtask-1b" not in task_ids

    def test_toggle_message_explains_views(self, mock_profile_with_hierarchy):
        """Test toggle message clarifies view differences"""
        profile, all_tasks = mock_profile_with_hierarchy

        # Flat view
        panel_flat, choices_flat = TaskListPanel.render(
            profile,
            show_hierarchy=False
        )

        # Tree view
        panel_tree, choices_tree = TaskListPanel.render(
            profile,
            show_hierarchy=True
        )

        # Both should have toggle choice
        toggle_flat = [c for c in choices_flat if c['id'] == 'toggle-tree'][0]
        toggle_tree = [c for c in choices_tree if c['id'] == 'toggle-tree'][0]

        # Messages should be different and descriptive
        assert 'flat' in toggle_flat['label'].lower()
        assert 'tree' in toggle_tree['label'].lower()
        assert toggle_flat['label'] != toggle_tree['label']

    def test_parent_task_numbering(self, mock_profile_with_hierarchy):
        """Test parent tasks are numbered sequentially in both views"""
        profile, all_tasks = mock_profile_with_hierarchy

        # Flat view
        panel_flat, choices_flat = TaskListPanel.render(
            profile,
            show_hierarchy=False
        )

        # Tree view
        panel_tree, choices_tree = TaskListPanel.render(
            profile,
            show_hierarchy=True
        )

        # Both should have same parent count
        task_choices_flat = [c for c in choices_flat if 'task' in c]
        task_choices_tree = [c for c in choices_tree if 'task' in c]

        assert len(task_choices_flat) == len(task_choices_tree) == 2

    def test_hierarchy_pagination_keeps_groups_together(self):
        """Test that parent-child groups are never split across pages"""
        profile = Mock()

        # Create 3 parent tasks with varying number of subtasks
        # Parent 1: 3 subtasks
        # Parent 2: 5 subtasks
        # Parent 3: 2 subtasks
        # Total: 3 parents + 10 subtasks = 13 tasks

        tasks = []
        for parent_num in range(1, 4):
            parent = Mock()
            parent.id = f"parent-{parent_num}"
            parent.name = f"Parent Task {parent_num}"
            parent.status = "pending"
            parent.children = []
            parent.metadata = {'port': 80, 'priority': 'HIGH', 'tags': []}

            # Varying subtask counts
            subtask_count = [3, 5, 2][parent_num - 1]
            for sub_num in range(subtask_count):
                subtask = Mock()
                subtask.id = f"parent-{parent_num}-sub-{sub_num}"
                subtask.name = f"Subtask {sub_num} of Parent {parent_num}"
                subtask.status = "pending"
                subtask.children = []
                subtask.parent = parent
                subtask.metadata = {'port': 80, 'priority': 'HIGH', 'tags': []}
                parent.children.append(subtask)

            tasks.append(parent)

        root = Mock()
        root.id = "root"
        root.children = tasks
        root.get_all_tasks.return_value = [p for p in tasks] + [
            c for p in tasks for c in p.children
        ]

        profile.task_tree = root
        profile.target = "192.168.45.100"

        # Render with small page size to force pagination
        # Page size of 8: Should fit parent1+subtasks (4 tasks), parent2+subtasks (6 tasks) = 10 tasks
        # But parent2 won't fit on page 1, so page 1 = parent1 only (4 tasks)
        panel, choices = TaskListPanel.render(
            profile,
            show_hierarchy=True,
            page=1,
            page_size=8
        )

        # Page 1 should contain parent-1 and all its subtasks
        # Should NOT contain any tasks from parent-2
        task_choices = [c for c in choices if 'task' in c]

        # Should have only 1 parent (parent-1) selectable on page 1
        assert len(task_choices) == 1
        assert task_choices[0]['task'].id == "parent-1"

    def test_default_page_size_is_twenty(self):
        """Test that default page size is 20"""
        profile = Mock()

        # Create 25 parent tasks (no subtasks)
        tasks = []
        for i in range(25):
            task = Mock()
            task.id = f"task-{i}"
            task.name = f"Task {i}"
            task.status = "pending"
            task.children = []
            task.metadata = {'port': 80, 'priority': 'HIGH', 'tags': []}
            tasks.append(task)

        root = Mock()
        root.id = "root"
        root.children = tasks
        root.get_all_tasks.return_value = tasks

        profile.task_tree = root
        profile.target = "192.168.45.100"

        # Render without specifying page_size (should default to 20)
        panel, choices = TaskListPanel.render(
            profile,
            show_hierarchy=False,
            page=1
        )

        # Should have 20 tasks on page 1
        task_choices = [c for c in choices if 'task' in c]
        assert len(task_choices) == 20

        # Should have "next page" option
        choice_ids = [c['id'] for c in choices]
        assert 'next-page' in choice_ids
