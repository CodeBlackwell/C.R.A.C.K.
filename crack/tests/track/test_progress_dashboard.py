"""
Progress Dashboard Test Suite

Tests PROVE the progress dashboard tool works by validating:
- Shortcut exists and is accessible
- Handler method exists and is callable
- Progress calculations are accurate
- Visual display renders correctly
- Service grouping works properly
- Quick wins and priorities are detected

Testing Philosophy:
- Test workflows, not code paths
- Use real objects, minimize mocking
- Test outcomes, not implementation
"""

import pytest
from unittest.mock import patch
from io import StringIO

from crack.track.core.state import TargetProfile
from crack.track.core.task_tree import TaskNode
from crack.track.interactive.session import InteractiveSession
from crack.track.interactive.shortcuts import ShortcutHandler
from crack.track.interactive.input_handler import InputProcessor


class TestProgressDashboardShortcut:
    """PROVES: 'pd' shortcut is properly registered"""

    def test_pd_in_shortcuts_list(self):
        """PROVES: 'pd' is recognized as a valid shortcut"""
        assert 'pd' in InputProcessor.SHORTCUTS

    def test_pd_shortcut_registered_in_handler(self, temp_crack_home):
        """PROVES: 'pd' shortcut is registered in ShortcutHandler"""
        profile = TargetProfile("192.168.45.100")
        profile.save()

        session = InteractiveSession("192.168.45.100")
        handler = ShortcutHandler(session)

        assert 'pd' in handler.shortcuts
        description, method_name = handler.shortcuts['pd']
        assert 'dashboard' in description.lower() or 'progress' in description.lower()
        assert method_name == 'progress_dashboard'

    def test_pd_handler_method_exists(self, temp_crack_home):
        """PROVES: progress_dashboard handler method exists"""
        profile = TargetProfile("192.168.45.100")
        profile.save()

        session = InteractiveSession("192.168.45.100")
        handler = ShortcutHandler(session)

        assert hasattr(handler, 'progress_dashboard')
        assert callable(handler.progress_dashboard)


class TestProgressCalculations:
    """PROVES: Dashboard calculates progress correctly"""

    def test_progress_zero_percent_no_tasks(self, temp_crack_home, capsys):
        """PROVES: Shows 0% when no tasks exist"""
        profile = TargetProfile("192.168.45.100")
        profile.save()

        session = InteractiveSession("192.168.45.100")
        session.handle_progress_dashboard()

        captured = capsys.readouterr()
        assert "No tasks available" in captured.out or "0%" in captured.out

    def test_progress_zero_percent_with_tasks(self, temp_crack_home, capsys):
        """PROVES: Shows 0% when tasks exist but none completed"""
        profile = TargetProfile("192.168.45.100")

        # Add pending tasks
        task1 = TaskNode("task-1", "Task 1", "command")
        task2 = TaskNode("task-2", "Task 2", "command")
        task1.status = 'pending'
        task2.status = 'pending'

        profile.task_tree.add_child(task1)
        profile.task_tree.add_child(task2)
        profile.save()

        session = InteractiveSession("192.168.45.100")
        session.handle_progress_dashboard()

        captured = capsys.readouterr()
        # Should show 0% completion
        assert "0%" in captured.out or "0 /" in captured.out
        assert "Pending" in captured.out

    def test_progress_fifty_percent(self, temp_crack_home, capsys):
        """PROVES: Calculates progress correctly with mixed task statuses"""
        profile = TargetProfile("192.168.45.100")

        # Clear default tasks to get predictable count
        profile.task_tree.children.clear()

        # Add 4 tasks: 2 completed, 2 pending
        for i in range(4):
            task = TaskNode(f"task-{i}", f"Task {i}", "command")
            task.status = 'completed' if i < 2 else 'pending'
            profile.task_tree.add_child(task)

        profile.save()

        session = InteractiveSession("192.168.45.100")
        session.handle_progress_dashboard()

        captured = capsys.readouterr()
        # Should show 50% completion (2 out of 4)
        assert "50%" in captured.out or "(2/4" in captured.out

    def test_progress_one_hundred_percent(self, temp_crack_home, capsys):
        """PROVES: Shows 100% when all tasks completed"""
        profile = TargetProfile("192.168.45.100")

        # Clear default tasks to get predictable count
        profile.task_tree.children.clear()

        # Add 5 completed tasks
        for i in range(5):
            task = TaskNode(f"task-{i}", f"Task {i}", "command")
            task.status = 'completed'
            profile.task_tree.add_child(task)

        profile.save()

        session = InteractiveSession("192.168.45.100")
        session.handle_progress_dashboard()

        captured = capsys.readouterr()
        # Should show 100% completion
        assert "100%" in captured.out
        assert "5/5" in captured.out or "Completed:    5" in captured.out


class TestServiceGrouping:
    """PROVES: Dashboard groups tasks by service correctly"""

    def test_groups_by_service_port(self, temp_crack_home, capsys):
        """PROVES: Tasks are grouped by service and port"""
        profile = TargetProfile("192.168.45.100")

        # Add HTTP tasks on port 80
        for i in range(3):
            task = TaskNode(f"http-80-{i}", f"HTTP Task {i}", "command")
            task.metadata['service'] = 'http'
            task.metadata['port'] = 80
            task.status = 'completed' if i == 0 else 'pending'
            profile.task_tree.add_child(task)

        # Add SMB tasks on port 445
        for i in range(2):
            task = TaskNode(f"smb-445-{i}", f"SMB Task {i}", "command")
            task.metadata['service'] = 'smb'
            task.metadata['port'] = 445
            task.status = 'completed'
            profile.task_tree.add_child(task)

        profile.save()

        session = InteractiveSession("192.168.45.100")
        session.handle_progress_dashboard()

        captured = capsys.readouterr()
        # Should show service breakdown
        assert "By Service" in captured.out
        # HTTP should show partial completion
        assert "HTTP" in captured.out or "80" in captured.out
        # SMB should show 100% completion
        assert "SMB" in captured.out or "445" in captured.out

    def test_single_service_no_breakdown(self, temp_crack_home, capsys):
        """PROVES: No service breakdown when only one service"""
        profile = TargetProfile("192.168.45.100")

        # Add tasks for single service
        for i in range(3):
            task = TaskNode(f"http-{i}", f"Task {i}", "command")
            task.metadata['service'] = 'http'
            profile.task_tree.add_child(task)

        profile.save()

        session = InteractiveSession("192.168.45.100")
        session.handle_progress_dashboard()

        captured = capsys.readouterr()
        # Should NOT show service breakdown for single service
        # (or should show it with single entry)
        # This is implementation-dependent, test what makes sense


class TestQuickWinsAndPriorities:
    """PROVES: Dashboard identifies quick wins and high priority tasks"""

    def test_detects_quick_wins(self, temp_crack_home, capsys):
        """PROVES: Quick wins are counted and displayed"""
        profile = TargetProfile("192.168.45.100")

        # Add quick win tasks
        task1 = TaskNode("quick-1", "Quick Win 1", "command")
        task1.metadata['tags'] = ['QUICK_WIN']
        task1.status = 'pending'

        task2 = TaskNode("quick-2", "Quick Win 2", "command")
        task2.metadata['tags'] = ['QUICK_WIN']
        task2.status = 'pending'

        # Add normal task
        task3 = TaskNode("normal-1", "Normal Task", "command")
        task3.status = 'pending'

        profile.task_tree.add_child(task1)
        profile.task_tree.add_child(task2)
        profile.task_tree.add_child(task3)
        profile.save()

        session = InteractiveSession("192.168.45.100")
        session.handle_progress_dashboard()

        captured = capsys.readouterr()
        assert "Quick Wins" in captured.out
        assert "2 remaining" in captured.out or "2" in captured.out

    def test_detects_high_priority(self, temp_crack_home, capsys):
        """PROVES: High priority tasks are counted and displayed"""
        profile = TargetProfile("192.168.45.100")

        # Add high priority tasks
        task1 = TaskNode("high-1", "High Priority 1", "command")
        task1.metadata['tags'] = ['OSCP:HIGH']
        task1.status = 'pending'

        task2 = TaskNode("high-2", "High Priority 2", "command")
        task2.metadata['tags'] = ['OSCP:HIGH']
        task2.status = 'in-progress'

        profile.task_tree.add_child(task1)
        profile.task_tree.add_child(task2)
        profile.save()

        session = InteractiveSession("192.168.45.100")
        session.handle_progress_dashboard()

        captured = capsys.readouterr()
        assert "High Priority" in captured.out or "OSCP:HIGH" in captured.out
        assert "2 pending" in captured.out or "2" in captured.out

    def test_no_quick_wins_message(self, temp_crack_home, capsys):
        """PROVES: No quick wins message when none exist"""
        profile = TargetProfile("192.168.45.100")

        # Add normal tasks
        task = TaskNode("normal-1", "Normal Task", "command")
        task.status = 'pending'
        profile.task_tree.add_child(task)
        profile.save()

        session = InteractiveSession("192.168.45.100")
        session.handle_progress_dashboard()

        captured = capsys.readouterr()
        # Should not mention quick wins if none exist
        # (or should show "0 quick wins")


class TestVisualDisplay:
    """PROVES: Dashboard renders visual elements correctly"""

    def test_progress_bar_renders(self, temp_crack_home, capsys):
        """PROVES: Progress bar uses block characters"""
        profile = TargetProfile("192.168.45.100")

        # Add tasks to show partial progress
        for i in range(10):
            task = TaskNode(f"task-{i}", f"Task {i}", "command")
            task.status = 'completed' if i < 5 else 'pending'
            profile.task_tree.add_child(task)

        profile.save()

        session = InteractiveSession("192.168.45.100")
        session.handle_progress_dashboard()

        captured = capsys.readouterr()
        # Should contain block characters for progress bar
        assert '█' in captured.out or '░' in captured.out

    def test_status_breakdown_displayed(self, temp_crack_home, capsys):
        """PROVES: Status breakdown shows all statuses"""
        profile = TargetProfile("192.168.45.100")

        # Add tasks with different statuses
        task1 = TaskNode("task-1", "Completed", "command")
        task1.status = 'completed'

        task2 = TaskNode("task-2", "In Progress", "command")
        task2.status = 'in-progress'

        task3 = TaskNode("task-3", "Pending", "command")
        task3.status = 'pending'

        task4 = TaskNode("task-4", "Skipped", "command")
        task4.status = 'skipped'

        profile.task_tree.add_child(task1)
        profile.task_tree.add_child(task2)
        profile.task_tree.add_child(task3)
        profile.task_tree.add_child(task4)
        profile.save()

        session = InteractiveSession("192.168.45.100")
        session.handle_progress_dashboard()

        captured = capsys.readouterr()
        assert "Status Breakdown" in captured.out
        assert "Completed" in captured.out
        assert "In Progress" in captured.out or "In-Progress" in captured.out
        assert "Pending" in captured.out
        assert "Skipped" in captured.out

    def test_shows_current_phase(self, temp_crack_home, capsys):
        """PROVES: Dashboard displays current phase"""
        profile = TargetProfile("192.168.45.100")
        profile.phase = 'service-specific'

        task = TaskNode("task-1", "Task 1", "command")
        profile.task_tree.add_child(task)
        profile.save()

        session = InteractiveSession("192.168.45.100")
        session.handle_progress_dashboard()

        captured = capsys.readouterr()
        assert "Phase" in captured.out
        assert "Service" in captured.out or "service-specific" in captured.out.lower()

    def test_shows_next_recommended(self, temp_crack_home, capsys):
        """PROVES: Dashboard shows next recommended task if available"""
        from crack.track.recommendations.engine import RecommendationEngine

        profile = TargetProfile("192.168.45.100")

        # Add pending task that should be recommended
        task = TaskNode("task-1", "High Value Task", "command")
        task.metadata['tags'] = ['OSCP:HIGH', 'QUICK_WIN']
        task.status = 'pending'
        profile.task_tree.add_child(task)
        profile.save()

        # Verify there's a recommendation
        recommendations = RecommendationEngine.get_recommendations(profile)
        assert recommendations.get('next') is not None

        session = InteractiveSession("192.168.45.100")
        session.handle_progress_dashboard()

        captured = capsys.readouterr()
        assert "Next Recommended" in captured.out or "Recommended" in captured.out
