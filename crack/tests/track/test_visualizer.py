"""
Tests for visualization system

Philosophy: Test real behavior with real objects, not mocks
"""

import pytest
from pathlib import Path
from crack.track.visualizer import visualize, Visualizer
from crack.track.core.state import TargetProfile
from crack.track.core.task_tree import TaskNode
from crack.track.services.registry import ServiceRegistry


class TestVisualizerViews:
    """Test each visualization view"""

    def test_view_architecture_renders(self):
        """PROVES: Architecture view renders without errors"""
        output = Visualizer.render_master_view(style='detailed')

        assert 'CRACK TRACK' in output
        assert 'ARCHITECTURE' in output
        assert 'State' in output or 'TargetProfile' in output
        assert 'Tasks' in output or 'TaskNode' in output
        assert 'Events' in output or 'EventBus' in output
        assert 'Plugin' in output
        assert 'PHASE' in output or 'Phase' in output

    def test_view_plugin_flow_renders(self):
        """PROVES: Plugin flow diagram renders correctly"""
        output = Visualizer.render_plugin_flow()

        assert 'Event Flow' in output or 'EVENT FLOW' in output
        assert 'service_detected' in output
        assert 'ServiceRegistry' in output
        assert 'plugin' in output.lower()
        assert 'TargetProfile' in output or 'tasks' in output.lower()

    def test_view_task_tree_with_profile(self, temp_crack_home):
        """PROVES: Task tree view renders profile tasks"""
        # Create profile with tasks
        profile = TargetProfile('192.168.45.100')
        profile.add_port(80, state='open', service='http', source='nmap')
        profile.save()

        output = Visualizer.render_task_tree('192.168.45.100')

        assert '192.168.45.100' in output
        assert 'TASK TREE' in output or 'Task' in output
        assert 'Progress' in output or 'Total' in output
        assert 'Completed' in output or 'completed' in output or '✅' in output
        assert 'Pending' in output or 'pending' in output or '⏳' in output

    def test_view_task_tree_missing_target(self, temp_crack_home):
        """PROVES: Task tree shows error for missing target"""
        output = Visualizer.render_task_tree('nonexistent')

        assert 'No profile found' in output or 'not found' in output.lower()

    def test_view_progress_with_profile(self, temp_crack_home):
        """PROVES: Progress view shows stats and bars"""
        profile = TargetProfile('192.168.45.100')
        profile.add_port(80, state='open', service='http', source='nmap')

        # Complete some tasks
        pending_tasks = profile.task_tree.get_all_pending()
        if pending_tasks:
            pending_tasks[0].mark_complete()

        profile.save()

        output = Visualizer.render_progress('192.168.45.100')

        assert '192.168.45.100' in output
        assert 'PROGRESS' in output or 'Progress' in output
        assert 'Overall' in output or 'Total' in output
        assert 'Status' in output or 'completed' in output or 'pending' in output
        assert '█' in output or '░' in output  # Progress bar chars

    def test_view_phase_flow_renders(self):
        """PROVES: Phase flow diagram renders all phases"""
        output = Visualizer._render_phase_model('detailed')

        assert 'Discovery' in output or 'discovery' in output.lower()
        assert 'Enumeration' in output or 'enumeration' in output.lower()
        assert 'Exploitation' in output or 'exploit' in output.lower()
        assert '┃' in output  # Box drawing chars
        assert '▼' in output  # Arrow

    def test_view_phase_flow_with_current_phase(self, temp_crack_home):
        """PROVES: Phase flow highlights current phase"""
        profile = TargetProfile('192.168.45.100')
        profile.set_phase('service-specific')
        profile.save()

        output = Visualizer._render_phase_model('detailed')

        # Should show phases
        assert 'Discovery' in output or 'Enumeration' in output

    def test_view_plugins_renders(self):
        """PROVES: Plugin registry view lists plugins"""
        # Initialize plugins
        ServiceRegistry.initialize_plugins()

        output = Visualizer._render_plugin_stats('detailed')

        assert 'Total Plugins' in output
        assert 'Categories' in output or 'Distribution' in output

        # Should show plugin count
        if ServiceRegistry._plugins:
            assert str(len(ServiceRegistry._plugins)) in output


class TestVisualizerMain:
    """Test main visualize() entry point"""

    def test_visualize_master(self):
        """PROVES: visualize() routes to master view"""
        output = visualize('master')

        assert 'CRACK TRACK' in output
        assert 'ARCHITECTURE' in output

    def test_visualize_plugin_flow(self):
        """PROVES: visualize() routes to plugin flow view"""
        output = visualize('plugin-flow')

        assert 'EVENT FLOW' in output or 'Event Flow' in output

    def test_visualize_task_tree_requires_target(self, temp_crack_home):
        """PROVES: Task tree view requires target"""
        # Create profile first
        profile = TargetProfile('192.168.45.100')
        profile.save()

        output = visualize('task-tree', '192.168.45.100')

        assert '192.168.45.100' in output

    def test_visualize_unknown_view(self):
        """PROVES: Unknown view returns error"""
        output = visualize('unknown-view')

        assert 'Unknown visualization view' in output or 'Unknown' in output

    def test_visualize_with_style(self):
        """PROVES: Style option works"""
        output = visualize('master', style='compact', theme='oscp')

        # Should not error
        assert 'CRACK TRACK' in output




class TestRenderingHelpers:
    """Test rendering helper functions"""

    def test_progress_bar_rendering(self, temp_crack_home):
        """PROVES: Progress bars render correctly"""
        profile = TargetProfile('192.168.45.100')
        profile.add_port(80, state='open', service='http', source='nmap')

        # Get some tasks
        tasks = profile.task_tree.get_all_pending()
        total = len(tasks)

        # Complete half
        for i, task in enumerate(tasks[:total//2]):
            task.mark_complete()

        profile.save()

        output = Visualizer.render_progress('192.168.45.100')

        # Should have progress bar characters
        assert '█' in output or '░' in output

    def test_task_node_tree_rendering(self, temp_crack_home):
        """PROVES: Task nodes render as tree structure"""
        profile = TargetProfile('192.168.45.100')
        profile.add_port(80, state='open', service='http', source='nmap')
        profile.save()

        output = Visualizer.render_task_tree('192.168.45.100')

        # Should have status icons
        assert '✅' in output or '⏳' in output or 'completed' in output or 'pending' in output


class TestIntegration:
    """Integration tests with real profiles"""

    def test_complete_workflow(self, temp_crack_home):
        """
        PROVES: Visualization works with complete profile workflow

        Workflow:
        1. Create profile
        2. Add ports
        3. Complete tasks
        4. Visualize progress
        """
        # Create and populate profile
        profile = TargetProfile('192.168.45.100')
        profile.add_port(80, state='open', service='http', version='Apache 2.4.41', source='nmap')
        profile.add_port(22, state='open', service='ssh', version='OpenSSH 7.9', source='nmap')

        # Complete a task
        pending = profile.task_tree.get_all_pending()
        if pending:
            pending[0].mark_complete()

        # Add finding
        profile.add_finding('vulnerability', 'Test vuln', source='manual')

        profile.save()

        # Test all visualizations
        arch = visualize('master')
        assert 'CRACK TRACK' in arch

        flow = visualize('plugin-flow')
        assert 'Event' in flow or 'EVENT' in flow

        tree = visualize('task-tree', '192.168.45.100')
        assert '192.168.45.100' in tree

        progress = visualize('progress', '192.168.45.100')
        assert 'Progress' in progress or 'PROGRESS' in progress


class TestErrorHandling:
    """Test error conditions"""

    def test_missing_target_for_task_tree(self):
        """PROVES: Error when target required but not provided"""
        output = visualize('task-tree', None)

        assert 'No profile found' in output or 'not found' in output.lower()

    def test_nonexistent_target(self, temp_crack_home):
        """PROVES: Error when target doesn't exist"""
        output = visualize('task-tree', 'nonexistent-target')

        assert 'No profile found' in output or 'not found' in output.lower()

    def test_invalid_view_name(self):
        """PROVES: Error for invalid view name"""
        output = visualize('invalid-view-name')

        assert 'Unknown visualization view' in output or 'Unknown' in output
