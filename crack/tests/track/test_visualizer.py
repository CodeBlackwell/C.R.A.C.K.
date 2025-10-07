"""
Tests for visualization system

Philosophy: Test real behavior with real objects, not mocks
"""

import pytest
from pathlib import Path
from crack.track.visualizer import (
    visualize,
    view_architecture,
    view_plugin_flow,
    view_task_tree,
    view_progress,
    view_phase_flow,
    view_decision_tree,
    view_plugins
)
from crack.track.visualizer.themes import colorize, strip_colors, get_theme_names
from crack.track.core.state import TargetProfile
from crack.track.core.task_tree import TaskNode
from crack.track.services.registry import ServiceRegistry


class TestVisualizerViews:
    """Test each visualization view"""

    def test_view_architecture_renders(self):
        """PROVES: Architecture view renders without errors"""
        output = view_architecture()

        assert 'CRACK Track Architecture' in output
        assert 'Core Layer' in output
        assert 'TargetProfile' in output
        assert 'TaskNode' in output
        assert 'EventBus' in output
        assert 'Plugin Layer' in output
        assert 'Phase System' in output

    def test_view_plugin_flow_renders(self):
        """PROVES: Plugin flow diagram renders correctly"""
        output = view_plugin_flow()

        assert '[Nmap Parser]' in output
        assert 'emit: port_discovered' in output
        assert 'emit: service_detected' in output
        assert '[EventBus]' in output
        assert '[ServiceRegistry]' in output
        assert '[Plugin]' in output
        assert '[TargetProfile]' in output

    def test_view_task_tree_with_profile(self, temp_crack_home):
        """PROVES: Task tree view renders profile tasks"""
        # Create profile with tasks
        profile = TargetProfile('192.168.45.100')
        profile.add_port(80, state='open', service='http', source='nmap')
        profile.save()

        output = view_task_tree('192.168.45.100')

        assert '192.168.45.100 Task Tree' in output
        assert 'Progress:' in output
        assert 'Legend:' in output
        assert 'Completed' in output
        assert 'Pending' in output

    def test_view_task_tree_missing_target(self, temp_crack_home):
        """PROVES: Task tree shows error for missing target"""
        output = view_task_tree('nonexistent')

        assert 'Error' in output
        assert 'not found' in output

    def test_view_progress_with_profile(self, temp_crack_home):
        """PROVES: Progress view shows stats and bars"""
        profile = TargetProfile('192.168.45.100')
        profile.add_port(80, state='open', service='http', source='nmap')

        # Complete some tasks
        pending_tasks = profile.task_tree.get_all_pending()
        if pending_tasks:
            pending_tasks[0].mark_complete()

        profile.save()

        output = view_progress('192.168.45.100')

        assert '192.168.45.100' in output
        assert 'Phase:' in output
        assert 'Overall Progress:' in output
        assert 'By Status:' in output
        assert '█' in output or '░' in output  # Progress bar chars

    def test_view_phase_flow_renders(self):
        """PROVES: Phase flow diagram renders all phases"""
        output = view_phase_flow()

        assert 'discovery' in output.lower()
        assert 'service' in output.lower()
        assert 'exploit' in output.lower()
        assert '┃' in output  # Box drawing chars
        assert '▼' in output  # Arrow

    def test_view_phase_flow_with_current_phase(self, temp_crack_home):
        """PROVES: Phase flow highlights current phase"""
        profile = TargetProfile('192.168.45.100')
        profile.set_phase('service-specific')
        profile.save()

        output = view_phase_flow('192.168.45.100')

        assert '◄──' in output  # Current phase marker

    def test_view_decision_tree_discovery(self):
        """PROVES: Decision tree view renders tree structure"""
        output = view_decision_tree('discovery')

        assert 'Discovery Phase Decision Tree' in output
        assert '[ROOT:' in output
        assert '?' in output  # Question marker
        assert 'quick-scan' in output or 'full-scan' in output
        assert 'Navigation:' in output

    def test_view_decision_tree_invalid_phase(self):
        """PROVES: Invalid phase returns error"""
        output = view_decision_tree('invalid-phase')

        assert 'Error' in output

    def test_view_plugins_renders(self):
        """PROVES: Plugin registry view lists plugins"""
        # Initialize plugins
        ServiceRegistry.initialize_plugins()

        output = view_plugins()

        assert 'Service Plugin Registry' in output
        assert 'plugins loaded' in output

        # Should show at least some common plugins
        if ServiceRegistry._plugins:
            first_plugin = list(ServiceRegistry._plugins.keys())[0]
            assert first_plugin in output.lower()


class TestVisualizerMain:
    """Test main visualize() entry point"""

    def test_visualize_architecture(self):
        """PROVES: visualize() routes to architecture view"""
        output = visualize('architecture')

        assert 'CRACK Track Architecture' in output

    def test_visualize_plugin_flow(self):
        """PROVES: visualize() routes to plugin flow view"""
        output = visualize('plugin-flow')

        assert 'Nmap Parser' in output

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

        assert 'Error' in output
        assert 'Unknown view' in output

    def test_visualize_with_color(self):
        """PROVES: Color option works (even if not visible in test)"""
        output = visualize('architecture', color=True, theme='oscp')

        # Should not error
        assert 'CRACK Track Architecture' in output


class TestThemes:
    """Test color theme system"""

    def test_colorize_basic(self):
        """PROVES: colorize() applies color codes"""
        text = "[completed]Task Done[/completed]"
        result = colorize(text, 'oscp')

        # Should have ANSI codes
        assert '\033[' in result
        assert 'Task Done' in result

    def test_colorize_multiple_tags(self):
        """PROVES: colorize() handles multiple tags"""
        text = "[completed]Done[/completed] [pending]Todo[/pending]"
        result = colorize(text, 'oscp')

        assert '\033[' in result
        assert 'Done' in result
        assert 'Todo' in result

    def test_colorize_mono_theme(self):
        """PROVES: mono theme strips colors"""
        text = "[completed]Task Done[/completed]"
        result = colorize(text, 'mono')

        # Mono theme has no color codes
        assert '\033[' not in result or result == text.replace('[completed]', '').replace('[/completed]', '')

    def test_strip_colors(self):
        """PROVES: strip_colors() removes ANSI codes"""
        text = "\033[92mGreen Text\033[0m"
        result = strip_colors(text)

        assert '\033[' not in result
        assert 'Green Text' in result

    def test_get_theme_names(self):
        """PROVES: get_theme_names() returns available themes"""
        themes = get_theme_names()

        assert 'oscp' in themes
        assert 'mono' in themes
        assert 'dark' in themes
        assert 'light' in themes


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

        output = view_progress('192.168.45.100')

        # Should have progress bar characters
        assert '█' in output or '░' in output

    def test_task_node_tree_rendering(self, temp_crack_home):
        """PROVES: Task nodes render as tree structure"""
        profile = TargetProfile('192.168.45.100')
        profile.add_port(80, state='open', service='http', source='nmap')
        profile.save()

        output = view_task_tree('192.168.45.100')

        # Should have tree drawing characters
        assert '├─►' in output or '└─►' in output
        assert '[✓]' in output or '[○]' in output  # Status icons


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
        arch = visualize('architecture')
        assert 'CRACK Track Architecture' in arch

        flow = visualize('plugin-flow')
        assert 'EventBus' in flow

        tree = visualize('task-tree', '192.168.45.100')
        assert '192.168.45.100' in tree

        progress = visualize('progress', '192.168.45.100')
        assert 'Progress:' in progress

        phases = visualize('phase-flow', '192.168.45.100')
        assert '◄──' in phases  # Current phase marker

        plugins = visualize('plugins')
        assert 'Plugin Registry' in plugins


class TestErrorHandling:
    """Test error conditions"""

    def test_missing_target_for_task_tree(self):
        """PROVES: Error when target required but not provided"""
        output = visualize('task-tree', None)

        assert 'Error' in output

    def test_nonexistent_target(self, temp_crack_home):
        """PROVES: Error when target doesn't exist"""
        output = visualize('task-tree', 'nonexistent-target')

        assert 'Error' in output or 'not found' in output

    def test_invalid_view_name(self):
        """PROVES: Error for invalid view name"""
        output = visualize('invalid-view-name')

        assert 'Error' in output
        assert 'Unknown view' in output
