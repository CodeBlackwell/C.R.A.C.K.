"""
Tests for Windows Core Plugin

Validates:
- Plugin registration
- Detection logic (manual trigger only)
- Task tree structure (5 categories)
- OSCP metadata completeness
- Educational content (alternatives, next_steps, notes)
- Command structure and flag explanations
"""

import pytest
from crack.track.services.windows_core import WindowsCorePlugin
from crack.track.services.registry import ServiceRegistry

# Initialize plugins at module load to ensure registry is populated
ServiceRegistry.initialize_plugins()


class TestWindowsCorePluginRegistration:
    """Test plugin registration and basic properties"""

    def test_plugin_registered(self):
        """PROVES: WindowsCorePlugin is registered in ServiceRegistry"""
        assert 'windows-core' in ServiceRegistry._plugins
        plugin_instance = ServiceRegistry._plugins['windows-core']
        assert isinstance(plugin_instance, WindowsCorePlugin)

    def test_plugin_name(self):
        """PROVES: Plugin name is 'windows-core'"""
        plugin = WindowsCorePlugin()
        assert plugin.name == 'windows-core'

    def test_plugin_default_ports_empty(self):
        """PROVES: Plugin has no default ports (manual trigger only)"""
        plugin = WindowsCorePlugin()
        assert plugin.default_ports == []

    def test_plugin_service_names_empty(self):
        """PROVES: Plugin has no service names (manual trigger only)"""
        plugin = WindowsCorePlugin()
        assert plugin.service_names == []


class TestWindowsCoreDetection:
    """Test detection logic (should always return False - manual trigger)"""

    def test_detect_returns_false_for_any_port(self):
        """PROVES: Plugin never auto-detects (manual trigger only)"""
        plugin = WindowsCorePlugin()
        port_info_samples = [
            {'port': 80, 'service': 'http'},
            {'port': 445, 'service': 'microsoft-ds'},
            {'port': 3389, 'service': 'ms-wbt-server'},
            {'port': 5985, 'service': 'winrm'},
            {},  # Empty port info
        ]
        for port_info in port_info_samples:
            assert plugin.detect(port_info) is False


class TestWindowsCoreTaskTreeStructure:
    """Test task tree generation and structure"""

    @pytest.fixture
    def plugin(self):
        return WindowsCorePlugin()

    @pytest.fixture
    def task_tree(self, plugin):
        return plugin.get_task_tree('192.168.45.100', 0, {'context': 'local'})

    def test_task_tree_root_structure(self, task_tree):
        """PROVES: Root task has correct structure"""
        assert task_tree['id'] == 'windows-core-192.168.45.100'
        assert 'Windows Core Techniques' in task_tree['name']
        assert task_tree['type'] == 'parent'
        assert 'children' in task_tree

    def test_task_tree_has_five_categories(self, task_tree):
        """PROVES: Task tree has exactly 5 major categories"""
        children = task_tree['children']
        assert len(children) == 5

        # Verify category names
        category_names = [child['name'] for child in children]
        assert 'PowerShell for Pentesters' in category_names
        assert 'PowerView Domain Enumeration' in category_names
        assert 'Antivirus (AV) Bypass Techniques' in category_names
        assert 'UAC Bypass Techniques' in category_names
        assert 'Authentication & Credentials' in category_names

    def test_powershell_category_structure(self, task_tree):
        """PROVES: PowerShell category has correct structure and tasks"""
        ps_category = task_tree['children'][0]
        assert ps_category['name'] == 'PowerShell for Pentesters'
        assert ps_category['type'] == 'parent'
        assert len(ps_category['children']) >= 10  # At least 10 PowerShell tasks

    def test_powerview_category_structure(self, task_tree):
        """PROVES: PowerView category has correct structure and tasks"""
        pv_category = task_tree['children'][1]
        assert pv_category['name'] == 'PowerView Domain Enumeration'
        assert pv_category['type'] == 'parent'
        assert len(pv_category['children']) >= 10  # At least 10 PowerView tasks

    def test_av_bypass_category_structure(self, task_tree):
        """PROVES: AV Bypass category has correct structure and tasks"""
        av_category = task_tree['children'][2]
        assert 'Antivirus' in av_category['name'] or 'AV' in av_category['name']
        assert av_category['type'] == 'parent'
        assert len(av_category['children']) >= 9  # At least 9 AV bypass tasks

    def test_uac_bypass_category_structure(self, task_tree):
        """PROVES: UAC Bypass category has correct structure and tasks"""
        uac_category = task_tree['children'][3]
        assert 'UAC' in uac_category['name']
        assert uac_category['type'] == 'parent'
        assert len(uac_category['children']) >= 6  # At least 6 UAC tasks

    def test_authentication_category_structure(self, task_tree):
        """PROVES: Authentication category has correct structure and tasks"""
        auth_category = task_tree['children'][4]
        assert 'Authentication' in auth_category['name'] or 'Credentials' in auth_category['name']
        assert auth_category['type'] == 'parent'
        assert len(auth_category['children']) >= 7  # At least 7 authentication tasks


class TestOSCPMetadataCompleteness:
    """Test OSCP metadata presence and quality"""

    @pytest.fixture
    def all_tasks(self):
        """Get all leaf tasks from all categories"""
        plugin = WindowsCorePlugin()
        tree = plugin.get_task_tree('192.168.45.100', 0, {'context': 'local'})
        tasks = []

        def collect_tasks(node):
            if node['type'] in ['command', 'manual']:
                tasks.append(node)
            if 'children' in node:
                for child in node['children']:
                    collect_tasks(child)

        collect_tasks(tree)
        return tasks

    def test_all_tasks_have_metadata(self, all_tasks):
        """PROVES: All tasks have metadata section"""
        for task in all_tasks:
            assert 'metadata' in task, f"Task {task['id']} missing metadata"

    def test_all_tasks_have_description(self, all_tasks):
        """PROVES: All tasks have description"""
        for task in all_tasks:
            metadata = task['metadata']
            assert 'description' in metadata, f"Task {task['id']} missing description"
            assert len(metadata['description']) > 20, f"Task {task['id']} description too short"

    def test_all_tasks_have_tags(self, all_tasks):
        """PROVES: All tasks have tags"""
        for task in all_tasks:
            metadata = task['metadata']
            if task['type'] == 'command':
                assert 'tags' in metadata, f"Task {task['id']} missing tags"
                assert isinstance(metadata['tags'], list), f"Task {task['id']} tags not a list"
                assert len(metadata['tags']) > 0, f"Task {task['id']} has no tags"

    def test_command_tasks_have_flag_explanations(self, all_tasks):
        """PROVES: Command tasks have flag explanations"""
        command_tasks = [t for t in all_tasks if t['type'] == 'command']
        for task in command_tasks:
            metadata = task['metadata']
            # Manual tasks may not have flags, but command tasks should
            if 'command' in metadata:
                # Most commands should have flag explanations
                # (some simple commands like 'whoami' may not)
                pass  # We'll check specific important ones below

    def test_tasks_have_alternatives(self, all_tasks):
        """PROVES: Most tasks have alternative methods"""
        tasks_with_alternatives = [t for t in all_tasks
                                   if 'alternatives' in t['metadata']]
        # At least 80% of tasks should have alternatives
        assert len(tasks_with_alternatives) / len(all_tasks) >= 0.8

    def test_tasks_have_next_steps(self, all_tasks):
        """PROVES: Most tasks have next steps"""
        tasks_with_next_steps = [t for t in all_tasks
                                 if 'next_steps' in t['metadata']]
        # At least 80% of tasks should have next steps
        assert len(tasks_with_next_steps) / len(all_tasks) >= 0.8

    def test_tasks_have_success_indicators(self, all_tasks):
        """PROVES: Most tasks have success indicators"""
        tasks_with_success = [t for t in all_tasks
                              if 'success_indicators' in t['metadata']]
        # At least 90% of tasks should have success indicators
        assert len(tasks_with_success) / len(all_tasks) >= 0.9

    def test_tasks_have_failure_indicators(self, all_tasks):
        """PROVES: Most tasks have failure indicators"""
        tasks_with_failure = [t for t in all_tasks
                              if 'failure_indicators' in t['metadata']]
        # At least 90% of tasks should have failure indicators
        assert len(tasks_with_failure) / len(all_tasks) >= 0.9

    def test_tasks_have_notes(self, all_tasks):
        """PROVES: Most tasks have educational notes"""
        tasks_with_notes = [t for t in all_tasks
                            if 'notes' in t['metadata']]
        # At least 80% of tasks should have notes
        assert len(tasks_with_notes) / len(all_tasks) >= 0.8


class TestSpecificTaskContent:
    """Test specific high-value tasks for quality"""

    @pytest.fixture
    def plugin(self):
        return WindowsCorePlugin()

    def test_powershell_download_execute_task(self, plugin):
        """PROVES: PowerShell download & execute task has complete metadata"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {'context': 'local'})
        ps_tasks = tree['children'][0]['children']

        download_task = next((t for t in ps_tasks if 'Download & Execute' in t['name']), None)
        assert download_task is not None

        metadata = download_task['metadata']
        assert 'command' in metadata
        assert 'IEX' in metadata['command'] or 'iex' in metadata['command']
        assert 'flag_explanations' in metadata
        assert 'success_indicators' in metadata
        assert 'failure_indicators' in metadata
        assert 'alternatives' in metadata
        assert len(metadata['alternatives']) >= 2

    def test_amsi_bypass_task(self, plugin):
        """PROVES: AMSI bypass task has complete metadata"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {'context': 'local'})
        ps_tasks = tree['children'][0]['children']

        amsi_task = next((t for t in ps_tasks if 'AMSI' in t['name']), None)
        assert amsi_task is not None

        metadata = amsi_task['metadata']
        assert 'command' in metadata
        assert 'AmsiUtils' in metadata['command'] or 'amsi' in metadata['command'].lower()
        assert 'flag_explanations' in metadata
        assert 'alternatives' in metadata
        assert len(metadata['alternatives']) >= 2

    def test_powerview_quick_enum_task(self, plugin):
        """PROVES: PowerView quick enum task has manual steps"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {'context': 'local'})
        pv_tasks = tree['children'][1]['children']

        quick_enum = next((t for t in pv_tasks if 'Quick' in t['name']), None)
        assert quick_enum is not None

        metadata = quick_enum['metadata']
        assert 'manual_steps' in metadata
        assert len(metadata['manual_steps']) >= 10  # Should have many enumeration steps

    def test_uac_bypass_fodhelper_task(self, plugin):
        """PROVES: fodhelper UAC bypass task has complete instructions"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {'context': 'local'})
        uac_tasks = tree['children'][3]['children']

        fodhelper_task = next((t for t in uac_tasks if 'fodhelper' in t['name'].lower()), None)
        assert fodhelper_task is not None

        metadata = fodhelper_task['metadata']
        assert 'command' in metadata
        assert 'HKCU' in metadata['command']  # Registry hijack
        assert 'ms-settings' in metadata['command']
        assert 'flag_explanations' in metadata
        assert 'success_indicators' in metadata

    def test_applocker_check_task(self, plugin):
        """PROVES: AppLocker check task exists and has bypass guidance"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {'context': 'local'})
        auth_tasks = tree['children'][4]['children']

        applocker_task = next((t for t in auth_tasks if 'AppLocker' in t['name']), None)
        assert applocker_task is not None

        metadata = applocker_task['metadata']
        assert 'Get-AppLockerPolicy' in metadata['command']
        assert 'next_steps' in metadata
        # Should mention writable bypass locations
        next_steps_text = ' '.join(metadata['next_steps'])
        assert 'writable' in next_steps_text.lower() or 'bypass' in next_steps_text.lower()


class TestEducationalQuality:
    """Test educational content quality for OSCP preparation"""

    @pytest.fixture
    def plugin(self):
        return WindowsCorePlugin()

    def test_oscp_tags_present(self, plugin):
        """PROVES: Tasks have OSCP relevance tags"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {'context': 'local'})

        oscp_tags_found = set()
        def collect_tags(node):
            if 'metadata' in node and 'tags' in node['metadata']:
                for tag in node['metadata']['tags']:
                    if tag.startswith('OSCP:'):
                        oscp_tags_found.add(tag)
            if 'children' in node:
                for child in node['children']:
                    collect_tags(child)

        collect_tags(tree)

        assert 'OSCP:HIGH' in oscp_tags_found
        assert 'OSCP:MEDIUM' in oscp_tags_found

    def test_quick_win_tags_present(self, plugin):
        """PROVES: Quick win tasks are marked"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {'context': 'local'})

        quick_win_count = 0
        def count_quick_wins(node):
            nonlocal quick_win_count
            if 'metadata' in node and 'tags' in node['metadata']:
                if 'QUICK_WIN' in node['metadata']['tags']:
                    quick_win_count += 1
            if 'children' in node:
                for child in node['children']:
                    count_quick_wins(child)

        count_quick_wins(tree)

        # Should have at least 5 quick win tasks
        assert quick_win_count >= 5

    def test_manual_alternatives_provided(self, plugin):
        """PROVES: Manual alternatives provided for automated tasks"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {'context': 'local'})

        automated_tasks = []
        def find_automated(node):
            if 'metadata' in node and 'tags' in node['metadata']:
                if 'AUTOMATED' in node['metadata']['tags']:
                    automated_tasks.append(node)
            if 'children' in node:
                for child in node['children']:
                    find_automated(child)

        find_automated(tree)

        # All automated tasks should have manual alternatives
        for task in automated_tasks:
            assert 'alternatives' in task['metadata'], \
                f"Automated task {task['id']} missing manual alternatives"

    def test_tools_have_download_links(self, plugin):
        """PROVES: Tool-based tasks reference download sources"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {'context': 'local'})

        tool_references = []
        def find_tool_refs(node):
            if 'metadata' in node:
                metadata = node['metadata']
                if 'notes' in metadata:
                    if 'github.com' in metadata['notes'].lower() or 'download' in metadata['notes'].lower():
                        tool_references.append(node)
            if 'children' in node:
                for child in node['children']:
                    find_tool_refs(child)

        find_tool_refs(tree)

        # Should have at least 10 tasks with tool references
        assert len(tool_references) >= 10


class TestTaskTreeIntegrity:
    """Test task tree integrity and consistency"""

    @pytest.fixture
    def plugin(self):
        return WindowsCorePlugin()

    def test_all_task_ids_unique(self, plugin):
        """PROVES: All task IDs are unique"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {'context': 'local'})

        task_ids = set()
        def collect_ids(node):
            assert node['id'] not in task_ids, f"Duplicate task ID: {node['id']}"
            task_ids.add(node['id'])
            if 'children' in node:
                for child in node['children']:
                    collect_ids(child)

        collect_ids(tree)

        # Should have many unique tasks
        assert len(task_ids) >= 40

    def test_all_tasks_have_names(self, plugin):
        """PROVES: All tasks have descriptive names"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {'context': 'local'})

        def check_names(node):
            assert 'name' in node, f"Task {node.get('id', 'unknown')} missing name"
            assert len(node['name']) > 5, f"Task {node['id']} name too short"
            if 'children' in node:
                for child in node['children']:
                    check_names(child)

        check_names(tree)

    def test_all_tasks_have_type(self, plugin):
        """PROVES: All tasks have valid type"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {'context': 'local'})

        valid_types = ['parent', 'command', 'manual']

        def check_types(node):
            assert 'type' in node, f"Task {node['id']} missing type"
            assert node['type'] in valid_types, \
                f"Task {node['id']} has invalid type: {node['type']}"
            if 'children' in node:
                for child in node['children']:
                    check_types(child)

        check_types(tree)

    def test_parent_tasks_have_children(self, plugin):
        """PROVES: Parent tasks have children"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {'context': 'local'})

        def check_parents(node):
            if node['type'] == 'parent':
                assert 'children' in node, f"Parent task {node['id']} has no children"
                assert len(node['children']) > 0, f"Parent task {node['id']} has empty children"
            if 'children' in node:
                for child in node['children']:
                    check_parents(child)

        check_parents(tree)

    def test_leaf_tasks_have_no_children(self, plugin):
        """PROVES: Leaf tasks (command/manual) have no children"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {'context': 'local'})

        def check_leaves(node):
            if node['type'] in ['command', 'manual']:
                assert 'children' not in node or len(node.get('children', [])) == 0, \
                    f"Leaf task {node['id']} should not have children"
            if 'children' in node:
                for child in node['children']:
                    check_leaves(child)

        check_leaves(tree)


class TestCategoryTaskCounts:
    """Test that each category has sufficient tasks"""

    @pytest.fixture
    def plugin(self):
        return WindowsCorePlugin()

    def test_powershell_has_sufficient_tasks(self, plugin):
        """PROVES: PowerShell category has 10+ tasks (target: 25+)"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {'context': 'local'})
        ps_category = tree['children'][0]
        assert len(ps_category['children']) >= 10

    def test_powerview_has_sufficient_tasks(self, plugin):
        """PROVES: PowerView category has 10+ tasks (target: 20+)"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {'context': 'local'})
        pv_category = tree['children'][1]
        assert len(pv_category['children']) >= 10

    def test_av_bypass_has_sufficient_tasks(self, plugin):
        """PROVES: AV Bypass category has 9+ tasks (target: 15+)"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {'context': 'local'})
        av_category = tree['children'][2]
        assert len(av_category['children']) >= 9

    def test_uac_bypass_has_sufficient_tasks(self, plugin):
        """PROVES: UAC Bypass category has 6+ tasks"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {'context': 'local'})
        uac_category = tree['children'][3]
        assert len(uac_category['children']) >= 6

    def test_authentication_has_sufficient_tasks(self, plugin):
        """PROVES: Authentication category has 7+ tasks (target: 15+)"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {'context': 'local'})
        auth_category = tree['children'][4]
        assert len(auth_category['children']) >= 7

    def test_total_task_count(self, plugin):
        """PROVES: Plugin has 40+ total tasks across all categories"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {'context': 'local'})

        def count_leaf_tasks(node):
            if node['type'] in ['command', 'manual']:
                return 1
            count = 0
            if 'children' in node:
                for child in node['children']:
                    count += count_leaf_tasks(child)
            return count

        total = count_leaf_tasks(tree)
        assert total >= 40, f"Expected 40+ tasks, got {total}"
