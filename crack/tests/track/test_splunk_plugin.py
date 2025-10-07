"""
Tests for Splunk/Splunkd service plugin

PROVES:
- Plugin detects Splunk services on multiple ports
- RCE techniques via custom applications are included
- Free version exploitation is covered
- Privilege escalation guidance is present
- OSCP educational content is comprehensive
"""

import pytest
from crack.track.services.splunk import SplunkPlugin


class TestSplunkPlugin:
    """Test suite for Splunk plugin"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return SplunkPlugin()

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "splunk"

    def test_default_ports(self, plugin):
        """PROVES: Plugin knows both Splunk web (8000) and API (8089) ports"""
        assert 8000 in plugin.default_ports
        assert 8089 in plugin.default_ports

    def test_service_names(self, plugin):
        """PROVES: Plugin recognizes Splunk service name variations"""
        assert 'splunk' in plugin.service_names
        assert 'splunkd' in plugin.service_names

    def test_detect_by_service_name(self, plugin):
        """PROVES: Plugin detects Splunk by service name"""
        port_info = {'service': 'splunk', 'port': 8000}
        assert plugin.detect(port_info) == True

        port_info2 = {'service': 'splunkd', 'port': 8089}
        assert plugin.detect(port_info2) == True

    def test_detect_by_port_8000(self, plugin):
        """PROVES: Plugin detects Splunk on port 8000"""
        port_info = {'service': 'http', 'port': 8000}
        assert plugin.detect(port_info) == True

    def test_detect_by_port_8089(self, plugin):
        """PROVES: Plugin detects Splunk on port 8089"""
        port_info = {'service': 'https', 'port': 8089}
        assert plugin.detect(port_info) == True

    def test_detect_by_product(self, plugin):
        """PROVES: Plugin detects Splunk by product name"""
        port_info = {'service': 'http', 'product': 'Splunk httpd', 'port': 9000}
        assert plugin.detect(port_info) == True

    def test_detect_negative(self, plugin):
        """PROVES: Plugin rejects unrelated services"""
        port_info = {'service': 'http', 'port': 80}
        assert plugin.detect(port_info) == False

    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid structure"""
        tree = plugin.get_task_tree('192.168.45.100', 8000, {'service': 'splunk'})

        # Root structure
        assert 'id' in tree
        assert tree['id'] == 'splunk-enum-8000'
        assert 'name' in tree
        assert 'Splunk' in tree['name']
        assert tree['type'] == 'parent'
        assert 'children' in tree

        # Has substantial tasks
        assert len(tree['children']) >= 5

    def test_service_identification_task(self, plugin):
        """PROVES: Plugin includes service identification task"""
        tree = plugin.get_task_tree('192.168.45.100', 8000, {'service': 'splunk'})

        identify_tasks = [t for t in tree['children'] if 'identify' in t['id'].lower()]
        assert len(identify_tasks) > 0

        task = identify_tasks[0]
        metadata = task.get('metadata', {})

        # Should use curl or similar
        assert 'curl' in metadata.get('command', '').lower() or \
               'http' in metadata.get('command', '').lower()

        # Should be QUICK_WIN
        assert 'QUICK_WIN' in metadata.get('tags', [])

    def test_free_version_check_task(self, plugin):
        """PROVES: Plugin includes critical free version check (no auth vulnerability)"""
        tree = plugin.get_task_tree('192.168.45.100', 8000, {'service': 'splunk'})

        free_tasks = [t for t in tree['children'] if 'free' in t['id'].lower() or 'free' in t.get('name', '').lower()]
        assert len(free_tasks) > 0

        task = free_tasks[0]
        metadata = task.get('metadata', {})

        # Should check licenseState
        command_or_desc = metadata.get('command', '') + metadata.get('description', '')
        assert 'license' in command_or_desc.lower() or 'free' in command_or_desc.lower()

        # Should be marked as OSCP:HIGH (critical vulnerability)
        assert 'OSCP:HIGH' in metadata.get('tags', [])

        # Should explain the vulnerability
        notes = metadata.get('notes', '')
        assert 'no auth' in notes.lower() or 'free version' in notes.lower()

    def test_default_credentials_task(self, plugin):
        """PROVES: Plugin includes default credentials testing"""
        tree = plugin.get_task_tree('192.168.45.100', 8000, {'service': 'splunk'})

        default_creds_tasks = [t for t in tree['children'] if 'default' in t['id'].lower()]
        assert len(default_creds_tasks) > 0

        task = default_creds_tasks[0]
        metadata = task.get('metadata', {})

        # Should test admin:changeme
        assert 'admin' in metadata.get('command', '').lower()
        assert 'changeme' in metadata.get('command', '').lower() or \
               'changeme' in metadata.get('notes', '').lower()

    def test_rce_task_container(self, plugin):
        """PROVES: Plugin includes RCE exploitation section"""
        tree = plugin.get_task_tree('192.168.45.100', 8000, {'service': 'splunk'})

        rce_tasks = [t for t in tree['children'] if 'rce' in t['id'].lower()]
        assert len(rce_tasks) > 0

        rce_container = rce_tasks[0]
        assert rce_container['type'] == 'parent'
        assert len(rce_container['children']) >= 2  # Should have multiple RCE methods

    def test_custom_application_rce(self, plugin):
        """PROVES: Plugin includes custom application RCE technique"""
        tree = plugin.get_task_tree('192.168.45.100', 8000, {'service': 'splunk'})

        # Find RCE tasks
        rce_children = []
        for child in tree['children']:
            if 'rce' in child['id'].lower() and child['type'] == 'parent':
                rce_children = child['children']
                break

        assert len(rce_children) > 0

        # Find custom app task
        app_tasks = [t for t in rce_children if 'app' in t['id'].lower() or 'custom' in t['id'].lower()]
        assert len(app_tasks) > 0

        task = app_tasks[0]
        metadata = task.get('metadata', {})

        # Should mention bin/, default/, inputs.conf
        command_or_notes = metadata.get('command', '') + metadata.get('notes', '')
        assert 'bin/' in command_or_notes
        assert 'inputs.conf' in command_or_notes

        # Should provide script examples
        assert 'python' in command_or_notes.lower() or 'powershell' in command_or_notes.lower()

        # Should be marked as RCE
        assert 'RCE' in metadata.get('tags', [])

    def test_scripted_inputs_guidance(self, plugin):
        """PROVES: Plugin explains scripted inputs mechanism"""
        tree = plugin.get_task_tree('192.168.45.100', 8000, {'service': 'splunk'})

        # Collect all notes
        all_notes = []
        def collect_notes(node):
            notes = node.get('metadata', {}).get('notes', '')
            if notes:
                all_notes.append(notes)
            for child in node.get('children', []):
                collect_notes(child)

        collect_notes(tree)

        combined_notes = ' '.join(all_notes).lower()

        # Should explain scripted inputs
        assert 'scripted input' in combined_notes or 'script://' in combined_notes
        assert 'interval' in combined_notes  # Execution interval

    def test_rest_api_deployment(self, plugin):
        """PROVES: Plugin includes REST API deployment method"""
        tree = plugin.get_task_tree('192.168.45.100', 8000, {'service': 'splunk'})

        # Find REST API tasks
        api_tasks = []
        def find_api(node):
            if 'api' in node.get('id', '').lower():
                api_tasks.append(node)
            for child in node.get('children', []):
                find_api(child)

        find_api(tree)

        assert len(api_tasks) > 0

        # Check for deployment via API
        api_deploy_tasks = [t for t in api_tasks if 'deploy' in t.get('id', '').lower() or \
                                                     'services/apps' in t.get('metadata', {}).get('command', '')]
        assert len(api_deploy_tasks) > 0

        task = api_deploy_tasks[0]
        metadata = task.get('metadata', {})

        # Should use curl with app upload
        assert 'curl' in metadata.get('command', '').lower()
        assert '/services/apps' in metadata.get('command', '')

    def test_privilege_escalation_task(self, plugin):
        """PROVES: Plugin includes privilege escalation guidance"""
        tree = plugin.get_task_tree('192.168.45.100', 8000, {'service': 'splunk'})

        privesc_tasks = [t for t in tree['children'] if 'privesc' in t['id'].lower() or 'privilege' in t.get('name', '').lower()]
        assert len(privesc_tasks) > 0

        task = privesc_tasks[0]
        metadata = task.get('metadata', {})

        # Should have substantial guidance
        notes = metadata.get('notes', '')
        assert len(notes) > 200

        # Should mention key concepts
        assert 'root' in notes.lower() or 'system' in notes.lower()
        assert 'forwarder' in notes.lower() or 'privilege' in notes.lower()

        # Should be tagged appropriately
        assert 'PRIVESC' in metadata.get('tags', []) or 'POST_EXPLOIT' in metadata.get('tags', [])

    def test_vulnerability_research_tasks(self, plugin):
        """PROVES: Plugin includes vulnerability research guidance"""
        tree = plugin.get_task_tree('192.168.45.100', 8000, {'service': 'splunk'})

        research_tasks = []
        def find_research(node):
            if 'research' in node.get('id', '').lower() or node.get('type') == 'research':
                research_tasks.append(node)
            for child in node.get('children', []):
                find_research(child)

        find_research(tree)

        assert len(research_tasks) >= 2  # Should have searchsploit, shodan, etc.

        # Check for searchsploit
        searchsploit_tasks = [t for t in research_tasks if 'searchsploit' in t.get('id', '').lower() or \
                                                            'searchsploit' in t.get('metadata', {}).get('command', '').lower()]
        assert len(searchsploit_tasks) > 0

    def test_oscp_metadata_completeness(self, plugin):
        """PROVES: Tasks include OSCP-required metadata"""
        tree = plugin.get_task_tree('192.168.45.100', 8000, {'service': 'splunk'})

        # Collect all command and manual tasks
        actionable_tasks = []
        def collect_tasks(node):
            if node.get('type') in ['command', 'manual']:
                actionable_tasks.append(node)
            for child in node.get('children', []):
                collect_tasks(child)

        collect_tasks(tree)

        assert len(actionable_tasks) >= 5

        # Check multiple tasks
        for task in actionable_tasks[:5]:
            metadata = task.get('metadata', {})

            # Required fields
            assert 'description' in metadata
            assert 'tags' in metadata
            assert len(metadata['tags']) > 0

            # If command type, should have command and flag explanations
            if task['type'] == 'command':
                assert 'command' in metadata
                if '-' in metadata['command'] or 'curl' in metadata['command']:
                    assert 'flag_explanations' in metadata

            # Educational fields
            if task['type'] == 'command':
                assert 'success_indicators' in metadata
                assert 'failure_indicators' in metadata
                assert 'alternatives' in metadata

    def test_python_payload_examples(self, plugin):
        """PROVES: Plugin includes Python payload examples (Splunk ships with Python)"""
        tree = plugin.get_task_tree('192.168.45.100', 8000, {'service': 'splunk'})

        # Collect all commands and notes
        all_content = []
        def collect_content(node):
            metadata = node.get('metadata', {})
            all_content.append(metadata.get('command', ''))
            all_content.append(metadata.get('notes', ''))
            for child in node.get('children', []):
                collect_content(child)

        collect_content(tree)

        combined = ' '.join(all_content)

        # Should have Python reverse shell example
        assert 'import socket' in combined or 'python' in combined.lower()

    def test_powershell_payload_examples(self, plugin):
        """PROVES: Plugin includes PowerShell payload examples (Windows support)"""
        tree = plugin.get_task_tree('192.168.45.100', 8000, {'service': 'splunk'})

        all_content = []
        def collect_content(node):
            metadata = node.get('metadata', {})
            all_content.append(metadata.get('command', ''))
            all_content.append(metadata.get('notes', ''))
            for child in node.get('children', []):
                collect_content(child)

        collect_content(tree)

        combined = ' '.join(all_content)

        # Should mention PowerShell
        assert 'powershell' in combined.lower() or 'ps1' in combined.lower()

    def test_cross_platform_support(self, plugin):
        """PROVES: Plugin addresses both Windows and Linux targets"""
        tree = plugin.get_task_tree('192.168.45.100', 8000, {'service': 'splunk'})

        all_notes = []
        def collect_notes(node):
            notes = node.get('metadata', {}).get('notes', '')
            if notes:
                all_notes.append(notes)
            for child in node.get('children', []):
                collect_notes(child)

        collect_notes(tree)

        combined_notes = ' '.join(all_notes).lower()

        # Should mention both OS types
        assert 'windows' in combined_notes
        assert 'linux' in combined_notes

    def test_github_reference_present(self, plugin):
        """PROVES: Plugin references exploit example repository"""
        tree = plugin.get_task_tree('192.168.45.100', 8000, {'service': 'splunk'})

        all_notes = []
        def collect_notes(node):
            notes = node.get('metadata', {}).get('notes', '')
            if notes:
                all_notes.append(notes)
            for child in node.get('children', []):
                collect_notes(child)

        collect_notes(tree)

        combined_notes = ' '.join(all_notes).lower()

        # Should reference GitHub repo for examples
        assert 'github' in combined_notes or '0xjpuff' in combined_notes

    def test_time_critical_vulnerability_highlighted(self, plugin):
        """PROVES: Free version vulnerability is properly highlighted as HIGH priority"""
        tree = plugin.get_task_tree('192.168.45.100', 8000, {'service': 'splunk'})

        # Find free version check
        free_tasks = [t for t in tree['children'] if 'free' in t['id'].lower()]
        assert len(free_tasks) > 0

        task = free_tasks[0]

        # Should be OSCP:HIGH
        assert 'OSCP:HIGH' in task['metadata']['tags']

        # Should have clear notes about the vulnerability
        notes = task['metadata'].get('notes', '')
        assert 'critical' in notes.lower() or 'no auth' in notes.lower()
        assert 'free' in notes.lower()

    def test_splunk_file_paths_documented(self, plugin):
        """PROVES: Plugin documents important Splunk file paths for privesc"""
        tree = plugin.get_task_tree('192.168.45.100', 8000, {'service': 'splunk'})

        # Find file path documentation
        all_content = []
        def collect_content(node):
            metadata = node.get('metadata', {})
            all_content.append(metadata.get('notes', ''))
            all_content.append(metadata.get('description', ''))
            for child in node.get('children', []):
                collect_content(child)

        collect_content(tree)

        combined = ' '.join(all_content)

        # Should document key paths
        assert '$SPLUNK_HOME' in combined or '/opt/splunk' in combined
        assert 'etc/passwd' in combined or 'etc/apps' in combined

    def test_listener_setup_guidance(self, plugin):
        """PROVES: Plugin reminds to set up listener for reverse shells"""
        tree = plugin.get_task_tree('192.168.45.100', 8000, {'service': 'splunk'})

        all_content = []
        def collect_content(node):
            metadata = node.get('metadata', {})
            all_content.append(metadata.get('command', ''))
            all_content.append(metadata.get('notes', ''))
            for child in node.get('children', []):
                collect_content(child)

        collect_content(tree)

        combined = ' '.join(all_content).lower()

        # Should mention listener setup
        assert 'nc -l' in combined or 'listener' in combined or 'netcat' in combined

    def test_requires_auth_tag_on_exploit_tasks(self, plugin):
        """PROVES: Exploit tasks properly tagged with REQUIRES_AUTH"""
        tree = plugin.get_task_tree('192.168.45.100', 8000, {'service': 'splunk'})

        # Find RCE tasks
        rce_tasks = []
        def find_rce(node):
            if 'rce' in node.get('id', '').lower():
                rce_tasks.append(node)
            for child in node.get('children', []):
                find_rce(child)

        find_rce(tree)

        # RCE tasks should mention auth requirement
        for task in rce_tasks:
            if task['type'] != 'parent':
                metadata = task.get('metadata', {})
                tags = metadata.get('tags', [])

                # Either tagged REQUIRES_AUTH or free version is mentioned
                has_auth_context = 'REQUIRES_AUTH' in tags or \
                                   'free' in metadata.get('description', '').lower() or \
                                   'credential' in metadata.get('description', '').lower()

                assert has_auth_context, f"Task {task['id']} should indicate auth requirement"
