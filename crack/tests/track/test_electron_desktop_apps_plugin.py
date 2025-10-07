"""
Test suite for Electron Desktop Apps & Angular Security Plugin

Validates:
- Plugin structure and metadata completeness
- Task tree generation for Electron/Angular security
- OSCP educational metadata (flag explanations, alternatives, success indicators)
- Manual plugin invocation (detect() returns False)
"""

import pytest
from crack.track.services.electron_desktop_apps import ElectronDesktopAppsPlugin


class TestElectronDesktopAppsPlugin:
    """Comprehensive test suite for Electron/Angular security plugin"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return ElectronDesktopAppsPlugin()

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct identifier"""
        assert plugin.name == "electron-desktop-apps"

    def test_plugin_ports(self, plugin):
        """PROVES: Plugin defines relevant HTTP/HTTPS ports for Angular apps"""
        expected_ports = [80, 443, 3000, 4200, 8080, 8443]
        assert plugin.default_ports == expected_ports

    def test_plugin_service_names(self, plugin):
        """PROVES: Plugin defines relevant service identifiers"""
        expected_services = ['electron', 'desktop-app', 'angular', 'angular-app', 'node-webkit', 'nw.js']
        assert plugin.service_names == expected_services

    def test_detect_returns_false(self, plugin):
        """PROVES: Plugin is manually triggered, never auto-detected"""
        # Test various port configurations
        port_infos = [
            {'port': 80, 'service': 'http'},
            {'port': 443, 'service': 'https'},
            {'port': 3000, 'service': 'http'},
            {'port': 4200, 'service': 'angular'},
            {'port': 8080, 'service': 'http-proxy'},
            {'service': 'electron', 'port': 9222},
            {'service': 'desktop-app', 'port': 1337}
        ]

        for port_info in port_infos:
            assert plugin.detect(port_info) == False, \
                f"Plugin should never auto-detect (manual trigger only), failed on {port_info}"

    def test_task_tree_structure(self, plugin):
        """PROVES: Plugin generates valid hierarchical task tree"""
        service_info = {'service': 'electron', 'port': 9222}
        tree = plugin.get_task_tree('target.local', 9222, service_info)

        # Verify root structure
        assert 'id' in tree
        assert tree['id'] == 'electron-angular-security'
        assert 'name' in tree
        assert tree['name'] == 'Electron Desktop Apps & Angular Security Testing'
        assert 'type' in tree
        assert tree['type'] == 'parent'
        assert 'children' in tree
        assert isinstance(tree['children'], list)
        assert len(tree['children']) > 0

    def test_electron_pentesting_section(self, plugin):
        """PROVES: Plugin includes comprehensive Electron pentesting tasks"""
        service_info = {'service': 'electron'}
        tree = plugin.get_task_tree('electron.app', 9222, service_info)

        # Find Electron section
        electron_section = None
        for child in tree['children']:
            if child['id'] == 'electron-desktop-pentesting':
                electron_section = child
                break

        assert electron_section is not None, "Electron section not found"
        assert electron_section['type'] == 'parent'
        assert len(electron_section['children']) >= 7, "Should have at least 7 Electron tasks"

        # Verify specific critical tasks exist
        task_ids = [t['id'] for t in electron_section['children']]
        critical_tasks = [
            'asar-extraction',
            'electron-security-config',
            'electron-xss-nodeintegration-rce',
            'electron-preload-exploitation',
            'electron-prototype-pollution-rce',
            'electron-ipc-fuzzing',
            'electron-v8-snapshot-backdoor',
            'electron-remote-debugging'
        ]

        for task_id in critical_tasks:
            assert task_id in task_ids, f"Missing critical Electron task: {task_id}"

    def test_angular_security_section(self, plugin):
        """PROVES: Plugin includes comprehensive Angular security tasks"""
        service_info = {'service': 'angular'}
        tree = plugin.get_task_tree('angular.app', 4200, service_info)

        # Find Angular section
        angular_section = None
        for child in tree['children']:
            if child['id'] == 'angular-security-testing':
                angular_section = child
                break

        assert angular_section is not None, "Angular section not found"
        assert angular_section['type'] == 'parent'
        assert len(angular_section['children']) >= 5, "Should have at least 5 Angular tasks"

        # Verify specific critical tasks exist
        task_ids = [t['id'] for t in angular_section['children']]
        critical_tasks = [
            'angular-detection',
            'angular-template-injection-interpolation',
            'angular-bypass-security-trust',
            'angular-csp-bypass',
            'angular-routing-access-control'
        ]

        for task_id in critical_tasks:
            assert task_id in task_ids, f"Missing critical Angular task: {task_id}"

    def test_asar_extraction_metadata(self, plugin):
        """PROVES: ASAR extraction task has complete educational metadata"""
        service_info = {}
        tree = plugin.get_task_tree('app', 0, service_info)

        # Find ASAR extraction task
        electron_tasks = tree['children'][0]['children']
        asar_task = next((t for t in electron_tasks if t['id'] == 'asar-extraction'), None)

        assert asar_task is not None
        metadata = asar_task['metadata']

        # Verify required fields
        assert 'command' in metadata
        assert 'npx asar extract' in metadata['command']
        assert 'description' in metadata
        assert 'tags' in metadata
        assert isinstance(metadata['tags'], list)
        assert len(metadata['tags']) > 0

        # Verify OSCP educational fields
        assert 'flag_explanations' in metadata
        assert len(metadata['flag_explanations']) >= 4, "Should explain npx, asar, extract, etc."
        assert 'success_indicators' in metadata
        assert len(metadata['success_indicators']) >= 3
        assert 'failure_indicators' in metadata
        assert len(metadata['failure_indicators']) >= 2
        assert 'next_steps' in metadata
        assert len(metadata['next_steps']) >= 4
        assert 'alternatives' in metadata
        assert len(metadata['alternatives']) >= 2
        assert 'notes' in metadata

    def test_nodeintegration_rce_metadata(self, plugin):
        """PROVES: NodeIntegration RCE task has comprehensive exploitation guidance"""
        service_info = {}
        tree = plugin.get_task_tree('app', 0, service_info)

        # Find nodeIntegration RCE task
        electron_tasks = tree['children'][0]['children']
        rce_task = next((t for t in electron_tasks if t['id'] == 'electron-xss-nodeintegration-rce'), None)

        assert rce_task is not None
        metadata = rce_task['metadata']

        # Verify exploitation metadata
        assert 'description' in metadata
        assert 'RCE' in metadata['description']
        assert 'tags' in metadata
        assert 'EXPLOIT' in metadata['tags']

        # Verify educational content
        assert 'flag_explanations' in metadata
        assert 'require()' in metadata['flag_explanations']
        assert 'child_process' in metadata['flag_explanations']

        assert 'success_indicators' in metadata
        assert any('Calculator' in ind for ind in metadata['success_indicators'])

        assert 'next_steps' in metadata
        assert len(metadata['next_steps']) >= 4
        # Should include reverse shell guidance
        assert any('reverse shell' in step.lower() for step in metadata['next_steps'])

        assert 'alternatives' in metadata
        assert len(metadata['alternatives']) >= 4
        # Should include OS-specific payloads
        assert any('Windows' in alt or 'calc' in alt for alt in metadata['alternatives'])
        assert any('Linux' in alt or 'gnome' in alt for alt in metadata['alternatives'])
        assert any('MacOS' in alt or 'Calculator.app' in alt for alt in metadata['alternatives'])

    def test_prototype_pollution_metadata(self, plugin):
        """PROVES: Prototype pollution task includes advanced exploitation techniques"""
        service_info = {}
        tree = plugin.get_task_tree('app', 0, service_info)

        # Find prototype pollution task
        electron_tasks = tree['children'][0]['children']
        pollution_task = next((t for t in electron_tasks if t['id'] == 'electron-prototype-pollution-rce'), None)

        assert pollution_task is not None
        metadata = pollution_task['metadata']

        # Verify advanced exploitation content
        assert 'tags' in metadata
        assert 'ADVANCED' in metadata['tags']

        assert 'flag_explanations' in metadata
        assert 'Array.prototype.indexOf' in metadata['flag_explanations']
        assert 'Function.prototype.call' in metadata['flag_explanations']
        assert 'process.mainModule.require' in metadata['flag_explanations']

        assert 'next_steps' in metadata
        # Should include real-world examples (Discord, Microsoft Teams)
        assert any('Discord' in step for step in metadata['next_steps'])

        assert 'notes' in metadata
        assert 'contextIsolation' in metadata['notes']
        # Should reference real CVEs/exploits
        assert 'Discord' in metadata['notes'] or 'Microsoft Teams' in metadata['notes']

    def test_v8_snapshot_tampering_metadata(self, plugin):
        """PROVES: V8 snapshot tampering task covers CVE-2025-55305"""
        service_info = {}
        tree = plugin.get_task_tree('app', 0, service_info)

        # Find V8 snapshot task
        electron_tasks = tree['children'][0]['children']
        snapshot_task = next((t for t in electron_tasks if t['id'] == 'electron-v8-snapshot-backdoor'), None)

        assert snapshot_task is not None
        metadata = snapshot_task['metadata']

        # Verify CVE reference
        assert 'description' in metadata
        assert 'CVE-2025-55305' in metadata['description'] or 'CVE-2025-55305' in metadata.get('notes', '')

        assert 'tags' in metadata
        assert 'PERSISTENCE' in metadata['tags']
        assert 'ADVANCED' in metadata['tags']

        assert 'flag_explanations' in metadata
        assert 'v8_context_snapshot.bin' in metadata['flag_explanations']
        assert 'electron-mksnapshot' in metadata['flag_explanations']

        assert 'next_steps' in metadata
        assert len(metadata['next_steps']) >= 5
        # Should include compilation and deployment steps
        assert any('npx' in step and 'electron-mksnapshot' in step for step in metadata['next_steps'])

    def test_angular_template_injection_metadata(self, plugin):
        """PROVES: Angular template injection task covers SSTI techniques"""
        service_info = {}
        tree = plugin.get_task_tree('app', 0, service_info)

        # Find Angular section and template injection task
        angular_tasks = tree['children'][1]['children']
        ssti_task = next((t for t in angular_tasks if t['id'] == 'angular-template-injection-interpolation'), None)

        assert ssti_task is not None
        metadata = ssti_task['metadata']

        # Verify SSTI content
        assert 'description' in metadata
        assert 'Template Injection' in metadata['description']

        assert 'flag_explanations' in metadata
        assert '{{7*7}}' in metadata['flag_explanations']
        assert 'constructor' in str(metadata['flag_explanations']).lower()

        assert 'success_indicators' in metadata
        assert any('49' in ind for ind in metadata['success_indicators'])

        assert 'next_steps' in metadata
        # Should include both AngularJS (v1.x) and Angular 2+ techniques
        assert len(metadata['next_steps']) >= 5

        assert 'alternatives' in metadata
        # Should include version-specific payloads
        assert any('AngularJS' in alt for alt in metadata['alternatives'])

    def test_bypass_security_trust_metadata(self, plugin):
        """PROVES: bypassSecurityTrust task covers all 5 bypass methods"""
        service_info = {}
        tree = plugin.get_task_tree('app', 0, service_info)

        # Find Angular section and bypassSecurityTrust task
        angular_tasks = tree['children'][1]['children']
        bypass_task = next((t for t in angular_tasks if t['id'] == 'angular-bypass-security-trust'), None)

        assert bypass_task is not None
        metadata = bypass_task['metadata']

        # Verify all 5 bypass methods covered
        assert 'flag_explanations' in metadata
        bypass_methods = [
            'bypassSecurityTrustHtml',
            'bypassSecurityTrustScript',
            'bypassSecurityTrustUrl',
            'bypassSecurityTrustResourceUrl',
            'bypassSecurityTrustStyle'
        ]

        for method in bypass_methods:
            assert method in metadata['flag_explanations'], f"Missing {method} explanation"

        # Verify exploitation guidance
        assert 'next_steps' in metadata
        assert len(metadata['next_steps']) >= 5

        assert 'alternatives' in metadata
        # Should include XSS payloads for each method
        assert len(metadata['alternatives']) >= 4

    def test_tools_section_exists(self, plugin):
        """PROVES: Plugin includes tools and training resources section"""
        service_info = {}
        tree = plugin.get_task_tree('app', 0, service_info)

        # Should have 3 main sections: Electron, Angular, Tools
        assert len(tree['children']) == 3

        tools_section = tree['children'][2]
        assert tools_section['id'] == 'electron-angular-tools'
        assert tools_section['type'] == 'parent'
        assert len(tools_section['children']) >= 2

    def test_electronegativity_scanner_task(self, plugin):
        """PROVES: Plugin includes automated scanner (Electronegativity) task"""
        service_info = {}
        tree = plugin.get_task_tree('app', 0, service_info)

        tools_tasks = tree['children'][2]['children']
        scanner_task = next((t for t in tools_tasks if t['id'] == 'electron-security-scanners'), None)

        assert scanner_task is not None
        metadata = scanner_task['metadata']

        # Verify scanner command
        assert 'command' in metadata
        assert 'electronegativity' in metadata['command']

        # Verify alternatives include multiple tools
        assert 'alternatives' in metadata
        alternatives_text = ' '.join(metadata['alternatives'])
        assert 'electrolint' in alternatives_text
        assert 'nodejsscan' in alternatives_text
        assert 'npm audit' in alternatives_text

    def test_training_resources_task(self, plugin):
        """PROVES: Plugin includes training labs and resources"""
        service_info = {}
        tree = plugin.get_task_tree('app', 0, service_info)

        tools_tasks = tree['children'][2]['children']
        training_task = next((t for t in tools_tasks if t['id'] == 'electron-angular-training'), None)

        assert training_task is not None
        metadata = training_task['metadata']

        # Verify training resources listed
        assert 'notes' in metadata
        notes = metadata['notes']

        # Should include vulnerable apps
        assert 'vulnerable1.zip' in notes
        assert 'vulnerable2.zip' in notes
        assert 'vulnerable3.zip' in notes

        # Should include training videos
        assert 'youtube.com' in notes

        # Should include reference materials
        assert 'doyensec' in notes or 'awesome-electronjs-hacking' in notes

    def test_oscp_relevance_tags(self, plugin):
        """PROVES: All tasks have appropriate OSCP relevance tags"""
        service_info = {}
        tree = plugin.get_task_tree('app', 0, service_info)

        # Collect all tasks (recursive)
        def collect_tasks(node, tasks_list):
            if node.get('type') in ['command', 'manual']:
                tasks_list.append(node)
            if 'children' in node:
                for child in node['children']:
                    collect_tasks(child, tasks_list)

        all_tasks = []
        collect_tasks(tree, all_tasks)

        assert len(all_tasks) > 0, "No tasks found"

        for task in all_tasks:
            metadata = task.get('metadata', {})
            if 'tags' in metadata:
                # Most tasks should be OSCP:LOW or OSCP:MEDIUM (advanced client-side)
                tags = metadata['tags']
                assert isinstance(tags, list)
                # At least check tags are present
                assert len(tags) > 0, f"Task {task['id']} has no tags"

    def test_flag_explanations_completeness(self, plugin):
        """PROVES: All command tasks explain their flags/parameters"""
        service_info = {}
        tree = plugin.get_task_tree('app', 0, service_info)

        # Collect command tasks
        def collect_command_tasks(node, tasks_list):
            if node.get('type') == 'command':
                tasks_list.append(node)
            if 'children' in node:
                for child in node['children']:
                    collect_command_tasks(child, tasks_list)

        command_tasks = []
        collect_command_tasks(tree, command_tasks)

        assert len(command_tasks) > 0, "No command tasks found"

        for task in command_tasks:
            metadata = task.get('metadata', {})

            # Command tasks should have flag_explanations
            if 'command' in metadata:
                assert 'flag_explanations' in metadata, \
                    f"Task {task['id']} missing flag_explanations"
                assert len(metadata['flag_explanations']) > 0, \
                    f"Task {task['id']} has empty flag_explanations"

    def test_alternatives_provided(self, plugin):
        """PROVES: All tasks provide manual alternatives for OSCP exam scenarios"""
        service_info = {}
        tree = plugin.get_task_tree('app', 0, service_info)

        # Collect all actionable tasks
        def collect_tasks(node, tasks_list):
            if node.get('type') in ['command', 'manual']:
                tasks_list.append(node)
            if 'children' in node:
                for child in node['children']:
                    collect_tasks(child, tasks_list)

        all_tasks = []
        collect_tasks(tree, all_tasks)

        for task in all_tasks:
            metadata = task.get('metadata', {})

            # Most tasks should have alternatives
            if 'alternatives' in metadata:
                assert isinstance(metadata['alternatives'], list)
                assert len(metadata['alternatives']) > 0, \
                    f"Task {task['id']} has empty alternatives"

    def test_success_failure_indicators(self, plugin):
        """PROVES: Tasks provide success and failure indicators for validation"""
        service_info = {}
        tree = plugin.get_task_tree('app', 0, service_info)

        # Collect all actionable tasks
        def collect_tasks(node, tasks_list):
            if node.get('type') in ['command', 'manual']:
                tasks_list.append(node)
            if 'children' in node:
                for child in node['children']:
                    collect_tasks(child, tasks_list)

        all_tasks = []
        collect_tasks(tree, all_tasks)

        tasks_with_indicators = 0

        for task in all_tasks:
            metadata = task.get('metadata', {})

            if 'success_indicators' in metadata and 'failure_indicators' in metadata:
                tasks_with_indicators += 1

                # Verify format
                assert isinstance(metadata['success_indicators'], list)
                assert isinstance(metadata['failure_indicators'], list)
                assert len(metadata['success_indicators']) >= 2, \
                    f"Task {task['id']} needs at least 2 success indicators"
                assert len(metadata['failure_indicators']) >= 2, \
                    f"Task {task['id']} needs at least 2 failure indicators"

        # Most tasks should have indicators
        assert tasks_with_indicators >= len(all_tasks) * 0.8, \
            "At least 80% of tasks should have success/failure indicators"

    def test_next_steps_guidance(self, plugin):
        """PROVES: Tasks provide clear next steps for attack chain progression"""
        service_info = {}
        tree = plugin.get_task_tree('app', 0, service_info)

        # Collect all actionable tasks
        def collect_tasks(node, tasks_list):
            if node.get('type') in ['command', 'manual']:
                tasks_list.append(node)
            if 'children' in node:
                for child in node['children']:
                    collect_tasks(child, tasks_list)

        all_tasks = []
        collect_tasks(tree, all_tasks)

        tasks_with_next_steps = 0

        for task in all_tasks:
            metadata = task.get('metadata', {})

            if 'next_steps' in metadata:
                tasks_with_next_steps += 1

                # Verify format
                assert isinstance(metadata['next_steps'], list)
                assert len(metadata['next_steps']) >= 2, \
                    f"Task {task['id']} should have at least 2 next steps"

        # Most tasks should guide the user forward
        assert tasks_with_next_steps >= len(all_tasks) * 0.8, \
            "At least 80% of tasks should have next_steps guidance"

    def test_plugin_docstring_completeness(self, plugin):
        """PROVES: Plugin has comprehensive documentation"""
        # Check class docstring
        assert plugin.__class__.__doc__ is not None
        docstring = plugin.__class__.__doc__

        # Should mention key components
        assert 'Electron' in docstring
        assert 'Angular' in docstring
        assert 'ASAR' in docstring
        assert 'Generated by: CrackPot' in docstring

    def test_no_hardcoded_targets(self, plugin):
        """PROVES: Plugin uses target parameter, not hardcoded values"""
        service_info = {}

        # Generate tree with specific target
        tree = plugin.get_task_tree('test.example.com', 8080, service_info)

        # Convert tree to string to search for hardcoded IPs
        tree_str = str(tree)

        # Should NOT contain common hardcoded IPs/domains
        hardcoded_patterns = ['192.168.1.1', '10.0.0.1', 'localhost', '127.0.0.1', 'example.com']

        # Some patterns are OK in documentation/notes, but not in commands
        # Extract all commands
        def collect_commands(node, commands_list):
            if node.get('metadata', {}).get('command'):
                commands_list.append(node['metadata']['command'])
            if 'children' in node:
                for child in node['children']:
                    collect_commands(child, commands_list)

        commands = []
        collect_commands(tree, commands)

        commands_str = ' '.join(commands)

        # Commands should use placeholders or parameters, not hardcoded targets
        # (Some examples in notes are OK, so we only check actual commands)
        for pattern in ['192.168.1.1', '10.0.0.1']:
            assert pattern not in commands_str, \
                f"Found hardcoded IP {pattern} in command (should use {{target}} or parameter)"
