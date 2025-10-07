"""
Tests for NextJS service plugin

Validates NextJS application security assessment plugin functionality
"""

import pytest
from crack.track.services.nextjs import NextJSPlugin


class TestNextJSPlugin:
    """Test suite for NextJS plugin"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return NextJSPlugin()

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "nextjs"

    def test_default_ports(self, plugin):
        """PROVES: Plugin specifies correct default ports"""
        assert 3000 in plugin.default_ports  # NextJS default dev port
        assert 80 in plugin.default_ports
        assert 443 in plugin.default_ports
        assert 8080 in plugin.default_ports

    def test_service_names(self, plugin):
        """PROVES: Plugin handles HTTP/HTTPS services"""
        assert 'http' in plugin.service_names
        assert 'https' in plugin.service_names

    def test_detect_by_product_nextjs(self, plugin):
        """PROVES: Plugin detects NextJS by product name"""
        port_info = {
            'port': 3000,
            'service': 'http',
            'product': 'Next.js 13.4.0'
        }
        assert plugin.detect(port_info) == True

    def test_detect_by_product_react(self, plugin):
        """PROVES: Plugin detects React/NextJS apps"""
        port_info = {
            'port': 80,
            'service': 'http',
            'product': 'React Server'
        }
        assert plugin.detect(port_info) == True

    def test_detect_by_product_nodejs(self, plugin):
        """PROVES: Plugin detects port 3000 with HTTP (NextJS default dev port)"""
        port_info = {
            'port': 3000,
            'service': 'http',
            'product': 'Node.js Express'
        }
        # Port 3000 + HTTP = likely NextJS development server
        assert plugin.detect(port_info) == True

    def test_detect_by_version(self, plugin):
        """PROVES: Plugin detects NextJS by version string"""
        port_info = {
            'port': 80,
            'service': 'http',
            'product': 'HTTP Server',
            'version': 'powered by next.js'
        }
        assert plugin.detect(port_info) == True

    def test_detect_by_port_3000(self, plugin):
        """PROVES: Plugin detects port 3000 with HTTP service (NextJS dev default)"""
        port_info = {
            'port': 3000,
            'service': 'http'
        }
        assert plugin.detect(port_info) == True

    def test_detect_negative_non_http(self, plugin):
        """PROVES: Plugin rejects non-HTTP services"""
        port_info = {
            'port': 22,
            'service': 'ssh'
        }
        assert plugin.detect(port_info) == False

    def test_detect_negative_no_indicators(self, plugin):
        """PROVES: Plugin rejects HTTP without NextJS indicators"""
        port_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd'
        }
        assert plugin.detect(port_info) == False

    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid structure"""
        service_info = {
            'port': 3000,
            'service': 'http',
            'product': 'Next.js 13.4.0',
            'version': '13.4.0'
        }
        tree = plugin.get_task_tree('192.168.45.100', 3000, service_info)

        # Root structure
        assert 'id' in tree
        assert tree['id'] == 'nextjs-enum-3000'
        assert 'name' in tree
        assert 'NextJS' in tree['name']
        assert 'type' in tree
        assert tree['type'] == 'parent'
        assert 'children' in tree
        assert len(tree['children']) > 0

    def test_task_tree_has_recon_phase(self, plugin):
        """PROVES: Task tree includes reconnaissance phase"""
        service_info = {
            'port': 3000,
            'service': 'http',
            'product': 'Next.js'
        }
        tree = plugin.get_task_tree('192.168.45.100', 3000, service_info)

        # Find recon parent
        recon_tasks = [t for t in tree['children'] if 'recon' in t['id'].lower()]
        assert len(recon_tasks) > 0

        recon = recon_tasks[0]
        assert recon['type'] == 'parent'
        assert 'children' in recon
        assert len(recon['children']) > 0

    def test_task_tree_has_nextjs_detection(self, plugin):
        """PROVES: Task tree includes NextJS framework detection"""
        service_info = {
            'port': 3000,
            'service': 'http',
            'product': 'Next.js'
        }
        tree = plugin.get_task_tree('192.168.45.100', 3000, service_info)

        # Find all tasks recursively
        def find_tasks(node, task_list):
            if 'children' in node:
                for child in node['children']:
                    task_list.append(child)
                    find_tasks(child, task_list)

        all_tasks = []
        find_tasks(tree, all_tasks)

        # Check for NextJS detection task
        detection_tasks = [t for t in all_tasks if 'detect' in t['id'].lower()]
        assert len(detection_tasks) > 0

    def test_task_tree_has_config_enumeration(self, plugin):
        """PROVES: Task tree includes config file enumeration"""
        service_info = {
            'port': 3000,
            'service': 'http',
            'product': 'Next.js'
        }
        tree = plugin.get_task_tree('192.168.45.100', 3000, service_info)

        def find_tasks(node, task_list):
            if 'children' in node:
                for child in node['children']:
                    task_list.append(child)
                    find_tasks(child, task_list)

        all_tasks = []
        find_tasks(tree, all_tasks)

        config_tasks = [t for t in all_tasks if 'config' in t['id'].lower()]
        assert len(config_tasks) > 0

    def test_task_tree_has_vuln_testing(self, plugin):
        """PROVES: Task tree includes vulnerability testing phase"""
        service_info = {
            'port': 3000,
            'service': 'http',
            'product': 'Next.js'
        }
        tree = plugin.get_task_tree('192.168.45.100', 3000, service_info)

        vuln_tasks = [t for t in tree['children'] if 'vuln' in t['id'].lower()]
        assert len(vuln_tasks) > 0

    def test_task_tree_has_cspt_testing(self, plugin):
        """PROVES: Task tree includes Client-Side Path Traversal testing"""
        service_info = {
            'port': 3000,
            'service': 'http',
            'product': 'Next.js'
        }
        tree = plugin.get_task_tree('192.168.45.100', 3000, service_info)

        def find_tasks(node, task_list):
            if 'children' in node:
                for child in node['children']:
                    task_list.append(child)
                    find_tasks(child, task_list)

        all_tasks = []
        find_tasks(tree, all_tasks)

        cspt_tasks = [t for t in all_tasks if 'cspt' in t['id'].lower()]
        assert len(cspt_tasks) > 0

    def test_task_tree_has_api_exploitation(self, plugin):
        """PROVES: Task tree includes API routes exploitation"""
        service_info = {
            'port': 3000,
            'service': 'http',
            'product': 'Next.js'
        }
        tree = plugin.get_task_tree('192.168.45.100', 3000, service_info)

        api_tasks = [t for t in tree['children'] if 'api' in t['id'].lower()]
        assert len(api_tasks) > 0

    def test_task_tree_has_middleware_testing(self, plugin):
        """PROVES: Task tree includes middleware exploitation"""
        service_info = {
            'port': 3000,
            'service': 'http',
            'product': 'Next.js'
        }
        tree = plugin.get_task_tree('192.168.45.100', 3000, service_info)

        middleware_tasks = [t for t in tree['children'] if 'middleware' in t['id'].lower()]
        assert len(middleware_tasks) > 0

    def test_oscp_metadata_completeness(self, plugin):
        """PROVES: Tasks include OSCP-required metadata"""
        service_info = {
            'port': 3000,
            'service': 'http',
            'product': 'Next.js'
        }
        tree = plugin.get_task_tree('192.168.45.100', 3000, service_info)

        # Find all command tasks recursively
        def find_command_tasks(node, task_list):
            if node.get('type') == 'command':
                task_list.append(node)
            if 'children' in node:
                for child in node['children']:
                    find_command_tasks(child, task_list)

        command_tasks = []
        find_command_tasks(tree, command_tasks)
        assert len(command_tasks) > 0, "Should have at least one command task"

        # Check first command task
        task = command_tasks[0]
        metadata = task.get('metadata', {})

        # Required fields for command tasks
        assert 'command' in metadata, "Command tasks must have 'command' field"
        assert 'description' in metadata, "Tasks must have description"
        assert 'flag_explanations' in metadata, "Must explain all flags"
        assert 'alternatives' in metadata, "Must provide manual alternatives"
        assert 'tags' in metadata, "Must have tags"
        assert len(metadata['tags']) > 0, "Must have at least one tag"

    def test_oscp_tags_present(self, plugin):
        """PROVES: Tasks use OSCP priority tags"""
        service_info = {
            'port': 3000,
            'service': 'http',
            'product': 'Next.js'
        }
        tree = plugin.get_task_tree('192.168.45.100', 3000, service_info)

        def find_all_tasks(node, task_list):
            task_list.append(node)
            if 'children' in node:
                for child in node['children']:
                    find_all_tasks(child, task_list)

        all_tasks = []
        find_all_tasks(tree, all_tasks)

        # Collect all tags
        all_tags = []
        for task in all_tasks:
            if 'metadata' in task and 'tags' in task['metadata']:
                all_tags.extend(task['metadata']['tags'])

        # Should have OSCP priority tags
        oscp_tags = [tag for tag in all_tags if 'OSCP:' in tag]
        assert len(oscp_tags) > 0, "Should have OSCP priority tags"

    def test_success_indicators_present(self, plugin):
        """PROVES: Command tasks include success indicators"""
        service_info = {
            'port': 3000,
            'service': 'http',
            'product': 'Next.js'
        }
        tree = plugin.get_task_tree('192.168.45.100', 3000, service_info)

        def find_command_tasks(node, task_list):
            if node.get('type') == 'command':
                task_list.append(node)
            if 'children' in node:
                for child in node['children']:
                    find_command_tasks(child, task_list)

        command_tasks = []
        find_command_tasks(tree, command_tasks)

        for task in command_tasks:
            metadata = task.get('metadata', {})
            assert 'success_indicators' in metadata, f"Task {task['id']} missing success_indicators"
            assert len(metadata['success_indicators']) > 0

    def test_failure_indicators_present(self, plugin):
        """PROVES: Tasks include failure indicators for troubleshooting"""
        service_info = {
            'port': 3000,
            'service': 'http',
            'product': 'Next.js'
        }
        tree = plugin.get_task_tree('192.168.45.100', 3000, service_info)

        def find_all_tasks(node, task_list):
            if 'metadata' in node:
                task_list.append(node)
            if 'children' in node:
                for child in node['children']:
                    find_all_tasks(child, task_list)

        tasks_with_metadata = []
        find_all_tasks(tree, tasks_with_metadata)

        # At least some tasks should have failure indicators
        tasks_with_failures = [t for t in tasks_with_metadata
                              if 'failure_indicators' in t.get('metadata', {})]
        assert len(tasks_with_failures) > 0

    def test_next_steps_guidance(self, plugin):
        """PROVES: Tasks provide next steps for attack progression"""
        service_info = {
            'port': 3000,
            'service': 'http',
            'product': 'Next.js'
        }
        tree = plugin.get_task_tree('192.168.45.100', 3000, service_info)

        def find_all_tasks(node, task_list):
            if 'metadata' in node:
                task_list.append(node)
            if 'children' in node:
                for child in node['children']:
                    find_all_tasks(child, task_list)

        tasks_with_metadata = []
        find_all_tasks(tree, tasks_with_metadata)

        # At least some tasks should have next_steps
        tasks_with_next_steps = [t for t in tasks_with_metadata
                                 if 'next_steps' in t.get('metadata', {})]
        assert len(tasks_with_next_steps) > 0

    def test_url_construction_http(self, plugin):
        """PROVES: Plugin constructs HTTP URLs correctly"""
        service_info = {
            'port': 3000,
            'service': 'http',
            'product': 'Next.js'
        }
        tree = plugin.get_task_tree('192.168.45.100', 3000, service_info)

        # Extract commands and check URL format
        def find_commands(node, commands):
            if 'metadata' in node and 'command' in node['metadata']:
                commands.append(node['metadata']['command'])
            if 'children' in node:
                for child in node['children']:
                    find_commands(child, commands)

        commands = []
        find_commands(tree, commands)

        http_commands = [c for c in commands if 'http://' in c]
        assert len(http_commands) > 0
        assert all('192.168.45.100' in c for c in http_commands)
        assert all('3000' in c for c in http_commands)

    def test_url_construction_https(self, plugin):
        """PROVES: Plugin constructs HTTPS URLs correctly for SSL ports"""
        service_info = {
            'port': 443,
            'service': 'https',
            'product': 'Next.js'
        }
        tree = plugin.get_task_tree('192.168.45.100', 443, service_info)

        def find_commands(node, commands):
            if 'metadata' in node and 'command' in node['metadata']:
                commands.append(node['metadata']['command'])
            if 'children' in node:
                for child in node['children']:
                    find_commands(child, commands)

        commands = []
        find_commands(tree, commands)

        https_commands = [c for c in commands if 'https://' in c]
        assert len(https_commands) > 0

    def test_research_phase_with_version(self, plugin):
        """PROVES: Research phase generated when version detected"""
        service_info = {
            'port': 3000,
            'service': 'http',
            'product': 'Next.js',
            'version': '13.4.0'
        }
        tree = plugin.get_task_tree('192.168.45.100', 3000, service_info)

        research_tasks = [t for t in tree['children'] if 'research' in t['id'].lower()]
        assert len(research_tasks) > 0

        research = research_tasks[0]
        assert 'children' in research
        assert len(research['children']) > 0

        # Should have searchsploit task
        searchsploit_tasks = [t for t in research['children'] if 'searchsploit' in t['id']]
        assert len(searchsploit_tasks) > 0

    def test_unique_task_ids(self, plugin):
        """PROVES: All task IDs are unique within tree"""
        service_info = {
            'port': 3000,
            'service': 'http',
            'product': 'Next.js',
            'version': '13.4.0'
        }
        tree = plugin.get_task_tree('192.168.45.100', 3000, service_info)

        def collect_ids(node, id_list):
            id_list.append(node['id'])
            if 'children' in node:
                for child in node['children']:
                    collect_ids(child, id_list)

        all_ids = []
        collect_ids(tree, all_ids)

        # Check uniqueness
        assert len(all_ids) == len(set(all_ids)), "All task IDs must be unique"

    def test_task_types_valid(self, plugin):
        """PROVES: All tasks have valid type values"""
        service_info = {
            'port': 3000,
            'service': 'http',
            'product': 'Next.js'
        }
        tree = plugin.get_task_tree('192.168.45.100', 3000, service_info)

        valid_types = ['parent', 'command', 'manual', 'research']

        def check_types(node):
            assert 'type' in node, f"Task {node.get('id')} missing type"
            assert node['type'] in valid_types, f"Invalid type: {node['type']}"
            if 'children' in node:
                for child in node['children']:
                    check_types(child)

        check_types(tree)

    def test_port_in_task_ids(self, plugin):
        """PROVES: Task IDs include port number for uniqueness"""
        service_info = {
            'port': 8080,
            'service': 'http',
            'product': 'Next.js'
        }
        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Root ID should contain port
        assert '8080' in tree['id']

    def test_manual_tasks_have_alternatives(self, plugin):
        """PROVES: Manual tasks provide alternative methods"""
        service_info = {
            'port': 3000,
            'service': 'http',
            'product': 'Next.js'
        }
        tree = plugin.get_task_tree('192.168.45.100', 3000, service_info)

        def find_manual_tasks(node, task_list):
            if node.get('type') == 'manual':
                task_list.append(node)
            if 'children' in node:
                for child in node['children']:
                    find_manual_tasks(child, task_list)

        manual_tasks = []
        find_manual_tasks(tree, manual_tasks)

        for task in manual_tasks:
            metadata = task.get('metadata', {})
            assert 'alternatives' in metadata, f"Manual task {task['id']} must have alternatives"
            assert len(metadata['alternatives']) > 0
