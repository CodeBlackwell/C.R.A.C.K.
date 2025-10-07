"""
Tests for RabbitMQ Management service plugin

PROVES:
- Plugin detects RabbitMQ Management services
- Task tree generation is complete and valid
- OSCP-required metadata is present
- Educational content is comprehensive
"""

import pytest
from crack.track.services.rabbitmq import RabbitMQPlugin


class TestRabbitMQPlugin:
    """Test suite for RabbitMQ Management plugin"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return RabbitMQPlugin()

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "rabbitmq"

    def test_default_ports(self, plugin):
        """PROVES: Plugin knows default RabbitMQ Management port"""
        assert 15672 in plugin.default_ports

    def test_service_names(self, plugin):
        """PROVES: Plugin recognizes RabbitMQ service name variations"""
        assert 'rabbitmq' in plugin.service_names
        assert 'rabbitmq-management' in plugin.service_names

    def test_detect_by_service_name(self, plugin):
        """PROVES: Plugin detects RabbitMQ by service name"""
        port_info = {'service': 'rabbitmq', 'port': 15672}
        assert plugin.detect(port_info) == True

    def test_detect_by_port(self, plugin):
        """PROVES: Plugin detects RabbitMQ by port number"""
        port_info = {'service': 'unknown', 'port': 15672}
        assert plugin.detect(port_info) == True

    def test_detect_by_product(self, plugin):
        """PROVES: Plugin detects RabbitMQ by product name"""
        port_info = {'service': 'http', 'product': 'RabbitMQ Management', 'port': 8080}
        assert plugin.detect(port_info) == True

    def test_detect_negative(self, plugin):
        """PROVES: Plugin rejects unrelated services"""
        port_info = {'service': 'http', 'port': 80}
        assert plugin.detect(port_info) == False

    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid structure"""
        tree = plugin.get_task_tree('192.168.45.100', 15672, {'service': 'rabbitmq'})

        # Root structure
        assert 'id' in tree
        assert tree['id'] == 'rabbitmq-enum-15672'
        assert 'name' in tree
        assert 'RabbitMQ' in tree['name']
        assert tree['type'] == 'parent'
        assert 'children' in tree

        # Has tasks
        assert len(tree['children']) > 0

    def test_default_credentials_task(self, plugin):
        """PROVES: Plugin includes default credentials test"""
        tree = plugin.get_task_tree('192.168.45.100', 15672, {'service': 'rabbitmq'})

        default_creds_tasks = [t for t in tree['children'] if 'default' in t['id'].lower()]
        assert len(default_creds_tasks) > 0

        task = default_creds_tasks[0]
        metadata = task.get('metadata', {})

        # Check for guest:guest mention
        assert 'guest:guest' in metadata.get('command', '').lower() or \
               'guest:guest' in metadata.get('description', '').lower()

    def test_api_enumeration_tasks(self, plugin):
        """PROVES: Plugin includes API enumeration tasks"""
        tree = plugin.get_task_tree('192.168.45.100', 15672, {'service': 'rabbitmq'})

        # Find API-related tasks
        api_tasks = []
        for child in tree['children']:
            if child['type'] == 'parent' and 'api' in child.get('id', '').lower():
                api_tasks.extend(child.get('children', []))
            elif 'api' in child.get('id', '').lower():
                api_tasks.append(child)

        assert len(api_tasks) > 0

        # Check for connections and queues enumeration
        task_ids = [t['id'] for t in api_tasks]
        assert any('connection' in tid for tid in task_ids)
        assert any('queue' in tid for tid in task_ids)

    def test_oscp_metadata_completeness(self, plugin):
        """PROVES: Tasks include OSCP-required metadata"""
        tree = plugin.get_task_tree('192.168.45.100', 15672, {'service': 'rabbitmq'})

        # Find command tasks
        command_tasks = []
        for child in tree['children']:
            if child['type'] == 'command':
                command_tasks.append(child)
            elif child['type'] == 'parent':
                command_tasks.extend([t for t in child.get('children', []) if t['type'] == 'command'])

        assert len(command_tasks) > 0

        # Check first command task
        task = command_tasks[0]
        metadata = task.get('metadata', {})

        # Required fields
        assert 'command' in metadata, "Command tasks must have 'command' field"
        assert 'description' in metadata, "Tasks must have description"
        assert 'flag_explanations' in metadata, "Must explain all flags"
        assert 'alternatives' in metadata, "Must provide manual alternatives"

        # Educational fields
        assert 'success_indicators' in metadata
        assert 'failure_indicators' in metadata
        assert 'next_steps' in metadata

        # At least one tag
        assert 'tags' in metadata
        assert len(metadata['tags']) > 0

    def test_flag_explanations_present(self, plugin):
        """PROVES: All command tasks explain their flags"""
        tree = plugin.get_task_tree('192.168.45.100', 15672, {'service': 'rabbitmq'})

        # Collect all command tasks
        command_tasks = []
        def collect_commands(node):
            if node.get('type') == 'command':
                command_tasks.append(node)
            for child in node.get('children', []):
                collect_commands(child)

        collect_commands(tree)

        assert len(command_tasks) > 0

        # Check each command task
        for task in command_tasks:
            metadata = task.get('metadata', {})
            if 'command' in metadata:
                assert 'flag_explanations' in metadata, f"Task {task['id']} missing flag_explanations"
                assert len(metadata['flag_explanations']) > 0, f"Task {task['id']} has empty flag_explanations"

    def test_manual_alternatives_present(self, plugin):
        """PROVES: Tasks provide manual alternatives"""
        tree = plugin.get_task_tree('192.168.45.100', 15672, {'service': 'rabbitmq'})

        # Collect all tasks with commands
        tasks_with_commands = []
        def collect_tasks(node):
            if node.get('metadata', {}).get('command'):
                tasks_with_commands.append(node)
            for child in node.get('children', []):
                collect_tasks(child)

        collect_tasks(tree)

        assert len(tasks_with_commands) > 0

        # Check for alternatives
        for task in tasks_with_commands:
            metadata = task.get('metadata', {})
            assert 'alternatives' in metadata, f"Task {task['id']} missing alternatives"
            assert len(metadata['alternatives']) >= 1, f"Task {task['id']} has no alternatives"

    def test_oscp_tags_present(self, plugin):
        """PROVES: Tasks have appropriate OSCP tags"""
        tree = plugin.get_task_tree('192.168.45.100', 15672, {'service': 'rabbitmq'})

        # Collect all tasks
        all_tasks = []
        def collect_all(node):
            all_tasks.append(node)
            for child in node.get('children', []):
                collect_all(child)

        collect_all(tree)

        # Find tasks with tags
        tagged_tasks = [t for t in all_tasks if t.get('metadata', {}).get('tags')]
        assert len(tagged_tasks) > 0

        # Check tag validity
        valid_oscp_tags = ['OSCP:HIGH', 'OSCP:MEDIUM', 'OSCP:LOW']
        valid_method_tags = ['MANUAL', 'AUTOMATED', 'NOISY', 'STEALTH', 'QUICK_WIN']
        valid_phase_tags = ['RECON', 'ENUM', 'EXPLOIT', 'PRIVESC', 'POST_EXPLOIT']
        valid_type_tags = ['RESEARCH', 'BRUTE_FORCE', 'VULN_SCAN', 'REQUIRES_AUTH']

        all_valid_tags = valid_oscp_tags + valid_method_tags + valid_phase_tags + valid_type_tags

        for task in tagged_tasks:
            tags = task['metadata']['tags']
            # At least one tag should be valid
            assert any(tag in all_valid_tags for tag in tags), f"Task {task.get('id')} has no valid tags: {tags}"

    def test_message_injection_task(self, plugin):
        """PROVES: Plugin includes message injection attack vector"""
        tree = plugin.get_task_tree('192.168.45.100', 15672, {'service': 'rabbitmq'})

        # Find message injection task
        inject_tasks = []
        def find_inject(node):
            if 'inject' in node.get('id', '').lower() or 'inject' in node.get('name', '').lower():
                inject_tasks.append(node)
            for child in node.get('children', []):
                find_inject(child)

        find_inject(tree)

        assert len(inject_tasks) > 0
        task = inject_tasks[0]
        metadata = task.get('metadata', {})

        # Should have detailed guidance
        assert 'description' in metadata
        assert 'payload' in metadata.get('command', '').lower() or \
               'payload' in metadata.get('description', '').lower()

    def test_hash_cracking_task(self, plugin):
        """PROVES: Plugin includes hash cracking guidance"""
        tree = plugin.get_task_tree('192.168.45.100', 15672, {'service': 'rabbitmq'})

        # Find hash cracking task
        hash_tasks = []
        def find_hash(node):
            if 'hash' in node.get('id', '').lower() or 'crack' in node.get('id', '').lower():
                hash_tasks.append(node)
            for child in node.get('children', []):
                find_hash(child)

        find_hash(tree)

        assert len(hash_tasks) > 0
        task = hash_tasks[0]
        metadata = task.get('metadata', {})

        # Should mention hashcat
        command_or_notes = metadata.get('command', '') + metadata.get('notes', '')
        assert 'hashcat' in command_or_notes.lower()

    def test_task_uniqueness(self, plugin):
        """PROVES: All task IDs are unique"""
        tree = plugin.get_task_tree('192.168.45.100', 15672, {'service': 'rabbitmq'})

        task_ids = []
        def collect_ids(node):
            if 'id' in node:
                task_ids.append(node['id'])
            for child in node.get('children', []):
                collect_ids(child)

        collect_ids(tree)

        # Check uniqueness
        assert len(task_ids) == len(set(task_ids)), "Duplicate task IDs found"

    def test_target_port_placeholders(self, plugin):
        """PROVES: Commands use target/port placeholders correctly"""
        tree = plugin.get_task_tree('192.168.45.100', 15672, {'service': 'rabbitmq'})

        # Collect all commands (except research tasks which may be global)
        commands = []
        def collect_commands(node):
            if node.get('metadata', {}).get('command') and node.get('type') != 'research':
                commands.append(node['metadata']['command'])
            for child in node.get('children', []):
                collect_commands(child)

        collect_commands(tree)

        assert len(commands) > 0

        # Check for placeholders (should use actual values or clear placeholders)
        for cmd in commands:
            # Should contain target reference (research tasks like Shodan are exempt)
            assert '192.168.45.100' in cmd or '<TARGET>' in cmd or 'USERNAME' in cmd or '{target}' in cmd or 'BASE64' in cmd, \
                   f"Command missing target placeholder: {cmd}"
