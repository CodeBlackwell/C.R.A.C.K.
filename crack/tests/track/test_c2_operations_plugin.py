"""
Test Suite: C2 Operations Plugin

PROVES: C2 framework operations plugin generates comprehensive task trees
        for Cobalt Strike, Mythic, and manual C2 alternatives

Test Coverage:
- Plugin registration and detection
- Cobalt Strike operations (listeners, payloads, beacon commands, OPSEC)
- Mythic C2 operations (Apollo, Poseidon agents)
- Manual C2 alternatives (netcat, PowerShell, metasploit)
"""

import pytest
from crack.track.services.c2_operations import C2OperationsPlugin


class TestC2OperationsPlugin:
    """Test C2 Operations Plugin functionality"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return C2OperationsPlugin()

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "c2-operations"

    def test_manual_trigger_only(self, plugin):
        """PROVES: Plugin is manual-trigger only (not auto-detected from ports)"""
        # Should never auto-detect from port scans
        port_info = {'port': 80, 'service': 'http'}
        assert plugin.detect(port_info) == False

        port_info = {'port': 443, 'service': 'https'}
        assert plugin.detect(port_info) == False

    def test_default_ports_empty(self, plugin):
        """PROVES: Plugin has no default ports (manual trigger only)"""
        assert plugin.default_ports == []

    def test_service_names_empty(self, plugin):
        """PROVES: Plugin has no service names (manual trigger only)"""
        assert plugin.service_names == []

    def test_task_tree_structure_all_frameworks(self, plugin):
        """PROVES: Task tree includes all C2 frameworks when framework='all'"""
        service_info = {'framework': 'all'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        # Verify root structure
        assert tree['id'] == 'c2-operations-192.168.45.100'
        assert tree['name'] == 'C2 Operations - 192.168.45.100'
        assert tree['type'] == 'parent'
        assert 'children' in tree

        # Should have 3 top-level children (Cobalt Strike, Mythic, Manual)
        assert len(tree['children']) == 3

        child_names = [child['name'] for child in tree['children']]
        assert 'Cobalt Strike Operations' in child_names
        assert 'Mythic C2 Operations' in child_names
        assert 'Manual C2 Alternatives' in child_names

    def test_task_tree_cobalt_strike_only(self, plugin):
        """PROVES: Task tree includes only Cobalt Strike when framework='cobalt-strike'"""
        service_info = {'framework': 'cobalt-strike'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        assert len(tree['children']) == 1
        assert tree['children'][0]['name'] == 'Cobalt Strike Operations'

    def test_task_tree_mythic_only(self, plugin):
        """PROVES: Task tree includes only Mythic when framework='mythic'"""
        service_info = {'framework': 'mythic'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        assert len(tree['children']) == 1
        assert tree['children'][0]['name'] == 'Mythic C2 Operations'

    def test_cobalt_strike_structure(self, plugin):
        """PROVES: Cobalt Strike section has proper structure"""
        service_info = {'framework': 'cobalt-strike'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        cs_tree = tree['children'][0]
        assert cs_tree['id'] == 'cobalt-strike-192.168.45.100'
        assert cs_tree['type'] == 'parent'
        assert 'children' in cs_tree
        assert len(cs_tree['children']) > 0

        # Check for major sections
        child_names = [child['name'] for child in cs_tree['children']]
        assert 'Cobalt Strike Listeners' in child_names
        assert 'Payload Generation & Hosting' in child_names
        assert 'Beacon Commands & Operations' in child_names
        assert 'OPSEC & Evasion Techniques' in child_names

    def test_cobalt_strike_listeners(self, plugin):
        """PROVES: Cobalt Strike listeners section includes HTTP, SMB, TCP"""
        service_info = {'framework': 'cobalt-strike'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        cs_tree = tree['children'][0]
        listeners = [child for child in cs_tree['children'] if child['name'] == 'Cobalt Strike Listeners'][0]

        listener_names = [child['name'] for child in listeners['children']]
        assert 'HTTP/HTTPS Listener (C2 Direct)' in listener_names
        assert 'SMB Beacon (Peer-to-Peer)' in listener_names
        assert 'TCP Beacon (Peer-to-Peer)' in listener_names

    def test_cobalt_strike_beacon_commands(self, plugin):
        """PROVES: Beacon commands include execute-assembly, powershell, tokens, lateral movement"""
        service_info = {'framework': 'cobalt-strike'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        cs_tree = tree['children'][0]
        beacon_cmds = [child for child in cs_tree['children'] if child['name'] == 'Beacon Commands & Operations'][0]

        cmd_names = [child['name'] for child in beacon_cmds['children']]
        assert 'Execute .NET Assembly (execute-assembly)' in cmd_names
        assert 'Import PowerShell Module' in cmd_names
        assert 'Create Token (make_token)' in cmd_names
        assert 'Steal Token (steal_token)' in cmd_names
        assert 'Pass-the-Hash (pth)' in cmd_names
        assert 'Lateral Movement (jump)' in cmd_names
        assert 'SOCKS Proxy (socks)' in cmd_names

    def test_cobalt_strike_opsec_techniques(self, plugin):
        """PROVES: OPSEC section includes malleable C2, artifact kit, unhook, token store"""
        service_info = {'framework': 'cobalt-strike'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        cs_tree = tree['children'][0]
        opsec = [child for child in cs_tree['children'] if child['name'] == 'OPSEC & Evasion Techniques'][0]

        opsec_names = [child['name'] for child in opsec['children']]
        assert 'Malleable C2 Profiles' in opsec_names
        assert 'Artifact Kit (AV Bypass)' in opsec_names
        assert 'Unhook EDR (unhook-bof)' in opsec_names
        assert 'Token Store (Avoid Repeated Theft)' in opsec_names

    def test_mythic_structure(self, plugin):
        """PROVES: Mythic section has proper structure with installation and agents"""
        service_info = {'framework': 'mythic'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        mythic_tree = tree['children'][0]
        assert mythic_tree['id'] == 'mythic-192.168.45.100'
        assert mythic_tree['type'] == 'parent'
        assert 'children' in mythic_tree
        assert len(mythic_tree['children']) > 0

        # Check for major sections
        child_names = [child['name'] for child in mythic_tree['children']]
        assert 'Mythic Installation & Setup' in child_names
        assert 'Apollo Agent (Windows)' in child_names
        assert 'Poseidon Agent (Linux/macOS)' in child_names

    def test_mythic_apollo_agent(self, plugin):
        """PROVES: Apollo agent section includes execute_assembly, powershell, privesc, lateral movement"""
        service_info = {'framework': 'mythic'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        mythic_tree = tree['children'][0]
        apollo = [child for child in mythic_tree['children'] if child['name'] == 'Apollo Agent (Windows)'][0]

        apollo_sections = [child['name'] for child in apollo['children']]
        assert 'Execute .NET Assembly' in apollo_sections
        assert 'PowerShell Execution' in apollo_sections
        assert 'Privilege Escalation' in apollo_sections
        assert 'Lateral Movement' in apollo_sections
        assert 'Mythic Forge (BOF/COFF)' in apollo_sections

    def test_mythic_poseidon_agent(self, plugin):
        """PROVES: Poseidon agent section includes SSH, PTY, SOCKS, triage"""
        service_info = {'framework': 'mythic'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        mythic_tree = tree['children'][0]
        poseidon = [child for child in mythic_tree['children'] if child['name'] == 'Poseidon Agent (Linux/macOS)'][0]

        poseidon_cmds = [child['name'] for child in poseidon['children']]
        assert 'SSH Lateral Movement' in poseidon_cmds
        assert 'Interactive PTY' in poseidon_cmds
        assert 'SOCKS Proxy' in poseidon_cmds
        assert 'Triage Directory (Find Sensitive Files)' in poseidon_cmds

    def test_manual_c2_alternatives(self, plugin):
        """PROVES: Manual C2 section includes netcat, PowerShell, metasploit, HTTP server"""
        service_info = {'framework': 'all'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        manual_tree = [child for child in tree['children'] if child['name'] == 'Manual C2 Alternatives'][0]

        manual_cmds = [child['name'] for child in manual_tree['children']]
        assert 'Netcat Reverse Shell' in manual_cmds
        assert 'PowerShell Reverse Shell' in manual_cmds
        assert 'Metasploit Multi Handler' in manual_cmds
        assert 'Python HTTP Server (File Transfer)' in manual_cmds

    def test_oscp_metadata_completeness(self, plugin):
        """PROVES: Tasks include OSCP-required metadata"""
        service_info = {'framework': 'all'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        # Find first command task
        def find_command_task(node):
            if node.get('type') == 'command':
                return node
            if 'children' in node:
                for child in node['children']:
                    result = find_command_task(child)
                    if result:
                        return result
            return None

        command_task = find_command_task(tree)
        assert command_task is not None, "Should have at least one command task"

        metadata = command_task.get('metadata', {})

        # Check required metadata fields
        assert 'description' in metadata, "Must have description"
        assert 'alternatives' in metadata, "Must provide manual alternatives"
        assert 'tags' in metadata, "Must have tags"
        assert len(metadata['tags']) > 0, "Must have at least one tag"

    def test_flag_explanations_present(self, plugin):
        """PROVES: Command tasks with flags include explanations"""
        service_info = {'framework': 'cobalt-strike'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        # Find execute-assembly task (has flags)
        def find_task_by_name(node, name):
            if node.get('name') == name:
                return node
            if 'children' in node:
                for child in node['children']:
                    result = find_task_by_name(child, name)
                    if result:
                        return result
            return None

        exec_asm_task = find_task_by_name(tree, 'Execute .NET Assembly (execute-assembly)')
        assert exec_asm_task is not None

        metadata = exec_asm_task.get('metadata', {})
        assert 'flag_explanations' in metadata
        assert 'execute-assembly' in metadata['flag_explanations']

    def test_success_failure_indicators(self, plugin):
        """PROVES: Tasks include success and failure indicators"""
        service_info = {'framework': 'cobalt-strike'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        # Find a command task with indicators
        def find_command_with_indicators(node):
            if node.get('type') == 'command' and 'metadata' in node:
                metadata = node['metadata']
                if 'success_indicators' in metadata and 'failure_indicators' in metadata:
                    return node
            if 'children' in node:
                for child in node['children']:
                    result = find_command_with_indicators(child)
                    if result:
                        return result
            return None

        task = find_command_with_indicators(tree)
        assert task is not None, "Should have tasks with success/failure indicators"

        metadata = task['metadata']
        assert len(metadata['success_indicators']) > 0
        assert len(metadata['failure_indicators']) > 0

    def test_target_placeholder_in_commands(self, plugin):
        """PROVES: Commands use target placeholder for flexibility"""
        service_info = {'framework': 'all'}
        tree = plugin.get_task_tree('TARGET_HOST', 0, service_info)

        # Verify target is used in task IDs
        assert 'TARGET_HOST' in tree['id']

        # Check that children also reference target
        for child in tree['children']:
            assert 'TARGET_HOST' in child['id']

    def test_oscp_tags_assigned(self, plugin):
        """PROVES: Tasks have appropriate OSCP priority tags"""
        service_info = {'framework': 'all'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        # Collect all tags from all tasks
        def collect_tags(node, tags_list):
            if 'metadata' in node and 'tags' in node['metadata']:
                tags_list.extend(node['metadata']['tags'])
            if 'children' in node:
                for child in node['children']:
                    collect_tags(child, tags_list)

        all_tags = []
        collect_tags(tree, all_tags)

        # Verify OSCP tags are present
        oscp_tags = [tag for tag in all_tags if tag.startswith('OSCP:')]
        assert len(oscp_tags) > 0, "Should have OSCP priority tags"

        # Verify multiple priority levels exist
        assert any('OSCP:HIGH' in tag for tag in all_tags), "Should have OSCP:HIGH tasks"

    def test_comprehensive_coverage(self, plugin):
        """PROVES: Plugin provides comprehensive C2 operations coverage"""
        service_info = {'framework': 'all'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        # Count total tasks
        def count_tasks(node):
            count = 1
            if 'children' in node:
                for child in node['children']:
                    count += count_tasks(child)
            return count

        total_tasks = count_tasks(tree)
        assert total_tasks > 50, "Should provide comprehensive coverage (50+ tasks)"

    def test_notes_field_educational(self, plugin):
        """PROVES: Manual tasks include educational notes"""
        service_info = {'framework': 'cobalt-strike'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        # Find manual task
        def find_manual_task(node):
            if node.get('type') == 'manual' and 'metadata' in node:
                return node
            if 'children' in node:
                for child in node['children']:
                    result = find_manual_task(child)
                    if result:
                        return result
            return None

        manual_task = find_manual_task(tree)
        assert manual_task is not None, "Should have manual tasks"

        metadata = manual_task['metadata']
        assert 'notes' in metadata or 'description' in metadata
        # Notes should provide educational context
        notes_or_desc = metadata.get('notes', metadata.get('description', ''))
        assert len(notes_or_desc) > 50, "Notes should provide substantial educational content"
