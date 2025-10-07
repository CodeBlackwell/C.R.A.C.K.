"""
Tests for GraphQL service plugin

PROVES:
- Plugin detects HTTP/HTTPS services
- Task tree generated for GraphQL enumeration
- All OSCP metadata fields present
- Educational content (flag explanations, alternatives, next steps)
- Comprehensive coverage of HackTricks GraphQL techniques
"""

import pytest
from crack.track.services.graphql import GraphQLPlugin


class TestGraphQLPluginDetection:
    """Test GraphQL service detection logic"""

    @pytest.fixture
    def plugin(self):
        """Create GraphQL plugin instance"""
        return GraphQLPlugin()

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "graphql"

    def test_detect_http_service(self, plugin):
        """PROVES: Plugin detects HTTP service"""
        port_info = {
            'port': 80,
            'service': 'http',
            'state': 'open'
        }
        assert plugin.detect(port_info) == True

    def test_detect_https_service(self, plugin):
        """PROVES: Plugin detects HTTPS service"""
        port_info = {
            'port': 443,
            'service': 'https',
            'state': 'open'
        }
        assert plugin.detect(port_info) == True

    def test_detect_ssl_http(self, plugin):
        """PROVES: Plugin detects SSL/HTTP service"""
        port_info = {
            'port': 8443,
            'service': 'ssl/http',
            'state': 'open'
        }
        assert plugin.detect(port_info) == True

    def test_detect_common_web_ports(self, plugin):
        """PROVES: Plugin detects common web ports"""
        for port in [80, 443, 8080, 8443, 3000, 4000]:
            port_info = {'port': port, 'service': 'unknown'}
            assert plugin.detect(port_info) == True

    def test_detect_negative(self, plugin):
        """PROVES: Plugin rejects non-HTTP services"""
        port_info = {
            'port': 22,
            'service': 'ssh',
            'state': 'open'
        }
        assert plugin.detect(port_info) == False


class TestGraphQLTaskTreeStructure:
    """Test GraphQL task tree generation and structure"""

    @pytest.fixture
    def plugin(self):
        return GraphQLPlugin()

    @pytest.fixture
    def http_service_info(self):
        return {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.4.41',
            'state': 'open'
        }

    @pytest.fixture
    def https_service_info(self):
        return {
            'port': 443,
            'service': 'https',
            'product': 'nginx',
            'version': '1.18.0',
            'state': 'open'
        }

    def test_task_tree_root_structure(self, plugin, http_service_info):
        """PROVES: Task tree has valid root structure"""
        tree = plugin.get_task_tree('192.168.45.100', 80, http_service_info)

        assert 'id' in tree
        assert tree['id'] == 'graphql-enum-80'
        assert 'name' in tree
        assert 'GraphQL API Enumeration' in tree['name']
        assert 'type' in tree
        assert tree['type'] == 'parent'
        assert 'children' in tree
        assert len(tree['children']) > 0

    def test_task_tree_has_all_phases(self, plugin, http_service_info):
        """PROVES: Task tree includes all enumeration phases"""
        tree = plugin.get_task_tree('192.168.45.100', 80, http_service_info)

        phase_names = [child['name'] for child in tree['children']]

        # Expected phases
        assert any('Discovery' in name for name in phase_names)
        assert any('Introspection' in name for name in phase_names)
        assert any('No Introspection' in name for name in phase_names)
        assert any('Query Exploitation' in name for name in phase_names)
        assert any('Mutation Testing' in name for name in phase_names)
        assert any('Security' in name or 'DoS' in name for name in phase_names)
        assert any('Advanced' in name for name in phase_names)
        assert any('Tools' in name or 'Automated' in name for name in phase_names)

    def test_https_protocol_detection(self, plugin, https_service_info):
        """PROVES: Plugin uses HTTPS protocol for SSL services"""
        tree = plugin.get_task_tree('192.168.45.100', 443, https_service_info)

        # Find first command task
        discovery = tree['children'][0]
        first_task = discovery['children'][0]
        command = first_task['metadata']['command']

        assert 'https://' in command
        assert 'http://' not in command.replace('https://', '')

    def test_http_protocol_detection(self, plugin, http_service_info):
        """PROVES: Plugin uses HTTP protocol for non-SSL services"""
        tree = plugin.get_task_tree('192.168.45.100', 80, http_service_info)

        discovery = tree['children'][0]
        first_task = discovery['children'][0]
        command = first_task['metadata']['command']

        assert 'http://' in command
        # Should not have https (except in alternatives/notes)
        assert command.count('https://') == 0


class TestGraphQLOSCPMetadata:
    """Test OSCP-required metadata fields"""

    @pytest.fixture
    def plugin(self):
        return GraphQLPlugin()

    @pytest.fixture
    def task_tree(self, plugin):
        service_info = {
            'port': 443,
            'service': 'https',
            'state': 'open'
        }
        return plugin.get_task_tree('192.168.45.100', 443, service_info)

    def get_all_command_tasks(self, tree):
        """Recursively extract all command tasks from tree"""
        tasks = []
        if tree.get('type') == 'command':
            tasks.append(tree)
        if 'children' in tree:
            for child in tree['children']:
                tasks.extend(self.get_all_command_tasks(child))
        return tasks

    def test_command_tasks_have_commands(self, task_tree):
        """PROVES: All command tasks have actual commands"""
        command_tasks = self.get_all_command_tasks(task_tree)

        assert len(command_tasks) > 10, "Should have multiple command tasks"

        for task in command_tasks:
            metadata = task.get('metadata', {})
            assert 'command' in metadata, f"Task {task['id']} missing command"
            assert len(metadata['command']) > 0, f"Task {task['id']} has empty command"

    def test_command_tasks_have_descriptions(self, task_tree):
        """PROVES: All command tasks have descriptions"""
        command_tasks = self.get_all_command_tasks(task_tree)

        for task in command_tasks:
            metadata = task.get('metadata', {})
            assert 'description' in metadata, f"Task {task['id']} missing description"
            assert len(metadata['description']) > 10, f"Task {task['id']} description too short"

    def test_command_tasks_have_flag_explanations(self, task_tree):
        """PROVES: Command tasks explain flags (OSCP requirement)"""
        command_tasks = self.get_all_command_tasks(task_tree)

        tasks_with_flags = [t for t in command_tasks if 'flag_explanations' in t.get('metadata', {})]

        # Most command tasks should explain flags
        assert len(tasks_with_flags) >= len(command_tasks) * 0.7, \
            "At least 70% of command tasks should have flag_explanations"

        # Check quality of explanations
        for task in tasks_with_flags:
            explanations = task['metadata']['flag_explanations']
            assert len(explanations) > 0, f"Task {task['id']} has empty flag_explanations"

            for flag, explanation in explanations.items():
                assert len(explanation) > 5, f"Flag {flag} explanation too short in {task['id']}"

    def test_tasks_have_success_indicators(self, task_tree):
        """PROVES: Tasks provide success indicators"""
        command_tasks = self.get_all_command_tasks(task_tree)

        tasks_with_indicators = [t for t in command_tasks
                                if 'success_indicators' in t.get('metadata', {})]

        assert len(tasks_with_indicators) >= len(command_tasks) * 0.6, \
            "At least 60% of tasks should have success_indicators"

        for task in tasks_with_indicators:
            indicators = task['metadata']['success_indicators']
            assert len(indicators) >= 1, f"Task {task['id']} needs at least 1 success indicator"
            assert all(len(i) > 10 for i in indicators), f"Success indicators too short in {task['id']}"

    def test_tasks_have_failure_indicators(self, task_tree):
        """PROVES: Tasks provide failure indicators"""
        command_tasks = self.get_all_command_tasks(task_tree)

        tasks_with_failures = [t for t in command_tasks
                              if 'failure_indicators' in t.get('metadata', {})]

        assert len(tasks_with_failures) >= len(command_tasks) * 0.5, \
            "At least 50% of tasks should have failure_indicators"

    def test_tasks_have_alternatives(self, task_tree):
        """PROVES: Tasks provide manual alternatives (OSCP critical)"""
        all_tasks = self.get_all_command_tasks(task_tree)
        # Also check manual tasks
        manual_tasks = self.get_manual_tasks(task_tree)
        all_tasks.extend(manual_tasks)

        tasks_with_alternatives = [t for t in all_tasks
                                  if 'alternatives' in t.get('metadata', {})]

        assert len(tasks_with_alternatives) >= len(all_tasks) * 0.7, \
            "At least 70% of tasks should provide manual alternatives"

        for task in tasks_with_alternatives:
            alternatives = task['metadata']['alternatives']
            assert len(alternatives) >= 1, f"Task {task['id']} needs at least 1 alternative"

    def test_tasks_have_next_steps(self, task_tree):
        """PROVES: Tasks guide next steps"""
        command_tasks = self.get_all_command_tasks(task_tree)

        tasks_with_next_steps = [t for t in command_tasks
                                if 'next_steps' in t.get('metadata', {})]

        assert len(tasks_with_next_steps) >= len(command_tasks) * 0.6, \
            "At least 60% of tasks should have next_steps"

        for task in tasks_with_next_steps:
            steps = task['metadata']['next_steps']
            assert len(steps) >= 2, f"Task {task['id']} should have 2+ next steps"

    def test_tasks_have_tags(self, task_tree):
        """PROVES: Tasks are tagged for filtering"""
        command_tasks = self.get_all_command_tasks(task_tree)

        for task in command_tasks:
            metadata = task.get('metadata', {})
            if 'tags' in metadata:
                assert len(metadata['tags']) > 0, f"Task {task['id']} has empty tags"

                # Validate tag format
                valid_priorities = ['OSCP:HIGH', 'OSCP:MEDIUM', 'OSCP:LOW']
                valid_methods = ['MANUAL', 'AUTOMATED', 'QUICK_WIN', 'NOISY', 'STEALTH']
                valid_phases = ['ENUM', 'EXPLOIT', 'BYPASS', 'BRUTE_FORCE', 'VULN_SCAN',
                              'RESEARCH', 'AUTHZ', 'CSRF', 'SQLI', 'UPLOAD', 'WEBSOCKET',
                              'ADVANCED', 'WEB']

                all_valid = valid_priorities + valid_methods + valid_phases
                for tag in metadata['tags']:
                    assert tag in all_valid, f"Invalid tag '{tag}' in task {task['id']}"

    def get_manual_tasks(self, tree):
        """Extract all manual tasks"""
        tasks = []
        if tree.get('type') == 'manual':
            tasks.append(tree)
        if 'children' in tree:
            for child in tree['children']:
                tasks.extend(self.get_manual_tasks(child))
        return tasks


class TestGraphQLSpecificTechniques:
    """Test GraphQL-specific enumeration techniques"""

    @pytest.fixture
    def plugin(self):
        return GraphQLPlugin()

    @pytest.fixture
    def task_tree(self, plugin):
        service_info = {'port': 443, 'service': 'https'}
        return plugin.get_task_tree('192.168.45.100', 443, service_info)

    def find_task_by_id_pattern(self, tree, pattern):
        """Find task by ID pattern"""
        if pattern in tree.get('id', ''):
            return tree
        if 'children' in tree:
            for child in tree['children']:
                result = self.find_task_by_id_pattern(child, pattern)
                if result:
                    return result
        return None

    def test_endpoint_discovery_task(self, task_tree):
        """PROVES: Includes GraphQL endpoint discovery"""
        task = self.find_task_by_id_pattern(task_tree, 'path-enum')
        assert task is not None, "Missing endpoint discovery task"

        command = task['metadata']['command']
        # Should test common GraphQL paths
        assert '/graphql' in command
        assert '/graphiql' in command
        assert '__typename' in command

    def test_introspection_query_task(self, task_tree):
        """PROVES: Includes introspection enumeration"""
        task = self.find_task_by_id_pattern(task_tree, 'basic-introspection')
        assert task is not None, "Missing introspection task"

        command = task['metadata']['command']
        assert '__schema' in command
        assert 'types' in command

    def test_introspection_bypass_techniques(self, task_tree):
        """PROVES: Includes introspection bypass methods"""
        bypass_task = self.find_task_by_id_pattern(task_tree, 'introspection-bypass')
        assert bypass_task is not None, "Missing introspection bypass parent"

        assert len(bypass_task['children']) >= 2, "Should have multiple bypass techniques"

        bypass_ids = [child['id'] for child in bypass_task['children']]
        assert any('newline' in id for id in bypass_ids), "Missing newline bypass"
        assert any('get' in id for id in bypass_ids), "Missing GET method bypass"

    def test_clairvoyance_task(self, task_tree):
        """PROVES: Includes blind schema discovery (clairvoyance)"""
        task = self.find_task_by_id_pattern(task_tree, 'clairvoyance')
        assert task is not None, "Missing clairvoyance task"

        command = task['metadata']['command']
        assert 'clairvoyance' in command

    def test_batching_attack_task(self, task_tree):
        """PROVES: Includes batching attack for rate limit bypass"""
        task = self.find_task_by_id_pattern(task_tree, 'batching-bruteforce')
        assert task is not None, "Missing batching attack task"

        metadata = task['metadata']
        assert 'rate limit' in metadata['description'].lower()
        # Batching mentioned in command or tags
        content = metadata['command'] + str(metadata.get('tags', []))
        assert 'batch' in content.lower() or 'multiple' in metadata['description'].lower()

    def test_alias_attack_task(self, task_tree):
        """PROVES: Includes alias-based attacks"""
        task = self.find_task_by_id_pattern(task_tree, 'alias')
        assert task is not None, "Missing alias attack task"

        # Should mention aliases in command or description
        assert 'alias' in task['metadata']['command'].lower() or \
               'alias' in task['metadata']['description'].lower()

    def test_mutation_testing_phase(self, task_tree):
        """PROVES: Includes mutation (write operation) testing"""
        mutation_phase = self.find_task_by_id_pattern(task_tree, 'mutation-testing')
        assert mutation_phase is not None, "Missing mutation testing phase"

        assert len(mutation_phase['children']) >= 2, "Should have multiple mutation tests"

    def test_authorization_bypass_task(self, task_tree):
        """PROVES: Includes authorization bypass testing"""
        task = self.find_task_by_id_pattern(task_tree, 'authz')
        assert task is not None, "Missing authorization testing"

        # Should be tagged appropriately
        if 'tags' in task.get('metadata', {}):
            assert 'AUTHZ' in task['metadata']['tags'] or 'EXPLOIT' in task['metadata']['tags']

    def test_graphql_cop_scanner(self, task_tree):
        """PROVES: Includes automated vulnerability scanner"""
        task = self.find_task_by_id_pattern(task_tree, 'graphql-cop')
        assert task is not None, "Missing graphql-cop scanner"

        command = task['metadata']['command']
        assert 'graphql-cop' in command

    def test_fingerprinting_task(self, task_tree):
        """PROVES: Includes GraphQL engine fingerprinting"""
        task = self.find_task_by_id_pattern(task_tree, 'fingerprint')
        assert task is not None, "Missing fingerprinting task"

        command = task['metadata']['command']
        assert 'graphw00f' in command

    def test_cve_research_task(self, task_tree):
        """PROVES: Includes CVE research guidance"""
        task = self.find_task_by_id_pattern(task_tree, 'cve-research')
        assert task is not None, "Missing CVE research"

        # Should mention specific CVEs in alternatives or notes
        metadata = task['metadata']
        content = str(metadata.get('alternatives', [])) + metadata.get('notes', '')
        assert 'CVE-' in content, "Should reference specific CVEs"


class TestGraphQLEducationalContent:
    """Test educational value for OSCP preparation"""

    @pytest.fixture
    def plugin(self):
        return GraphQLPlugin()

    @pytest.fixture
    def task_tree(self, plugin):
        service_info = {'port': 80, 'service': 'http'}
        return plugin.get_task_tree('192.168.45.100', 80, service_info)

    def get_all_tasks(self, tree):
        """Get all tasks regardless of type"""
        tasks = [tree]
        if 'children' in tree:
            for child in tree['children']:
                tasks.extend(self.get_all_tasks(child))
        return tasks

    def test_quick_win_tasks_tagged(self, task_tree):
        """PROVES: Quick win tasks are identified"""
        all_tasks = self.get_all_tasks(task_tree)

        quick_wins = [t for t in all_tasks
                     if 'tags' in t.get('metadata', {})
                     and 'QUICK_WIN' in t['metadata']['tags']]

        assert len(quick_wins) >= 3, "Should have multiple quick win tasks"

    def test_oscp_priority_tagging(self, task_tree):
        """PROVES: Tasks are tagged with OSCP priority levels"""
        all_tasks = self.get_all_tasks(task_tree)

        tagged_tasks = [t for t in all_tasks
                       if 'tags' in t.get('metadata', {})]

        oscp_tagged = [t for t in tagged_tasks
                      if any(tag.startswith('OSCP:') for tag in t['metadata']['tags'])]

        assert len(oscp_tagged) >= len(tagged_tasks) * 0.5, \
            "At least 50% of tagged tasks should have OSCP priority"

    def test_manual_techniques_emphasized(self, task_tree):
        """PROVES: Manual techniques are emphasized (OSCP exam prep)"""
        all_tasks = self.get_all_tasks(task_tree)

        manual_tasks = [t for t in all_tasks
                       if t.get('type') == 'manual' or
                       ('tags' in t.get('metadata', {}) and 'MANUAL' in t['metadata']['tags'])]

        assert len(manual_tasks) >= 3, "Should have multiple manual technique tasks"

    def test_tool_installation_guidance(self, task_tree):
        """PROVES: Alternatives include tool installation instructions"""
        all_tasks = self.get_all_tasks(task_tree)

        install_guidance = []
        for task in all_tasks:
            alternatives = task.get('metadata', {}).get('alternatives', [])
            for alt in alternatives:
                if 'install' in alt.lower() or 'git clone' in alt.lower() or 'pip install' in alt.lower():
                    install_guidance.append(task)
                    break

        assert len(install_guidance) >= 3, "Should provide installation guidance for key tools"

    def test_time_estimates_provided(self, task_tree):
        """PROVES: Some tasks include time estimates (exam planning)"""
        all_tasks = self.get_all_tasks(task_tree)

        tasks_with_time = [t for t in all_tasks
                          if 'estimated_time' in t.get('metadata', {})]

        assert len(tasks_with_time) >= 3, "Should provide time estimates for planning"

    def test_notes_provide_context(self, task_tree):
        """PROVES: Notes provide additional context and tips"""
        all_tasks = self.get_all_tasks(task_tree)

        tasks_with_notes = [t for t in all_tasks
                           if 'notes' in t.get('metadata', {})]

        assert len(tasks_with_notes) >= 5, "Should have helpful notes throughout"

        for task in tasks_with_notes[:5]:  # Check first 5
            notes = task['metadata']['notes']
            assert len(notes) > 20, f"Notes should be substantial in {task['id']}"


class TestGraphQLPluginIntegration:
    """Test plugin integration with CRACK Track"""

    def test_plugin_registered(self):
        """PROVES: Plugin auto-registers with ServiceRegistry"""
        from crack.track.services.registry import ServiceRegistry

        # Instantiate plugin to ensure it registers
        plugin = GraphQLPlugin()

        # Get all registered plugin classes
        registered_names = ServiceRegistry._plugins

        # GraphQL plugin should be registered
        assert 'graphql' in registered_names, "GraphQL plugin should be registered"

    def test_plugin_creates_valid_task_ids(self):
        """PROVES: All task IDs are unique and valid"""
        plugin = GraphQLPlugin()
        service_info = {'port': 8080, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        def get_all_ids(tree):
            ids = [tree['id']]
            if 'children' in tree:
                for child in tree['children']:
                    ids.extend(get_all_ids(child))
            return ids

        all_ids = get_all_ids(tree)

        # Check uniqueness
        assert len(all_ids) == len(set(all_ids)), "All task IDs must be unique"

        # Check format (should include port)
        for task_id in all_ids:
            assert '8080' in task_id or 'root' in task_id, f"Task ID {task_id} should include port"

    def test_plugin_handles_different_ports(self):
        """PROVES: Plugin generates port-specific tasks"""
        plugin = GraphQLPlugin()

        tree_80 = plugin.get_task_tree('192.168.45.100', 80, {'service': 'http'})
        tree_443 = plugin.get_task_tree('192.168.45.100', 443, {'service': 'https'})

        # Different ports should generate different root IDs
        assert tree_80['id'] != tree_443['id']
        assert '80' in tree_80['id']
        assert '443' in tree_443['id']
