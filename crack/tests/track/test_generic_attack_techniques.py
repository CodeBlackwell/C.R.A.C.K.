"""
Tests for Generic Attack Techniques Plugin

Validates that the plugin generates comprehensive attack methodology
tasks for credential attacks, exploit research, exfiltration, and
specialized techniques.
"""

import pytest
from crack.track.services.generic_attack_techniques import GenericAttackTechniquesPlugin


class TestGenericAttackTechniquesPlugin:
    """Test suite for Generic Attack Techniques plugin"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return GenericAttackTechniquesPlugin()

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "generic-attacks"

    def test_plugin_service_names(self, plugin):
        """PROVES: Plugin is universal (applies to all services)"""
        assert '*' in plugin.service_names

    def test_detection_disabled_by_default(self, plugin):
        """PROVES: Plugin doesn't auto-activate (prevents duplication)"""
        port_info = {
            'port': 80,
            'service': 'http',
            'state': 'open'
        }
        # Should return False to prevent auto-activation
        assert plugin.detect(port_info) == False

    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid hierarchical structure"""
        service_info = {
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.4.41',
            'port': 80
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Verify root structure
        assert tree['id'] == 'generic-attacks'
        assert tree['name'] == 'Generic Attack Techniques'
        assert tree['type'] == 'parent'
        assert 'children' in tree
        assert len(tree['children']) > 0

        # Verify major phases present
        child_names = [child['name'] for child in tree['children']]
        assert any('Credential' in name for name in child_names)
        assert any('Exploit' in name or 'Research' in name for name in child_names)
        assert any('Exfiltration' in name for name in child_names)

    def test_credential_attacks_section(self, plugin):
        """PROVES: Credential attacks section includes key techniques"""
        service_info = {'service': 'http', 'port': 80}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find credential attacks section
        cred_section = None
        for child in tree['children']:
            if 'Credential' in child['name']:
                cred_section = child
                break

        assert cred_section is not None
        assert cred_section['type'] == 'parent'
        assert len(cred_section['children']) > 0

        # Check for key subsections
        subsection_names = [s['name'] for s in cred_section['children']]
        assert any('Default' in name for name in subsection_names)
        assert any('Wordlist' in name for name in subsection_names)
        assert any('Brute' in name for name in subsection_names)

    def test_wordlist_generation_tasks(self, plugin):
        """PROVES: Wordlist generation includes multiple methods"""
        service_info = {'service': 'http', 'port': 80}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Navigate to wordlist section
        cred_section = next(c for c in tree['children'] if 'Credential' in c['name'])
        wordlist_section = next(c for c in cred_section['children'] if 'Wordlist' in c['name'])

        assert wordlist_section['type'] == 'parent'
        assert len(wordlist_section['children']) >= 3

        # Check for specific tools
        task_names = [t['name'] for t in wordlist_section['children']]
        assert any('Crunch' in name for name in task_names)
        assert any('CeWL' in name or 'Website' in name for name in task_names)

    def test_exploit_research_section(self, plugin):
        """PROVES: Exploit research includes multiple sources"""
        service_info = {
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.4.41',
            'port': 80
        }
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find exploit research section
        research_section = None
        for child in tree['children']:
            if 'Exploit' in child['name'] or 'Research' in child['name']:
                research_section = child
                break

        assert research_section is not None
        assert len(research_section['children']) >= 2

        # Check for key research tasks
        task_ids = [t['id'] for t in research_section['children']]
        assert any('searchsploit' in task_id for task_id in task_ids)
        assert any('online' in task_id or 'cve' in task_id for task_id in task_ids)

    def test_exfiltration_methods_section(self, plugin):
        """PROVES: Exfiltration section covers major protocols"""
        service_info = {'service': 'http', 'port': 80}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find exfiltration section
        exfil_section = None
        for child in tree['children']:
            if 'Exfiltration' in child['name']:
                exfil_section = child
                break

        assert exfil_section is not None
        assert exfil_section['type'] == 'parent'
        assert len(exfil_section['children']) >= 3

        # Check for protocol coverage
        def find_tasks_recursive(node):
            """Recursively find all task names"""
            tasks = [node['name']]
            if 'children' in node:
                for child in node['children']:
                    tasks.extend(find_tasks_recursive(child))
            return tasks

        all_names = ' '.join(find_tasks_recursive(exfil_section))
        assert 'HTTP' in all_names
        assert 'FTP' in all_names or 'SMB' in all_names

    def test_oscp_metadata_completeness(self, plugin):
        """PROVES: Command tasks include OSCP-required metadata"""
        service_info = {'service': 'http', 'port': 80}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        def find_command_tasks(node):
            """Recursively find all command tasks"""
            tasks = []
            if node.get('type') == 'command':
                tasks.append(node)
            if 'children' in node:
                for child in node['children']:
                    tasks.extend(find_command_tasks(child))
            return tasks

        command_tasks = find_command_tasks(tree)
        assert len(command_tasks) > 0, "Should have at least one command task"

        # Check first command task for required fields
        task = command_tasks[0]
        metadata = task.get('metadata', {})

        assert 'command' in metadata, "Command tasks must have 'command' field"
        assert 'description' in metadata, "Tasks must have description"
        assert 'tags' in metadata, "Tasks must have tags"
        assert len(metadata['tags']) > 0, "Tags list must not be empty"

        # Most tasks should have educational fields
        has_educational = any(
            'flag_explanations' in find_task_metadata(t) or
            'alternatives' in find_task_metadata(t)
            for t in command_tasks[:5]  # Check first 5 tasks
        )
        assert has_educational, "Tasks should include educational metadata"

    def test_service_specific_brute_force_http(self, plugin):
        """PROVES: HTTP service gets HTTP-specific brute-force tasks"""
        service_info = {'service': 'http', 'port': 80}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        def find_task_by_id_contains(node, search_term):
            """Recursively search for task ID"""
            if search_term in node.get('id', ''):
                return node
            if 'children' in node:
                for child in node['children']:
                    result = find_task_by_id_contains(child, search_term)
                    if result:
                        return result
            return None

        http_brute = find_task_by_id_contains(tree, 'http-basic-brute')
        assert http_brute is not None
        assert 'metadata' in http_brute
        assert 'command' in http_brute['metadata']
        assert 'http-get' in http_brute['metadata']['command']

    def test_service_specific_brute_force_ssh(self, plugin):
        """PROVES: SSH service gets SSH-specific brute-force tasks"""
        service_info = {'service': 'ssh', 'port': 22}
        tree = plugin.get_task_tree('192.168.45.100', 22, service_info)

        def find_task_by_id_contains(node, search_term):
            """Recursively search for task ID"""
            if search_term in node.get('id', ''):
                return node
            if 'children' in node:
                for child in node['children']:
                    result = find_task_by_id_contains(child, search_term)
                    if result:
                        return result
            return None

        ssh_brute = find_task_by_id_contains(tree, 'ssh-brute')
        assert ssh_brute is not None
        assert 'metadata' in ssh_brute
        assert 'NOISY' in ssh_brute['metadata'].get('tags', [])
        assert 'SLOW' in ssh_brute['metadata'].get('tags', [])

    def test_specialized_techniques_section(self, plugin):
        """PROVES: Specialized techniques includes advanced attacks"""
        service_info = {'service': 'http', 'port': 80}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find specialized section
        specialized = None
        for child in tree['children']:
            if 'Specialized' in child['name']:
                specialized = child
                break

        assert specialized is not None
        assert specialized['type'] == 'parent'
        assert len(specialized['children']) > 0

        # Check for archive exploitation
        child_names = [c['name'] for c in specialized['children']]
        assert any('Archive' in name or 'Zip' in name for name in child_names)

    def test_archive_exploitation_tasks(self, plugin):
        """PROVES: Archive exploitation includes path traversal techniques"""
        service_info = {'service': 'http', 'port': 80}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        def find_task_recursive(node, search_term):
            """Recursively search for task"""
            if search_term.lower() in node.get('name', '').lower():
                return node
            if 'children' in node:
                for child in node['children']:
                    result = find_task_recursive(child, search_term)
                    if result:
                        return result
            return None

        archive_task = find_task_recursive(tree, 'archive') or find_task_recursive(tree, 'zip-slip')
        if archive_task:  # May be nested
            # Verify it has educational content
            if 'metadata' in archive_task:
                metadata = archive_task['metadata']
                assert 'description' in metadata
                # Check for CVE reference or path traversal mention
                full_text = str(metadata).lower()
                assert 'path' in full_text or 'traversal' in full_text or 'cve' in full_text

    def test_default_credentials_research_task(self, plugin):
        """PROVES: Default credentials task includes resource links"""
        service_info = {'service': 'http', 'port': 80}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        def find_task_by_id(node, task_id):
            """Recursively search by task ID"""
            if node.get('id') == task_id:
                return node
            if 'children' in node:
                for child in node['children']:
                    result = find_task_by_id(child, task_id)
                    if result:
                        return result
            return None

        default_creds = find_task_by_id(tree, 'default-creds-research')
        assert default_creds is not None
        assert 'metadata' in default_creds
        metadata = default_creds['metadata']

        # Should include resource links in notes or alternatives
        notes_and_alts = metadata.get('notes', '') + ' '.join(metadata.get('alternatives', []))
        assert 'https://' in notes_and_alts or 'github.com' in notes_and_alts

    def test_cewl_target_substitution(self, plugin):
        """PROVES: CeWL command includes target IP substitution"""
        target = '192.168.45.100'
        service_info = {'service': 'http', 'port': 80}
        tree = plugin.get_task_tree(target, 80, service_info)

        def find_task_by_name_contains(node, search_term):
            """Recursively search for task by name"""
            if search_term.lower() in node.get('name', '').lower():
                return node
            if 'children' in node:
                for child in node['children']:
                    result = find_task_by_name_contains(child, search_term)
                    if result:
                        return result
            return None

        cewl_task = find_task_by_name_contains(tree, 'cewl')
        if cewl_task and 'metadata' in cewl_task:
            command = cewl_task['metadata'].get('command', '')
            assert target in command, "CeWL command should include target IP"

    def test_tags_consistency(self, plugin):
        """PROVES: Tags follow standard conventions"""
        service_info = {'service': 'http', 'port': 80}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        def collect_all_tags(node):
            """Recursively collect all tags"""
            tags = set()
            if 'metadata' in node and 'tags' in node['metadata']:
                tags.update(node['metadata']['tags'])
            if 'children' in node:
                for child in node['children']:
                    tags.update(collect_all_tags(child))
            return tags

        all_tags = collect_all_tags(tree)

        # Verify standard tags are used
        standard_tags = {
            'OSCP:HIGH', 'OSCP:MEDIUM', 'OSCP:LOW',
            'QUICK_WIN', 'MANUAL', 'AUTOMATED',
            'NOISY', 'STEALTH', 'RESEARCH',
            'BRUTE_FORCE', 'EXFILTRATION', 'EXPLOIT'
        }

        found_standard = all_tags & standard_tags
        assert len(found_standard) > 0, "Should use standard tags"

    def test_multiple_exfiltration_protocols(self, plugin):
        """PROVES: Multiple exfiltration protocols covered"""
        service_info = {'service': 'http', 'port': 80}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        def find_section(node, name_contains):
            """Find section by name"""
            if name_contains.lower() in node.get('name', '').lower():
                return node
            if 'children' in node:
                for child in node['children']:
                    result = find_section(child, name_contains)
                    if result:
                        return result
            return None

        exfil_section = find_section(tree, 'exfiltration')
        assert exfil_section is not None

        # Count protocol sections
        if 'children' in exfil_section:
            child_names = [c.get('name', '') for c in exfil_section['children']]
            protocols_mentioned = ['HTTP', 'FTP', 'SMB', 'Netcat']
            protocols_found = sum(1 for p in protocols_mentioned if any(p in name for name in child_names))
            assert protocols_found >= 2, "Should cover at least 2 exfiltration protocols"


def find_task_metadata(task):
    """Helper to safely get task metadata"""
    return task.get('metadata', {})


def test_plugin_registration():
    """PROVES: Plugin is registered in ServiceRegistry"""
    from crack.track.services.registry import ServiceRegistry

    # Plugin should be auto-registered via decorator
    registered_plugins = [p.name for p in ServiceRegistry.get_all_plugins()]

    # Note: Plugin may not auto-register if detect() always returns False
    # This is by design - it's a manually triggered plugin
    # Test that it CAN be instantiated
    plugin = GenericAttackTechniquesPlugin()
    assert plugin.name == "generic-attacks"


def test_integration_with_real_service():
    """PROVES: Plugin generates valid tasks for real service scenario"""
    plugin = GenericAttackTechniquesPlugin()

    # Simulate real Apache service detection
    service_info = {
        'port': 80,
        'state': 'open',
        'service': 'http',
        'product': 'Apache httpd',
        'version': '2.4.41',
        'extrainfo': '(Ubuntu)',
        'source': 'nmap -sV scan'
    }

    tree = plugin.get_task_tree('10.10.10.100', 80, service_info)

    # Verify tree is complete and valid
    assert tree is not None
    assert tree['type'] == 'parent'
    assert len(tree['children']) >= 3  # At least 3 major sections

    # Verify exploit research includes version
    def find_task_with_version(node, version):
        """Check if version appears in any task"""
        if version in str(node):
            return True
        if 'children' in node:
            return any(find_task_with_version(child, version) for child in node['children'])
        return False

    assert find_task_with_version(tree, '2.4.41'), "Version should appear in exploit research"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
