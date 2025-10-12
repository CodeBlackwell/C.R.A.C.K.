"""
Tests for PHP Bypass Plugin

Validates detection logic, task generation, and OSCP metadata completeness
for PHP disable_functions and open_basedir bypass techniques.
"""

import pytest
from crack.track.services.php_bypass import PHPBypassPlugin


class TestPHPBypassPlugin:
    """Test suite for PHP Bypass plugin"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return PHPBypassPlugin()

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "php-bypass"

    def test_default_ports(self, plugin):
        """PROVES: Plugin defines web service ports"""
        assert 80 in plugin.default_ports
        assert 443 in plugin.default_ports
        assert 8080 in plugin.default_ports

    def test_service_names(self, plugin):
        """PROVES: Plugin recognizes HTTP services"""
        assert 'http' in plugin.service_names
        assert 'https' in plugin.service_names

    def test_detect_http_service_without_php(self, plugin):
        """PROVES: Plugin returns 0 for generic HTTP (no PHP indicators)"""
        from crack.track.core.state import TargetProfile
        profile = TargetProfile("test.example.com")

        port_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '',
            'extrainfo': ''
        }
        # Should return 0 (no PHP evidence) - HTTP plugin should win
        assert plugin.detect(port_info, profile) == 0

    def test_detect_https_service_with_php(self, plugin):
        """PROVES: Plugin detects HTTPS services with PHP explicitly in version"""
        from crack.track.core.state import TargetProfile
        profile = TargetProfile("test.example.com")

        port_info = {
            'port': 443,
            'service': 'https',
            'product': 'nginx',
            'version': 'nginx/1.18 with PHP/7.4',
            'extrainfo': ''
        }
        # Should return 95 (PHP explicitly detected)
        assert plugin.detect(port_info, profile) == 95

    def test_detect_php_product(self, plugin):
        """PROVES: Plugin detects PHP in product string"""
        from crack.track.core.state import TargetProfile
        profile = TargetProfile("test.example.com")

        port_info = {
            'port': 8080,
            'service': 'http-proxy',
            'product': 'PHP 7.4',
            'version': '',
            'extrainfo': ''
        }
        # Should return 95 (PHP in product)
        assert plugin.detect(port_info, profile) == 95

    def test_detect_negative(self, plugin):
        """PROVES: Plugin returns 0 for non-HTTP services"""
        from crack.track.core.state import TargetProfile
        profile = TargetProfile("test.example.com")

        port_info = {
            'port': 22,
            'service': 'ssh',
            'product': 'OpenSSH',
            'version': '',
            'extrainfo': ''
        }
        # Should return 0 (not HTTP)
        assert plugin.detect(port_info, profile) == 0

    def test_detect_from_finding_php_technology(self, plugin):
        """PROVES: Plugin activates from PHP technology findings"""
        finding = {
            'type': 'tech_php',
            'description': 'PHP/7.4.3 detected'
        }
        # Should return 100 (perfect match)
        assert plugin.detect_from_finding(finding) == 100

    def test_detect_from_finding_webshell(self, plugin):
        """PROVES: Plugin prioritizes webshell findings"""
        finding = {
            'type': 'file',
            'description': 'webshell uploaded to target'
        }
        # Should return 95 (webshell priority)
        assert plugin.detect_from_finding(finding) == 95

    def test_detect_from_finding_php_indicators(self, plugin):
        """PROVES: Plugin detects PHP in finding descriptions"""
        finding = {
            'type': 'technology',
            'description': 'X-Powered-By: PHP/8.0'
        }
        # Should return 90 (PHP indicator)
        assert plugin.detect_from_finding(finding) == 90

    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid structure"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Root structure
        assert tree['id'] == 'php-bypass-80'
        assert tree['name'] == 'PHP Security Bypass Techniques (Port 80)'
        assert tree['type'] == 'parent'
        assert 'children' in tree
        assert len(tree['children']) > 0

    def test_task_phases_present(self, plugin):
        """PROVES: All major bypass technique phases are present"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        phase_ids = [child['id'] for child in tree['children']]

        # Verify major phases
        assert 'php-recon-80' in phase_ids  # Phase 1: Reconnaissance
        assert 'php-exec-functions-80' in phase_ids  # Phase 2: Exec functions
        assert 'open-basedir-bypass-80' in phase_ids  # Phase 3: open_basedir
        assert 'disable-funcs-bypass-80' in phase_ids  # Phase 4: disable_functions
        assert 'php-capabilities-80' in phase_ids  # Phase 5: PHP capabilities
        assert 'automated-tools-80' in phase_ids  # Phase 6: Tools

    def test_reconnaissance_tasks(self, plugin):
        """PROVES: Reconnaissance phase contains critical discovery tasks"""
        service_info = {'port': 443, 'service': 'https'}
        tree = plugin.get_task_tree('10.10.10.100', 443, service_info)

        recon_phase = next((c for c in tree['children'] if c['id'] == 'php-recon-443'), None)
        assert recon_phase is not None
        assert recon_phase['type'] == 'parent'
        assert len(recon_phase['children']) >= 2

        # Check for phpinfo task
        task_ids = [t['id'] for t in recon_phase['children']]
        assert 'phpinfo-check-443' in task_ids
        assert 'function-test-443' in task_ids

    def test_command_execution_functions(self, plugin):
        """PROVES: All major PHP execution functions covered"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        exec_phase = next((c for c in tree['children'] if c['id'] == 'php-exec-functions-80'), None)
        assert exec_phase is not None

        task_ids = [t['id'] for t in exec_phase['children']]

        # Verify all major execution functions covered
        assert 'exec-test-80' in task_ids
        assert 'system-test-80' in task_ids
        assert 'shell-exec-test-80' in task_ids
        assert 'proc-open-test-80' in task_ids
        assert 'pcntl-exec-test-80' in task_ids
        assert 'mail-abuse-80' in task_ids

    def test_basedir_bypass_techniques(self, plugin):
        """PROVES: open_basedir bypass techniques included"""
        service_info = {'port': 8080, 'service': 'http-alt'}
        tree = plugin.get_task_tree('192.168.45.200', 8080, service_info)

        basedir_phase = next((c for c in tree['children'] if c['id'] == 'open-basedir-bypass-8080'), None)
        assert basedir_phase is not None

        task_ids = [t['id'] for t in basedir_phase['children']]
        assert 'glob-bypass-8080' in task_ids
        assert 'fastcgi-basedir-bypass-8080' in task_ids

    def test_disable_functions_bypasses(self, plugin):
        """PROVES: Multiple disable_functions bypass techniques present"""
        service_info = {'port': 443, 'service': 'https'}
        tree = plugin.get_task_tree('192.168.45.150', 443, service_info)

        disable_phase = next((c for c in tree['children'] if c['id'] == 'disable-funcs-bypass-443'), None)
        assert disable_phase is not None

        task_ids = [t['id'] for t in disable_phase['children']]

        # Verify major bypass techniques
        assert 'ld-preload-bypass-443' in task_ids
        assert 'dl-function-bypass-443' in task_ids
        assert 'fastcgi-disable-funcs-443' in task_ids
        assert 'mod-cgi-bypass-443' in task_ids
        assert 'proc-mem-bypass-443' in task_ids

    def test_php_capabilities_without_exec(self, plugin):
        """PROVES: PHP native capabilities covered for restricted environments"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        capabilities_phase = next((c for c in tree['children'] if c['id'] == 'php-capabilities-80'), None)
        assert capabilities_phase is not None

        task_ids = [t['id'] for t in capabilities_phase['children']]
        assert 'file-operations-80' in task_ids
        assert 'network-operations-80' in task_ids
        assert 'database-operations-80' in task_ids

    def test_automated_tools_included(self, plugin):
        """PROVES: Automated bypass tools referenced"""
        service_info = {'port': 443, 'service': 'https'}
        tree = plugin.get_task_tree('192.168.45.100', 443, service_info)

        tools_phase = next((c for c in tree['children'] if c['id'] == 'automated-tools-443'), None)
        assert tools_phase is not None

        task_ids = [t['id'] for t in tools_phase['children']]
        assert 'dfunc-bypasser-443' in task_ids
        assert 'p0wny-shell-443' in task_ids
        assert 'chankro-443' in task_ids

    def test_oscp_metadata_completeness(self, plugin):
        """PROVES: Tasks include OSCP-required metadata fields"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Flatten task tree to get all tasks
        def get_all_tasks(node, tasks=[]):
            if node.get('type') == 'parent' and 'children' in node:
                for child in node['children']:
                    get_all_tasks(child, tasks)
            else:
                if 'metadata' in node:
                    tasks.append(node)
            return tasks

        all_tasks = []
        for phase in tree['children']:
            get_all_tasks(phase, all_tasks)

        assert len(all_tasks) > 10, "Should have multiple tasks with metadata"

        # Check first task with metadata
        task = all_tasks[0]
        metadata = task['metadata']

        # Required fields
        assert 'description' in metadata, "Tasks must have description"
        assert 'flag_explanations' in metadata, "Must explain flags/functions"
        assert 'success_indicators' in metadata, "Must define success criteria"
        assert 'failure_indicators' in metadata, "Must define failure modes"
        assert 'next_steps' in metadata, "Must provide next steps"
        assert 'alternatives' in metadata, "Must provide manual alternatives"
        assert 'tags' in metadata, "Must have classification tags"

    def test_flag_explanations_present(self, plugin):
        """PROVES: Flag explanations provided for educational value"""
        service_info = {'port': 443, 'service': 'https'}
        tree = plugin.get_task_tree('192.168.45.100', 443, service_info)

        # Get recon phase
        recon_phase = next((c for c in tree['children'] if c['id'] == 'php-recon-443'), None)
        phpinfo_task = recon_phase['children'][0]

        metadata = phpinfo_task['metadata']
        flag_expl = metadata['flag_explanations']

        # Verify flag explanations are meaningful
        assert 'phpinfo()' in flag_expl
        assert len(flag_expl['phpinfo()']) > 10  # Meaningful explanation

    def test_success_failure_indicators(self, plugin):
        """PROVES: Success and failure indicators help users verify results"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        exec_phase = next((c for c in tree['children'] if c['id'] == 'php-exec-functions-80'), None)
        exec_task = exec_phase['children'][0]  # exec() test

        metadata = exec_task['metadata']

        # Verify indicators exist and are useful
        assert len(metadata['success_indicators']) >= 2
        assert len(metadata['failure_indicators']) >= 2

        # Check for specific content
        success_text = ' '.join(metadata['success_indicators']).lower()
        assert 'output' in success_text or 'command' in success_text

    def test_alternatives_provided(self, plugin):
        """PROVES: Manual alternatives provided for OSCP exam scenarios"""
        service_info = {'port': 443, 'service': 'https'}
        tree = plugin.get_task_tree('192.168.45.100', 443, service_info)

        # Get a command execution task
        exec_phase = next((c for c in tree['children'] if c['id'] == 'php-exec-functions-443'), None)
        task = exec_phase['children'][0]

        metadata = task['metadata']
        alternatives = metadata['alternatives']

        # Verify alternatives exist and are meaningful
        assert len(alternatives) >= 2
        assert any('<?php' in alt for alt in alternatives)  # Contains actual PHP code

    def test_oscp_tags_appropriate(self, plugin):
        """PROVES: Tasks tagged with appropriate OSCP relevance"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Collect all tags from all tasks
        def collect_tags(node, all_tags=set()):
            if node.get('type') == 'parent' and 'children' in node:
                for child in node['children']:
                    collect_tags(child, all_tags)
            elif 'metadata' in node and 'tags' in node['metadata']:
                all_tags.update(node['metadata']['tags'])
            return all_tags

        all_tags = set()
        for phase in tree['children']:
            collect_tags(phase, all_tags)

        # Verify appropriate tags used
        assert 'OSCP:HIGH' in all_tags
        assert 'MANUAL' in all_tags
        assert 'QUICK_WIN' in all_tags
        assert 'ADVANCED' in all_tags

    def test_notes_provide_context(self, plugin):
        """PROVES: Notes provide additional context and warnings"""
        service_info = {'port': 443, 'service': 'https'}
        tree = plugin.get_task_tree('192.168.45.100', 443, service_info)

        # Get LD_PRELOAD bypass task (should have detailed notes)
        disable_phase = next((c for c in tree['children'] if c['id'] == 'disable-funcs-bypass-443'), None)
        ld_preload_task = next((t for t in disable_phase['children'] if t['id'] == 'ld-preload-bypass-443'), None)

        metadata = ld_preload_task['metadata']

        # Verify notes exist and are detailed
        assert 'notes' in metadata
        assert len(metadata['notes']) > 50  # Substantial notes
        assert 'CHECK:' in metadata['notes'] or 'TECHNIQUE:' in metadata['notes']

    def test_time_estimates_for_complex_tasks(self, plugin):
        """PROVES: Complex tasks include time estimates for exam planning"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Get advanced bypass tasks
        disable_phase = next((c for c in tree['children'] if c['id'] == 'disable-funcs-bypass-80'), None)

        tasks_with_time = [
            t for t in disable_phase['children']
            if 'metadata' in t and 'estimated_time' in t['metadata']
        ]

        # Verify time estimates present for advanced techniques
        assert len(tasks_with_time) >= 3, "Advanced techniques should have time estimates"

    def test_quick_win_tasks_prioritized(self, plugin):
        """PROVES: QUICK_WIN tasks present for rapid enumeration"""
        service_info = {'port': 443, 'service': 'https'}
        tree = plugin.get_task_tree('192.168.45.100', 443, service_info)

        # Collect tasks tagged QUICK_WIN
        def find_quick_wins(node, quick_wins=[]):
            if node.get('type') == 'parent' and 'children' in node:
                for child in node['children']:
                    find_quick_wins(child, quick_wins)
            elif 'metadata' in node and 'tags' in node['metadata']:
                if 'QUICK_WIN' in node['metadata']['tags']:
                    quick_wins.append(node)
            return quick_wins

        quick_wins = []
        for phase in tree['children']:
            find_quick_wins(phase, quick_wins)

        # Verify quick wins present
        assert len(quick_wins) >= 5, "Should have multiple QUICK_WIN tasks"

        # Verify quick wins are in early phases (recon, basic testing)
        quick_win_names = [t['name'] for t in quick_wins]
        quick_text = ' '.join(quick_win_names).lower()
        assert 'phpinfo' in quick_text or 'test' in quick_text or 'check' in quick_text

    def test_command_vs_manual_task_types(self, plugin):
        """PROVES: Tasks appropriately typed as command or manual"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Tools phase should have command tasks
        tools_phase = next((c for c in tree['children'] if c['id'] == 'automated-tools-80'), None)
        command_tasks = [t for t in tools_phase['children'] if t['type'] == 'command']
        manual_tasks = [t for t in tools_phase['children'] if t['type'] == 'manual']

        # dfunc-bypasser and chankro should be command type
        assert len(command_tasks) >= 2

        # Most PHP technique tasks should be manual (require webshell upload)
        exec_phase = next((c for c in tree['children'] if c['id'] == 'php-exec-functions-80'), None)
        exec_manual = [t for t in exec_phase['children'] if t['type'] == 'manual']
        assert len(exec_manual) >= 5  # Most exec function tests are manual

    def test_educational_value_comprehensive(self, plugin):
        """PROVES: Plugin provides comprehensive educational value for OSCP"""
        service_info = {'port': 443, 'service': 'https'}
        tree = plugin.get_task_tree('192.168.45.100', 443, service_info)

        # Count educational elements
        total_flag_explanations = 0
        total_alternatives = 0
        total_next_steps = 0

        def count_educational(node):
            nonlocal total_flag_explanations, total_alternatives, total_next_steps
            if node.get('type') == 'parent' and 'children' in node:
                for child in node['children']:
                    count_educational(child)
            elif 'metadata' in node:
                meta = node['metadata']
                total_flag_explanations += len(meta.get('flag_explanations', {}))
                total_alternatives += len(meta.get('alternatives', []))
                total_next_steps += len(meta.get('next_steps', []))

        for phase in tree['children']:
            count_educational(phase)

        # Verify substantial educational content
        assert total_flag_explanations >= 30, "Should explain many flags/concepts"
        assert total_alternatives >= 40, "Should provide many alternative methods"
        assert total_next_steps >= 50, "Should guide attack progression"

    def test_plugin_targets_post_exploitation(self, plugin):
        """PROVES: Plugin focuses on post-exploitation scenario (webshell obtained)"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Verify focus on bypass techniques, not initial exploitation
        root_name = tree['name'].lower()
        assert 'bypass' in root_name or 'security' in root_name

        # Check that tasks assume PHP code execution available
        recon_phase = next((c for c in tree['children'] if c['id'] == 'php-recon-80'), None)
        first_task = recon_phase['children'][0]

        # First task should be about enumerating restrictions, not getting access
        assert '<?php' in first_task['metadata']['command']
        assert 'phpinfo' in first_task['name'].lower() or 'check' in first_task['name'].lower()
