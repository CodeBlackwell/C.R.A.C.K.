"""
Tests for Apache HTTP Server plugin

PROVES:
- Plugin correctly detects Apache servers
- Task tree generates Apache-specific techniques
- OSCP metadata is complete and educational
- All major attack vectors covered
"""

import pytest
from crack.track.services.apache import ApachePlugin


class TestApachePlugin:
    """Test suite for Apache HTTP Server plugin"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return ApachePlugin()

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "apache"

    def test_default_ports(self, plugin):
        """PROVES: Plugin lists common Apache ports"""
        assert 80 in plugin.default_ports
        assert 443 in plugin.default_ports
        assert 8080 in plugin.default_ports
        assert 8443 in plugin.default_ports

    def test_service_names(self, plugin):
        """PROVES: Plugin recognizes HTTP service names"""
        assert 'http' in plugin.service_names
        assert 'https' in plugin.service_names

    # === DETECTION TESTS ===

    def test_detect_by_product_apache(self, plugin):
        """PROVES: Plugin detects Apache by product name"""
        port_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.4.41'
        }
        assert plugin.detect(port_info) == True

    def test_detect_by_product_httpd(self, plugin):
        """PROVES: Plugin detects httpd (Apache binary name)"""
        port_info = {
            'port': 80,
            'service': 'httpd',
            'product': 'httpd',
            'version': '2.4.29'
        }
        assert plugin.detect(port_info) == True

    def test_detect_by_version_field(self, plugin):
        """PROVES: Plugin detects Apache in version field"""
        port_info = {
            'port': 443,
            'service': 'https',
            'product': 'unknown',
            'version': 'Apache/2.4.52'
        }
        assert plugin.detect(port_info) == True

    def test_detect_linux_http_heuristic(self, plugin):
        """PROVES: Plugin uses Linux+HTTP heuristic for Apache"""
        port_info = {
            'port': 80,
            'service': 'http',
            'product': '',
            'extrainfo': '(Ubuntu)'
        }
        assert plugin.detect(port_info) == True

    def test_detect_negative_iis(self, plugin):
        """PROVES: Plugin rejects IIS servers"""
        port_info = {
            'port': 80,
            'service': 'http',
            'product': 'Microsoft IIS httpd',
            'version': '10.0'
        }
        assert plugin.detect(port_info) == False

    def test_detect_negative_nginx(self, plugin):
        """PROVES: Plugin rejects nginx servers"""
        port_info = {
            'port': 80,
            'service': 'http',
            'product': 'nginx',
            'version': '1.18.0'
        }
        assert plugin.detect(port_info) == False

    def test_detect_negative_ssh(self, plugin):
        """PROVES: Plugin rejects non-HTTP services"""
        port_info = {
            'port': 22,
            'service': 'ssh',
            'product': 'OpenSSH',
            'version': '8.2p1'
        }
        assert plugin.detect(port_info) == False

    # === TASK TREE STRUCTURE TESTS ===

    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid root structure"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.4.41'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        assert tree['id'] == 'apache-enum-80'
        assert 'Apache HTTP Server Enumeration' in tree['name']
        assert tree['type'] == 'parent'
        assert 'children' in tree
        assert len(tree['children']) > 0

    def test_task_tree_has_multiple_attack_vectors(self, plugin):
        """PROVES: Task tree covers major Apache attack vectors"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.4.41'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)
        task_ids = [task['id'] for task in tree['children']]

        # Must include these critical tasks
        assert any('php-ext' in tid for tid in task_ids), "Missing PHP extension enumeration"
        assert any('cve-2021-41773' in tid for tid in task_ids), "Missing CVE-2021-41773"
        assert any('htaccess-lfi' in tid for tid in task_ids), "Missing .htaccess LFI"
        assert any('confusion' in tid for tid in task_ids), "Missing confusion attacks"
        assert any('shellshock' in tid for tid in task_ids), "Missing Shellshock"
        assert any('old-php-cgi' in tid for tid in task_ids), "Missing old PHP+CGI RCE"

    def test_https_protocol_detection(self, plugin):
        """PROVES: Plugin correctly handles HTTPS on port 443"""
        service_info = {
            'port': 443,
            'service': 'https',
            'product': 'Apache httpd',
            'version': '2.4.52'
        }

        tree = plugin.get_task_tree('192.168.45.100', 443, service_info)

        # Check that base_url uses https
        cve_task = next((t for t in tree['children'] if 'cve-2021-41773' in t['id']), None)
        assert cve_task is not None
        assert 'https://' in cve_task['metadata']['command']

    # === OSCP METADATA TESTS ===

    def test_quick_win_tasks_present(self, plugin):
        """PROVES: Plugin includes QUICK_WIN tasks for rapid assessment"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.4.49'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        quick_wins = []
        def find_quick_wins(node):
            if node.get('type') == 'command' or node.get('type') == 'manual':
                tags = node.get('metadata', {}).get('tags', [])
                if 'QUICK_WIN' in tags:
                    quick_wins.append(node['name'])
            if 'children' in node:
                for child in node['children']:
                    find_quick_wins(child)

        find_quick_wins(tree)
        assert len(quick_wins) >= 3, "Should have at least 3 quick win tasks"

    def test_flag_explanations_present(self, plugin):
        """PROVES: All command tasks have flag explanations"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.4.41'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        def check_flags(node):
            if node.get('type') == 'command':
                metadata = node.get('metadata', {})
                assert 'flag_explanations' in metadata, f"Missing flag_explanations in {node['id']}"
                assert len(metadata['flag_explanations']) > 0, f"Empty flag_explanations in {node['id']}"
            if 'children' in node:
                for child in node['children']:
                    check_flags(child)

        check_flags(tree)

    def test_success_indicators_present(self, plugin):
        """PROVES: Tasks include success indicators"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.4.41'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        def check_indicators(node):
            if node.get('type') in ['command', 'manual']:
                metadata = node.get('metadata', {})
                assert 'success_indicators' in metadata, f"Missing success_indicators in {node['id']}"
            if 'children' in node:
                for child in node['children']:
                    check_indicators(child)

        check_indicators(tree)

    def test_alternatives_present(self, plugin):
        """PROVES: Tasks include manual alternatives for OSCP exam"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.4.41'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        tasks_with_alternatives = []
        def check_alternatives(node):
            if node.get('type') in ['command', 'manual']:
                metadata = node.get('metadata', {})
                if 'alternatives' in metadata and len(metadata['alternatives']) > 0:
                    tasks_with_alternatives.append(node['id'])
            if 'children' in node:
                for child in node['children']:
                    check_alternatives(child)

        check_alternatives(tree)
        assert len(tasks_with_alternatives) >= 5, "Should have multiple tasks with alternatives"

    def test_oscp_high_tags_present(self, plugin):
        """PROVES: Plugin prioritizes OSCP:HIGH tasks"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.4.41'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        oscp_high_count = 0
        def count_oscp_high(node):
            nonlocal oscp_high_count
            if node.get('type') in ['command', 'manual']:
                tags = node.get('metadata', {}).get('tags', [])
                if 'OSCP:HIGH' in tags:
                    oscp_high_count += 1
            if 'children' in node:
                for child in node['children']:
                    count_oscp_high(child)

        count_oscp_high(tree)
        assert oscp_high_count >= 5, "Should have at least 5 OSCP:HIGH tasks"

    # === SPECIFIC TECHNIQUE TESTS ===

    def test_cve_2021_41773_task(self, plugin):
        """PROVES: CVE-2021-41773 task is properly configured"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.4.49'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)
        cve_task = next((t for t in tree['children'] if 'cve-2021-41773' in t['id']), None)

        assert cve_task is not None
        assert cve_task['type'] == 'command'
        metadata = cve_task['metadata']
        assert '.%2e' in metadata['command'], "Should use URL-encoded path traversal"
        assert 'QUICK_WIN' in metadata['tags']
        assert 'CVE' in metadata['tags']
        assert 'flag_explanations' in metadata
        assert 'alternatives' in metadata

    def test_htaccess_lfi_task_tree(self, plugin):
        """PROVES: .htaccess LFI has multi-step workflow"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.4.52'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)
        htaccess_task = next((t for t in tree['children'] if 'htaccess-lfi' in t['id']), None)

        assert htaccess_task is not None
        assert htaccess_task['type'] == 'parent'
        assert len(htaccess_task['children']) >= 3, "Should have multi-step workflow"

        # Check for prerequisite check
        check_task = next((t for t in htaccess_task['children'] if 'check-override' in t['id']), None)
        assert check_task is not None

        # Check for payload crafting
        craft_task = next((t for t in htaccess_task['children'] if 'craft' in t['id']), None)
        assert craft_task is not None

        # Check for exploitation
        exploit_task = next((t for t in htaccess_task['children'] if 'exploit' in t['id']), None)
        assert exploit_task is not None

    def test_confusion_attacks_parent_task(self, plugin):
        """PROVES: Confusion attacks are organized hierarchically"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.4.41'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)
        confusion_task = next((t for t in tree['children'] if 'confusion' in t['id']), None)

        assert confusion_task is not None
        assert confusion_task['type'] == 'parent'
        assert len(confusion_task['children']) >= 4, "Should have multiple confusion techniques"

        # Check for specific confusion techniques
        child_ids = [c['id'] for c in confusion_task['children']]
        assert any('truncation' in cid for cid in child_ids), "Missing path truncation"
        assert any('handler' in cid for cid in child_ids), "Missing handler bypass"
        assert any('documentroot' in cid for cid in child_ids), "Missing DocumentRoot confusion"

    def test_shellshock_task_structure(self, plugin):
        """PROVES: Shellshock has detection and exploitation phases"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.2.22'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)
        shellshock_task = next((t for t in tree['children'] if 'shellshock' in t['id']), None)

        assert shellshock_task is not None
        assert shellshock_task['type'] == 'parent'

        # Check for detection task
        detect_task = next((t for t in shellshock_task['children'] if 'detect' in t['id']), None)
        assert detect_task is not None
        assert 'nmap' in detect_task['metadata']['command'].lower() or 'curl' in detect_task['metadata']['command'].lower()

        # Check for exploitation task
        exploit_task = next((t for t in shellshock_task['children'] if 'exploit' in t['id']), None)
        assert exploit_task is not None
        assert 'LHOST' in exploit_task['metadata']['command'] or 'reverse' in exploit_task['name'].lower()

    def test_old_php_cgi_rce_task(self, plugin):
        """PROVES: Old PHP+CGI RCE task is comprehensive"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.2.22'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)
        php_cgi_task = next((t for t in tree['children'] if 'old-php-cgi-rce' in t['id']), None)

        assert php_cgi_task is not None
        metadata = php_cgi_task['metadata']
        assert 'allow_url_include' in metadata['command']
        assert 'auto_prepend_file' in metadata['command']
        assert 'CVE' in metadata['tags']
        assert 'CVE-2012-1823' in metadata['notes'] or 'CVE-2012-2311' in metadata['notes']

    def test_server_status_info_tasks(self, plugin):
        """PROVES: Server-status and server-info enumeration included"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.4.41'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find server-status parent task
        status_task = next((t for t in tree['children'] if 'server-status' in t['id']), None)
        assert status_task is not None
        assert status_task['type'] == 'parent'

        # Check for both endpoints
        child_ids = [c['id'] for c in status_task['children']]
        assert any('status-check' in cid for cid in child_ids)
        assert any('info-check' in cid for cid in child_ids)

    # === VERSION-SPECIFIC TESTS ===

    def test_exploit_research_for_known_version(self, plugin):
        """PROVES: Plugin generates exploit research tasks for known versions"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.4.49'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)
        exploit_task = next((t for t in tree['children'] if 'exploit-research' in t['id']), None)

        assert exploit_task is not None
        assert exploit_task['type'] == 'parent'
        assert any('searchsploit' in c['id'] for c in exploit_task['children'])
        assert any('cve-lookup' in c['id'] for c in exploit_task['children'])

    def test_no_exploit_research_for_unknown_version(self, plugin):
        """PROVES: Plugin skips exploit research for unknown versions"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': 'unknown'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)
        exploit_task = next((t for t in tree['children'] if 'exploit-research' in t['id']), None)

        assert exploit_task is None

    # === EDUCATIONAL QUALITY TESTS ===

    def test_estimated_time_on_quick_tasks(self, plugin):
        """PROVES: Quick tasks have time estimates for exam planning"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.4.41'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        tasks_with_time = []
        def find_timed_tasks(node):
            if node.get('type') in ['command', 'manual']:
                metadata = node.get('metadata', {})
                if 'estimated_time' in metadata:
                    tasks_with_time.append(node['id'])
            if 'children' in node:
                for child in node['children']:
                    find_timed_tasks(child)

        find_timed_tasks(tree)
        assert len(tasks_with_time) >= 3, "Should have time estimates on critical tasks"

    def test_next_steps_guidance(self, plugin):
        """PROVES: Tasks provide next-step guidance"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.4.41'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        tasks_with_next_steps = []
        def find_next_steps(node):
            if node.get('type') in ['command', 'manual']:
                metadata = node.get('metadata', {})
                if 'next_steps' in metadata and len(metadata['next_steps']) > 0:
                    tasks_with_next_steps.append(node['id'])
            if 'children' in node:
                for child in node['children']:
                    find_next_steps(child)

        find_next_steps(tree)
        assert len(tasks_with_next_steps) >= 8, "Should guide users on next steps"

    def test_failure_indicators_present(self, plugin):
        """PROVES: Tasks help diagnose failures"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.4.41'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        tasks_with_failures = []
        def find_failure_indicators(node):
            if node.get('type') in ['command', 'manual']:
                metadata = node.get('metadata', {})
                if 'failure_indicators' in metadata:
                    tasks_with_failures.append(node['id'])
            if 'children' in node:
                for child in node['children']:
                    find_failure_indicators(child)

        find_failure_indicators(tree)
        assert len(tasks_with_failures) >= 5, "Should help diagnose failures"

    # === INTEGRATION TESTS ===

    def test_task_ids_unique(self, plugin):
        """PROVES: All task IDs are unique within tree"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.4.41'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        task_ids = []
        def collect_ids(node):
            task_ids.append(node['id'])
            if 'children' in node:
                for child in node['children']:
                    collect_ids(child)

        collect_ids(tree)

        assert len(task_ids) == len(set(task_ids)), "Task IDs must be unique"

    def test_port_in_task_ids(self, plugin):
        """PROVES: Task IDs include port number for uniqueness across targets"""
        service_info = {
            'port': 8080,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.4.41'
        }

        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        assert '8080' in tree['id']
        # Check children also include port
        for child in tree['children']:
            assert '8080' in child['id'], f"Child {child['name']} missing port in ID"

    def test_target_placeholder_in_commands(self, plugin):
        """PROVES: Commands use target variable correctly"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.4.41'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        def check_target_usage(node):
            if node.get('type') == 'command':
                command = node.get('metadata', {}).get('command', '')
                # Command should reference the actual target, not a placeholder
                assert '192.168.45.100' in command or '{target}' not in command, \
                    f"Command in {node['id']} has improper target reference"
            if 'children' in node:
                for child in node['children']:
                    check_target_usage(child)

        check_target_usage(tree)
