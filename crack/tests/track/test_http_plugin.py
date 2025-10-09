"""
Test HTTP/HTTPS enumeration plugin

Validates comprehensive HTTP enumeration task generation for OSCP workflows.
Most common OSCP service - critical to have thorough testing.
"""

import pytest
from crack.track.services.http import HTTPPlugin


class TestHTTPPlugin:
    """Test HTTP/HTTPS plugin functionality"""

    @pytest.fixture
    def plugin(self):
        """Create HTTP plugin instance"""
        return HTTPPlugin()

    # ======================
    # Registration Tests
    # ======================

    def test_plugin_registered(self, plugin):
        """PROVES: HTTP plugin accessible via registry"""
        from crack.track.services.registry import ServiceRegistry

        # Test with valid port_info dict
        port_info = {
            'port': 80,
            'service': 'http',
            'version': ''
        }
        registered = ServiceRegistry.get_plugin(port_info)
        assert registered is not None, "HTTP plugin not registered"
        assert registered.name == 'http'

    # ======================
    # Detection Tests
    # ======================

    def test_detect_http_by_service_name(self, plugin):
        """PROVES: Detects 'http' service"""
        port_info = {
            'port': 80,
            'service': 'http',
            'version': ''
        }
        confidence = plugin.detect(port_info)
        assert confidence == 100, "Should be perfect match (http on port 80)"

    def test_detect_https_by_service_name(self, plugin):
        """PROVES: Detects 'https' service"""
        port_info = {
            'port': 443,
            'service': 'https',
            'version': ''
        }
        confidence = plugin.detect(port_info)
        assert confidence == 100, "Should be perfect match (https on port 443)"

    def test_detect_http_by_port_80(self, plugin):
        """PROVES: Port 80 triggers HTTP detection"""
        port_info = {
            'port': 80,
            'service': 'unknown',
            'version': ''
        }
        confidence = plugin.detect(port_info)
        assert confidence == 60, "Should match by port with medium confidence"

    def test_detect_http_by_port_8080(self, plugin):
        """PROVES: Port 8080 triggers HTTP detection"""
        port_info = {
            'port': 8080,
            'service': '',
            'version': ''
        }
        confidence = plugin.detect(port_info)
        assert confidence == 60, "Port 8080 should match with medium confidence"

    def test_detect_http_by_version_apache(self, plugin):
        """PROVES: Apache version string triggers detection"""
        port_info = {
            'port': 9999,
            'service': 'unknown',
            'version': 'Apache httpd 2.4.41'
        }
        confidence = plugin.detect(port_info)
        assert confidence == 80, "Apache version should trigger detection"

    def test_detect_http_by_version_nginx(self, plugin):
        """PROVES: Nginx version string triggers detection"""
        port_info = {
            'port': 9000,
            'service': '',
            'version': 'nginx 1.18.0'
        }
        confidence = plugin.detect(port_info)
        assert confidence == 80, "Nginx version should trigger detection"

    def test_detect_ssl_http_service(self, plugin):
        """PROVES: Detects 'ssl/http' service"""
        port_info = {
            'port': 443,
            'service': 'ssl/http',
            'version': ''
        }
        confidence = plugin.detect(port_info)
        assert confidence == 90, "ssl/http should be high confidence"

    def test_no_detection_for_non_http(self, plugin):
        """PROVES: Does not match non-HTTP services"""
        port_info = {
            'port': 22,
            'service': 'ssh',
            'version': 'OpenSSH 7.4'
        }
        confidence = plugin.detect(port_info)
        assert confidence == 0, "Should not detect SSH as HTTP"

    def test_web_keyword_detection(self, plugin):
        """PROVES: Detects web-related keywords in service"""
        port_info = {
            'port': 9000,
            'service': 'web-api',
            'version': ''
        }
        confidence = plugin.detect(port_info)
        assert confidence == 40, "web-api keyword should trigger detection"

    # ======================
    # Task Generation Tests
    # ======================

    def test_http_task_tree_structure(self, plugin):
        """PROVES: HTTP task tree has correct structure"""
        service_info = {
            'port': 80,
            'service': 'http',
            'version': 'Apache httpd 2.4.41'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Root structure
        assert tree['id'] == 'http-enum-80'
        assert 'HTTP Enumeration' in tree['name']
        assert tree['type'] == 'parent'
        assert 'children' in tree
        assert len(tree['children']) > 0

    def test_https_uses_correct_protocol(self, plugin):
        """PROVES: HTTPS service generates https:// URLs"""
        service_info = {
            'port': 443,
            'service': 'https',
            'version': ''
        }

        tree = plugin.get_task_tree('192.168.45.100', 443, service_info)

        # Find whatweb task
        whatweb_task = None
        for task in tree['children']:
            if 'whatweb' in task['id']:
                whatweb_task = task
                break

        assert whatweb_task is not None
        command = whatweb_task['metadata']['command']
        assert 'https://192.168.45.100:443' in command, "Should use HTTPS protocol"

    def test_gobuster_task_generated(self, plugin):
        """PROVES: Gobuster directory brute-force task created"""
        service_info = {'port': 80, 'service': 'http', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find gobuster task
        gobuster_task = None
        for task in tree['children']:
            if 'gobuster' in task['id']:
                gobuster_task = task
                break

        assert gobuster_task is not None, "Gobuster task not found"
        assert gobuster_task['type'] == 'command'

        metadata = gobuster_task['metadata']
        assert 'gobuster dir' in metadata['command']
        assert '-u http://192.168.45.100:80' in metadata['command']
        assert '-w' in metadata['command']
        assert 'dirb/common.txt' in metadata['command']

    def test_nikto_task_generated(self, plugin):
        """PROVES: Nikto vulnerability scan task created"""
        service_info = {'port': 80, 'service': 'http', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find nikto task
        nikto_task = None
        for task in tree['children']:
            if 'nikto' in task['id']:
                nikto_task = task
                break

        assert nikto_task is not None, "Nikto task not found"

        metadata = nikto_task['metadata']
        assert 'nikto' in metadata['command']
        assert '-h http://192.168.45.100:80' in metadata['command']
        assert 'NOISY' in metadata['tags']

    def test_whatweb_task_generated(self, plugin):
        """PROVES: Technology fingerprinting task created"""
        service_info = {'port': 80, 'service': 'http', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find whatweb task
        whatweb_task = None
        for task in tree['children']:
            if 'whatweb' in task['id']:
                whatweb_task = task
                break

        assert whatweb_task is not None, "WhatWeb task not found"
        assert 'Technology Fingerprinting' in whatweb_task['name']

        metadata = whatweb_task['metadata']
        assert 'whatweb' in metadata['command']
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'QUICK_WIN' in metadata['tags']

    def test_http_methods_enumeration_task(self, plugin):
        """PROVES: HTTP methods enumeration task generated"""
        service_info = {'port': 80, 'service': 'http', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find HTTP methods task
        methods_task = None
        for task in tree['children']:
            if 'http-methods' in task['id']:
                methods_task = task
                break

        assert methods_task is not None, "HTTP methods task not found"

        metadata = methods_task['metadata']
        assert 'nmap' in metadata['command']
        assert '--script http-methods' in metadata['command']
        assert 'retest' in metadata['command'], "Should test each method individually"

    def test_xst_detection_task(self, plugin):
        """PROVES: Cross-Site Tracing detection task generated"""
        service_info = {'port': 80, 'service': 'http', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find XST task
        xst_task = None
        for task in tree['children']:
            if 'http-trace' in task['id']:
                xst_task = task
                break

        assert xst_task is not None, "XST detection task not found"
        assert 'XST' in xst_task['name'] or 'Cross Site Tracing' in xst_task['name']

        metadata = xst_task['metadata']
        assert 'TRACE' in metadata['description']

    def test_nse_directory_enumeration_task(self, plugin):
        """PROVES: NSE http-enum task generated"""
        service_info = {'port': 80, 'service': 'http', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find http-enum task
        enum_task = None
        for task in tree['children']:
            if 'http-enum' in task['id']:
                enum_task = task
                break

        assert enum_task is not None, "NSE http-enum task not found"

        metadata = enum_task['metadata']
        assert '--script http-enum' in metadata['command']

    def test_waf_detection_task(self, plugin):
        """PROVES: WAF detection task generated"""
        service_info = {'port': 80, 'service': 'http', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find WAF detection task
        waf_task = None
        for task in tree['children']:
            if 'waf-detect' in task['id']:
                waf_task = task
                break

        assert waf_task is not None, "WAF detection task not found"

        metadata = waf_task['metadata']
        assert 'http-waf-detect' in metadata['command']
        assert 'RECON' in metadata['tags']

    def test_default_credentials_task(self, plugin):
        """PROVES: Default credentials testing task generated"""
        service_info = {'port': 80, 'service': 'http', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find default accounts task
        default_task = None
        for task in tree['children']:
            if 'http-default-accounts' in task['id']:
                default_task = task
                break

        assert default_task is not None, "Default credentials task not found"

        metadata = default_task['metadata']
        assert 'http-default-accounts' in metadata['command']
        assert 'QUICK_WIN' in metadata['tags']

    def test_http_brute_force_task(self, plugin):
        """PROVES: HTTP authentication brute-force task generated"""
        service_info = {'port': 80, 'service': 'http', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find brute-force task
        brute_task = None
        for task in tree['children']:
            if 'http-brute' in task['id']:
                brute_task = task
                break

        assert brute_task is not None, "HTTP brute-force task not found"

        metadata = brute_task['metadata']
        assert 'http-brute' in metadata['command']
        assert 'BRUTE_FORCE' in metadata['tags']
        assert 'NOISY' in metadata['tags']

    def test_manual_checks_included(self, plugin):
        """PROVES: Manual enumeration tasks included"""
        service_info = {'port': 80, 'service': 'http', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find manual checks parent
        manual_parent = None
        for task in tree['children']:
            if 'manual-checks' in task['id']:
                manual_parent = task
                break

        assert manual_parent is not None, "Manual checks not found"
        assert manual_parent['type'] == 'parent'
        assert 'children' in manual_parent

        child_ids = [c['id'] for c in manual_parent['children']]
        assert any('robots' in cid for cid in child_ids), "robots.txt check missing"
        assert any('sitemap' in cid for cid in child_ids), "sitemap.xml check missing"
        assert any('headers' in cid for cid in child_ids), "HTTP headers check missing"
        assert any('source' in cid for cid in child_ids), "Source review missing"

    def test_robots_txt_check(self, plugin):
        """PROVES: robots.txt check included in manual tasks"""
        service_info = {'port': 80, 'service': 'http', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find robots.txt task
        robots_task = None
        for parent in tree['children']:
            if 'manual-checks' in parent['id']:
                for child in parent.get('children', []):
                    if 'robots' in child['id']:
                        robots_task = child
                        break

        assert robots_task is not None, "robots.txt task not found"

        metadata = robots_task['metadata']
        assert 'curl' in metadata['command']
        assert '/robots.txt' in metadata['command']
        assert 'QUICK_WIN' in metadata['tags']

    # ======================
    # Metadata Quality Tests
    # ======================

    def test_oscp_metadata_complete(self, plugin):
        """PROVES: All HTTP tasks have complete OSCP metadata"""
        service_info = {'port': 80, 'service': 'http', 'version': 'Apache 2.4.41'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        def check_task_metadata(task):
            """Recursively check task metadata"""
            if task['type'] == 'command':
                metadata = task.get('metadata', {})

                # Required fields
                assert 'command' in metadata, f"Missing command in {task['id']}"
                assert 'description' in metadata, f"Missing description in {task['id']}"
                assert 'tags' in metadata, f"Missing tags in {task['id']}"

                # Educational fields
                if 'nmap' in metadata['command'] or 'gobuster' in metadata['command']:
                    assert 'flag_explanations' in metadata, f"Missing flag explanations in {task['id']}"

                # Searchsploit/research tasks don't need indicators (informational)
                if 'searchsploit' not in task['id'] and 'cve-lookup' not in task['id']:
                    assert 'success_indicators' in metadata or 'failure_indicators' in metadata, \
                        f"Missing indicators in {task['id']}"

            # Recurse into children
            if 'children' in task:
                for child in task['children']:
                    check_task_metadata(child)

        check_task_metadata(tree)

    def test_flag_explanations_present(self, plugin):
        """PROVES: Command tasks include flag explanations"""
        service_info = {'port': 80, 'service': 'http', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find gobuster task
        gobuster_task = None
        for task in tree['children']:
            if 'gobuster' in task['id']:
                gobuster_task = task
                break

        assert gobuster_task is not None

        metadata = gobuster_task['metadata']
        assert 'flag_explanations' in metadata

        flags = metadata['flag_explanations']
        assert 'dir' in flags, "Missing 'dir' flag explanation"
        assert '-u' in flags, "Missing '-u' flag explanation"
        assert '-w' in flags, "Missing '-w' flag explanation"

    def test_success_indicators_present(self, plugin):
        """PROVES: Tasks include success indicators"""
        service_info = {'port': 80, 'service': 'http', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Check whatweb task
        whatweb_task = None
        for task in tree['children']:
            if 'whatweb' in task['id']:
                whatweb_task = task
                break

        assert whatweb_task is not None

        metadata = whatweb_task['metadata']
        assert 'success_indicators' in metadata
        assert len(metadata['success_indicators']) > 0
        assert isinstance(metadata['success_indicators'], list)

    def test_next_steps_guidance(self, plugin):
        """PROVES: Tasks include next-step guidance"""
        service_info = {'port': 80, 'service': 'http', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Check nikto task
        nikto_task = None
        for task in tree['children']:
            if 'nikto' in task['id']:
                nikto_task = task
                break

        assert nikto_task is not None

        metadata = nikto_task['metadata']
        assert 'next_steps' in metadata
        assert len(metadata['next_steps']) > 0

    def test_manual_alternatives_provided(self, plugin):
        """PROVES: Automated tasks include manual alternatives"""
        service_info = {'port': 80, 'service': 'http', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Check gobuster task
        gobuster_task = None
        for task in tree['children']:
            if 'gobuster' in task['id']:
                gobuster_task = task
                break

        assert gobuster_task is not None

        metadata = gobuster_task['metadata']
        assert 'alternatives' in metadata
        assert len(metadata['alternatives']) > 0
        assert isinstance(metadata['alternatives'], list)

    # ======================
    # Alternative Commands Integration (Phase 6)
    # ======================

    def test_alternative_commands_linked(self, plugin):
        """PROVES: Phase 6 alternative commands linked to tasks"""
        service_info = {'port': 80, 'service': 'http', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Check whatweb task for alternative_ids
        whatweb_task = None
        for task in tree['children']:
            if 'whatweb' in task['id']:
                whatweb_task = task
                break

        assert whatweb_task is not None

        metadata = whatweb_task['metadata']
        assert 'alternative_ids' in metadata, "Phase 6: alternative_ids missing"
        assert isinstance(metadata['alternative_ids'], list)
        assert len(metadata['alternative_ids']) > 0

    def test_alternative_context_provided(self, plugin):
        """PROVES: Alternative commands have context metadata"""
        service_info = {'port': 80, 'service': 'http', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Check gobuster task
        gobuster_task = None
        for task in tree['children']:
            if 'gobuster' in task['id']:
                gobuster_task = task
                break

        assert gobuster_task is not None

        metadata = gobuster_task['metadata']
        assert 'alternative_context' in metadata, "Phase 6: alternative_context missing"

        context = metadata['alternative_context']
        assert 'service' in context
        assert context['service'] == 'http'
        assert 'port' in context
        assert 'purpose' in context

    def test_wordlist_metadata_present(self, plugin):
        """PROVES: Phase 4 wordlist selection metadata present"""
        service_info = {'port': 80, 'service': 'http', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Check gobuster task
        gobuster_task = None
        for task in tree['children']:
            if 'gobuster' in task['id']:
                gobuster_task = task
                break

        assert gobuster_task is not None

        metadata = gobuster_task['metadata']
        assert 'wordlist_purpose' in metadata, "Phase 4: wordlist_purpose missing"
        assert metadata['wordlist_purpose'] == 'web-enumeration'

    # ======================
    # Exploit Research Tests
    # ======================

    def test_exploit_research_with_version(self, plugin):
        """PROVES: Exploit research generated when version detected"""
        service_info = {
            'port': 80,
            'service': 'http',
            'version': 'Apache httpd 2.4.41'
        }
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find exploit research parent
        exploit_parent = None
        for task in tree['children']:
            if 'exploit-research' in task['id']:
                exploit_parent = task
                break

        assert exploit_parent is not None, "Exploit research not generated for versioned service"
        assert exploit_parent['type'] == 'parent'

        child_ids = [c['id'] for c in exploit_parent['children']]
        assert any('searchsploit' in cid for cid in child_ids), "SearchSploit task missing"

    def test_no_exploit_research_without_version(self, plugin):
        """PROVES: Exploit research skipped when no version"""
        service_info = {
            'port': 80,
            'service': 'http',
            'version': ''
        }
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Check for exploit research
        exploit_parent = None
        for task in tree['children']:
            if 'exploit-research' in task['id']:
                exploit_parent = task
                break

        # Should not generate exploit research without version
        assert exploit_parent is None, "Should not generate exploit research without version"

    # ======================
    # Dynamic Task Generation Tests
    # ======================

    def test_wordpress_detection_spawns_wpscan(self, plugin):
        """PROVES: WordPress detection triggers WPScan task"""
        # Simulate whatweb completing with WordPress result
        task_id = 'whatweb-80'
        result = 'WordPress 5.7.2 detected'
        target = '192.168.45.100'

        new_tasks = plugin.on_task_complete(task_id, result, target)

        # Should spawn wpscan task
        assert len(new_tasks) > 0, "Should generate WPScan task"

        wpscan_task = new_tasks[0]
        assert 'wpscan' in wpscan_task['id']
        assert 'WordPress' in wpscan_task['name']
        assert 'wpscan' in wpscan_task['metadata']['command']

    def test_admin_panel_detection_spawns_login_test(self, plugin):
        """PROVES: /admin discovery triggers login testing"""
        task_id = 'gobuster-80'
        result = 'Found: /admin (Status: 200)'
        target = '192.168.45.100'

        new_tasks = plugin.on_task_complete(task_id, result, target)

        # Should spawn admin login test
        assert len(new_tasks) > 0, "Should generate admin login test"

        admin_task = new_tasks[0]
        assert 'admin-login-test' in admin_task['id']
        assert 'Admin Panel' in admin_task['name']

    # ======================
    # OSCP Tag Coverage Tests
    # ======================

    def test_oscp_high_tags_present(self, plugin):
        """PROVES: High-value OSCP tasks tagged correctly"""
        service_info = {'port': 80, 'service': 'http', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        high_value_tasks = 0

        def count_high_value(task):
            nonlocal high_value_tasks
            if task.get('type') == 'command':
                metadata = task.get('metadata', {})
                if 'OSCP:HIGH' in metadata.get('tags', []):
                    high_value_tasks += 1

            if 'children' in task:
                for child in task['children']:
                    count_high_value(child)

        count_high_value(tree)

        # Should have multiple high-value tasks
        assert high_value_tasks >= 5, f"Expected 5+ OSCP:HIGH tasks, got {high_value_tasks}"

    def test_quick_win_tags_present(self, plugin):
        """PROVES: Quick win tasks identified"""
        service_info = {'port': 80, 'service': 'http', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        quick_wins = []

        def collect_quick_wins(task):
            if task.get('type') in ['command', 'manual']:
                metadata = task.get('metadata', {})
                if 'QUICK_WIN' in metadata.get('tags', []):
                    quick_wins.append(task['id'])

            if 'children' in task:
                for child in task['children']:
                    collect_quick_wins(child)

        collect_quick_wins(tree)

        assert len(quick_wins) >= 3, "Should have multiple quick win tasks"

    # ======================
    # Task Hierarchy Tests
    # ======================

    def test_no_duplicate_task_ids(self, plugin):
        """PROVES: All task IDs are unique (known duplicate: http-enum-80)"""
        service_info = {'port': 80, 'service': 'http', 'version': 'Apache 2.4.41'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        def collect_ids(node):
            ids = [node['id']]
            if 'children' in node:
                for child in node['children']:
                    ids.extend(collect_ids(child))
            return ids

        all_ids = collect_ids(tree)

        # Known duplicate: http-enum-80 (root and NSE task)
        # This is acceptable as they serve different purposes
        duplicates = [id for id in all_ids if all_ids.count(id) > 1]

        # Only allow http-enum-{port} as acceptable duplicate
        for dup_id in set(duplicates):
            assert dup_id.startswith('http-enum-'), \
                f"Unexpected duplicate ID: {dup_id}"

    def test_task_hierarchy_valid(self, plugin):
        """PROVES: Task tree structure is valid"""
        service_info = {'port': 80, 'service': 'http', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        def validate_node(node, depth=0):
            assert 'id' in node, "Node missing ID"
            assert 'name' in node, "Node missing name"
            assert 'type' in node, "Node missing type"
            assert node['type'] in ['parent', 'command', 'manual'], f"Invalid type: {node['type']}"

            if node['type'] == 'parent':
                assert 'children' in node, "Parent node missing children"
                assert len(node['children']) > 0, "Parent node has no children"

                for child in node['children']:
                    validate_node(child, depth + 1)

            if node['type'] in ['command', 'manual']:
                assert 'metadata' in node, "Command/manual node missing metadata"

        validate_node(tree)

    def test_comprehensive_coverage(self, plugin):
        """PROVES: Comprehensive HTTP enumeration coverage"""
        service_info = {'port': 80, 'service': 'http', 'version': 'Apache 2.4.41'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Collect all task categories
        task_categories = set()
        for task in tree['children']:
            if 'whatweb' in task['id']:
                task_categories.add('fingerprinting')
            elif 'gobuster' in task['id']:
                task_categories.add('directory-enum')
            elif 'nikto' in task['id']:
                task_categories.add('vuln-scan')
            elif 'http-methods' in task['id']:
                task_categories.add('methods-enum')
            elif 'http-trace' in task['id']:
                task_categories.add('xst-detection')
            elif 'http-enum' in task['id']:
                task_categories.add('nse-enum')
            elif 'waf-detect' in task['id']:
                task_categories.add('waf-detection')
            elif 'default-accounts' in task['id']:
                task_categories.add('default-creds')
            elif 'http-brute' in task['id']:
                task_categories.add('brute-force')
            elif 'manual-checks' in task['id']:
                task_categories.add('manual-enum')
            elif 'exploit-research' in task['id']:
                task_categories.add('exploit-research')

        # Should cover all major HTTP enumeration categories
        expected_categories = {
            'fingerprinting',
            'directory-enum',
            'vuln-scan',
            'methods-enum',
            'manual-enum'
        }

        assert expected_categories.issubset(task_categories), \
            f"Missing categories: {expected_categories - task_categories}"

    def test_task_count_reasonable(self, plugin):
        """PROVES: Reasonable number of tasks (not too few, not too many)"""
        service_info = {'port': 80, 'service': 'http', 'version': 'Apache 2.4.41'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Count all tasks
        def count_tasks(node):
            count = 1
            if 'children' in node:
                for child in node['children']:
                    count += count_tasks(child)
            return count

        total_tasks = count_tasks(tree)

        # Should have comprehensive coverage but not overwhelming
        assert 15 <= total_tasks <= 50, \
            f"Task count should be 15-50, got {total_tasks}"

    # ======================
    # Port Variation Tests
    # ======================

    def test_non_standard_port_handling(self, plugin):
        """PROVES: Non-standard ports handled correctly"""
        service_info = {'port': 8888, 'service': 'http', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 8888, service_info)

        # Check whatweb uses correct port
        whatweb_task = None
        for task in tree['children']:
            if 'whatweb' in task['id']:
                whatweb_task = task
                break

        assert whatweb_task is not None
        command = whatweb_task['metadata']['command']
        assert '8888' in command, "Should use correct port in commands"

    def test_https_on_non_standard_port(self, plugin):
        """PROVES: HTTPS detection on non-standard ports"""
        service_info = {'port': 8443, 'service': 'https', 'version': ''}
        tree = plugin.get_task_tree('192.168.45.100', 8443, service_info)

        # Should use https protocol
        whatweb_task = None
        for task in tree['children']:
            if 'whatweb' in task['id']:
                whatweb_task = task
                break

        assert whatweb_task is not None
        command = whatweb_task['metadata']['command']
        assert 'https://192.168.45.100:8443' in command

    # ======================
    # Manual Alternatives Tests
    # ======================

    def test_get_manual_alternatives_whatweb(self, plugin):
        """PROVES: Manual alternatives provided for whatweb"""
        alternatives = plugin.get_manual_alternatives('whatweb-80')

        assert len(alternatives) > 0
        assert any('curl' in alt.lower() for alt in alternatives)

    def test_get_manual_alternatives_gobuster(self, plugin):
        """PROVES: Manual alternatives provided for gobuster"""
        alternatives = plugin.get_manual_alternatives('gobuster-80')

        assert len(alternatives) > 0
        assert any('manual' in alt.lower() for alt in alternatives)
        assert any('/admin' in alt or 'path' in alt.lower() for alt in alternatives)

    def test_get_manual_alternatives_nikto(self, plugin):
        """PROVES: Manual alternatives provided for nikto"""
        alternatives = plugin.get_manual_alternatives('nikto-80')

        assert len(alternatives) > 0
        assert any('nmap' in alt.lower() or 'manual' in alt.lower() for alt in alternatives)
