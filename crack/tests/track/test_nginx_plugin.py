"""
Tests for Nginx service plugin

PROVES:
- Nginx servers detected correctly
- Comprehensive task tree generated
- All misconfigurations covered (alias, proxy_pass, CRLF, etc.)
- OSCP metadata complete (flags, alternatives, indicators)
"""

import pytest
from crack.track.services.nginx import NginxPlugin


class TestNginxPlugin:
    """Test suite for Nginx service plugin"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return NginxPlugin()

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "nginx"

    def test_default_ports(self, plugin):
        """PROVES: Plugin knows common Nginx ports"""
        assert 80 in plugin.default_ports
        assert 443 in plugin.default_ports
        assert 8080 in plugin.default_ports
        assert 8443 in plugin.default_ports

    def test_service_names(self, plugin):
        """PROVES: Plugin recognizes Nginx service identifiers"""
        assert 'nginx' in plugin.service_names
        assert 'http' in plugin.service_names
        assert 'https' in plugin.service_names

    def test_detect_by_product_name(self, plugin):
        """PROVES: Plugin detects Nginx by product name"""
        port_info = {
            'port': 80,
            'service': 'http',
            'product': 'nginx',
            'version': '1.18.0'
        }
        assert plugin.detect(port_info) == True

    def test_detect_by_product_nginx_explicit(self, plugin):
        """PROVES: Plugin detects explicit Nginx mentions"""
        port_info = {
            'port': 8080,
            'service': 'http-proxy',
            'product': 'nginx httpd',
            'version': '1.20.1'
        }
        assert plugin.detect(port_info) == True

    def test_detect_by_version_field(self, plugin):
        """PROVES: Plugin detects Nginx in version field"""
        port_info = {
            'port': 443,
            'service': 'https',
            'product': '',
            'version': 'nginx/1.18.0'
        }
        assert plugin.detect(port_info) == True

    def test_detect_generic_http_without_nginx_rejected(self, plugin):
        """PROVES: Plugin doesn't auto-trigger for generic HTTP (prevents false positives)"""
        port_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.4.41'
        }
        assert plugin.detect(port_info) == False

    def test_detect_http_without_product_rejected(self, plugin):
        """PROVES: Plugin requires explicit Nginx mention to avoid false positives"""
        port_info = {
            'port': 80,
            'service': 'http',
            'product': '',
            'version': ''
        }
        assert plugin.detect(port_info) == False

    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid structure"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'nginx',
            'version': '1.18.0'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Root structure
        assert tree['id'] == 'nginx-security-80'
        assert tree['name'] == 'Nginx Security Testing (Port 80)'
        assert tree['type'] == 'parent'
        assert 'children' in tree

        # Has tasks
        assert len(tree['children']) > 0

    def test_nginx_fingerprint_task(self, plugin):
        """PROVES: Version detection task included"""
        service_info = {'port': 80, 'service': 'http', 'product': 'nginx'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        fingerprint_task = next((t for t in tree['children'] if 'fingerprint' in t['id']), None)
        assert fingerprint_task is not None
        assert 'curl -I' in fingerprint_task['metadata']['command']
        assert 'OSCP:HIGH' in fingerprint_task['metadata']['tags']

    def test_config_disclosure_tasks(self, plugin):
        """PROVES: Missing root location tests included"""
        service_info = {'port': 443, 'service': 'https', 'product': 'nginx'}
        tree = plugin.get_task_tree('192.168.45.100', 443, service_info)

        config_task = next((t for t in tree['children'] if 'config-disclosure' in t['id']), None)
        assert config_task is not None
        assert config_task['type'] == 'parent'
        assert len(config_task['children']) >= 3  # nginx.conf, sites-enabled, access.log

        # Check nginx.conf retrieval task
        nginx_conf_task = next((t for t in config_task['children'] if 'nginx-conf-test' in t['id']), None)
        assert nginx_conf_task is not None
        assert 'nginx.conf' in nginx_conf_task['metadata']['command']
        assert 'success_indicators' in nginx_conf_task['metadata']
        assert 'failure_indicators' in nginx_conf_task['metadata']

    def test_alias_traversal_tasks(self, plugin):
        """PROVES: Alias off-by-slash vulnerability tests included"""
        service_info = {'port': 80, 'service': 'http', 'product': 'nginx'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        alias_task = next((t for t in tree['children'] if 'alias-traversal' in t['id']), None)
        assert alias_task is not None
        assert alias_task['type'] == 'parent'

        # Check manual test task
        manual_test = next((t for t in alias_task['children'] if 'alias-traversal-test' in t['id']), None)
        assert manual_test is not None
        assert 'OSCP:HIGH' in manual_test['metadata']['tags']
        assert '/imgs../' in manual_test['metadata']['notes']  # Example payload

        # Check automated fuzzing task
        auto_test = next((t for t in alias_task['children'] if 'automated-scan' in t['id']), None)
        assert auto_test is not None
        assert 'ffuf' in auto_test['metadata']['command']

    def test_proxy_pass_ssrf_tasks(self, plugin):
        """PROVES: proxy_pass SSRF and h2c smuggling tests included"""
        service_info = {'port': 443, 'service': 'https', 'product': 'nginx'}
        tree = plugin.get_task_tree('192.168.45.100', 443, service_info)

        proxy_task = next((t for t in tree['children'] if 'proxy-pass' in t['id']), None)
        assert proxy_task is not None

        # Check h2c smuggling test
        h2c_task = next((t for t in proxy_task['children'] if 'h2c-smuggling' in t['id']), None)
        assert h2c_task is not None
        assert 'OSCP:HIGH' in h2c_task['metadata']['tags']
        assert 'Upgrade' in h2c_task['metadata']['notes']
        assert 'h2csmuggler' in h2c_task['metadata']['notes']

    def test_crlf_injection_tasks(self, plugin):
        """PROVES: $uri CRLF injection tests included"""
        service_info = {'port': 80, 'service': 'http', 'product': 'nginx'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        uri_task = next((t for t in tree['children'] if 'uri-injection' in t['id']), None)
        assert uri_task is not None

        # Check CRLF injection test
        crlf_task = next((t for t in uri_task['children'] if 'crlf-injection-test' in t['id']), None)
        assert crlf_task is not None
        assert '%0d%0a' in crlf_task['metadata']['command']
        assert 'OSCP:HIGH' in crlf_task['metadata']['tags']
        assert 'flag_explanations' in crlf_task['metadata']

        # Verify flag explanations
        flags = crlf_task['metadata']['flag_explanations']
        assert '-i' in flags
        assert '%0d%0a' in flags

    def test_try_files_lfi_task(self, plugin):
        """PROVES: try_files $uri$args LFI test included"""
        service_info = {'port': 8080, 'service': 'http', 'product': 'nginx'}
        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        try_files_task = next((t for t in tree['children'] if 'try-files-lfi' in t['id']), None)
        assert try_files_task is not None
        assert '/etc/passwd' in try_files_task['metadata']['command']
        assert 'OSCP:HIGH' in try_files_task['metadata']['tags']
        assert 'success_indicators' in try_files_task['metadata']
        assert 'alternatives' in try_files_task['metadata']

    def test_merge_slashes_task(self, plugin):
        """PROVES: merge_slashes detection included"""
        service_info = {'port': 80, 'service': 'http', 'product': 'nginx'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        merge_task = next((t for t in tree['children'] if 'merge-slashes' in t['id']), None)
        assert merge_task is not None
        assert '//admin' in merge_task['metadata']['command']
        assert 'OSCP:MEDIUM' in merge_task['metadata']['tags']

    def test_x_accel_header_task(self, plugin):
        """PROVES: X-Accel-Redirect header injection test included"""
        service_info = {'port': 443, 'service': 'https', 'product': 'nginx'}
        tree = plugin.get_task_tree('192.168.45.100', 443, service_info)

        x_accel_task = next((t for t in tree['children'] if 'x-accel' in t['id']), None)
        assert x_accel_task is not None
        assert 'OSCP:HIGH' in x_accel_task['metadata']['tags']
        assert 'X-Accel-Redirect' in x_accel_task['metadata']['notes']

    def test_map_bypass_task(self, plugin):
        """PROVES: Map directive authorization bypass included"""
        service_info = {'port': 80, 'service': 'http', 'product': 'nginx'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        map_task = next((t for t in tree['children'] if 'map-bypass' in t['id']), None)
        assert map_task is not None
        assert 'OSCP:MEDIUM' in map_task['metadata']['tags']
        assert 'default' in map_task['metadata']['notes']

    def test_path_restriction_bypass_task(self, plugin):
        """PROVES: Path restriction bypass tests included"""
        service_info = {'port': 80, 'service': 'http', 'product': 'nginx'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        path_task = next((t for t in tree['children'] if 'path-restriction' in t['id']), None)
        assert path_task is not None
        assert 'location =' in path_task['metadata']['notes']

    def test_static_analysis_tools_tasks(self, plugin):
        """PROVES: Gixy and nginxpwner tasks included"""
        service_info = {'port': 80, 'service': 'http', 'product': 'nginx'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        static_task = next((t for t in tree['children'] if 'static-analysis' in t['id']), None)
        assert static_task is not None
        assert static_task['type'] == 'parent'

        # Check Gixy task
        gixy_task = next((t for t in static_task['children'] if 'gixy' in t['id']), None)
        assert gixy_task is not None
        assert 'gixy' in gixy_task['metadata']['notes'].lower()

        # Check nginxpwner task
        pwner_task = next((t for t in static_task['children'] if 'nginxpwner' in t['id']), None)
        assert pwner_task is not None
        assert 'nginxpwner' in pwner_task['metadata']['command']

    def test_exploit_research_conditional(self, plugin):
        """PROVES: Exploit research only added when version known"""
        # With version
        service_info_with_version = {
            'port': 80,
            'service': 'http',
            'product': 'nginx',
            'version': '1.18.0'
        }
        tree_with_version = plugin.get_task_tree('192.168.45.100', 80, service_info_with_version)
        exploit_task = next((t for t in tree_with_version['children'] if 'exploit-research' in t['id']), None)
        assert exploit_task is not None

        # Verify searchsploit and CVE lookup children
        assert len(exploit_task['children']) >= 2
        searchsploit_task = next((t for t in exploit_task['children'] if 'searchsploit' in t['id']), None)
        assert searchsploit_task is not None
        assert 'searchsploit nginx 1.18.0' in searchsploit_task['metadata']['command']

        # Without version
        service_info_no_version = {
            'port': 80,
            'service': 'http',
            'product': 'nginx',
            'version': ''
        }
        tree_no_version = plugin.get_task_tree('192.168.45.100', 80, service_info_no_version)
        exploit_task_2 = next((t for t in tree_no_version['children'] if 'exploit-research' in t['id']), None)
        assert exploit_task_2 is None  # Should not be present

    def test_https_protocol_detection(self, plugin):
        """PROVES: Plugin uses HTTPS for port 443"""
        service_info = {
            'port': 443,
            'service': 'https',
            'product': 'nginx'
        }
        tree = plugin.get_task_tree('192.168.45.100', 443, service_info)

        # Find any task with URL command
        fingerprint_task = next((t for t in tree['children'] if 'fingerprint' in t['id']), None)
        assert 'https://192.168.45.100:443' in fingerprint_task['metadata']['command']

    def test_http_protocol_detection(self, plugin):
        """PROVES: Plugin uses HTTP for port 80"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'nginx'
        }
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        fingerprint_task = next((t for t in tree['children'] if 'fingerprint' in t['id']), None)
        assert 'http://192.168.45.100:80' in fingerprint_task['metadata']['command']

    def test_oscp_metadata_completeness(self, plugin):
        """PROVES: All command tasks have OSCP-required metadata"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'nginx',
            'version': '1.18.0'
        }
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Recursively find all command tasks
        def find_command_tasks(node):
            tasks = []
            if node.get('type') == 'command':
                tasks.append(node)
            for child in node.get('children', []):
                tasks.extend(find_command_tasks(child))
            return tasks

        command_tasks = find_command_tasks(tree)
        assert len(command_tasks) > 0, "Should have command tasks"

        # Check each command task for required metadata
        for task in command_tasks:
            metadata = task.get('metadata', {})

            # Required fields
            assert 'command' in metadata, f"Task {task['id']} missing command"
            assert 'description' in metadata, f"Task {task['id']} missing description"

            # OSCP educational fields (at least some should be present)
            oscp_fields = ['flag_explanations', 'success_indicators', 'failure_indicators',
                          'next_steps', 'alternatives', 'tags', 'notes']
            present_fields = [f for f in oscp_fields if f in metadata and metadata[f]]
            assert len(present_fields) >= 3, f"Task {task['id']} should have at least 3 OSCP metadata fields"

    def test_flag_explanations_present(self, plugin):
        """PROVES: Commands with flags have explanations"""
        service_info = {'port': 80, 'service': 'http', 'product': 'nginx'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Check CRLF injection task (has multiple flags)
        def find_task_by_id(node, target_id):
            if target_id in node.get('id', ''):
                return node
            for child in node.get('children', []):
                result = find_task_by_id(child, target_id)
                if result:
                    return result
            return None

        crlf_task = find_task_by_id(tree, 'crlf-injection-test')
        if crlf_task:
            flags = crlf_task['metadata'].get('flag_explanations', {})
            assert len(flags) > 0, "CRLF task should explain flags"
            assert '-i' in flags
            assert '%0d%0a' in flags

    def test_success_failure_indicators(self, plugin):
        """PROVES: Tasks include success and failure indicators"""
        service_info = {'port': 80, 'service': 'http', 'product': 'nginx'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Check fingerprint task
        fingerprint_task = next((t for t in tree['children'] if 'fingerprint' in t['id']), None)
        assert fingerprint_task is not None

        metadata = fingerprint_task['metadata']
        assert 'success_indicators' in metadata
        assert 'failure_indicators' in metadata
        assert len(metadata['success_indicators']) >= 2
        assert len(metadata['failure_indicators']) >= 2

    def test_alternatives_provided(self, plugin):
        """PROVES: Manual alternatives provided for automated tasks"""
        service_info = {'port': 80, 'service': 'http', 'product': 'nginx'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Check fingerprint task
        fingerprint_task = next((t for t in tree['children'] if 'fingerprint' in t['id']), None)
        metadata = fingerprint_task['metadata']

        assert 'alternatives' in metadata
        assert len(metadata['alternatives']) >= 2
        # Should include manual methods
        alternatives_text = ' '.join(metadata['alternatives'])
        assert 'nmap' in alternatives_text.lower() or 'browser' in alternatives_text.lower()

    def test_next_steps_guidance(self, plugin):
        """PROVES: Tasks include next_steps for attack chain progression"""
        service_info = {'port': 80, 'service': 'http', 'product': 'nginx'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Check fingerprint task
        fingerprint_task = next((t for t in tree['children'] if 'fingerprint' in t['id']), None)
        metadata = fingerprint_task['metadata']

        assert 'next_steps' in metadata
        assert len(metadata['next_steps']) >= 2

    def test_manual_alternatives_method(self, plugin):
        """PROVES: get_manual_alternatives() returns alternatives"""
        alternatives = plugin.get_manual_alternatives('nginx-fingerprint-80')
        assert len(alternatives) > 0
        assert any('curl' in alt.lower() for alt in alternatives)

        # Test different task types
        config_alts = plugin.get_manual_alternatives('nginx-config-disclosure-80')
        assert len(config_alts) > 0

        alias_alts = plugin.get_manual_alternatives('nginx-alias-traversal-80')
        assert len(alias_alts) > 0

    def test_comprehensive_coverage(self, plugin):
        """PROVES: All major Nginx misconfigurations covered"""
        service_info = {'port': 80, 'service': 'http', 'product': 'nginx', 'version': '1.18.0'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # List of all task IDs
        def get_all_task_ids(node):
            ids = [node['id']]
            for child in node.get('children', []):
                ids.extend(get_all_task_ids(child))
            return ids

        task_ids = get_all_task_ids(tree)

        # Verify coverage of major misconfigurations
        required_coverage = [
            'fingerprint',          # Version detection
            'config-disclosure',    # Missing root location
            'alias-traversal',      # Alias off-by-slash
            'proxy-pass',           # proxy_pass SSRF/h2c
            'uri-injection',        # $uri CRLF injection
            'try-files-lfi',        # try_files LFI
            'merge-slashes',        # merge_slashes bypass
            'x-accel',              # X-Accel-* headers
            'map-bypass',           # Map directive
            'path-restriction',     # Path restriction bypass
            'static-analysis',      # Tools (Gixy, nginxpwner)
            'exploit-research'      # CVE lookup
        ]

        for required in required_coverage:
            assert any(required in task_id for task_id in task_ids), \
                f"Missing coverage for: {required}"

    def test_task_count_reasonable(self, plugin):
        """PROVES: Plugin generates comprehensive but not overwhelming task count"""
        service_info = {'port': 80, 'service': 'http', 'product': 'nginx', 'version': '1.18.0'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        def count_all_tasks(node):
            count = 1
            for child in node.get('children', []):
                count += count_all_tasks(child)
            return count

        total_tasks = count_all_tasks(tree)
        # Should have 20-50 tasks (comprehensive but manageable)
        assert 20 <= total_tasks <= 50, f"Task count {total_tasks} outside expected range"

    def test_tags_consistent(self, plugin):
        """PROVES: Tags follow OSCP standards"""
        service_info = {'port': 80, 'service': 'http', 'product': 'nginx'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        def get_all_tags(node):
            tags = node.get('metadata', {}).get('tags', [])
            for child in node.get('children', []):
                tags.extend(get_all_tags(child))
            return tags

        all_tags = get_all_tags(tree)

        # Check for standard OSCP tags
        oscp_tags = [t for t in all_tags if 'OSCP:' in t]
        assert len(oscp_tags) > 0, "Should have OSCP priority tags"

        # Verify valid tag formats
        valid_prefixes = ['OSCP:', 'QUICK_WIN', 'MANUAL', 'AUTOMATED', 'ADVANCED',
                         'RESEARCH', 'ENUM', 'EXPLOIT', 'EDUCATIONAL']
        for tag in all_tags:
            assert any(tag.startswith(prefix) for prefix in valid_prefixes), \
                f"Invalid tag format: {tag}"

    def test_educational_notes_present(self, plugin):
        """PROVES: Complex tasks include educational notes"""
        service_info = {'port': 80, 'service': 'http', 'product': 'nginx'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find h2c smuggling task (complex vulnerability)
        def find_task_by_id(node, target_id):
            if target_id in node.get('id', ''):
                return node
            for child in node.get('children', []):
                result = find_task_by_id(child, target_id)
                if result:
                    return result
            return None

        h2c_task = find_task_by_id(tree, 'h2c-smuggling-test')
        if h2c_task:
            assert 'notes' in h2c_task['metadata']
            notes = h2c_task['metadata']['notes']
            # Should explain vulnerability
            assert 'Vulnerable' in notes or 'vulnerable' in notes
            # Should explain exploitation
            assert 'Attack' in notes or 'Exploit' in notes
            # Should be substantial
            assert len(notes) > 200, "Educational notes should be detailed"
