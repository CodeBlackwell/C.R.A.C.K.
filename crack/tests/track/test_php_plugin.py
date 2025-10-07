"""
Test suite for PHP exploitation plugin

PROVES: PHP plugin generates comprehensive OSCP-relevant tasks
"""

import pytest
from crack.track.services.php import PHPPlugin


class TestPHPPlugin:
    """Test PHP exploitation plugin"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return PHPPlugin()

    def test_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "php"

    def test_default_ports(self, plugin):
        """PROVES: Plugin has web service ports"""
        assert 80 in plugin.default_ports
        assert 443 in plugin.default_ports
        assert 8080 in plugin.default_ports

    def test_service_names(self, plugin):
        """PROVES: Plugin detects HTTP services"""
        assert 'http' in plugin.service_names
        assert 'https' in plugin.service_names

    # Detection Tests
    def test_detect_php_in_service(self, plugin):
        """PROVES: Plugin detects PHP in service banner"""
        port_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.4.41',
            'extrainfo': 'PHP/7.4.3'
        }
        assert plugin.detect(port_info) == True

    def test_detect_http_service(self, plugin):
        """PROVES: Plugin detects generic HTTP (potential PHP)"""
        port_info = {
            'port': 80,
            'service': 'http'
        }
        assert plugin.detect(port_info) == True

    def test_detect_https_service(self, plugin):
        """PROVES: Plugin detects HTTPS services"""
        port_info = {
            'port': 443,
            'service': 'https'
        }
        assert plugin.detect(port_info) == True

    def test_detect_apache_server(self, plugin):
        """PROVES: Plugin detects Apache (common PHP host)"""
        port_info = {
            'port': 8080,
            'service': 'http',
            'product': 'Apache httpd'
        }
        assert plugin.detect(port_info) == True

    def test_detect_nginx_server(self, plugin):
        """PROVES: Plugin detects Nginx (common PHP host)"""
        port_info = {
            'port': 8000,
            'service': 'http',
            'product': 'nginx'
        }
        assert plugin.detect(port_info) == True

    def test_detect_negative_ssh(self, plugin):
        """PROVES: Plugin rejects SSH service"""
        port_info = {
            'port': 22,
            'service': 'ssh'
        }
        assert plugin.detect(port_info) == False

    def test_detect_negative_smtp(self, plugin):
        """PROVES: Plugin rejects SMTP service"""
        port_info = {
            'port': 25,
            'service': 'smtp'
        }
        assert plugin.detect(port_info) == False

    # Task Tree Structure Tests
    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid structure"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.4.41'
        }
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Root structure
        assert tree['id'] == 'php-exploit-80'
        assert tree['type'] == 'parent'
        assert 'children' in tree
        assert len(tree['children']) > 0

    def test_php_detection_tasks(self, plugin):
        """PROVES: Plugin generates PHP detection tasks"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find PHP detection parent task
        php_detect = None
        for child in tree['children']:
            if child['id'] == 'php-detect-80':
                php_detect = child
                break

        assert php_detect is not None
        assert php_detect['type'] == 'parent'
        assert len(php_detect['children']) >= 2

        # Check for header check task
        task_ids = [t['id'] for t in php_detect['children']]
        assert 'php-headers-80' in task_ids
        assert 'phpinfo-search-80' in task_ids

    def test_file_inclusion_tasks(self, plugin):
        """PROVES: Plugin generates LFI/RFI tasks"""
        service_info = {'port': 443, 'service': 'https'}
        tree = plugin.get_task_tree('192.168.45.100', 443, service_info)

        # Find file inclusion parent task
        file_inclusion = None
        for child in tree['children']:
            if child['id'] == 'file-inclusion-443':
                file_inclusion = child
                break

        assert file_inclusion is not None
        assert file_inclusion['type'] == 'parent'
        assert len(file_inclusion['children']) >= 5

        # Check for specific LFI techniques
        task_ids = [t['id'] for t in file_inclusion['children']]
        assert 'lfi-common-params-443' in task_ids
        assert 'php-wrapper-filter-443' in task_ids
        assert 'php-wrapper-input-443' in task_ids
        assert 'rfi-test-443' in task_ids
        assert 'lfi-log-poison-443' in task_ids

    def test_rce_techniques_tasks(self, plugin):
        """PROVES: Plugin generates RCE technique tasks"""
        service_info = {'port': 8080, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Find RCE parent task
        rce_tasks = None
        for child in tree['children']:
            if child['id'] == 'php-rce-8080':
                rce_tasks = child
                break

        assert rce_tasks is not None
        assert rce_tasks['type'] == 'parent'
        assert len(rce_tasks['children']) >= 2

        # Check for RCE techniques
        task_ids = [t['id'] for t in rce_tasks['children']]
        assert 'php-eval-injection-8080' in task_ids
        assert 'php-deserialization-8080' in task_ids

    def test_bypass_techniques_tasks(self, plugin):
        """PROVES: Plugin generates bypass technique tasks"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find bypass parent task
        bypass_tasks = None
        for child in tree['children']:
            if child['id'] == 'php-bypass-80':
                bypass_tasks = child
                break

        assert bypass_tasks is not None
        assert bypass_tasks['type'] == 'parent'

        # Check for bypass techniques
        task_ids = [t['id'] for t in bypass_tasks['children']]
        assert 'php-type-juggling-80' in task_ids
        assert 'php-disable-functions-80' in task_ids
        assert 'php-session-manipulation-80' in task_ids

    def test_ssrf_task(self, plugin):
        """PROVES: Plugin generates SSRF testing task"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find SSRF task
        ssrf_task = None
        for child in tree['children']:
            if child['id'] == 'php-ssrf-80':
                ssrf_task = child
                break

        assert ssrf_task is not None
        assert ssrf_task['type'] == 'manual'

    # OSCP Metadata Tests
    def test_oscp_metadata_headers_check(self, plugin):
        """PROVES: Header check task has OSCP metadata"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Navigate to headers task
        php_detect = [c for c in tree['children'] if c['id'] == 'php-detect-80'][0]
        headers_task = [c for c in php_detect['children'] if c['id'] == 'php-headers-80'][0]

        metadata = headers_task['metadata']

        # Required OSCP fields
        assert 'command' in metadata
        assert 'description' in metadata
        assert 'flag_explanations' in metadata
        assert 'success_indicators' in metadata
        assert 'failure_indicators' in metadata
        assert 'next_steps' in metadata
        assert 'alternatives' in metadata
        assert 'tags' in metadata

        # Verify flag explanations
        assert '-I' in metadata['flag_explanations']

        # Verify tags
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'QUICK_WIN' in metadata['tags']

        # Verify alternatives provided
        assert len(metadata['alternatives']) >= 2

    def test_oscp_metadata_lfi_task(self, plugin):
        """PROVES: LFI task has comprehensive OSCP guidance"""
        service_info = {'port': 443, 'service': 'https'}
        tree = plugin.get_task_tree('192.168.45.100', 443, service_info)

        # Navigate to LFI task
        file_inclusion = [c for c in tree['children'] if c['id'] == 'file-inclusion-443'][0]
        lfi_task = [c for c in file_inclusion['children'] if c['id'] == 'lfi-common-params-443'][0]

        metadata = lfi_task['metadata']

        # Check comprehensive notes
        assert 'notes' in metadata
        assert 'etc/passwd' in metadata['notes'].lower()
        assert 'common lfi' in metadata['notes'].lower()

        # Check success/failure indicators
        assert len(metadata['success_indicators']) >= 2
        assert len(metadata['failure_indicators']) >= 2

        # Check next steps
        assert len(metadata['next_steps']) >= 3

        # Check alternatives
        assert len(metadata['alternatives']) >= 2

    def test_oscp_metadata_wrapper_task(self, plugin):
        """PROVES: PHP wrapper task has detailed explanations"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Navigate to wrapper task
        file_inclusion = [c for c in tree['children'] if c['id'] == 'file-inclusion-80'][0]
        wrapper_task = [c for c in file_inclusion['children'] if c['id'] == 'php-wrapper-filter-80'][0]

        metadata = wrapper_task['metadata']

        # Check educational content
        assert 'notes' in metadata
        assert 'php://filter' in metadata['notes'].lower()
        assert 'base64' in metadata['notes'].lower()

        # Check manual alternatives
        assert 'alternatives' in metadata
        assert len(metadata['alternatives']) >= 2

    def test_version_exploit_research(self, plugin):
        """PROVES: Plugin generates exploit research for known versions"""
        service_info = {
            'port': 80,
            'service': 'http',
            'version': '7.2.34',
            'product': 'Apache httpd'
        }
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find version exploit research
        exploit_research = None
        for child in tree['children']:
            if 'php-version-exploits' in child['id']:
                exploit_research = child
                break

        assert exploit_research is not None
        assert exploit_research['type'] == 'parent'

        # Check for searchsploit task
        task_ids = [t['id'] for t in exploit_research['children']]
        assert 'searchsploit-php-80' in task_ids

    def test_https_detection(self, plugin):
        """PROVES: Plugin correctly detects HTTPS and uses https:// in commands"""
        service_info = {'port': 443, 'service': 'https'}
        tree = plugin.get_task_tree('192.168.45.100', 443, service_info)

        # Check that commands use https://
        php_detect = [c for c in tree['children'] if c['id'] == 'php-detect-443'][0]
        headers_task = [c for c in php_detect['children'] if c['id'] == 'php-headers-443'][0]

        command = headers_task['metadata']['command']
        assert 'https://' in command
        assert 'http://' not in command or 'https://' in command

    def test_http_detection(self, plugin):
        """PROVES: Plugin uses http:// for non-HTTPS ports"""
        service_info = {'port': 8080, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        # Check that commands use http://
        php_detect = [c for c in tree['children'] if c['id'] == 'php-detect-8080'][0]
        headers_task = [c for c in php_detect['children'] if c['id'] == 'php-headers-8080'][0]

        command = headers_task['metadata']['command']
        assert 'http://' in command

    def test_tags_consistency(self, plugin):
        """PROVES: All tasks have appropriate OSCP tags"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Collect all command/manual tasks
        def collect_tasks(node, tasks_list):
            if node.get('type') in ['command', 'manual']:
                if 'metadata' in node and 'tags' in node['metadata']:
                    tasks_list.append(node)
            if 'children' in node:
                for child in node['children']:
                    collect_tasks(child, tasks_list)

        all_tasks = []
        collect_tasks(tree, all_tasks)

        # Verify all tasks have tags
        for task in all_tasks:
            tags = task['metadata']['tags']
            assert len(tags) > 0, f"Task {task['id']} has no tags"

            # Verify valid tag format
            valid_prefixes = ['OSCP:', 'QUICK_WIN', 'MANUAL', 'AUTOMATED', 'RESEARCH']
            has_valid_tag = any(any(tag.startswith(prefix) for prefix in valid_prefixes) for tag in tags)
            assert has_valid_tag, f"Task {task['id']} has invalid tags: {tags}"

    def test_comprehensive_coverage(self, plugin):
        """PROVES: Plugin covers all major PHP exploitation areas"""
        service_info = {'port': 80, 'service': 'http', 'version': '7.4.3'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Expected major categories
        expected_categories = [
            'php-detect',      # Detection
            'file-inclusion',  # LFI/RFI
            'php-rce',         # RCE techniques
            'php-bypass',      # Bypass techniques
            'php-ssrf',        # SSRF
            'php-env-exploit', # Environment exploitation
            'php-version-exploits'  # Version-specific exploits
        ]

        task_ids = [child['id'] for child in tree['children']]

        for category in expected_categories:
            matching_tasks = [tid for tid in task_ids if category in tid]
            assert len(matching_tasks) > 0, f"Missing category: {category}"

    def test_educational_value(self, plugin):
        """PROVES: Tasks provide educational content for OSCP learning"""
        service_info = {'port': 80, 'service': 'http'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Check type juggling task for educational content
        bypass_tasks = [c for c in tree['children'] if c['id'] == 'php-bypass-80'][0]
        type_juggling = [c for c in bypass_tasks['children'] if c['id'] == 'php-type-juggling-80'][0]

        metadata = type_juggling['metadata']

        # Educational components
        assert 'notes' in metadata
        notes = metadata['notes']

        # Should explain the vulnerability
        assert 'comparison' in notes.lower() or '==' in notes
        assert 'type juggling' in notes.lower() or 'type coercion' in notes.lower()

        # Should provide examples
        assert 'example' in notes.lower() or 'exploit:' in notes.lower() or 'payload' in notes.lower()

        # Should explain why it works
        assert 'why' in notes.lower() or 'because' in notes.lower()

    def test_no_empty_metadata(self, plugin):
        """PROVES: No tasks have empty metadata fields"""
        service_info = {'port': 80, 'service': 'http', 'version': '7.4.3'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        def check_metadata(node):
            if 'metadata' in node:
                metadata = node['metadata']
                for key, value in metadata.items():
                    if isinstance(value, str):
                        assert value.strip() != '', f"Empty metadata field '{key}' in task {node['id']}"
                    elif isinstance(value, (list, dict)):
                        assert len(value) > 0, f"Empty metadata field '{key}' in task {node['id']}"

            if 'children' in node:
                for child in node['children']:
                    check_metadata(child)

        check_metadata(tree)

    def test_unique_task_ids(self, plugin):
        """PROVES: All task IDs are unique"""
        service_info = {'port': 80, 'service': 'http', 'version': '7.4.3'}
        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        def collect_ids(node, id_list):
            id_list.append(node['id'])
            if 'children' in node:
                for child in node['children']:
                    collect_ids(child, id_list)

        all_ids = []
        collect_ids(tree, all_ids)

        # Check uniqueness
        assert len(all_ids) == len(set(all_ids)), "Duplicate task IDs found"

    def test_target_port_placeholders(self, plugin):
        """PROVES: Commands use {target} and {port} placeholders correctly"""
        service_info = {'port': 8443, 'service': 'https'}
        target = '10.10.10.100'
        port = 8443

        tree = plugin.get_task_tree(target, port, service_info)

        # Commands should contain the actual target/port, not placeholders
        php_detect = [c for c in tree['children'] if 'php-detect' in c['id']][0]
        headers_task = [c for c in php_detect['children'] if 'php-headers' in c['id']][0]

        command = headers_task['metadata']['command']
        assert target in command
        assert str(port) in command
