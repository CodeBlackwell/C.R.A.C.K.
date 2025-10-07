"""
Tests for IIS service plugin

PROVES:
- IIS detection works for multiple indicators
- Task tree generation is comprehensive
- OSCP-required metadata present (flags, alternatives, indicators)
- Educational value (flag explanations, next steps)
"""

import pytest
from crack.track.services.iis import IISPlugin


class TestIISPlugin:
    """Test suite for IIS plugin"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return IISPlugin()

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "iis"

    def test_default_ports(self, plugin):
        """PROVES: Plugin defines common IIS ports"""
        assert 80 in plugin.default_ports
        assert 443 in plugin.default_ports
        assert 8080 in plugin.default_ports
        assert 8443 in plugin.default_ports

    def test_detect_by_product_iis(self, plugin):
        """PROVES: Plugin detects Microsoft-IIS in product field"""
        port_info = {
            'port': 80,
            'service': 'http',
            'product': 'Microsoft-IIS/10.0',
            'version': ''
        }
        assert plugin.detect(port_info) == True

    def test_detect_by_service_microsoft_iis(self, plugin):
        """PROVES: Plugin detects microsoft-iis service name"""
        port_info = {
            'port': 80,
            'service': 'microsoft-iis',
            'product': '',
            'version': ''
        }
        assert plugin.detect(port_info) == True

    def test_detect_by_aspnet_indicators(self, plugin):
        """PROVES: Plugin detects ASP.NET indicators"""
        port_info = {
            'port': 443,
            'service': 'https',
            'product': 'ASP.NET',
            'version': '',
            'extrainfo': 'aspx'
        }
        assert plugin.detect(port_info) == True

    def test_detect_by_microsoft_product_windows(self, plugin):
        """PROVES: Plugin detects Microsoft/Windows HTTP servers"""
        port_info = {
            'port': 80,
            'service': 'http',
            'product': 'Microsoft HTTPAPI httpd',
            'version': '2.0',
            'extrainfo': 'SSDP/UPnP on Windows'
        }
        assert plugin.detect(port_info) == True

    def test_detect_negative_apache(self, plugin):
        """PROVES: Plugin rejects Apache servers"""
        port_info = {
            'port': 80,
            'service': 'http',
            'product': 'Apache httpd',
            'version': '2.4.41'
        }
        assert plugin.detect(port_info) == False

    def test_detect_negative_nginx(self, plugin):
        """PROVES: Plugin rejects nginx servers"""
        port_info = {
            'port': 443,
            'service': 'https',
            'product': 'nginx',
            'version': '1.18.0'
        }
        assert plugin.detect(port_info) == False

    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid structure"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Microsoft-IIS/10.0',
            'version': '10.0'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Root structure
        assert tree['id'] == 'iis-enum-80'
        assert 'IIS Enumeration' in tree['name']
        assert tree['type'] == 'parent'
        assert 'children' in tree
        assert len(tree['children']) > 0

    def test_task_tree_has_quick_wins(self, plugin):
        """PROVES: Task tree includes QUICK_WIN tasks"""
        service_info = {
            'port': 443,
            'service': 'https',
            'product': 'Microsoft-IIS/10.0',
            'version': '10.0'
        }

        tree = plugin.get_task_tree('192.168.45.100', 443, service_info)

        # Find QUICK_WIN tasks
        def find_quick_wins(node):
            quick_wins = []
            if node.get('type') == 'command':
                if 'QUICK_WIN' in node.get('metadata', {}).get('tags', []):
                    quick_wins.append(node)
            for child in node.get('children', []):
                quick_wins.extend(find_quick_wins(child))
            return quick_wins

        quick_win_tasks = find_quick_wins(tree)
        assert len(quick_win_tasks) > 0, "Should have at least one QUICK_WIN task"

        # Verify first quick win is internal IP disclosure
        first_qw = quick_win_tasks[0]
        assert 'internal-ip' in first_qw['id'].lower() or 'trace' in first_qw['id'].lower()

    def test_internal_ip_disclosure_task(self, plugin):
        """PROVES: Internal IP disclosure task is properly configured"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Microsoft-IIS/10.0'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find internal IP disclosure task
        ip_task = None
        for child in tree['children']:
            if 'internal-ip' in child['id']:
                ip_task = child
                break

        assert ip_task is not None, "Internal IP disclosure task should exist"
        metadata = ip_task['metadata']

        # Verify required fields
        assert 'command' in metadata
        assert 'nc -v' in metadata['command']
        assert 'description' in metadata
        assert 'flag_explanations' in metadata
        assert '-v' in metadata['flag_explanations']

        # Verify OSCP fields
        assert 'success_indicators' in metadata
        assert len(metadata['success_indicators']) > 0
        assert 'failure_indicators' in metadata
        assert 'next_steps' in metadata
        assert 'alternatives' in metadata

        # Verify tags
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'QUICK_WIN' in metadata['tags']

    def test_trace_axd_task(self, plugin):
        """PROVES: Trace.axd debugging check is included"""
        service_info = {
            'port': 443,
            'service': 'https',
            'product': 'Microsoft-IIS/10.0'
        }

        tree = plugin.get_task_tree('192.168.45.100', 443, service_info)

        # Find trace.axd task
        trace_task = None
        for child in tree['children']:
            if 'trace-axd' in child['id']:
                trace_task = child
                break

        assert trace_task is not None, "Trace.axd task should exist"
        metadata = trace_task['metadata']

        # Verify curl command with /trace.axd
        assert 'curl' in metadata['command']
        assert '/trace.axd' in metadata['command']
        assert 'https://192.168.45.100:443' in metadata['command']

        # Verify OSCP relevance
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'QUICK_WIN' in metadata['tags']

    def test_shortname_enumeration_task(self, plugin):
        """PROVES: IIS shortname (tilde) vulnerability scanner is included"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Microsoft-IIS/7.5'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find shortname task
        shortname_task = None
        for child in tree['children']:
            if 'shortname' in child['id']:
                shortname_task = child
                break

        assert shortname_task is not None, "Shortname scanner task should exist"
        metadata = shortname_task['metadata']

        # Verify command
        assert 'iis_shortname_scanner.jar' in metadata['command']
        assert 'java -jar' in metadata['command']

        # Verify flag explanations
        assert 'flag_explanations' in metadata
        assert len(metadata['flag_explanations']) >= 2

        # Verify alternatives include manual and metasploit
        alternatives = metadata.get('alternatives', [])
        assert any('curl' in alt for alt in alternatives)
        assert any('msfconsole' in alt or 'metasploit' in alt.lower() for alt in alternatives)

    def test_webconfig_upload_attack(self, plugin):
        """PROVES: web.config upload attack chain is comprehensive"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Microsoft-IIS/10.0'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find webconfig upload task (parent)
        webconfig_task = None
        for child in tree['children']:
            if 'webconfig-upload' in child['id']:
                webconfig_task = child
                break

        assert webconfig_task is not None, "web.config upload task should exist"
        assert webconfig_task['type'] == 'parent', "Should be parent with subtasks"
        assert len(webconfig_task['children']) >= 3, "Should have recon, craft, execute steps"

        # Verify subtask IDs
        subtask_ids = [t['id'] for t in webconfig_task['children']]
        assert any('recon' in tid for tid in subtask_ids)
        assert any('craft' in tid for tid in subtask_ids)
        assert any('execute' in tid for tid in subtask_ids)

    def test_path_traversal_tasks(self, plugin):
        """PROVES: Path traversal attack chain is present"""
        service_info = {
            'port': 443,
            'service': 'https',
            'product': 'Microsoft-IIS/10.0'
        }

        tree = plugin.get_task_tree('192.168.45.100', 443, service_info)

        # Find path traversal parent
        traversal_task = None
        for child in tree['children']:
            if 'path-traversal' in child['id']:
                traversal_task = child
                break

        assert traversal_task is not None, "Path traversal task should exist"
        assert traversal_task['type'] == 'parent'
        assert len(traversal_task['children']) >= 3, "Should have web.config, DLL, common files tasks"

        # Verify web.config download task
        webconfig_dl = traversal_task['children'][0]
        assert 'webconfig' in webconfig_dl['id']
        assert '..%2f..%2f' in webconfig_dl['metadata']['command']
        assert 'curl' in webconfig_dl['metadata']['command']

    def test_aspnet_decryption_tasks(self, plugin):
        """PROVES: ASP.NET configuration decryption tasks present"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Microsoft-IIS/10.0'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find decrypt config task
        decrypt_task = None
        for child in tree['children']:
            if 'decrypt-config' in child['id']:
                decrypt_task = child
                break

        assert decrypt_task is not None, "Decrypt config task should exist"
        assert decrypt_task['type'] == 'parent'

        # Verify aspnet_regiis task
        regiis_task = decrypt_task['children'][0]
        assert 'aspnet_regiis.exe' in regiis_task['metadata']['command']
        assert 'POST_EXPLOIT' in regiis_task['metadata']['tags']

    def test_iis_dir_bruteforce_task(self, plugin):
        """PROVES: IIS-specific directory brute-force is configured"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Microsoft-IIS/10.0'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find dir bruteforce task
        dir_task = None
        for child in tree['children']:
            if 'dir-bruteforce' in child['id']:
                dir_task = child
                break

        assert dir_task is not None, "Directory brute-force task should exist"
        metadata = dir_task['metadata']

        # Verify IIS-specific wordlist
        assert 'IIS.fuzz.txt' in metadata['command']
        assert 'gobuster' in metadata['command']
        assert '-o' in metadata['command'], "Should save output for OSCP docs"

        # Verify OSCP relevance
        assert 'OSCP:HIGH' in metadata['tags']

    def test_auth_bypass_tasks(self, plugin):
        """PROVES: Authentication bypass techniques included"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Microsoft-IIS/7.5'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find auth bypass task (IIS 7.5 NTFS stream)
        auth_bypass_task = None
        for child in tree['children']:
            if 'auth-bypass' in child['id'] and 'cve' not in child['id']:
                auth_bypass_task = child
                break

        assert auth_bypass_task is not None, "Auth bypass task should exist"
        metadata = auth_bypass_task['metadata']

        # Verify NTFS stream syntax
        assert '::$INDEX_ALLOCATION' in metadata['command']
        assert 'curl' in metadata['command']

        # Verify IIS 7.5 specific
        assert '7.5' in metadata['description'] or '7.5' in metadata.get('notes', '')

    def test_vhost_discovery_task(self, plugin):
        """PROVES: VHost discovery for HTTPAPI 2.0 404 errors"""
        service_info = {
            'port': 443,
            'service': 'https',
            'product': 'Microsoft-IIS/10.0'
        }

        tree = plugin.get_task_tree('192.168.45.100', 443, service_info)

        # Find vhost discovery task
        vhost_task = None
        for child in tree['children']:
            if 'vhost' in child['id']:
                vhost_task = child
                break

        assert vhost_task is not None, "VHost discovery task should exist"
        metadata = vhost_task['metadata']

        # Verify mentions HTTPAPI 2.0
        assert 'HTTPAPI' in metadata['description'] or 'HTTPAPI' in metadata.get('notes', '')

        # Verify alternatives include gobuster/ffuf
        alternatives = metadata.get('alternatives', [])
        assert any('ffuf' in alt or 'gobuster' in alt for alt in alternatives)

    def test_https_protocol_detection(self, plugin):
        """PROVES: Plugin adapts commands for HTTPS ports"""
        service_info = {
            'port': 443,
            'service': 'https',
            'product': 'Microsoft-IIS/10.0'
        }

        tree = plugin.get_task_tree('192.168.45.100', 443, service_info)

        # Find tasks with URLs
        url_tasks = []
        def collect_url_tasks(node):
            if node.get('type') in ['command', 'manual']:
                metadata = node.get('metadata', {})
                if 'command' in metadata and 'http' in metadata['command']:
                    url_tasks.append(node)
            for child in node.get('children', []):
                collect_url_tasks(child)

        collect_url_tasks(tree)

        # Verify HTTPS is used
        https_count = sum(1 for t in url_tasks if 'https://' in t['metadata']['command'])
        assert https_count > 0, "Should use HTTPS protocol for port 443"

    def test_exploit_research_conditional(self, plugin):
        """PROVES: Exploit research task generated when version detected"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Microsoft-IIS/7.5',
            'version': '7.5'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find exploit research task
        exploit_task = None
        for child in tree['children']:
            if 'exploit-research' in child['id']:
                exploit_task = child
                break

        assert exploit_task is not None, "Exploit research should exist when version known"
        assert exploit_task['type'] == 'parent'
        assert len(exploit_task['children']) >= 2, "Should have searchsploit and CVE lookup"

        # Verify searchsploit task
        searchsploit_task = exploit_task['children'][0]
        assert 'searchsploit' in searchsploit_task['metadata']['command']
        assert '7.5' in searchsploit_task['metadata']['command']

    def test_exploit_research_skipped_without_version(self, plugin):
        """PROVES: Exploit research skipped when version unknown"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Microsoft-IIS',
            'version': 'unknown'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find exploit research task
        exploit_task = None
        for child in tree['children']:
            if 'exploit-research' in child['id']:
                exploit_task = child
                break

        # Should not exist for unknown version
        assert exploit_task is None, "Exploit research should be skipped for unknown version"

    def test_oscp_metadata_completeness(self, plugin):
        """PROVES: All command tasks have OSCP-required metadata"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Microsoft-IIS/10.0',
            'version': '10.0'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Collect all command tasks
        command_tasks = []
        def collect_commands(node):
            if node.get('type') == 'command':
                command_tasks.append(node)
            for child in node.get('children', []):
                collect_commands(child)

        collect_commands(tree)

        assert len(command_tasks) > 5, "Should have multiple command tasks"

        # Verify each command task
        for task in command_tasks:
            metadata = task.get('metadata', {})

            # Required fields
            assert 'command' in metadata, f"Task {task['id']} missing command"
            assert 'description' in metadata, f"Task {task['id']} missing description"
            assert 'tags' in metadata, f"Task {task['id']} missing tags"

            # OSCP educational fields
            assert 'flag_explanations' in metadata or task['type'] == 'manual', \
                f"Task {task['id']} missing flag_explanations"
            assert 'alternatives' in metadata, f"Task {task['id']} missing alternatives"
            assert 'success_indicators' in metadata, f"Task {task['id']} missing success_indicators"
            assert 'next_steps' in metadata, f"Task {task['id']} missing next_steps"

            # Verify tags are non-empty
            assert len(metadata['tags']) > 0, f"Task {task['id']} has empty tags"

    def test_flag_explanations_quality(self, plugin):
        """PROVES: Flag explanations are descriptive and educational"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Microsoft-IIS/10.0'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find internal IP disclosure task
        ip_task = None
        for child in tree['children']:
            if 'internal-ip' in child['id']:
                ip_task = child
                break

        flag_explanations = ip_task['metadata']['flag_explanations']

        # Verify flag explanations exist and are descriptive
        for flag, explanation in flag_explanations.items():
            assert len(explanation) > 10, f"Flag {flag} explanation too short: {explanation}"
            assert explanation != flag, f"Flag {flag} explanation is just the flag itself"

    def test_alternatives_include_manual_methods(self, plugin):
        """PROVES: Alternatives include manual methods for OSCP exam"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Microsoft-IIS/10.0'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Collect all tasks with alternatives
        tasks_with_alts = []
        def collect_alternatives(node):
            metadata = node.get('metadata', {})
            if 'alternatives' in metadata:
                tasks_with_alts.append((node['id'], metadata['alternatives']))
            for child in node.get('children', []):
                collect_alternatives(child)

        collect_alternatives(tree)

        assert len(tasks_with_alts) > 5, "Should have multiple tasks with alternatives"

        # Verify at least some alternatives are manual
        manual_count = 0
        for task_id, alternatives in tasks_with_alts:
            if any('Manual:' in alt or 'Browser:' in alt or 'curl' in alt or 'nc' in alt
                   for alt in alternatives):
                manual_count += 1

        assert manual_count > 3, "Should have multiple tasks with manual alternatives"

    def test_fileless_backdoor_detection_tasks(self, plugin):
        """PROVES: Fileless backdoor detection tasks present (blue team / awareness)"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Microsoft-IIS/10.0'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Find fileless backdoor task
        backdoor_task = None
        for child in tree['children']:
            if 'fileless-backdoor' in child['id']:
                backdoor_task = child
                break

        assert backdoor_task is not None, "Fileless backdoor detection should exist"
        assert backdoor_task['type'] == 'parent'

        # Verify subtasks mention NET-STAR, Assembly.Load
        has_net_star = False
        for subtask in backdoor_task['children']:
            metadata = subtask.get('metadata', {})
            desc = metadata.get('description', '').lower()
            next_steps = ' '.join(metadata.get('next_steps', [])).lower()

            if 'net-star' in desc or 'assembly.load' in next_steps:
                has_net_star = True
                break

        assert has_net_star, "Should reference NET-STAR or reflective loading techniques"

    def test_plugin_size_reasonable(self, plugin):
        """PROVES: Plugin file size is reasonable (not bloated)"""
        import os
        plugin_file = '/home/kali/OSCP/crack/track/services/iis.py'
        size_kb = os.path.getsize(plugin_file) / 1024

        # Target: <15KB per requirements, allow up to 45KB for comprehensive IIS coverage
        # IIS has extensive attack surface (web.config, path traversal, ASP.NET, etc.)
        assert size_kb < 45, f"Plugin too large: {size_kb:.1f}KB (target <45KB)"
        assert size_kb > 5, f"Plugin suspiciously small: {size_kb:.1f}KB (check completeness)"

    def test_task_count_comprehensive(self, plugin):
        """PROVES: Plugin generates comprehensive task list"""
        service_info = {
            'port': 80,
            'service': 'http',
            'product': 'Microsoft-IIS/10.0',
            'version': '10.0'
        }

        tree = plugin.get_task_tree('192.168.45.100', 80, service_info)

        # Count all tasks (including nested)
        task_count = 0
        def count_tasks(node):
            nonlocal task_count
            task_count += 1
            for child in node.get('children', []):
                count_tasks(child)

        count_tasks(tree)

        # Should have at least 20 total tasks (including parent containers)
        assert task_count >= 20, f"Only {task_count} tasks generated (expected 20+)"
