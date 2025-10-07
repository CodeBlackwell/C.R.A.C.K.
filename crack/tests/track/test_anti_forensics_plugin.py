"""
Tests for Anti-Forensics & Evasion service plugin

PROVES: Plugin generates comprehensive covering tracks and evasion tasks
"""

import pytest
from crack.track.services.anti_forensics import AntiForensicsPlugin


class TestAntiForensicsPlugin:
    """Test suite for Anti-Forensics plugin"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return AntiForensicsPlugin()

    def test_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "anti-forensics"

    def test_service_names(self, plugin):
        """PROVES: Plugin recognizes alternative names"""
        names = plugin.service_names
        assert 'anti-forensics' in names
        assert 'evasion' in names
        assert 'covering-tracks' in names

    def test_detect_returns_false(self, plugin):
        """PROVES: Plugin not auto-detected (manually triggered)"""
        port_info = {
            'port': 80,
            'service': 'http',
            'state': 'open'
        }
        assert plugin.detect(port_info) == False

    def test_windows_task_structure(self, plugin):
        """PROVES: Windows task tree has valid structure"""
        service_info = {'os_type': 'windows'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        # Root structure
        assert tree['id'] == 'anti-forensics-windows'
        assert tree['type'] == 'parent'
        assert 'Windows Anti-Forensics' in tree['name']
        assert 'children' in tree
        assert len(tree['children']) > 0

    def test_linux_task_structure(self, plugin):
        """PROVES: Linux task tree has valid structure"""
        service_info = {'os_type': 'linux'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        # Root structure
        assert tree['id'] == 'anti-forensics-linux'
        assert tree['type'] == 'parent'
        assert 'Linux Anti-Forensics' in tree['name']
        assert 'children' in tree
        assert len(tree['children']) > 0

    def test_windows_log_tampering_tasks(self, plugin):
        """PROVES: Windows log tampering tasks included"""
        service_info = {'os_type': 'windows'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        # Find log tampering section
        log_section = None
        for child in tree['children']:
            if 'log' in child['id'].lower():
                log_section = child
                break

        assert log_section is not None, "Log tampering section missing"
        assert 'children' in log_section

        # Verify specific tasks
        task_ids = [t['id'] for t in log_section['children']]
        assert any('clear-event-logs' in tid for tid in task_ids)
        assert any('disable-event-logs' in tid for tid in task_ids)
        assert any('powershell-logging' in tid for tid in task_ids)

    def test_windows_clear_event_logs_metadata(self, plugin):
        """PROVES: Windows event log clearing has complete OSCP metadata"""
        service_info = {'os_type': 'windows'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        # Find clear event logs task
        clear_logs_task = None
        for section in tree['children']:
            if 'children' in section:
                for task in section['children']:
                    if 'clear-event-logs' in task['id']:
                        clear_logs_task = task
                        break

        assert clear_logs_task is not None
        metadata = clear_logs_task['metadata']

        # Required OSCP fields
        assert 'command' in metadata
        assert 'wevtutil' in metadata['command']
        assert 'description' in metadata
        assert 'flag_explanations' in metadata
        assert len(metadata['flag_explanations']) >= 2
        assert 'success_indicators' in metadata
        assert len(metadata['success_indicators']) >= 1
        assert 'failure_indicators' in metadata
        assert len(metadata['failure_indicators']) >= 1
        assert 'alternatives' in metadata
        assert len(metadata['alternatives']) >= 2
        assert 'tags' in metadata
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'POST_EXPLOIT' in metadata['tags']

    def test_windows_powershell_logging_task(self, plugin):
        """PROVES: PowerShell logging disable task present (2023+ forensics)"""
        service_info = {'os_type': 'windows'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        # Find PowerShell logging task
        ps_task = None
        for section in tree['children']:
            if 'children' in section:
                for task in section['children']:
                    if 'powershell-logging' in task['id']:
                        ps_task = task
                        break

        assert ps_task is not None, "PowerShell logging task missing"
        metadata = ps_task['metadata']

        assert 'command' in metadata
        assert 'EnableScriptBlockLogging' in metadata['command']
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'STEALTH' in metadata['tags']

    def test_windows_shadow_copy_deletion(self, plugin):
        """PROVES: Shadow copy deletion task included"""
        service_info = {'os_type': 'windows'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        # Find shadow copy task
        shadow_task = None
        for section in tree['children']:
            if 'children' in section:
                for task in section['children']:
                    if 'shadow' in task['id'].lower():
                        shadow_task = task
                        break
                    if 'children' in task:
                        for subtask in task['children']:
                            if 'shadow' in subtask['id'].lower():
                                shadow_task = subtask
                                break

        assert shadow_task is not None, "Shadow copy task missing"
        metadata = shadow_task['metadata']

        assert 'vssadmin' in metadata['command']
        assert 'delete shadows' in metadata['command']
        assert 'OSCP:HIGH' in metadata['tags']

    def test_windows_advanced_evasion_section(self, plugin):
        """PROVES: Advanced evasion techniques (2023+) included"""
        service_info = {'os_type': 'windows'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        # Find advanced evasion section
        advanced_section = None
        for child in tree['children']:
            if 'advanced' in child['id'].lower():
                advanced_section = child
                break

        assert advanced_section is not None, "Advanced evasion section missing"
        assert '2023' in advanced_section['name']

        # Verify specific techniques
        task_ids = [t['id'] for t in advanced_section['children']]
        assert any('etw' in tid.lower() for tid in task_ids), "ETW patching missing"
        assert any('ads' in tid.lower() for tid in task_ids), "ADS hiding missing"
        assert any('byovd' in tid.lower() or 'aukill' in tid.lower() for tid in task_ids), "BYOVD missing"

    def test_windows_etw_patching_task(self, plugin):
        """PROVES: ETW patching task has educational content"""
        service_info = {'os_type': 'windows'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        # Find ETW task
        etw_task = None
        for section in tree['children']:
            if 'children' in section:
                for task in section['children']:
                    if 'etw' in task['id'].lower():
                        etw_task = task
                        break

        assert etw_task is not None, "ETW patching task missing"
        metadata = etw_task['metadata']

        assert 'notes' in metadata
        assert any('2024' in note or 'ETW' in note for note in metadata['notes'])
        assert 'alternatives' in metadata

    def test_windows_ads_hiding_task(self, plugin):
        """PROVES: Alternate Data Streams hiding task present"""
        service_info = {'os_type': 'windows'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        # Find ADS task
        ads_task = None
        for section in tree['children']:
            if 'children' in section:
                for task in section['children']:
                    if 'ads' in task['id'].lower():
                        ads_task = task
                        break

        assert ads_task is not None, "ADS hiding task missing"
        metadata = ads_task['metadata']

        assert 'command' in metadata
        assert ':' in metadata['command'], "ADS syntax missing"
        assert 'FIN12' in metadata['notes'] or '2023' in metadata['notes']
        assert 'STEALTH' in metadata['tags']

    def test_linux_log_tampering_tasks(self, plugin):
        """PROVES: Linux log tampering tasks included"""
        service_info = {'os_type': 'linux'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        # Find log tampering section
        log_section = None
        for child in tree['children']:
            if 'log' in child['id'].lower():
                log_section = child
                break

        assert log_section is not None, "Log tampering section missing"
        assert 'children' in log_section

        # Verify specific tasks
        task_ids = [t['id'] for t in log_section['children']]
        assert any('history' in tid for tid in task_ids)
        assert any('auth' in tid for tid in task_ids)
        assert any('disable' in tid or 'syslog' in tid for tid in task_ids)

    def test_linux_clear_history_metadata(self, plugin):
        """PROVES: Linux history clearing has complete OSCP metadata"""
        service_info = {'os_type': 'linux'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        # Find clear history task
        history_task = None
        for section in tree['children']:
            if 'children' in section:
                for task in section['children']:
                    if 'history' in task['id']:
                        history_task = task
                        break

        assert history_task is not None
        metadata = history_task['metadata']

        # Required OSCP fields
        assert 'command' in metadata
        assert 'history -c' in metadata['command']
        assert '.bash_history' in metadata['command']
        assert 'description' in metadata
        assert 'flag_explanations' in metadata
        assert 'success_indicators' in metadata
        assert 'failure_indicators' in metadata
        assert 'alternatives' in metadata
        assert len(metadata['alternatives']) >= 2
        assert 'tags' in metadata
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'QUICK_WIN' in metadata['tags']
        assert 'estimated_time' in metadata

    def test_linux_auth_log_clearing(self, plugin):
        """PROVES: Linux authentication log clearing included"""
        service_info = {'os_type': 'linux'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        # Find auth log task
        auth_task = None
        for section in tree['children']:
            if 'children' in section:
                for task in section['children']:
                    if 'auth' in task['id']:
                        auth_task = task
                        break

        assert auth_task is not None, "Auth log clearing missing"
        metadata = auth_task['metadata']

        assert 'command' in metadata
        assert '/var/log/auth.log' in metadata['command'] or '/var/log/secure' in metadata['command']
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'NOISY' in metadata['tags']

    def test_linux_timestamp_manipulation(self, plugin):
        """PROVES: Linux timestamp manipulation tasks present"""
        service_info = {'os_type': 'linux'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        # Find timestamp section
        timestamp_section = None
        for child in tree['children']:
            if 'timestamp' in child['id'].lower():
                timestamp_section = child
                break

        assert timestamp_section is not None, "Timestamp manipulation missing"
        assert 'children' in timestamp_section

        # Verify touch command task
        touch_task = None
        for task in timestamp_section['children']:
            if 'touch' in task['id']:
                touch_task = task
                break

        assert touch_task is not None
        metadata = touch_task['metadata']
        assert 'touch -r' in metadata['command']
        assert 'STEALTH' in metadata['tags']

    def test_linux_advanced_evasion_section(self, plugin):
        """PROVES: Advanced Linux evasion (2023+) included"""
        service_info = {'os_type': 'linux'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        # Find advanced section
        advanced_section = None
        for child in tree['children']:
            if 'advanced' in child['id'].lower():
                advanced_section = child
                break

        assert advanced_section is not None, "Advanced evasion section missing"
        assert '2023' in advanced_section['name']

        # Verify modern techniques
        task_ids = [t['id'] for t in advanced_section['children']]
        assert any('self-patch' in tid.lower() for tid in task_ids)
        assert any('cloud' in tid.lower() or 'c2' in tid.lower() for tid in task_ids)
        assert any('persistence' in tid.lower() for tid in task_ids)

    def test_linux_self_patching_task(self, plugin):
        """PROVES: Self-patching services task has CVE context"""
        service_info = {'os_type': 'linux'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        # Find self-patching task
        patch_task = None
        for section in tree['children']:
            if 'children' in section:
                for task in section['children']:
                    if 'self-patch' in task['id'].lower():
                        patch_task = task
                        break

        assert patch_task is not None, "Self-patching task missing"
        metadata = patch_task['metadata']

        assert 'notes' in metadata
        notes_text = ' '.join(metadata['notes'])
        assert 'CVE-2023' in notes_text or 'ActiveMQ' in notes_text
        assert 'Maven' in notes_text or 'repo1.maven.org' in notes_text

    def test_linux_cloud_c2_evasion_task(self, plugin):
        """PROVES: Cloud service C2 task mentions Dropbox/Cloudflare"""
        service_info = {'os_type': 'linux'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        # Find cloud C2 task
        c2_task = None
        for section in tree['children']:
            if 'children' in section:
                for task in section['children']:
                    if 'cloud' in task['id'].lower() or 'c2' in task['id'].lower():
                        c2_task = task
                        break

        assert c2_task is not None, "Cloud C2 task missing"
        metadata = c2_task['metadata']

        assert 'notes' in metadata
        notes_text = ' '.join(metadata['notes'])
        assert 'Dropbox' in notes_text or 'Cloudflare' in notes_text
        assert 'Bearer' in notes_text or 'OAuth' in notes_text

    def test_linux_dnscat_exfiltration_task(self, plugin):
        """PROVES: DNScat2 exfiltration task present"""
        service_info = {'os_type': 'linux'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        # Find DNScat task
        dnscat_task = None
        for section in tree['children']:
            if 'children' in section:
                for task in section['children']:
                    if 'dnscat' in task['id'].lower():
                        dnscat_task = task
                        break
                    if 'children' in task:
                        for subtask in task['children']:
                            if 'dnscat' in subtask['id'].lower():
                                dnscat_task = subtask
                                break

        assert dnscat_task is not None, "DNScat exfiltration task missing"
        metadata = dnscat_task['metadata']

        assert 'notes' in metadata
        notes_text = ' '.join(metadata['notes'])
        assert 'DNS' in notes_text
        assert '9 bytes' in notes_text or 'first 9' in notes_text.lower()

    def test_linux_shred_secure_deletion(self, plugin):
        """PROVES: Shred secure deletion task present"""
        service_info = {'os_type': 'linux'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        # Find shred task
        shred_task = None
        for section in tree['children']:
            if 'children' in section:
                for task in section['children']:
                    if 'shred' in task['id']:
                        shred_task = task
                        break
                    if 'children' in task:
                        for subtask in task['children']:
                            if 'shred' in subtask['id']:
                                shred_task = subtask
                                break

        assert shred_task is not None, "Shred task missing"
        metadata = shred_task['metadata']

        assert 'command' in metadata
        assert 'shred' in metadata['command']
        assert '-v' in metadata['command'] or '-f' in metadata['command']
        assert 'flag_explanations' in metadata
        assert len(metadata['flag_explanations']) >= 3

    def test_generic_fallback_structure(self, plugin):
        """PROVES: Generic fallback works for unknown OS"""
        service_info = {'os_type': 'unknown'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        assert tree['id'] == 'anti-forensics-generic'
        assert tree['type'] == 'parent'
        assert 'Generic' in tree['name']
        assert len(tree['children']) > 0

    def test_all_command_tasks_have_metadata(self, plugin):
        """PROVES: All command-type tasks have required metadata"""
        service_info = {'os_type': 'windows'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        def check_tasks(node):
            """Recursively check all tasks"""
            if node['type'] == 'command':
                assert 'metadata' in node, f"Task {node['id']} missing metadata"
                metadata = node['metadata']
                assert 'command' in metadata, f"Task {node['id']} missing command"
                assert 'description' in metadata, f"Task {node['id']} missing description"
                # Flag explanations required if command has flags
                if '-' in metadata['command']:
                    assert 'flag_explanations' in metadata, f"Task {node['id']} missing flag explanations"

            if 'children' in node:
                for child in node['children']:
                    check_tasks(child)

        check_tasks(tree)

    def test_all_manual_tasks_have_notes(self, plugin):
        """PROVES: All manual tasks have guidance notes"""
        service_info = {'os_type': 'linux'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        def check_tasks(node):
            """Recursively check all tasks"""
            if node['type'] == 'manual':
                assert 'metadata' in node, f"Manual task {node['id']} missing metadata"
                metadata = node['metadata']
                assert 'notes' in metadata or 'description' in metadata, \
                    f"Manual task {node['id']} missing notes/description"

            if 'children' in node:
                for child in node['children']:
                    check_tasks(child)

        check_tasks(tree)

    def test_oscp_tags_present(self, plugin):
        """PROVES: Tasks tagged appropriately for OSCP"""
        service_info = {'os_type': 'windows'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        oscp_tags_found = []

        def collect_tags(node):
            """Recursively collect tags"""
            if 'metadata' in node and 'tags' in node['metadata']:
                oscp_tags_found.extend([
                    tag for tag in node['metadata']['tags']
                    if 'OSCP' in tag or 'POST_EXPLOIT' in tag
                ])
            if 'children' in node:
                for child in node['children']:
                    collect_tags(child)

        collect_tags(tree)

        # Should have multiple OSCP-relevant tags
        assert len(oscp_tags_found) > 5, "Not enough OSCP tags"
        assert any('OSCP:HIGH' in tag for tag in oscp_tags_found)
        assert any('POST_EXPLOIT' in tag for tag in oscp_tags_found)

    def test_alternatives_provided(self, plugin):
        """PROVES: Command tasks include manual alternatives"""
        service_info = {'os_type': 'linux'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        command_tasks_with_alternatives = 0

        def check_tasks(node):
            """Recursively check tasks"""
            nonlocal command_tasks_with_alternatives
            if node['type'] == 'command' and 'metadata' in node:
                if 'alternatives' in node['metadata']:
                    assert len(node['metadata']['alternatives']) >= 1
                    command_tasks_with_alternatives += 1

            if 'children' in node:
                for child in node['children']:
                    check_tasks(child)

        check_tasks(tree)

        # Most command tasks should have alternatives
        assert command_tasks_with_alternatives >= 3, "Not enough alternatives provided"

    def test_success_failure_indicators(self, plugin):
        """PROVES: Tasks include success/failure indicators"""
        service_info = {'os_type': 'windows'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        tasks_with_indicators = 0

        def check_tasks(node):
            """Recursively check tasks"""
            nonlocal tasks_with_indicators
            if 'metadata' in node:
                metadata = node['metadata']
                if 'success_indicators' in metadata and 'failure_indicators' in metadata:
                    assert len(metadata['success_indicators']) >= 1
                    assert len(metadata['failure_indicators']) >= 1
                    tasks_with_indicators += 1

            if 'children' in node:
                for child in node['children']:
                    check_tasks(child)

        check_tasks(tree)

        # Multiple tasks should have indicators
        assert tasks_with_indicators >= 5, "Not enough success/failure indicators"

    def test_on_task_complete_returns_empty(self, plugin):
        """PROVES: No dynamic task generation for anti-forensics"""
        result = plugin.on_task_complete('test-task', 'output', '192.168.45.100')
        assert result == []

    def test_get_manual_alternatives_returns_guidance(self, plugin):
        """PROVES: Manual alternatives method returns guidance"""
        alternatives = plugin.get_manual_alternatives('any-task')
        assert isinstance(alternatives, list)
        assert len(alternatives) >= 1


class TestAntiForensicsIntegration:
    """Integration tests for anti-forensics plugin in CRACK Track"""

    def test_plugin_registration(self):
        """PROVES: Plugin auto-registers with ServiceRegistry"""
        from crack.track.services.registry import ServiceRegistry

        # Plugin should be registered
        plugins = ServiceRegistry.get_all_plugins()
        plugin_names = [p.name for p in plugins]
        assert 'anti-forensics' in plugin_names

    def test_manual_trigger_workflow(self):
        """PROVES: Plugin works in manual trigger workflow"""
        plugin = AntiForensicsPlugin()

        # Simulate manual trigger with Windows system
        service_info = {'os_type': 'windows'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        # Verify comprehensive output
        assert tree is not None
        assert len(tree['children']) >= 4  # Multiple major sections

        # Count total tasks
        def count_tasks(node):
            count = 1
            if 'children' in node:
                for child in node['children']:
                    count += count_tasks(child)
            return count

        total_tasks = count_tasks(tree)
        assert total_tasks >= 15, f"Expected 15+ tasks, got {total_tasks}"
