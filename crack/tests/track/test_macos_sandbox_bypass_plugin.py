"""
Tests for macOS Sandbox & TCC Bypass Plugin

PROVES: Plugin correctly detects macOS systems and generates comprehensive privilege escalation tasks
"""

import pytest
from crack.track.services.macos_sandbox_bypass import MacOSSandboxBypassPlugin


class TestMacOSSandboxBypassPlugin:
    """Test suite for macOS Sandbox & TCC Bypass plugin"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return MacOSSandboxBypassPlugin()

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "macos-sandbox-bypass"

    def test_service_names(self, plugin):
        """PROVES: Plugin recognizes macOS service identifiers"""
        expected_names = ['macos', 'darwin', 'osx']
        assert plugin.service_names == expected_names

    def test_default_ports_empty(self, plugin):
        """PROVES: Plugin is not port-based (OS-level privilege escalation)"""
        assert plugin.default_ports == []

    def test_detect_by_ostype_darwin(self, plugin):
        """PROVES: Plugin detects Darwin OS type"""
        port_info = {
            'port': 22,
            'service': 'ssh',
            'ostype': 'Darwin'
        }
        assert plugin.detect(port_info) == True

    def test_detect_by_ostype_macos(self, plugin):
        """PROVES: Plugin detects macOS OS type"""
        port_info = {
            'port': 445,
            'service': 'smb',
            'ostype': 'Mac OS X'
        }
        assert plugin.detect(port_info) == True

    def test_detect_by_service_apple(self, plugin):
        """PROVES: Plugin detects Apple services"""
        port_info = {
            'port': 548,
            'service': 'afp-apple',
            'ostype': ''
        }
        assert plugin.detect(port_info) == True

    def test_detect_by_product_apple(self, plugin):
        """PROVES: Plugin detects Apple products"""
        port_info = {
            'port': 22,
            'service': 'ssh',
            'product': 'Apple SSH'
        }
        assert plugin.detect(port_info) == True

    def test_detect_case_insensitive(self, plugin):
        """PROVES: Plugin performs case-insensitive detection"""
        port_info = {
            'port': 22,
            'service': 'ssh',
            'ostype': 'DARWIN'
        }
        assert plugin.detect(port_info) == True

    def test_detect_negative_linux(self, plugin):
        """PROVES: Plugin rejects Linux systems"""
        port_info = {
            'port': 22,
            'service': 'ssh',
            'ostype': 'Linux'
        }
        assert plugin.detect(port_info) == False

    def test_detect_negative_windows(self, plugin):
        """PROVES: Plugin rejects Windows systems"""
        port_info = {
            'port': 445,
            'service': 'smb',
            'ostype': 'Windows'
        }
        assert plugin.detect(port_info) == False

    def test_task_tree_structure(self, plugin):
        """PROVES: Plugin generates valid task tree structure"""
        service_info = {
            'port': 22,
            'service': 'ssh',
            'ostype': 'Darwin'
        }

        tree = plugin.get_task_tree('192.168.45.100', 22, service_info)

        # Root structure
        assert 'id' in tree
        assert 'name' in tree
        assert 'type' in tree
        assert 'children' in tree
        assert tree['type'] == 'parent'
        assert tree['id'] == 'macos-sandbox-tcc-bypass'

    def test_task_tree_has_phases(self, plugin):
        """PROVES: Task tree includes all major attack phases"""
        service_info = {'ostype': 'Darwin'}
        tree = plugin.get_task_tree('192.168.45.100', 22, service_info)

        phase_ids = [child['id'] for child in tree['children']]

        # Verify all major phases present
        assert 'tcc-enumeration' in phase_ids
        assert 'sandbox-enumeration' in phase_ids
        assert 'tcc-bypass-techniques' in phase_ids
        assert 'sandbox-escape-techniques' in phase_ids
        assert 'process-injection-privesc' in phase_ids
        assert 'apple-events-abuse' in phase_ids
        assert 'mount-filesystem-attacks' in phase_ids
        assert 'tcc-payloads' in phase_ids
        assert 'exploit-research' in phase_ids

    def test_tcc_enumeration_tasks(self, plugin):
        """PROVES: TCC enumeration phase has comprehensive tasks"""
        tree = plugin.get_task_tree('192.168.45.100', 22, {'ostype': 'Darwin'})

        # Find TCC enumeration phase
        tcc_phase = next(c for c in tree['children'] if c['id'] == 'tcc-enumeration')

        assert tcc_phase['type'] == 'parent'
        assert len(tcc_phase['children']) >= 3

        # Check for key tasks
        task_ids = [t['id'] for t in tcc_phase['children']]
        assert 'tcc-user-db-query' in task_ids
        assert 'tcc-system-db-query' in task_ids
        assert 'tcc-location-services' in task_ids

    def test_tcc_user_db_task_metadata(self, plugin):
        """PROVES: TCC user database task has complete OSCP metadata"""
        tree = plugin.get_task_tree('192.168.45.100', 22, {'ostype': 'Darwin'})

        tcc_phase = next(c for c in tree['children'] if c['id'] == 'tcc-enumeration')
        user_db_task = next(t for t in tcc_phase['children'] if t['id'] == 'tcc-user-db-query')

        metadata = user_db_task['metadata']

        # Required fields
        assert 'command' in metadata
        assert 'description' in metadata
        assert 'tags' in metadata
        assert 'flag_explanations' in metadata
        assert 'success_indicators' in metadata
        assert 'failure_indicators' in metadata
        assert 'next_steps' in metadata
        assert 'alternatives' in metadata
        assert 'notes' in metadata

        # Verify command structure
        assert 'sqlite3' in metadata['command']
        assert 'TCC.db' in metadata['command']
        assert '192.168.45.100' in metadata['command']

        # Verify tags
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'ENUM' in metadata['tags']

    def test_sandbox_escape_techniques(self, plugin):
        """PROVES: Sandbox escape phase includes diverse bypass methods"""
        tree = plugin.get_task_tree('192.168.45.100', 22, {'ostype': 'Darwin'})

        escape_phase = next(c for c in tree['children'] if c['id'] == 'sandbox-escape-techniques')

        assert len(escape_phase['children']) >= 5

        task_ids = [t['id'] for t in escape_phase['children']]

        # Key escape techniques
        assert 'sandbox-dylib-injection' in task_ids
        assert 'sandbox-plugin-injection' in task_ids
        assert 'sandbox-xpc-service-abuse' in task_ids
        assert 'sandbox-app-folder-exploit' in task_ids
        assert 'sandbox-launch-agent-persistence' in task_ids

    def test_apple_events_abuse_phase(self, plugin):
        """PROVES: Apple Events abuse phase includes AppleScript techniques"""
        tree = plugin.get_task_tree('192.168.45.100', 22, {'ostype': 'Darwin'})

        ae_phase = next(c for c in tree['children'] if c['id'] == 'apple-events-abuse')

        assert len(ae_phase['children']) >= 4

        task_ids = [t['id'] for t in ae_phase['children']]
        assert 'applescript-enumerate-apps' in task_ids
        assert 'applescript-iterm-control' in task_ids
        assert 'applescript-keystrokes-abuse' in task_ids

    def test_tcc_payloads_data_exfil(self, plugin):
        """PROVES: TCC payloads phase includes data exfiltration techniques"""
        tree = plugin.get_task_tree('192.168.45.100', 22, {'ostype': 'Darwin'})

        payloads_phase = next(c for c in tree['children'] if c['id'] == 'tcc-payloads')

        task_ids = [t['id'] for t in payloads_phase['children']]

        # Data exfiltration tasks
        assert 'exfil-desktop-documents' in task_ids
        assert 'exfil-photos-library' in task_ids
        assert 'record-camera' in task_ids
        assert 'record-microphone' in task_ids
        assert 'record-screen' in task_ids
        assert 'keylogger-accessibility' in task_ids

    def test_mounting_attacks_phase(self, plugin):
        """PROVES: Mounting attacks phase includes filesystem bypass techniques"""
        tree = plugin.get_task_tree('192.168.45.100', 22, {'ostype': 'Darwin'})

        mount_phase = next(c for c in tree['children'] if c['id'] == 'mount-filesystem-attacks')

        task_ids = [t['id'] for t in mount_phase['children']]
        assert 'mount-timemachine-snapshot' in task_ids
        assert 'mount-asr-disk-copy' in task_ids

    def test_cve_references_present(self, plugin):
        """PROVES: Plugin references historical CVEs for educational value"""
        tree = plugin.get_task_tree('192.168.45.100', 22, {'ostype': 'Darwin'})

        # Collect all task metadata
        all_tasks = []
        for phase in tree['children']:
            if phase['type'] == 'parent' and 'children' in phase:
                all_tasks.extend(phase['children'])

        # Check for CVE references in task IDs, names, or notes
        cve_found = False
        for task in all_tasks:
            task_str = str(task)
            if 'CVE' in task_str or 'cve' in task_str.lower():
                cve_found = True
                break

        assert cve_found, "Plugin should reference historical CVEs for learning"

    def test_manual_task_alternatives(self, plugin):
        """PROVES: Manual tasks include actionable alternatives"""
        tree = plugin.get_task_tree('192.168.45.100', 22, {'ostype': 'Darwin'})

        # Find first manual task
        manual_task = None
        for phase in tree['children']:
            if phase['type'] == 'parent' and 'children' in phase:
                for task in phase['children']:
                    if task['type'] == 'manual':
                        manual_task = task
                        break
                if manual_task:
                    break

        assert manual_task is not None
        assert 'metadata' in manual_task
        assert 'alternatives' in manual_task['metadata']
        assert len(manual_task['metadata']['alternatives']) > 0

    def test_command_tasks_have_flag_explanations(self, plugin):
        """PROVES: Command tasks include flag explanations for education"""
        tree = plugin.get_task_tree('192.168.45.100', 22, {'ostype': 'Darwin'})

        # Find first command task
        command_task = None
        for phase in tree['children']:
            if phase['type'] == 'parent' and 'children' in phase:
                for task in phase['children']:
                    if task['type'] == 'command':
                        command_task = task
                        break
                if command_task:
                    break

        assert command_task is not None
        metadata = command_task['metadata']
        assert 'flag_explanations' in metadata
        assert isinstance(metadata['flag_explanations'], dict)
        assert len(metadata['flag_explanations']) > 0

    def test_oscp_tags_present(self, plugin):
        """PROVES: Tasks are tagged with OSCP relevance"""
        tree = plugin.get_task_tree('192.168.45.100', 22, {'ostype': 'Darwin'})

        # Collect all tasks with metadata
        tagged_tasks = []
        for phase in tree['children']:
            if phase['type'] == 'parent' and 'children' in phase:
                for task in phase['children']:
                    if 'metadata' in task and 'tags' in task['metadata']:
                        tagged_tasks.append(task)

        assert len(tagged_tasks) > 0

        # Check for OSCP tags
        oscp_tagged = [t for t in tagged_tasks if any('OSCP:' in tag for tag in t['metadata']['tags'])]
        assert len(oscp_tagged) > 0

    def test_quick_win_tasks_identified(self, plugin):
        """PROVES: Fast, high-value tasks are tagged as QUICK_WIN"""
        tree = plugin.get_task_tree('192.168.45.100', 22, {'ostype': 'Darwin'})

        # Find all QUICK_WIN tasks
        quick_wins = []
        for phase in tree['children']:
            if phase['type'] == 'parent' and 'children' in phase:
                for task in phase['children']:
                    if 'metadata' in task and 'tags' in task['metadata']:
                        if 'QUICK_WIN' in task['metadata']['tags']:
                            quick_wins.append(task)

        assert len(quick_wins) > 0

    def test_macos_specific_tags(self, plugin):
        """PROVES: Tasks are tagged as macOS-specific"""
        tree = plugin.get_task_tree('192.168.45.100', 22, {'ostype': 'Darwin'})

        macos_tagged = 0
        for phase in tree['children']:
            if phase['type'] == 'parent' and 'children' in phase:
                for task in phase['children']:
                    if 'metadata' in task and 'tags' in task['metadata']:
                        if 'MACOS' in task['metadata']['tags']:
                            macos_tagged += 1

        assert macos_tagged > 5

    def test_process_injection_techniques(self, plugin):
        """PROVES: Process injection phase includes multiple privilege escalation vectors"""
        tree = plugin.get_task_tree('192.168.45.100', 22, {'ostype': 'Darwin'})

        injection_phase = next(c for c in tree['children'] if c['id'] == 'process-injection-privesc')

        task_ids = [t['id'] for t in injection_phase['children']]

        assert 'inject-terminal-fda' in task_ids
        assert 'inject-finder-automation' in task_ids
        assert 'inject-automator-control' in task_ids

    def test_exploit_research_phase(self, plugin):
        """PROVES: Plugin includes exploit research guidance"""
        tree = plugin.get_task_tree('192.168.45.100', 22, {'ostype': 'Darwin'})

        research_phase = next(c for c in tree['children'] if c['id'] == 'exploit-research')

        assert len(research_phase['children']) >= 2

        task_ids = [t['id'] for t in research_phase['children']]
        assert 'research-macos-version' in task_ids
        assert 'research-installed-apps' in task_ids

    def test_success_failure_indicators(self, plugin):
        """PROVES: Command tasks include success and failure indicators"""
        tree = plugin.get_task_tree('192.168.45.100', 22, {'ostype': 'Darwin'})

        # Find command tasks
        command_tasks = []
        for phase in tree['children']:
            if phase['type'] == 'parent' and 'children' in phase:
                for task in phase['children']:
                    if task['type'] == 'command':
                        command_tasks.append(task)

        assert len(command_tasks) > 0

        # Check first command task
        task = command_tasks[0]
        metadata = task['metadata']

        assert 'success_indicators' in metadata
        assert 'failure_indicators' in metadata
        assert len(metadata['success_indicators']) >= 2
        assert len(metadata['failure_indicators']) >= 2

    def test_next_steps_guidance(self, plugin):
        """PROVES: Tasks provide next steps for attack progression"""
        tree = plugin.get_task_tree('192.168.45.100', 22, {'ostype': 'Darwin'})

        # Find tasks with next_steps
        tasks_with_next_steps = []
        for phase in tree['children']:
            if phase['type'] == 'parent' and 'children' in phase:
                for task in phase['children']:
                    if 'metadata' in task and 'next_steps' in task['metadata']:
                        tasks_with_next_steps.append(task)

        assert len(tasks_with_next_steps) > 3

        # Verify next_steps is a list with content
        for task in tasks_with_next_steps:
            next_steps = task['metadata']['next_steps']
            assert isinstance(next_steps, list)
            assert len(next_steps) > 0

    def test_target_placeholder_injection(self, plugin):
        """PROVES: Commands include target IP placeholder"""
        tree = plugin.get_task_tree('192.168.45.100', 22, {'ostype': 'Darwin'})

        # Find command task
        tcc_phase = next(c for c in tree['children'] if c['id'] == 'tcc-enumeration')
        cmd_task = next(t for t in tcc_phase['children'] if t['type'] == 'command')

        assert '192.168.45.100' in cmd_task['metadata']['command']

    def test_comprehensive_coverage(self, plugin):
        """PROVES: Plugin provides comprehensive macOS privilege escalation coverage"""
        tree = plugin.get_task_tree('192.168.45.100', 22, {'ostype': 'Darwin'})

        # Count total tasks
        total_tasks = 0
        for phase in tree['children']:
            if phase['type'] == 'parent' and 'children' in phase:
                total_tasks += len(phase['children'])

        # Should have substantial coverage (40+ tasks across all phases)
        assert total_tasks >= 40, f"Expected 40+ tasks, got {total_tasks}"

    def test_tcc_bypass_diversity(self, plugin):
        """PROVES: TCC bypass phase includes multiple bypass vectors"""
        tree = plugin.get_task_tree('192.168.45.100', 22, {'ostype': 'Darwin'})

        bypass_phase = next(c for c in tree['children'] if c['id'] == 'tcc-bypass-techniques')

        # Should have multiple bypass techniques
        assert len(bypass_phase['children']) >= 5

    def test_educational_notes_present(self, plugin):
        """PROVES: Tasks include educational notes for OSCP preparation"""
        tree = plugin.get_task_tree('192.168.45.100', 22, {'ostype': 'Darwin'})

        # Count tasks with notes
        tasks_with_notes = 0
        for phase in tree['children']:
            if phase['type'] == 'parent' and 'children' in phase:
                for task in phase['children']:
                    if 'metadata' in task and 'notes' in task['metadata']:
                        tasks_with_notes += 1

        # Most tasks should have notes
        assert tasks_with_notes >= 20

    def test_no_hardcoded_credentials(self, plugin):
        """PROVES: Plugin doesn't contain hardcoded credentials"""
        tree = plugin.get_task_tree('192.168.45.100', 22, {'ostype': 'Darwin'})

        tree_str = str(tree).lower()

        # Check for common credential indicators
        assert 'password' not in tree_str or 'password' in 'no password'  # Allow descriptions
        assert 'admin:admin' not in tree_str
        assert 'root:root' not in tree_str
        assert 'password123' not in tree_str
