"""
Comprehensive Tests for Windows Privilege Escalation Extended Plugin

Tests cover:
- Plugin registration and detection (manual trigger only)
- Task tree structure validation (5 major categories)
- All categories present: autorun-privesc, com-hijacking, msi-exploit,
  service-registry-abuse, potato-extended
- OSCP metadata completeness (flag_explanations, success_indicators,
  failure_indicators, next_steps, alternatives, tags)
- Key tasks validation: WMIC enum, scheduled tasks, Registry Run keys,
  Procmon COM detect, WiX MSI, AlwaysInstallElevated, RoguePotato,
  PrintSpoofer, GodPotato
- Task ID uniqueness
- Educational content quality
"""

import pytest
import sys
from pathlib import Path

# Add track directory to path
track_dir = Path(__file__).parent.parent.parent / 'track'
sys.path.insert(0, str(track_dir.parent))

from track.services.windows_privesc_extended import WindowsPrivescExtendedPlugin
from track.services.registry import ServiceRegistry


class TestWindowsPrivescExtendedPluginRegistration:
    """Test plugin registration and basic properties"""

    def test_plugin_registered(self):
        """PROVES: WindowsPrivescExtendedPlugin is registered in ServiceRegistry"""
        assert 'windows-privesc-extended' in ServiceRegistry._plugins
        plugin_class = ServiceRegistry._plugins['windows-privesc-extended']
        assert plugin_class == WindowsPrivescExtendedPlugin

    def test_plugin_name(self):
        """PROVES: Plugin name is 'windows-privesc-extended'"""
        plugin = WindowsPrivescExtendedPlugin()
        assert plugin.name == 'windows-privesc-extended'

    def test_plugin_default_ports_empty(self):
        """PROVES: Plugin has no default ports (manual trigger only)"""
        plugin = WindowsPrivescExtendedPlugin()
        assert plugin.default_ports == []

    def test_plugin_service_names_empty(self):
        """PROVES: Plugin has no service names (manual trigger only)"""
        plugin = WindowsPrivescExtendedPlugin()
        assert plugin.service_names == []


class TestWindowsPrivescExtendedDetection:
    """Test detection logic (should always return False - manual trigger)"""

    def test_detect_returns_false_for_any_port(self):
        """PROVES: Plugin never auto-detects (manual trigger only)"""
        plugin = WindowsPrivescExtendedPlugin()
        port_info_samples = [
            {'port': 445, 'service': 'microsoft-ds'},
            {'port': 3389, 'service': 'ms-wbt-server'},
            {'port': 5985, 'service': 'winrm'},
            {'port': 135, 'service': 'msrpc'},
            {},  # Empty port info
        ]
        for port_info in port_info_samples:
            assert plugin.detect(port_info) is False


class TestWindowsPrivescExtendedTaskTreeStructure:
    """Test task tree generation and structure"""

    @pytest.fixture
    def plugin(self):
        return WindowsPrivescExtendedPlugin()

    @pytest.fixture
    def task_tree(self, plugin):
        return plugin.get_task_tree('192.168.45.100', 0, {'context': 'local'})

    def test_task_tree_root_structure(self, task_tree):
        """PROVES: Root task has correct structure"""
        assert task_tree['id'] == 'windows-privesc-extended-192.168.45.100'
        assert 'Windows Privilege Escalation Extended' in task_tree['name']
        assert task_tree['type'] == 'parent'
        assert 'children' in task_tree

    def test_task_tree_has_five_categories(self, task_tree):
        """PROVES: Task tree has exactly 5 major categories"""
        children = task_tree['children']
        assert len(children) == 5, f"Expected 5 categories, got {len(children)}"

        # Verify category IDs
        category_ids = [child['id'] for child in children]
        assert any('autorun-privesc' in cid for cid in category_ids)
        assert any('com-hijacking' in cid for cid in category_ids)
        assert any('msi-exploit' in cid for cid in category_ids)
        assert any('service-registry-abuse' in cid for cid in category_ids)
        assert any('potato-extended' in cid for cid in category_ids)

    def test_autorun_privesc_category_structure(self, task_tree):
        """PROVES: Autorun privesc category has correct structure and tasks"""
        autorun_category = next(c for c in task_tree['children']
                                if 'autorun-privesc' in c['id'])
        assert 'Autorun Binary Privilege Escalation' in autorun_category['name']
        assert autorun_category['type'] == 'parent'
        assert len(autorun_category['children']) >= 7  # At least 7 autorun techniques

    def test_com_hijacking_category_structure(self, task_tree):
        """PROVES: COM hijacking category has correct structure and tasks"""
        com_category = next(c for c in task_tree['children']
                           if 'com-hijacking' in c['id'])
        assert 'COM Hijacking' in com_category['name']
        assert com_category['type'] == 'parent'
        assert len(com_category['children']) >= 5  # At least 5 COM techniques

    def test_msi_exploitation_category_structure(self, task_tree):
        """PROVES: MSI exploitation category has correct structure and tasks"""
        msi_category = next(c for c in task_tree['children']
                           if 'msi-exploit' in c['id'])
        assert 'MSI Exploitation' in msi_category['name']
        assert msi_category['type'] == 'parent'
        assert len(msi_category['children']) >= 3  # At least 3 MSI techniques

    def test_service_registry_abuse_category_structure(self, task_tree):
        """PROVES: Service registry abuse category has correct structure and tasks"""
        service_category = next(c for c in task_tree['children']
                               if 'service-registry-abuse' in c['id'])
        assert 'Service Registry Abuse' in service_category['name']
        assert service_category['type'] == 'parent'
        assert len(service_category['children']) >= 2  # At least 2 service techniques

    def test_potato_extended_category_structure(self, task_tree):
        """PROVES: Potato exploits category has correct structure and tasks"""
        potato_category = next(c for c in task_tree['children']
                              if 'potato-extended' in c['id'])
        assert 'Potato Exploits' in potato_category['name']
        assert potato_category['type'] == 'parent'
        assert len(potato_category['children']) >= 9  # At least 9 Potato variants


class TestAutorunPrivescTasks:
    """Test autorun privilege escalation task details"""

    @pytest.fixture
    def autorun_category(self):
        plugin = WindowsPrivescExtendedPlugin()
        tree = plugin.get_task_tree('192.168.45.100', 0, {})
        return next(c for c in tree['children'] if 'autorun-privesc' in c['id'])

    def test_wmic_startup_enum_task(self, autorun_category):
        """PROVES: WMIC startup enumeration task is present and complete"""
        wmic_task = next(t for t in autorun_category['children']
                        if 'wmic-startup-enum' in t['id'])

        assert wmic_task['name'] == 'WMIC Startup Enumeration'
        assert wmic_task['type'] == 'command'

        metadata = wmic_task['metadata']
        assert 'wmic startup get caption,command' in metadata['command']
        assert 'description' in metadata
        assert 'flag_explanations' in metadata
        assert len(metadata['flag_explanations']) >= 3
        assert 'startup' in metadata['flag_explanations']
        assert 'success_indicators' in metadata
        assert len(metadata['success_indicators']) >= 2
        assert 'failure_indicators' in metadata
        assert 'next_steps' in metadata
        assert 'alternatives' in metadata
        assert 'tags' in metadata
        assert 'OSCP:HIGH' in metadata['tags']

    def test_scheduled_tasks_enum_task(self, autorun_category):
        """PROVES: Scheduled tasks enumeration task is present and complete"""
        schtasks_task = next(t for t in autorun_category['children']
                            if 'schtasks-system-enum' in t['id'])

        assert 'Scheduled Tasks' in schtasks_task['name']
        assert schtasks_task['type'] == 'command'

        metadata = schtasks_task['metadata']
        assert 'schtasks /query' in metadata['command']
        assert '/fo LIST' in metadata['command']
        assert 'flag_explanations' in metadata
        assert '/query' in metadata['flag_explanations']
        assert '/v' in metadata['flag_explanations']
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'QUICK_WIN' in metadata['tags'] or 'EXPLOIT' in metadata['tags']

    def test_registry_run_keys_task(self, autorun_category):
        """PROVES: Registry Run keys enumeration task is present"""
        run_keys_task = next(t for t in autorun_category['children']
                            if 'registry-run-keys' in t['id'])

        assert 'Registry Run' in run_keys_task['name']
        metadata = run_keys_task['metadata']
        assert 'reg query' in metadata['command']
        assert 'CurrentVersion\\Run' in metadata['command']
        assert 'HKLM' in metadata['flag_explanations']
        assert 'HKCU' in metadata['flag_explanations']
        assert 'success_indicators' in metadata
        assert 'alternatives' in metadata

    def test_startup_folder_hijack_task(self, autorun_category):
        """PROVES: Startup folder hijacking task is present"""
        startup_task = next(t for t in autorun_category['children']
                           if 'startup-folder-hijack' in t['id'])

        assert 'Startup Folder' in startup_task['name']
        metadata = startup_task['metadata']
        assert '%programdata%' in metadata['command'] or '%appdata%' in metadata['command']
        assert 'flag_explanations' in metadata
        assert 'next_steps' in metadata
        assert len(metadata['next_steps']) >= 2

    def test_autoruns_comprehensive_task(self, autorun_category):
        """PROVES: SysInternals Autoruns task is present"""
        autoruns_task = next(t for t in autorun_category['children']
                            if 'autoruns-comprehensive' in t['id'])

        assert 'Autoruns' in autoruns_task['name']
        metadata = autoruns_task['metadata']
        assert 'autorunsc.exe' in metadata['command']
        assert '-m' in metadata['flag_explanations']
        assert '-a' in metadata['flag_explanations']
        assert 'AUTOMATED' in metadata['tags']


class TestCOMHijackingTasks:
    """Test COM hijacking task details"""

    @pytest.fixture
    def com_category(self):
        plugin = WindowsPrivescExtendedPlugin()
        tree = plugin.get_task_tree('192.168.45.100', 0, {})
        return next(c for c in tree['children'] if 'com-hijacking' in c['id'])

    def test_procmon_com_detect_task(self, com_category):
        """PROVES: Procmon COM detection task is present and complete"""
        procmon_task = next(t for t in com_category['children']
                           if 'procmon-com-detect' in t['id'])

        assert 'Procmon' in procmon_task['name']
        assert procmon_task['type'] == 'command'

        metadata = procmon_task['metadata']
        assert 'procmon.exe' in metadata['command']
        assert 'flag_explanations' in metadata
        assert '/Quiet' in metadata['flag_explanations']
        assert '/BackingFile' in metadata['flag_explanations']
        assert 'success_indicators' in metadata
        assert any('InprocServer32' in ind for ind in metadata['success_indicators'])
        assert 'next_steps' in metadata
        assert 'alternatives' in metadata

    def test_com_hijack_create_task(self, com_category):
        """PROVES: COM hijack creation task is present"""
        create_task = next(t for t in com_category['children']
                          if 'com-hijack-create' in t['id'])

        assert 'Create COM Hijack' in create_task['name']
        metadata = create_task['metadata']
        assert 'New-Item' in metadata['command']
        assert 'HKCU:Software\\Classes\\CLSID' in metadata['command']
        assert 'InprocServer32' in metadata['flag_explanations']
        assert 'OSCP:MEDIUM' in metadata['tags'] or 'OSCP:HIGH' in metadata['tags']
        assert 'EXPLOIT' in metadata['tags'] or 'PERSISTENCE' in metadata['tags']

    def test_task_scheduler_com_hijack_task(self, com_category):
        """PROVES: Task Scheduler COM hijack task is present"""
        sched_task = next(t for t in com_category['children']
                         if 'task-scheduler-com-hijack' in t['id'])

        assert 'Task Scheduler COM Hijack' in sched_task['name']
        metadata = sched_task['metadata']
        assert 'Get-ScheduledTask' in metadata['command']
        assert 'Actions.ClassId' in metadata['flag_explanations']
        assert 'success_indicators' in metadata
        assert 'QUICK_WIN' in metadata['tags'] or 'OSCP:HIGH' in metadata['tags']


class TestMSIExploitationTasks:
    """Test MSI exploitation task details"""

    @pytest.fixture
    def msi_category(self):
        plugin = WindowsPrivescExtendedPlugin()
        tree = plugin.get_task_tree('192.168.45.100', 0, {})
        return next(c for c in tree['children'] if 'msi-exploit' in c['id'])

    def test_wix_malicious_msi_task(self, msi_category):
        """PROVES: WiX Toolset MSI creation task is present"""
        wix_task = next(t for t in msi_category['children']
                       if 'wix-malicious-msi' in t['id'])

        assert 'WiX' in wix_task['name']
        assert wix_task['type'] == 'manual'

        metadata = wix_task['metadata']
        assert 'description' in metadata
        assert 'manual_steps' in metadata
        assert len(metadata['manual_steps']) >= 4
        assert any('candle.exe' in step for step in metadata['manual_steps'])
        assert any('light.exe' in step for step in metadata['manual_steps'])
        assert 'success_indicators' in metadata
        assert 'alternatives' in metadata

    def test_msi_wrapper_task(self, msi_category):
        """PROVES: MSI Wrapper task is present"""
        wrapper_task = next(t for t in msi_category['children']
                           if 'msi-wrapper-gui' in t['id'])

        assert 'MSI Wrapper' in wrapper_task['name']
        assert wrapper_task['type'] == 'manual'
        metadata = wrapper_task['metadata']
        assert 'manual_steps' in metadata
        assert len(metadata['manual_steps']) >= 5

    def test_always_install_elevated_task(self, msi_category):
        """PROVES: AlwaysInstallElevated check task is present and complete"""
        elevated_task = next(t for t in msi_category['children']
                            if 'always-install-elevated' in t['id'])

        assert 'AlwaysInstallElevated' in elevated_task['name']
        assert elevated_task['type'] == 'command'

        metadata = elevated_task['metadata']
        assert 'reg query' in metadata['command']
        assert 'AlwaysInstallElevated' in metadata['command']
        assert 'flag_explanations' in metadata
        assert 'HKCU' in metadata['flag_explanations']
        assert 'HKLM' in metadata['flag_explanations']
        assert 'AlwaysInstallElevated' in metadata['flag_explanations']
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'QUICK_WIN' in metadata['tags'] or 'EXPLOIT' in metadata['tags']
        assert 'success_indicators' in metadata
        assert any('0x1' in ind or '= 1' in ind for ind in metadata['success_indicators'])
        assert 'next_steps' in metadata
        assert any('msiexec' in step for step in metadata['next_steps'])


class TestServiceRegistryAbuseTasks:
    """Test service registry abuse task details"""

    @pytest.fixture
    def service_category(self):
        plugin = WindowsPrivescExtendedPlugin()
        tree = plugin.get_task_tree('192.168.45.100', 0, {})
        return next(c for c in tree['children'] if 'service-registry-abuse' in c['id'])

    def test_writable_service_registry_enum_task(self, service_category):
        """PROVES: Writable service registry enumeration task is present"""
        enum_task = next(t for t in service_category['children']
                        if 'writable-service-registry-enum' in t['id'])

        assert 'Writable Service Registry' in enum_task['name']
        assert enum_task['type'] == 'command'

        metadata = enum_task['metadata']
        assert 'accesschk.exe' in metadata['command']
        assert 'CurrentControlSet\\Services' in metadata['command']
        assert 'flag_explanations' in metadata
        assert '-u' in metadata['flag_explanations']
        assert '-w' in metadata['flag_explanations']
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'success_indicators' in metadata
        assert 'next_steps' in metadata

    def test_performance_subkey_dll_injection_task(self, service_category):
        """PROVES: Performance subkey DLL injection task is present"""
        perf_task = next(t for t in service_category['children']
                        if 'performance-subkey-dll-injection' in t['id'])

        assert 'Performance Subkey' in perf_task['name']
        assert perf_task['type'] == 'manual'
        metadata = perf_task['metadata']
        assert 'manual_steps' in metadata
        assert any('Performance' in step for step in metadata['manual_steps'])


class TestPotatoExtendedTasks:
    """Test Potato exploit task details"""

    @pytest.fixture
    def potato_category(self):
        plugin = WindowsPrivescExtendedPlugin()
        tree = plugin.get_task_tree('192.168.45.100', 0, {})
        return next(c for c in tree['children'] if 'potato-extended' in c['id'])

    def test_roguepotato_task(self, potato_category):
        """PROVES: RoguePotato task is present and complete"""
        rogue_task = next(t for t in potato_category['children']
                         if 'roguepotato' in t['id'])

        assert 'RoguePotato' in rogue_task['name']
        assert rogue_task['type'] == 'command'

        metadata = rogue_task['metadata']
        assert 'RoguePotato.exe' in metadata['command']
        assert 'flag_explanations' in metadata
        assert '-r' in metadata['flag_explanations']
        assert '-e' in metadata['flag_explanations']
        assert '-l' in metadata['flag_explanations']
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'QUICK_WIN' in metadata['tags'] or 'EXPLOIT' in metadata['tags']
        assert 'success_indicators' in metadata
        assert any('SYSTEM' in ind for ind in metadata['success_indicators'])
        assert 'failure_indicators' in metadata
        assert 'next_steps' in metadata
        assert 'alternatives' in metadata

    def test_printspoofer_task(self, potato_category):
        """PROVES: PrintSpoofer task is present and complete"""
        print_task = next(t for t in potato_category['children']
                         if 'printspoofer' in t['id'])

        assert 'PrintSpoofer' in print_task['name']
        assert print_task['type'] == 'command'

        metadata = print_task['metadata']
        assert 'PrintSpoofer.exe' in metadata['command']
        assert 'flag_explanations' in metadata
        assert '-i' in metadata['flag_explanations']
        assert '-c' in metadata['flag_explanations']
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'QUICK_WIN' in metadata['tags']
        assert 'success_indicators' in metadata
        assert 'alternatives' in metadata

    def test_godpotato_task(self, potato_category):
        """PROVES: GodPotato task is present and complete"""
        god_task = next(t for t in potato_category['children']
                       if 'godpotato' in t['id'])

        assert 'GodPotato' in god_task['name']
        assert god_task['type'] == 'command'

        metadata = god_task['metadata']
        assert 'GodPotato.exe' in metadata['command']
        assert 'flag_explanations' in metadata
        assert '-cmd' in metadata['flag_explanations']
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'QUICK_WIN' in metadata['tags']
        assert 'RELIABLE' in metadata['tags']
        assert 'success_indicators' in metadata
        assert 'alternatives' in metadata

    def test_sharpefspotato_task(self, potato_category):
        """PROVES: SharpEfsPotato task is present"""
        efs_task = next(t for t in potato_category['children']
                       if 'sharpefspotato' in t['id'])

        assert 'SharpEfsPotato' in efs_task['name']
        metadata = efs_task['metadata']
        assert 'SharpEfsPotato.exe' in metadata['command']
        assert '-p' in metadata['flag_explanations']
        assert '-a' in metadata['flag_explanations']

    def test_juicypotato_legacy_task(self, potato_category):
        """PROVES: JuicyPotato (legacy) task is present"""
        juicy_task = next(t for t in potato_category['children']
                         if 'juicypotato-legacy' in t['id'])

        assert 'JuicyPotato' in juicy_task['name']
        assert 'Legacy' in juicy_task['name']
        metadata = juicy_task['metadata']
        assert 'JuicyPotato.exe' in metadata['command']
        assert '-l' in metadata['flag_explanations']
        assert '-c' in metadata['flag_explanations']
        assert '-t' in metadata['flag_explanations']
        assert 'LEGACY' in metadata['tags']

    def test_juicypotatong_task(self, potato_category):
        """PROVES: JuicyPotatoNG task is present"""
        ng_task = next(t for t in potato_category['children']
                      if 'juicypotatong' in t['id'])

        assert 'JuicyPotatoNG' in ng_task['name']
        metadata = ng_task['metadata']
        assert 'JuicyPotatoNG.exe' in metadata['command']
        assert '-t' in metadata['flag_explanations']
        assert '-p' in metadata['flag_explanations']

    def test_fullpowers_task(self, potato_category):
        """PROVES: FullPowers privilege restoration task is present"""
        full_task = next(t for t in potato_category['children']
                        if 'fullpowers' in t['id'])

        assert 'FullPowers' in full_task['name']
        metadata = full_task['metadata']
        assert 'FullPowers.exe' in metadata['command']
        assert '-c' in metadata['flag_explanations']
        assert '-z' in metadata['flag_explanations']
        assert 'CHAIN' in metadata['tags']


class TestOSCPMetadataCompleteness:
    """Test OSCP metadata presence and quality across all tasks"""

    @pytest.fixture
    def all_tasks(self):
        """Get all leaf tasks from all categories"""
        plugin = WindowsPrivescExtendedPlugin()
        tree = plugin.get_task_tree('192.168.45.100', 0, {'context': 'local'})
        tasks = []

        def collect_tasks(node):
            if node['type'] in ['command', 'manual']:
                tasks.append(node)
            if 'children' in node:
                for child in node['children']:
                    collect_tasks(child)

        collect_tasks(tree)
        return tasks

    def test_all_tasks_have_metadata(self, all_tasks):
        """PROVES: All tasks have metadata section"""
        for task in all_tasks:
            assert 'metadata' in task, f"Task {task['id']} missing metadata"

    def test_all_tasks_have_description(self, all_tasks):
        """PROVES: All tasks have meaningful descriptions"""
        for task in all_tasks:
            metadata = task['metadata']
            assert 'description' in metadata, f"Task {task['id']} missing description"
            assert len(metadata['description']) > 20, f"Task {task['id']} description too short"

    def test_command_tasks_have_commands(self, all_tasks):
        """PROVES: Command tasks have command field"""
        command_tasks = [t for t in all_tasks if t['type'] == 'command']
        for task in command_tasks:
            metadata = task['metadata']
            assert 'command' in metadata, f"Command task {task['id']} missing command"
            assert len(metadata['command']) > 5, f"Task {task['id']} command too short"

    def test_manual_tasks_have_steps(self, all_tasks):
        """PROVES: Manual tasks have manual_steps or commands"""
        manual_tasks = [t for t in all_tasks if t['type'] == 'manual']
        for task in manual_tasks:
            metadata = task['metadata']
            has_steps = 'manual_steps' in metadata or 'commands' in metadata
            assert has_steps, f"Manual task {task['id']} missing manual_steps/commands"

    def test_all_tasks_have_tags(self, all_tasks):
        """PROVES: All tasks have appropriate tags"""
        for task in all_tasks:
            metadata = task['metadata']
            assert 'tags' in metadata, f"Task {task['id']} missing tags"
            assert isinstance(metadata['tags'], list), f"Task {task['id']} tags not a list"
            assert len(metadata['tags']) > 0, f"Task {task['id']} has no tags"

    def test_tasks_have_oscp_tags(self, all_tasks):
        """PROVES: Most tasks have OSCP relevance tags"""
        oscp_tags = ['OSCP:HIGH', 'OSCP:MEDIUM', 'OSCP:LOW']
        tasks_with_oscp = [t for t in all_tasks
                          if any(tag in t['metadata'].get('tags', [])
                                for tag in oscp_tags)]
        # At least 80% should have OSCP tags
        assert len(tasks_with_oscp) / len(all_tasks) >= 0.8

    def test_command_tasks_have_flag_explanations(self, all_tasks):
        """PROVES: Command tasks have flag explanations"""
        command_tasks = [t for t in all_tasks if t['type'] == 'command']
        tasks_with_flags = [t for t in command_tasks
                           if 'flag_explanations' in t['metadata']
                           and len(t['metadata']['flag_explanations']) > 0]
        # At least 90% of command tasks should have flag explanations
        assert len(tasks_with_flags) / len(command_tasks) >= 0.9

    def test_tasks_have_success_indicators(self, all_tasks):
        """PROVES: Tasks have success indicators"""
        tasks_with_success = [t for t in all_tasks
                             if 'success_indicators' in t['metadata']
                             and len(t['metadata']['success_indicators']) > 0]
        # At least 95% should have success indicators
        assert len(tasks_with_success) / len(all_tasks) >= 0.95

    def test_tasks_have_failure_indicators(self, all_tasks):
        """PROVES: Most tasks have failure indicators"""
        tasks_with_failure = [t for t in all_tasks
                             if 'failure_indicators' in t['metadata']
                             and len(t['metadata']['failure_indicators']) > 0]
        # At least 90% should have failure indicators
        assert len(tasks_with_failure) / len(all_tasks) >= 0.9

    def test_tasks_have_next_steps(self, all_tasks):
        """PROVES: Tasks have next steps guidance"""
        tasks_with_next = [t for t in all_tasks
                          if 'next_steps' in t['metadata']
                          and len(t['metadata']['next_steps']) > 0]
        # At least 95% should have next steps
        assert len(tasks_with_next) / len(all_tasks) >= 0.95

    def test_tasks_have_alternatives(self, all_tasks):
        """PROVES: Tasks have alternative methods"""
        tasks_with_alt = [t for t in all_tasks
                         if 'alternatives' in t['metadata']
                         and len(t['metadata']['alternatives']) > 0]
        # At least 85% should have alternatives
        assert len(tasks_with_alt) / len(all_tasks) >= 0.85

    def test_tasks_have_notes(self, all_tasks):
        """PROVES: Most tasks have educational notes"""
        tasks_with_notes = [t for t in all_tasks
                           if 'notes' in t['metadata']
                           and len(t['metadata']['notes']) > 10]
        # At least 80% should have notes
        assert len(tasks_with_notes) / len(all_tasks) >= 0.8


class TestTaskIDUniqueness:
    """Test that all task IDs are unique"""

    def test_all_task_ids_unique(self):
        """PROVES: All task IDs are unique (no duplicates)"""
        plugin = WindowsPrivescExtendedPlugin()
        tree = plugin.get_task_tree('192.168.45.100', 0, {})

        all_ids = []

        def collect_ids(node):
            all_ids.append(node['id'])
            if 'children' in node:
                for child in node['children']:
                    collect_ids(child)

        collect_ids(tree)

        # Check for duplicates
        assert len(all_ids) == len(set(all_ids)), \
            f"Duplicate task IDs found: {[id for id in all_ids if all_ids.count(id) > 1]}"


class TestTaskTreeCompleteness:
    """Test overall task tree completeness and coverage"""

    @pytest.fixture
    def plugin(self):
        return WindowsPrivescExtendedPlugin()

    @pytest.fixture
    def task_tree(self, plugin):
        return plugin.get_task_tree('192.168.45.100', 0, {})

    def test_total_task_count(self, task_tree):
        """PROVES: Plugin has substantial number of tasks"""
        def count_tasks(node):
            count = 1
            if 'children' in node:
                for child in node['children']:
                    count += count_tasks(child)
            return count

        total = count_tasks(task_tree)
        # Should have at least 30+ tasks (5 categories with multiple tasks each)
        assert total >= 30, f"Expected 30+ tasks, got {total}"

    def test_command_task_count(self, task_tree):
        """PROVES: Plugin has many executable command tasks"""
        def count_command_tasks(node):
            count = 1 if node['type'] == 'command' else 0
            if 'children' in node:
                for child in node['children']:
                    count += count_command_tasks(child)
            return count

        command_count = count_command_tasks(task_tree)
        # Should have at least 20+ command tasks
        assert command_count >= 20, f"Expected 20+ command tasks, got {command_count}"

    def test_manual_task_count(self, task_tree):
        """PROVES: Plugin has manual tasks for complex techniques"""
        def count_manual_tasks(node):
            count = 1 if node['type'] == 'manual' else 0
            if 'children' in node:
                for child in node['children']:
                    count += count_manual_tasks(child)
            return count

        manual_count = count_manual_tasks(task_tree)
        # Should have at least 5+ manual tasks
        assert manual_count >= 5, f"Expected 5+ manual tasks, got {manual_count}"


class TestEdgeCasesAndRobustness:
    """Test edge cases and robustness"""

    def test_handles_empty_service_info(self):
        """PROVES: Plugin handles empty service_info gracefully"""
        plugin = WindowsPrivescExtendedPlugin()
        task_tree = plugin.get_task_tree('192.168.45.100', 0, {})
        assert task_tree is not None
        assert 'children' in task_tree
        assert len(task_tree['children']) == 5

    def test_handles_different_contexts(self):
        """PROVES: Plugin works with different context values"""
        plugin = WindowsPrivescExtendedPlugin()

        contexts = ['local', 'remote', 'post-exploit', '']
        for context in contexts:
            task_tree = plugin.get_task_tree('10.10.10.10', 0, {'context': context})
            assert task_tree is not None
            assert len(task_tree['children']) == 5

    def test_target_appears_in_task_ids(self):
        """PROVES: Target hostname appears in task IDs"""
        plugin = WindowsPrivescExtendedPlugin()
        target = '192.168.45.200'
        task_tree = plugin.get_task_tree(target, 0, {})

        assert target in task_tree['id']

        # Check at least some child IDs contain target
        for child in task_tree['children']:
            assert target in child['id']


class TestEducationalContentQuality:
    """Test quality of educational content for OSCP preparation"""

    @pytest.fixture
    def all_tasks(self):
        plugin = WindowsPrivescExtendedPlugin()
        tree = plugin.get_task_tree('192.168.45.100', 0, {})
        tasks = []

        def collect_tasks(node):
            if node['type'] in ['command', 'manual']:
                tasks.append(node)
            if 'children' in node:
                for child in node['children']:
                    collect_tasks(child)

        collect_tasks(tree)
        return tasks

    def test_success_indicators_are_specific(self, all_tasks):
        """PROVES: Success indicators are specific and actionable"""
        for task in all_tasks:
            if 'success_indicators' in task['metadata']:
                indicators = task['metadata']['success_indicators']
                for indicator in indicators:
                    assert len(indicator) > 10, \
                        f"Task {task['id']} has too short success indicator: {indicator}"

    def test_failure_indicators_are_helpful(self, all_tasks):
        """PROVES: Failure indicators help troubleshooting"""
        for task in all_tasks:
            if 'failure_indicators' in task['metadata']:
                indicators = task['metadata']['failure_indicators']
                for indicator in indicators:
                    assert len(indicator) > 10, \
                        f"Task {task['id']} has too short failure indicator: {indicator}"

    def test_next_steps_are_actionable(self, all_tasks):
        """PROVES: Next steps provide clear guidance"""
        for task in all_tasks:
            if 'next_steps' in task['metadata']:
                steps = task['metadata']['next_steps']
                assert len(steps) >= 2, \
                    f"Task {task['id']} should have at least 2 next steps"
                for step in steps:
                    assert len(step) > 15, \
                        f"Task {task['id']} next step too short: {step}"

    def test_alternatives_provide_options(self, all_tasks):
        """PROVES: Alternatives provide viable options"""
        command_tasks = [t for t in all_tasks if t['type'] == 'command']
        for task in command_tasks:
            if 'alternatives' in task['metadata']:
                alts = task['metadata']['alternatives']
                assert len(alts) >= 1, \
                    f"Command task {task['id']} should have alternatives"

    def test_flag_explanations_are_detailed(self, all_tasks):
        """PROVES: Flag explanations are educational"""
        command_tasks = [t for t in all_tasks if t['type'] == 'command']
        for task in command_tasks:
            if 'flag_explanations' in task['metadata']:
                flags = task['metadata']['flag_explanations']
                for flag, explanation in flags.items():
                    assert len(explanation) > 5, \
                        f"Task {task['id']} flag {flag} explanation too short"
                    assert explanation != flag, \
                        f"Task {task['id']} flag {flag} explanation just repeats flag"


class TestQuickWinTasks:
    """Test identification of quick win tasks for OSCP"""

    def test_quick_win_tasks_present(self):
        """PROVES: Plugin includes QUICK_WIN tasks"""
        plugin = WindowsPrivescExtendedPlugin()
        tree = plugin.get_task_tree('192.168.45.100', 0, {})

        def find_quick_wins(node):
            wins = []
            if node.get('type') in ['command', 'manual']:
                if 'QUICK_WIN' in node['metadata'].get('tags', []):
                    wins.append(node['name'])
            if 'children' in node:
                for child in node['children']:
                    wins.extend(find_quick_wins(child))
            return wins

        quick_wins = find_quick_wins(tree)
        assert len(quick_wins) >= 5, f"Expected at least 5 QUICK_WIN tasks, got {len(quick_wins)}"

    def test_high_oscp_relevance_tasks(self):
        """PROVES: Plugin has many OSCP:HIGH tasks"""
        plugin = WindowsPrivescExtendedPlugin()
        tree = plugin.get_task_tree('192.168.45.100', 0, {})

        def find_high_oscp(node):
            high = []
            if node.get('type') in ['command', 'manual']:
                if 'OSCP:HIGH' in node['metadata'].get('tags', []):
                    high.append(node['name'])
            if 'children' in node:
                for child in node['children']:
                    high.extend(find_high_oscp(child))
            return high

        high_oscp = find_high_oscp(tree)
        assert len(high_oscp) >= 10, f"Expected at least 10 OSCP:HIGH tasks, got {len(high_oscp)}"
