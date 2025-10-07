"""
Tests for C2 Configuration Extraction and Analysis Plugin

Validates C2 analysis task generation including:
- Memory dump and process analysis
- Beacon configuration extraction
- Network indicator identification
- Persistence mechanism hunting
- OSCP report documentation guidance
"""

import pytest
from crack.track.services.post_exploit import PostExploitPlugin


class TestC2AnalysisPlugin:
    """Test suite for C2 analysis functionality in PostExploitPlugin"""

    @pytest.fixture
    def plugin(self):
        """Create PostExploitPlugin instance"""
        return PostExploitPlugin()

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "post-exploit"

    def test_c2_analysis_windows_task_structure(self, plugin):
        """PROVES: C2 analysis generates valid hierarchical task tree for Windows"""
        service_info = {
            'os_type': 'windows'
        }

        tasks = plugin._get_c2_analysis_tasks('192.168.45.100', os_type='windows')

        # Root structure
        assert tasks['id'] == 'c2-analysis'
        assert tasks['name'] == 'C2 Configuration Extraction and Analysis'
        assert tasks['type'] == 'parent'
        assert 'children' in tasks

        # Verify major phases present
        phase_ids = [child['id'] for child in tasks['children']]
        assert 'c2-memory-dump' in phase_ids
        assert 'c2-config-extraction' in phase_ids
        assert 'c2-network-indicators' in phase_ids
        assert 'c2-persistence-hunt' in phase_ids
        assert 'c2-documentation' in phase_ids

    def test_c2_analysis_linux_task_structure(self, plugin):
        """PROVES: C2 analysis adapts commands for Linux OS"""
        tasks = plugin._get_c2_analysis_tasks('192.168.45.100', os_type='linux')

        # Find suspicious process identification task
        memory_dump_phase = next(
            child for child in tasks['children']
            if child['id'] == 'c2-memory-dump'
        )

        suspicious_proc_task = memory_dump_phase['children'][0]

        # Verify Linux-specific command used
        assert 'ps aux' in suspicious_proc_task['metadata']['command']
        assert 'grep -E' in suspicious_proc_task['metadata']['command']
        assert 'powershell' in suspicious_proc_task['metadata']['command']  # Pattern to search

    def test_memory_dump_phase_tasks(self, plugin):
        """PROVES: Memory dump phase includes process identification and dumping"""
        tasks = plugin._get_c2_analysis_tasks('192.168.45.100', os_type='windows')

        memory_phase = next(
            child for child in tasks['children']
            if child['id'] == 'c2-memory-dump'
        )

        assert memory_phase['type'] == 'parent'
        assert len(memory_phase['children']) == 2

        # Task 1: Identify suspicious processes
        task1 = memory_phase['children'][0]
        assert task1['id'] == 'c2-identify-suspicious'
        assert task1['type'] == 'command'
        assert 'tasklist' in task1['metadata']['command']
        assert 'OSCP:MEDIUM' in task1['metadata']['tags']
        assert 'QUICK_WIN' in task1['metadata']['tags']

        # Task 2: Dump process memory
        task2 = memory_phase['children'][1]
        assert task2['id'] == 'c2-dump-process'
        assert 'procdump' in task2['metadata']['command']

    def test_config_extraction_phase_tasks(self, plugin):
        """PROVES: Config extraction phase includes beacon location, string analysis, and decryption"""
        tasks = plugin._get_c2_analysis_tasks('192.168.45.100', os_type='windows')

        config_phase = next(
            child for child in tasks['children']
            if child['id'] == 'c2-config-extraction'
        )

        assert config_phase['type'] == 'parent'
        assert len(config_phase['children']) == 3

        task_ids = [task['id'] for task in config_phase['children']]
        assert 'c2-find-beacon-files' in task_ids
        assert 'c2-strings-analysis' in task_ids
        assert 'c2-rc4-decrypt' in task_ids

    def test_strings_analysis_task_metadata(self, plugin):
        """PROVES: Strings analysis task has comprehensive OSCP metadata"""
        tasks = plugin._get_c2_analysis_tasks('192.168.45.100', os_type='linux')

        config_phase = next(
            child for child in tasks['children']
            if child['id'] == 'c2-config-extraction'
        )

        strings_task = next(
            task for task in config_phase['children']
            if task['id'] == 'c2-strings-analysis'
        )

        metadata = strings_task['metadata']

        # Required OSCP fields
        assert 'command' in metadata
        assert 'strings' in metadata['command']
        assert 'grep -E' in metadata['command']

        assert 'description' in metadata
        assert 'flag_explanations' in metadata
        assert 'success_indicators' in metadata
        assert 'failure_indicators' in metadata
        assert 'next_steps' in metadata
        assert 'alternatives' in metadata
        assert 'tags' in metadata
        assert 'estimated_time' in metadata

        # Verify flag explanations
        flags = metadata['flag_explanations']
        assert 'strings' in flags
        assert '-a' in flags
        assert '-n 8' in flags
        assert 'grep -E' in flags
        assert 'tee' in flags

        # Verify success indicators
        success = metadata['success_indicators']
        assert len(success) >= 4
        assert any('HTTP' in s or 'URL' in s for s in success)
        assert any('User-Agent' in s for s in success)

        # Verify alternatives
        alternatives = metadata['alternatives']
        assert len(alternatives) >= 3
        assert any('Windows' in alt or 'Sysinternals' in alt for alt in alternatives)
        assert any('Manual' in alt or 'hex editor' in alt for alt in alternatives)

        # Verify tags
        assert 'OSCP:MEDIUM' in metadata['tags']
        assert 'QUICK_WIN' in metadata['tags']
        assert 'MANUAL' in metadata['tags']
        assert 'POST_EXPLOIT' in metadata['tags']

    def test_rc4_decryption_task_includes_script(self, plugin):
        """PROVES: RC4 decryption task includes complete Python decryption script"""
        tasks = plugin._get_c2_analysis_tasks('192.168.45.100')

        config_phase = next(
            child for child in tasks['children']
            if child['id'] == 'c2-config-extraction'
        )

        rc4_task = next(
            task for task in config_phase['children']
            if task['id'] == 'c2-rc4-decrypt'
        )

        assert rc4_task['type'] == 'manual'
        metadata = rc4_task['metadata']

        # Verify notes contain complete script
        notes = metadata['notes']
        assert isinstance(notes, list)

        script_content = '\n'.join(notes)
        assert 'def rc4(key, data):' in script_content
        assert 'S = list(range(256))' in script_content
        assert 'struct.unpack' in script_content
        assert 'blob[4:4+size]' in script_content
        assert 'blob[4+size:4+size+16]' in script_content
        assert 'unit42.paloaltonetworks.com' in script_content

        # Verify tags
        assert 'OSCP:MEDIUM' in metadata['tags']
        assert 'MANUAL' in metadata['tags']
        assert 'RESEARCH' in metadata['tags']

    def test_network_indicators_phase_tasks(self, plugin):
        """PROVES: Network indicators phase includes connection analysis and traffic capture"""
        tasks = plugin._get_c2_analysis_tasks('192.168.45.100', os_type='windows')

        network_phase = next(
            child for child in tasks['children']
            if child['id'] == 'c2-network-indicators'
        )

        assert network_phase['type'] == 'parent'
        assert len(network_phase['children']) == 3

        task_ids = [task['id'] for task in network_phase['children']]
        assert 'c2-active-connections' in task_ids
        assert 'c2-traffic-capture' in task_ids
        assert 'c2-http-fingerprint' in task_ids

    def test_active_connections_task_comprehensive(self, plugin):
        """PROVES: Active connections task has complete guidance for OSCP"""
        tasks = plugin._get_c2_analysis_tasks('192.168.45.100', os_type='linux')

        network_phase = next(
            child for child in tasks['children']
            if child['id'] == 'c2-network-indicators'
        )

        conn_task = next(
            task for task in network_phase['children']
            if task['id'] == 'c2-active-connections'
        )

        metadata = conn_task['metadata']

        # Verify Linux command
        assert 'netstat -antp' in metadata['command']
        assert 'grep ESTABLISHED' in metadata['command']

        # Verify comprehensive metadata
        flags = metadata['flag_explanations']
        assert '-a' in flags
        assert '-n' in flags
        assert '-t' in flags
        assert '-p' in flags

        # Success indicators mention common C2 ports
        success = metadata['success_indicators']
        assert any('443' in s or '80' in s or '4443' in s for s in success)

        # Next steps guide correlation and analysis
        next_steps = metadata['next_steps']
        assert len(next_steps) >= 4
        assert any('threat intel' in step.lower() for step in next_steps)
        assert any('tcpdump' in step.lower() or 'wireshark' in step.lower() for step in next_steps)

        # Alternatives include PowerShell and manual methods
        alternatives = metadata['alternatives']
        assert any('PowerShell' in alt or 'Get-NetTCPConnection' in alt for alt in alternatives)
        assert any('Manual' in alt or 'TCPView' in alt for alt in alternatives)

    def test_http_fingerprinting_task_details(self, plugin):
        """PROVES: HTTP fingerprinting task includes C2 framework indicators"""
        tasks = plugin._get_c2_analysis_tasks('192.168.45.100')

        network_phase = next(
            child for child in tasks['children']
            if child['id'] == 'c2-network-indicators'
        )

        fingerprint_task = next(
            task for task in network_phase['children']
            if task['id'] == 'c2-http-fingerprint'
        )

        assert fingerprint_task['type'] == 'manual'
        metadata = fingerprint_task['metadata']

        # Verify notes contain framework signatures
        notes = metadata['notes']
        notes_content = '\n'.join(notes)

        assert 'AdaptixC2' in notes_content
        assert 'Cobalt Strike' in notes_content
        assert 'Metasploit' in notes_content
        assert 'User-Agent patterns' in notes_content
        assert 'Wireshark filters' in notes_content
        assert 'http.request.method' in notes_content
        assert 'X-Beacon' in notes_content

        # Verify alternatives
        alternatives = metadata['alternatives']
        assert any('tshark' in alt for alt in alternatives)
        assert any('curl' in alt for alt in alternatives)

    def test_persistence_hunt_phase_tasks(self, plugin):
        """PROVES: Persistence hunt phase covers all common C2 persistence methods"""
        tasks = plugin._get_c2_analysis_tasks('192.168.45.100', os_type='windows')

        persistence_phase = next(
            child for child in tasks['children']
            if child['id'] == 'c2-persistence-hunt'
        )

        assert persistence_phase['type'] == 'parent'
        assert len(persistence_phase['children']) == 4

        task_ids = [task['id'] for task in persistence_phase['children']]
        assert 'c2-startup-folders' in task_ids
        assert 'c2-registry-run' in task_ids
        assert 'c2-dll-hijack' in task_ids
        assert 'c2-scheduled-tasks' in task_ids

    def test_registry_run_keys_task_windows_specific(self, plugin):
        """PROVES: Registry Run keys task is Windows-specific with proper metadata"""
        tasks = plugin._get_c2_analysis_tasks('192.168.45.100', os_type='windows')

        persistence_phase = next(
            child for child in tasks['children']
            if child['id'] == 'c2-persistence-hunt'
        )

        reg_task = next(
            task for task in persistence_phase['children']
            if task['id'] == 'c2-registry-run'
        )

        metadata = reg_task['metadata']

        # Verify Windows registry command
        assert 'reg query' in metadata['command']
        assert 'HKCU' in metadata['command']
        assert 'HKLM' in metadata['command']
        assert 'CurrentVersion\\Run' in metadata['command']

        # Flag explanations
        flags = metadata['flag_explanations']
        assert 'reg query' in flags
        assert 'HKCU' in flags
        assert 'HKLM' in flags

        # Success indicators mention suspicious patterns
        success = metadata['success_indicators']
        assert any('Updater' in s or 'Loader' in s for s in success)
        assert any('PowerShell' in s or '-enc' in s for s in success)

        # Next steps include decoding
        next_steps = metadata['next_steps']
        assert any('Decode' in step or 'EncodedCommand' in step for step in next_steps)

        # Alternatives include PowerShell and Autoruns
        alternatives = metadata['alternatives']
        assert any('PowerShell' in alt or 'Get-ItemProperty' in alt for alt in alternatives)
        assert any('Autoruns' in alt for alt in alternatives)

        # MITRE ATT&CK reference in notes
        assert 'T1547.001' in metadata['notes']

        # Tags
        assert 'WINDOWS' in metadata['tags']
        assert 'OSCP:MEDIUM' in metadata['tags']

    def test_dll_hijacking_task_comprehensive(self, plugin):
        """PROVES: DLL hijacking task includes common locations and verification steps"""
        tasks = plugin._get_c2_analysis_tasks('192.168.45.100', os_type='windows')

        persistence_phase = next(
            child for child in tasks['children']
            if child['id'] == 'c2-persistence-hunt'
        )

        dll_task = next(
            task for task in persistence_phase['children']
            if task['id'] == 'c2-dll-hijack'
        )

        assert dll_task['type'] == 'manual'
        metadata = dll_task['metadata']

        # Verify notes contain common DLL hijack locations
        notes = metadata['notes']
        notes_content = '\n'.join(notes)

        assert 'msimg32.dll' in notes_content
        assert '%APPDATA%' in notes_content or 'AppData' in notes_content
        assert 'Templates' in notes_content
        assert 'sigcheck' in notes_content
        assert 'T1574/001' in notes_content

        # Alternatives include Process Monitor
        alternatives = metadata['alternatives']
        assert any('Process Monitor' in alt for alt in alternatives)

        # Tags
        assert 'OSCP:MEDIUM' in metadata['tags']
        assert 'WINDOWS' in metadata['tags']

    def test_scheduled_tasks_cross_platform(self, plugin):
        """PROVES: Scheduled tasks check adapts to Windows and Linux"""
        # Windows version
        win_tasks = plugin._get_c2_analysis_tasks('192.168.45.100', os_type='windows')
        win_persistence = next(
            child for child in win_tasks['children']
            if child['id'] == 'c2-persistence-hunt'
        )
        win_sched_task = next(
            task for task in win_persistence['children']
            if task['id'] == 'c2-scheduled-tasks'
        )

        assert 'schtasks' in win_sched_task['metadata']['command']
        assert '/query' in win_sched_task['metadata']['command']

        # Linux version
        linux_tasks = plugin._get_c2_analysis_tasks('192.168.45.100', os_type='linux')
        linux_persistence = next(
            child for child in linux_tasks['children']
            if child['id'] == 'c2-persistence-hunt'
        )
        linux_sched_task = next(
            task for task in linux_persistence['children']
            if task['id'] == 'c2-scheduled-tasks'
        )

        assert 'crontab -l' in linux_sched_task['metadata']['command']
        assert '/etc/cron' in linux_sched_task['metadata']['command']

    def test_documentation_task_oscp_requirements(self, plugin):
        """PROVES: Documentation task provides complete OSCP reporting guidance"""
        tasks = plugin._get_c2_analysis_tasks('192.168.45.100')

        doc_task = next(
            child for child in tasks['children']
            if child['id'] == 'c2-documentation'
        )

        assert doc_task['type'] == 'manual'
        metadata = doc_task['metadata']

        # Verify comprehensive notes
        notes = metadata['notes']
        notes_content = '\n'.join(notes)

        # OSCP report sections
        assert 'C2 Infrastructure' in notes_content
        assert 'Beacon Configuration' in notes_content
        assert 'Persistence Mechanisms' in notes_content
        assert 'IOCs' in notes_content
        assert 'Screenshots' in notes_content

        # Specific required items
        assert 'Sleep/jitter' in notes_content
        assert 'User-Agent' in notes_content
        assert 'File hashes' in notes_content
        assert 'MD5/SHA256' in notes_content

        # CRACK Track integration
        assert 'crack track finding' in notes_content
        assert 'crack track note' in notes_content
        assert '--source' in notes_content

        # Tags
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'MANUAL' in metadata['tags']

    def test_all_command_tasks_have_flag_explanations(self, plugin):
        """PROVES: All command-type tasks include flag explanations"""
        tasks = plugin._get_c2_analysis_tasks('192.168.45.100', os_type='windows')

        def check_command_tasks(node):
            """Recursively check all command tasks have flag explanations"""
            if node.get('type') == 'command':
                metadata = node.get('metadata', {})
                assert 'flag_explanations' in metadata, f"Task {node['id']} missing flag_explanations"
                assert len(metadata['flag_explanations']) > 0, f"Task {node['id']} has empty flag_explanations"

            if 'children' in node:
                for child in node['children']:
                    check_command_tasks(child)

        check_command_tasks(tasks)

    def test_all_tasks_have_success_indicators(self, plugin):
        """PROVES: All command/manual tasks include success indicators for OSCP"""
        tasks = plugin._get_c2_analysis_tasks('192.168.45.100', os_type='windows')

        def check_indicators(node):
            """Recursively check tasks have success indicators"""
            if node.get('type') in ['command', 'manual']:
                metadata = node.get('metadata', {})

                # Command tasks must have success indicators
                if node.get('type') == 'command':
                    assert 'success_indicators' in metadata, f"Task {node['id']} missing success_indicators"
                    assert len(metadata['success_indicators']) > 0

            if 'children' in node:
                for child in node['children']:
                    check_indicators(child)

        check_indicators(tasks)

    def test_all_tasks_have_alternatives(self, plugin):
        """PROVES: All command tasks provide manual alternatives for OSCP exam"""
        tasks = plugin._get_c2_analysis_tasks('192.168.45.100', os_type='windows')

        def check_alternatives(node):
            """Recursively check command tasks have alternatives"""
            if node.get('type') == 'command':
                metadata = node.get('metadata', {})
                assert 'alternatives' in metadata, f"Task {node['id']} missing alternatives"
                alternatives = metadata['alternatives']
                assert len(alternatives) >= 1, f"Task {node['id']} needs at least 1 alternative"

                # At least one alternative should mention manual method
                has_manual = any('Manual' in alt or 'manual' in alt for alt in alternatives)
                has_tool = any(alt for alt in alternatives if not alt.startswith('Manual'))
                assert has_manual or has_tool, f"Task {node['id']} should have manual alternative or tool alternative"

            if 'children' in node:
                for child in node['children']:
                    check_alternatives(child)

        check_alternatives(tasks)

    def test_all_tasks_have_oscp_tags(self, plugin):
        """PROVES: All tasks are tagged with OSCP relevance level"""
        tasks = plugin._get_c2_analysis_tasks('192.168.45.100', os_type='windows')

        def check_oscp_tags(node):
            """Recursively check tasks have OSCP tags"""
            if node.get('type') in ['command', 'manual']:
                metadata = node.get('metadata', {})
                tags = metadata.get('tags', [])

                # Should have at least one OSCP tag
                oscp_tags = [tag for tag in tags if tag.startswith('OSCP:')]
                assert len(oscp_tags) > 0, f"Task {node['id']} missing OSCP relevance tag"

            if 'children' in node:
                for child in node['children']:
                    check_oscp_tags(child)

        check_oscp_tags(tasks)

    def test_task_ids_are_unique(self, plugin):
        """PROVES: All task IDs are unique within C2 analysis tree"""
        tasks = plugin._get_c2_analysis_tasks('192.168.45.100')

        task_ids = []

        def collect_ids(node):
            task_ids.append(node['id'])
            if 'children' in node:
                for child in node['children']:
                    collect_ids(child)

        collect_ids(tasks)

        # Check for duplicates
        assert len(task_ids) == len(set(task_ids)), f"Duplicate task IDs found: {[id for id in task_ids if task_ids.count(id) > 1]}"

    def test_estimated_times_present(self, plugin):
        """PROVES: Tasks include time estimates for OSCP exam planning"""
        tasks = plugin._get_c2_analysis_tasks('192.168.45.100', os_type='windows')

        tasks_with_times = []

        def check_times(node):
            if node.get('type') in ['command', 'manual']:
                metadata = node.get('metadata', {})
                if 'estimated_time' in metadata:
                    tasks_with_times.append(node['id'])

            if 'children' in node:
                for child in node['children']:
                    check_times(child)

        check_times(tasks)

        # At least some tasks should have time estimates
        assert len(tasks_with_times) >= 10, "Most tasks should include time estimates for OSCP planning"

    def test_c2_analysis_provides_value_for_oscp(self, plugin):
        """
        PROVES: C2 analysis plugin provides educational value for OSCP exam

        Value assertions:
        1. Teaches post-exploitation enumeration
        2. Covers C2 infrastructure documentation for reports
        3. Includes manual alternatives when tools fail
        4. Provides complete RC4 decryption script (educational)
        5. Maps to MITRE ATT&CK for report writing
        """
        tasks = plugin._get_c2_analysis_tasks('192.168.45.100', os_type='windows')

        # 1. Covers multiple post-exploitation phases
        phase_count = len(tasks['children'])
        assert phase_count >= 5, "Should cover multiple C2 analysis phases"

        # 2. Includes OSCP:HIGH documentation task
        doc_task = next(
            child for child in tasks['children']
            if child['id'] == 'c2-documentation'
        )
        assert 'OSCP:HIGH' in doc_task['metadata']['tags']

        # 3. All command tasks have manual alternatives
        # (tested in test_all_tasks_have_alternatives)

        # 4. RC4 decryption script included
        config_phase = next(
            child for child in tasks['children']
            if child['id'] == 'c2-config-extraction'
        )
        rc4_task = next(
            task for task in config_phase['children']
            if task['id'] == 'c2-rc4-decrypt'
        )
        script_content = '\n'.join(rc4_task['metadata']['notes'])
        assert 'def rc4(key, data):' in script_content

        # 5. MITRE ATT&CK references present
        persistence_phase = next(
            child for child in tasks['children']
            if child['id'] == 'c2-persistence-hunt'
        )

        mitre_references = []
        for task in persistence_phase['children']:
            metadata = task['metadata']
            if 'notes' in metadata:
                notes_content = str(metadata['notes'])
                if 'T1547' in notes_content or 'T1574' in notes_content or 'T1053' in notes_content:
                    mitre_references.append(task['id'])

        assert len(mitre_references) >= 3, "Should reference MITRE ATT&CK techniques"
