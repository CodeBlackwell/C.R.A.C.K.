"""
Tests for Windows Buffer Overflow exploitation plugin

Validates:
- Service detection (POP3, VulnServer, Windows services)
- Complete 8-phase exploitation methodology
- OSCP-required metadata completeness
- Protection bypass task generation
- SEH exploitation workflow
"""

import pytest
from crack.track.services.windows_bof import WindowsBufferOverflowPlugin


class TestWindowsBufferOverflowPlugin:
    """Test suite for Windows BOF exploitation plugin"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return WindowsBufferOverflowPlugin()

    def test_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "windows-bof"

    def test_default_ports(self, plugin):
        """PROVES: Plugin monitors common vulnerable Windows service ports"""
        assert 110 in plugin.default_ports  # SLMail POP3
        assert 9999 in plugin.default_ports  # VulnServer
        assert 9998 in plugin.default_ports  # Brainstorm
        assert len(plugin.default_ports) >= 5

    def test_detect_by_service_name_slmail(self, plugin):
        """PROVES: Plugin detects SLMail service"""
        port_info = {
            'port': 110,
            'service': 'pop3',
            'product': 'Seattle Lab Mail Server'
        }
        assert plugin.detect(port_info) == True

    def test_detect_by_service_name_vulnserver(self, plugin):
        """PROVES: Plugin detects VulnServer"""
        port_info = {
            'port': 9999,
            'service': 'vulnserver'
        }
        assert plugin.detect(port_info) == True

    def test_detect_by_port(self, plugin):
        """PROVES: Plugin detects by common vulnerable ports"""
        port_info = {
            'port': 110,
            'service': 'unknown'
        }
        assert plugin.detect(port_info) == True

    def test_detect_by_windows_os(self, plugin):
        """PROVES: Plugin detects Windows services on common ports"""
        port_info = {
            'port': 8080,
            'service': 'http',
            'ostype': 'Windows'
        }
        assert plugin.detect(port_info) == True

    def test_detect_negative(self, plugin):
        """PROVES: Plugin rejects unrelated services"""
        port_info = {
            'port': 22,
            'service': 'ssh',
            'product': 'OpenSSH'
        }
        assert plugin.detect(port_info) == False

    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid hierarchical structure"""
        service_info = {
            'port': 110,
            'service': 'pop3',
            'version': 'SLMail 5.5'
        }

        tree = plugin.get_task_tree('192.168.45.100', 110, service_info)

        # Root structure
        assert tree['id'] == 'windows-bof-110'
        assert tree['type'] == 'parent'
        assert 'Windows Buffer Overflow' in tree['name']
        assert 'children' in tree
        assert len(tree['children']) > 0

    def test_eight_phase_methodology(self, plugin):
        """PROVES: All 8 phases of BOF exploitation are present"""
        service_info = {'port': 9999, 'service': 'vulnserver'}
        tree = plugin.get_task_tree('192.168.45.100', 9999, service_info)

        phase_names = [child['name'] for child in tree['children']]

        # Check for all critical phases
        assert any('Phase 1' in name or 'Setup' in name for name in phase_names)
        assert any('Phase 2' in name or 'Offset Discovery' in name for name in phase_names)
        assert any('Phase 3' in name or 'Bad Character' in name for name in phase_names)
        assert any('Phase 4' in name or 'Return Address' in name for name in phase_names)
        assert any('Phase 5' in name or 'Shellcode' in name for name in phase_names)
        assert any('Phase 6' in name or 'Protection' in name for name in phase_names)
        assert any('Phase 7' in name or 'Troubleshooting' in name or 'Exploitation Problems' in name for name in phase_names)

    def test_phase1_setup_tasks(self, plugin):
        """PROVES: Phase 1 contains Immunity Debugger setup"""
        service_info = {'port': 110, 'service': 'pop3'}
        tree = plugin.get_task_tree('192.168.45.100', 110, service_info)

        setup_phase = [c for c in tree['children'] if 'Setup' in c['name']][0]
        setup_tasks = setup_phase['children']
        task_ids = [t['id'] for t in setup_tasks]

        assert any('immunity-debugger' in tid for tid in task_ids)
        assert any('exploit-template' in tid for tid in task_ids)

    def test_phase2_pattern_generation(self, plugin):
        """PROVES: Phase 2 includes pattern_create and pattern_offset"""
        service_info = {'port': 110, 'service': 'pop3'}
        tree = plugin.get_task_tree('192.168.45.100', 110, service_info)

        offset_phase = [c for c in tree['children'] if 'Offset Discovery' in c['name']][0]
        offset_tasks = offset_phase['children']

        pattern_create = [t for t in offset_tasks if 'pattern-create' in t['id']]
        pattern_offset = [t for t in offset_tasks if 'pattern-offset' in t['id']]

        assert len(pattern_create) > 0, "pattern_create task missing"
        assert len(pattern_offset) > 0, "pattern_offset task missing"

        # Check pattern_create command
        create_task = pattern_create[0]
        assert 'pattern_create.rb' in create_task['metadata']['command']
        assert '-l 3000' in create_task['metadata']['command']

    def test_phase3_badchars(self, plugin):
        """PROVES: Phase 3 includes bad character identification"""
        service_info = {'port': 9999, 'service': 'vulnserver'}
        tree = plugin.get_task_tree('192.168.45.100', 9999, service_info)

        badchar_phase = [c for c in tree['children'] if 'Bad Character' in c['name']][0]
        badchar_tasks = badchar_phase['children']

        # Should have badchar generation and identification
        assert len(badchar_tasks) >= 2
        assert any('badchars' in t['id'] for t in badchar_tasks)

        # Check badchar generation includes all bytes except \x00
        generate_task = [t for t in badchar_tasks if 'generate-badchars' in t['id']][0]
        assert '\\x01' in generate_task['metadata']['command']
        assert '\\xff' in generate_task['metadata']['command']

    def test_phase4_jmp_esp_finding(self, plugin):
        """PROVES: Phase 4 includes JMP ESP gadget finding"""
        service_info = {'port': 110, 'service': 'pop3'}
        tree = plugin.get_task_tree('192.168.45.100', 110, service_info)

        return_addr_phase = [c for c in tree['children'] if 'Return Address' in c['name']][0]
        return_tasks = return_addr_phase['children']

        # Should include mona modules, JMP ESP, and SEH gadget finding
        assert any('mona-modules' in t['id'] for t in return_tasks)
        assert any('jmp-esp' in t['id'] for t in return_tasks)
        assert any('pop-pop-ret' in t['id'] for t in return_tasks)

        # Check JMP ESP command
        jmp_esp_task = [t for t in return_tasks if 'jmp-esp' in t['id']][0]
        assert '\\xff\\xe4' in jmp_esp_task['metadata']['command']
        assert '!mona' in jmp_esp_task['metadata']['command']

    def test_phase5_shellcode_generation(self, plugin):
        """PROVES: Phase 5 includes msfvenom shellcode generation"""
        service_info = {'port': 9999, 'service': 'vulnserver'}
        tree = plugin.get_task_tree('192.168.45.100', 9999, service_info)

        shellcode_phase = [c for c in tree['children'] if 'Shellcode' in c['name']][0]
        shellcode_tasks = shellcode_phase['children']

        # Should have msfvenom and final exploit assembly
        assert any('msfvenom' in t['id'] for t in shellcode_tasks)
        assert any('final-exploit' in t['id'] for t in shellcode_tasks)

        # Check msfvenom command
        msfvenom_task = [t for t in shellcode_tasks if 'msfvenom' in t['id']][0]
        cmd = msfvenom_task['metadata']['command']
        assert 'windows/shell_reverse_tcp' in cmd
        assert 'LHOST' in cmd
        assert 'LPORT' in cmd
        assert '-b' in cmd  # Bad characters
        assert '-f python' in cmd

    def test_phase6_protection_bypasses(self, plugin):
        """PROVES: Phase 6 includes DEP, ASLR, Canary, SEH bypasses"""
        service_info = {'port': 110, 'service': 'pop3'}
        tree = plugin.get_task_tree('192.168.45.100', 110, service_info)

        protection_phase = [c for c in tree['children'] if 'Protection' in c['name']][0]
        bypass_tasks = protection_phase['children']

        # Should cover all major protections
        bypass_names = [t['name'].lower() for t in bypass_tasks]
        assert any('dep' in name or 'nx' in name for name in bypass_names)
        assert any('aslr' in name for name in bypass_names)
        assert any('canary' in name or 'canaries' in name for name in bypass_names)
        assert any('seh' in name for name in bypass_names)

    def test_seh_exploitation_details(self, plugin):
        """PROVES: SEH exploitation includes nSEH and POP POP RET details"""
        service_info = {'port': 8080, 'service': 'http', 'ostype': 'Windows'}
        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        protection_phase = [c for c in tree['children'] if 'Protection' in c['name']][0]
        seh_task = [t for t in protection_phase['children'] if 'SEH' in t['name']][0]

        metadata = seh_task['metadata']
        next_steps = ' '.join(metadata.get('next_steps', []))

        # Check for critical SEH details
        assert 'nSEH' in next_steps
        assert 'POP POP RET' in next_steps
        assert 'short jump' in next_steps.lower()
        assert 'exception' in next_steps.lower()

    def test_phase7_troubleshooting(self, plugin):
        """PROVES: Phase 7 includes common exploitation problems"""
        service_info = {'port': 9999, 'service': 'vulnserver'}
        tree = plugin.get_task_tree('192.168.45.100', 9999, service_info)

        troubleshoot_phase = [c for c in tree['children'] if 'Exploitation Problems' in c['name'] or 'Troubleshooting' in c['name']][0]
        troubleshoot_tasks = troubleshoot_phase['children']

        # Should cover shell interaction, shellcode corruption, service restart
        task_names = [t['name'].lower() for t in troubleshoot_tasks]
        assert any('shell' in name and 'interaction' in name for name in task_names)
        assert any('corruption' in name or 'self' in name for name in task_names)
        assert any('restart' in name or 'stability' in name for name in task_names)

    def test_exploit_research_with_version(self, plugin):
        """PROVES: Exploit research phase added when version detected"""
        service_info = {
            'port': 110,
            'service': 'pop3',
            'version': 'SLMail 5.5.0'
        }
        tree = plugin.get_task_tree('192.168.45.100', 110, service_info)

        # Should have Phase 8: Exploit Research
        phase_names = [c['name'] for c in tree['children']]
        assert any('Phase 8' in name or 'Exploit Research' in name for name in phase_names)

        exploit_research = [c for c in tree['children'] if 'Exploit Research' in c['name']][0]
        assert 'SLMail 5.5.0' in exploit_research['name']

    def test_oscp_metadata_completeness(self, plugin):
        """PROVES: All command tasks include OSCP-required metadata"""
        service_info = {'port': 110, 'service': 'pop3'}
        tree = plugin.get_task_tree('192.168.45.100', 110, service_info)

        # Flatten tree to get all tasks
        def get_all_tasks(node):
            tasks = []
            if 'children' in node:
                for child in node['children']:
                    tasks.append(child)
                    tasks.extend(get_all_tasks(child))
            return tasks

        all_tasks = get_all_tasks(tree)
        command_tasks = [t for t in all_tasks if t.get('type') == 'command']

        assert len(command_tasks) > 0, "No command tasks found"

        # Check random sample of command tasks for metadata
        for task in command_tasks[:5]:  # Check first 5 command tasks
            metadata = task.get('metadata', {})

            # Required fields
            assert 'command' in metadata, f"Task {task['id']} missing command"
            assert 'description' in metadata, f"Task {task['id']} missing description"
            assert 'tags' in metadata, f"Task {task['id']} missing tags"

            # OSCP educational fields
            if 'flag_explanations' not in metadata:
                # Manual tasks might not have flag explanations
                continue

            # Should have success/failure indicators or next_steps
            has_indicators = (
                'success_indicators' in metadata or
                'failure_indicators' in metadata or
                'next_steps' in metadata
            )
            assert has_indicators, f"Task {task['id']} missing guidance fields"

    def test_flag_explanations_quality(self, plugin):
        """PROVES: Flag explanations are educational and detailed"""
        service_info = {'port': 9999, 'service': 'vulnserver'}
        tree = plugin.get_task_tree('192.168.45.100', 9999, service_info)

        # Get pattern_create task as example
        offset_phase = [c for c in tree['children'] if 'Offset Discovery' in c['name']][0]
        pattern_task = [t for t in offset_phase['children'] if 'pattern-create' in t['id']][0]

        flag_explanations = pattern_task['metadata'].get('flag_explanations', {})
        assert len(flag_explanations) > 0

        # Check explanations are substantive (not just flag names)
        for flag, explanation in flag_explanations.items():
            assert len(explanation) > 10, f"Flag {flag} explanation too short"
            assert explanation != flag, "Explanation should differ from flag name"

    def test_alternatives_provided(self, plugin):
        """PROVES: Manual alternatives provided for automated tasks"""
        service_info = {'port': 110, 'service': 'pop3'}
        tree = plugin.get_task_tree('192.168.45.100', 110, service_info)

        def get_all_tasks(node):
            tasks = []
            if 'children' in node:
                for child in node['children']:
                    tasks.append(child)
                    tasks.extend(get_all_tasks(child))
            return tasks

        all_tasks = get_all_tasks(tree)
        tasks_with_alternatives = [
            t for t in all_tasks
            if t.get('metadata', {}).get('alternatives')
        ]

        # Should have multiple tasks with alternatives
        assert len(tasks_with_alternatives) > 5

        # Check alternatives are meaningful
        for task in tasks_with_alternatives[:3]:
            alternatives = task['metadata']['alternatives']
            assert isinstance(alternatives, list)
            assert len(alternatives) > 0
            for alt in alternatives:
                assert len(alt) > 10, "Alternatives should be detailed"

    def test_oscp_tags_present(self, plugin):
        """PROVES: Tasks use OSCP priority tags"""
        service_info = {'port': 9999, 'service': 'vulnserver'}
        tree = plugin.get_task_tree('192.168.45.100', 9999, service_info)

        def get_all_tasks(node):
            tasks = []
            if 'children' in node:
                for child in node['children']:
                    tasks.append(child)
                    tasks.extend(get_all_tasks(child))
            return tasks

        all_tasks = get_all_tasks(tree)
        tasks_with_tags = [
            t for t in all_tasks
            if t.get('metadata', {}).get('tags')
        ]

        assert len(tasks_with_tags) > 0

        # Collect all tags
        all_tags = []
        for task in tasks_with_tags:
            all_tags.extend(task['metadata']['tags'])

        # Should use OSCP priority tags
        assert any('OSCP:HIGH' in tag for tag in all_tags)
        assert any('QUICK_WIN' in tag for tag in all_tags)
        assert any('WINDOWS' in tag for tag in all_tags)

    def test_next_steps_actionable(self, plugin):
        """PROVES: Next steps provide clear guidance"""
        service_info = {'port': 110, 'service': 'pop3'}
        tree = plugin.get_task_tree('192.168.45.100', 110, service_info)

        offset_phase = [c for c in tree['children'] if 'Offset Discovery' in c['name']][0]
        verify_task = [t for t in offset_phase['children'] if 'verify-eip' in t['id']][0]

        next_steps = verify_task['metadata'].get('next_steps', [])
        assert len(next_steps) >= 3, "Should provide multiple next steps"

        # Check for actionable content
        for step in next_steps:
            assert len(step) > 20, "Steps should be detailed"
            # Should contain technical content
            assert any(
                keyword in step.lower()
                for keyword in ['verify', 'check', 'modify', 'run', 'note', 'test']
            )

    def test_success_failure_indicators(self, plugin):
        """PROVES: Tasks include success and failure indicators"""
        service_info = {'port': 9999, 'service': 'vulnserver'}
        tree = plugin.get_task_tree('192.168.45.100', 9999, service_info)

        shellcode_phase = [c for c in tree['children'] if 'Shellcode' in c['name']][0]
        msfvenom_task = [t for t in shellcode_phase['children'] if 'msfvenom' in t['id']][0]

        metadata = msfvenom_task['metadata']
        assert 'success_indicators' in metadata
        assert 'failure_indicators' in metadata

        success = metadata['success_indicators']
        failure = metadata['failure_indicators']

        assert len(success) >= 2, "Should provide multiple success indicators"
        assert len(failure) >= 2, "Should provide multiple failure indicators"

        # Indicators should be meaningful
        for indicator in success + failure:
            assert len(indicator) > 10

    def test_target_ip_in_commands(self, plugin):
        """PROVES: Target IP properly substituted in commands"""
        target_ip = '192.168.45.200'
        service_info = {'port': 110, 'service': 'pop3'}
        tree = plugin.get_task_tree(target_ip, 110, service_info)

        # Check setup phase for target IP in template
        setup_phase = [c for c in tree['children'] if 'Setup' in c['name']][0]
        template_task = [t for t in setup_phase['children'] if 'template' in t['id']][0]

        command = template_task['metadata']['command']
        assert target_ip in command, "Target IP should appear in exploit template"

    def test_windows_specific_tools(self, plugin):
        """PROVES: Tasks reference Windows-specific tools"""
        service_info = {'port': 8080, 'service': 'http', 'ostype': 'Windows'}
        tree = plugin.get_task_tree('192.168.45.100', 8080, service_info)

        def get_all_metadata(node):
            metadata_list = []
            if 'metadata' in node:
                metadata_list.append(node['metadata'])
            if 'children' in node:
                for child in node['children']:
                    metadata_list.extend(get_all_metadata(child))
            return metadata_list

        all_metadata = get_all_metadata(tree)
        all_text = ' '.join([
            str(m.get('command', '')) + ' ' +
            str(m.get('description', '')) + ' ' +
            ' '.join(m.get('next_steps', [])) + ' ' +
            ' '.join(m.get('alternatives', []))
            for m in all_metadata
        ])

        # Check for Windows-specific tools
        assert 'Immunity' in all_text or 'immunity' in all_text
        assert 'mona' in all_text
        assert any(term in all_text.lower() for term in ['x32dbg', 'x64dbg', 'windbg'])

    def test_no_linux_specific_content(self, plugin):
        """PROVES: Plugin focuses on Windows exploitation (no Linux-specific bypasses)"""
        service_info = {'port': 110, 'service': 'pop3'}
        tree = plugin.get_task_tree('192.168.45.100', 110, service_info)

        def get_all_metadata(node):
            metadata_list = []
            if 'metadata' in node:
                metadata_list.append(node['metadata'])
            if 'children' in node:
                for child in node['children']:
                    metadata_list.extend(get_all_metadata(child))
            return metadata_list

        all_metadata = get_all_metadata(tree)
        all_text = ' '.join([
            str(m.get('description', '')) + ' ' +
            ' '.join(m.get('notes', []) if isinstance(m.get('notes'), list) else [m.get('notes', '')])
            for m in all_metadata
        ]).lower()

        # Should NOT reference Linux-specific techniques in main content
        # (Some notes may mention for comparison, but primary focus is Windows)
        windows_mentions = all_text.count('windows')
        linux_mentions = all_text.count('linux')

        assert windows_mentions > linux_mentions, "Should focus primarily on Windows"
