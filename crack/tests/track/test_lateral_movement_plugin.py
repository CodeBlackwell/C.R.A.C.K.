"""
Comprehensive tests for Lateral Movement plugin

Tests cover:
- Plugin registration and detection
- Task tree generation for all lateral movement methods
- OSCP metadata completeness
- Manual alternatives and educational content
- Pass-the-Hash scenarios
- Multi-method coverage
"""

import pytest
from crack.track.services.lateral_movement import LateralMovementPlugin
from crack.track.services.registry import ServiceRegistry

# Initialize plugins at module load to ensure registry is populated
ServiceRegistry.initialize_plugins()


@pytest.fixture
def plugin():
    """Create lateral movement plugin instance"""
    return LateralMovementPlugin()


@pytest.fixture
def test_target():
    """Test target IP"""
    return "192.168.45.100"


class TestPluginRegistration:
    """Test plugin registration and basic properties"""

    def test_plugin_registered(self):
        """PROVES: Lateral movement plugin is registered in ServiceRegistry"""
        assert 'lateral-movement' in [p.name for p in ServiceRegistry.get_all_plugins()]

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "lateral-movement"

    def test_default_ports(self, plugin):
        """PROVES: Plugin knows common lateral movement ports"""
        expected_ports = [445, 135, 3389, 5985, 5986]
        assert set(plugin.default_ports) == set(expected_ports)

    def test_service_names(self, plugin):
        """PROVES: Plugin has appropriate service name identifiers"""
        assert 'lateral-movement' in plugin.service_names
        assert 'windows-lateral' in plugin.service_names


class TestDetection:
    """Test service detection logic"""

    def test_manual_trigger_only(self, plugin):
        """PROVES: Plugin does NOT auto-detect (manual trigger only)"""
        # SMB service
        port_info = {
            'port': 445,
            'service': 'microsoft-ds',
            'state': 'open'
        }
        assert plugin.detect(port_info) is False

        # WinRM service
        port_info = {
            'port': 5985,
            'service': 'winrm',
            'state': 'open'
        }
        assert plugin.detect(port_info) is False

        # RDP service
        port_info = {
            'port': 3389,
            'service': 'ms-wbt-server',
            'state': 'open'
        }
        assert plugin.detect(port_info) is False


class TestTaskTreeGeneration:
    """Test task tree generation and structure"""

    def test_task_tree_structure(self, plugin, test_target):
        """PROVES: Task tree has proper hierarchical structure"""
        task_tree = plugin.get_task_tree(test_target, 445, {})

        # Root task
        assert task_tree['id'] == f'lateral-movement-{test_target}'
        assert task_tree['type'] == 'parent'
        assert 'children' in task_tree

        # Should have multiple technique categories
        assert len(task_tree['children']) >= 8  # PsExec, WMI, DCOM, WinRM, Tasks, RDP, SCM, Additional

    def test_psexec_techniques(self, plugin, test_target):
        """PROVES: PsExec/SMBExec techniques are comprehensive"""
        task_tree = plugin.get_task_tree(test_target, 445, {})

        # Find PsExec parent task
        psexec_task = None
        for child in task_tree['children']:
            if 'psexec' in child['id'].lower():
                psexec_task = child
                break

        assert psexec_task is not None
        assert psexec_task['type'] == 'parent'

        # Should have multiple PsExec methods
        assert len(psexec_task['children']) >= 5

        # Verify key tasks exist
        task_ids = [t['id'] for t in psexec_task['children']]
        assert any('manual-sc-exec' in tid for tid in task_ids)
        assert any('sysinternals-psexec' in tid for tid in task_ids)
        assert any('impacket-psexec' in tid for tid in task_ids)
        assert any('impacket-smbexec' in tid for tid in task_ids)
        assert any('crackmapexec' in tid for tid in task_ids)

    def test_wmi_techniques(self, plugin, test_target):
        """PROVES: WMI execution techniques are present"""
        task_tree = plugin.get_task_tree(test_target, 445, {})

        # Find WMI parent task
        wmi_task = None
        for child in task_tree['children']:
            if 'wmi' in child['id'].lower():
                wmi_task = child
                break

        assert wmi_task is not None
        assert wmi_task['type'] == 'parent'

        # Should have multiple WMI methods
        assert len(wmi_task['children']) >= 4

        # Verify key WMI tasks
        task_ids = [t['id'] for t in wmi_task['children']]
        assert any('manual-wmic' in tid for tid in task_ids)
        assert any('powershell-wmi' in tid for tid in task_ids)
        assert any('impacket-wmiexec' in tid for tid in task_ids)
        assert any('sharpwmi' in tid for tid in task_ids)

    def test_dcom_techniques(self, plugin, test_target):
        """PROVES: DCOM execution techniques are covered"""
        task_tree = plugin.get_task_tree(test_target, 445, {})

        # Find DCOM parent task
        dcom_task = None
        for child in task_tree['children']:
            if 'dcom' in child['id'].lower():
                dcom_task = child
                break

        assert dcom_task is not None
        assert dcom_task['type'] == 'parent'

        # Should have multiple DCOM methods
        assert len(dcom_task['children']) >= 4

        # Verify DCOM objects covered
        task_ids = [t['id'] for t in dcom_task['children']]
        assert any('mmc20' in tid for tid in task_ids)
        assert any('shellwindows' in tid for tid in task_ids)
        assert any('excel' in tid for tid in task_ids)
        assert any('impacket-dcomexec' in tid for tid in task_ids)

    def test_winrm_techniques(self, plugin, test_target):
        """PROVES: WinRM/PowerShell remoting techniques are included"""
        task_tree = plugin.get_task_tree(test_target, 5985, {})

        # Find WinRM parent task
        winrm_task = None
        for child in task_tree['children']:
            if 'winrm' in child['id'].lower():
                winrm_task = child
                break

        assert winrm_task is not None
        assert winrm_task['type'] == 'parent'

        # Should have WinRM methods
        assert len(winrm_task['children']) >= 3

        # Verify WinRM tasks
        task_ids = [t['id'] for t in winrm_task['children']]
        assert any('enter-pssession' in tid for tid in task_ids)
        assert any('invoke-command' in tid for tid in task_ids)
        assert any('evil-winrm' in tid for tid in task_ids)

    def test_scheduled_tasks_techniques(self, plugin, test_target):
        """PROVES: Scheduled task execution techniques are present"""
        task_tree = plugin.get_task_tree(test_target, 445, {})

        # Find scheduled tasks parent
        schtasks_task = None
        for child in task_tree['children']:
            if 'schtasks' in child['id'].lower():
                schtasks_task = child
                break

        assert schtasks_task is not None
        assert schtasks_task['type'] == 'parent'

        # Verify task scheduler methods
        task_ids = [t['id'] for t in schtasks_task['children']]
        assert any('at-command' in tid for tid in task_ids)
        assert any('schtasks-create' in tid for tid in task_ids)
        assert any('impacket-atexec' in tid for tid in task_ids)

    def test_rdp_techniques(self, plugin, test_target):
        """PROVES: RDP execution techniques are covered"""
        task_tree = plugin.get_task_tree(test_target, 3389, {})

        # Find RDP parent task
        rdp_task = None
        for child in task_tree['children']:
            if 'rdp' in child['id'].lower():
                rdp_task = child
                break

        assert rdp_task is not None
        assert rdp_task['type'] == 'parent'

        # Verify RDP tasks
        task_ids = [t['id'] for t in rdp_task['children']]
        assert any('rdp-login' in tid for tid in task_ids)
        assert any('rdp-pth' in tid for tid in task_ids)


class TestOSCPMetadata:
    """Test OSCP educational metadata completeness"""

    def test_all_tasks_have_metadata(self, plugin, test_target):
        """PROVES: All command tasks have complete metadata"""
        task_tree = plugin.get_task_tree(test_target, 445, {})

        def check_metadata(task):
            if task['type'] == 'command':
                assert 'metadata' in task
                metadata = task['metadata']

                # Required fields
                assert 'command' in metadata
                assert 'description' in metadata
                assert 'tags' in metadata

                # OSCP educational fields
                assert 'flag_explanations' in metadata
                assert len(metadata['flag_explanations']) > 0

                assert 'success_indicators' in metadata
                assert len(metadata['success_indicators']) >= 1

                assert 'failure_indicators' in metadata
                assert len(metadata['failure_indicators']) >= 1

                assert 'alternatives' in metadata
                assert len(metadata['alternatives']) >= 1

                assert 'next_steps' in metadata
                assert len(metadata['next_steps']) >= 1

            # Recurse to children
            if 'children' in task:
                for child in task['children']:
                    check_metadata(child)

        check_metadata(task_tree)

    def test_oscp_tags_present(self, plugin, test_target):
        """PROVES: Tasks have appropriate OSCP relevance tags"""
        task_tree = plugin.get_task_tree(test_target, 445, {})

        def collect_tags(task, tags_list):
            if task['type'] == 'command' and 'metadata' in task:
                tags_list.extend(task['metadata'].get('tags', []))

            if 'children' in task:
                for child in task['children']:
                    collect_tags(child, tags_list)

        all_tags = []
        collect_tags(task_tree, all_tags)

        # Should have OSCP tags
        oscp_tags = [t for t in all_tags if 'OSCP:' in t]
        assert len(oscp_tags) > 0

        # Should have method tags
        assert 'MANUAL' in all_tags or 'AUTOMATED' in all_tags

    def test_flag_explanations_comprehensive(self, plugin, test_target):
        """PROVES: Flag explanations are detailed and educational"""
        task_tree = plugin.get_task_tree(test_target, 445, {})

        # Check manual sc.exe task
        psexec_task = next(c for c in task_tree['children'] if 'psexec' in c['id'])
        manual_sc = next(c for c in psexec_task['children'] if 'manual-sc-exec' in c['id'])

        flag_explanations = manual_sc['metadata']['flag_explanations']

        # Should explain critical flags
        assert 'binPath=' in flag_explanations or '\\\\TARGET' in flag_explanations
        assert len(flag_explanations) >= 3

        # Explanations should be meaningful (not just flag name)
        for flag, explanation in flag_explanations.items():
            assert len(explanation) > 10  # Non-trivial explanation
            assert explanation != flag  # Not just repeating the flag

    def test_success_failure_indicators(self, plugin, test_target):
        """PROVES: Success/failure indicators help users verify results"""
        task_tree = plugin.get_task_tree(test_target, 445, {})

        # Check Impacket psexec task
        psexec_task = next(c for c in task_tree['children'] if 'psexec' in c['id'])
        impacket_psexec = next(c for c in psexec_task['children'] if 'impacket-psexec' in c['id'])

        metadata = impacket_psexec['metadata']

        # Success indicators should be specific
        success = metadata['success_indicators']
        assert len(success) >= 2
        assert any('shell' in s.lower() or 'prompt' in s.lower() for s in success)

        # Failure indicators should include troubleshooting
        failures = metadata['failure_indicators']
        assert len(failures) >= 2
        assert any('access denied' in f.lower() or 'denied' in f.lower() for f in failures)


class TestPassTheHashSupport:
    """Test Pass-the-Hash technique coverage"""

    def test_pth_in_impacket_tools(self, plugin, test_target):
        """PROVES: Impacket tools show Pass-the-Hash examples"""
        task_tree = plugin.get_task_tree(test_target, 445, {})

        # Check psexec.py
        psexec_task = next(c for c in task_tree['children'] if 'psexec' in c['id'])
        impacket_psexec = next(c for c in psexec_task['children'] if 'impacket-psexec' in c['id'])

        metadata = impacket_psexec['metadata']

        # Should mention -hashes flag
        assert '-hashes LMHASH:NTHASH' in metadata['flag_explanations']

        # Alternatives should include PTH example
        alternatives = ' '.join(metadata['alternatives'])
        assert '-hashes' in alternatives or 'NTHASH' in alternatives

    def test_rdp_pth_task(self, plugin, test_target):
        """PROVES: RDP Pass-the-Hash technique is documented"""
        task_tree = plugin.get_task_tree(test_target, 3389, {})

        rdp_task = next(c for c in task_tree['children'] if 'rdp' in c['id'])
        rdp_pth = next(c for c in rdp_task['children'] if 'pth' in c['id'])

        metadata = rdp_pth['metadata']

        # Should explain Restricted Admin mode
        assert '/pth:' in metadata['flag_explanations']
        assert 'Restricted Admin' in metadata['notes'] or 'Restricted Admin' in metadata['description']


class TestManualAlternatives:
    """Test manual alternatives for OSCP exam scenarios"""

    def test_manual_alternatives_present(self, plugin, test_target):
        """PROVES: Every automated task has manual alternatives"""
        task_tree = plugin.get_task_tree(test_target, 445, {})

        def check_alternatives(task):
            if task['type'] == 'command':
                metadata = task['metadata']
                tags = metadata.get('tags', [])

                # If automated, should have manual alternatives
                if 'AUTOMATED' in tags:
                    assert 'alternatives' in metadata
                    assert len(metadata['alternatives']) >= 1

            if 'children' in task:
                for child in task['children']:
                    check_alternatives(child)

        check_alternatives(task_tree)

    def test_manual_sc_exe_task(self, plugin, test_target):
        """PROVES: Manual sc.exe execution is well-documented"""
        task_tree = plugin.get_task_tree(test_target, 445, {})

        psexec_task = next(c for c in task_tree['children'] if 'psexec' in c['id'])
        manual_sc = next(c for c in psexec_task['children'] if 'manual-sc-exec' in c['id'])

        metadata = manual_sc['metadata']

        # Should be tagged as manual
        assert 'MANUAL' in metadata['tags']

        # Command should use sc.exe
        assert 'sc.exe' in metadata['command']

        # Should explain cleanup (delete service)
        assert 'delete' in metadata['command'].lower()


class TestMultiMethodCoverage:
    """Test coverage of multiple lateral movement methods"""

    def test_impacket_tools_covered(self, plugin, test_target):
        """PROVES: All major Impacket lateral movement tools are covered"""
        task_tree = plugin.get_task_tree(test_target, 445, {})

        def collect_commands(task, commands):
            if task['type'] == 'command' and 'metadata' in task:
                commands.append(task['metadata']['command'])

            if 'children' in task:
                for child in task['children']:
                    collect_commands(child, commands)

        all_commands = []
        collect_commands(task_tree, all_commands)
        commands_str = ' '.join(all_commands)

        # Verify Impacket tools
        assert 'psexec.py' in commands_str
        assert 'smbexec.py' in commands_str
        assert 'wmiexec.py' in commands_str
        assert 'dcomexec.py' in commands_str
        assert 'atexec.py' in commands_str

    def test_windows_native_tools(self, plugin, test_target):
        """PROVES: Windows native tools are documented"""
        task_tree = plugin.get_task_tree(test_target, 445, {})

        def collect_commands(task, commands):
            if task['type'] == 'command' and 'metadata' in task:
                commands.append(task['metadata']['command'])

            if 'children' in task:
                for child in task['children']:
                    collect_commands(child, commands)

        all_commands = []
        collect_commands(task_tree, all_commands)
        commands_str = ' '.join(all_commands)

        # Windows native tools
        assert 'sc.exe' in commands_str
        assert 'schtasks' in commands_str
        assert 'wmic' in commands_str or 'Get-WmiObject' in commands_str
        assert 'Enter-PSSession' in commands_str or 'Invoke-Command' in commands_str

    def test_third_party_tools(self, plugin, test_target):
        """PROVES: Third-party tools (SharpLateral, SharpMove, etc.) are covered"""
        task_tree = plugin.get_task_tree(test_target, 445, {})

        def collect_commands(task, commands):
            if task['type'] == 'command' and 'metadata' in task:
                commands.append(task['metadata']['command'])
                commands.extend(task['metadata'].get('alternatives', []))

            if 'children' in task:
                for child in task['children']:
                    collect_commands(child, commands)

        all_commands = []
        collect_commands(task_tree, all_commands)
        commands_str = ' '.join(all_commands)

        # Third-party C# tools
        assert 'SharpLateral' in commands_str or 'sharplateral' in commands_str.lower()
        assert 'SharpMove' in commands_str or 'sharpmove' in commands_str.lower()
        assert 'SharpWMI' in commands_str or 'sharpwmi' in commands_str.lower()

        # Other tools
        assert 'crackmapexec' in commands_str.lower() or 'cme' in commands_str
        assert 'evil-winrm' in commands_str.lower()
        assert 'xfreerdp' in commands_str.lower()


class TestOPSECConsiderations:
    """Test OPSEC and detection guidance"""

    def test_opsec_section_exists(self, plugin, test_target):
        """PROVES: OPSEC considerations are documented"""
        task_tree = plugin.get_task_tree(test_target, 445, {})

        # Find OPSEC parent task
        opsec_task = None
        for child in task_tree['children']:
            if 'opsec' in child['id'].lower():
                opsec_task = child
                break

        assert opsec_task is not None
        assert opsec_task['type'] == 'parent'

        # Should have artifacts/detection info
        assert len(opsec_task['children']) > 0

    def test_opsec_artifacts_documented(self, plugin, test_target):
        """PROVES: Common artifacts and detection signatures are listed"""
        task_tree = plugin.get_task_tree(test_target, 445, {})

        opsec_task = next(c for c in task_tree['children'] if 'opsec' in c['id'])
        artifacts_task = next(c for c in opsec_task['children'] if 'artifacts' in c['id'])

        metadata = artifacts_task['metadata']
        notes = metadata['notes']

        # Should mention common event IDs
        assert '4624' in notes  # Logon event
        assert '7045' in notes  # Service install
        assert '4698' in notes  # Scheduled task created

        # Should mention Sysmon
        assert 'Sysmon' in notes

        # Should mention OPSEC best practices
        assert 'OPSEC' in notes
        assert 'stealthy' in notes.lower() or 'stealth' in notes.lower()


class TestReferencesAndDocumentation:
    """Test references and educational resources"""

    def test_references_section_exists(self, plugin, test_target):
        """PROVES: References section exists with external resources"""
        task_tree = plugin.get_task_tree(test_target, 445, {})

        # Find references task
        ref_task = None
        for child in task_tree['children']:
            if 'reference' in child['id'].lower():
                ref_task = child
                break

        assert ref_task is not None
        assert ref_task['type'] == 'parent'

    def test_tool_github_links(self, plugin, test_target):
        """PROVES: GitHub links for tools are provided"""
        task_tree = plugin.get_task_tree(test_target, 445, {})

        ref_task = next(c for c in task_tree['children'] if 'reference' in c['id'])
        ref_child = ref_task['children'][0]
        notes = ref_child['metadata']['notes']

        # Should have GitHub links
        assert 'github.com' in notes.lower()

        # Key tools
        assert 'impacket' in notes.lower()
        assert 'evil-winrm' in notes.lower()
        assert 'sharplateral' in notes.lower()

    def test_hacktricks_attribution(self, plugin, test_target):
        """PROVES: HackTricks source is attributed"""
        task_tree = plugin.get_task_tree(test_target, 445, {})

        ref_task = next(c for c in task_tree['children'] if 'reference' in c['id'])
        ref_child = ref_task['children'][0]
        notes = ref_child['metadata']['notes']

        # Should reference HackTricks
        assert 'hacktricks' in notes.lower()


class TestTaskCounts:
    """Test that plugin has sufficient coverage"""

    def test_total_task_count(self, plugin, test_target):
        """PROVES: Plugin has substantial number of tasks"""
        task_tree = plugin.get_task_tree(test_target, 445, {})

        def count_tasks(task):
            count = 1
            if 'children' in task:
                for child in task['children']:
                    count += count_tasks(child)
            return count

        total_tasks = count_tasks(task_tree)

        # Should have at least 35+ tasks (comprehensive coverage)
        assert total_tasks >= 35

    def test_command_task_count(self, plugin, test_target):
        """PROVES: Plugin has many executable command tasks"""
        task_tree = plugin.get_task_tree(test_target, 445, {})

        def count_command_tasks(task):
            count = 1 if task['type'] == 'command' else 0
            if 'children' in task:
                for child in task['children']:
                    count += count_command_tasks(child)
            return count

        command_count = count_command_tasks(task_tree)

        # Should have at least 23+ command tasks
        assert command_count >= 23


class TestPluginQuality:
    """Test overall plugin quality and completeness"""

    def test_no_placeholder_values(self, plugin, test_target):
        """PROVES: No TODO or placeholder values in task tree"""
        task_tree = plugin.get_task_tree(test_target, 445, {})

        def check_no_placeholders(task):
            # Check all string values
            task_str = str(task)
            assert 'TODO' not in task_str
            assert 'FIXME' not in task_str
            assert 'XXX' not in task_str
            assert '<TODO>' not in task_str

            if 'children' in task:
                for child in task['children']:
                    check_no_placeholders(child)

        check_no_placeholders(task_tree)

    def test_unique_task_ids(self, plugin, test_target):
        """PROVES: All task IDs are unique (no duplicates)"""
        task_tree = plugin.get_task_tree(test_target, 445, {})

        def collect_ids(task, ids_list):
            ids_list.append(task['id'])
            if 'children' in task:
                for child in task['children']:
                    collect_ids(child, ids_list)

        all_ids = []
        collect_ids(task_tree, all_ids)

        # No duplicates
        assert len(all_ids) == len(set(all_ids))

    def test_notes_are_educational(self, plugin, test_target):
        """PROVES: Notes field provides educational value"""
        task_tree = plugin.get_task_tree(test_target, 445, {})

        # Check a few key tasks for educational notes
        psexec_task = next(c for c in task_tree['children'] if 'psexec' in c['id'])
        manual_sc = next(c for c in psexec_task['children'] if 'manual-sc-exec' in c['id'])

        notes = manual_sc['metadata']['notes']

        # Should explain requirements
        assert 'Requires' in notes or 'requires' in notes

        # Should mention UAC or admin rights
        assert 'admin' in notes.lower() or 'uac' in notes.lower()

        # Should be substantial
        assert len(notes) > 50


class TestEdgeCases:
    """Test edge cases and robustness"""

    def test_handles_empty_service_info(self, plugin, test_target):
        """PROVES: Plugin handles empty service_info gracefully"""
        task_tree = plugin.get_task_tree(test_target, 445, {})
        assert task_tree is not None
        assert 'children' in task_tree

    def test_handles_different_ports(self, plugin, test_target):
        """PROVES: Plugin works with different port numbers"""
        # Test with different common ports
        for port in [445, 135, 3389, 5985]:
            task_tree = plugin.get_task_tree(test_target, port, {})
            assert task_tree is not None
            assert task_tree['id'] == f'lateral-movement-{test_target}'

    def test_target_appears_in_commands(self, plugin):
        """PROVES: Target placeholder appears in generated commands"""
        test_target = "10.10.10.100"
        task_tree = plugin.get_task_tree(test_target, 445, {})

        def check_target_in_commands(task):
            if task['type'] == 'command' and 'metadata' in task:
                command = task['metadata']['command']
                # Target should appear in command (direct or via {target})
                assert test_target in command or '{target}' in command

            if 'children' in task:
                for child in task['children']:
                    check_target_in_commands(child)

        # Check at least some tasks
        psexec_task = next(c for c in task_tree['children'] if 'psexec' in c['id'])
        check_target_in_commands(psexec_task)
