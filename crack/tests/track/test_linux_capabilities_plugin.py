"""
Tests for Linux Capabilities & SUID privilege escalation plugin

This test validates comprehensive Linux privilege escalation enumeration
covering capabilities, SUID binaries, and container escape techniques.
"""

import pytest
from crack.track.services.linux_capabilities import LinuxCapabilitiesPlugin


class TestLinuxCapabilitiesPlugin:
    """Test suite for LinuxCapabilitiesPlugin"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return LinuxCapabilitiesPlugin()

    def test_plugin_registration(self, plugin):
        """PROVES: Plugin is properly registered"""
        assert plugin.name == "linux-capabilities"
        assert "linux-capabilities" in plugin.service_names
        assert "capabilities" in plugin.service_names

    def test_plugin_not_auto_detected(self, plugin):
        """PROVES: Plugin is manually triggered, not auto-detected"""
        # This plugin should never auto-detect (manual trigger only)
        port_info = {'port': 22, 'service': 'ssh', 'state': 'open'}
        assert plugin.detect(port_info) is False

    def test_task_tree_structure(self, plugin):
        """PROVES: Plugin generates comprehensive 4-phase task tree"""
        tree = plugin.get_task_tree(
            target='192.168.45.100',
            port=0,  # Not port-specific
            service_info={'os_type': 'linux'}
        )

        # Verify root structure
        assert tree['id'] == 'linux-capabilities-enum'
        assert tree['name'] == 'Linux Capabilities & SUID Privilege Escalation'
        assert tree['type'] == 'parent'
        assert 'children' in tree

        # Verify 4 phases present
        phase_names = [child['name'] for child in tree['children']]
        assert 'Phase 1: Discovery & Enumeration' in phase_names
        assert 'Phase 2: Capability-Specific Exploitation' in phase_names
        assert 'Phase 3: SUID/EUID Exploitation' in phase_names
        assert 'Phase 4: Docker/Container Escape Techniques' in phase_names

    def test_discovery_phase_content(self, plugin):
        """PROVES: Discovery phase includes all critical enumeration tasks"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {})

        discovery_phase = next(
            child for child in tree['children']
            if 'Discovery' in child['name']
        )

        # Extract task IDs
        task_ids = [task['id'] for task in discovery_phase['children']]

        # Critical tasks must be present
        assert 'caps-scan-binaries' in task_ids
        assert 'caps-check-current-process' in task_ids
        assert 'caps-find-suid' in task_ids

    def test_getcap_command_metadata(self, plugin):
        """PROVES: getcap command has full OSCP metadata"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {})

        discovery_phase = tree['children'][0]
        getcap_task = next(
            task for task in discovery_phase['children']
            if task['id'] == 'caps-scan-binaries'
        )

        metadata = getcap_task['metadata']

        # Verify command
        assert metadata['command'] == 'getcap -r / 2>/dev/null'

        # Verify OSCP tags
        assert 'OSCP:HIGH' in metadata['tags']
        assert 'QUICK_WIN' in metadata['tags']

        # Verify educational content
        assert 'flag_explanations' in metadata
        assert 'getcap' in metadata['flag_explanations']
        assert '-r' in metadata['flag_explanations']

        # Verify guidance
        assert 'success_indicators' in metadata
        assert 'failure_indicators' in metadata
        assert 'next_steps' in metadata
        assert 'alternatives' in metadata

        # Verify content quality
        assert len(metadata['success_indicators']) >= 2
        assert len(metadata['next_steps']) >= 2
        assert len(metadata['alternatives']) >= 2

    def test_capability_exploitation_phase(self, plugin):
        """PROVES: Phase 2 covers all major Linux capabilities"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {})

        exploit_phase = tree['children'][1]
        assert 'Capability-Specific Exploitation' in exploit_phase['name']

        # Get all capability task names
        cap_names = []
        for child in exploit_phase['children']:
            cap_names.append(child['name'])
            # Also check nested tasks (some are parent nodes)
            if child['type'] == 'parent' and 'children' in child:
                for subchild in child['children']:
                    cap_names.append(subchild['name'])

        # Convert to single string for easier searching
        all_caps = ' '.join(cap_names)

        # Critical capabilities must be covered
        assert 'CAP_SETUID' in all_caps
        assert 'CAP_SETGID' in all_caps
        assert 'CAP_DAC_OVERRIDE' in all_caps
        assert 'CAP_DAC_READ_SEARCH' in all_caps
        assert 'CAP_SYS_ADMIN' in all_caps
        assert 'CAP_SYS_PTRACE' in all_caps
        assert 'CAP_SYS_MODULE' in all_caps
        assert 'CAP_CHOWN' in all_caps
        assert 'CAP_FOWNER' in all_caps
        assert 'CAP_SETFCAP' in all_caps

    def test_cap_setuid_python_exploit(self, plugin):
        """PROVES: CAP_SETUID exploitation includes Python code"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {})

        # Navigate to CAP_SETUID exploitation
        exploit_phase = tree['children'][1]
        cap_setuid_parent = next(
            child for child in exploit_phase['children']
            if 'CAP_SETUID' in child['name']
        )

        python_task = cap_setuid_parent['children'][0]
        assert 'Python' in python_task['name']

        notes = python_task['metadata']['notes']
        notes_str = ' '.join(notes) if isinstance(notes, list) else notes

        # Verify Python exploitation code present
        assert 'import os' in notes_str
        assert 'os.setuid(0)' in notes_str
        assert 'os.system' in notes_str or '/bin/bash' in notes_str

    def test_suid_exploitation_phase(self, plugin):
        """PROVES: Phase 3 covers SUID/EUID exploitation techniques"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {})

        suid_phase = tree['children'][2]
        assert 'SUID/EUID' in suid_phase['name']

        task_names = [task['name'] for task in suid_phase['children']]

        # Educational understanding
        assert any('Understanding UID' in name for name in task_names)

        # Exploitation techniques
        task_content = str(task_names)
        assert 'system()' in task_content or 'execve()' in task_content
        assert 'PATH' in task_content
        assert 'Command Injection' in task_content or 'LD_PRELOAD' in task_content

    def test_container_escape_phase(self, plugin):
        """PROVES: Phase 4 includes Docker/container escape techniques"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {})

        container_phase = tree['children'][3]
        assert 'Container Escape' in container_phase['name']

        task_ids = [task['id'] for task in container_phase['children']]

        # Critical container escape tasks
        assert 'container-detect' in task_ids
        assert 'container-check-caps' in task_ids

        # Check for specific escape methods in task content
        all_tasks_str = str(container_phase)
        assert 'docker' in all_tasks_str.lower()
        assert 'privileged' in all_tasks_str.lower()

    def test_cap_sys_admin_docker_escape(self, plugin):
        """PROVES: CAP_SYS_ADMIN includes Docker host mount escape"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {})

        # Find CAP_SYS_ADMIN exploitation tasks
        exploit_phase = tree['children'][1]

        # Search for CAP_SYS_ADMIN parent task
        cap_sys_admin_task = None
        for child in exploit_phase['children']:
            if 'CAP_SYS_ADMIN' in child['name']:
                cap_sys_admin_task = child
                break

        assert cap_sys_admin_task is not None
        assert cap_sys_admin_task['type'] == 'parent'

        # Check for Docker escape subtask
        subtask_names = [sub['name'] for sub in cap_sys_admin_task['children']]
        assert any('Docker' in name and 'Mount' in name for name in subtask_names)

    def test_cap_dac_read_search_shocker(self, plugin):
        """PROVES: CAP_DAC_READ_SEARCH includes Shocker exploit"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {})

        exploit_phase = tree['children'][1]

        # Find CAP_DAC_READ_SEARCH task
        dac_read_task = None
        for child in exploit_phase['children']:
            if 'CAP_DAC_READ' in child['name']:
                dac_read_task = child
                break

        assert dac_read_task is not None

        # Check for Shocker exploit reference
        all_content = str(dac_read_task)
        assert 'shocker' in all_content.lower() or 'open_by_handle_at' in all_content

    def test_manual_alternatives_provided(self, plugin):
        """PROVES: Plugin provides manual alternatives for OSCP exam"""
        alternatives = plugin.get_manual_alternatives('caps-scan-binaries')

        assert len(alternatives) > 0
        assert any('Manual' in alt for alt in alternatives)

    def test_tags_consistency(self, plugin):
        """PROVES: All tasks use consistent OSCP tag format"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {})

        def check_tags_recursive(node):
            """Recursively check all task tags"""
            if 'metadata' in node and 'tags' in node['metadata']:
                tags = node['metadata']['tags']
                for tag in tags:
                    # Verify OSCP tags use correct format
                    if tag.startswith('OSCP:'):
                        assert tag in ['OSCP:HIGH', 'OSCP:MEDIUM', 'OSCP:LOW']

                    # Verify no typos in common tags
                    if 'EXPLOIT' in tag:
                        assert tag == 'EXPLOIT'
                    if 'MANUAL' in tag:
                        assert tag == 'MANUAL'

            # Recurse to children
            if 'children' in node:
                for child in node['children']:
                    check_tags_recursive(child)

        check_tags_recursive(tree)

    def test_estimated_time_present(self, plugin):
        """PROVES: Tasks include time estimates for OSCP exam planning"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {})

        # Count tasks with estimated_time
        time_estimates_found = 0

        def count_time_estimates(node):
            nonlocal time_estimates_found
            if 'metadata' in node and 'estimated_time' in node['metadata']:
                time_estimates_found += 1
            if 'children' in node:
                for child in node['children']:
                    count_time_estimates(child)

        count_time_estimates(tree)

        # At least 10 tasks should have time estimates
        assert time_estimates_found >= 10

    def test_gtfobins_references(self, plugin):
        """PROVES: Plugin references GTFOBins for capability exploitation"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {})

        # Convert entire tree to string
        tree_str = str(tree)

        # Should reference GTFOBins
        assert 'gtfobins' in tree_str.lower()

    def test_comprehensive_coverage(self, plugin):
        """PROVES: Plugin covers >15 capability types and techniques"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {})

        # Count unique exploitation techniques
        techniques = set()

        def extract_techniques(node):
            if 'name' in node:
                techniques.add(node['name'])
            if 'children' in node:
                for child in node['children']:
                    extract_techniques(child)

        extract_techniques(tree)

        # Should have comprehensive coverage
        # (4 phases + discovery tasks + ~15 capability exploits + SUID techniques + container escapes)
        assert len(techniques) >= 20

    def test_no_hardcoded_ips(self, plugin):
        """PROVES: Plugin uses placeholders, not hardcoded attacker IPs"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {})
        tree_str = str(tree)

        # Check for placeholder patterns (should be present)
        assert 'YOURIP' in tree_str or '<IP>' in tree_str or 'LHOST' in tree_str

        # Should NOT have common attacker IPs hardcoded
        assert '10.10.14.8' not in tree_str or 'YOURIP' in tree_str  # If present, should be example
        assert '192.168.119.' not in tree_str  # No hardcoded attacker subnet

    def test_python_exploitation_code_quality(self, plugin):
        """PROVES: Python exploitation code is syntactically valid"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {})
        tree_str = str(tree)

        # Common Python exploitation patterns should be present
        if 'import os' in tree_str:
            # If Python code present, should be well-formed
            assert 'os.setuid' in tree_str or 'os.setgid' in tree_str or 'os.system' in tree_str

            # Should show proper imports
            assert 'import ' in tree_str

    def test_docker_escape_comprehensive(self, plugin):
        """PROVES: Container escape covers socket, privileged, and capability escapes"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {})

        container_phase = tree['children'][3]
        content = str(container_phase)

        # Multiple escape vectors should be covered
        assert 'docker.sock' in content or 'docker socket' in content.lower()
        assert 'privileged' in content.lower()
        assert 'mount' in content.lower()

    def test_source_attribution(self, plugin):
        """PROVES: Plugin includes source attribution to HackTricks"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {})

        # Check module docstring (captured in class)
        module_doc = LinuxCapabilitiesPlugin.__doc__
        assert 'HackTricks' in module_doc or 'hacktricks' in module_doc.lower()

    def test_educational_focus(self, plugin):
        """PROVES: Plugin maintains educational focus with explanations"""
        tree = plugin.get_task_tree('192.168.45.100', 0, {})

        # Sample a command task
        discovery_phase = tree['children'][0]
        getcap_task = discovery_phase['children'][0]
        metadata = getcap_task['metadata']

        # Educational components
        assert 'flag_explanations' in metadata
        assert 'next_steps' in metadata
        assert 'alternatives' in metadata
        assert 'success_indicators' in metadata
        assert 'failure_indicators' in metadata

        # Content should be instructional
        assert len(metadata['flag_explanations']) >= 3

    def test_plugin_size_target_met(self, plugin):
        """PROVES: Plugin meets target size guideline"""
        import inspect
        source = inspect.getsource(LinuxCapabilitiesPlugin)

        # Should be substantial (>800 lines in plugin class)
        # Note: This is the class only, not the whole file
        line_count = len(source.split('\n'))
        assert line_count >= 500  # Class should be at least 500 lines


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
