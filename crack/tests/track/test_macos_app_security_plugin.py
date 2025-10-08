"""
Tests for macOS Application Security Analysis Plugin

PROVES: Plugin correctly handles macOS binary analysis, code signing,
        debugging, and fuzzing task generation
"""

import pytest
from crack.track.services.macos_app_security import MacOSAppSecurityPlugin


class TestMacOSAppSecurityPlugin:
    """Test suite for macOS app security analysis plugin"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return MacOSAppSecurityPlugin()

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "macos-app-security"

    def test_plugin_registration(self):
        """PROVES: Plugin is registered in ServiceRegistry"""
        from crack.track.services.registry import ServiceRegistry

        registered_plugins = [p.name for p in ServiceRegistry.get_all_plugins()]
        assert "macos-app-security" in registered_plugins

    def test_detect_macos_service(self, plugin):
        """PROVES: Plugin detects macOS-specific services"""
        test_cases = [
            {'service': 'macos-app', 'port': 0},
            {'service': 'darwin-binary', 'port': 0},
            {'service': 'mach-o', 'port': 0},
            {'product': 'macOS Application', 'port': 0},
            {'product': 'Darwin Binary', 'port': 0},
        ]

        for port_info in test_cases:
            assert plugin.detect(port_info) == True, f"Failed to detect: {port_info}"

    def test_detect_negative(self, plugin):
        """PROVES: Plugin rejects non-macOS services"""
        port_info = {'service': 'http', 'port': 80}
        assert plugin.detect(port_info) == False

    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid structure"""
        service_info = {
            'service': 'macos-app',
            'binary_path': '/Applications/Target.app/Contents/MacOS/Target',
            'app_path': '/Applications/Target.app'
        }

        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        # Root structure
        assert 'id' in tree
        assert tree['id'] == 'macos-app-security'
        assert 'name' in tree
        assert 'type' in tree
        assert tree['type'] == 'parent'
        assert 'children' in tree
        assert len(tree['children']) > 0

    def test_static_analysis_phase(self, plugin):
        """PROVES: Static analysis tasks present"""
        service_info = {
            'binary_path': '/bin/ls',
            'app_path': '/System/Applications/Safari.app'
        }

        tree = plugin.get_task_tree('target', 0, service_info)

        # Find static analysis phase
        static_phase = None
        for child in tree['children']:
            if child['id'] == 'static-analysis':
                static_phase = child
                break

        assert static_phase is not None, "Static analysis phase not found"
        assert static_phase['type'] == 'parent'
        assert len(static_phase['children']) > 0

        # Verify key tasks
        task_ids = [t['id'] for t in static_phase['children']]
        assert 'otool-basic-info' in task_ids
        assert 'otool-disassemble' in task_ids
        assert 'nm-symbols' in task_ids
        assert 'jtool2-analysis' in task_ids

    def test_code_signing_phase(self, plugin):
        """PROVES: Code signing analysis tasks present"""
        service_info = {'binary_path': '/bin/ls'}
        tree = plugin.get_task_tree('target', 0, service_info)

        # Find code signing phase
        code_signing_phase = None
        for child in tree['children']:
            if child['id'] == 'code-signing':
                code_signing_phase = child
                break

        assert code_signing_phase is not None

        task_ids = [t['id'] for t in code_signing_phase['children']]
        assert 'codesign-verify' in task_ids
        assert 'codesign-entitlements' in task_ids
        assert 'spctl-assess' in task_ids

    def test_objc_swift_analysis_phase(self, plugin):
        """PROVES: Objective-C and Swift analysis tasks present"""
        service_info = {'binary_path': '/Applications/Test.app/Contents/MacOS/Test'}
        tree = plugin.get_task_tree('target', 0, service_info)

        objc_phase = None
        for child in tree['children']:
            if child['id'] == 'objc-swift-analysis':
                objc_phase = child
                break

        assert objc_phase is not None

        task_ids = [t['id'] for t in objc_phase['children']]
        assert 'dynadump' in task_ids
        assert 'swift-metadata' in task_ids
        assert 'swift-demangle' in task_ids

    def test_dynamic_analysis_phase(self, plugin):
        """PROVES: Dynamic analysis and debugging tasks present"""
        service_info = {'binary_path': '/tmp/malware'}
        tree = plugin.get_task_tree('target', 0, service_info)

        dynamic_phase = None
        for child in tree['children']:
            if child['id'] == 'dynamic-analysis':
                dynamic_phase = child
                break

        assert dynamic_phase is not None

        task_ids = [t['id'] for t in dynamic_phase['children']]
        assert 'lldb-basic' in task_ids
        assert 'lldb-commands' in task_ids
        assert 'lldb-objc-breakpoint' in task_ids
        assert 'bypass-pt-deny-attach' in task_ids
        assert 'dtrace-syscalls' in task_ids
        assert 'fs-usage' in task_ids

    def test_fuzzing_phase(self, plugin):
        """PROVES: Fuzzing tasks present"""
        service_info = {'binary_path': '/usr/bin/target'}
        tree = plugin.get_task_tree('target', 0, service_info)

        fuzzing_phase = None
        for child in tree['children']:
            if child['id'] == 'fuzzing':
                fuzzing_phase = child
                break

        assert fuzzing_phase is not None

        task_ids = [t['id'] for t in fuzzing_phase['children']]
        assert 'fuzzing-setup' in task_ids
        assert 'afl-fuzzing' in task_ids
        assert 'litefuzz-gui' in task_ids
        assert 'libgmalloc-testing' in task_ids

    def test_anti_analysis_phase(self, plugin):
        """PROVES: Anti-analysis detection tasks present"""
        service_info = {'binary_path': '/tmp/suspicious'}
        tree = plugin.get_task_tree('target', 0, service_info)

        anti_analysis_phase = None
        for child in tree['children']:
            if child['id'] == 'anti-analysis':
                anti_analysis_phase = child
                break

        assert anti_analysis_phase is not None

        task_ids = [t['id'] for t in anti_analysis_phase['children']]
        assert 'vm-detection' in task_ids
        assert 'debug-detection' in task_ids

    def test_oscp_metadata_completeness(self, plugin):
        """PROVES: Tasks include comprehensive OSCP metadata"""
        service_info = {'binary_path': '/bin/test'}
        tree = plugin.get_task_tree('target', 0, service_info)

        # Get all command tasks
        def get_all_command_tasks(node, tasks=[]):
            if node.get('type') == 'command':
                tasks.append(node)
            for child in node.get('children', []):
                get_all_command_tasks(child, tasks)
            return tasks

        command_tasks = get_all_command_tasks(tree, [])

        assert len(command_tasks) > 0, "No command tasks found"

        # Check first command task
        task = command_tasks[0]
        metadata = task.get('metadata', {})

        # Required fields
        assert 'command' in metadata, "Command missing"
        assert 'description' in metadata, "Description missing"
        assert 'tags' in metadata, "Tags missing"
        assert 'flag_explanations' in metadata, "Flag explanations missing"
        assert 'success_indicators' in metadata, "Success indicators missing"
        assert 'failure_indicators' in metadata, "Failure indicators missing"
        assert 'next_steps' in metadata, "Next steps missing"
        assert 'alternatives' in metadata, "Alternatives missing"

    def test_flag_explanations_present(self, plugin):
        """PROVES: All command tasks have flag explanations"""
        service_info = {'binary_path': '/bin/ls'}
        tree = plugin.get_task_tree('target', 0, service_info)

        def check_command_tasks(node):
            if node.get('type') == 'command':
                metadata = node.get('metadata', {})
                assert 'flag_explanations' in metadata
                assert len(metadata['flag_explanations']) > 0

            for child in node.get('children', []):
                check_command_tasks(child)

        check_command_tasks(tree)

    def test_alternatives_for_manual_execution(self, plugin):
        """PROVES: Tasks provide manual alternatives for OSCP"""
        service_info = {'binary_path': '/usr/bin/test'}
        tree = plugin.get_task_tree('target', 0, service_info)

        def check_alternatives(node):
            if node.get('type') == 'command':
                metadata = node.get('metadata', {})
                assert 'alternatives' in metadata
                assert len(metadata['alternatives']) > 0

            for child in node.get('children', []):
                check_alternatives(child)

        check_alternatives(tree)

    def test_task_has_oscp_tags(self, plugin):
        """PROVES: Tasks tagged for OSCP relevance"""
        service_info = {'binary_path': '/Applications/Test.app'}
        tree = plugin.get_task_tree('target', 0, service_info)

        def find_oscp_tags(node, found_tags=set()):
            metadata = node.get('metadata', {})
            tags = metadata.get('tags', [])
            for tag in tags:
                if 'OSCP:' in tag:
                    found_tags.add(tag)

            for child in node.get('children', []):
                find_oscp_tags(child, found_tags)

            return found_tags

        oscp_tags = find_oscp_tags(tree)

        # Should have OSCP priority tags
        assert 'OSCP:HIGH' in oscp_tags or 'OSCP:MEDIUM' in oscp_tags

    def test_success_failure_indicators(self, plugin):
        """PROVES: Tasks include success/failure indicators"""
        service_info = {'binary_path': '/bin/test'}
        tree = plugin.get_task_tree('target', 0, service_info)

        def check_indicators(node):
            if node.get('type') in ['command', 'manual']:
                metadata = node.get('metadata', {})

                if 'success_indicators' in metadata:
                    assert len(metadata['success_indicators']) >= 1

                if 'failure_indicators' in metadata:
                    assert len(metadata['failure_indicators']) >= 1

            for child in node.get('children', []):
                check_indicators(child)

        check_indicators(tree)

    def test_next_steps_guidance(self, plugin):
        """PROVES: Tasks provide next steps for attack progression"""
        service_info = {'binary_path': '/usr/local/bin/vuln'}
        tree = plugin.get_task_tree('target', 0, service_info)

        def check_next_steps(node):
            if node.get('type') in ['command', 'manual']:
                metadata = node.get('metadata', {})

                if 'next_steps' in metadata:
                    assert len(metadata['next_steps']) >= 1

            for child in node.get('children', []):
                check_next_steps(child)

        check_next_steps(tree)

    def test_tool_installation_notes(self, plugin):
        """PROVES: Tasks include tool installation guidance"""
        service_info = {'binary_path': '/tmp/target'}
        tree = plugin.get_task_tree('target', 0, service_info)

        # Check that specialized tools have installation notes
        def find_tool_notes(node, notes_found=[]):
            metadata = node.get('metadata', {})
            notes = metadata.get('notes', '')

            if 'Install:' in notes or 'Download:' in notes or 'brew install' in notes:
                notes_found.append(notes)

            for child in node.get('children', []):
                find_tool_notes(child, notes_found)

            return notes_found

        tool_notes = find_tool_notes(tree)

        assert len(tool_notes) > 0, "No tool installation notes found"

    def test_comprehensive_coverage(self, plugin):
        """PROVES: Plugin covers all major macOS app security areas"""
        service_info = {'binary_path': '/Applications/Target.app/Contents/MacOS/Target'}
        tree = plugin.get_task_tree('target', 0, service_info)

        phase_ids = [child['id'] for child in tree['children']]

        # Verify all major phases present
        required_phases = [
            'static-analysis',
            'code-signing',
            'objc-swift-analysis',
            'dynamic-analysis',
            'fuzzing',
            'anti-analysis',
            'advanced-tools',
            'exploit-development'
        ]

        for phase in required_phases:
            assert phase in phase_ids, f"Missing phase: {phase}"

    def test_binary_path_substitution(self, plugin):
        """PROVES: Binary paths correctly substituted in commands"""
        test_binary = '/custom/path/to/binary'
        service_info = {'binary_path': test_binary}

        tree = plugin.get_task_tree('target', 0, service_info)

        # Find a command task and check substitution
        def find_command_with_binary(node):
            if node.get('type') == 'command':
                metadata = node.get('metadata', {})
                command = metadata.get('command', '')
                if test_binary in command:
                    return True

            for child in node.get('children', []):
                if find_command_with_binary(child):
                    return True

            return False

        assert find_command_with_binary(tree), "Binary path not substituted in commands"

    def test_educational_value(self, plugin):
        """PROVES: Plugin provides educational content for learning"""
        service_info = {'binary_path': '/bin/test'}
        tree = plugin.get_task_tree('target', 0, service_info)

        # Count tasks with comprehensive metadata
        def count_educational_tasks(node, count=0):
            metadata = node.get('metadata', {})

            # Task is educational if it has multiple learning components
            has_explanations = 'flag_explanations' in metadata
            has_alternatives = 'alternatives' in metadata
            has_next_steps = 'next_steps' in metadata
            has_notes = 'notes' in metadata

            if sum([has_explanations, has_alternatives, has_next_steps, has_notes]) >= 3:
                count += 1

            for child in node.get('children', []):
                count = count_educational_tasks(child, count)

            return count

        educational_count = count_educational_tasks(tree)

        # Should have many educational tasks
        assert educational_count > 20, f"Only {educational_count} educational tasks found"
