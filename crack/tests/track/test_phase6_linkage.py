"""
Phase 6 Tests: Task Tree Linkage for Alternative Commands

Tests for Phase 6.1 (TaskNode metadata enhancement) and Phase 6.2 (Service plugin integration).
Validates backward compatibility and alternative command linkage.
"""

import pytest
from crack.track.core.task_tree import TaskNode
from crack.track.core.state import TargetProfile
from crack.track.parsers.registry import ParserRegistry
from crack.track.alternatives.registry import AlternativeCommandRegistry


class TestPhase61TaskNodeMetadata:
    """Phase 6.1: TaskNode Metadata Enhancement"""

    def test_tasknode_has_alternative_fields(self):
        """
        PROVES: TaskNode includes alternative_ids and alternative_context fields

        Required for Phase 6.1 completion.
        """
        task = TaskNode(
            task_id='test-task',
            name='Test Task'
        )

        # Verify new fields exist in metadata
        assert 'alternative_ids' in task.metadata
        assert 'alternative_context' in task.metadata

        # Verify types
        assert isinstance(task.metadata['alternative_ids'], list)
        assert isinstance(task.metadata['alternative_context'], dict)

        # Verify initial values
        assert task.metadata['alternative_ids'] == []
        assert task.metadata['alternative_context'] == {}

    def test_tasknode_backward_compatibility(self):
        """
        PROVES: Old alternatives field still exists for backward compatibility

        Existing code may rely on 'alternatives' field - must not break.
        """
        task = TaskNode(
            task_id='legacy-task',
            name='Legacy Task'
        )

        # Old field must still exist
        assert 'alternatives' in task.metadata
        assert isinstance(task.metadata['alternatives'], list)

    def test_tasknode_serialization_includes_new_fields(self):
        """
        PROVES: New alternative fields serialize to JSON correctly

        Profile persistence requires proper serialization.
        """
        task = TaskNode(
            task_id='task-1',
            name='Task 1'
        )

        # Add alternative data
        task.metadata['alternative_ids'] = ['alt-cmd-1', 'alt-cmd-2']
        task.metadata['alternative_context'] = {
            'service': 'http',
            'port': 80,
            'purpose': 'web-enumeration'
        }

        # Serialize
        task_dict = task.to_dict()

        # Verify serialization
        assert 'alternative_ids' in task_dict['metadata']
        assert task_dict['metadata']['alternative_ids'] == ['alt-cmd-1', 'alt-cmd-2']
        assert 'alternative_context' in task_dict['metadata']
        assert task_dict['metadata']['alternative_context']['service'] == 'http'

    def test_tasknode_deserialization_handles_new_fields(self):
        """
        PROVES: New fields deserialize from JSON correctly

        Loading saved profiles with alternative linkage works.
        """
        task_data = {
            'id': 'task-1',
            'name': 'Task 1',
            'type': 'command',
            'status': 'pending',
            'metadata': {
                'command': 'echo test',
                'alternative_ids': ['alt-1', 'alt-2'],
                'alternative_context': {
                    'service': 'http',
                    'port': 80
                },
                'tags': [],
                'depends_on': [],
                'notes': [],
                'created_at': '2025-10-09T12:00:00',
                'completed_at': None
            },
            'children': []
        }

        # Deserialize
        task = TaskNode.from_dict(task_data)

        # Verify fields loaded correctly
        assert task.metadata['alternative_ids'] == ['alt-1', 'alt-2']
        assert task.metadata['alternative_context']['service'] == 'http'
        assert task.metadata['alternative_context']['port'] == 80

    def test_tasknode_deserialization_handles_missing_fields(self):
        """
        PROVES: Deserialization handles old profiles without new fields (backward compat)

        Old profiles don't have alternative_ids/alternative_context - must not crash.
        """
        # Old profile data WITHOUT new fields
        old_task_data = {
            'id': 'old-task',
            'name': 'Old Task',
            'type': 'command',
            'status': 'pending',
            'metadata': {
                'command': 'echo old',
                'tags': [],
                'depends_on': [],
                'notes': [],
                'created_at': '2025-01-01T00:00:00',
                'completed_at': None
                # NOTE: No alternative_ids or alternative_context
            },
            'children': []
        }

        # Deserialize (should not crash)
        task = TaskNode.from_dict(old_task_data)

        # Verify task loaded
        assert task.id == 'old-task'
        assert task.name == 'Old Task'

        # New fields should have defaults (empty list/dict)
        # They get added by __init__ even if not in serialized data
        assert 'alternative_ids' in task.metadata
        assert 'alternative_context' in task.metadata


class TestPhase62ServicePluginIntegration:
    """Phase 6.2: Service Plugin Integration (HTTP Plugin)"""

    def test_http_plugin_links_alternatives_to_whatweb(self, temp_crack_home, typical_oscp_nmap_xml):
        """
        PROVES: HTTP plugin links alternatives to whatweb task

        whatweb task should have alt-http-headers-inspect linked.
        """
        # Initialize registries
        ParserRegistry.initialize_parsers()
        AlternativeCommandRegistry.load_all()

        # Create profile and import scan
        profile = TargetProfile("192.168.45.100")
        ParserRegistry.parse_file(typical_oscp_nmap_xml, "192.168.45.100", profile)

        # Find whatweb task
        whatweb_task = profile.task_tree.find_task('whatweb-80')
        assert whatweb_task is not None, "whatweb task should exist"

        # Verify alternative_ids linked
        assert 'alternative_ids' in whatweb_task.metadata
        assert 'alt-http-headers-inspect' in whatweb_task.metadata['alternative_ids']

    def test_http_plugin_links_alternatives_to_gobuster(self, temp_crack_home, typical_oscp_nmap_xml):
        """
        PROVES: HTTP plugin links alternatives to gobuster task

        gobuster task should have directory enumeration alternatives linked.
        """
        # Initialize registries
        ParserRegistry.initialize_parsers()
        AlternativeCommandRegistry.load_all()

        # Create profile and import scan
        profile = TargetProfile("192.168.45.100")
        ParserRegistry.parse_file(typical_oscp_nmap_xml, "192.168.45.100", profile)

        # Find gobuster task
        gobuster_task = profile.task_tree.find_task('gobuster-80')
        assert gobuster_task is not None, "gobuster task should exist"

        # Verify alternative_ids linked
        assert 'alternative_ids' in gobuster_task.metadata
        assert 'alt-manual-dir-check' in gobuster_task.metadata['alternative_ids']
        assert 'alt-robots-check' in gobuster_task.metadata['alternative_ids']

    def test_http_plugin_links_alternatives_to_http_methods(self, temp_crack_home, typical_oscp_nmap_xml):
        """
        PROVES: HTTP plugin links alternatives to http-methods task

        http-methods task should have manual method testing alternatives.
        """
        # Initialize registries
        ParserRegistry.initialize_parsers()
        AlternativeCommandRegistry.load_all()

        # Create profile and import scan
        profile = TargetProfile("192.168.45.100")
        ParserRegistry.parse_file(typical_oscp_nmap_xml, "192.168.45.100", profile)

        # Find http-methods task
        methods_task = profile.task_tree.find_task('http-methods-80')
        assert methods_task is not None, "http-methods task should exist"

        # Verify alternative_ids linked
        assert 'alternative_ids' in methods_task.metadata
        assert 'alt-http-methods-manual' in methods_task.metadata['alternative_ids']
        assert 'alt-http-trace-xst' in methods_task.metadata['alternative_ids']

    def test_http_plugin_adds_alternative_context(self, temp_crack_home, typical_oscp_nmap_xml):
        """
        PROVES: HTTP plugin adds alternative_context with service, port, purpose

        Context enables smart variable resolution (TARGET, PORT auto-fill).
        """
        # Initialize registries
        ParserRegistry.initialize_parsers()
        AlternativeCommandRegistry.load_all()

        # Create profile and import scan
        profile = TargetProfile("192.168.45.100")
        ParserRegistry.parse_file(typical_oscp_nmap_xml, "192.168.45.100", profile)

        # Find gobuster task
        gobuster_task = profile.task_tree.find_task('gobuster-80')
        assert gobuster_task is not None

        # Verify alternative_context
        context = gobuster_task.metadata.get('alternative_context', {})
        assert context.get('service') == 'http'
        assert context.get('port') == 80
        assert context.get('purpose') == 'web-enumeration'

    def test_http_plugin_multiple_ports_link_independently(self, temp_crack_home, web_heavy_nmap_xml):
        """
        PROVES: HTTP plugin links alternatives independently for each port

        Multiple HTTP ports (80, 443, 8080, 8443) each get their own alternative linkage.
        """
        # Initialize registries
        ParserRegistry.initialize_parsers()
        AlternativeCommandRegistry.load_all()

        # Create profile with multiple HTTP ports
        profile = TargetProfile("192.168.45.101")
        ParserRegistry.parse_file(web_heavy_nmap_xml, "192.168.45.101", profile)

        # Check each HTTP port has alternatives linked
        for port in [80, 443, 8080, 8443]:
            gobuster_task = profile.task_tree.find_task(f'gobuster-{port}')
            assert gobuster_task is not None, f"gobuster-{port} should exist"

            # Each should have alternatives
            assert 'alternative_ids' in gobuster_task.metadata
            assert len(gobuster_task.metadata['alternative_ids']) > 0

            # Each should have correct port in context
            context = gobuster_task.metadata.get('alternative_context', {})
            assert context.get('port') == port

    def test_old_alternatives_field_preserved(self, temp_crack_home, typical_oscp_nmap_xml):
        """
        PROVES: Old 'alternatives' field still exists alongside new alternative_ids

        Backward compatibility - existing code relying on 'alternatives' must not break.
        """
        # Initialize registries
        ParserRegistry.initialize_parsers()
        AlternativeCommandRegistry.load_all()

        # Create profile and import scan
        profile = TargetProfile("192.168.45.100")
        ParserRegistry.parse_file(typical_oscp_nmap_xml, "192.168.45.100", profile)

        # Find gobuster task
        gobuster_task = profile.task_tree.find_task('gobuster-80')
        assert gobuster_task is not None

        # Verify BOTH fields exist
        assert 'alternatives' in gobuster_task.metadata, "Old field must exist"
        assert 'alternative_ids' in gobuster_task.metadata, "New field must exist"

        # Old field should still have old-style alternatives
        assert len(gobuster_task.metadata['alternatives']) > 0


class TestPhase6RegistryAutoLinking:
    """Test AlternativeCommandRegistry.auto_link_to_task() method"""

    def test_auto_link_by_task_id_pattern(self):
        """
        PROVES: Registry can auto-link alternatives based on task ID pattern

        http-methods-80 should match http-* pattern alternatives.
        """
        # Initialize registry
        AlternativeCommandRegistry.load_all()

        # Create mock task with ID that matches http-* pattern
        task = TaskNode(
            task_id='http-methods-80',
            name='HTTP Methods Enumeration'
        )

        # Auto-link
        alt_ids = AlternativeCommandRegistry.auto_link_to_task(task)

        # Verify alternatives linked
        assert len(alt_ids) > 0
        # Should include HTTP method testing alternatives
        assert 'alt-http-methods-manual' in alt_ids or 'alt-http-trace-xst' in alt_ids

    def test_auto_link_by_service_metadata(self):
        """
        PROVES: Registry can auto-link alternatives based on service in metadata

        Task with service='http' should get HTTP alternatives.
        """
        # Initialize registry
        AlternativeCommandRegistry.load_all()

        # Create mock task with service metadata
        task = TaskNode(
            task_id='custom-http-task',
            name='Custom HTTP Task'
        )
        task.metadata['service'] = 'http'

        # Auto-link
        alt_ids = AlternativeCommandRegistry.auto_link_to_task(task)

        # Should have HTTP alternatives (even though task ID doesn't match patterns)
        assert len(alt_ids) > 0

    def test_auto_link_by_tags(self):
        """
        PROVES: Registry can auto-link alternatives based on task tags

        Task with OSCP:HIGH tag should get OSCP:HIGH alternatives.
        """
        # Initialize registry
        AlternativeCommandRegistry.load_all()

        # Create mock task with tags
        task = TaskNode(
            task_id='test-task',
            name='Test Task'
        )
        task.metadata['tags'] = ['OSCP:HIGH', 'QUICK_WIN']

        # Auto-link
        alt_ids = AlternativeCommandRegistry.auto_link_to_task(task)

        # Should have alternatives matching tags
        assert len(alt_ids) > 0

    def test_auto_link_deduplicates_results(self):
        """
        PROVES: Registry deduplicates alternatives from multiple match sources

        If alternative matches by BOTH pattern AND service, it should only appear once.
        """
        # Initialize registry
        AlternativeCommandRegistry.load_all()

        # Create task that matches multiple ways
        task = TaskNode(
            task_id='http-methods-80',
            name='HTTP Methods'
        )
        task.metadata['service'] = 'http'
        task.metadata['tags'] = ['OSCP:HIGH']

        # Auto-link
        alt_ids = AlternativeCommandRegistry.auto_link_to_task(task)

        # Check for duplicates
        assert len(alt_ids) == len(set(alt_ids)), "Should have no duplicates"


class TestPhase6BackwardCompatibility:
    """Comprehensive backward compatibility tests"""

    def test_old_profile_without_alternatives_loads(self, temp_crack_home):
        """
        PROVES: Old profiles without alternative fields load successfully

        Critical for production - existing users must not lose data.
        """
        # Create old-style profile manually
        profile = TargetProfile("192.168.45.100")

        # Add old-style task WITHOUT new fields
        old_task = TaskNode(
            task_id='old-gobuster',
            name='Old Gobuster Task'
        )
        # Remove new fields to simulate old profile
        del old_task.metadata['alternative_ids']
        del old_task.metadata['alternative_context']

        profile.task_tree.add_child(old_task)
        profile.save()

        # Load profile (should not crash)
        loaded_profile = TargetProfile.load("192.168.45.100")

        # Verify profile loaded
        assert loaded_profile.target == "192.168.45.100"

        # Find old task
        loaded_task = loaded_profile.task_tree.find_task('old-gobuster')
        assert loaded_task is not None

    def test_service_plugins_still_work_without_alternatives_module(self, temp_crack_home, typical_oscp_nmap_xml):
        """
        PROVES: Service plugins work even if alternatives module fails to load

        Alternatives are optional enhancement - core functionality must not break.
        """
        # Initialize only parsers (not alternatives)
        ParserRegistry.initialize_parsers()
        # Don't load AlternativeCommandRegistry

        # Create profile and import scan (should work without alternatives)
        profile = TargetProfile("192.168.45.100")

        # Should not crash even without alternatives loaded
        ParserRegistry.parse_file(typical_oscp_nmap_xml, "192.168.45.100", profile)

        # Verify tasks created
        assert len(profile.ports) > 0
        assert profile.task_tree.find_task('gobuster-80') is not None

    def test_profile_save_load_roundtrip_preserves_alternatives(self, temp_crack_home, typical_oscp_nmap_xml):
        """
        PROVES: Saving and loading profile preserves alternative linkage

        Alternative IDs must persist across save/load cycles.
        """
        # Initialize registries
        ParserRegistry.initialize_parsers()
        AlternativeCommandRegistry.load_all()

        # Create profile with alternatives
        profile = TargetProfile("192.168.45.100")
        ParserRegistry.parse_file(typical_oscp_nmap_xml, "192.168.45.100", profile)

        # Get original alternative IDs
        gobuster_task = profile.task_tree.find_task('gobuster-80')
        original_alt_ids = gobuster_task.metadata['alternative_ids'].copy()
        original_context = gobuster_task.metadata['alternative_context'].copy()

        # Save and reload
        profile.save()
        loaded_profile = TargetProfile.load("192.168.45.100")

        # Verify alternatives preserved
        loaded_task = loaded_profile.task_tree.find_task('gobuster-80')
        assert loaded_task.metadata['alternative_ids'] == original_alt_ids
        assert loaded_task.metadata['alternative_context'] == original_context
