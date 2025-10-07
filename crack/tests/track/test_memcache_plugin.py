"""
Tests for Memcache service plugin

PROVES:
- Plugin detects Memcache services
- Task tree includes version-specific enumeration (pre/post 1.4.31)
- Manual and automated techniques are covered
- OSCP educational content is comprehensive
"""

import pytest
from crack.track.services.memcache import MemcachePlugin


class TestMemcachePlugin:
    """Test suite for Memcache plugin"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return MemcachePlugin()

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "memcache"

    def test_default_ports(self, plugin):
        """PROVES: Plugin knows default Memcache port"""
        assert 11211 in plugin.default_ports

    def test_service_names(self, plugin):
        """PROVES: Plugin recognizes Memcache service name variations"""
        assert 'memcache' in plugin.service_names
        assert 'memcached' in plugin.service_names

    def test_detect_by_service_name(self, plugin):
        """PROVES: Plugin detects Memcache by service name"""
        port_info = {'service': 'memcache', 'port': 11211}
        assert plugin.detect(port_info) == True

    def test_detect_by_port(self, plugin):
        """PROVES: Plugin detects Memcache by port number"""
        port_info = {'service': 'unknown', 'port': 11211}
        assert plugin.detect(port_info) == True

    def test_detect_negative(self, plugin):
        """PROVES: Plugin rejects unrelated services"""
        port_info = {'service': 'http', 'port': 80}
        assert plugin.detect(port_info) == False

    def test_task_tree_structure(self, plugin):
        """PROVES: Task tree has valid structure"""
        tree = plugin.get_task_tree('192.168.45.100', 11211, {'service': 'memcache'})

        # Root structure
        assert 'id' in tree
        assert tree['id'] == 'memcache-enum-11211'
        assert 'name' in tree
        assert 'Memcache' in tree['name']
        assert tree['type'] == 'parent'
        assert 'children' in tree

        # Has tasks
        assert len(tree['children']) >= 5  # Should have multiple enumeration tasks

    def test_version_detection_task(self, plugin):
        """PROVES: Plugin includes version detection (critical for technique selection)"""
        tree = plugin.get_task_tree('192.168.45.100', 11211, {'service': 'memcache'})

        version_tasks = [t for t in tree['children'] if 'version' in t['id'].lower()]
        assert len(version_tasks) > 0

        task = version_tasks[0]
        metadata = task.get('metadata', {})

        # Should use netcat for manual version check
        assert 'nc' in metadata.get('command', '').lower()
        assert 'version' in metadata.get('command', '').lower()

        # Should be tagged as QUICK_WIN
        assert 'QUICK_WIN' in metadata.get('tags', [])

    def test_statistics_gathering_task(self, plugin):
        """PROVES: Plugin includes stats command"""
        tree = plugin.get_task_tree('192.168.45.100', 11211, {'service': 'memcache'})

        stats_tasks = [t for t in tree['children'] if 'stats' in t['id'].lower() and 'version' not in t['id'].lower()]
        assert len(stats_tasks) > 0

        task = stats_tasks[0]
        metadata = task.get('metadata', {})

        # Should use echo + nc pattern
        assert 'stats' in metadata.get('command', '').lower()
        assert 'nc' in metadata.get('command', '').lower()

    def test_slab_enumeration_task(self, plugin):
        """PROVES: Plugin includes slab enumeration"""
        tree = plugin.get_task_tree('192.168.45.100', 11211, {'service': 'memcache'})

        slab_tasks = []
        def find_slabs(node):
            if 'slab' in node.get('id', '').lower():
                slab_tasks.append(node)
            for child in node.get('children', []):
                find_slabs(child)

        find_slabs(tree)

        assert len(slab_tasks) > 0
        task = slab_tasks[0]
        metadata = task.get('metadata', {})

        # Should explain slab concept
        assert 'slab' in metadata.get('description', '').lower()
        assert 'chunk' in metadata.get('notes', '').lower() or 'chunk' in metadata.get('description', '').lower()

    def test_version_specific_key_dumping(self, plugin):
        """PROVES: Plugin includes both old (<1.4.31) and new (>=1.4.31) key dumping methods"""
        tree = plugin.get_task_tree('192.168.45.100', 11211, {'service': 'memcache'})

        # Find key dumping task container
        key_dump_tasks = []
        def find_key_dump(node):
            if 'key' in node.get('id', '').lower() and node.get('type') == 'parent':
                key_dump_tasks.extend(node.get('children', []))
            for child in node.get('children', []):
                find_key_dump(child)

        find_key_dump(tree)

        assert len(key_dump_tasks) >= 2  # Should have at least old and new methods

        # Check for cachedump (old method)
        cachedump_tasks = [t for t in key_dump_tasks if 'cachedump' in t.get('id', '').lower()]
        assert len(cachedump_tasks) > 0

        cachedump_task = cachedump_tasks[0]
        assert 'stats cachedump' in cachedump_task.get('metadata', {}).get('command', '')
        assert '1.4.31' in cachedump_task.get('metadata', {}).get('description', '')

        # Check for metadump (new method)
        metadump_tasks = [t for t in key_dump_tasks if 'metadump' in t.get('id', '').lower()]
        assert len(metadump_tasks) > 0

        metadump_task = metadump_tasks[0]
        assert 'lru_crawler metadump' in metadump_task.get('metadata', {}).get('command', '')

    def test_automated_tools_included(self, plugin):
        """PROVES: Plugin includes automated extraction tools"""
        tree = plugin.get_task_tree('192.168.45.100', 11211, {'service': 'memcache'})

        # Find automated tool tasks
        tool_tasks = []
        def find_tools(node):
            metadata = node.get('metadata', {})
            command = metadata.get('command', '').lower()
            if 'memcdump' in command or 'metasploit' in command or 'msf' in command:
                tool_tasks.append(node)
            for child in node.get('children', []):
                find_tools(child)

        find_tools(tree)

        assert len(tool_tasks) >= 2  # Should have libmemcached and metasploit

        # Check for libmemcached-tools
        libmem_tasks = [t for t in tool_tasks if 'memcdump' in t.get('metadata', {}).get('command', '').lower()]
        assert len(libmem_tasks) > 0

        # Check for metasploit
        msf_tasks = [t for t in tool_tasks if 'msf' in t.get('metadata', {}).get('command', '').lower()]
        assert len(msf_tasks) > 0

    def test_value_retrieval_task(self, plugin):
        """PROVES: Plugin includes task for retrieving cached values"""
        tree = plugin.get_task_tree('192.168.45.100', 11211, {'service': 'memcache'})

        get_tasks = []
        def find_get(node):
            if 'get' in node.get('id', '').lower() and 'value' in node.get('id', '').lower():
                get_tasks.append(node)
            for child in node.get('children', []):
                find_get(child)

        find_get(tree)

        assert len(get_tasks) > 0
        task = get_tasks[0]
        metadata = task.get('metadata', {})

        # Should use "get" command
        assert 'get' in metadata.get('command', '').lower()
        assert '<KEY_NAME>' in metadata.get('command', '') or 'key' in metadata.get('command', '').lower()

    def test_educational_notes_task(self, plugin):
        """PROVES: Plugin includes comprehensive educational notes"""
        tree = plugin.get_task_tree('192.168.45.100', 11211, {'service': 'memcache'})

        # Find notes/educational task
        notes_tasks = []
        def find_notes(node):
            if 'notes' in node.get('id', '').lower() or node.get('type') == 'manual':
                if len(node.get('metadata', {}).get('notes', '')) > 500:  # Substantial notes
                    notes_tasks.append(node)
            for child in node.get('children', []):
                find_notes(child)

        find_notes(tree)

        assert len(notes_tasks) > 0
        task = notes_tasks[0]
        notes = task.get('metadata', {}).get('notes', '')

        # Should cover key concepts
        assert 'oscp' in notes.lower()
        assert 'session' in notes.lower() or 'cache' in notes.lower()
        assert 'manual' in notes.lower()

    def test_oscp_metadata_completeness(self, plugin):
        """PROVES: Command tasks include OSCP-required metadata"""
        tree = plugin.get_task_tree('192.168.45.100', 11211, {'service': 'memcache'})

        # Collect all command tasks
        command_tasks = []
        def collect_commands(node):
            if node.get('type') == 'command':
                command_tasks.append(node)
            for child in node.get('children', []):
                collect_commands(child)

        collect_commands(tree)

        assert len(command_tasks) >= 5

        # Check multiple command tasks
        for task in command_tasks[:5]:  # Check first 5
            metadata = task.get('metadata', {})

            # Required fields
            assert 'command' in metadata
            assert 'description' in metadata
            assert 'flag_explanations' in metadata
            assert len(metadata['flag_explanations']) > 0

            # Educational fields
            assert 'success_indicators' in metadata
            assert 'failure_indicators' in metadata
            assert 'next_steps' in metadata
            assert 'alternatives' in metadata

            # Tags
            assert 'tags' in metadata
            assert len(metadata['tags']) > 0

    def test_manual_method_priority(self, plugin):
        """PROVES: Manual methods are prioritized (nc/telnet before automated tools)"""
        tree = plugin.get_task_tree('192.168.45.100', 11211, {'service': 'memcache'})

        # Check first few tasks
        first_tasks = tree['children'][:5]

        manual_count = 0
        for task in first_tasks:
            metadata = task.get('metadata', {})
            command = metadata.get('command', '').lower()
            tags = metadata.get('tags', [])

            if 'nc' in command or 'telnet' in command or 'MANUAL' in tags:
                manual_count += 1

        # Majority of early tasks should be manual
        assert manual_count >= 3, "Manual methods should be prioritized in task order"

    def test_flag_explanations_quality(self, plugin):
        """PROVES: Flag explanations are detailed and educational"""
        tree = plugin.get_task_tree('192.168.45.100', 11211, {'service': 'memcache'})

        # Find version detection task (should have excellent flag explanations)
        version_task = [t for t in tree['children'] if 'version' in t['id'].lower()][0]
        flag_exp = version_task['metadata']['flag_explanations']

        # Should explain each flag
        assert len(flag_exp) >= 3
        assert 'nc' in flag_exp or 'echo' in flag_exp

        # Explanations should be substantive (not just flag name)
        for flag, explanation in flag_exp.items():
            assert len(explanation) > 10, f"Flag {flag} explanation too brief: {explanation}"

    def test_time_estimates_present(self, plugin):
        """PROVES: Tasks include time estimates for OSCP exam planning"""
        tree = plugin.get_task_tree('192.168.45.100', 11211, {'service': 'memcache'})

        tasks_with_time = []
        def find_time_estimates(node):
            metadata = node.get('metadata', {})
            if 'estimated_time' in metadata:
                tasks_with_time.append(node)
            for child in node.get('children', []):
                find_time_estimates(child)

        find_time_estimates(tree)

        # At least some tasks should have time estimates
        assert len(tasks_with_time) >= 2

    def test_no_authentication_mentioned(self, plugin):
        """PROVES: Plugin mentions Memcache lacks authentication (key vulnerability)"""
        tree = plugin.get_task_tree('192.168.45.100', 11211, {'service': 'memcache'})

        # Collect all notes and descriptions
        all_text = []
        def collect_text(node):
            metadata = node.get('metadata', {})
            all_text.append(metadata.get('notes', ''))
            all_text.append(metadata.get('description', ''))
            for child in node.get('children', []):
                collect_text(child)

        collect_text(tree)

        combined_text = ' '.join(all_text).lower()

        # Should mention lack of auth or SASL
        assert 'no auth' in combined_text or 'without auth' in combined_text or 'sasl' in combined_text

    def test_session_hijacking_guidance(self, plugin):
        """PROVES: Plugin provides guidance on finding session tokens"""
        tree = plugin.get_task_tree('192.168.45.100', 11211, {'service': 'memcache'})

        # Collect all notes
        all_notes = []
        def collect_notes(node):
            notes = node.get('metadata', {}).get('notes', '')
            if notes:
                all_notes.append(notes)
            for child in node.get('children', []):
                collect_notes(child)

        collect_notes(tree)

        combined_notes = ' '.join(all_notes).lower()

        # Should mention sessions or tokens
        assert 'session' in combined_notes or 'token' in combined_notes or 'cookie' in combined_notes
