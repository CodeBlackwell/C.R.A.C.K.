"""
Service Plugin Unit Tests

Tests individual service plugins in isolation using dynamic discovery.
All plugins are automatically tested via parametrization.
"""

import pytest
from crack.track.services.registry import ServiceRegistry
from crack.track.services.base import ServicePlugin

# Initialize plugins at module level for parametrization
# This needs to happen BEFORE pytest collects parametrized tests
ServiceRegistry.initialize_plugins()


class TestPluginInterface:
    """
    PROVES: All plugins implement required ServicePlugin interface

    Dynamic test using all registered plugins
    """

    @pytest.mark.parametrize("plugin", ServiceRegistry.get_all_plugins())
    def test_plugin_has_name(self, plugin):
        """All plugins must have unique name property"""
        assert hasattr(plugin, 'name'), f"Plugin {plugin} missing 'name' property"
        assert isinstance(plugin.name, str), f"Plugin {plugin}.name must be string"
        assert len(plugin.name) > 0, f"Plugin {plugin}.name cannot be empty"

    @pytest.mark.parametrize("plugin", ServiceRegistry.get_all_plugins())
    def test_plugin_has_default_ports(self, plugin):
        """All plugins must have default_ports (can be empty list)"""
        assert hasattr(plugin, 'default_ports'), f"Plugin {plugin.name} missing 'default_ports'"
        assert isinstance(plugin.default_ports, list), f"Plugin {plugin.name}.default_ports must be list"

    @pytest.mark.parametrize("plugin", ServiceRegistry.get_all_plugins())
    def test_plugin_has_service_names(self, plugin):
        """All plugins must have service_names list"""
        assert hasattr(plugin, 'service_names'), f"Plugin {plugin.name} missing 'service_names'"
        assert isinstance(plugin.service_names, list), f"Plugin {plugin.name}.service_names must be list"

        # Manual-trigger plugins (e.g., post-exploitation) can have empty service_names
        # They are explicitly invoked, not auto-detected from port scans
        if not plugin.service_names:
            # If service_names is empty, default_ports should also be empty (manual trigger)
            assert not plugin.default_ports, \
                f"Plugin {plugin.name} has empty service_names but non-empty default_ports. " \
                f"Manual plugins should have both empty."
        else:
            # Auto-detection plugins must have at least one service name
            assert len(plugin.service_names) > 0, f"Plugin {plugin.name}.service_names cannot be empty"

    @pytest.mark.parametrize("plugin", ServiceRegistry.get_all_plugins())
    def test_plugin_implements_detect(self, plugin):
        """All plugins must implement detect() method"""
        assert hasattr(plugin, 'detect'), f"Plugin {plugin.name} missing 'detect' method"
        assert callable(plugin.detect), f"Plugin {plugin.name}.detect must be callable"

        # Test detect with minimal port_info
        port_info = {'port': 80, 'service': 'test', 'state': 'open'}
        result = plugin.detect(port_info)
        # Plugins can return bool (legacy) or float/int (confidence score 0-100)
        assert isinstance(result, (bool, int, float)), \
            f"Plugin {plugin.name}.detect must return bool or numeric confidence score, got {type(result)}"

        # If numeric, should be in valid confidence range
        if isinstance(result, (int, float)):
            assert 0 <= result <= 100, \
                f"Plugin {plugin.name}.detect confidence score must be 0-100, got {result}"

    @pytest.mark.parametrize("plugin", ServiceRegistry.get_all_plugins())
    def test_plugin_implements_get_task_tree(self, plugin):
        """All plugins must implement get_task_tree() method"""
        assert hasattr(plugin, 'get_task_tree'), f"Plugin {plugin.name} missing 'get_task_tree'"
        assert callable(plugin.get_task_tree), f"Plugin {plugin.name}.get_task_tree must be callable"


class TestPluginDetection:
    """
    PROVES: Plugin detection logic works correctly

    Each plugin should detect its own service but not others
    """

    def test_http_plugin_detects_http(self):
        """HTTP plugin detects HTTP service"""
        plugin = ServiceRegistry.get_plugin_by_name('http')
        assert plugin is not None, "HTTP plugin not registered"

        # Should match service name
        assert plugin.detect({'port': 80, 'service': 'http', 'state': 'open'})
        assert plugin.detect({'port': 443, 'service': 'https', 'state': 'open'})

        # Should match port
        assert plugin.detect({'port': 80, 'service': 'unknown', 'state': 'open'})

        # Should not match SMB
        assert not plugin.detect({'port': 445, 'service': 'microsoft-ds', 'state': 'open'})

    def test_smb_plugin_detects_smb(self):
        """SMB plugin detects SMB service"""
        plugin = ServiceRegistry.get_plugin_by_name('smb')
        assert plugin is not None, "SMB plugin not registered"

        assert plugin.detect({'port': 445, 'service': 'microsoft-ds', 'state': 'open'})
        assert plugin.detect({'port': 139, 'service': 'netbios-ssn', 'state': 'open'})

        # Should not match HTTP
        assert not plugin.detect({'port': 80, 'service': 'http', 'state': 'open'})

    def test_ssh_plugin_detects_ssh(self):
        """SSH plugin detects SSH service"""
        plugin = ServiceRegistry.get_plugin_by_name('ssh')
        assert plugin is not None, "SSH plugin not registered"

        assert plugin.detect({'port': 22, 'service': 'ssh', 'state': 'open'})

        # Should not match HTTP
        assert not plugin.detect({'port': 80, 'service': 'http', 'state': 'open'})

    def test_mysql_plugin_detects_mysql(self):
        """MySQL plugin detects MySQL service"""
        plugin = ServiceRegistry.get_plugin_by_name('mysql')
        assert plugin is not None, "MySQL plugin not registered"

        assert plugin.detect({'port': 3306, 'service': 'mysql', 'state': 'open'})
        assert plugin.detect({'port': 3306, 'service': 'mariadb', 'state': 'open'})

        # Should not match PostgreSQL
        assert not plugin.detect({'port': 5432, 'service': 'postgresql', 'state': 'open'})

    def test_nfs_plugin_detects_nfs(self):
        """NFS plugin detects NFS service"""
        plugin = ServiceRegistry.get_plugin_by_name('nfs')
        assert plugin is not None, "NFS plugin not registered"

        assert plugin.detect({'port': 2049, 'service': 'nfs', 'state': 'open'})
        assert plugin.detect({'port': 2049, 'service': 'nfs3', 'state': 'open'})
        assert plugin.detect({'port': 2049, 'service': 'nfs4', 'state': 'open'})

        # Should not match SMB
        assert not plugin.detect({'port': 445, 'service': 'microsoft-ds', 'state': 'open'})


class TestPluginTaskGeneration:
    """
    PROVES: Plugins generate valid task trees with complete metadata
    """

    @pytest.mark.parametrize("plugin", ServiceRegistry.get_all_plugins())
    def test_plugin_generates_valid_task_tree(self, plugin):
        """All plugins must generate valid task tree structure"""
        # Skip generic/post-exploit plugins that may not generate tasks
        if plugin.name in ['generic', 'post-exploit']:
            pytest.skip(f"Skipping {plugin.name} - special handling")

        # Generate task tree
        task_tree = plugin.get_task_tree(
            target='192.168.45.100',
            port=plugin.default_ports[0] if plugin.default_ports else 80,
            service_info={'version': 'test-1.0'}
        )

        # Validate structure
        assert isinstance(task_tree, dict), f"Plugin {plugin.name} must return dict"
        assert 'id' in task_tree, f"Plugin {plugin.name} task tree missing 'id'"
        assert 'name' in task_tree, f"Plugin {plugin.name} task tree missing 'name'"
        assert 'type' in task_tree, f"Plugin {plugin.name} task tree missing 'type'"

    @pytest.mark.parametrize("plugin_name", ['http', 'smb', 'ssh', 'mysql', 'nfs'])
    def test_plugin_tasks_have_metadata(self, plugin_name):
        """Core plugins must include rich metadata in tasks"""
        plugin = ServiceRegistry.get_plugin_by_name(plugin_name)
        assert plugin is not None, f"{plugin_name} plugin not registered"

        task_tree = plugin.get_task_tree(
            target='192.168.45.100',
            port=plugin.default_ports[0] if plugin.default_ports else 80,
            service_info={'version': 'test-1.0'}
        )

        # Check for children (tasks)
        assert 'children' in task_tree, f"{plugin_name} should have children tasks"
        children = task_tree.get('children', [])

        if len(children) > 0:
            # Check first task has metadata
            first_task = children[0]

            # Should have metadata or be a parent task
            if first_task.get('type') != 'parent':
                assert 'metadata' in first_task, \
                    f"{plugin_name} first task should have metadata"

    @pytest.mark.parametrize("plugin_name", ['http', 'smb', 'ssh', 'mysql', 'nfs'])
    def test_plugin_tasks_have_oscp_tags(self, plugin_name):
        """Core plugins should use OSCP relevance tags"""
        plugin = ServiceRegistry.get_plugin_by_name(plugin_name)
        task_tree = plugin.get_task_tree(
            target='192.168.45.100',
            port=plugin.default_ports[0] if plugin.default_ports else 80,
            service_info={'version': 'test-1.0'}
        )

        # Recursively find all metadata
        def get_all_metadata(node):
            metadata_list = []
            if 'metadata' in node:
                metadata_list.append(node['metadata'])
            for child in node.get('children', []):
                metadata_list.extend(get_all_metadata(child))
            return metadata_list

        all_metadata = get_all_metadata(task_tree)

        # At least one task should have OSCP tags
        oscp_tags_found = False
        for metadata in all_metadata:
            tags = metadata.get('tags', [])
            if any('OSCP:' in str(tag) for tag in tags):
                oscp_tags_found = True
                break

        assert oscp_tags_found, \
            f"{plugin_name} plugin should include OSCP relevance tags (OSCP:HIGH/MEDIUM/LOW)"


class TestPluginMetadataQuality:
    """
    PROVES: Plugin metadata is complete and educational (OSCP preparation)
    """

    @pytest.mark.parametrize("plugin_name", ['mysql', 'nfs'])
    def test_new_plugins_have_flag_explanations(self, plugin_name):
        """New plugins (MySQL, NFS) must explain command flags"""
        plugin = ServiceRegistry.get_plugin_by_name(plugin_name)
        task_tree = plugin.get_task_tree(
            target='192.168.45.100',
            port=plugin.default_ports[0],
            service_info={'version': 'test-1.0'}
        )

        # Find tasks with commands
        def find_command_tasks(node):
            tasks = []
            if node.get('type') == 'command' or node.get('metadata', {}).get('command'):
                tasks.append(node)
            for child in node.get('children', []):
                tasks.extend(find_command_tasks(child))
            return tasks

        command_tasks = find_command_tasks(task_tree)
        assert len(command_tasks) > 0, f"{plugin_name} should have command tasks"

        # At least one command task should have flag explanations
        has_flag_explanations = any(
            'flag_explanations' in task.get('metadata', {})
            for task in command_tasks
        )

        assert has_flag_explanations, \
            f"{plugin_name} should include flag_explanations for educational value"

    @pytest.mark.parametrize("plugin_name", ['mysql', 'nfs'])
    def test_new_plugins_have_success_indicators(self, plugin_name):
        """New plugins must include success/failure indicators"""
        plugin = ServiceRegistry.get_plugin_by_name(plugin_name)
        task_tree = plugin.get_task_tree(
            target='192.168.45.100',
            port=plugin.default_ports[0],
            service_info={'version': 'test-1.0'}
        )

        # Find all metadata
        def get_all_metadata(node):
            metadata_list = []
            if 'metadata' in node:
                metadata_list.append(node['metadata'])
            for child in node.get('children', []):
                metadata_list.extend(get_all_metadata(child))
            return metadata_list

        all_metadata = get_all_metadata(task_tree)

        # At least one task should have success indicators
        has_indicators = any(
            'success_indicators' in m or 'failure_indicators' in m
            for m in all_metadata
        )

        assert has_indicators, \
            f"{plugin_name} should include success/failure indicators"

    @pytest.mark.parametrize("plugin_name", ['mysql', 'nfs'])
    def test_new_plugins_have_alternatives(self, plugin_name):
        """New plugins must provide manual alternatives (OSCP exam prep)"""
        plugin = ServiceRegistry.get_plugin_by_name(plugin_name)
        task_tree = plugin.get_task_tree(
            target='192.168.45.100',
            port=plugin.default_ports[0],
            service_info={'version': 'test-1.0'}
        )

        # Find all metadata
        def get_all_metadata(node):
            metadata_list = []
            if 'metadata' in node:
                metadata_list.append(node['metadata'])
            for child in node.get('children', []):
                metadata_list.extend(get_all_metadata(child))
            return metadata_list

        all_metadata = get_all_metadata(task_tree)

        # At least one task should have alternatives
        has_alternatives = any('alternatives' in m for m in all_metadata)

        assert has_alternatives, \
            f"{plugin_name} should provide manual alternatives for OSCP exam scenarios"


class TestPluginRegistry:
    """
    PROVES: ServiceRegistry correctly manages plugins
    """

    def test_registry_has_all_expected_plugins(self):
        """Registry should contain all core plugins"""
        expected_plugins = ['http', 'smb', 'ssh', 'ftp', 'sql', 'smtp', 'mysql', 'nfs', 'post-exploit']

        registered_names = [p.name for p in ServiceRegistry.get_all_plugins()]

        for expected in expected_plugins:
            assert expected in registered_names, \
                f"Plugin '{expected}' not registered. Found: {registered_names}"

    def test_registry_get_plugin_by_name(self):
        """Registry should retrieve plugins by name"""
        mysql_plugin = ServiceRegistry.get_plugin_by_name('mysql')
        assert mysql_plugin is not None, "MySQL plugin should be retrievable"
        assert mysql_plugin.name == 'mysql'

        nfs_plugin = ServiceRegistry.get_plugin_by_name('nfs')
        assert nfs_plugin is not None, "NFS plugin should be retrievable"
        assert nfs_plugin.name == 'nfs'

    def test_registry_get_plugin_for_port_info(self):
        """Registry should match correct plugin for port info"""
        # MySQL - Note: Both 'sql' and 'mysql' plugins can handle MySQL
        # The 'sql' plugin is generic (handles MySQL, PostgreSQL, MSSQL)
        # Either plugin is acceptable for MySQL services
        mysql_port_info = {'port': 3306, 'service': 'mysql', 'state': 'open'}
        plugin = ServiceRegistry.get_plugin(mysql_port_info)
        assert plugin is not None, "Should find plugin for MySQL"
        assert plugin.name in ['mysql', 'sql'], \
            f"Should return MySQL or SQL plugin for MySQL service, got {plugin.name}"

        # Verify both plugins can detect MySQL
        mysql_plugin = ServiceRegistry.get_plugin_by_name('mysql')
        sql_plugin = ServiceRegistry.get_plugin_by_name('sql')
        assert mysql_plugin.detect(mysql_port_info), "MySQL plugin should detect MySQL service"
        assert sql_plugin.detect(mysql_port_info), "SQL plugin should detect MySQL service"

        # NFS - Should be unique to NFS plugin
        nfs_port_info = {'port': 2049, 'service': 'nfs', 'state': 'open'}
        plugin = ServiceRegistry.get_plugin(nfs_port_info)
        assert plugin is not None, "Should find plugin for NFS"
        assert plugin.name == 'nfs', f"Should return NFS plugin, got {plugin.name}"
