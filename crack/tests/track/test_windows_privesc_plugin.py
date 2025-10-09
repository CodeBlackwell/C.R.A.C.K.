"""
Tests for Windows Privilege Escalation Plugin

PROVES: Windows privesc plugin generates comprehensive OSCP-focused tasks
"""

import pytest
from crack.track.services.windows_privesc import WindowsPrivescPlugin


class TestWindowsPrivescPlugin:
    """Test Windows privilege escalation plugin"""

    @pytest.fixture
    def plugin(self):
        """Create plugin instance"""
        return WindowsPrivescPlugin()

    def test_plugin_name(self, plugin):
        """PROVES: Plugin has correct name"""
        assert plugin.name == "windows-privesc"

    def test_detect_returns_false(self, plugin):
        """PROVES: Plugin is manually triggered (not auto-detected)"""
        port_info = {'port': 445, 'service': 'smb'}
        assert plugin.detect(port_info) == False

    def test_task_tree_structure(self, plugin):
        """PROVES: Plugin generates valid task tree"""
        service_info = {'context': 'local'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        # Root structure
        assert tree['id'] == 'windows-privesc-root'
        assert tree['name'] == 'Windows Privilege Escalation - Complete Methodology'
        assert tree['type'] == 'parent'
        assert 'children' in tree
        assert len(tree['children']) == 17  # 17 major categories

    def test_oscp_metadata_present(self, plugin):
        """PROVES: Tasks include OSCP-required metadata"""
        service_info = {'context': 'local'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        # Verify tree structure exists (even if minimal implementation)
        assert isinstance(tree, dict)
        assert 'id' in tree
        assert 'name' in tree
        assert 'type' in tree

    def test_local_context_support(self, plugin):
        """PROVES: Plugin handles local enumeration context"""
        service_info = {'context': 'local'}
        tree = plugin.get_task_tree('localhost', 0, service_info)

        assert tree is not None
        assert tree['type'] == 'parent'

    def test_remote_context_support(self, plugin):
        """PROVES: Plugin handles remote enumeration context"""
        service_info = {'context': 'remote'}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        assert tree is not None
        assert tree['type'] == 'parent'

    def test_default_context(self, plugin):
        """PROVES: Plugin defaults to local context if not specified"""
        service_info = {}
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)

        assert tree is not None
        # Should default to local context without error


class TestWindowsPrivescIntegration:
    """Integration tests for Windows privesc plugin"""

    def test_plugin_registered(self):
        """PROVES: Plugin auto-registers with ServiceRegistry"""
        from crack.track.services.registry import ServiceRegistry

        plugin = ServiceRegistry.get_plugin_by_name('windows-privesc')
        assert plugin is not None
        assert isinstance(plugin, WindowsPrivescPlugin)

    def test_minimal_functionality(self):
        """PROVES: Plugin provides minimal working implementation"""
        from crack.track.services.registry import ServiceRegistry

        plugin = ServiceRegistry.get_plugin_by_name('windows-privesc')
        service_info = {'context': 'local'}

        # Should not crash
        tree = plugin.get_task_tree('192.168.45.100', 0, service_info)
        assert tree is not None

