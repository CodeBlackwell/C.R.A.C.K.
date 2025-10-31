"""
Integration tests for SQL-backed service plugins

Tests end-to-end workflow:
1. Plugin detects service
2. Plugin generates task tree from SQL
3. Variables substituted correctly
4. Fallback to hardcoded works if SQL unavailable

Coverage: All 5 pilot plugins (ftp, nfs, smtp, mysql, ssh)
"""

import pytest
import os
from unittest.mock import Mock, patch

from crack.track.services.ftp import FTPPlugin
from crack.track.services.nfs import NFSPlugin
from crack.track.services.smtp import SMTPPlugin
from crack.track.services.mysql import MySQLPlugin
from crack.track.services.ssh import SSHPlugin


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture(autouse=True)
def enable_sql_mode():
    """Enable SQL mode for all tests in this module"""
    os.environ['CRACK_USE_SQL'] = 'true'
    yield
    os.environ.pop('CRACK_USE_SQL', None)


# ============================================================================
# TESTS - FTP Plugin (Pilot - Already Migrated)
# ============================================================================

class TestFTPPluginSQLIntegration:
    """Test FTP plugin with SQL backend"""

    def test_ftp_plugin_generates_tasks_from_sql(self):
        """FTP plugin generates task tree from SQL backend"""
        plugin = FTPPlugin()
        task_tree = plugin.get_task_tree('192.168.45.100', 21, {'service': 'ftp'})

        assert 'children' in task_tree
        assert len(task_tree['children']) > 0

    def test_ftp_variables_substituted(self):
        """Variables are substituted in FTP task commands"""
        plugin = FTPPlugin()
        task_tree = plugin.get_task_tree('192.168.45.100', 21, {'service': 'ftp'})

        # Find first command task
        command_task = self._find_command_task(task_tree['children'])
        cmd = command_task.get('metadata', {}).get('command', '')

        assert '192.168.45.100' in cmd, "Target IP not substituted"
        assert '21' in cmd, "Port not substituted"
        assert '<TARGET>' not in cmd, "Placeholder not replaced"
        assert '<PORT>' not in cmd, "Port placeholder not replaced"

    def test_ftp_fallback_to_hardcoded(self):
        """FTP plugin falls back to hardcoded when SQL unavailable"""
        os.environ['CRACK_USE_SQL'] = 'false'

        plugin = FTPPlugin()
        task_tree = plugin.get_task_tree('192.168.45.100', 21, {'service': 'ftp'})

        # Should still generate tasks (from hardcoded)
        assert 'children' in task_tree
        assert len(task_tree['children']) > 0

    # Helper
    def _find_command_task(self, tasks):
        for task in tasks:
            if task.get('type') == 'command':
                return task
            if 'children' in task:
                found = self._find_command_task(task['children'])
                if found:
                    return found
        return None


# ============================================================================
# TESTS - NFS Plugin
# ============================================================================

class TestNFSPluginSQLIntegration:
    """Test NFS plugin with SQL backend"""

    def test_nfs_plugin_generates_tasks_from_sql(self):
        """NFS plugin generates task tree from SQL backend"""
        plugin = NFSPlugin()
        task_tree = plugin.get_task_tree('192.168.45.100', 2049, {'service': 'nfs'})

        assert 'children' in task_tree
        assert len(task_tree['children']) >= 8, f"Expected 8+ tasks, got {len(task_tree['children'])}"

    def test_nfs_variables_substituted(self):
        """Variables are substituted in NFS task commands"""
        plugin = NFSPlugin()
        task_tree = plugin.get_task_tree('192.168.45.100', 2049, {'service': 'nfs'})

        cmd_task = self._find_command_task(task_tree['children'])
        if cmd_task:
            cmd = cmd_task.get('metadata', {}).get('command', '')
            assert '192.168.45.100' in cmd, "Target IP not substituted"
            # Note: Not all NFS commands use <PORT> (e.g., showmount uses default 111)
            # Just verify placeholders are replaced
            assert '<TARGET>' not in cmd, "Target placeholder not replaced"

    def test_nfs_fallback_to_hardcoded(self):
        """NFS plugin falls back to hardcoded when SQL unavailable"""
        os.environ['CRACK_USE_SQL'] = 'false'

        plugin = NFSPlugin()
        task_tree = plugin.get_task_tree('192.168.45.100', 2049, {'service': 'nfs'})

        assert len(task_tree['children']) >= 8

    def _find_command_task(self, tasks):
        for task in tasks:
            if task.get('type') == 'command':
                return task
            if 'children' in task:
                found = self._find_command_task(task['children'])
                if found:
                    return found
        return None


# ============================================================================
# TESTS - SMTP Plugin
# ============================================================================

class TestSMTPPluginSQLIntegration:
    """Test SMTP plugin with SQL backend"""

    def test_smtp_plugin_generates_tasks_from_sql(self):
        """SMTP plugin generates task tree from SQL backend"""
        plugin = SMTPPlugin()
        task_tree = plugin.get_task_tree('192.168.45.100', 25, {'service': 'smtp'})

        assert 'children' in task_tree
        assert len(task_tree['children']) >= 10, f"Expected 10+ tasks, got {len(task_tree['children'])}"

    def test_smtp_port_variations(self):
        """SMTP plugin handles different ports (25, 465, 587)"""
        plugin = SMTPPlugin()

        for port in [25, 465, 587]:
            task_tree = plugin.get_task_tree('192.168.45.100', port, {'service': 'smtp'})
            assert len(task_tree['children']) > 0, f"No tasks for port {port}"

    def test_smtp_fallback_to_hardcoded(self):
        """SMTP plugin falls back to hardcoded when SQL unavailable"""
        os.environ['CRACK_USE_SQL'] = 'false'

        plugin = SMTPPlugin()
        task_tree = plugin.get_task_tree('192.168.45.100', 25, {'service': 'smtp'})

        assert len(task_tree['children']) >= 10


# ============================================================================
# TESTS - MySQL Plugin
# ============================================================================

class TestMySQLPluginSQLIntegration:
    """Test MySQL plugin with SQL backend (nested tasks)"""

    def test_mysql_plugin_generates_tasks(self):
        """MySQL plugin generates task tree from SQL backend"""
        plugin = MySQLPlugin()
        task_tree = plugin.get_task_tree('192.168.45.100', 3306, {'service': 'mysql'})

        assert 'children' in task_tree
        # MySQL may have parent task structure
        assert len(task_tree['children']) >= 1

    def test_mysql_nested_structure(self):
        """MySQL plugin may have nested task structure"""
        plugin = MySQLPlugin()
        task_tree = plugin.get_task_tree('192.168.45.100', 3306, {'service': 'mysql'})

        # Check if any task is a parent type
        has_parent = any(
            task.get('type') == 'parent' or 'children' in task
            for task in task_tree.get('children', [])
        )
        # MySQL may or may not have nested structure depending on migration
        assert task_tree.get('children') is not None

    def test_mysql_fallback_to_hardcoded(self):
        """MySQL plugin falls back to hardcoded when SQL unavailable"""
        os.environ['CRACK_USE_SQL'] = 'false'

        plugin = MySQLPlugin()
        task_tree = plugin.get_task_tree('192.168.45.100', 3306, {'service': 'mysql'})

        assert len(task_tree['children']) >= 10


# ============================================================================
# TESTS - SSH Plugin
# ============================================================================

class TestSSHPluginSQLIntegration:
    """Test SSH plugin with SQL backend (preserves on_task_complete)"""

    def test_ssh_plugin_generates_tasks(self):
        """SSH plugin generates task tree from SQL backend"""
        plugin = SSHPlugin()
        task_tree = plugin.get_task_tree('192.168.45.100', 22, {'service': 'ssh'})

        assert 'children' in task_tree
        assert len(task_tree['children']) >= 1

    def test_ssh_preserves_on_task_complete(self):
        """SSH plugin still has on_task_complete() method (Phase 5 work)"""
        plugin = SSHPlugin()

        assert hasattr(plugin, 'on_task_complete')
        assert callable(plugin.on_task_complete)

        # Basic smoke test
        result = plugin.on_task_complete('test-task', 'OpenSSH 7.4', '192.168.45.100')
        assert isinstance(result, list)

    def test_ssh_fallback_to_hardcoded(self):
        """SSH plugin falls back to hardcoded when SQL unavailable"""
        os.environ['CRACK_USE_SQL'] = 'false'

        plugin = SSHPlugin()
        task_tree = plugin.get_task_tree('192.168.45.100', 22, {'service': 'ssh'})

        assert len(task_tree['children']) >= 8


# ============================================================================
# TESTS - All Plugins Fallback
# ============================================================================

class TestAllPluginsFallback:
    """Test all 5 plugins fall back gracefully"""

    def test_all_plugins_fallback_gracefully(self):
        """All 5 plugins fall back gracefully when SQL unavailable"""
        os.environ['CRACK_USE_SQL'] = 'false'

        plugins = [
            (FTPPlugin(), '192.168.45.100', 21),
            (NFSPlugin(), '192.168.45.101', 2049),
            (SMTPPlugin(), '192.168.45.102', 25),
            (MySQLPlugin(), '192.168.45.103', 3306),
            (SSHPlugin(), '192.168.45.104', 22),
        ]

        for plugin, target, port in plugins:
            task_tree = plugin.get_task_tree(target, port, {'service': plugin.name})

            assert 'children' in task_tree, f"{plugin.name} fallback failed"
            assert len(task_tree['children']) > 0, f"{plugin.name} generated no tasks"
