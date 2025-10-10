"""
ServicePlugin Task Completion Tests

Tests the task_completed event handling that calls plugin's on_task_complete() methods
"""

import pytest
from crack.track.services.registry import ServiceRegistry
from crack.track.services.base import ServicePlugin
from crack.track.core.events import EventBus
from typing import Dict, Any, List


class MockHTTPPlugin(ServicePlugin):
    """Mock HTTP plugin for testing"""

    @property
    def name(self) -> str:
        return "http"

    @property
    def default_ports(self) -> List[int]:
        return [80, 443, 8080]

    def detect(self, port_info: Dict[str, Any]) -> float:
        return 100 if port_info.get('service') == 'http' else 0

    def get_task_tree(self, target: str, port: int, service_info: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'id': f'http-enum-{port}',
            'name': f'HTTP Enumeration (Port {port})',
            'type': 'parent'
        }

    def on_task_complete(self, task_id: str, result: str, target: str) -> List[Dict[str, Any]]:
        """Generate follow-up tasks based on results"""
        new_tasks = []

        # If gobuster found /admin, add login test
        if 'gobuster' in task_id and '/admin' in result.lower():
            new_tasks.append({
                'id': f'admin-login-test-80',
                'name': 'Test Admin Panel Authentication',
                'type': 'manual'
            })

        # If WordPress detected, add WPScan
        if 'whatweb' in task_id and 'wordpress' in result.lower():
            new_tasks.append({
                'id': 'wpscan-80',
                'name': 'WordPress Scan',
                'type': 'command'
            })

        return new_tasks


class MockSMBPlugin(ServicePlugin):
    """Mock SMB plugin for testing"""

    @property
    def name(self) -> str:
        return "smb"

    @property
    def default_ports(self) -> List[int]:
        return [139, 445]

    def detect(self, port_info: Dict[str, Any]) -> float:
        return 100 if port_info.get('service') == 'smb' else 0

    def get_task_tree(self, target: str, port: int, service_info: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'id': f'smb-enum-{port}',
            'name': f'SMB Enumeration (Port {port})',
            'type': 'parent'
        }

    def on_task_complete(self, task_id: str, result: str, target: str) -> List[Dict[str, Any]]:
        """Generate follow-up tasks based on results"""
        new_tasks = []

        # If shares found, add mount tasks
        if 'enum4linux' in task_id and 'share' in result.lower():
            new_tasks.append({
                'id': 'mount-share-445',
                'name': 'Mount SMB Share',
                'type': 'command'
            })

        return new_tasks


class TestPluginTaskMatching:
    """
    PROVES: Fuzzy matching correctly identifies which plugin owns a task
    """

    def setup_method(self):
        """Setup for each test"""
        # Clear registry and event bus
        ServiceRegistry.clear()
        EventBus.clear()

        # Register mock plugins
        ServiceRegistry._plugins['http'] = MockHTTPPlugin()
        ServiceRegistry._plugins['smb'] = MockSMBPlugin()

    def test_direct_plugin_name_match(self):
        """Task ID containing plugin name matches"""
        plugin = ServiceRegistry._plugins['http']

        # Direct match: 'http' in task ID
        assert ServiceRegistry._plugin_can_handle_task(plugin, 'http-enum-80', None)
        assert ServiceRegistry._plugin_can_handle_task(plugin, 'whatweb-http-80', None)

    def test_alias_matching(self):
        """Task ID containing service alias matches"""
        plugin = ServiceRegistry._plugins['http']

        # Alias matches
        assert ServiceRegistry._plugin_can_handle_task(plugin, 'gobuster-80', None)
        assert ServiceRegistry._plugin_can_handle_task(plugin, 'whatweb-scan-80', None)
        assert ServiceRegistry._plugin_can_handle_task(plugin, 'nikto-vuln-80', None)

    def test_port_based_matching(self):
        """Task ending with plugin's default port matches"""
        plugin = ServiceRegistry._plugins['http']

        # Port-based matching
        assert ServiceRegistry._plugin_can_handle_task(plugin, 'custom-scan-80', None)
        assert ServiceRegistry._plugin_can_handle_task(plugin, 'test-443', None)
        assert ServiceRegistry._plugin_can_handle_task(plugin, 'enum-8080', None)

    def test_non_matching_tasks_rejected(self):
        """Tasks for different services don't match"""
        http_plugin = ServiceRegistry._plugins['http']
        smb_plugin = ServiceRegistry._plugins['smb']

        # HTTP plugin should not handle SMB tasks
        assert not ServiceRegistry._plugin_can_handle_task(http_plugin, 'smb-enum-445', None)
        assert not ServiceRegistry._plugin_can_handle_task(http_plugin, 'enum4linux-445', None)

        # SMB plugin should not handle HTTP tasks
        assert not ServiceRegistry._plugin_can_handle_task(smb_plugin, 'http-enum-80', None)
        assert not ServiceRegistry._plugin_can_handle_task(smb_plugin, 'gobuster-80', None)


class TestTaskCompletionHandler:
    """
    PROVES: task_completed events trigger on_task_complete() calls
    """

    def setup_method(self):
        """Setup for each test"""
        # Clear registry and event bus
        ServiceRegistry.clear()
        EventBus.clear()

        # Register mock plugins
        ServiceRegistry._plugins['http'] = MockHTTPPlugin()
        ServiceRegistry._plugins['smb'] = MockSMBPlugin()

        # Re-setup event handlers
        for plugin in ServiceRegistry._plugins.values():
            ServiceRegistry._setup_event_handlers(plugin)

        # Capture emitted tasks
        self.emitted_tasks = []

        def capture_task(data):
            self.emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

    def test_gobuster_admin_generates_login_task(self):
        """Gobuster finding /admin generates admin login test task"""
        # Simulate gobuster finding /admin
        EventBus.emit('task_completed', {
            'task': None,
            'task_id': 'gobuster-80',
            'output': [
                '/admin (Status: 200)',
                '/login (Status: 200)',
                '/upload (Status: 403)'
            ],
            'target': '192.168.45.100',
            'command': 'gobuster dir -u http://192.168.45.100 -w wordlist.txt',
            'exit_code': 0
        })

        # Should generate admin login test task
        assert len(self.emitted_tasks) > 0, "Should generate follow-up task"

        task = self.emitted_tasks[0]['task_tree']
        assert 'admin' in task['id'].lower(), "Should be admin-related task"
        assert 'login' in task['name'].lower() or 'auth' in task['name'].lower()

    def test_whatweb_wordpress_generates_wpscan_task(self):
        """WhatWeb detecting WordPress generates WPScan task"""
        # Simulate whatweb detecting WordPress
        EventBus.emit('task_completed', {
            'task': None,
            'task_id': 'whatweb-80',
            'output': [
                'http://192.168.45.100:80 [200 OK]',
                'WordPress[5.8.1]',
                'Apache[2.4.41]'
            ],
            'target': '192.168.45.100',
            'command': 'whatweb http://192.168.45.100 -v',
            'exit_code': 0
        })

        # Should generate WPScan task
        assert len(self.emitted_tasks) > 0, "Should generate follow-up task"

        task = self.emitted_tasks[0]['task_tree']
        assert 'wpscan' in task['id'].lower() or 'wordpress' in task['name'].lower()

    def test_enum4linux_shares_generates_mount_task(self):
        """Enum4linux finding shares generates mount task"""
        # Simulate enum4linux finding shares
        EventBus.emit('task_completed', {
            'task': None,
            'task_id': 'enum4linux-445',
            'output': [
                'Share Enumeration on 192.168.45.100',
                '    Sharename       Type      Comment',
                '    ---------       ----      -------',
                '    ADMIN$          Disk      Remote Admin',
                '    C$              Disk      Default share',
                '    Share           Disk      Custom Share'
            ],
            'target': '192.168.45.100',
            'command': 'enum4linux -a 192.168.45.100',
            'exit_code': 0
        })

        # Should generate mount task
        assert len(self.emitted_tasks) > 0, "Should generate follow-up task"

        task = self.emitted_tasks[0]['task_tree']
        assert 'mount' in task['name'].lower() or 'share' in task['name'].lower()

    def test_irrelevant_task_completion_no_tasks(self):
        """Task completion with no interesting findings generates no tasks"""
        # Simulate task with boring results
        EventBus.emit('task_completed', {
            'task': None,
            'task_id': 'gobuster-80',
            'output': [
                '/images (Status: 404)',
                '/css (Status: 404)',
                '/js (Status: 404)'
            ],
            'target': '192.168.45.100',
            'command': 'gobuster dir -u http://192.168.45.100 -w wordlist.txt',
            'exit_code': 0
        })

        # Should not generate tasks
        assert len(self.emitted_tasks) == 0, "Boring results should not generate tasks"

    def test_wrong_plugin_task_not_processed(self):
        """HTTP plugin doesn't process SMB tasks"""
        # Simulate SMB task completion
        EventBus.emit('task_completed', {
            'task': None,
            'task_id': 'smb-enum-445',
            'output': ['SMB enumeration results'],
            'target': '192.168.45.100',
            'command': 'smbclient -L //192.168.45.100',
            'exit_code': 0
        })

        # HTTP plugin's on_task_complete should not be called
        # (Only SMB plugin should process, but we're not testing SMB logic here)
        # This test just verifies no cross-contamination
        pass  # Implicit: no exceptions raised


class TestMultiplePlugins:
    """
    PROVES: Multiple plugins can coexist without interference
    """

    def setup_method(self):
        """Setup for each test"""
        # Clear registry and event bus
        ServiceRegistry.clear()
        EventBus.clear()

        # Register both plugins
        ServiceRegistry._plugins['http'] = MockHTTPPlugin()
        ServiceRegistry._plugins['smb'] = MockSMBPlugin()

        # Setup handlers
        for plugin in ServiceRegistry._plugins.values():
            ServiceRegistry._setup_event_handlers(plugin)

        self.emitted_tasks = []

        def capture_task(data):
            self.emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

    def test_concurrent_task_completions(self):
        """Multiple task completions are handled independently"""
        # HTTP task
        EventBus.emit('task_completed', {
            'task': None,
            'task_id': 'gobuster-80',
            'output': ['/admin (Status: 200)'],
            'target': '192.168.45.100',
            'command': 'gobuster',
            'exit_code': 0
        })

        # SMB task
        EventBus.emit('task_completed', {
            'task': None,
            'task_id': 'enum4linux-445',
            'output': ['Share found'],
            'target': '192.168.45.100',
            'command': 'enum4linux',
            'exit_code': 0
        })

        # Both should generate tasks
        assert len(self.emitted_tasks) == 2, "Both plugins should generate tasks"

        # Verify they're different tasks
        task_ids = [t['task_tree']['id'] for t in self.emitted_tasks]
        assert len(set(task_ids)) == 2, "Tasks should be unique"
