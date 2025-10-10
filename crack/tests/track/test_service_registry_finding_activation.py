"""Tests for finding-based plugin activation in ServiceRegistry"""

import pytest
import time
from crack.track.services.base import ServicePlugin
from crack.track.services.registry import ServiceRegistry
from crack.track.core.events import EventBus


class TestFindingBasedActivation:
    """Test finding-based plugin activation flow"""

    def setup_method(self):
        """Reset registry before each test"""
        ServiceRegistry.clear()
        EventBus.clear()

    def wait_for_resolution(self, timeout=0.1):
        """Wait for finding resolution timers to complete

        Args:
            timeout: Maximum time to wait in seconds
        """
        time.sleep(timeout)

    def test_plugin_activates_on_finding(self):
        """Plugin with detect_from_finding activates on finding_added event"""

        @ServiceRegistry.register
        class TestPlugin(ServicePlugin):
            @property
            def name(self):
                return "test-finding"

            def detect(self, port_info):
                return 0

            def detect_from_finding(self, finding, profile=None):
                if finding.get('type') == 'shell_obtained':
                    return 100
                return 0

            def get_task_tree(self, target, port, service_info):
                return {
                    'id': 'test-task',
                    'name': 'Test Task',
                    'type': 'manual'
                }

        # Setup event capture
        generated_tasks = []
        EventBus.on('plugin_tasks_generated', lambda d: generated_tasks.append(d))

        # Emit finding
        EventBus.emit('finding_added', {
            'finding': {
                'type': 'shell_obtained',
                'description': 'Got reverse shell',
                'source': 'manual'
            },
            'target': '192.168.1.1'
        })

        # Wait for timer-based resolution
        self.wait_for_resolution()

        # Verify task generated
        assert len(generated_tasks) == 1
        assert generated_tasks[0]['plugin'] == 'test-finding'
        assert generated_tasks[0]['source'] == 'finding_activation'

    def test_conflict_resolution_highest_confidence_wins(self):
        """Multiple plugins claiming same finding - highest confidence wins"""

        @ServiceRegistry.register
        class LowConfPlugin(ServicePlugin):
            @property
            def name(self):
                return "low-conf"

            def detect(self, port_info):
                return 0

            def detect_from_finding(self, finding, profile=None):
                return 30

            def get_task_tree(self, target, port, service_info):
                return {'id': 'low', 'name': 'Low'}

        @ServiceRegistry.register
        class HighConfPlugin(ServicePlugin):
            @property
            def name(self):
                return "high-conf"

            def detect(self, port_info):
                return 0

            def detect_from_finding(self, finding, profile=None):
                return 90

            def get_task_tree(self, target, port, service_info):
                return {'id': 'high', 'name': 'High'}

        generated_tasks = []
        EventBus.on('plugin_tasks_generated', lambda d: generated_tasks.append(d))

        EventBus.emit('finding_added', {
            'finding': {'type': 'test', 'description': 'Test'},
            'target': '192.168.1.1'
        })

        # Wait for timer-based resolution
        self.wait_for_resolution()

        # Only high confidence plugin should generate tasks
        assert len(generated_tasks) == 1
        assert generated_tasks[0]['plugin'] == 'high-conf'

    def test_deduplication_prevents_double_activation(self):
        """Same finding doesn't activate plugin twice"""

        activation_count = 0

        @ServiceRegistry.register
        class DedupePlugin(ServicePlugin):
            @property
            def name(self):
                return "dedupe-test"

            def detect(self, port_info):
                return 0

            def detect_from_finding(self, finding, profile=None):
                return 100 if finding.get('type') == 'dedupe' else 0

            def get_task_tree(self, target, port, service_info):
                nonlocal activation_count
                activation_count += 1
                return {'id': f'task-{activation_count}'}

        # Emit same finding twice
        finding = {'type': 'dedupe', 'description': 'Test'}
        EventBus.emit('finding_added', {'finding': finding, 'target': '192.168.1.1'})
        EventBus.emit('finding_added', {'finding': finding, 'target': '192.168.1.1'})

        

        # Wait for timer-based resolution

        self.wait_for_resolution()

        # Should only activate once
        assert activation_count == 1

    def test_service_info_contains_finding_context(self):
        """get_task_tree receives finding context in service_info"""

        received_service_info = None

        @ServiceRegistry.register
        class ContextPlugin(ServicePlugin):
            @property
            def name(self):
                return "context-test"

            def detect(self, port_info):
                return 0

            def detect_from_finding(self, finding, profile=None):
                return 100

            def get_task_tree(self, target, port, service_info):
                nonlocal received_service_info
                received_service_info = service_info
                return {'id': 'test'}

        EventBus.emit('finding_added', {
            'finding': {
                'type': 'shell_obtained',
                'description': 'Got shell',
                'source': 'exploit'
            },
            'target': '192.168.1.1'
        })

        # Wait for timer-based resolution
        self.wait_for_resolution()

        # Verify service_info populated correctly
        assert received_service_info is not None
        assert received_service_info['activation_source'] == 'finding'
        assert received_service_info['finding_type'] == 'shell_obtained'
        assert 'finding' in received_service_info

    def test_zero_confidence_does_not_activate(self):
        """Plugin returning 0 confidence does not activate"""

        @ServiceRegistry.register
        class NoActivatePlugin(ServicePlugin):
            @property
            def name(self):
                return "no-activate"

            def detect(self, port_info):
                return 0

            def detect_from_finding(self, finding, profile=None):
                return 0  # Never activate

            def get_task_tree(self, target, port, service_info):
                return {'id': 'should-not-run'}

        generated_tasks = []
        EventBus.on('plugin_tasks_generated', lambda d: generated_tasks.append(d))

        EventBus.emit('finding_added', {
            'finding': {'type': 'test', 'description': 'Test'},
            'target': '192.168.1.1'
        })

        # No tasks should be generated
        assert len(generated_tasks) == 0

    def test_missing_finding_does_not_crash(self):
        """Event with missing finding dict is handled gracefully"""

        @ServiceRegistry.register
        class SafePlugin(ServicePlugin):
            @property
            def name(self):
                return "safe-plugin"

            def detect(self, port_info):
                return 0

            def detect_from_finding(self, finding, profile=None):
                return 100

            def get_task_tree(self, target, port, service_info):
                return {'id': 'safe-task'}

        generated_tasks = []
        EventBus.on('plugin_tasks_generated', lambda d: generated_tasks.append(d))

        # Emit event with no finding
        EventBus.emit('finding_added', {
            'target': '192.168.1.1'
        })

        # Should not crash, and no tasks generated
        assert len(generated_tasks) == 0

    def test_exception_in_detect_from_finding_is_handled(self):
        """Exception in detect_from_finding is caught and logged"""

        @ServiceRegistry.register
        class BrokenPlugin(ServicePlugin):
            @property
            def name(self):
                return "broken-plugin"

            def detect(self, port_info):
                return 0

            def detect_from_finding(self, finding, profile=None):
                raise ValueError("Test exception")

            def get_task_tree(self, target, port, service_info):
                return {'id': 'should-not-run'}

        generated_tasks = []
        EventBus.on('plugin_tasks_generated', lambda d: generated_tasks.append(d))

        EventBus.emit('finding_added', {
            'finding': {'type': 'test', 'description': 'Test'},
            'target': '192.168.1.1'
        })

        # Should not crash, and no tasks generated
        assert len(generated_tasks) == 0

    def test_port_is_zero_for_finding_activation(self):
        """Finding-based activation passes port=0 to get_task_tree"""

        received_port = None

        @ServiceRegistry.register
        class PortCheckPlugin(ServicePlugin):
            @property
            def name(self):
                return "port-check"

            def detect(self, port_info):
                return 0

            def detect_from_finding(self, finding, profile=None):
                return 100

            def get_task_tree(self, target, port, service_info):
                nonlocal received_port
                received_port = port
                return {'id': 'test'}

        EventBus.emit('finding_added', {
            'finding': {'type': 'test', 'description': 'Test'},
            'target': '192.168.1.1'
        })

        # Wait for timer-based resolution
        self.wait_for_resolution()

        # Verify port is 0 (no port for finding-based activation)
        assert received_port == 0

    def test_multiple_findings_trigger_multiple_activations(self):
        """Different findings can activate the same plugin multiple times"""

        activation_count = 0

        @ServiceRegistry.register
        class MultiActivatePlugin(ServicePlugin):
            @property
            def name(self):
                return "multi-activate"

            def detect(self, port_info):
                return 0

            def detect_from_finding(self, finding, profile=None):
                return 100

            def get_task_tree(self, target, port, service_info):
                nonlocal activation_count
                activation_count += 1
                return {'id': f'task-{activation_count}'}

        # Emit different findings
        EventBus.emit('finding_added', {
            'finding': {'type': 'shell_obtained', 'description': 'First shell'},
            'target': '192.168.1.1'
        })

        EventBus.emit('finding_added', {
            'finding': {'type': 'shell_obtained', 'description': 'Second shell'},
            'target': '192.168.1.1'
        })

        # Wait for timer-based resolution
        self.wait_for_resolution()

        # Should activate twice (different descriptions = different findings)
        assert activation_count == 2
