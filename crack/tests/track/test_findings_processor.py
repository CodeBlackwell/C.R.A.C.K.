"""
Findings Processor Unit Tests

Tests the findings→tasks conversion system that closes the enumeration loop.
"""

import pytest
from crack.track.services.findings_processor import FindingsProcessor
from crack.track.core.events import EventBus


class TestFindingsProcessorInitialization:
    """
    PROVES: FindingsProcessor initializes correctly and registers event handlers
    """

    def test_processor_initializes_with_target(self):
        """Processor stores target information"""
        processor = FindingsProcessor(target='192.168.45.100')
        assert processor.target == '192.168.45.100'
        assert isinstance(processor.processed_findings, set)
        assert len(processor.processed_findings) == 0

    def test_processor_has_converters(self):
        """Processor has converters for all finding types"""
        processor = FindingsProcessor(target='192.168.45.100')

        expected_types = [
            'directory', 'directories',
            'file', 'files',
            'credential', 'credentials',
            'vulnerability', 'vulnerabilities',
            'service', 'services',
            'user', 'users'
        ]

        for finding_type in expected_types:
            assert finding_type in processor.converters, \
                f"Processor missing converter for {finding_type}"

    def test_processor_registers_event_handler(self):
        """Processor registers handler for finding_added events"""
        # Clear previous handlers
        EventBus.clear('finding_added')

        processor = FindingsProcessor(target='192.168.45.100')

        # Check that handler is registered
        handlers = EventBus.get_handlers('finding_added')
        assert len(handlers) > 0, "Processor should register finding_added handler"


class TestDirectoryFindingConversion:
    """
    PROVES: Directory findings generate appropriate tasks
    """

    def setup_method(self):
        """Setup for each test"""
        EventBus.clear()
        self.processor = FindingsProcessor(target='192.168.45.100')
        self.emitted_tasks = []

        # Capture emitted tasks
        def capture_task(data):
            self.emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

    def test_interesting_directory_generates_task(self):
        """Interesting directories like /admin generate inspection tasks"""
        finding = {
            'type': 'directory',
            'description': '/admin',
            'source': 'gobuster'
        }

        EventBus.emit('finding_added', {'finding': finding})

        # Should generate a task
        assert len(self.emitted_tasks) > 0, "Should generate task for /admin"
        task = self.emitted_tasks[0]['task_tree']
        assert 'admin' in task['name'].lower(), "Task should reference admin directory"

    def test_boring_directory_skipped(self):
        """Non-interesting directories don't generate tasks"""
        finding = {
            'type': 'directory',
            'description': '/images',
            'source': 'gobuster'
        }

        EventBus.emit('finding_added', {'finding': finding})

        # Should not generate a task
        assert len(self.emitted_tasks) == 0, "Should skip boring directory"

    def test_dict_format_directory_parsed(self):
        """Directory findings in dict format are parsed correctly"""
        finding = {
            'type': 'directory',
            'description': "{'path': '/admin', 'status': 301}",
            'source': 'gobuster'
        }

        EventBus.emit('finding_added', {'finding': finding})

        # Should generate a task
        assert len(self.emitted_tasks) > 0, "Should parse dict format"


class TestFileFindingConversion:
    """
    PROVES: File findings generate appropriate tasks
    """

    def setup_method(self):
        """Setup for each test"""
        EventBus.clear()
        self.processor = FindingsProcessor(target='192.168.45.100')
        self.emitted_tasks = []

        def capture_task(data):
            self.emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

    def test_interesting_file_generates_task(self):
        """Interesting files like .env generate fetch tasks"""
        finding = {
            'type': 'file',
            'description': '/.env',
            'source': 'gobuster'
        }

        EventBus.emit('finding_added', {'finding': finding})

        # Should generate a task
        assert len(self.emitted_tasks) > 0, "Should generate task for .env file"
        task = self.emitted_tasks[0]['task_tree']
        assert 'fetch' in task['name'].lower() or 'download' in task['name'].lower()

    def test_config_file_generates_task(self):
        """Config files generate tasks"""
        finding = {
            'type': 'file',
            'description': '/config.php',
            'source': 'gobuster'
        }

        EventBus.emit('finding_added', {'finding': finding})

        assert len(self.emitted_tasks) > 0, "Should generate task for config.php"

    def test_boring_file_skipped(self):
        """Non-interesting files don't generate tasks"""
        finding = {
            'type': 'file',
            'description': '/index.html',
            'source': 'gobuster'
        }

        EventBus.emit('finding_added', {'finding': finding})

        assert len(self.emitted_tasks) == 0, "Should skip boring file"


class TestVulnerabilityFindingConversion:
    """
    PROVES: Vulnerability findings generate research tasks
    """

    def setup_method(self):
        """Setup for each test"""
        EventBus.clear()
        self.processor = FindingsProcessor(target='192.168.45.100')
        self.emitted_tasks = []

        def capture_task(data):
            self.emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

    def test_cve_finding_generates_research_task(self):
        """CVE findings generate searchsploit tasks"""
        finding = {
            'type': 'vulnerability',
            'description': 'CVE-2021-44228 detected',
            'source': 'nmap'
        }

        EventBus.emit('finding_added', {'finding': finding})

        # Should generate a research task
        assert len(self.emitted_tasks) > 0, "Should generate CVE research task"
        task = self.emitted_tasks[0]['task_tree']
        assert 'CVE-2021-44228' in task['name'] or 'research' in task['name'].lower()

    def test_generic_vuln_without_cve_skipped(self):
        """Generic vulnerabilities without CVE don't generate tasks"""
        finding = {
            'type': 'vulnerability',
            'description': 'Potential XSS vulnerability',
            'source': 'manual'
        }

        EventBus.emit('finding_added', {'finding': finding})

        # Should not generate automatic task (manual verification needed)
        assert len(self.emitted_tasks) == 0, "Should skip non-CVE vulnerabilities"


class TestUserFindingConversion:
    """
    PROVES: User findings generate password testing tasks
    """

    def setup_method(self):
        """Setup for each test"""
        EventBus.clear()
        self.processor = FindingsProcessor(target='192.168.45.100')
        self.emitted_tasks = []

        def capture_task(data):
            self.emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

    def test_user_finding_generates_password_test(self):
        """User findings generate common password tests"""
        finding = {
            'type': 'user',
            'description': 'admin',
            'source': 'enum4linux'
        }

        EventBus.emit('finding_added', {'finding': finding})

        # Should generate a password test task
        assert len(self.emitted_tasks) > 0, "Should generate password test for user"
        task = self.emitted_tasks[0]['task_tree']
        assert 'admin' in task['name'].lower()
        assert 'password' in task['name'].lower() or 'test' in task['name'].lower()


class TestCredentialFindingHandling:
    """
    PROVES: Credential findings are logged but don't auto-generate tasks
    """

    def setup_method(self):
        """Setup for each test"""
        EventBus.clear()
        self.processor = FindingsProcessor(target='192.168.45.100')
        self.emitted_tasks = []

        def capture_task(data):
            self.emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

    def test_credential_finding_no_auto_tasks(self):
        """Credentials don't automatically generate tasks (manual verification)"""
        finding = {
            'type': 'credential',
            'description': 'admin:password123',
            'source': 'config file'
        }

        EventBus.emit('finding_added', {'finding': finding})

        # Should NOT auto-generate tasks (requires manual verification)
        assert len(self.emitted_tasks) == 0, \
            "Credentials should not auto-generate tasks (manual verification required)"


class TestFindingDeduplication:
    """
    PROVES: Duplicate findings are detected and skipped
    """

    def setup_method(self):
        """Setup for each test"""
        EventBus.clear()
        self.processor = FindingsProcessor(target='192.168.45.100')
        self.emitted_tasks = []

        def capture_task(data):
            self.emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

    def test_duplicate_finding_skipped(self):
        """Duplicate findings don't generate multiple tasks"""
        finding = {
            'type': 'directory',
            'description': '/admin',
            'source': 'gobuster'
        }

        # Emit same finding twice
        EventBus.emit('finding_added', {'finding': finding})
        EventBus.emit('finding_added', {'finding': finding})

        # Should only generate one task
        assert len(self.emitted_tasks) == 1, \
            "Duplicate finding should be skipped"

    def test_similar_findings_with_different_sources_processed_once(self):
        """Similar findings from different sources are deduped"""
        finding1 = {
            'type': 'directory',
            'description': '/admin',
            'source': 'gobuster'
        }
        finding2 = {
            'type': 'directory',
            'description': '/admin',
            'source': 'dirb'
        }

        EventBus.emit('finding_added', {'finding': finding1})
        EventBus.emit('finding_added', {'finding': finding2})

        # Should only generate one task (same directory from different tools)
        assert len(self.emitted_tasks) == 1, \
            "Same finding from different sources should be deduped"

    def test_clear_history_resets_deduplication(self):
        """clear_history() allows reprocessing of findings"""
        finding = {
            'type': 'directory',
            'description': '/admin',
            'source': 'gobuster'
        }

        # Process finding
        EventBus.emit('finding_added', {'finding': finding})
        assert len(self.emitted_tasks) == 1

        # Clear history
        self.processor.clear_history()

        # Process again - should work
        EventBus.emit('finding_added', {'finding': finding})
        assert len(self.emitted_tasks) == 2, \
            "After clear_history, finding should be reprocessed"


class TestTaskGeneration:
    """
    PROVES: Generated tasks have correct structure and metadata
    """

    def setup_method(self):
        """Setup for each test"""
        EventBus.clear()
        self.processor = FindingsProcessor(target='192.168.45.100')
        self.emitted_tasks = []

        def capture_task(data):
            self.emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

    def test_generated_task_has_required_fields(self):
        """Generated tasks have required fields (id, name, type, status)"""
        finding = {
            'type': 'directory',
            'description': '/admin',
            'source': 'gobuster'
        }

        EventBus.emit('finding_added', {'finding': finding})

        task = self.emitted_tasks[0]['task_tree']
        assert 'id' in task, "Task missing 'id'"
        assert 'name' in task, "Task missing 'name'"
        assert 'type' in task, "Task missing 'type'"
        assert 'status' in task, "Task missing 'status'"

    def test_generated_task_has_metadata(self):
        """Generated tasks include metadata"""
        finding = {
            'type': 'directory',
            'description': '/admin',
            'source': 'gobuster'
        }

        EventBus.emit('finding_added', {'finding': finding})

        task = self.emitted_tasks[0]['task_tree']
        assert 'metadata' in task, "Task should have metadata"

    def test_generated_task_tracks_finding_source(self):
        """Generated tasks track their origin finding"""
        finding = {
            'type': 'directory',
            'description': '/admin',
            'source': 'gobuster (Task: http-enum-123)'
        }

        EventBus.emit('finding_added', {'finding': finding})

        task = self.emitted_tasks[0]['task_tree']
        metadata = task.get('metadata', {})
        assert 'finding_source' in metadata, "Task should track finding source"

    def test_generated_task_has_correct_target(self):
        """Event includes correct target"""
        finding = {
            'type': 'directory',
            'description': '/admin',
            'source': 'gobuster'
        }

        EventBus.emit('finding_added', {'finding': finding})

        event_data = self.emitted_tasks[0]
        assert event_data['target'] == '192.168.45.100', "Event should include target"


class TestErrorHandling:
    """
    PROVES: FindingsProcessor handles errors gracefully
    """

    def setup_method(self):
        """Setup for each test"""
        EventBus.clear()
        self.processor = FindingsProcessor(target='192.168.45.100')

    def test_invalid_finding_type_handled(self):
        """Invalid finding types don't crash the processor"""
        finding = {
            'type': 'invalid_type',
            'description': 'test',
            'source': 'manual'
        }

        # Should not raise exception
        try:
            EventBus.emit('finding_added', {'finding': finding})
        except Exception as e:
            pytest.fail(f"Should handle invalid finding type gracefully: {e}")

    def test_missing_finding_fields_handled(self):
        """Findings with missing fields don't crash"""
        finding = {
            'type': 'directory'
            # Missing description and source
        }

        try:
            EventBus.emit('finding_added', {'finding': finding})
        except Exception as e:
            pytest.fail(f"Should handle missing fields gracefully: {e}")

    def test_malformed_finding_data_handled(self):
        """Malformed finding data doesn't crash"""
        finding = {
            'type': 'directory',
            'description': None,  # Invalid
            'source': 'test'
        }

        try:
            EventBus.emit('finding_added', {'finding': finding})
        except Exception as e:
            pytest.fail(f"Should handle malformed data gracefully: {e}")
