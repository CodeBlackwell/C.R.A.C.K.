"""
Tests for CorrelationIntelligence - Reactive event-driven task generation

Tests cover:
1. Initialization and event handler registration
2. Credential spray generation
3. Username task generation
4. Attack chain triggers
5. Deduplication
6. Edge cases and error handling
"""

import pytest
from unittest.mock import Mock, patch
from crack.track.intelligence.correlation_engine import CorrelationIntelligence
from crack.track.core.state import TargetProfile
from crack.track.core.events import EventBus


@pytest.fixture
def mock_profile():
    """Create mock TargetProfile with services"""
    profile = Mock(spec=TargetProfile)
    profile.target = '192.168.45.100'
    profile.ports = {
        22: {'state': 'open', 'service': 'ssh', 'version': 'OpenSSH 8.2'},
        3306: {'state': 'open', 'service': 'mysql', 'version': 'MySQL 5.7'},
        445: {'state': 'open', 'service': 'smb', 'version': 'Samba 4.11'},
        80: {'state': 'open', 'service': 'http', 'version': 'Apache 2.4'},
        8080: {'state': 'closed', 'service': 'http-proxy', 'version': None}
    }
    return profile


@pytest.fixture
def correlation_engine(mock_profile):
    """Create CorrelationIntelligence instance"""
    EventBus.clear()  # Clear any existing handlers
    config = {'intelligence': {'correlation': {'enabled': True}}}
    return CorrelationIntelligence('192.168.45.100', mock_profile, config)


@pytest.fixture(autouse=True)
def cleanup_event_bus():
    """Clear EventBus after each test"""
    yield
    EventBus.clear()


class TestInitialization:
    """Test engine initialization and setup"""

    def test_initialization_registers_handlers(self, mock_profile):
        """Handler registered on EventBus during init"""
        EventBus.clear()
        config = {'intelligence': {'correlation': {'enabled': True}}}

        engine = CorrelationIntelligence('192.168.45.100', mock_profile, config)

        handlers = EventBus.get_handlers('finding_added')
        assert len(handlers) > 0
        assert engine.on_finding_added in handlers

    def test_initialization_sets_attributes(self, mock_profile):
        """All attributes properly initialized"""
        config = {'intelligence': {'correlation': {'enabled': True}}}

        engine = CorrelationIntelligence('192.168.45.100', mock_profile, config)

        assert engine.target == '192.168.45.100'
        assert engine.profile == mock_profile
        assert engine.config == config
        assert isinstance(engine.processed_findings, set)
        assert len(engine.processed_findings) == 0


class TestCredentialSpray:
    """Test credential spray task generation"""

    def test_credential_finding_generates_spray_tasks(self, correlation_engine):
        """Credential finding generates tasks for all auth services"""
        # Mock task emission
        emitted_tasks = []

        def capture_task(data):
            emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

        # Emit credential finding
        finding = {
            'type': 'credential',
            'description': 'admin:password123',
            'source': 'mysql'
        }

        EventBus.emit('finding_added', {'finding': finding})

        # Should generate spray tasks for SSH, MySQL, SMB (not closed port)
        assert len(emitted_tasks) == 3

        # Verify task structure
        task_names = [t['task_tree']['name'] for t in emitted_tasks]
        assert any('ssh:22' in name for name in task_names)
        assert any('mysql:3306' in name for name in task_names)
        assert any('smb:445' in name for name in task_names)

        # Verify metadata
        for task_data in emitted_tasks:
            task = task_data['task_tree']
            assert task['type'] == 'executable'
            assert task['status'] == 'pending'
            assert task['metadata']['intelligence_source'] == 'correlation'
            assert task['metadata']['oscp_likelihood'] == 0.7

    def test_credential_dict_format(self, correlation_engine):
        """Credential in dict format parsed correctly"""
        emitted_tasks = []

        def capture_task(data):
            emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

        finding = {
            'type': 'credential_found',
            'description': {'username': 'root', 'password': 'toor'},
            'source': 'database'
        }

        EventBus.emit('finding_added', {'finding': finding})

        assert len(emitted_tasks) > 0
        # Verify root credential used in commands
        commands = [t['task_tree']['metadata']['command'] for t in emitted_tasks]
        assert any('root' in cmd and 'toor' in cmd for cmd in commands)

    def test_no_services_no_spray_tasks(self, mock_profile):
        """No auth services = no spray tasks generated"""
        # Profile with no auth services
        mock_profile.ports = {
            80: {'state': 'open', 'service': 'http', 'version': 'Apache 2.4'}
        }

        engine = CorrelationIntelligence('192.168.45.100', mock_profile, {})

        emitted_tasks = []

        def capture_task(data):
            emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

        finding = {
            'type': 'credential',
            'description': 'admin:password',
            'source': 'test'
        }

        EventBus.emit('finding_added', {'finding': finding})

        assert len(emitted_tasks) == 0

    def test_credential_without_username_skipped(self, correlation_engine):
        """Malformed credential without username skipped"""
        emitted_tasks = []

        def capture_task(data):
            emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

        finding = {
            'type': 'credential',
            'description': '',  # Empty description
            'source': 'test'
        }

        EventBus.emit('finding_added', {'finding': finding})

        assert len(emitted_tasks) == 0

    def test_closed_ports_not_sprayed(self, correlation_engine):
        """Closed ports excluded from spray"""
        emitted_tasks = []

        def capture_task(data):
            emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

        finding = {
            'type': 'credential',
            'description': 'admin:password',
            'source': 'test'
        }

        EventBus.emit('finding_added', {'finding': finding})

        # Verify port 8080 (closed) not in tasks
        task_names = [t['task_tree']['name'] for t in emitted_tasks]
        assert not any('8080' in name for name in task_names)

    def test_service_specific_commands(self, correlation_engine):
        """Service-specific commands generated correctly"""
        emitted_tasks = []

        def capture_task(data):
            emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

        finding = {
            'type': 'credential',
            'description': 'admin:password',
            'source': 'test'
        }

        EventBus.emit('finding_added', {'finding': finding})

        # Verify service-specific command formats
        commands = {t['task_tree']['name']: t['task_tree']['metadata']['command']
                    for t in emitted_tasks}

        # SSH command
        ssh_cmd = next((cmd for name, cmd in commands.items() if 'ssh:22' in name), None)
        assert ssh_cmd
        assert 'sshpass' in ssh_cmd
        assert 'admin@192.168.45.100' in ssh_cmd

        # MySQL command
        mysql_cmd = next((cmd for name, cmd in commands.items() if 'mysql:3306' in name), None)
        assert mysql_cmd
        assert 'mysql' in mysql_cmd
        assert '-u admin' in mysql_cmd


class TestUsernameGeneration:
    """Test username-based task generation"""

    def test_username_generates_password_test(self, correlation_engine):
        """Username finding generates password testing task"""
        emitted_tasks = []

        def capture_task(data):
            emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

        finding = {
            'type': 'user',
            'description': 'admin',
            'source': 'enum4linux'
        }

        EventBus.emit('finding_added', {'finding': finding})

        assert len(emitted_tasks) == 1
        task = emitted_tasks[0]['task_tree']
        assert 'Test common passwords' in task['name']
        assert 'admin' in task['name']
        assert 'admin:admin' in task['metadata']['command']
        assert task['metadata']['oscp_likelihood'] == 0.6

    def test_username_dict_format(self, correlation_engine):
        """Username in dict format parsed correctly"""
        emitted_tasks = []

        def capture_task(data):
            emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

        finding = {
            'type': 'user_found',
            'description': {'username': 'john.doe'},
            'source': 'ldap'
        }

        EventBus.emit('finding_added', {'finding': finding})

        assert len(emitted_tasks) == 1
        task = emitted_tasks[0]['task_tree']
        assert 'john.doe' in task['name']

    def test_empty_username_skipped(self, correlation_engine):
        """Empty username skipped gracefully"""
        emitted_tasks = []

        def capture_task(data):
            emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

        finding = {
            'type': 'user',
            'description': '',
            'source': 'test'
        }

        EventBus.emit('finding_added', {'finding': finding})

        assert len(emitted_tasks) == 0


class TestChainTriggers:
    """Test attack chain trigger detection"""

    def test_sqli_triggers_chain(self, correlation_engine):
        """SQLi finding triggers sqli_to_shell chain"""
        emitted_tasks = []

        def capture_task(data):
            emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

        finding = {
            'type': 'sql_injection',
            'description': 'SQLi found in id parameter',
            'source': 'manual'
        }

        EventBus.emit('finding_added', {'finding': finding})

        assert len(emitted_tasks) == 1
        task = emitted_tasks[0]['task_tree']
        assert task['type'] == 'notification'
        assert 'sqli_to_shell' in task['metadata']['chain_name']
        assert task['metadata']['in_attack_chain'] is True

    def test_lfi_triggers_chain(self, correlation_engine):
        """LFI finding triggers lfi_to_rce chain"""
        emitted_tasks = []

        def capture_task(data):
            emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

        finding = {
            'type': 'lfi_found',
            'description': 'LFI in page parameter',
            'source': 'ffuf'
        }

        EventBus.emit('finding_added', {'finding': finding})

        assert len(emitted_tasks) == 1
        task = emitted_tasks[0]['task_tree']
        assert 'lfi_to_rce' in task['metadata']['chain_name']

    def test_ssti_triggers_chain(self, correlation_engine):
        """SSTI finding triggers ssti_to_rce chain"""
        emitted_tasks = []

        def capture_task(data):
            emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

        finding = {
            'type': 'ssti',
            'description': 'SSTI in template',
            'source': 'manual'
        }

        EventBus.emit('finding_added', {'finding': finding})

        assert len(emitted_tasks) == 1
        task = emitted_tasks[0]['task_tree']
        assert 'ssti_to_rce' in task['metadata']['chain_name']

    def test_deserialization_triggers_chain(self, correlation_engine):
        """Deserialization finding triggers deser_to_rce chain"""
        emitted_tasks = []

        def capture_task(data):
            emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

        finding = {
            'type': 'deserialization_vulnerability',
            'description': 'Unsafe deserialization',
            'source': 'ysoserial'
        }

        EventBus.emit('finding_added', {'finding': finding})

        assert len(emitted_tasks) == 1
        task = emitted_tasks[0]['task_tree']
        assert 'deser_to_rce' in task['metadata']['chain_name']

    def test_all_chain_trigger_aliases(self, correlation_engine):
        """All chain trigger aliases detected"""
        # Test key aliases for each chain type
        test_cases = [
            ('sqli', 'sqli_to_shell'),
            ('sqli_found', 'sqli_to_shell'),
            ('lfi', 'lfi_to_rce'),
            ('cmdi', 'cmdi_to_shell'),
            ('command_injection', 'cmdi_to_shell'),
            ('rce', 'rce_to_shell'),
            ('file_upload', 'upload_to_shell'),
            ('xxe', 'xxe_to_data_exfil'),
        ]

        for finding_type, expected_chain in test_cases:
            chain = correlation_engine._detect_chain_trigger(finding_type)
            assert chain == expected_chain, f"Failed for {finding_type}"


class TestDeduplication:
    """Test finding deduplication logic"""

    def test_duplicate_finding_not_processed_twice(self, correlation_engine):
        """Same finding processed only once"""
        emitted_tasks = []

        def capture_task(data):
            emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

        finding = {
            'type': 'credential',
            'description': 'admin:password',
            'source': 'test'
        }

        # Emit same finding twice
        EventBus.emit('finding_added', {'finding': finding})
        initial_count = len(emitted_tasks)

        EventBus.emit('finding_added', {'finding': finding})
        final_count = len(emitted_tasks)

        # Should not generate duplicate tasks
        assert final_count == initial_count

    def test_different_findings_both_processed(self, correlation_engine):
        """Different findings both processed"""
        emitted_tasks = []

        def capture_task(data):
            emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

        finding1 = {
            'type': 'credential',
            'description': 'admin:password',
            'source': 'test'
        }

        finding2 = {
            'type': 'credential',
            'description': 'root:toor',
            'source': 'test'
        }

        EventBus.emit('finding_added', {'finding': finding1})
        count1 = len(emitted_tasks)

        EventBus.emit('finding_added', {'finding': finding2})
        count2 = len(emitted_tasks)

        # Both should generate tasks
        assert count2 > count1

    def test_clear_history_resets_deduplication(self, correlation_engine):
        """clear_history() allows reprocessing"""
        emitted_tasks = []

        def capture_task(data):
            emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

        finding = {
            'type': 'user',
            'description': 'admin',
            'source': 'test'
        }

        # Process once
        EventBus.emit('finding_added', {'finding': finding})
        initial_count = len(emitted_tasks)

        # Clear history
        correlation_engine.clear_history()

        # Process again
        EventBus.emit('finding_added', {'finding': finding})
        final_count = len(emitted_tasks)

        # Should generate tasks again
        assert final_count > initial_count


class TestEdgeCases:
    """Test edge cases and error handling"""

    def test_empty_finding_data_handled(self, correlation_engine):
        """Empty finding data handled gracefully"""
        emitted_tasks = []

        def capture_task(data):
            emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

        # Empty event data
        EventBus.emit('finding_added', {})

        # Should not crash
        assert len(emitted_tasks) == 0

    def test_missing_finding_type_handled(self, correlation_engine):
        """Missing finding type handled gracefully"""
        emitted_tasks = []

        def capture_task(data):
            emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

        finding = {
            'description': 'test',
            'source': 'test'
            # Missing 'type' key
        }

        EventBus.emit('finding_added', {'finding': finding})

        # Should not crash
        assert len(emitted_tasks) == 0

    def test_unknown_finding_type_ignored(self, correlation_engine):
        """Unknown finding types ignored gracefully"""
        emitted_tasks = []

        def capture_task(data):
            emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

        finding = {
            'type': 'unknown_type',
            'description': 'test',
            'source': 'test'
        }

        EventBus.emit('finding_added', {'finding': finding})

        # Should not generate tasks
        assert len(emitted_tasks) == 0

    def test_get_correlation_tasks_returns_empty(self, correlation_engine):
        """get_correlation_tasks() returns empty list (event-driven)"""
        tasks = correlation_engine.get_correlation_tasks()
        assert tasks == []


class TestTaskStructure:
    """Test generated task structure and metadata"""

    def test_task_has_required_fields(self, correlation_engine):
        """Generated tasks have all required fields"""
        emitted_tasks = []

        def capture_task(data):
            emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

        finding = {
            'type': 'user',
            'description': 'admin',
            'source': 'test'
        }

        EventBus.emit('finding_added', {'finding': finding})

        task = emitted_tasks[0]['task_tree']

        # Required fields
        assert 'id' in task
        assert 'name' in task
        assert 'type' in task
        assert 'status' in task
        assert 'metadata' in task
        assert task['status'] == 'pending'

    def test_task_metadata_complete(self, correlation_engine):
        """Task metadata contains intelligence markers"""
        emitted_tasks = []

        def capture_task(data):
            emitted_tasks.append(data)

        EventBus.on('plugin_tasks_generated', capture_task)

        finding = {
            'type': 'credential',
            'description': 'admin:password',
            'source': 'test'
        }

        EventBus.emit('finding_added', {'finding': finding})

        task = emitted_tasks[0]['task_tree']
        metadata = task['metadata']

        assert 'intelligence_source' in metadata
        assert metadata['intelligence_source'] == 'correlation'
        assert 'command' in metadata
        assert 'category' in metadata

    def test_event_emission_structure(self, correlation_engine):
        """Event emission has correct structure"""
        emitted_events = []

        def capture_event(data):
            emitted_events.append(data)

        EventBus.on('plugin_tasks_generated', capture_event)

        finding = {
            'type': 'user',
            'description': 'admin',
            'source': 'test'
        }

        EventBus.emit('finding_added', {'finding': finding})

        event = emitted_events[0]

        assert 'target' in event
        assert 'task_tree' in event
        assert 'source' in event
        assert event['target'] == '192.168.45.100'
        assert event['source'] == 'correlation'
