"""
Tests for Alternative Commands infrastructure

Tests prove that the core infrastructure works end-to-end:
1. Models can be created and validated
2. Context resolution works from profile/task/config
3. Executor fills variables and executes commands
4. Registry loads, indexes, and searches alternatives
5. Phase 6.4-6.5: Display integration and interactive mode
"""

import pytest
from crack.track.alternatives.models import AlternativeCommand, Variable, ExecutionResult
from crack.track.alternatives.context import ContextResolver
from crack.track.alternatives.executor import AlternativeExecutor
from crack.track.alternatives.registry import AlternativeCommandRegistry
from crack.track.core.state import TargetProfile
from crack.track.core.task_tree import TaskNode
from crack.track.formatters.console import ConsoleFormatter


class TestAlternativeModels:
    """Test data models"""

    def test_variable_creation(self):
        """PROVES: Variable model can be created with all fields"""
        var = Variable(
            name='TARGET',
            description='Target IP',
            example='192.168.45.100',
            auto_resolve=True,
            required=True
        )

        assert var.name == 'TARGET'
        assert var.auto_resolve is True
        assert var.required is True

    def test_variable_normalizes_name(self):
        """PROVES: Variable strips angle brackets from name"""
        var = Variable(name='<TARGET>')
        assert var.name == 'TARGET'

    def test_alternative_command_creation(self):
        """PROVES: AlternativeCommand can be created with minimum fields"""
        alt = AlternativeCommand(
            id='test-alt',
            name='Test Alternative',
            command_template='echo <TARGET>',
            category='test'
        )

        assert alt.id == 'test-alt'
        assert alt.command_template == 'echo <TARGET>'
        assert alt.variables == []  # Default empty list

    def test_alternative_command_with_variables(self):
        """PROVES: AlternativeCommand can have variables"""
        alt = AlternativeCommand(
            id='test-alt',
            name='Test',
            command_template='curl http://<TARGET>:<PORT>',
            category='test',
            variables=[
                Variable(name='TARGET', auto_resolve=True, required=True),
                Variable(name='PORT', auto_resolve=True, required=True)
            ]
        )

        assert len(alt.variables) == 2
        assert alt.get_variable('TARGET').name == 'TARGET'
        assert alt.get_variable('PORT').name == 'PORT'

    def test_get_required_variables(self):
        """PROVES: Can filter required variables"""
        alt = AlternativeCommand(
            id='test',
            name='Test',
            command_template='cmd',
            category='test',
            variables=[
                Variable(name='VAR1', required=True),
                Variable(name='VAR2', required=False)
            ]
        )

        required = alt.get_required_variables()
        assert len(required) == 1
        assert required[0].name == 'VAR1'


class TestContextResolver:
    """Test context resolution"""

    def test_resolve_from_profile_target(self, temp_crack_home):
        """PROVES: Can resolve TARGET from profile.target"""
        profile = TargetProfile('192.168.45.100')
        context = ContextResolver(profile=profile)

        resolved = context.resolve('TARGET')
        assert resolved == '192.168.45.100'

    def test_resolve_from_task_metadata(self, temp_crack_home):
        """PROVES: Can resolve PORT from task metadata"""
        profile = TargetProfile('192.168.45.100')
        task = TaskNode(task_id='test', name='Test', task_type='command')
        task.metadata['port'] = 80

        context = ContextResolver(profile=profile, task=task)

        resolved = context.resolve('PORT')
        assert resolved == '80'

    def test_resolve_priority_task_over_profile(self, temp_crack_home):
        """PROVES: Task metadata has higher priority than profile"""
        profile = TargetProfile('192.168.45.100')
        profile.ports[80] = {'state': 'open'}

        task = TaskNode(task_id='test', name='Test')
        task.metadata['port'] = 443

        context = ContextResolver(profile=profile, task=task)

        # Should use task port (443), not the only profile port (80)
        resolved = context.resolve('PORT')
        assert resolved == '443'

    def test_resolve_returns_none_if_not_found(self, temp_crack_home):
        """PROVES: Returns None for unknown variables"""
        profile = TargetProfile('192.168.45.100')
        context = ContextResolver(profile=profile)

        resolved = context.resolve('UNKNOWN_VAR')
        assert resolved is None

    def test_get_resolution_source(self, temp_crack_home):
        """PROVES: Can identify resolution source"""
        profile = TargetProfile('192.168.45.100')
        task = TaskNode(task_id='test', name='Test')
        task.metadata['port'] = 80

        context = ContextResolver(profile=profile, task=task)

        assert context.get_resolution_source('TARGET') == 'profile'
        assert context.get_resolution_source('PORT') == 'task'
        assert context.get_resolution_source('UNKNOWN') is None


class TestAlternativeExecutor:
    """Test command execution"""

    def test_fill_template(self):
        """PROVES: Template filling works with variables"""
        template = 'curl http://<TARGET>:<PORT>/<PATH>'
        values = {
            'TARGET': '192.168.45.100',
            'PORT': '80',
            'PATH': 'admin'
        }

        result = AlternativeExecutor._fill_template(template, values)
        assert result == 'curl http://192.168.45.100:80/admin'

    def test_auto_resolve_variables(self, temp_crack_home):
        """PROVES: Variables can be auto-resolved from context"""
        profile = TargetProfile('192.168.45.100')
        task = TaskNode(task_id='test', name='Test')
        task.metadata['port'] = 80

        context = ContextResolver(profile=profile, task=task)

        alt = AlternativeCommand(
            id='test',
            name='Test',
            command_template='nc <TARGET> <PORT>',
            category='test',
            variables=[
                Variable(name='TARGET', auto_resolve=True),
                Variable(name='PORT', auto_resolve=True)
            ]
        )

        values = AlternativeExecutor._auto_resolve_variables(alt, context)

        assert values['TARGET'] == '192.168.45.100'
        assert values['PORT'] == '80'

    def test_get_missing_required(self):
        """PROVES: Can detect missing required variables"""
        alt = AlternativeCommand(
            id='test',
            name='Test',
            command_template='cmd',
            category='test',
            variables=[
                Variable(name='VAR1', required=True),
                Variable(name='VAR2', required=True),
                Variable(name='VAR3', required=False)
            ]
        )

        values = {'VAR1': 'value1'}  # VAR2 missing

        missing = AlternativeExecutor._get_missing_required(alt, values)

        assert len(missing) == 1
        assert missing[0].name == 'VAR2'

    def test_dry_run_generates_command(self, temp_crack_home):
        """PROVES: Dry run generates command without execution"""
        profile = TargetProfile('192.168.45.100')
        context = ContextResolver(profile=profile)

        alt = AlternativeCommand(
            id='test',
            name='Test',
            command_template='echo <TARGET>',
            category='test',
            variables=[Variable(name='TARGET', auto_resolve=True)]
        )

        result = AlternativeExecutor.execute(
            alt,
            context=context,
            interactive=False,
            dry_run=True
        )

        assert result.success is True
        assert result.command == 'echo 192.168.45.100'
        assert result.output == ''  # Not executed


class TestAlternativeRegistry:
    """Test registry functionality"""

    def setUp(self):
        """Clear registry before each test"""
        AlternativeCommandRegistry.clear()

    def tearDown(self):
        """Clear registry after each test"""
        AlternativeCommandRegistry.clear()

    def test_register_alternative(self):
        """PROVES: Alternatives can be registered"""
        self.setUp()

        alt = AlternativeCommand(
            id='test-1',
            name='Test 1',
            command_template='cmd',
            category='test'
        )

        AlternativeCommandRegistry.register(alt)

        retrieved = AlternativeCommandRegistry.get('test-1')
        assert retrieved is not None
        assert retrieved.id == 'test-1'

        self.tearDown()

    def test_get_by_category(self):
        """PROVES: Can retrieve alternatives by category"""
        self.setUp()

        AlternativeCommandRegistry.register(AlternativeCommand(
            id='web-1',
            name='Web 1',
            command_template='cmd',
            category='web-enumeration'
        ))

        AlternativeCommandRegistry.register(AlternativeCommand(
            id='web-2',
            name='Web 2',
            command_template='cmd',
            category='web-enumeration'
        ))

        AlternativeCommandRegistry.register(AlternativeCommand(
            id='privesc-1',
            name='PrivEsc 1',
            command_template='cmd',
            category='privilege-escalation'
        ))

        web_alts = AlternativeCommandRegistry.get_by_category('web-enumeration')
        assert len(web_alts) == 2

        privesc_alts = AlternativeCommandRegistry.get_by_category('privilege-escalation')
        assert len(privesc_alts) == 1

        self.tearDown()

    def test_get_for_task_with_glob_pattern(self):
        """PROVES: Can retrieve alternatives for task using glob matching"""
        self.setUp()

        AlternativeCommandRegistry.register(AlternativeCommand(
            id='alt-1',
            name='Alternative 1',
            command_template='cmd',
            category='test',
            parent_task_pattern='gobuster-*'
        ))

        # Should match
        matches = AlternativeCommandRegistry.get_for_task('gobuster-80')
        assert len(matches) == 1

        # Should not match
        no_matches = AlternativeCommandRegistry.get_for_task('nikto-80')
        assert len(no_matches) == 0

        self.tearDown()

    def test_search_alternatives(self):
        """PROVES: Can search alternatives by name/description"""
        self.setUp()

        AlternativeCommandRegistry.register(AlternativeCommand(
            id='curl-check',
            name='Manual Directory Check',
            command_template='curl http://target',
            description='Use curl to manually check directories',
            category='web-enumeration'
        ))

        AlternativeCommandRegistry.register(AlternativeCommand(
            id='nc-check',
            name='Netcat Port Check',
            command_template='nc -zv target 80',
            description='Check port with netcat',
            category='network-recon'
        ))

        # Search by name
        results = AlternativeCommandRegistry.search('curl')
        assert len(results) == 1
        assert results[0].id == 'curl-check'

        # Search by description
        results = AlternativeCommandRegistry.search('netcat')
        assert len(results) == 1
        assert results[0].id == 'nc-check'

        self.tearDown()

    def test_list_categories(self):
        """PROVES: Can list all categories"""
        self.setUp()

        AlternativeCommandRegistry.register(AlternativeCommand(
            id='1', name='1', command_template='cmd', category='cat-a'
        ))
        AlternativeCommandRegistry.register(AlternativeCommand(
            id='2', name='2', command_template='cmd', category='cat-b'
        ))
        AlternativeCommandRegistry.register(AlternativeCommand(
            id='3', name='3', command_template='cmd', category='cat-a'
        ))

        categories = AlternativeCommandRegistry.list_categories()
        assert sorted(categories) == ['cat-a', 'cat-b']

        self.tearDown()


class TestEndToEnd:
    """End-to-end integration tests"""

    def test_complete_workflow(self, temp_crack_home):
        """
        PROVES: Complete workflow works end-to-end

        Workflow:
        1. Create alternative command
        2. Register in registry
        3. Retrieve from registry
        4. Execute with auto-filled variables
        5. Command executes successfully
        """
        AlternativeCommandRegistry.clear()

        # Step 1: Create alternative
        alt = AlternativeCommand(
            id='test-whoami',
            name='Check Current User',
            command_template='whoami',
            description='Display current user',
            category='test',
            variables=[],  # No variables
            tags=['TEST']
        )

        # Step 2: Register
        AlternativeCommandRegistry.register(alt)

        # Step 3: Retrieve
        retrieved = AlternativeCommandRegistry.get('test-whoami')
        assert retrieved is not None

        # Step 4 & 5: Execute
        profile = TargetProfile('test-target')
        context = ContextResolver(profile=profile)

        result = AlternativeExecutor.execute(
            retrieved,
            context=context,
            interactive=False  # No user prompts
        )

        assert result.success is True
        assert result.command == 'whoami'
        assert len(result.output) > 0  # Should have username

        AlternativeCommandRegistry.clear()


class TestPhase6DisplayIntegration:
    """Phase 6.4: Test display integration for alternative commands"""

    def test_task_node_has_alternative_ids_field(self):
        """PROVES: TaskNode metadata has alternative_ids field"""
        task = TaskNode(task_id='test-task', name='Test Task')
        
        assert 'alternative_ids' in task.metadata
        assert isinstance(task.metadata['alternative_ids'], list)
        assert task.metadata['alternative_ids'] == []

    def test_task_node_has_alternative_context_field(self):
        """PROVES: TaskNode metadata has alternative_context field"""
        task = TaskNode(task_id='test-task', name='Test Task')
        
        assert 'alternative_context' in task.metadata
        assert isinstance(task.metadata['alternative_context'], dict)

    def test_console_formatter_shows_alternative_count(self):
        """PROVES: Console formatter displays alternative count badge"""
        task = TaskNode(task_id='test-task', name='Test Task')
        task.metadata['alternative_ids'] = ['alt-1', 'alt-2', 'alt-3']
        
        formatted = ConsoleFormatter._format_task_node(task, indent=0)
        
        # Should contain alternative count badge
        assert '[3 alt]' in formatted or '3 alt' in formatted

    def test_console_format_task_details_shows_alternatives(self, temp_crack_home):
        """PROVES: Task details formatter shows linked alternatives"""
        # Clear registry and add test alternative
        AlternativeCommandRegistry.clear()
        test_alt = AlternativeCommand(
            id='test-alt-1',
            name='Test Alternative',
            command_template='echo test',
            description='Test alternative command',
            category='test',
            tags=['TEST']
        )
        AlternativeCommandRegistry.register(test_alt)
        
        # Create task with alternative_ids
        task = TaskNode(task_id='test-task', name='Test Task')
        task.metadata['alternative_ids'] = ['test-alt-1']
        
        formatted = ConsoleFormatter.format_task_details(task)
        
        # Should show alternative commands section
        assert 'Alternative Commands' in formatted
        assert 'Test Alternative' in formatted
        assert 'Test alternative command' in formatted
        
        AlternativeCommandRegistry.clear()

    def test_task_with_no_alternatives_shows_nothing(self):
        """PROVES: Tasks without alternatives don't show alternative section"""
        task = TaskNode(task_id='test-task', name='Test Task')
        # No alternative_ids set
        
        formatted = ConsoleFormatter._format_task_node(task, indent=0)
        
        # Should NOT contain alternative badge
        assert 'alt]' not in formatted


class TestPhase6InteractiveIntegration:
    """Phase 6.5: Test interactive mode integration"""

    def test_auto_link_to_task_pattern_matching(self, temp_crack_home):
        """PROVES: Auto-linking works via pattern matching"""
        AlternativeCommandRegistry.clear()
        
        # Register alternative with parent_task_pattern
        alt = AlternativeCommand(
            id='gobuster-alt',
            name='Manual Directory Check',
            command_template='curl <TARGET>',
            description='Manual alternative to gobuster',
            category='web-enumeration',
            parent_task_pattern='gobuster-*'  # Pattern for gobuster tasks
        )
        AlternativeCommandRegistry.register(alt)
        
        # Create task that matches pattern
        task = TaskNode(task_id='gobuster-80', name='Gobuster Port 80')
        
        # Auto-link
        linked_ids = AlternativeCommandRegistry.auto_link_to_task(task)
        
        assert 'gobuster-alt' in linked_ids
        
        AlternativeCommandRegistry.clear()

    def test_auto_link_by_service_type(self, temp_crack_home):
        """PROVES: Auto-linking works via service metadata"""
        AlternativeCommandRegistry.clear()
        
        # Register alternative with service type
        alt = AlternativeCommand(
            id='http-manual-check',
            name='Manual HTTP Check',
            command_template='curl http://<TARGET>',
            description='Manual HTTP verification',
            category='web-enumeration',
            subcategory='http-methods'  # Will extract 'http' service
        )
        AlternativeCommandRegistry.register(alt)
        
        # Create task with service metadata
        task = TaskNode(task_id='whatweb-80', name='WhatWeb Port 80')
        task.metadata['service'] = 'http'
        
        # Auto-link
        linked_ids = AlternativeCommandRegistry.auto_link_to_task(task)
        
        assert 'http-manual-check' in linked_ids
        
        AlternativeCommandRegistry.clear()

    def test_auto_link_by_tags(self, temp_crack_home):
        """PROVES: Auto-linking works via task tags"""
        AlternativeCommandRegistry.clear()
        
        # Register alternative with tags
        alt = AlternativeCommand(
            id='quick-win-alt',
            name='Quick Win Command',
            command_template='echo quick',
            description='Quick win alternative',
            category='test',
            tags=['QUICK_WIN']
        )
        AlternativeCommandRegistry.register(alt)
        
        # Create task with matching tag
        task = TaskNode(task_id='test-task', name='Test Task')
        task.metadata['tags'] = ['QUICK_WIN', 'OSCP:HIGH']
        
        # Auto-link
        linked_ids = AlternativeCommandRegistry.auto_link_to_task(task)
        
        assert 'quick-win-alt' in linked_ids
        
        AlternativeCommandRegistry.clear()

    def test_context_hints_propagate_to_resolver(self, temp_crack_home):
        """PROVES: Context hints from task metadata pass to ContextResolver.resolve()"""
        # Create task with alternative_context hints
        task = TaskNode(task_id='gobuster-80', name='Gobuster Port 80')
        task.metadata['alternative_context'] = {
            'service': 'http',
            'port': 80,
            'purpose': 'web-enumeration'
        }

        # Create context resolver
        profile = TargetProfile('192.168.45.100')
        context = ContextResolver(
            profile=profile,
            task=task,
            auto_load_config=False
        )

        # Verify hints can be used in resolve()
        context_hints = task.metadata['alternative_context']

        # Resolve WORDLIST with context hints
        wordlist = context.resolve('WORDLIST', context_hints=context_hints)

        # Should get web wordlist based on purpose
        assert wordlist is not None
        assert 'dirb' in wordlist or 'common' in wordlist

    def test_task_metadata_preserves_backward_compatibility(self):
        """PROVES: Old 'alternatives' field still exists for backward compatibility"""
        task = TaskNode(task_id='test-task', name='Test Task')
        
        # Old field still exists
        assert 'alternatives' in task.metadata
        
        # New fields also exist
        assert 'alternative_ids' in task.metadata
        assert 'alternative_context' in task.metadata

    def test_deduplication_in_auto_link(self, temp_crack_home):
        """PROVES: Auto-linking deduplicates alternatives matched multiple ways"""
        AlternativeCommandRegistry.clear()
        
        # Register alternative that matches multiple ways
        alt = AlternativeCommand(
            id='multi-match-alt',
            name='Multi Match Alternative',
            command_template='echo test',
            description='Matches by pattern, service, and tag',
            category='web-enumeration',
            parent_task_pattern='http-*',
            subcategory='http-methods',
            tags=['OSCP:HIGH']
        )
        AlternativeCommandRegistry.register(alt)
        
        # Create task that matches all three ways
        task = TaskNode(task_id='http-enum-80', name='HTTP Enum Port 80')
        task.metadata['service'] = 'http'
        task.metadata['tags'] = ['OSCP:HIGH']
        
        # Auto-link
        linked_ids = AlternativeCommandRegistry.auto_link_to_task(task)
        
        # Should only appear once despite matching 3 ways
        assert linked_ids.count('multi-match-alt') == 1
        
        AlternativeCommandRegistry.clear()
