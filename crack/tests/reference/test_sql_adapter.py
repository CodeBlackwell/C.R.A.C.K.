"""
Tests for SQL Command Registry Adapter

Validates that SQLCommandRegistryAdapter provides backwards-compatible
API with HybridCommandRegistry.
"""

import pytest
import sqlite3
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from crack.reference.core.sql_adapter import SQLCommandRegistryAdapter, load_registry, quick_search
from crack.reference.core.registry import Command, CommandVariable


class TestSQLCommandRegistryAdapter:
    """Test suite for SQL adapter"""

    @pytest.fixture
    def mock_repo(self):
        """Mock CommandRepository for testing"""
        with patch('db.repositories.CommandRepository') as MockRepo:
            mock_instance = MockRepo.return_value
            yield mock_instance

    @pytest.fixture
    def sample_sql_command(self):
        """Sample command in SQL format"""
        return {
            'id': 'nmap-quick-scan',
            'name': 'Quick Full Port Scan',
            'command_template': 'nmap -p- -T4 <TARGET>',
            'description': 'Fast full port scan',
            'category': 'recon',
            'subcategory': 'port-scanning',
            'notes': 'Use for initial enumeration',
            'oscp_relevance': 'high',
            'flags': [
                {'flag': '-p-', 'explanation': 'Scan all 65535 ports', 'is_required': True},
                {'flag': '-T4', 'explanation': 'Aggressive timing', 'is_required': False}
            ],
            'variables': [
                {
                    'name': '<TARGET>',
                    'description': 'Target IP address',
                    'example_value': '192.168.1.1',
                    'is_required': True,
                    'position': 1,
                    'data_type': 'string',
                    'default_value': None
                }
            ],
            'tags': [
                {'name': 'OSCP:HIGH', 'category': 'oscp', 'description': 'High priority', 'color': 'green'},
                {'name': 'QUICK_WIN', 'category': 'tactic', 'description': 'Quick win', 'color': 'yellow'}
            ],
            'success_indicators': [
                {'pattern': 'Nmap done', 'pattern_type': 'literal', 'description': 'Scan complete'}
            ],
            'failure_indicators': [
                {'pattern': 'Failed to resolve', 'pattern_type': 'literal', 'description': 'DNS error'}
            ],
            'alternatives': [],
            'prerequisites': [],
            'next_steps': []
        }

    def test_adapter_initialization(self, mock_repo):
        """Test adapter initializes correctly"""
        adapter = SQLCommandRegistryAdapter()
        assert adapter.repo is not None
        assert adapter.theme is not None
        assert adapter.config_manager is None

    def test_to_command_dataclass_conversion(self, mock_repo, sample_sql_command):
        """Test SQL result converts to Command dataclass correctly"""
        adapter = SQLCommandRegistryAdapter()
        command = adapter._to_command_dataclass(sample_sql_command)

        # Verify basic fields
        assert isinstance(command, Command)
        assert command.id == 'nmap-quick-scan'
        assert command.name == 'Quick Full Port Scan'
        assert command.command == 'nmap -p- -T4 <TARGET>'
        assert command.description == 'Fast full port scan'
        assert command.category == 'recon'
        assert command.subcategory == 'port-scanning'
        assert command.notes == 'Use for initial enumeration'
        assert command.oscp_relevance == 'high'

        # Verify variables conversion
        assert len(command.variables) == 1
        var = command.variables[0]
        assert isinstance(var, CommandVariable)
        assert var.name == '<TARGET>'
        assert var.description == 'Target IP address'
        assert var.example == '192.168.1.1'
        assert var.required is True

        # Verify tags extraction
        assert len(command.tags) == 2
        assert 'OSCP:HIGH' in command.tags
        assert 'QUICK_WIN' in command.tags

        # Verify flag_explanations dict
        assert len(command.flag_explanations) == 2
        assert command.flag_explanations['-p-'] == 'Scan all 65535 ports'
        assert command.flag_explanations['-T4'] == 'Aggressive timing'

        # Verify indicators
        assert len(command.success_indicators) == 1
        assert 'Nmap done' in command.success_indicators
        assert len(command.failure_indicators) == 1
        assert 'Failed to resolve' in command.failure_indicators

    def test_to_command_dataclass_handles_none(self, mock_repo):
        """Test conversion handles None gracefully"""
        adapter = SQLCommandRegistryAdapter()
        result = adapter._to_command_dataclass(None)
        assert result is None

    def test_get_command(self, mock_repo, sample_sql_command):
        """Test get_command returns Command dataclass"""
        mock_repo.find_by_id.return_value = sample_sql_command
        adapter = SQLCommandRegistryAdapter()

        command = adapter.get_command('nmap-quick-scan')

        mock_repo.find_by_id.assert_called_once_with('nmap-quick-scan')
        assert isinstance(command, Command)
        assert command.id == 'nmap-quick-scan'

    def test_get_command_not_found(self, mock_repo):
        """Test get_command returns None for missing command"""
        mock_repo.find_by_id.return_value = None
        adapter = SQLCommandRegistryAdapter()

        command = adapter.get_command('nonexistent')

        assert command is None

    def test_search(self, mock_repo, sample_sql_command):
        """Test search returns sorted Command list"""
        mock_repo.get_all_commands.return_value = [sample_sql_command]
        adapter = SQLCommandRegistryAdapter()

        results = adapter.search('nmap')

        assert len(results) == 1
        assert isinstance(results[0], Command)
        assert results[0].id == 'nmap-quick-scan'

    def test_search_sorting_by_relevance(self, mock_repo):
        """Test search results sorted by OSCP relevance"""
        low_priority = {
            'id': 'cmd-low',
            'name': 'Low Priority Command',
            'command_template': 'tool --flag',
            'description': 'Test',
            'category': 'custom',
            'subcategory': '',
            'notes': '',
            'oscp_relevance': 'low',
            'flags': [],
            'variables': [],
            'tags': [],
            'success_indicators': [],
            'failure_indicators': [],
            'alternatives': [],
            'prerequisites': [],
            'next_steps': []
        }

        high_priority = {
            **low_priority,
            'id': 'cmd-high',
            'name': 'High Priority Command',
            'oscp_relevance': 'high'
        }

        mock_repo.get_all_commands.return_value = [low_priority, high_priority]
        adapter = SQLCommandRegistryAdapter()

        results = adapter.search('command')

        assert len(results) == 2
        assert results[0].oscp_relevance == 'high'
        assert results[1].oscp_relevance == 'low'

    def test_filter_by_category(self, mock_repo, sample_sql_command):
        """Test filter_by_category returns commands in category"""
        mock_repo.search_by_category.return_value = [sample_sql_command]
        adapter = SQLCommandRegistryAdapter()

        results = adapter.filter_by_category('recon')

        mock_repo.search_by_category.assert_called_once_with('recon', None)
        assert len(results) == 1
        assert results[0].category == 'recon'

    def test_filter_by_category_with_subcategory(self, mock_repo, sample_sql_command):
        """Test filter_by_category with subcategory filter"""
        mock_repo.search_by_category.return_value = [sample_sql_command]
        adapter = SQLCommandRegistryAdapter()

        results = adapter.filter_by_category('recon', 'port-scanning')

        mock_repo.search_by_category.assert_called_once_with('recon', 'port-scanning')
        assert len(results) == 1
        assert results[0].subcategory == 'port-scanning'

    def test_get_subcategories(self, mock_repo, sample_sql_command):
        """Test get_subcategories returns unique subcategories"""
        cmd1 = {**sample_sql_command, 'subcategory': 'port-scanning'}
        cmd2 = {**sample_sql_command, 'id': 'cmd2', 'subcategory': 'service-enum'}
        cmd3 = {**sample_sql_command, 'id': 'cmd3', 'subcategory': 'port-scanning'}

        mock_repo.search_by_category.return_value = [cmd1, cmd2, cmd3]
        adapter = SQLCommandRegistryAdapter()

        subcats = adapter.get_subcategories('recon')

        assert len(subcats) == 2
        assert 'port-scanning' in subcats
        assert 'service-enum' in subcats
        assert subcats == sorted(subcats)  # Should be sorted

    def test_filter_by_tags(self, mock_repo, sample_sql_command):
        """Test filter_by_tags returns commands with matching tags"""
        mock_repo.search_by_tags.return_value = [sample_sql_command]
        adapter = SQLCommandRegistryAdapter()

        results = adapter.filter_by_tags(['OSCP:HIGH'])

        mock_repo.search_by_tags.assert_called_once_with(['OSCP:HIGH'], match_all=True)
        assert len(results) == 1
        assert 'OSCP:HIGH' in results[0].tags

    def test_filter_by_tags_with_exclusion(self, mock_repo, sample_sql_command):
        """Test filter_by_tags excludes specified tags"""
        mock_repo.search_by_tags.return_value = [sample_sql_command]
        adapter = SQLCommandRegistryAdapter()

        results = adapter.filter_by_tags(['OSCP:HIGH'], exclude_tags=['DEPRECATED'])

        assert len(results) == 1

        # Add a command with excluded tag
        deprecated_cmd = {
            **sample_sql_command,
            'id': 'deprecated-cmd',
            'tags': [
                {'name': 'OSCP:HIGH', 'category': 'oscp', 'description': '', 'color': ''},
                {'name': 'DEPRECATED', 'category': 'status', 'description': '', 'color': ''}
            ]
        }
        mock_repo.search_by_tags.return_value = [sample_sql_command, deprecated_cmd]

        results = adapter.filter_by_tags(['OSCP:HIGH'], exclude_tags=['DEPRECATED'])

        # Should exclude the deprecated command
        assert len(results) == 1
        assert results[0].id == 'nmap-quick-scan'

    def test_get_quick_wins(self, mock_repo, sample_sql_command):
        """Test get_quick_wins returns QUICK_WIN tagged commands"""
        mock_repo.search_by_tags.return_value = [sample_sql_command]
        adapter = SQLCommandRegistryAdapter()

        results = adapter.get_quick_wins()

        mock_repo.search_by_tags.assert_called_once_with(['QUICK_WIN'], match_all=True)
        assert len(results) == 1

    def test_get_oscp_high(self, mock_repo, sample_sql_command):
        """Test get_oscp_high returns high-relevance commands"""
        mock_repo.get_all_commands.return_value = [sample_sql_command]
        adapter = SQLCommandRegistryAdapter()

        results = adapter.get_oscp_high()

        mock_repo.get_all_commands.assert_called_once_with(oscp_only=True)
        assert len(results) == 1
        assert results[0].oscp_relevance == 'high'

    def test_get_stats(self, mock_repo, sample_sql_command):
        """Test get_stats returns comprehensive statistics"""
        mock_repo.count_commands.return_value = 100
        mock_repo.get_all_commands.return_value = [sample_sql_command]
        mock_repo.search_by_category.return_value = [sample_sql_command]
        mock_repo.search_by_tags.return_value = [sample_sql_command]

        adapter = SQLCommandRegistryAdapter()
        stats = adapter.get_stats()

        assert stats['total_commands'] == 100
        assert 'by_category' in stats
        assert 'by_subcategory' in stats
        assert 'top_tags' in stats
        assert 'quick_wins' in stats
        assert 'oscp_high' in stats

    def test_validate_schema(self, mock_repo, sample_sql_command):
        """Test validate_schema detects errors"""
        # Valid command
        valid_cmd = sample_sql_command.copy()

        # Command missing ID
        missing_id = {**valid_cmd, 'id': ''}

        # Command with undefined placeholder
        undefined_placeholder = {
            **valid_cmd,
            'command_template': 'nmap <TARGET> <UNDEFINED>',
            'variables': valid_cmd['variables']  # Only has <TARGET>
        }

        mock_repo.get_all_commands.return_value = [
            valid_cmd,
            missing_id,
            undefined_placeholder
        ]

        adapter = SQLCommandRegistryAdapter()
        errors = adapter.validate_schema()

        assert len(errors) >= 2
        assert any('missing ID' in err for err in errors)
        assert any('UNDEFINED' in err and 'not defined' in err for err in errors)

    def test_add_command_not_implemented(self, mock_repo):
        """Test add_command raises NotImplementedError"""
        adapter = SQLCommandRegistryAdapter()
        cmd = Command(
            id='test',
            name='Test',
            category='custom',
            command='echo test',
            description='Test command'
        )

        with pytest.raises(NotImplementedError):
            adapter.add_command(cmd)

    def test_save_to_json_not_implemented(self, mock_repo):
        """Test save_to_json raises NotImplementedError"""
        adapter = SQLCommandRegistryAdapter()

        with pytest.raises(NotImplementedError):
            adapter.save_to_json()

    def test_interactive_fill_basic(self, mock_repo, sample_sql_command):
        """Test interactive_fill with basic input"""
        mock_repo.find_by_id.return_value = sample_sql_command
        adapter = SQLCommandRegistryAdapter()
        command = adapter.get_command('nmap-quick-scan')

        with patch('builtins.input', return_value='192.168.1.100'):
            filled = adapter.interactive_fill(command)

        assert '<TARGET>' not in filled
        assert '192.168.1.100' in filled

    def test_interactive_fill_with_config(self, mock_repo, sample_sql_command):
        """Test interactive_fill uses config values"""
        mock_config = Mock()
        mock_config.get_placeholder_values.return_value = {'<TARGET>': '10.10.10.10'}

        adapter = SQLCommandRegistryAdapter(config_manager=mock_config)
        command = adapter._to_command_dataclass(sample_sql_command)

        with patch('builtins.input', return_value=''):  # User presses Enter
            filled = adapter.interactive_fill(command)

        assert '10.10.10.10' in filled

    def test_load_registry_convenience_function(self, mock_repo):
        """Test load_registry convenience function"""
        registry = load_registry()
        assert isinstance(registry, SQLCommandRegistryAdapter)

    def test_quick_search_convenience_function(self, mock_repo, sample_sql_command):
        """Test quick_search convenience function"""
        mock_repo.get_all_commands.return_value = [sample_sql_command]

        results = quick_search('nmap')

        assert len(results) == 1
        assert results[0].id == 'nmap-quick-scan'


class TestBackwardsCompatibility:
    """Test that adapter is API-compatible with HybridCommandRegistry"""

    @pytest.fixture
    def mock_repo(self):
        """Mock CommandRepository"""
        with patch('db.repositories.CommandRepository') as MockRepo:
            yield MockRepo.return_value

    def test_has_same_public_methods(self, mock_repo):
        """Test adapter exposes same public API as HybridCommandRegistry"""
        from crack.reference.core.registry import HybridCommandRegistry

        adapter = SQLCommandRegistryAdapter()
        registry = HybridCommandRegistry()

        # Get public methods (excluding private/magic methods)
        adapter_methods = {m for m in dir(adapter) if not m.startswith('_')}
        registry_methods = {m for m in dir(registry) if not m.startswith('_')}

        # Adapter should have all registry methods
        missing_methods = registry_methods - adapter_methods
        assert len(missing_methods) == 0, f"Missing methods: {missing_methods}"

    def test_get_command_signature_compatible(self, mock_repo):
        """Test get_command has compatible signature"""
        from crack.reference.core.registry import HybridCommandRegistry
        import inspect

        adapter = SQLCommandRegistryAdapter()
        registry = HybridCommandRegistry()

        adapter_sig = inspect.signature(adapter.get_command)
        registry_sig = inspect.signature(registry.get_command)

        # Parameter names should match
        assert list(adapter_sig.parameters.keys()) == list(registry_sig.parameters.keys())

    def test_search_signature_compatible(self, mock_repo):
        """Test search has compatible signature"""
        from crack.reference.core.registry import HybridCommandRegistry
        import inspect

        adapter = SQLCommandRegistryAdapter()
        registry = HybridCommandRegistry()

        adapter_sig = inspect.signature(adapter.search)
        registry_sig = inspect.signature(registry.search)

        assert list(adapter_sig.parameters.keys()) == list(registry_sig.parameters.keys())


class TestIntegrationWithRealDatabase:
    """Integration tests using real SQLite database"""

    def test_adapter_with_real_database(self, tmp_path):
        """Test adapter works with real database"""
        # Create temporary database
        db_path = tmp_path / 'test.db'

        # Initialize schema
        schema_path = Path(__file__).parent.parent.parent / 'db' / 'schema.sql'
        if schema_path.exists():
            conn = sqlite3.connect(str(db_path))
            with open(schema_path, 'r') as f:
                conn.executescript(f.read())
            conn.close()

            # Create adapter
            adapter = SQLCommandRegistryAdapter(str(db_path))

            # Should initialize without errors
            assert adapter.repo is not None

            # Count should be 0 for empty database
            assert adapter.repo.count_commands() == 0
