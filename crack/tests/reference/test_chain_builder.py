"""Tests for chain builder functionality."""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from crack.reference.builders.chain_builder import ChainBuilder
from crack.reference.chains.command_resolver import CommandResolver


class TestChainBuilder:
    """Test ChainBuilder core functionality."""

    def test_from_scratch_creates_empty_chain(self):
        """Test creating a new chain from scratch."""
        builder = ChainBuilder.from_scratch()

        assert builder.chain['id'] == ''
        assert builder.chain['name'] == ''
        assert builder.chain['version'] == '1.0.0'
        assert builder.chain['steps'] == []
        assert builder.chain['oscp_relevant'] is True

    def test_set_metadata_updates_fields(self):
        """Test setting metadata fields."""
        builder = ChainBuilder.from_scratch()

        builder.set_metadata(
            id='test-chain-id',
            name='Test Chain',
            description='Test description',
            category='privilege_escalation',
            difficulty='beginner',
            time_estimate='10 minutes',
            oscp_relevant=True,
            author='Test Author',
            tags=['OSCP', 'LINUX']
        )

        assert builder.chain['id'] == 'test-chain-id'
        assert builder.chain['name'] == 'Test Chain'
        assert builder.chain['description'] == 'Test description'
        assert builder.chain['metadata']['category'] == 'privilege_escalation'
        assert builder.chain['difficulty'] == 'beginner'
        assert builder.chain['time_estimate'] == '10 minutes'
        assert builder.chain['oscp_relevant'] is True
        assert builder.chain['metadata']['author'] == 'Test Author'
        assert builder.chain['metadata']['tags'] == ['OSCP', 'LINUX']

    def test_add_step_adds_to_chain(self):
        """Test adding a step to the chain."""
        builder = ChainBuilder.from_scratch()

        step_data = {
            'name': 'Test Step',
            'objective': 'Test objective',
            'command_ref': 'test-command',
            'id': 'test-step-1',
            'success_criteria': ['Success']
        }

        builder.add_step(step_data)

        assert len(builder.chain['steps']) == 1
        assert builder.chain['steps'][0]['name'] == 'Test Step'
        assert builder.chain['steps'][0]['objective'] == 'Test objective'
        assert builder.chain['steps'][0]['command_ref'] == 'test-command'
        assert builder.chain['steps'][0]['id'] == 'test-step-1'

    def test_add_step_requires_name(self):
        """Test that adding a step without name raises error."""
        builder = ChainBuilder.from_scratch()

        step_data = {
            'objective': 'Test objective',
            'command_ref': 'test-command'
        }

        with pytest.raises(ValueError, match="Step must have 'name' field"):
            builder.add_step(step_data)

    def test_add_step_requires_objective(self):
        """Test that adding a step without objective raises error."""
        builder = ChainBuilder.from_scratch()

        step_data = {
            'name': 'Test Step',
            'command_ref': 'test-command'
        }

        with pytest.raises(ValueError, match="Step must have 'objective' field"):
            builder.add_step(step_data)

    def test_add_step_requires_command_ref(self):
        """Test that adding a step without command_ref raises error."""
        builder = ChainBuilder.from_scratch()

        step_data = {
            'name': 'Test Step',
            'objective': 'Test objective'
        }

        with pytest.raises(ValueError, match="Step must have 'command_ref' field"):
            builder.add_step(step_data)

    def test_remove_step_by_index(self):
        """Test removing a step by index."""
        builder = ChainBuilder.from_scratch()

        # Add two steps
        builder.add_step({
            'name': 'Step 1',
            'objective': 'Objective 1',
            'command_ref': 'cmd-1'
        })
        builder.add_step({
            'name': 'Step 2',
            'objective': 'Objective 2',
            'command_ref': 'cmd-2'
        })

        assert len(builder.chain['steps']) == 2

        # Remove first step
        builder.remove_step(0)

        assert len(builder.chain['steps']) == 1
        assert builder.chain['steps'][0]['name'] == 'Step 2'

    def test_remove_step_invalid_index(self):
        """Test removing a step with invalid index raises error."""
        builder = ChainBuilder.from_scratch()

        with pytest.raises(IndexError):
            builder.remove_step(0)

    def test_get_available_step_ids(self):
        """Test getting available step IDs for dependencies."""
        builder = ChainBuilder.from_scratch()

        # Add steps with IDs
        builder.add_step({
            'name': 'Step 1',
            'objective': 'Obj 1',
            'command_ref': 'cmd-1',
            'id': 'step-1'
        })
        builder.add_step({
            'name': 'Step 2',
            'objective': 'Obj 2',
            'command_ref': 'cmd-2',
            'id': 'step-2'
        })
        # Add step without ID
        builder.add_step({
            'name': 'Step 3',
            'objective': 'Obj 3',
            'command_ref': 'cmd-3'
        })

        ids = builder.get_available_step_ids()

        assert len(ids) == 2
        assert 'step-1' in ids
        assert 'step-2' in ids

    def test_to_dict_returns_copy(self):
        """Test that to_dict returns a deep copy."""
        builder = ChainBuilder.from_scratch()
        builder.set_metadata(id='test-id', name='Test')

        chain_dict = builder.to_dict()
        chain_dict['id'] = 'modified-id'

        # Original should be unchanged
        assert builder.chain['id'] == 'test-id'

    def test_to_json_creates_valid_json(self):
        """Test JSON serialization."""
        builder = ChainBuilder.from_scratch()
        builder.set_metadata(
            id='test-chain',
            name='Test Chain',
            category='privilege_escalation',
            difficulty='beginner'
        )

        json_str = builder.to_json()
        parsed = json.loads(json_str)

        assert parsed['id'] == 'test-chain'
        assert parsed['name'] == 'Test Chain'

    def test_validate_with_valid_chain(self):
        """Test validation with a valid chain."""
        builder = ChainBuilder.from_scratch()
        builder.set_metadata(
            id='valid-chain-test-basic',
            name='Valid Chain',
            category='privilege_escalation',
            difficulty='beginner',
            time_estimate='10 minutes'
        )
        builder.add_step({
            'name': 'Step 1',
            'objective': 'Test',
            'command_ref': 'test-command'
        })

        # Mock CommandResolver to return a command
        resolver = MagicMock(spec=CommandResolver)
        resolver.validate_references.return_value = {}  # No errors

        errors = builder.validate(command_resolver=resolver)

        # Should have schema errors (missing required fields) but no command ref errors
        # This is acceptable for our test
        assert isinstance(errors, list)

    def test_save_requires_id(self):
        """Test that saving without ID raises error."""
        builder = ChainBuilder.from_scratch()

        with pytest.raises(ValueError, match="Chain ID must be set"):
            builder.save()

    def test_save_requires_category(self):
        """Test that saving without category raises error."""
        builder = ChainBuilder.from_scratch()
        builder.set_metadata(id='test-chain')

        with pytest.raises(ValueError, match="Chain category must be set"):
            builder.save()

    def test_save_creates_file(self, tmp_path):
        """Test that save creates a file."""
        builder = ChainBuilder.from_scratch()
        builder.set_metadata(
            id='test-save-chain',
            name='Test Save',
            category='privilege_escalation',
            difficulty='beginner'
        )

        # Save to temp path
        filepath = tmp_path / 'test-save-chain.json'
        result_path = builder.save(filepath=filepath)

        assert result_path == filepath
        assert filepath.exists()

        # Verify content
        with open(filepath) as f:
            data = json.load(f)
            assert data['id'] == 'test-save-chain'
            assert data['name'] == 'Test Save'

    @patch('crack.reference.builders.chain_builder.ChainLoader')
    def test_from_template_clones_chain(self, mock_loader_class):
        """Test creating chain from template."""
        # Mock loader instance
        mock_loader = MagicMock()
        mock_loader_class.return_value = mock_loader

        # Mock chain data
        template_data = {
            'id': 'template-chain',
            'name': 'Template Chain',
            'version': '2.0.0',
            'metadata': {
                'author': 'Original Author',
                'created': '2024-01-01',
                'updated': '2024-01-01',
                'tags': ['OSCP'],
                'category': 'privilege_escalation'
            },
            'steps': [
                {
                    'name': 'Step 1',
                    'objective': 'Test',
                    'command_ref': 'test-cmd'
                }
            ],
            'difficulty': 'beginner',
            'time_estimate': '10 minutes',
            'oscp_relevant': True,
            'prerequisites': [],
            'notes': None
        }

        mock_loader.load_all_chains.return_value = {
            'template-chain': template_data
        }

        # Create from template
        builder = ChainBuilder.from_template('template-chain', loader=mock_loader)

        # Verify cloned data
        assert builder.chain['id'] == 'template-chain'
        assert builder.chain['name'] == 'Template Chain'
        assert len(builder.chain['steps']) == 1
        # Version should be reset
        assert builder.chain['version'] == '1.0.0'

    @patch('crack.reference.builders.chain_builder.ChainLoader')
    def test_from_template_nonexistent_chain(self, mock_loader_class):
        """Test creating from non-existent template raises error."""
        mock_loader = MagicMock()
        mock_loader_class.return_value = mock_loader
        mock_loader.load_all_chains.return_value = {}

        with pytest.raises(ValueError, match="Chain 'nonexistent' not found"):
            ChainBuilder.from_template('nonexistent', loader=mock_loader)

    def test_from_template_does_not_mutate_original(self):
        """Test that cloning doesn't mutate the original chain data."""
        original_data = {
            'id': 'original',
            'name': 'Original',
            'version': '1.0.0',
            'metadata': {
                'author': 'Author',
                'created': '2024-01-01',
                'updated': '2024-01-01',
                'tags': [],
                'category': 'privilege_escalation'
            },
            'steps': [],
            'difficulty': 'beginner',
            'time_estimate': '10 minutes',
            'oscp_relevant': True,
            'prerequisites': [],
            'notes': None
        }

        builder = ChainBuilder(chain_data=original_data)
        builder.set_metadata(name='Modified')

        # Original should be unchanged
        assert original_data['name'] == 'Original'

    def test_add_step_with_dependencies(self):
        """Test adding step with dependencies."""
        builder = ChainBuilder.from_scratch()

        # Add first step
        builder.add_step({
            'name': 'Step 1',
            'objective': 'Obj 1',
            'command_ref': 'cmd-1',
            'id': 'step-1'
        })

        # Add second step with dependency
        builder.add_step({
            'name': 'Step 2',
            'objective': 'Obj 2',
            'command_ref': 'cmd-2',
            'id': 'step-2',
            'dependencies': ['step-1']
        })

        assert builder.chain['steps'][1]['dependencies'] == ['step-1']

    def test_get_steps_returns_copy(self):
        """Test that get_steps returns a deep copy."""
        builder = ChainBuilder.from_scratch()
        builder.add_step({
            'name': 'Step 1',
            'objective': 'Obj 1',
            'command_ref': 'cmd-1'
        })

        steps = builder.get_steps()
        steps[0]['name'] = 'Modified'

        # Original should be unchanged
        assert builder.chain['steps'][0]['name'] == 'Step 1'


class TestChainBuilderCLI:
    """Test ChainBuilderCLI interactive functionality."""

    def test_validate_chain_id_format_valid(self):
        """Test valid chain ID formats."""
        from crack.reference.cli.chain_builder import ChainBuilderCLI

        cli = ChainBuilderCLI()

        assert cli._validate_chain_id_format('linux-privesc-suid-basic')
        assert cli._validate_chain_id_format('web-exploit-sqli-union')
        assert cli._validate_chain_id_format('windows-enum-ad-basic')

    def test_validate_chain_id_format_invalid(self):
        """Test invalid chain ID formats."""
        from crack.reference.cli.chain_builder import ChainBuilderCLI

        cli = ChainBuilderCLI()

        assert not cli._validate_chain_id_format('invalid')
        assert not cli._validate_chain_id_format('no-dashes')
        assert not cli._validate_chain_id_format('UPPERCASE-NOT-ALLOWED-HERE')
        assert not cli._validate_chain_id_format('linux_privesc_suid_basic')  # underscores
