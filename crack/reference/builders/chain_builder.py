"""Core chain builder logic for creating and modifying attack chains."""

import copy
import json
from datetime import date
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..chains.validator import ChainValidator
from ..chains.command_resolver import CommandResolver
from ..chains.loader import ChainLoader


class ChainBuilder:
    """Builder for creating and modifying attack chains."""

    def __init__(self, chain_data: Optional[Dict[str, Any]] = None):
        """
        Initialize chain builder.

        Args:
            chain_data: Optional existing chain data to modify
        """
        if chain_data:
            # Deep copy to avoid mutating original
            self.chain = copy.deepcopy(chain_data)
        else:
            # Initialize empty chain structure
            self.chain = {
                'id': '',
                'name': '',
                'description': '',
                'version': '1.0.0',
                'metadata': {
                    'author': '',
                    'created': date.today().isoformat(),
                    'updated': date.today().isoformat(),
                    'tags': [],
                    'category': '',
                    'platform': None,
                    'references': []
                },
                'difficulty': 'beginner',
                'time_estimate': '',
                'oscp_relevant': True,
                'steps': [],
                'prerequisites': [],
                'notes': None
            }

    @classmethod
    def from_scratch(cls) -> 'ChainBuilder':
        """Create a new chain from scratch."""
        return cls(chain_data=None)

    @classmethod
    def from_template(cls, chain_id: str, loader: Optional[ChainLoader] = None) -> 'ChainBuilder':
        """
        Create a new chain by cloning an existing one.

        Args:
            chain_id: ID of chain to use as template
            loader: Optional ChainLoader instance (creates default if None)

        Returns:
            ChainBuilder instance with cloned chain data

        Raises:
            ValueError: If chain_id not found
        """
        if loader is None:
            loader = ChainLoader()

        # Load all chains to find the template
        data_dir = Path(__file__).parent.parent / 'data' / 'attack_chains'
        all_chains = loader.load_all_chains([data_dir])

        if chain_id not in all_chains:
            raise ValueError(f"Chain '{chain_id}' not found")

        template_chain = all_chains[chain_id]
        builder = cls(chain_data=template_chain)

        # Reset metadata for new chain
        builder.chain['version'] = '1.0.0'
        builder.chain['metadata']['created'] = date.today().isoformat()
        builder.chain['metadata']['updated'] = date.today().isoformat()

        return builder

    def set_metadata(self, **kwargs) -> None:
        """
        Set chain metadata fields.

        Args:
            **kwargs: Metadata fields (id, name, description, difficulty, etc.)
        """
        # Top-level fields
        for field in ['id', 'name', 'description', 'difficulty', 'time_estimate',
                      'oscp_relevant', 'prerequisites', 'notes']:
            if field in kwargs and kwargs[field] is not None:
                self.chain[field] = kwargs[field]

        # Metadata fields
        for field in ['author', 'category', 'platform', 'tags', 'references']:
            if field in kwargs and kwargs[field] is not None:
                self.chain['metadata'][field] = kwargs[field]

        # Auto-update 'updated' timestamp
        self.chain['metadata']['updated'] = date.today().isoformat()

    def add_step(self, step_data: Dict[str, Any]) -> None:
        """
        Add a step to the chain.

        Args:
            step_data: Step dictionary with keys: name, objective, command_ref, etc.
        """
        # Ensure required fields
        if 'name' not in step_data:
            raise ValueError("Step must have 'name' field")
        if 'objective' not in step_data:
            raise ValueError("Step must have 'objective' field")
        if 'command_ref' not in step_data:
            raise ValueError("Step must have 'command_ref' field")

        # Set defaults for optional fields
        step = {
            'name': step_data['name'],
            'objective': step_data['objective'],
            'command_ref': step_data['command_ref'],
            'id': step_data.get('id'),
            'description': step_data.get('description'),
            'evidence': step_data.get('evidence', []),
            'dependencies': step_data.get('dependencies', []),
            'repeatable': step_data.get('repeatable'),
            'success_criteria': step_data.get('success_criteria', []),
            'failure_conditions': step_data.get('failure_conditions', []),
            'next_steps': step_data.get('next_steps', [])
        }

        # Remove None values
        step = {k: v for k, v in step.items() if v is not None}

        self.chain['steps'].append(step)
        self.chain['metadata']['updated'] = date.today().isoformat()

    def remove_step(self, index: int) -> None:
        """
        Remove a step by index.

        Args:
            index: Index of step to remove

        Raises:
            IndexError: If index out of range
        """
        if index < 0 or index >= len(self.chain['steps']):
            raise IndexError(f"Step index {index} out of range")

        self.chain['steps'].pop(index)
        self.chain['metadata']['updated'] = date.today().isoformat()

    def get_steps(self) -> List[Dict[str, Any]]:
        """Get list of all steps."""
        return copy.deepcopy(self.chain['steps'])

    def validate(self, command_resolver: Optional[CommandResolver] = None) -> List[str]:
        """
        Validate the chain using existing validators.

        Args:
            command_resolver: Optional CommandResolver for command ref validation

        Returns:
            List of validation error messages (empty if valid)
        """
        errors = []

        # Create validator
        if command_resolver is None:
            command_resolver = CommandResolver()

        validator = ChainValidator(command_resolver=command_resolver)

        # Run all validations
        errors.extend(validator.validate_schema(self.chain))
        errors.extend(validator.check_circular_dependencies(self.chain))
        errors.extend(validator.validate_command_refs(self.chain))

        return errors

    def to_dict(self) -> Dict[str, Any]:
        """Get chain as dictionary (deep copy)."""
        return copy.deepcopy(self.chain)

    def to_json(self, indent: int = 2) -> str:
        """
        Serialize chain to JSON string.

        Args:
            indent: Number of spaces for indentation

        Returns:
            Formatted JSON string
        """
        return json.dumps(self.chain, indent=indent, ensure_ascii=False)

    def save(self, filepath: Optional[Path] = None) -> Path:
        """
        Save chain to JSON file.

        Args:
            filepath: Optional custom file path. If None, auto-generates based on metadata.

        Returns:
            Path where chain was saved

        Raises:
            ValueError: If chain ID or category not set
        """
        if not self.chain['id']:
            raise ValueError("Chain ID must be set before saving")
        if not self.chain['metadata']['category']:
            raise ValueError("Chain category must be set before saving")

        if filepath is None:
            # Auto-generate filepath
            base_dir = Path(__file__).parent.parent / 'data' / 'attack_chains'
            category = self.chain['metadata']['category']
            category_dir = base_dir / category
            category_dir.mkdir(parents=True, exist_ok=True)
            filepath = category_dir / f"{self.chain['id']}.json"

        # Write JSON
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(self.to_json())

        return filepath

    def get_available_step_ids(self) -> List[str]:
        """
        Get list of step IDs available for dependencies.

        Returns:
            List of step IDs (from steps that have 'id' field)
        """
        return [step['id'] for step in self.chain['steps'] if 'id' in step and step['id']]
