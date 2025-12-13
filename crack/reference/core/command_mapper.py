"""
Command Mapper - Centralized data source to Command dataclass conversion

This module provides a single source of truth for converting various data formats
(Neo4j records, SQL results, JSON objects) to Command dataclasses, eliminating
140+ lines of duplicated mapping logic across adapters.
"""

from typing import Dict, List, Any, Optional
from .registry import Command, CommandVariable


class CommandMapper:
    """
    Maps data from various sources to Command dataclass

    Supports:
    - Neo4j graph records
    - SQL/PostgreSQL query results
    - JSON objects (HybridCommandRegistry)

    Uses configurable field mappings to handle different field names
    across backends while maintaining DRY principles.
    """

    # Default field mappings for different backends
    NEO4J_FIELD_MAPPING = {
        'command': 'command',
        'variables': {
            'example': 'example',
            'required': 'required'
        },
        'tags': 'direct',  # Tags are already strings
        'indicators': 'direct'  # Indicators are already strings
    }

    SQL_FIELD_MAPPING = {
        'command': 'command_template',
        'variables': {
            'example': 'example_value',
            'required': 'is_required'
        },
        'tags': 'extract_name',  # Tags are dicts with 'name' field
        'indicators': 'extract_pattern'  # Indicators are dicts with 'pattern' field
    }

    JSON_FIELD_MAPPING = {
        'command': 'command',
        'variables': {
            'example': 'example',
            'required': 'required'
        },
        'tags': 'direct',
        'indicators': 'direct'
    }

    @staticmethod
    def map_variables(
        source_vars: List[Dict],
        field_mapping: Dict[str, str]
    ) -> List[CommandVariable]:
        """
        Generic variable mapping with configurable field names

        Args:
            source_vars: List of variable dicts from data source
            field_mapping: Dict mapping standard field names to source field names

        Returns:
            List of CommandVariable dataclasses

        Example:
            >>> # Neo4j format
            >>> neo4j_vars = [{'name': '<TARGET>', 'example': '10.10.10.1', 'required': True}]
            >>> CommandMapper.map_variables(neo4j_vars, NEO4J_FIELD_MAPPING['variables'])
            [CommandVariable(name='<TARGET>', example='10.10.10.1', required=True)]

            >>> # SQL format
            >>> sql_vars = [{'name': '<TARGET>', 'example_value': '10.10.10.1', 'is_required': True}]
            >>> CommandMapper.map_variables(sql_vars, SQL_FIELD_MAPPING['variables'])
            [CommandVariable(name='<TARGET>', example='10.10.10.1', required=True)]
        """
        variables = []
        for var in source_vars:
            variables.append(CommandVariable(
                name=var.get('name', ''),
                description=var.get('description', ''),
                example=var.get(field_mapping.get('example', 'example'), ''),
                required=var.get(field_mapping.get('required', 'required'), True)
            ))
        return variables

    @staticmethod
    def extract_tags(source_tags: List, extraction_mode: str) -> List[str]:
        """
        Extract tag names from various formats

        Args:
            source_tags: List of tags (strings or dicts)
            extraction_mode: 'direct' or 'extract_name'

        Returns:
            List of tag name strings
        """
        if extraction_mode == 'direct':
            # Tags are already strings
            return [t for t in source_tags if t]
        elif extraction_mode == 'extract_name':
            # Tags are dicts with 'name' field
            return [tag.get('name', '') for tag in source_tags if tag]
        else:
            return []

    @staticmethod
    def extract_flag_explanations(source_flags: List[Dict]) -> Dict[str, str]:
        """
        Extract flag explanations from list format

        Args:
            source_flags: List of flag dicts with 'flag' and 'explanation' fields

        Returns:
            Dict mapping flag names to explanations
        """
        flag_explanations = {}
        for flag in source_flags:
            if flag and 'flag' in flag:
                flag_explanations[flag['flag']] = flag.get('explanation', '')
        return flag_explanations

    @staticmethod
    def extract_indicators(
        source_indicators: List,
        extraction_mode: str
    ) -> List[str]:
        """
        Extract indicator patterns from various formats

        Args:
            source_indicators: List of indicators (strings or dicts)
            extraction_mode: 'direct' or 'extract_pattern'

        Returns:
            List of indicator pattern strings
        """
        if extraction_mode == 'direct':
            # Indicators are already strings
            return [i for i in source_indicators if i]
        elif extraction_mode == 'extract_pattern':
            # Indicators are dicts with 'pattern' field
            return [ind.get('pattern', '') for ind in source_indicators if ind]
        else:
            return []

    @staticmethod
    def to_command(
        data: Dict[str, Any],
        field_mapping: Dict[str, Any] = None
    ) -> Optional[Command]:
        """
        Single conversion method with field name mapping

        Args:
            data: Source data dict (Neo4j record, SQL result, or JSON object)
            field_mapping: Field mapping configuration (defaults to JSON mapping)

        Returns:
            Command dataclass instance or None

        Example:
            >>> # Neo4j record
            >>> record = {'cmd': {...}, 'variables': [...], 'tags': [...]}
            >>> command = CommandMapper.to_command(record, CommandMapper.NEO4J_FIELD_MAPPING)

            >>> # SQL result
            >>> result = {'id': 'cmd-1', 'command_template': 'nmap <TARGET>', ...}
            >>> command = CommandMapper.to_command(result, CommandMapper.SQL_FIELD_MAPPING)
        """
        if data is None:
            return None

        # Use JSON mapping as default
        if field_mapping is None:
            field_mapping = CommandMapper.JSON_FIELD_MAPPING

        try:
            # Handle Neo4j record format (has 'cmd' node)
            if 'cmd' in data:
                cmd_node = data['cmd']
                variables_data = data.get('variables', [])
                tags_data = data.get('tags', [])
                flags_data = data.get('flags', [])
                success_data = data.get('success_indicators', [])
                failure_data = data.get('failure_indicators', [])
            else:
                # Handle SQL/JSON format (flat dict)
                cmd_node = data
                variables_data = data.get('variables', [])
                tags_data = data.get('tags', [])
                flags_data = data.get('flags', [])
                success_data = data.get('success_indicators', [])
                failure_data = data.get('failure_indicators', [])

            # Map variables
            variables = CommandMapper.map_variables(
                variables_data,
                field_mapping.get('variables', {})
            )

            # Extract tags
            tags = CommandMapper.extract_tags(
                tags_data,
                field_mapping.get('tags', 'direct')
            )

            # Extract flag explanations
            flag_explanations = CommandMapper.extract_flag_explanations(flags_data)

            # Extract indicators
            success_indicators = CommandMapper.extract_indicators(
                success_data,
                field_mapping.get('indicators', 'direct')
            )
            failure_indicators = CommandMapper.extract_indicators(
                failure_data,
                field_mapping.get('indicators', 'direct')
            )

            # Extract relationship command IDs (SQL only)
            alternatives = []
            prerequisites = []
            next_steps = []
            if 'alternatives' in data:
                alternatives = [
                    rel.get('target_command_id', '') if isinstance(rel, dict) else rel
                    for rel in data.get('alternatives', [])
                ]
            if 'prerequisites' in data:
                prerequisites = [
                    rel.get('source_command_id', '') if isinstance(rel, dict) else rel
                    for rel in data.get('prerequisites', [])
                ]
            if 'next_steps' in data:
                next_steps = [
                    rel.get('target_command_id', '') if isinstance(rel, dict) else rel
                    for rel in data.get('next_steps', [])
                ]

            # Get command field name
            command_field = field_mapping.get('command', 'command')

            # Import nested dataclass types
            from crack.reference.core.registry import (
                FlagDefinition,
                ExampleDefinition,
                EducationalContent
            )

            # Handle nested dataclasses - flags
            flags_list = []
            if 'flags' in cmd_node and cmd_node['flags']:
                flags_list = [
                    FlagDefinition(**flag) if isinstance(flag, dict) else flag
                    for flag in cmd_node['flags']
                ]

            # Handle nested dataclasses - examples
            examples_list = []
            if 'examples' in cmd_node and cmd_node['examples']:
                examples_list = [
                    ExampleDefinition(**ex) if isinstance(ex, dict) else ex
                    for ex in cmd_node['examples']
                ]

            # Handle nested dataclasses - educational
            educational_obj = None
            if 'educational' in cmd_node and cmd_node['educational']:
                if isinstance(cmd_node['educational'], dict):
                    educational_obj = EducationalContent(**cmd_node['educational'])
                else:
                    educational_obj = cmd_node['educational']

            # Build Command dataclass
            return Command(
                id=cmd_node.get('id', ''),
                name=cmd_node.get('name', ''),
                category=cmd_node.get('category', 'custom'),
                command=cmd_node.get(command_field, ''),
                description=cmd_node.get('description', ''),
                subcategory=cmd_node.get('subcategory', ''),
                filled_example=cmd_node.get('filled_example', ''),
                tags=tags,
                variables=variables,
                flag_explanations=flag_explanations,
                success_indicators=success_indicators,
                failure_indicators=failure_indicators,
                next_steps=next_steps,
                alternatives=alternatives,
                prerequisites=prerequisites,
                troubleshooting=cmd_node.get('troubleshooting', {}),
                notes=cmd_node.get('notes', ''),
                oscp_relevance=cmd_node.get('oscp_relevance', 'medium'),
                # Missing existing fields
                advantages=cmd_node.get('advantages', []),
                disadvantages=cmd_node.get('disadvantages', []),
                use_cases=cmd_node.get('use_cases', []),
                output_analysis=cmd_node.get('output_analysis', []),
                common_uses=cmd_node.get('common_uses', []),
                references=cmd_node.get('references', []),
                # New PowerShell/platform-specific fields
                os=cmd_node.get('os', ''),
                flags=flags_list,
                examples=examples_list,
                educational=educational_obj,
                oscp_priority=cmd_node.get('oscp_priority', ''),
                related_commands=cmd_node.get('related_commands', []),
                custom_metadata=cmd_node.get('custom_metadata', {})
            )

        except Exception as e:
            # Don't print here - let caller handle errors via AdapterErrorHandler
            raise ValueError(f"Error mapping data to Command: {e}") from e
