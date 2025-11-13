"""
Concrete extractors for Neo4j data transformation.

Uses the extraction framework to eliminate ~150 lines of repetitive logic.
"""

import json
from typing import List, Dict, Any, Tuple, Set
from .extraction_framework import (
    NodeRelationshipExtractor,
    SimpleNodeExtractor,
    TagExtractor,
    ExtractionContext,
    generate_id,
    safe_get,
    join_list
)


class VariablesExtractor(NodeRelationshipExtractor):
    """
    Extract variable nodes and command->variable relationships.

    Pattern:
    - Iterate through commands
    - Extract variables field (list of dicts)
    - Create unique variable nodes (deduplicated by name)
    - Create command->variable relationships with position
    """

    def extract_nodes(self, sources: List[Dict], id_field: str = 'id') -> List[Dict]:
        """Extract unique variable nodes"""
        variables = []
        seen_vars = set()

        for cmd in sources:
            cmd_id = self.validate_source_id(cmd, id_field)
            if not cmd_id:
                continue

            for var in cmd.get('variables', []):
                var_name = var.get('name')
                if not var_name:
                    continue

                # Create unique variable node (deduplicated by name)
                if var_name not in seen_vars:
                    var_id = generate_id(f"var_{var_name}")
                    variables.append({
                        'id': var_id,
                        'name': var_name,
                        'description': safe_get(var, 'description'),
                        'example': safe_get(var, 'example'),
                        'required': str(var.get('required', True))
                    })
                    seen_vars.add(var_name)

        return variables

    def extract_relationships(self, sources: List[Dict], id_field: str = 'id') -> List[Dict]:
        """Extract command->variable relationships"""
        relationships = []

        for cmd in sources:
            cmd_id = self.validate_source_id(cmd, id_field)
            if not cmd_id:
                continue

            for idx, var in enumerate(cmd.get('variables', [])):
                var_name = var.get('name')
                if not var_name:
                    continue

                var_id = generate_id(f"var_{var_name}")
                relationships.append({
                    'command_id': cmd_id,
                    'variable_id': var_id,
                    'position': str(idx),
                    'example': safe_get(var, 'example'),
                    'required': str(var.get('required', True))
                })

        return relationships


class FlagsExtractor(NodeRelationshipExtractor):
    """
    Extract flag nodes and command->flag relationships.

    Pattern:
    - Iterate through commands
    - Extract flag_explanations field (dict of flag: explanation)
    - Create unique flag nodes (deduplicated by flag ID)
    - Create command->flag relationships with position
    """

    def extract_nodes(self, sources: List[Dict], id_field: str = 'id') -> List[Dict]:
        """Extract unique flag nodes"""
        flags = []
        seen_flags = set()

        for cmd in sources:
            cmd_id = self.validate_source_id(cmd, id_field)
            if not cmd_id:
                continue

            flag_explanations = cmd.get('flag_explanations', {})
            for flag, explanation in flag_explanations.items():
                flag_id = generate_id(f"flag_{flag}")

                # Create unique flag node (deduplicated by ID)
                if flag_id not in seen_flags:
                    flags.append({
                        'id': flag_id,
                        'flag': flag,
                        'explanation': explanation
                    })
                    seen_flags.add(flag_id)

        return flags

    def extract_relationships(self, sources: List[Dict], id_field: str = 'id') -> List[Dict]:
        """Extract command->flag relationships"""
        relationships = []

        for cmd in sources:
            cmd_id = self.validate_source_id(cmd, id_field)
            if not cmd_id:
                continue

            flag_explanations = cmd.get('flag_explanations', {})
            for idx, (flag, _) in enumerate(flag_explanations.items()):
                flag_id = generate_id(f"flag_{flag}")
                relationships.append({
                    'command_id': cmd_id,
                    'flag_id': flag_id,
                    'position': str(idx)
                })

        return relationships


class IndicatorsExtractor(NodeRelationshipExtractor):
    """
    Extract indicator nodes and command->indicator relationships.

    Pattern:
    - Iterate through commands
    - Extract success_indicators and failure_indicators (lists)
    - Create indicator nodes (sequential IDs)
    - Create command->indicator relationships with type
    """

    def extract(self, sources: List[Dict], id_field: str = 'id') -> Tuple[List[Dict], List[Dict]]:
        """Extract both nodes and relationships in single pass"""
        indicators = []
        relationships = []
        indicator_id_counter = 0

        for cmd in sources:
            cmd_id = self.validate_source_id(cmd, id_field)
            if not cmd_id:
                continue

            # Success indicators
            for indicator_text in cmd.get('success_indicators', []):
                indicator_id_counter += 1
                ind_id = f"indicator_{indicator_id_counter}"

                indicators.append({
                    'id': ind_id,
                    'pattern': indicator_text,
                    'indicator_type': 'success'
                })

                relationships.append({
                    'command_id': cmd_id,
                    'indicator_id': ind_id,
                    'indicator_type': 'success'
                })

            # Failure indicators
            for indicator_text in cmd.get('failure_indicators', []):
                indicator_id_counter += 1
                ind_id = f"indicator_{indicator_id_counter}"

                indicators.append({
                    'id': ind_id,
                    'pattern': indicator_text,
                    'indicator_type': 'failure'
                })

                relationships.append({
                    'command_id': cmd_id,
                    'indicator_id': ind_id,
                    'indicator_type': 'failure'
                })

        return indicators, relationships

    def extract_nodes(self, sources: List[Dict], id_field: str = 'id') -> List[Dict]:
        """Extract indicator nodes"""
        return self.extract(sources, id_field)[0]

    def extract_relationships(self, sources: List[Dict], id_field: str = 'id') -> List[Dict]:
        """Extract command->indicator relationships"""
        return self.extract(sources, id_field)[1]


class CommandRelationshipsExtractor:
    """
    Extract command->command relationships.

    Pattern:
    - Iterate through commands
    - Extract alternatives and prerequisites fields (lists of command IDs)
    - Create command->command relationships
    """

    def extract_alternatives(self, commands: List[Dict]) -> List[Dict]:
        """Extract alternative command relationships"""
        relationships = []

        for cmd in commands:
            cmd_id = cmd.get('id')
            if not cmd_id:
                continue

            for alt in cmd.get('alternatives', []):
                relationships.append({
                    'command_id': cmd_id,
                    'alternative_command_id': alt
                })

        return relationships

    def extract_prerequisites(self, commands: List[Dict]) -> List[Dict]:
        """Extract prerequisite command relationships"""
        relationships = []

        for cmd in commands:
            cmd_id = cmd.get('id')
            if not cmd_id:
                continue

            for prereq in cmd.get('prerequisites', []):
                relationships.append({
                    'command_id': cmd_id,
                    'prerequisite_command_id': prereq
                })

        return relationships


class ChainStepsExtractor:
    """
    Extract chain step nodes and relationships.

    Pattern:
    - Iterate through chains
    - Extract steps field (list of dicts)
    - Create step nodes
    - Create chain->step relationships
    - Create step->command relationships
    """

    def extract(self, chains: List[Dict]) -> Tuple[List[Dict], List[Dict], List[Dict]]:
        """
        Extract steps, chain->step rels, step->command rels.

        Returns:
            Tuple of (step_nodes, chain_step_rels, step_command_rels)
        """
        steps = []
        chain_step_rels = []
        step_command_rels = []

        for chain in chains:
            chain_id = chain.get('id')
            if not chain_id:
                continue

            for idx, step in enumerate(chain.get('steps', [])):
                step_id = step.get('id')
                if not step_id:
                    continue

                # Create step node
                steps.append({
                    'id': step_id,
                    'name': safe_get(step, 'name'),
                    'description': safe_get(step, 'description'),
                    'expected_output': safe_get(step, 'expected_output'),
                    'notes': safe_get(step, 'notes')
                })

                # Chain -> Step relationship
                chain_step_rels.append({
                    'chain_id': chain_id,
                    'step_id': step_id,
                    'order': str(step.get('step_order', idx))
                })

                # Step -> Command relationship
                cmd_ref = step.get('command_ref')
                if cmd_ref:
                    step_command_rels.append({
                        'step_id': step_id,
                        'command_id': cmd_ref
                    })

        return steps, chain_step_rels, step_command_rels


class TagRelationshipsExtractor:
    """
    Extract tag relationships for commands and chains.

    Pattern:
    - Iterate through entities
    - Extract tags field (list of strings or dicts)
    - Create entity->tag relationships
    """

    def extract_command_tags(self, commands: List[Dict]) -> List[Dict]:
        """Extract command->tag relationships"""
        relationships = []

        for cmd in commands:
            cmd_id = cmd.get('id')
            if not cmd_id:
                continue

            for tag in cmd.get('tags', []):
                tag_name = tag if isinstance(tag, str) else tag.get('name')
                if tag_name:
                    relationships.append({
                        'command_id': cmd_id,
                        'tag_name': tag_name
                    })

        return relationships

    def extract_chain_tags(self, chains: List[Dict]) -> List[Dict]:
        """Extract chain->tag relationships"""
        relationships = []

        for chain in chains:
            chain_id = chain.get('id')
            if not chain_id:
                continue

            for tag in chain.get('tags', []):
                tag_name = tag if isinstance(tag, str) else tag.get('name')
                if tag_name:
                    relationships.append({
                        'chain_id': chain_id,
                        'tag_name': tag_name
                    })

        return relationships


class CommandsExtractor(SimpleNodeExtractor):
    """
    Extract command nodes.

    Simple 1:1 transformation from source commands to CSV.
    """

    def __init__(self, context=None):
        field_mapping = {
            'id': 'id',
            'name': 'name',
            'category': 'category',
            'command': 'command',
            'description': 'description',
            'subcategory': 'subcategory',
            'notes': 'notes',
            'oscp_relevance': 'oscp_relevance'
        }
        super().__init__(field_mapping, context)


class AttackChainsExtractor(SimpleNodeExtractor):
    """
    Extract attack chain nodes.

    Simple 1:1 transformation from source chains to CSV.
    """

    def __init__(self, context=None):
        field_mapping = {
            'id': 'id',
            'name': 'name',
            'description': 'description',
            'version': 'version',
            'category': 'category',
            'platform': 'platform',
            'difficulty': 'difficulty',
            'time_estimate': 'time_estimate',
            'oscp_relevant': 'oscp_relevant',
            'notes': 'notes'
        }
        super().__init__(field_mapping, context)


class CheatsheetsExtractor(NodeRelationshipExtractor):
    """
    Extract cheatsheet nodes and cheatsheet->command relationships.

    Pattern:
    - Extract cheatsheet nodes with JSON-stringified complex fields
    - Extract command references from scenarios and sections
    - Create cheatsheet->command relationships
    """

    def extract_nodes(self, sources: List[Dict], id_field: str = 'id') -> List[Dict]:
        """Extract cheatsheet nodes"""
        cheatsheets = []

        for sheet in sources:
            sheet_id = self.validate_source_id(sheet, id_field)
            if not sheet_id:
                continue

            # Serialize complex nested structures as JSON strings for Neo4j
            educational_header_json = json.dumps(sheet.get('educational_header', {}))
            scenarios_json = json.dumps(sheet.get('scenarios', []))
            sections_json = json.dumps(sheet.get('sections', []))
            tags_list = join_list(sheet.get('tags', []))

            cheatsheets.append({
                'id': sheet_id,
                'name': safe_get(sheet, 'name'),
                'description': safe_get(sheet, 'description'),
                'tags': tags_list,
                'educational_header': educational_header_json,
                'scenarios': scenarios_json,
                'sections': sections_json
            })

        return cheatsheets

    def extract_relationships(self, sources: List[Dict], id_field: str = 'id') -> List[Dict]:
        """Extract cheatsheet->command relationships from scenarios and sections"""
        relationships = []

        for sheet in sources:
            sheet_id = self.validate_source_id(sheet, id_field)
            if not sheet_id:
                continue

            # Extract command IDs from scenarios
            for scenario in sheet.get('scenarios', []):
                for cmd_id in scenario.get('commands', []):
                    if cmd_id:
                        relationships.append({
                            'cheatsheet_id': sheet_id,
                            'command_id': cmd_id,
                            'context': 'scenario',
                            'scenario_title': safe_get(scenario, 'title'),
                            'section_title': ''  # Empty for scenarios
                        })

            # Extract command IDs from sections
            for section in sheet.get('sections', []):
                for cmd_id in section.get('commands', []):
                    if cmd_id:
                        relationships.append({
                            'cheatsheet_id': sheet_id,
                            'command_id': cmd_id,
                            'context': 'section',
                            'scenario_title': '',  # Empty for sections
                            'section_title': safe_get(section, 'title')
                        })

        return relationships
