#!/usr/bin/env python3
"""
Transform loaded JSON into Neo4j CSV format

Generates CSV files for Neo4j LOAD CSV import with proper escaping and structure.
"""

import csv
import os
import sys
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Tuple, Set, Callable
import argparse
from load_existing_json import load_command_jsons, load_attack_chain_jsons, load_cheatsheet_jsons

# Add parent directory to path to import schema module
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import unified schema definitions
from schema import SchemaRegistry, SchemaLoadError

# Import extraction framework and extractors
from extraction import (
    VariablesExtractor,
    FlagsExtractor,
    IndicatorsExtractor,
    CommandRelationshipsExtractor,
    ChainStepsExtractor,
    TagRelationshipsExtractor,
    CommandsExtractor,
    AttackChainsExtractor,
    CheatsheetsExtractor,
    TagExtractor
)

# Import validation framework
from validation import FieldValidator, ValidationResult


def extract_unique_tags(commands: List[Dict], chains: List[Dict], cheatsheets: List[Dict]) -> List[Dict]:
    """Extract unique tags from all commands, chains, and cheatsheets"""
    tag_set = set()

    # Tags from commands
    for cmd in commands:
        tags = cmd.get('tags', [])
        tag_set.update(tags)

    # Tags from chains
    for chain in chains:
        tags = chain.get('metadata', {}).get('tags', [])
        tag_set.update(tags)

    # Tags from cheatsheets
    for sheet in cheatsheets:
        tags = sheet.get('tags', [])
        tag_set.update(tags)

    # Infer tag categories
    tags_list = []
    for tag_name in sorted(tag_set):
        category = infer_tag_category(tag_name)
        tags_list.append({
            'name': tag_name,
            'category': category
        })

    return tags_list


def infer_tag_category(tag_name: str) -> str:
    """Infer tag category from tag name"""
    tag_upper = tag_name.upper()

    if 'OSCP' in tag_upper or 'PRIORITY' in tag_upper or 'QUICK_WIN' in tag_upper:
        return 'priority'
    elif any(x in tag_upper for x in ['ENUM', 'RECON', 'EXPLOIT', 'PRIVESC', 'POST_EXPLOIT']):
        return 'phase'
    elif any(x in tag_upper for x in ['NMAP', 'METASPLOIT', 'BURP', 'FFUF', 'GOBUSTER']):
        return 'tool'
    elif any(x in tag_upper for x in ['LINUX', 'WINDOWS', 'WEB', 'NETWORK', 'AD']):
        return 'platform'
    else:
        return 'general'




def write_csv_file(filepath: str, data: List[Dict], fieldnames: List[str]):
    """Write data to CSV with proper escaping"""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
        writer.writeheader()

        for row in data:
            # Convert None to empty string
            clean_row = {k: (v if v is not None else '') for k, v in row.items()}
            writer.writerow(clean_row)


def generate_id(text: str) -> str:
    """Generate consistent ID from text"""
    return hashlib.md5(text.encode()).hexdigest()[:16]


# =============================================================================
# Extractor Functions
# =============================================================================
# These functions extract data from source JSON and format for CSV output.
# All extractors must match signature: (commands, chains, cheatsheets) -> List[Dict]

# =============================================================================
# Extraction Wrapper Functions
# =============================================================================
# These functions use the extraction framework to reduce repetitive code.
# All extractors match signature: (commands, chains, cheatsheets) -> List[Dict]

def _extract_commands_csv(commands: List[Dict], chains: List[Dict], cheatsheets: List[Dict]) -> List[Dict]:
    """Extract commands for CSV using CommandsExtractor"""
    extractor = CommandsExtractor()
    return extractor.extract_nodes(commands)


def _extract_attack_chains_csv(commands: List[Dict], chains: List[Dict], cheatsheets: List[Dict]) -> List[Dict]:
    """Extract attack chains for CSV using AttackChainsExtractor"""
    extractor = AttackChainsExtractor()
    return extractor.extract_nodes(chains)


def _extract_variables_nodes(commands: List[Dict], chains: List[Dict], cheatsheets: List[Dict]) -> List[Dict]:
    """Extract variables only (nodes) using VariablesExtractor"""
    extractor = VariablesExtractor()
    return extractor.extract_nodes(commands)


def _extract_command_variables_rels(commands: List[Dict], chains: List[Dict], cheatsheets: List[Dict]) -> List[Dict]:
    """Extract command->variable relationships using VariablesExtractor"""
    extractor = VariablesExtractor()
    return extractor.extract_relationships(commands)


def _extract_flags_nodes(commands: List[Dict], chains: List[Dict], cheatsheets: List[Dict]) -> List[Dict]:
    """Extract flags only (nodes) using FlagsExtractor"""
    extractor = FlagsExtractor()
    return extractor.extract_nodes(commands)


def _extract_command_flags_rels(commands: List[Dict], chains: List[Dict], cheatsheets: List[Dict]) -> List[Dict]:
    """Extract command->flag relationships using FlagsExtractor"""
    extractor = FlagsExtractor()
    return extractor.extract_relationships(commands)


def _extract_indicators_nodes(commands: List[Dict], chains: List[Dict], cheatsheets: List[Dict]) -> List[Dict]:
    """Extract indicators only (nodes) using IndicatorsExtractor"""
    extractor = IndicatorsExtractor()
    return extractor.extract_nodes(commands)


def _extract_command_indicators_rels(commands: List[Dict], chains: List[Dict], cheatsheets: List[Dict]) -> List[Dict]:
    """Extract command->indicator relationships using IndicatorsExtractor"""
    extractor = IndicatorsExtractor()
    return extractor.extract_relationships(commands)


def _extract_chain_steps_nodes(commands: List[Dict], chains: List[Dict], cheatsheets: List[Dict]) -> List[Dict]:
    """Extract chain steps only (nodes) using ChainStepsExtractor"""
    extractor = ChainStepsExtractor()
    return extractor.extract(chains)[0]


def _extract_chain_steps_rels(commands: List[Dict], chains: List[Dict], cheatsheets: List[Dict]) -> List[Dict]:
    """Extract chain->step relationships using ChainStepsExtractor"""
    extractor = ChainStepsExtractor()
    return extractor.extract(chains)[1]


def _extract_step_commands_rels(commands: List[Dict], chains: List[Dict], cheatsheets: List[Dict]) -> List[Dict]:
    """Extract step->command relationships using ChainStepsExtractor"""
    extractor = ChainStepsExtractor()
    return extractor.extract(chains)[2]


def _extract_command_tag_rels(commands: List[Dict], chains: List[Dict], cheatsheets: List[Dict]) -> List[Dict]:
    """Extract command->tag relationships using TagRelationshipsExtractor"""
    extractor = TagRelationshipsExtractor()
    return extractor.extract_command_tags(commands)


def _extract_chain_tag_rels(commands: List[Dict], chains: List[Dict], cheatsheets: List[Dict]) -> List[Dict]:
    """Extract chain->tag relationships using TagRelationshipsExtractor"""
    extractor = TagRelationshipsExtractor()
    return extractor.extract_chain_tags(chains)


def _extract_command_alternatives_rels(commands: List[Dict], chains: List[Dict], cheatsheets: List[Dict]) -> List[Dict]:
    """Extract alternative command relationships using CommandRelationshipsExtractor"""
    extractor = CommandRelationshipsExtractor()
    return extractor.extract_alternatives(commands)


def _extract_command_prerequisites_rels(commands: List[Dict], chains: List[Dict], cheatsheets: List[Dict]) -> List[Dict]:
    """Extract prerequisite command relationships using CommandRelationshipsExtractor"""
    extractor = CommandRelationshipsExtractor()
    return extractor.extract_prerequisites(commands)


def _extract_unique_tags_adapted(commands: List[Dict], chains: List[Dict], cheatsheets: List[Dict]) -> List[Dict]:
    """Extract unique tags using TagExtractor"""
    extractor = TagExtractor()
    return extractor.extract_unique_tags(commands, chains, cheatsheets)


def _extract_cheatsheets_csv(commands: List[Dict], chains: List[Dict], cheatsheets: List[Dict]) -> List[Dict]:
    """Extract cheatsheets for CSV using CheatsheetsExtractor"""
    extractor = CheatsheetsExtractor()
    return extractor.extract_nodes(cheatsheets)


def _extract_cheatsheet_command_rels(commands: List[Dict], chains: List[Dict], cheatsheets: List[Dict]) -> List[Dict]:
    """Extract cheatsheet->command relationships using CheatsheetsExtractor"""
    extractor = CheatsheetsExtractor()
    return extractor.extract_relationships(cheatsheets)


def _extract_cheatsheet_tag_rels(commands: List[Dict], chains: List[Dict], cheatsheets: List[Dict]) -> List[Dict]:
    """Extract cheatsheet->tag relationships"""
    relationships = []
    for sheet in cheatsheets:
        sheet_id = sheet.get('id')
        if not sheet_id:
            continue
        for tag in sheet.get('tags', []):
            tag_name = tag if isinstance(tag, str) else tag.get('name')
            if tag_name:
                relationships.append({
                    'cheatsheet_id': sheet_id,
                    'tag_name': tag_name
                })
    return relationships


def transform_all_to_neo4j(commands: List[Dict], chains: List[Dict], cheatsheets: List[Dict],
                           output_dir: str, validate: bool = False):
    """Data-driven transformation using schema-loaded extraction specs"""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    # Load schema from YAML
    schema_path = Path(__file__).parent.parent / 'schema' / 'neo4j_schema.yaml'
    print(f"Loading schema from {schema_path}...")
    try:
        registry = SchemaRegistry(str(schema_path))

        # Register extractor functions from this module
        registry.register_extractors(sys.modules[__name__])

        # Validate schema
        registry.validate(strict=False)  # Non-strict to allow missing extractors

        schema = registry.get_schema()
        print(f"  Loaded {len(schema.nodes)} node types, {len(schema.relationships)} relationship types")
    except SchemaLoadError as e:
        print(f"ERROR loading schema: {e}")
        raise

    # Initialize validator if requested
    validator = FieldValidator() if validate else None
    validation_results = []

    print()
    print("Transforming data to Neo4j CSV format...")
    print()

    print("Generating node CSVs...")
    for spec in schema.nodes:
        print(f"  {spec.csv_filename}... ({spec.description})")
        if not spec.extractor:
            print(f"    WARNING: No extractor for {spec.name}, skipping")
            continue
        data = spec.extractor(commands, chains, cheatsheets)

        # Validate extracted data if requested
        if validator:
            result = validator.validate_node_extraction(
                spec.label,
                spec.fieldnames,
                spec.id_field,
                data
            )
            validation_results.append(result)

        write_csv_file(str(output_path / spec.csv_filename), data, spec.fieldnames)
        print(f"    Written {len(data)} {spec.name}")

    print()
    print("Generating relationship CSVs...")
    for spec in schema.relationships:
        print(f"  {spec.csv_filename}... ({spec.description})")
        if not spec.extractor:
            print(f"    WARNING: No extractor for {spec.name}, skipping")
            continue
        data = spec.extractor(commands, chains, cheatsheets)

        # Validate extracted data if requested
        if validator:
            result = validator.validate_relationship_extraction(
                spec.rel_type,
                spec.fieldnames,
                spec.start_id_col,
                spec.end_id_col,
                data
            )
            validation_results.append(result)

        write_csv_file(str(output_path / spec.csv_filename), data, spec.fieldnames)
        print(f"    Written {len(data)} {spec.name}")

    print()
    print(f"CSV generation complete! Output directory: {output_dir}")

    # Print validation report if requested
    if validator and validation_results:
        validator.print_validation_report(validation_results)


def main():
    parser = argparse.ArgumentParser(
        description="Transform JSON to Neo4j CSV format"
    )
    parser.add_argument(
        '--input-dir',
        default='reference/data',
        help='Input directory (default: reference/data/)'
    )
    parser.add_argument(
        '--output-dir',
        default='db/neo4j-migration/data/neo4j',
        help='Output directory (default: db/neo4j-migration/data/neo4j/)'
    )
    parser.add_argument(
        '--validate',
        action='store_true',
        help='Run validation after transformation'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Detailed logging'
    )

    args = parser.parse_args()

    # Determine directories
    if os.path.isabs(args.input_dir):
        input_dir = Path(args.input_dir)
    else:
        input_dir = Path.cwd() / args.input_dir

    if os.path.isabs(args.output_dir):
        output_dir = Path(args.output_dir)
    else:
        output_dir = Path.cwd() / args.output_dir

    # Load JSON data
    print(f"Loading JSON from: {input_dir}")
    commands, cmd_errors = load_command_jsons(str(input_dir / "commands"))
    chains, chain_errors = load_attack_chain_jsons(str(input_dir / "attack_chains"))
    cheatsheets, sheet_errors = load_cheatsheet_jsons(str(input_dir / "cheatsheets"))

    if cmd_errors or chain_errors or sheet_errors:
        print("Errors loading JSON files:")
        for err in cmd_errors + chain_errors + sheet_errors:
            print(f"  ERROR: {err}")
        return 1

    print(f"Loaded {len(commands)} commands, {len(chains)} chains, {len(cheatsheets)} cheatsheet entries")
    print()

    # Transform to CSV
    transform_all_to_neo4j(commands, chains, cheatsheets, str(output_dir), validate=args.validate)

    # Show file sizes
    print()
    print("Generated CSV files:")
    csv_files = sorted(output_dir.glob('*.csv'))
    total_size = 0
    for csv_file in csv_files:
        size = csv_file.stat().st_size
        total_size += size
        print(f"  {csv_file.name}: {size:,} bytes")

    print(f"\nTotal size: {total_size:,} bytes ({total_size / 1024:.1f} KB)")

    return 0


if __name__ == '__main__':
    sys.exit(main())
