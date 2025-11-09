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
from typing import Dict, List, Any, Tuple, Set
import argparse
from load_existing_json import load_command_jsons, load_attack_chain_jsons, load_cheatsheet_jsons


def extract_unique_tags(commands: List[Dict], chains: List[Dict]) -> List[Dict]:
    """Extract unique tags from all commands and chains"""
    tag_set = set()

    # Tags from commands
    for cmd in commands:
        tags = cmd.get('tags', [])
        tag_set.update(tags)

    # Tags from chains
    for chain in chains:
        tags = chain.get('metadata', {}).get('tags', [])
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


def extract_variables(commands: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
    """Extract variables and command->variable relationships"""
    variables = []
    relationships = []
    seen_vars = set()

    for cmd in commands:
        cmd_id = cmd.get('id')
        if not cmd_id:
            continue

        for idx, var in enumerate(cmd.get('variables', [])):
            var_name = var.get('name')
            if not var_name:
                continue

            # Create unique variable node (if not seen)
            if var_name not in seen_vars:
                var_id = generate_id(f"var_{var_name}")
                variables.append({
                    'id': var_id,
                    'name': var_name,
                    'description': var.get('description', ''),
                    'example': var.get('example', ''),
                    'required': str(var.get('required', True))
                })
                seen_vars.add(var_name)

            # Create relationship
            var_id = generate_id(f"var_{var_name}")
            relationships.append({
                'command_id': cmd_id,
                'variable_id': var_id,
                'position': str(idx),
                'example': var.get('example', ''),
                'required': str(var.get('required', True))
            })

    return variables, relationships


def extract_flags(commands: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
    """Extract flag explanations and relationships"""
    flags = []
    relationships = []
    seen_flags = set()

    for cmd in commands:
        cmd_id = cmd.get('id')
        if not cmd_id:
            continue

        flag_explanations = cmd.get('flag_explanations', {})
        for idx, (flag, explanation) in enumerate(flag_explanations.items()):
            flag_id = generate_id(f"flag_{flag}")

            # Create unique flag node
            if flag_id not in seen_flags:
                flags.append({
                    'id': flag_id,
                    'flag': flag,
                    'explanation': explanation
                })
                seen_flags.add(flag_id)

            # Create relationship
            relationships.append({
                'command_id': cmd_id,
                'flag_id': flag_id,
                'position': str(idx)
            })

    return flags, relationships


def extract_indicators(commands: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
    """Extract success/failure indicators and relationships"""
    indicators = []
    relationships = []
    indicator_id_counter = 0

    for cmd in commands:
        cmd_id = cmd.get('id')
        if not cmd_id:
            continue

        # Success indicators
        for indicator_text in cmd.get('success_indicators', []):
            indicator_id_counter += 1
            ind_id = f"indicator_{indicator_id_counter}"

            indicators.append({
                'id': ind_id,
                'indicator': indicator_text,
                'type': 'success'
            })

            relationships.append({
                'command_id': cmd_id,
                'indicator_id': ind_id,
                'type': 'success'
            })

        # Failure indicators
        for indicator_text in cmd.get('failure_indicators', []):
            indicator_id_counter += 1
            ind_id = f"indicator_{indicator_id_counter}"

            indicators.append({
                'id': ind_id,
                'indicator': indicator_text,
                'type': 'failure'
            })

            relationships.append({
                'command_id': cmd_id,
                'indicator_id': ind_id,
                'type': 'failure'
            })

    return indicators, relationships


def extract_command_relationships(commands: List[Dict]) -> Dict[str, List[Dict]]:
    """Extract alternatives and prerequisites relationships"""
    relationships = {
        'alternatives': [],
        'prerequisites': []
    }

    for cmd in commands:
        cmd_id = cmd.get('id')
        if not cmd_id:
            continue

        # Alternatives
        for alt in cmd.get('alternatives', []):
            relationships['alternatives'].append({
                'command_id': cmd_id,
                'alternative_command_id': alt
            })

        # Prerequisites
        for prereq in cmd.get('prerequisites', []):
            relationships['prerequisites'].append({
                'command_id': cmd_id,
                'prerequisite_command_id': prereq
            })

    return relationships


def extract_chain_steps(chains: List[Dict]) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    """Extract steps, chain->step relationships, step->command relationships"""
    steps = []
    chain_step_rels = []
    step_command_rels = []
    step_dependency_rels = []

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
                'name': step.get('name', ''),
                'step_order': str(step.get('step_order', idx)),
                'objective': step.get('objective', ''),
                'description': step.get('description', ''),
                'evidence': '|'.join(step.get('evidence', [])),
                'success_criteria': '|'.join(step.get('success_criteria', [])),
                'failure_conditions': '|'.join(step.get('failure_conditions', []))
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

            # Step dependencies
            for dep_step_id in step.get('dependencies', []):
                step_dependency_rels.append({
                    'step_id': step_id,
                    'depends_on_step_id': dep_step_id
                })

    return steps, chain_step_rels, step_command_rels


def extract_references(chains: List[Dict]) -> List[Dict]:
    """Extract external references from chains"""
    references = []
    ref_id_counter = 0

    for chain in chains:
        chain_id = chain.get('id')
        refs = chain.get('metadata', {}).get('references', [])

        for url in refs:
            ref_id_counter += 1
            references.append({
                'id': f"ref_{ref_id_counter}",
                'chain_id': chain_id,
                'url': url
            })

    return references


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


def transform_all_to_neo4j(commands: List[Dict], chains: List[Dict], cheatsheets: List[Dict], output_dir: str):
    """Orchestrate all transformation and CSV generation"""

    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    print("Transforming data to Neo4j CSV format...")
    print()

    # 1. Commands CSV
    print("Generating commands.csv...")
    commands_csv = []
    for cmd in commands:
        commands_csv.append({
            'id': cmd.get('id', ''),
            'name': cmd.get('name', ''),
            'category': cmd.get('category', ''),
            'command': cmd.get('command', ''),
            'description': cmd.get('description', ''),
            'subcategory': cmd.get('subcategory', ''),
            'notes': cmd.get('notes', ''),
            'oscp_relevance': cmd.get('oscp_relevance', 'medium')
        })

    write_csv_file(
        str(output_path / 'commands.csv'),
        commands_csv,
        ['id', 'name', 'category', 'command', 'description', 'subcategory', 'notes', 'oscp_relevance']
    )
    print(f"  Written {len(commands_csv)} commands")

    # 2. Attack Chains CSV
    print("Generating attack_chains.csv...")
    chains_csv = []
    for chain in chains:
        metadata = chain.get('metadata', {})
        chains_csv.append({
            'id': chain.get('id', ''),
            'name': chain.get('name', ''),
            'description': chain.get('description', ''),
            'version': chain.get('version', '1.0.0'),
            'category': metadata.get('category', ''),
            'platform': metadata.get('platform', ''),
            'difficulty': chain.get('difficulty', 'intermediate'),
            'time_estimate': chain.get('time_estimate', ''),
            'oscp_relevant': str(chain.get('oscp_relevant', False)),
            'notes': chain.get('notes', '')
        })

    write_csv_file(
        str(output_path / 'attack_chains.csv'),
        chains_csv,
        ['id', 'name', 'description', 'version', 'category', 'platform', 'difficulty', 'time_estimate', 'oscp_relevant', 'notes']
    )
    print(f"  Written {len(chains_csv)} attack chains")

    # 3. Tags CSV
    print("Generating tags.csv...")
    tags = extract_unique_tags(commands, chains)
    write_csv_file(
        str(output_path / 'tags.csv'),
        tags,
        ['name', 'category']
    )
    print(f"  Written {len(tags)} unique tags")

    # 4. Variables CSV
    print("Generating variables.csv...")
    variables, var_rels = extract_variables(commands)
    write_csv_file(
        str(output_path / 'variables.csv'),
        variables,
        ['id', 'name', 'description', 'example', 'required']
    )
    print(f"  Written {len(variables)} unique variables")

    # 5. Flags CSV
    print("Generating flags.csv...")
    flags, flag_rels = extract_flags(commands)
    write_csv_file(
        str(output_path / 'flags.csv'),
        flags,
        ['id', 'flag', 'explanation']
    )
    print(f"  Written {len(flags)} unique flags")

    # 6. Indicators CSV
    print("Generating indicators.csv...")
    indicators, indicator_rels = extract_indicators(commands)
    write_csv_file(
        str(output_path / 'indicators.csv'),
        indicators,
        ['id', 'indicator', 'type']
    )
    print(f"  Written {len(indicators)} indicators")

    # 7. Chain Steps CSV
    print("Generating chain_steps.csv...")
    steps, chain_step_rels, step_command_rels = extract_chain_steps(chains)
    write_csv_file(
        str(output_path / 'chain_steps.csv'),
        steps,
        ['id', 'name', 'step_order', 'objective', 'description', 'evidence', 'success_criteria', 'failure_conditions']
    )
    print(f"  Written {len(steps)} chain steps")

    # 8. References CSV
    print("Generating references.csv...")
    references = extract_references(chains)
    write_csv_file(
        str(output_path / 'references.csv'),
        references,
        ['id', 'chain_id', 'url']
    )
    print(f"  Written {len(references)} references")

    print()
    print("Generating relationship CSVs...")

    # 9. Command -> Variable
    write_csv_file(
        str(output_path / 'command_has_variable.csv'),
        var_rels,
        ['command_id', 'variable_id', 'position', 'example', 'required']
    )
    print(f"  Written {len(var_rels)} command->variable relationships")

    # 10. Command -> Flag
    write_csv_file(
        str(output_path / 'command_has_flag.csv'),
        flag_rels,
        ['command_id', 'flag_id', 'position']
    )
    print(f"  Written {len(flag_rels)} command->flag relationships")

    # 11. Command -> Indicator
    write_csv_file(
        str(output_path / 'command_has_indicator.csv'),
        indicator_rels,
        ['command_id', 'indicator_id', 'type']
    )
    print(f"  Written {len(indicator_rels)} command->indicator relationships")

    # 12. Command -> Tag
    tag_rels = []
    for cmd in commands:
        cmd_id = cmd.get('id')
        if not cmd_id:
            continue
        for tag in cmd.get('tags', []):
            tag_rels.append({
                'command_id': cmd_id,
                'tag_name': tag
            })

    write_csv_file(
        str(output_path / 'command_tagged_with.csv'),
        tag_rels,
        ['command_id', 'tag_name']
    )
    print(f"  Written {len(tag_rels)} command->tag relationships")

    # 13. Command relationships (alternatives, prerequisites)
    cmd_rels = extract_command_relationships(commands)

    write_csv_file(
        str(output_path / 'command_alternative_for.csv'),
        cmd_rels['alternatives'],
        ['command_id', 'alternative_command_id']
    )
    print(f"  Written {len(cmd_rels['alternatives'])} alternative relationships")

    write_csv_file(
        str(output_path / 'command_requires.csv'),
        cmd_rels['prerequisites'],
        ['command_id', 'prerequisite_command_id']
    )
    print(f"  Written {len(cmd_rels['prerequisites'])} prerequisite relationships")

    # 14. Chain -> Step
    write_csv_file(
        str(output_path / 'chain_contains_step.csv'),
        chain_step_rels,
        ['chain_id', 'step_id', 'order']
    )
    print(f"  Written {len(chain_step_rels)} chain->step relationships")

    # 15. Step -> Command
    write_csv_file(
        str(output_path / 'step_uses_command.csv'),
        step_command_rels,
        ['step_id', 'command_id']
    )
    print(f"  Written {len(step_command_rels)} step->command relationships")

    # 16. Chain -> Tag
    chain_tag_rels = []
    for chain in chains:
        chain_id = chain.get('id')
        if not chain_id:
            continue
        for tag in chain.get('metadata', {}).get('tags', []):
            chain_tag_rels.append({
                'chain_id': chain_id,
                'tag_name': tag
            })

    write_csv_file(
        str(output_path / 'chain_tagged_with.csv'),
        chain_tag_rels,
        ['chain_id', 'tag_name']
    )
    print(f"  Written {len(chain_tag_rels)} chain->tag relationships")

    print()
    print(f"CSV generation complete! Output directory: {output_dir}")


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
    transform_all_to_neo4j(commands, chains, cheatsheets, str(output_dir))

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
