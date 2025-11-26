#!/usr/bin/env python3
"""
Analyze relationship violations in command JSON files.
Identifies text descriptions in next_steps, alternatives, and prerequisites
that should be command ID references.
"""

import json
import glob
import re
import csv
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple, Set

def is_valid_command_id(text: str) -> bool:
    """Check if text matches command ID format (kebab-case)."""
    if not isinstance(text, str):
        return False
    # Valid command IDs: lowercase, numbers, hyphens only
    return bool(re.match(r'^[a-z0-9]+(-[a-z0-9]+)*$', text))

def load_all_command_ids(commands_dir: str) -> Set[str]:
    """Load all command IDs from the database."""
    command_ids = set()

    json_files = glob.glob(f'{commands_dir}/**/*.json', recursive=True)
    for json_file in json_files:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            commands = data.get('commands', [data] if 'id' in data else [])
            for cmd in commands:
                if 'id' in cmd:
                    command_ids.add(cmd['id'])
        except Exception as e:
            print(f"Error loading {json_file}: {e}")

    return command_ids

def categorize_violation(text: str, all_command_ids: Set[str]) -> Tuple[str, List[str]]:
    """
    Categorize violation as direct match, fuzzy match, or missing command.

    Returns:
        (confidence, match_candidates)
        confidence: 'direct', 'fuzzy', 'missing'
        match_candidates: list of potential command IDs
    """
    # Direct match - text is already a command ID
    if text in all_command_ids:
        return 'direct', [text]

    # Extract tool names and actions from text
    tool_keywords = ['nmap', 'sqlmap', 'enum4linux', 'kerbrute', 'impacket',
                     'crackmapexec', 'bloodhound', 'mimikatz', 'rubeus',
                     'smbclient', 'rpcclient', 'john', 'hashcat', 'hydra',
                     'gobuster', 'ffuf', 'burp', 'netcat', 'nc', 'curl',
                     'wget', 'powershell', 'ps', 'evil-winrm', 'winrm']

    text_lower = text.lower()
    candidates = []

    # Check if any tool keyword is mentioned
    for tool in tool_keywords:
        if tool in text_lower:
            # Find command IDs that start with this tool
            matches = [cid for cid in all_command_ids if cid.startswith(tool)]
            candidates.extend(matches)

    # If we found candidates, it's a fuzzy match
    if candidates:
        return 'fuzzy', list(set(candidates))

    # No match found - missing command
    return 'missing', []

def analyze_command_relationships(commands_dir: str) -> Dict:
    """Analyze all relationship fields for violations."""

    all_command_ids = load_all_command_ids(commands_dir)
    print(f"Loaded {len(all_command_ids)} command IDs from database")

    violations = []
    stats = {
        'total_commands': 0,
        'total_violations': 0,
        'fields': {
            'next_steps': {'text_count': 0, 'id_count': 0, 'commands_with_field': 0},
            'alternatives': {'text_count': 0, 'id_count': 0, 'commands_with_field': 0},
            'prerequisites': {'text_count': 0, 'id_count': 0, 'commands_with_field': 0}
        },
        'categories': {
            'direct': 0,
            'fuzzy': 0,
            'missing': 0
        }
    }

    json_files = glob.glob(f'{commands_dir}/**/*.json', recursive=True)

    for json_file in json_files:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            print(f"Error reading {json_file}: {e}")
            continue

        commands = data.get('commands', [data] if 'id' in data else [])

        for cmd in commands:
            stats['total_commands'] += 1
            cmd_id = cmd.get('id', 'unknown')

            # Check each relationship field
            for field in ['next_steps', 'alternatives', 'prerequisites']:
                if field not in cmd:
                    continue

                stats['fields'][field]['commands_with_field'] += 1

                field_value = cmd[field]
                if not isinstance(field_value, list):
                    continue

                for item in field_value:
                    if is_valid_command_id(item):
                        # Valid ID format
                        stats['fields'][field]['id_count'] += 1

                        # Check if ID exists in database
                        if item not in all_command_ids:
                            violation = {
                                'file': json_file,
                                'command_id': cmd_id,
                                'field': field,
                                'violation_type': 'broken_reference',
                                'text': item,
                                'confidence': 'broken',
                                'candidates': []
                            }
                            violations.append(violation)
                            stats['total_violations'] += 1
                    else:
                        # Text description instead of ID
                        stats['fields'][field]['text_count'] += 1

                        confidence, candidates = categorize_violation(item, all_command_ids)
                        stats['categories'][confidence] += 1

                        violation = {
                            'file': json_file,
                            'command_id': cmd_id,
                            'field': field,
                            'violation_type': 'text_instead_of_id',
                            'text': item,
                            'confidence': confidence,
                            'candidates': candidates[:5]  # Top 5 candidates
                        }
                        violations.append(violation)
                        stats['total_violations'] += 1

    return {
        'violations': violations,
        'stats': stats,
        'all_command_ids': list(all_command_ids)
    }

def generate_csv_report(analysis: Dict, output_file: str):
    """Generate CSV report of violations."""

    with open(output_file, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=[
            'file', 'command_id', 'field', 'violation_type',
            'text', 'confidence', 'candidates'
        ])
        writer.writeheader()

        for violation in analysis['violations']:
            row = violation.copy()
            row['candidates'] = ' | '.join(row['candidates']) if row['candidates'] else ''
            writer.writerow(row)

    print(f"\nCSV report saved to: {output_file}")

def print_summary(analysis: Dict):
    """Print summary statistics."""
    stats = analysis['stats']

    print("\n" + "="*80)
    print("RELATIONSHIP VIOLATION ANALYSIS")
    print("="*80)

    print(f"\nTotal Commands: {stats['total_commands']}")
    print(f"Total Violations: {stats['total_violations']}")

    print("\n--- Violations by Field ---")
    for field, data in stats['fields'].items():
        total = data['text_count'] + data['id_count']
        pct = (data['text_count'] / total * 100) if total > 0 else 0
        print(f"\n{field}:")
        print(f"  Commands with field: {data['commands_with_field']}")
        print(f"  Valid IDs: {data['id_count']}")
        print(f"  Text violations: {data['text_count']}")
        print(f"  Violation rate: {pct:.1f}%")

    print("\n--- Violations by Category ---")
    total_cat = sum(stats['categories'].values())
    for category, count in stats['categories'].items():
        pct = (count / total_cat * 100) if total_cat > 0 else 0
        print(f"  {category}: {count} ({pct:.1f}%)")

    print("\n" + "="*80)

def print_examples(analysis: Dict, limit: int = 10):
    """Print example violations."""
    print("\n--- Example Violations ---\n")

    # Group by confidence
    by_confidence = defaultdict(list)
    for v in analysis['violations']:
        by_confidence[v['confidence']].append(v)

    for confidence in ['direct', 'fuzzy', 'missing', 'broken']:
        if confidence not in by_confidence:
            continue

        print(f"\n{confidence.upper()} ({len(by_confidence[confidence])} total):")
        for v in by_confidence[confidence][:limit]:
            print(f"  [{v['command_id']}] {v['field']}")
            print(f"    Text: \"{v['text'][:80]}...\" " if len(v['text']) > 80 else f"    Text: \"{v['text']}\"")
            if v['candidates']:
                print(f"    Candidates: {', '.join(v['candidates'][:3])}")
            print()

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='Analyze relationship violations in command JSON files'
    )
    parser.add_argument(
        '--commands-dir',
        default='db/data/commands',
        help='Directory containing command JSON files'
    )
    parser.add_argument(
        '--output-csv',
        default='violations_matrix.csv',
        help='Output CSV file for violations'
    )
    parser.add_argument(
        '--output-json',
        default='violations_analysis.json',
        help='Output JSON file for full analysis'
    )
    parser.add_argument(
        '--examples',
        type=int,
        default=5,
        help='Number of example violations to show per category'
    )

    args = parser.parse_args()

    # Run analysis
    print(f"Analyzing commands in: {args.commands_dir}")
    analysis = analyze_command_relationships(args.commands_dir)

    # Print summary
    print_summary(analysis)

    # Print examples
    if args.examples > 0:
        print_examples(analysis, args.examples)

    # Save reports
    generate_csv_report(analysis, args.output_csv)

    with open(args.output_json, 'w') as f:
        # Don't save full command ID list to JSON (too large)
        output_data = {
            'violations': analysis['violations'],
            'stats': analysis['stats']
        }
        json.dump(output_data, f, indent=2)

    print(f"JSON report saved to: {args.output_json}")
    print("\nAnalysis complete!")
