#!/usr/bin/env python3
"""
Suggest fixes for broken command references by finding similar existing commands.
"""

import json
import glob
from difflib import SequenceMatcher
from collections import defaultdict

def similarity(a: str, b: str) -> float:
    """Calculate similarity between two strings."""
    return SequenceMatcher(None, a, b).ratio()

def load_all_commands(commands_dir: str):
    """Load all commands with their details."""
    commands = {}

    json_files = glob.glob(f'{commands_dir}/**/*.json', recursive=True)
    for json_file in json_files:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            cmd_list = data.get('commands', [data] if 'id' in data else [])
            for cmd in cmd_list:
                if 'id' in cmd:
                    commands[cmd['id']] = {
                        'file': json_file,
                        'name': cmd.get('name', ''),
                        'description': cmd.get('description', ''),
                        'category': cmd.get('category', '')
                    }
        except Exception as e:
            print(f"Error loading {json_file}: {e}")

    return commands

def suggest_fixes(broken_ids, all_commands):
    """Suggest fixes for broken references."""
    suggestions = {}

    for broken_id in broken_ids:
        # Find similar command IDs
        similarities = []
        for cmd_id in all_commands:
            sim = similarity(broken_id, cmd_id)
            if sim > 0.5:  # Only consider if >50% similar
                similarities.append((cmd_id, sim, all_commands[cmd_id]))

        # Sort by similarity
        similarities.sort(key=lambda x: x[1], reverse=True)

        suggestions[broken_id] = {
            'top_matches': similarities[:5],
            'action': 'replace' if similarities and similarities[0][1] > 0.8 else 'create_or_remove'
        }

    return suggestions

def print_suggestions(suggestions):
    """Print fix suggestions."""
    print("\n" + "="*80)
    print("BROKEN REFERENCE FIX SUGGESTIONS")
    print("="*80)

    # Group by action
    replace = {k: v for k, v in suggestions.items() if v['action'] == 'replace'}
    create = {k: v for k, v in suggestions.items() if v['action'] == 'create_or_remove'}

    print(f"\nHIGH CONFIDENCE REPLACEMENTS ({len(replace)}):")
    print("These are likely typos or renamed commands")
    print("-" * 80)
    for broken_id, data in sorted(replace.items()):
        if data['top_matches']:
            best_match, sim, details = data['top_matches'][0]
            print(f"\n{broken_id}")
            print(f"  → {best_match} (similarity: {sim:.2f})")
            print(f"    {details['name']}")

    print(f"\n\nLOW CONFIDENCE - CREATE OR REMOVE ({len(create)}):")
    print("These may need new command entries or should be removed")
    print("-" * 80)
    for broken_id, data in sorted(create.items())[:20]:  # Show first 20
        print(f"\n{broken_id}")
        if data['top_matches']:
            print("  Possible matches:")
            for match_id, sim, details in data['top_matches'][:3]:
                print(f"    {match_id} ({sim:.2f}): {details['name']}")
        else:
            print("  No similar commands found - consider creating or removing")

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Suggest fixes for broken command references')
    parser.add_argument('--commands-dir', default='db/data/commands')
    parser.add_argument('--violations-file', default='violations_analysis.json')
    parser.add_argument('--output', default='broken_reference_suggestions.json')

    args = parser.parse_args()

    # Load violations
    with open(args.violations_file) as f:
        violations_data = json.load(f)

    # Get unique broken IDs
    broken_violations = [v for v in violations_data['violations']
                         if v['violation_type'] == 'broken_reference']
    broken_ids = sorted(set(v['text'] for v in broken_violations))

    print(f"Found {len(broken_ids)} unique broken references")

    # Load all commands
    all_commands = load_all_commands(args.commands_dir)
    print(f"Loaded {len(all_commands)} existing commands")

    # Generate suggestions
    suggestions = suggest_fixes(broken_ids, all_commands)

    # Print suggestions
    print_suggestions(suggestions)

    # Save to JSON
    with open(args.output, 'w') as f:
        # Simplify for JSON output
        output = {}
        for broken_id, data in suggestions.items():
            output[broken_id] = {
                'action': data['action'],
                'matches': [
                    {'id': m[0], 'similarity': m[1], 'name': m[2]['name']}
                    for m in data['top_matches']
                ]
            }
        json.dump(output, f, indent=2)

    print(f"\n\nSuggestions saved to: {args.output}")
