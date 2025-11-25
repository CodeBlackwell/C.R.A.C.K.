#!/usr/bin/env python3
"""
Load and validate existing JSON files from db/data/

Scans commands, chains, and cheatsheets directories for JSON files,
parses them, and validates structure.
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Any, Tuple
import argparse
from load_writeups import load_writeup_jsons


def load_command_jsons(base_dir: str = "db/data/commands") -> Tuple[List[Dict], List[str]]:
    """Load all command JSON files, return list of command dicts and errors"""
    commands = []
    errors = []

    base_path = Path(base_dir)
    if not base_path.exists():
        errors.append(f"Commands directory not found: {base_dir}")
        return commands, errors

    json_files = list(base_path.rglob("*.json"))

    for json_file in json_files:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            if 'commands' in data and isinstance(data['commands'], list):
                for cmd in data['commands']:
                    cmd['_source_file'] = str(json_file.relative_to(base_path.parent))
                    commands.append(cmd)
            else:
                errors.append(f"Invalid structure in {json_file}: missing 'commands' array")

        except json.JSONDecodeError as e:
            errors.append(f"JSON parse error in {json_file}: {e}")
        except Exception as e:
            errors.append(f"Error loading {json_file}: {e}")

    return commands, errors


def load_attack_chain_jsons(base_dir: str = "db/data/chains") -> Tuple[List[Dict], List[str]]:
    """Load all attack chain JSON files, return list of chain dicts and errors"""
    chains = []
    errors = []

    base_path = Path(base_dir)
    if not base_path.exists():
        errors.append(f"Attack chains directory not found: {base_dir}")
        return chains, errors

    json_files = list(base_path.rglob("*.json"))

    for json_file in json_files:
        # Skip metadata.json
        if json_file.name == "metadata.json":
            continue

        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Attack chain files contain single chain per file
            if 'id' in data and 'steps' in data:
                data['_source_file'] = str(json_file.relative_to(base_path.parent))
                chains.append(data)
            else:
                errors.append(f"Invalid attack chain structure in {json_file}: missing 'id' or 'steps'")

        except json.JSONDecodeError as e:
            errors.append(f"JSON parse error in {json_file}: {e}")
        except Exception as e:
            errors.append(f"Error loading {json_file}: {e}")

    return chains, errors


def load_cheatsheet_jsons(base_dir: str = "db/data/cheatsheets") -> Tuple[List[Dict], List[str]]:
    """Load all cheatsheet JSON files, return list of cheatsheet dicts and errors"""
    cheatsheets = []
    errors = []

    base_path = Path(base_dir)
    if not base_path.exists():
        errors.append(f"Cheatsheets directory not found: {base_dir}")
        return cheatsheets, errors

    json_files = list(base_path.rglob("*.json"))

    for json_file in json_files:
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            data['_source_file'] = str(json_file.relative_to(base_path.parent))

            # Cheatsheets may have different structures - normalize
            if 'cheatsheets' in data:
                # Array of cheatsheets (Active Directory format)
                for sheet in data.get('cheatsheets', []):
                    sheet['_source_file'] = str(json_file.relative_to(base_path.parent))
                    sheet['_is_cheatsheet'] = True
                    cheatsheets.append(sheet)
            elif 'commands' in data:
                # Same structure as command files
                for cmd in data.get('commands', []):
                    cmd['_source_file'] = str(json_file.relative_to(base_path.parent))
                    cmd['_is_cheatsheet'] = True
                    cheatsheets.append(cmd)
            elif 'sections' in data:
                # Section-based structure (like quick-wins)
                data['_is_cheatsheet'] = True
                cheatsheets.append(data)
            else:
                # Generic cheatsheet structure
                data['_is_cheatsheet'] = True
                cheatsheets.append(data)

        except json.JSONDecodeError as e:
            errors.append(f"JSON parse error in {json_file}: {e}")
        except Exception as e:
            errors.append(f"Error loading {json_file}: {e}")

    return cheatsheets, errors


def validate_loaded_data(commands: List[Dict], chains: List[Dict], cheatsheets: List[Dict]) -> Dict[str, Any]:
    """Validate data integrity, return statistics and issues"""

    stats = {
        'total_commands': len(commands),
        'total_chains': len(chains),
        'total_cheatsheets': len(cheatsheets),
        'unique_command_ids': 0,
        'unique_chain_ids': 0,
        'total_variables': 0,
        'total_tags': 0,
        'total_flags': 0,
        'total_steps': 0,
        'total_relationships': 0,
        'issues': []
    }

    # Check for duplicate command IDs
    command_ids = set()
    duplicate_ids = set()
    for cmd in commands:
        cmd_id = cmd.get('id')
        if cmd_id:
            if cmd_id in command_ids:
                duplicate_ids.add(cmd_id)
            command_ids.add(cmd_id)
        else:
            stats['issues'].append(f"Command missing ID in {cmd.get('_source_file', 'unknown')}")

    stats['unique_command_ids'] = len(command_ids)
    if duplicate_ids:
        stats['issues'].append(f"Duplicate command IDs: {', '.join(sorted(duplicate_ids))}")

    # Check for duplicate chain IDs
    chain_ids = set()
    duplicate_chain_ids = set()
    for chain in chains:
        chain_id = chain.get('id')
        if chain_id:
            if chain_id in chain_ids:
                duplicate_chain_ids.add(chain_id)
            chain_ids.add(chain_id)
        else:
            stats['issues'].append(f"Chain missing ID in {chain.get('_source_file', 'unknown')}")

    stats['unique_chain_ids'] = len(chain_ids)
    if duplicate_chain_ids:
        stats['issues'].append(f"Duplicate chain IDs: {', '.join(sorted(duplicate_chain_ids))}")

    # Count variables
    all_tags = set()
    for cmd in commands:
        variables = cmd.get('variables', [])
        stats['total_variables'] += len(variables)

        tags = cmd.get('tags', [])
        all_tags.update(tags)

        flags = cmd.get('flag_explanations', {})
        stats['total_flags'] += len(flags)

        alternatives = cmd.get('alternatives', [])
        prerequisites = cmd.get('prerequisites', [])
        stats['total_relationships'] += len(alternatives) + len(prerequisites)

    stats['total_tags'] = len(all_tags)

    # Count chain steps and relationships
    for chain in chains:
        steps = chain.get('steps', [])
        stats['total_steps'] += len(steps)

        chain_tags = chain.get('metadata', {}).get('tags', [])
        all_tags.update(chain_tags)

        # Count step dependencies
        for step in steps:
            deps = step.get('dependencies', [])
            stats['total_relationships'] += len(deps)

    # Validate command references in attack chain steps
    for chain in chains:
        for step in chain.get('steps', []):
            cmd_ref = step.get('command_ref')
            if cmd_ref and cmd_ref not in command_ids:
                stats['issues'].append(
                    f"Chain '{chain.get('id')}' step '{step.get('id')}' references "
                    f"unknown command: {cmd_ref}"
                )

    # Validate alternative/prerequisite references
    for cmd in commands:
        cmd_id = cmd.get('id')
        for alt in cmd.get('alternatives', []):
            # Skip if alternative is a dict or not a string (malformed data)
            if not isinstance(alt, str):
                continue
            if alt not in command_ids:
                stats['issues'].append(f"Command '{cmd_id}' references unknown alternative: {alt}")

        for prereq in cmd.get('prerequisites', []):
            # Skip if prerequisite is a dict or not a string (malformed data)
            if not isinstance(prereq, str):
                continue
            if prereq not in command_ids:
                stats['issues'].append(f"Command '{cmd_id}' references unknown prerequisite: {prereq}")

    return stats


def main():
    parser = argparse.ArgumentParser(
        description="Load and validate existing JSON files from db/data/"
    )
    parser.add_argument(
        '--base-dir',
        default='db/data',
        help='Base directory (default: db/data/)'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show file-by-file progress'
    )
    parser.add_argument(
        '--validate',
        action='store_true',
        help='Run validation checks'
    )

    args = parser.parse_args()

    # Determine base directory
    if os.path.isabs(args.base_dir):
        base_dir = Path(args.base_dir)
    else:
        # Relative to current working directory
        base_dir = Path.cwd() / args.base_dir

    print(f"Loading JSON files from: {base_dir}")
    print()

    # Load commands
    cmd_dir = base_dir / "commands"
    print(f"Loading commands from: {cmd_dir}")
    commands, cmd_errors = load_command_jsons(str(cmd_dir))
    print(f"  Loaded {len(commands)} commands")
    if cmd_errors and args.verbose:
        for err in cmd_errors:
            print(f"  ERROR: {err}")

    # Load attack chains
    chain_dir = base_dir / "chains"
    print(f"Loading attack chains from: {chain_dir}")
    chains, chain_errors = load_attack_chain_jsons(str(chain_dir))
    print(f"  Loaded {len(chains)} attack chains")
    if chain_errors and args.verbose:
        for err in chain_errors:
            print(f"  ERROR: {err}")

    # Load cheatsheets
    sheet_dir = base_dir / "cheatsheets"
    print(f"Loading cheatsheets from: {sheet_dir}")
    cheatsheets, sheet_errors = load_cheatsheet_jsons(str(sheet_dir))
    print(f"  Loaded {len(cheatsheets)} cheatsheet entries")
    if sheet_errors and args.verbose:
        for err in sheet_errors:
            print(f"  ERROR: {err}")

    print()

    # Validation
    if args.validate:
        print("Validating data integrity...")
        stats = validate_loaded_data(commands, chains, cheatsheets)

        print(f"\nStatistics:")
        print(f"  Total commands: {stats['total_commands']}")
        print(f"  Unique command IDs: {stats['unique_command_ids']}")
        print(f"  Total attack chains: {stats['total_chains']}")
        print(f"  Unique chain IDs: {stats['unique_chain_ids']}")
        print(f"  Total cheatsheet entries: {stats['total_cheatsheets']}")
        print(f"  Total variables: {stats['total_variables']}")
        print(f"  Total unique tags: {stats['total_tags']}")
        print(f"  Total flags: {stats['total_flags']}")
        print(f"  Total chain steps: {stats['total_steps']}")
        print(f"  Total relationships: {stats['total_relationships']}")

        if stats['issues']:
            print(f"\nData Quality Issues ({len(stats['issues'])}):")
            for issue in stats['issues'][:20]:  # Show first 20
                print(f"  - {issue}")
            if len(stats['issues']) > 20:
                print(f"  ... and {len(stats['issues']) - 20} more issues")
            return 1
        else:
            print("\nNo data integrity issues found!")

    all_errors = cmd_errors + chain_errors + sheet_errors
    if all_errors:
        print(f"\nTotal errors: {len(all_errors)}")
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
