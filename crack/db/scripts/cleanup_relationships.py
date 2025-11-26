#!/usr/bin/env python3
"""
Comprehensive relationship cleanup script.
Fixes broken references, converts text to IDs, and migrates to methodology_guidance.
"""

import json
import glob
import re
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Set, Tuple

def load_fix_mapping(suggestions_file: str) -> Dict[str, str]:
    """Load high-confidence broken reference fixes."""
    with open(suggestions_file) as f:
        suggestions = json.load(f)

    # Only use high-confidence matches (>0.8 similarity)
    mapping = {}
    for broken_id, data in suggestions.items():
        if data['action'] == 'replace' and data['matches']:
            best_match = data['matches'][0]
            if best_match['similarity'] > 0.8:
                mapping[broken_id] = best_match['id']

    return mapping

def load_all_command_ids(commands_dir: str) -> Set[str]:
    """Load all valid command IDs."""
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
            pass

    return command_ids

def categorize_text_for_methodology(text: str) -> str:
    """Categorize text into methodology_guidance sub-field."""
    text_lower = text.lower()

    # Patterns for different guidance categories
    patterns = {
        'after_success': [
            r'^\s*(then|next|after|if successful)',
            r'(enumerate|scan|check|verify|test).*(more|further|next)',
            r'^\s*run\s',
            r'^\s*perform\s'
        ],
        'on_failure': [
            r'^\s*(if (this )?fails?|when blocked|if no results)',
            r'(try|attempt|use).*(instead|alternative)',
            r'^\s*fallback'
        ],
        'time_estimate': [
            r'\d+\s*(minutes?|hours?|seconds?|mins?|hrs?)',
            r'(quick|fast|slow|takes|estimated)'
        ],
        'oscp_tips': [
            r'oscp|exam|lab|practice',
            r'(common|typical|usually|often) (in|on|during|for)',
            r'exam.?time'
        ],
        'manual_alternative': [
            r'manual(ly)?',
            r'without.*(tool|script)',
            r'by hand',
            r'can also.*(use|do|try)'
        ]
    }

    # Check patterns
    for category, pattern_list in patterns.items():
        for pattern in pattern_list:
            if re.search(pattern, text_lower):
                return category

    # Default: after_success
    return 'after_success'

def cleanup_command_file(filepath: str, fix_mapping: Dict[str, str],
                         all_command_ids: Set[str], backup_dir: Path, dry_run: bool = True) -> Dict:
    """Clean up a single command file."""

    stats = {
        'file': filepath,
        'changes': 0,
        'broken_fixed': 0,
        'moved_to_methodology': 0,
        'errors': []
    }

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        stats['errors'].append(f"Failed to load: {e}")
        return stats

    commands = data.get('commands', [data] if 'id' in data else [])
    modified = False

    for cmd in commands:
        cmd_id = cmd.get('id', 'unknown')

        # Initialize methodology_guidance if not exists
        if 'methodology_guidance' not in cmd:
            cmd['methodology_guidance'] = {}

        methodology = cmd['methodology_guidance']

        # Process each relationship field
        for field in ['next_steps', 'alternatives', 'prerequisites']:
            if field not in cmd or not isinstance(cmd[field], list):
                continue

            new_field_values = []
            texts_for_methodology = []

            for item in cmd[field]:
                if not isinstance(item, str):
                    new_field_values.append(item)
                    continue

                # Check if it's a valid command ID
                if re.match(r'^[a-z0-9]+(-[a-z0-9]+)*$', item):
                    # Valid ID format
                    if item in all_command_ids:
                        # Exists - keep it
                        new_field_values.append(item)
                    elif item in fix_mapping:
                        # Broken reference with known fix
                        new_field_values.append(fix_mapping[item])
                        stats['broken_fixed'] += 1
                        stats['changes'] += 1
                        modified = True
                    else:
                        # Broken reference, no fix - remove for now
                        # Could optionally keep or log
                        stats['errors'].append(f"{cmd_id}.{field}: Broken ref {item} (no fix)")
                else:
                    # Text description - move to methodology_guidance
                    category = categorize_text_for_methodology(item)
                    texts_for_methodology.append((category, item))
                    stats['moved_to_methodology'] += 1
                    stats['changes'] += 1
                    modified = True

            # Update field with clean IDs only
            if modified:
                cmd[field] = new_field_values

            # Add texts to methodology_guidance
            for category, text in texts_for_methodology:
                if category not in methodology:
                    methodology[category] = text
                else:
                    # Append if not already present
                    if text not in methodology[category]:
                        methodology[category] += f" {text}"

        # Clean empty methodology fields
        if not methodology:
            del cmd['methodology_guidance']

    # Save if modified and not dry run
    if modified and not dry_run:
        # Backup original to centralized backup directory
        # Preserve directory structure in backup
        file_path = Path(filepath).resolve()

        # Use the filepath as-is if already relative, otherwise make it relative
        if Path(filepath).is_absolute():
            relative_path = file_path.relative_to(Path.cwd())
        else:
            relative_path = Path(filepath)

        backup_path = backup_dir / relative_path

        # Create backup subdirectories if needed
        backup_path.parent.mkdir(parents=True, exist_ok=True)

        # Copy to backup
        shutil.copy(filepath, backup_path)

        # Write cleaned version
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write('\n')  # Add trailing newline

        stats['backed_up_to'] = str(backup_path)

    return stats

def cleanup_all_files(commands_dir: str, suggestions_file: str, backup_dir: str, dry_run: bool = True):
    """Clean up all command files."""

    print(f"{'DRY RUN MODE' if dry_run else 'LIVE MODE'} - Cleanup starting...")
    print("="*80)

    # Create backup directory
    backup_path = Path(backup_dir)
    if not dry_run:
        backup_path.mkdir(parents=True, exist_ok=True)
        print(f"Backups will be saved to: {backup_path.absolute()}")
        print()

    # Load fix mapping
    fix_mapping = load_fix_mapping(suggestions_file)
    print(f"Loaded {len(fix_mapping)} high-confidence broken reference fixes")

    # Load all valid command IDs
    all_command_ids = load_all_command_ids(commands_dir)
    print(f"Loaded {len(all_command_ids)} valid command IDs")
    print()

    # Process all JSON files
    json_files = glob.glob(f'{commands_dir}/**/*.json', recursive=True)
    json_files = [f for f in json_files if not '.backup' in f]

    total_stats = {
        'files_processed': 0,
        'files_modified': 0,
        'total_changes': 0,
        'broken_fixed': 0,
        'moved_to_methodology': 0,
        'errors': []
    }

    for json_file in sorted(json_files):
        stats = cleanup_command_file(json_file, fix_mapping, all_command_ids, backup_path, dry_run)

        total_stats['files_processed'] += 1
        if stats['changes'] > 0:
            total_stats['files_modified'] += 1
            total_stats['total_changes'] += stats['changes']
            total_stats['broken_fixed'] += stats['broken_fixed']
            total_stats['moved_to_methodology'] += stats['moved_to_methodology']

            print(f"{'[DRY RUN] ' if dry_run else ''}Modified: {json_file}")
            print(f"  Changes: {stats['changes']} "
                  f"(broken fixed: {stats['broken_fixed']}, "
                  f"moved to guidance: {stats['moved_to_methodology']})")

        if stats['errors']:
            total_stats['errors'].extend(stats['errors'])

    # Print summary
    print("\n" + "="*80)
    print("CLEANUP SUMMARY")
    print("="*80)
    print(f"Files processed: {total_stats['files_processed']}")
    print(f"Files modified: {total_stats['files_modified']}")
    print(f"Total changes: {total_stats['total_changes']}")
    print(f"  Broken references fixed: {total_stats['broken_fixed']}")
    print(f"  Texts moved to methodology_guidance: {total_stats['moved_to_methodology']}")
    print(f"Errors encountered: {len(total_stats['errors'])}")

    if total_stats['errors'][:10]:
        print("\nFirst 10 errors:")
        for err in total_stats['errors'][:10]:
            print(f"  - {err}")

    return total_stats

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Clean up command relationship violations')
    parser.add_argument('--commands-dir', default='db/data/commands')
    parser.add_argument('--suggestions', default='broken_reference_suggestions.json',
                        help='Broken reference fix suggestions file')
    parser.add_argument('--backup-dir', default='db/backups/relationship_cleanup',
                        help='Directory to store backups')
    parser.add_argument('--dry-run', action='store_true',
                        help='Show what would be changed without modifying files')
    parser.add_argument('--apply', action='store_true',
                        help='Actually apply the changes (creates backups)')

    args = parser.parse_args()

    if not args.apply and not args.dry_run:
        print("Warning: Neither --dry-run nor --apply specified. Defaulting to dry-run.")
        args.dry_run = True

    dry_run = not args.apply

    # Run cleanup
    stats = cleanup_all_files(args.commands_dir, args.suggestions, args.backup_dir, dry_run=dry_run)

    if dry_run:
        print("\n" + "="*80)
        print("DRY RUN COMPLETE - No files were modified")
        print("Run with --apply to actually make changes")
        print("="*80)
