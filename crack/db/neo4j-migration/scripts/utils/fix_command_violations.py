#!/usr/bin/env python3
"""
Auto-fix command validation violations.
Fixes common schema compliance issues in command JSON files.
"""

import json
import glob
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# Category mapping: invalid -> valid
CATEGORY_MAPPING = {
    'active-directory': 'exploitation',
    'post-exploitation': 'post-exploit',
    'tunneling': 'pivoting',
    'monitoring': 'enumeration',
    'password-attacks': 'exploitation',
}

VALID_CATEGORIES = ['recon', 'web', 'exploitation', 'post-exploit', 'enumeration', 'pivoting', 'file-transfer', 'custom']

def fix_category(category: str) -> str:
    """Fix invalid category names."""
    if category in VALID_CATEGORIES:
        return category

    # Try mapping
    if category in CATEGORY_MAPPING:
        return CATEGORY_MAPPING[category]

    # Default to custom
    return 'custom'

def fix_variables_array(variables):
    """Fix variables array if it's malformed."""
    if not variables:
        return []

    if not isinstance(variables, list):
        return []

    fixed_vars = []
    for var in variables:
        if isinstance(var, str):
            # String instead of dict - convert
            fixed_vars.append({
                'name': var if var.startswith('<') else f'<{var}>',
                'description': 'Auto-fixed variable',
                'example': '',
                'required': True
            })
        elif isinstance(var, dict):
            # Ensure required fields
            if 'name' not in var:
                continue  # Skip invalid variable

            fixed_var = {
                'name': var.get('name', ''),
                'description': var.get('description', 'Auto-fixed variable'),
                'example': var.get('example', var.get('default', '')),
                'required': var.get('required', True)
            }
            fixed_vars.append(fixed_var)

    return fixed_vars

def fix_array_field(value):
    """Ensure field is an array."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return value
    return []

def fix_command(cmd: dict) -> tuple[dict, list]:
    """Fix a single command and return (fixed_cmd, changes)."""
    changes = []
    fixed = cmd.copy()

    # Fix category
    if 'category' in fixed:
        old_cat = fixed['category']
        new_cat = fix_category(old_cat)
        if old_cat != new_cat:
            fixed['category'] = new_cat
            changes.append(f"Category: {old_cat} -> {new_cat}")

    # Fix variables array
    if 'variables' in fixed:
        old_vars = fixed['variables']
        new_vars = fix_variables_array(old_vars)
        if old_vars != new_vars:
            fixed['variables'] = new_vars
            changes.append(f"Variables: fixed {len(new_vars)} variables")

    # Fix array fields
    array_fields = ['tags', 'alternatives', 'prerequisites', 'next_steps', 'success_indicators', 'failure_indicators']
    for field in array_fields:
        if field in fixed:
            old_val = fixed[field]
            new_val = fix_array_field(old_val)
            if old_val != new_val:
                fixed[field] = new_val
                changes.append(f"{field}: converted to array")

    # Ensure troubleshooting is dict
    if 'troubleshooting' in fixed and not isinstance(fixed['troubleshooting'], dict):
        fixed['troubleshooting'] = {}
        changes.append("troubleshooting: converted to dict")

    # Ensure flag_explanations is dict
    if 'flag_explanations' in fixed and not isinstance(fixed['flag_explanations'], dict):
        fixed['flag_explanations'] = {}
        changes.append("flag_explanations: converted to dict")

    return fixed, changes

def fix_file(json_file: str, dry_run: bool = False) -> tuple[int, list]:
    """Fix a single JSON file and return (fixes_count, error_list)."""
    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        return 0, [f"Failed to read: {e}"]

    # Handle both single command files and command arrays
    commands = data.get('commands', [data] if 'id' in data else [])

    total_fixes = 0
    all_changes = []
    fixed_commands = []

    for cmd in commands:
        fixed_cmd, changes = fix_command(cmd)
        fixed_commands.append(fixed_cmd)

        if changes:
            total_fixes += len(changes)
            cmd_id = cmd.get('id', 'unknown')
            all_changes.append(f"  [{cmd_id}] {', '.join(changes)}")

    # Write back if changes were made
    if total_fixes > 0 and not dry_run:
        if 'commands' in data:
            data['commands'] = fixed_commands
        else:
            data = fixed_commands[0] if len(fixed_commands) == 1 else data

        try:
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            return 0, [f"Failed to write: {e}"]

    return total_fixes, all_changes

def fix_all_commands(commands_dir: str = "reference/data/commands", dry_run: bool = False):
    """Fix all command files."""

    json_files = glob.glob(f'{commands_dir}/**/*.json', recursive=True)

    total_files = 0
    files_fixed = 0
    total_fixes = 0
    fix_details = {}

    for json_file in sorted(json_files):
        # Skip backup files
        if json_file.endswith('.bak') or '.backup' in json_file:
            continue

        total_files += 1
        fixes_count, changes = fix_file(json_file, dry_run)

        if fixes_count > 0:
            files_fixed += 1
            total_fixes += fixes_count
            fix_details[json_file] = changes

    return {
        'timestamp': datetime.now().isoformat(),
        'dry_run': dry_run,
        'summary': {
            'files_scanned': total_files,
            'files_fixed': files_fixed,
            'total_fixes': total_fixes
        },
        'details': fix_details
    }

def print_report(report):
    """Print fix report."""
    print("\n" + "="*80)
    print("COMMAND FIX REPORT")
    print("="*80)
    print(f"Timestamp: {report['timestamp']}")
    print(f"Mode: {'DRY RUN' if report['dry_run'] else 'LIVE'}")
    print(f"\nFiles Scanned: {report['summary']['files_scanned']}")
    print(f"Files Fixed: {report['summary']['files_fixed']}")
    print(f"Total Fixes Applied: {report['summary']['total_fixes']}")

    if report['details']:
        print(f"\n--- Files Modified (showing first 20) ---")
        for i, (file_path, changes) in enumerate(list(report['details'].items())[:20]):
            print(f"\n[{i+1}] {file_path}")
            for change in changes[:10]:
                print(change)
            if len(changes) > 10:
                print(f"  ... and {len(changes) - 10} more changes")

    print("="*80 + "\n")

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Auto-fix command validation violations')
    parser.add_argument('--commands-dir', default='reference/data/commands',
                       help='Directory containing command JSON files')
    parser.add_argument('--output', default='fix_report.json',
                       help='Output JSON report file')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be fixed without modifying files')

    args = parser.parse_args()

    # Run fixes
    report = fix_all_commands(args.commands_dir, args.dry_run)

    # Print report
    print_report(report)

    # Save JSON report
    with open(args.output, 'w') as f:
        json.dump(report, f, indent=2)
    print(f"Full report saved to: {args.output}")
