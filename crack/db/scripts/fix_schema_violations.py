#!/usr/bin/env python3
"""Fix all remaining schema violations"""

import json
import re
from pathlib import Path

# Category mappings (invalid -> valid)
CATEGORY_FIXES = {
    'ENUMERATION': 'enumeration',
    'LATERAL_MOVEMENT': 'exploitation',
    'POST_EXPLOIT': 'post-exploit',
    'SHELLS': 'exploitation',
    'cleanup': 'utilities',
    'lateral-movement': 'exploitation',
}

# ID renames (old -> new)
ID_RENAMES = {
    'rbcd-getST': 'rbcd-get-st',
    'impacket-getST-constrained': 'impacket-get-st-constrained',
}


def fix_command(cmd, all_command_ids):
    """Fix violations in a single command. Returns (modified, fixes_applied)"""
    fixes = []

    # Fix 1: Invalid ID format
    if cmd.get('id') in ID_RENAMES:
        old_id = cmd['id']
        cmd['id'] = ID_RENAMES[old_id]
        fixes.append(f"ID: {old_id} -> {cmd['id']}")

    # Fix 2: Invalid category
    if cmd.get('category') in CATEGORY_FIXES:
        old_cat = cmd['category']
        cmd['category'] = CATEGORY_FIXES[old_cat]
        fixes.append(f"category: {old_cat} -> {cmd['category']}")

    # Fix 3: Remove text from alternatives (keep only valid kebab-case IDs)
    if 'alternatives' in cmd:
        original = cmd['alternatives']
        valid = [a for a in original if re.match(r'^[a-z0-9]+(-[a-z0-9]+)*$', a)]
        if len(valid) != len(original):
            removed = set(original) - set(valid)
            cmd['alternatives'] = valid
            fixes.append(f"alternatives: removed {removed}")

    # Fix 4: Remove orphaned references (refs to non-existent commands)
    for field in ['alternatives', 'prerequisites']:
        if field in cmd:
            original = cmd[field]
            valid = [ref for ref in original if ref in all_command_ids]
            if len(valid) != len(original):
                removed = set(original) - set(valid)
                cmd[field] = valid
                fixes.append(f"{field}: removed orphans {removed}")

    # Fix 5: Remove unused variables
    if 'variables' in cmd and cmd.get('command'):
        placeholders = set(re.findall(r'<([A-Z0-9_]+)>', cmd['command']))
        original_count = len(cmd['variables'])
        used_vars = []
        for var in cmd['variables']:
            if isinstance(var, dict):
                name = var.get('name', '').strip('<>')
                if name in placeholders:
                    used_vars.append(var)
            else:
                used_vars.append(var)
        if len(used_vars) != original_count:
            removed = original_count - len(used_vars)
            cmd['variables'] = used_vars
            fixes.append(f"variables: removed {removed} unused")

    return len(fixes) > 0, fixes


def load_all_command_ids(commands_dir):
    """Load all valid command IDs"""
    all_ids = set()
    for json_file in commands_dir.rglob('*.json'):
        try:
            with open(json_file) as f:
                data = json.load(f)
            for cmd in data.get('commands', []):
                if cmd.get('id'):
                    all_ids.add(cmd['id'])
        except:
            pass
    return all_ids


def process_file(json_file, all_command_ids):
    """Fix violations in all commands in a file"""
    with open(json_file, 'r') as f:
        data = json.load(f)

    file_modified = False
    all_fixes = []

    for cmd in data.get('commands', []):
        modified, fixes = fix_command(cmd, all_command_ids)
        if modified:
            file_modified = True
            all_fixes.append((cmd.get('id'), fixes))

    if file_modified:
        with open(json_file, 'w') as f:
            json.dump(data, f, indent=2)

    return file_modified, all_fixes


def main():
    commands_dir = Path(__file__).parent.parent / 'data' / 'commands'

    print("Loading all command IDs...")
    all_command_ids = load_all_command_ids(commands_dir)
    print(f"Found {len(all_command_ids)} command IDs")
    print()

    print(f"Processing files in: {commands_dir}")
    print("=" * 70)

    total_updated = 0
    total_fixes = 0

    for json_file in sorted(commands_dir.rglob('*.json')):
        modified, fixes = process_file(json_file, all_command_ids)
        if modified:
            rel_path = json_file.relative_to(commands_dir)
            print(f"\n{rel_path}:")
            for cmd_id, fix_list in fixes:
                for fix in fix_list:
                    print(f"  [{cmd_id}] {fix}")
                    total_fixes += 1
            total_updated += 1

    print()
    print("=" * 70)
    print(f"Total files updated: {total_updated}")
    print(f"Total fixes applied: {total_fixes}")


if __name__ == '__main__':
    main()
