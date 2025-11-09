#!/usr/bin/env python3
"""
Round 12: Remove unused variables from auto-generated stub files.
These stubs have old variable format (dict) with unused TARGET placeholders.
"""

import json
import re
from pathlib import Path

def fix_stub_unused_variables(base_path: Path) -> dict:
    """Remove unused variable definitions from stub files"""

    stats = {
        'files_modified': 0,
        'variables_removed': 0,
        'commands_fixed': 0
    }

    # Target the 3 stub files with violations
    stub_files = [
        'enumeration/auto-generated-enumeration-stubs.json',
        'post-exploitation/auto-generated-post-exploitation-stubs.json',
        'utilities/auto-generated-utilities-stubs.json',
    ]

    for stub_file in stub_files:
        file_path = base_path / stub_file

        if not file_path.exists():
            print(f"✗ File not found: {stub_file}")
            continue

        with open(file_path) as f:
            data = json.load(f)

        modified = False

        for cmd in data.get('commands', []):
            command_text = cmd.get('command', '')

            # Skip if no variables field
            if 'variables' not in cmd:
                continue

            # Find placeholders in command text
            placeholders = set(re.findall(r'<([A-Z0-9_]+)>', command_text))

            # Handle OLD format (dict) and NEW format (array)
            if isinstance(cmd['variables'], dict):
                # Old format: {"<TARGET>": {...}}
                old_vars = cmd['variables']
                used_vars = {}

                for var_name, var_def in old_vars.items():
                    clean_name = var_name.strip('<>')
                    if clean_name in placeholders:
                        used_vars[var_name] = var_def

                if len(used_vars) < len(old_vars):
                    removed = len(old_vars) - len(used_vars)

                    if len(used_vars) == 0:
                        # Remove variables field entirely if empty
                        del cmd['variables']
                    else:
                        cmd['variables'] = used_vars

                    stats['variables_removed'] += removed
                    stats['commands_fixed'] += 1
                    modified = True
                    print(f"✓ Removed {removed} unused vars from '{cmd.get('id')}' in {stub_file}")

            elif isinstance(cmd['variables'], list):
                # New format: [{"name": "<TARGET>", ...}]
                old_vars = cmd['variables']
                used_vars = []

                for var in old_vars:
                    if isinstance(var, dict) and 'name' in var:
                        var_name = var['name'].strip('<>')
                        if var_name in placeholders:
                            used_vars.append(var)

                if len(used_vars) < len(old_vars):
                    removed = len(old_vars) - len(used_vars)

                    if len(used_vars) == 0:
                        # Remove variables field entirely if empty
                        del cmd['variables']
                    else:
                        cmd['variables'] = used_vars

                    stats['variables_removed'] += removed
                    stats['commands_fixed'] += 1
                    modified = True
                    print(f"✓ Removed {removed} unused vars from '{cmd.get('id')}' in {stub_file}")

        # Save if modified
        if modified:
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
            stats['files_modified'] += 1

    return stats


def main():
    base_path = Path('reference/data/commands')

    print("=" * 80)
    print("ROUND 12: CLEAN UNUSED VARIABLES FROM STUB FILES")
    print("=" * 80)
    print("Strategy: Remove unused variables from auto-generated stubs")
    print()

    stats = fix_stub_unused_variables(base_path)

    print("\n" + "=" * 80)
    print("ROUND 12 RESULTS")
    print("=" * 80)
    print(f"Files modified: {stats['files_modified']}")
    print(f"Commands cleaned: {stats['commands_fixed']}")
    print(f"Variables removed: {stats['variables_removed']}")

    print("\n" + "=" * 80)
    print("NEXT STEP: Run validation to confirm 100% compliance")
    print("  python3 db/neo4j-migration/scripts/utils/validate_schema_compliance.py")
    print("=" * 80)


if __name__ == '__main__':
    main()
