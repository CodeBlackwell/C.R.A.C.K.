#!/usr/bin/env python3
"""
Round 9: Remove unused variable definitions.
Variables defined but not used in command text.
"""

import json
import re
from pathlib import Path

def fix_unused_variables(base_path: Path) -> dict:
    """Remove variable definitions that aren't used in commands"""

    stats = {
        'files_modified': 0,
        'variables_removed': 0,
        'commands_fixed': 0
    }

    for json_file in base_path.rglob('*.json'):
        try:
            with open(json_file) as f:
                data = json.load(f)

            modified = False

            for cmd in data.get('commands', []):
                command_text = cmd.get('command', '')

                if 'variables' not in cmd or not isinstance(cmd['variables'], list):
                    continue

                # Find placeholders in command
                placeholders = set(re.findall(r'<([A-Z_][A-Z0-9_]*)>', command_text))

                # Find defined variables
                defined_vars = []
                for var in cmd['variables']:
                    if isinstance(var, dict) and 'name' in var:
                        var_name = var['name'].strip('<>')
                        defined_vars.append((var_name, var))

                # Filter to keep only used variables
                original_count = len(defined_vars)
                used_vars = [var_def for var_name, var_def in defined_vars
                            if var_name in placeholders]

                if len(used_vars) < original_count:
                    cmd['variables'] = used_vars
                    removed = original_count - len(used_vars)
                    stats['variables_removed'] += removed
                    stats['commands_fixed'] += 1
                    modified = True

            # Save if modified
            if modified:
                with open(json_file, 'w') as f:
                    json.dump(data, f, indent=2)
                stats['files_modified'] += 1

        except Exception as e:
            print(f"✗ Error processing {json_file.name}: {e}")

    return stats


def main():
    base_path = Path('reference/data/commands')

    print("=" * 80)
    print("ROUND 9: CLEAN UNUSED VARIABLE DEFINITIONS")
    print("=" * 80)
    print("Strategy: Remove variables not referenced in command text")
    print()

    stats = fix_unused_variables(base_path)

    print("\n" + "=" * 80)
    print("ROUND 9 RESULTS")
    print("=" * 80)
    print(f"Files modified: {stats['files_modified']}")
    print(f"Commands cleaned: {stats['commands_fixed']}")
    print(f"Variables removed: {stats['variables_removed']}")

    print("\n" + "=" * 80)
    print("NEXT STEP: Run validation to confirm")
    print("  python3 db/neo4j-migration/scripts/utils/validate_schema_compliance.py")
    print("=" * 80)


if __name__ == '__main__':
    main()
