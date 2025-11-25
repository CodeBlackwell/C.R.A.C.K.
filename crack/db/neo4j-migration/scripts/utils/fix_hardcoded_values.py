#!/usr/bin/env python3
"""
Round 8: Fix hardcoded values in commands.
Replace hardcoded ports/IPs with placeholders where appropriate.
"""

import json
from pathlib import Path

def fix_hardcoded_values(base_path: Path) -> dict:
    """Fix specific hardcoded values that should be placeholders"""

    stats = {
        'files_modified': 0,
        'values_fixed': 0,
        'commands_fixed': []
    }

    # Specific fixes to apply
    fixes = [
        {
            'file': 'post-exploit/general-transfer.json',
            'command_id': 'ftp-transfer',
            'old': 'python3 -m pyftpdlib -p 21 -w',
            'new': 'python3 -m pyftpdlib -p <PORT> -w',
            'add_variable': {
                'name': '<PORT>',
                'description': 'FTP server port',
                'example': '21',
                'required': False
            }
        },
        {
            'file': 'enumeration/auto-generated-enumeration-stubs.json',
            'command_id': 'nmap-smb-enum',
            'old': 'sudo nmap -p 445',
            'new': 'sudo nmap -p <PORT>',
            'add_variable': {
                'name': '<PORT>',
                'description': 'SMB port to scan',
                'example': '445',
                'required': False
            }
        }
    ]

    for fix in fixes:
        file_path = base_path / fix['file']

        if not file_path.exists():
            print(f"✗ File not found: {fix['file']}")
            continue

        with open(file_path) as f:
            data = json.load(f)

        modified = False

        for cmd in data.get('commands', []):
            if cmd.get('id') != fix['command_id']:
                continue

            # Replace command text
            if fix['old'] in cmd.get('command', ''):
                cmd['command'] = cmd['command'].replace(fix['old'], fix['new'])
                modified = True

                # Add variable if not exists
                if 'variables' not in cmd:
                    cmd['variables'] = []

                # Check if variable already exists
                var_name = fix['add_variable']['name']
                var_exists = any(v.get('name') == var_name
                                for v in cmd['variables']
                                if isinstance(v, dict))

                if not var_exists:
                    cmd['variables'].append(fix['add_variable'])

                stats['values_fixed'] += 1
                stats['commands_fixed'].append(
                    f"{fix['file']}: {fix['command_id']}"
                )
                print(f"✓ Fixed {fix['command_id']} in {fix['file']}")

        if modified:
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
            stats['files_modified'] += 1

    return stats


def main():
    base_path = Path('db/data/commands')

    print("=" * 80)
    print("ROUND 8: FIX HARDCODED VALUES")
    print("=" * 80)
    print("Strategy: Replace hardcoded ports with placeholders")
    print()

    stats = fix_hardcoded_values(base_path)

    print("\n" + "=" * 80)
    print("ROUND 8 RESULTS")
    print("=" * 80)
    print(f"Files modified: {stats['files_modified']}")
    print(f"Hardcoded values fixed: {stats['values_fixed']}")

    if stats['commands_fixed']:
        print("\nCommands fixed:")
        for cmd in stats['commands_fixed']:
            print(f"  ✓ {cmd}")

    print("\nNOTE: Some 'hardcoded' values were intentional:")
    print("  - 0.0.0.0 in php-web-server (binds to all interfaces)")
    print("  - Instructional text like 'password: root' (not actual values)")

    print("\n" + "=" * 80)
    print("NEXT STEP: Run validation to confirm")
    print("  python3 db/neo4j-migration/scripts/utils/validate_schema_compliance.py")
    print("=" * 80)


if __name__ == '__main__':
    main()
