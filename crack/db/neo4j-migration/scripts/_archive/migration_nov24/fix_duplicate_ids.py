#!/usr/bin/env python3
"""
Round 6: Fix duplicate command IDs.
Strategy: Keep manually-created commands, remove auto-generated stubs.
"""

import json
from pathlib import Path
from collections import defaultdict

def fix_duplicates(base_path: Path) -> dict:
    """Remove duplicate IDs, keeping manually-created versions"""

    stats = {
        'files_modified': 0,
        'duplicates_removed': 0,
        'commands_removed': []
    }

    # Specific duplicates to remove
    remove_commands = [
        # import-powerup: keep manual version, remove stub
        ('enumeration/auto-generated-enumeration-stubs.json', 'import-powerup'),

        # psloggedon: keep manual version in ad-session-share-enum.json
        ('utilities/auto-generated-utilities-stubs.json', 'psloggedon'),

        # admin (3 instances - all garbage, remove all)
        ('post-exploitation/auto-generated-post-exploitation-stubs.json', 'admin'),
        ('utilities/auto-generated-utilities-stubs.json', 'admin'),

        # rubeus (2 instances in same file - keep first, remove second)
        # Will handle by removing the one with less complete command
    ]

    # Process specific removals
    for file_path_rel, cmd_id in remove_commands:
        file_path = base_path / file_path_rel

        if not file_path.exists():
            continue

        with open(file_path) as f:
            data = json.load(f)

        original_count = len(data.get('commands', []))
        data['commands'] = [cmd for cmd in data.get('commands', [])
                           if cmd.get('id') != cmd_id]
        removed = original_count - len(data['commands'])

        if removed > 0:
            # Update metadata if present
            if 'metadata' in data and 'count' in data['metadata']:
                data['metadata']['count'] = len(data['commands'])

            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)

            stats['files_modified'] += 1
            stats['duplicates_removed'] += removed
            stats['commands_removed'].append(f"{file_path_rel}: {cmd_id}")
            print(f"✓ Removed '{cmd_id}' from {file_path_rel}")

    # Handle rubeus duplicates (both in utilities-stubs)
    rubeus_file = base_path / 'utilities/auto-generated-utilities-stubs.json'
    if rubeus_file.exists():
        with open(rubeus_file) as f:
            data = json.load(f)

        # Find all rubeus commands
        rubeus_commands = [cmd for cmd in data.get('commands', [])
                          if cmd.get('id') == 'rubeus']

        if len(rubeus_commands) > 1:
            # Keep the one with more complete command, remove others
            best = max(rubeus_commands, key=lambda x: len(x.get('command', '')))

            # Remove all rubeus, then add back the best one
            data['commands'] = [cmd for cmd in data['commands']
                               if cmd.get('id') != 'rubeus']
            data['commands'].append(best)

            # Update metadata
            if 'metadata' in data and 'count' in data['metadata']:
                data['metadata']['count'] = len(data['commands'])

            with open(rubeus_file, 'w') as f:
                json.dump(data, f, indent=2)

            removed_count = len(rubeus_commands) - 1
            stats['duplicates_removed'] += removed_count
            stats['commands_removed'].append(f"utilities/auto-generated-utilities-stubs.json: rubeus ({removed_count} duplicates)")
            print(f"✓ Removed {removed_count} duplicate 'rubeus' entries")

    return stats


def main():
    base_path = Path('db/data/commands')

    print("=" * 80)
    print("ROUND 6: FIX DUPLICATE COMMAND IDs")
    print("=" * 80)
    print()

    stats = fix_duplicates(base_path)

    print("\n" + "=" * 80)
    print("ROUND 6 RESULTS")
    print("=" * 80)
    print(f"Files modified: {stats['files_modified']}")
    print(f"Duplicates removed: {stats['duplicates_removed']}")

    if stats['commands_removed']:
        print("\nCommands removed:")
        for cmd in stats['commands_removed']:
            print(f"  - {cmd}")

    print("\n" + "=" * 80)
    print("NEXT STEP: Run validation to confirm")
    print("  python3 db/neo4j-migration/scripts/utils/validate_schema_compliance.py")
    print("=" * 80)


if __name__ == '__main__':
    main()
