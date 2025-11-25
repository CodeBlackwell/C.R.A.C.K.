#!/usr/bin/env python3
"""
Round 7: Fix final 11 text-based alternatives.
Strategy: Move text to notes field, remove from alternatives.
"""

import json
from pathlib import Path

def fix_text_alternatives(base_path: Path, index_path: Path) -> dict:
    """Move text alternatives to notes field"""

    # Load valid IDs
    with open(index_path) as f:
        valid_ids = set(json.load(f).keys())

    stats = {
        'files_modified': 0,
        'alternatives_moved': 0,
        'commands_fixed': []
    }

    for json_file in base_path.rglob('*.json'):
        try:
            with open(json_file) as f:
                data = json.load(f)

            modified = False

            for cmd in data.get('commands', []):
                if 'alternatives' not in cmd or not isinstance(cmd['alternatives'], list):
                    continue

                original_alts = cmd['alternatives'][:]
                valid_alts = []
                moved_to_notes = []

                for alt in original_alts:
                    if not isinstance(alt, str):
                        valid_alts.append(alt)
                        continue

                    # Check if it's text (has spaces, long, or special chars)
                    is_text = (' ' in alt or len(alt) > 60 or
                              any(char in alt for char in [':', '.', '(', ')']))

                    if is_text:
                        # Move to notes
                        moved_to_notes.append(alt)
                        modified = True
                        stats['alternatives_moved'] += 1
                    else:
                        # Keep in alternatives
                        valid_alts.append(alt)

                if moved_to_notes:
                    # Update alternatives
                    cmd['alternatives'] = valid_alts

                    # Append to notes
                    current_notes = cmd.get('notes', '')

                    # Create alternative techniques section
                    alt_section = "\n\nAlternative Techniques:\n" + "\n".join(
                        f"- {alt}" for alt in moved_to_notes
                    )

                    if current_notes:
                        cmd['notes'] = current_notes.rstrip() + alt_section
                    else:
                        cmd['notes'] = alt_section.strip()

                    rel_path = str(json_file.relative_to(base_path))
                    stats['commands_fixed'].append(
                        f"{rel_path}: {cmd.get('id')} ({len(moved_to_notes)} alternatives)"
                    )

            # Save if modified
            if modified:
                with open(json_file, 'w') as f:
                    json.dump(data, f, indent=2)
                stats['files_modified'] += 1

        except Exception as e:
            print(f"✗ Error processing {json_file.name}: {e}")

    return stats


def main():
    base_path = Path('db/data/commands')
    index_path = Path('db/neo4j-migration/data/command_index.json')

    print("=" * 80)
    print("ROUND 7: FIX FINAL TEXT-BASED ALTERNATIVES")
    print("=" * 80)
    print("Strategy: Move text alternatives to notes field")
    print()

    stats = fix_text_alternatives(base_path, index_path)

    print("\n" + "=" * 80)
    print("ROUND 7 RESULTS")
    print("=" * 80)
    print(f"Files modified: {stats['files_modified']}")
    print(f"Alternatives moved to notes: {stats['alternatives_moved']}")

    if stats['commands_fixed']:
        print("\nCommands fixed:")
        for cmd in stats['commands_fixed']:
            print(f"  ✓ {cmd}")

    print("\n" + "=" * 80)
    print("NEXT STEP: Run validation to confirm")
    print("  python3 db/neo4j-migration/scripts/utils/validate_schema_compliance.py")
    print("=" * 80)


if __name__ == '__main__':
    main()
