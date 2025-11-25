#!/usr/bin/env python3
"""
Round 4: Remove orphaned command references.
Orphaned refs are command IDs in alternatives/prerequisites that don't exist.
"""

import json
from pathlib import Path
from typing import Dict, Set
from collections import defaultdict

def load_valid_command_ids(index_path: Path) -> Set[str]:
    """Load all valid command IDs from the index"""
    with open(index_path) as f:
        command_index = json.load(f)
    return set(command_index.keys())


def remove_orphaned_refs(base_path: Path, valid_ids: Set[str]) -> Dict:
    """Remove orphaned references from all commands"""

    stats = {
        'files_scanned': 0,
        'files_modified': 0,
        'alternatives_removed': 0,
        'prerequisites_removed': 0,
        'next_steps_removed': 0,
        'total_removed': 0
    }

    orphaned_by_file = defaultdict(lambda: {
        'alternatives': [],
        'prerequisites': [],
        'next_steps': []
    })

    for json_file in base_path.rglob('*.json'):
        try:
            with open(json_file) as f:
                data = json.load(f)

            modified = False
            stats['files_scanned'] += 1

            for cmd in data.get('commands', []):
                cmd_id = cmd.get('id', '')

                # Check alternatives
                if 'alternatives' in cmd and isinstance(cmd['alternatives'], list):
                    original_alts = cmd['alternatives']
                    valid_alts = []

                    for alt in original_alts:
                        if not isinstance(alt, str):
                            # Keep non-string entries (shouldn't exist, but preserve)
                            valid_alts.append(alt)
                        elif alt in valid_ids:
                            # Valid command ID
                            valid_alts.append(alt)
                        else:
                            # Orphaned reference - remove it
                            stats['alternatives_removed'] += 1
                            stats['total_removed'] += 1
                            modified = True
                            rel_path = str(json_file.relative_to(base_path))
                            orphaned_by_file[rel_path]['alternatives'].append({
                                'command_id': cmd_id,
                                'orphaned_ref': alt
                            })

                    if len(valid_alts) != len(original_alts):
                        cmd['alternatives'] = valid_alts

                # Check prerequisites
                if 'prerequisites' in cmd and isinstance(cmd['prerequisites'], list):
                    original_prereqs = cmd['prerequisites']
                    valid_prereqs = []

                    for prereq in original_prereqs:
                        if not isinstance(prereq, str):
                            valid_prereqs.append(prereq)
                        elif prereq in valid_ids:
                            valid_prereqs.append(prereq)
                        else:
                            stats['prerequisites_removed'] += 1
                            stats['total_removed'] += 1
                            modified = True
                            rel_path = str(json_file.relative_to(base_path))
                            orphaned_by_file[rel_path]['prerequisites'].append({
                                'command_id': cmd_id,
                                'orphaned_ref': prereq
                            })

                    if len(valid_prereqs) != len(original_prereqs):
                        cmd['prerequisites'] = valid_prereqs

                # Check next_steps (if they reference command IDs)
                if 'next_steps' in cmd and isinstance(cmd['next_steps'], list):
                    original_next = cmd['next_steps']
                    valid_next = []

                    for step in original_next:
                        if not isinstance(step, str):
                            valid_next.append(step)
                        # Only remove if it looks like a command ID (kebab-case)
                        elif '-' in step and step in valid_ids:
                            valid_next.append(step)
                        elif '-' in step and step not in valid_ids:
                            # Might be orphaned command ID reference
                            # Only remove if it matches command ID pattern
                            if step.replace('-', '').replace('_', '').isalnum() and len(step) < 50:
                                stats['next_steps_removed'] += 1
                                stats['total_removed'] += 1
                                modified = True
                                rel_path = str(json_file.relative_to(base_path))
                                orphaned_by_file[rel_path]['next_steps'].append({
                                    'command_id': cmd_id,
                                    'orphaned_ref': step
                                })
                            else:
                                # Keep it (likely descriptive text)
                                valid_next.append(step)
                        else:
                            # Not a command ID reference, keep it
                            valid_next.append(step)

                    if len(valid_next) != len(original_next):
                        cmd['next_steps'] = valid_next

            # Save if modified
            if modified:
                with open(json_file, 'w') as f:
                    json.dump(data, f, indent=2)
                stats['files_modified'] += 1

        except Exception as e:
            print(f"✗ Error processing {json_file.name}: {e}")

    stats['orphaned_by_file'] = orphaned_by_file
    return stats


def main():
    base_path = Path('db/data/commands')
    index_path = Path('db/neo4j-migration/data/command_index.json')

    print("=" * 80)
    print("ROUND 4: REMOVE ORPHANED COMMAND REFERENCES")
    print("=" * 80)

    # Load valid command IDs
    print(f"Loading valid command IDs from {index_path}...")
    valid_ids = load_valid_command_ids(index_path)
    print(f"Loaded {len(valid_ids)} valid command IDs")

    # Remove orphaned references
    print("\nScanning for orphaned references...")
    print("-" * 80)

    stats = remove_orphaned_refs(base_path, valid_ids)

    # Print results
    print("\n" + "=" * 80)
    print("ROUND 4 RESULTS")
    print("=" * 80)
    print(f"Files scanned: {stats['files_scanned']}")
    print(f"Files modified: {stats['files_modified']}")
    print(f"\nOrphaned references removed:")
    print(f"  Alternatives: {stats['alternatives_removed']}")
    print(f"  Prerequisites: {stats['prerequisites_removed']}")
    print(f"  Next steps: {stats['next_steps_removed']}")
    print(f"  TOTAL: {stats['total_removed']}")

    # Show top files with orphaned refs
    if stats['orphaned_by_file']:
        print("\n" + "=" * 80)
        print("TOP FILES WITH ORPHANED REFERENCES:")
        print("=" * 80)

        file_counts = []
        for file_path, orphans in stats['orphaned_by_file'].items():
            total = (len(orphans['alternatives']) +
                    len(orphans['prerequisites']) +
                    len(orphans['next_steps']))
            file_counts.append((file_path, total, orphans))

        for file_path, count, orphans in sorted(file_counts, key=lambda x: -x[1])[:10]:
            print(f"\n{file_path} ({count} orphaned refs)")
            if orphans['alternatives']:
                print(f"  Alternatives: {len(orphans['alternatives'])}")
                for item in orphans['alternatives'][:3]:
                    print(f"    - {item['orphaned_ref']} (in {item['command_id']})")
            if orphans['prerequisites']:
                print(f"  Prerequisites: {len(orphans['prerequisites'])}")
                for item in orphans['prerequisites'][:3]:
                    print(f"    - {item['orphaned_ref']} (in {item['command_id']})")

    print("\n" + "=" * 80)
    print("NEXT STEP: Run validation to confirm")
    print("  python3 db/neo4j-migration/scripts/utils/validate_schema_compliance.py")
    print("=" * 80)


if __name__ == '__main__':
    main()
