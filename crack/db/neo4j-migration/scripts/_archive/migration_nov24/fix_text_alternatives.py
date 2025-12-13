#!/usr/bin/env python3
"""
Round 3: Auto-fix text-based alternatives/prerequisites using QUICK_WIN_UPDATES.
"""

import json
from pathlib import Path
from typing import Dict, List
from collections import defaultdict

def apply_quick_wins(base_path: Path, updates_file: Path) -> Dict:
    """Apply quick-win updates from the analysis"""

    with open(updates_file) as f:
        updates_data = json.load(f)

    stats = {
        'files_modified': 0,
        'updates_applied': 0,
        'updates_failed': 0,
        'by_confidence': defaultdict(int)
    }

    files_to_modify = defaultdict(list)

    # Group updates by file
    for file_entry in updates_data['files']:
        file_path = file_entry['file'].replace('data/commands/', '')
        for update in file_entry['updates']:
            files_to_modify[file_path].append(update)

    # Apply updates file by file
    for rel_path, updates in files_to_modify.items():
        file_path = base_path / rel_path

        if not file_path.exists():
            print(f"✗ File not found: {rel_path}")
            stats['updates_failed'] += len(updates)
            continue

        try:
            with open(file_path) as f:
                data = json.load(f)

            modified = False

            # Apply each update
            for update in updates:
                cmd_id = update['command_id']
                field = update['field']
                old_text = update['old_text']
                new_id = update['new_id']
                confidence = update['confidence']

                # Find the command
                cmd = next((c for c in data.get('commands', []) if c.get('id') == cmd_id), None)

                if not cmd:
                    print(f"  ✗ Command not found: {cmd_id} in {rel_path}")
                    stats['updates_failed'] += 1
                    continue

                # Update the field
                if field in cmd and isinstance(cmd[field], list):
                    if old_text in cmd[field]:
                        # Replace text with ID
                        idx = cmd[field].index(old_text)
                        cmd[field][idx] = new_id
                        modified = True
                        stats['updates_applied'] += 1
                        stats['by_confidence'][confidence] += 1
                    else:
                        # Already updated or text not found
                        stats['updates_failed'] += 1
                elif field in cmd and isinstance(cmd[field], str):
                    if cmd[field] == old_text:
                        cmd[field] = new_id
                        modified = True
                        stats['updates_applied'] += 1
                        stats['by_confidence'][confidence] += 1
                    else:
                        stats['updates_failed'] += 1

            # Save if modified
            if modified:
                with open(file_path, 'w') as f:
                    json.dump(data, f, indent=2)
                stats['files_modified'] += 1
                print(f"✓ {rel_path}: {len([u for u in updates if u['command_id'] in [c['id'] for c in data.get('commands', [])]])} updates applied")

        except Exception as e:
            print(f"✗ Error processing {rel_path}: {e}")
            stats['updates_failed'] += len(updates)

    return stats


def fix_remaining_alternatives(base_path: Path) -> Dict:
    """
    Fix remaining text-based alternatives by attempting fuzzy matching.
    This handles the 70% that aren't in QUICK_WIN_UPDATES.
    """
    from difflib import SequenceMatcher

    def similarity_ratio(a: str, b: str) -> float:
        """Calculate similarity ratio between two strings (0-100)"""
        return SequenceMatcher(None, a.lower(), b.lower()).ratio() * 100

    # Load command index
    index_path = Path('db/neo4j-migration/data/command_index.json')
    with open(index_path) as f:
        command_index = json.load(f)

    all_ids = set(command_index.keys())

    stats = {
        'files_scanned': 0,
        'alternatives_checked': 0,
        'fuzzy_matches': 0,
        'no_match': 0
    }

    files_modified = 0

    for json_file in base_path.rglob('*.json'):
        try:
            with open(json_file) as f:
                data = json.load(f)

            modified = False
            stats['files_scanned'] += 1

            for cmd in data.get('commands', []):
                # Check alternatives
                if 'alternatives' in cmd and isinstance(cmd['alternatives'], list):
                    new_alternatives = []

                    for alt in cmd['alternatives']:
                        stats['alternatives_checked'] += 1

                        # Skip if already an ID
                        if isinstance(alt, str) and alt in all_ids:
                            new_alternatives.append(alt)
                            continue

                        # Skip if not a string (nested objects, etc.)
                        if not isinstance(alt, str):
                            continue

                        # Try exact match
                        if alt in all_ids:
                            new_alternatives.append(alt)
                            continue

                        # Try fuzzy matching
                        best_match = None
                        best_score = 0

                        for cmd_id in all_ids:
                            score = similarity_ratio(alt, cmd_id)
                            if score > best_score:
                                best_score = score
                                best_match = cmd_id

                        # Use fuzzy match if score > 80
                        if best_score > 80:
                            new_alternatives.append(best_match)
                            stats['fuzzy_matches'] += 1
                            modified = True
                        else:
                            # Keep original text (will be caught in next round)
                            new_alternatives.append(alt)
                            stats['no_match'] += 1

                    if modified:
                        cmd['alternatives'] = new_alternatives

            # Save if modified
            if modified:
                with open(json_file, 'w') as f:
                    json.dump(data, f, indent=2)
                files_modified += 1

        except Exception as e:
            pass

    stats['files_modified'] = files_modified
    return stats


def main():
    base_path = Path('db/data/commands')
    updates_file = Path('db/neo4j-migration/data/QUICK_WIN_UPDATES.json')

    print("=" * 80)
    print("ROUND 3: FIX TEXT-BASED ALTERNATIVES")
    print("=" * 80)

    # Phase 1: Apply quick wins (high confidence)
    print("\nPhase 1: Applying quick-win updates (64 high-confidence mappings)...")
    print("-" * 80)

    quick_win_stats = apply_quick_wins(base_path, updates_file)

    print("\n" + "=" * 80)
    print("PHASE 1 RESULTS (Quick Wins)")
    print("=" * 80)
    print(f"Files modified: {quick_win_stats['files_modified']}")
    print(f"Updates applied: {quick_win_stats['updates_applied']}")
    print(f"Updates failed: {quick_win_stats['updates_failed']}")
    print(f"\nBy confidence:")
    for conf, count in sorted(quick_win_stats['by_confidence'].items()):
        print(f"  {conf}: {count}")

    # Phase 2: Fuzzy matching for remaining alternatives
    print("\n" + "=" * 80)
    print("Phase 2: Fuzzy matching for remaining alternatives...")
    print("-" * 80)

    fuzzy_stats = fix_remaining_alternatives(base_path)

    print("\n" + "=" * 80)
    print("PHASE 2 RESULTS (Fuzzy Matching)")
    print("=" * 80)
    print(f"Files scanned: {fuzzy_stats['files_scanned']}")
    print(f"Alternatives checked: {fuzzy_stats['alternatives_checked']}")
    print(f"Fuzzy matches found: {fuzzy_stats['fuzzy_matches']}")
    print(f"No match found: {fuzzy_stats['no_match']}")
    print(f"Files modified: {fuzzy_stats['files_modified']}")

    print("\n" + "=" * 80)
    print("ROUND 3 TOTAL RESULTS")
    print("=" * 80)
    total_fixed = quick_win_stats['updates_applied'] + fuzzy_stats['fuzzy_matches']
    print(f"Total alternatives fixed: {total_fixed}")
    print(f"Total files modified: {quick_win_stats['files_modified'] + fuzzy_stats['files_modified']}")

    print("\n" + "=" * 80)
    print("NEXT STEP: Run validation to confirm")
    print("  python3 db/neo4j-migration/scripts/utils/validate_schema_compliance.py")
    print("=" * 80)


if __name__ == '__main__':
    main()
