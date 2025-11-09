#!/usr/bin/env python3
"""
Generate Fixes Checklist - Create comprehensive checklist document

Purpose: Generate markdown checklist with all violations for tracking fixes
Output: db/neo4j-migration/FIXES_CHECKLIST_DETAILED.md
"""

import json
import sys
from pathlib import Path
from collections import defaultdict, Counter
from datetime import datetime

def looks_like_id(text: str) -> bool:
    """Check if text looks like command ID"""
    return ' ' not in text and '<' not in text and len(text) < 50

def main():
    # Paths
    project_root = Path('/home/kali/Desktop/OSCP/crack')
    commands_dir = project_root / 'reference' / 'data' / 'commands'
    output_file = project_root / 'db' / 'neo4j-migration' / 'FIXES_CHECKLIST_DETAILED.md'

    # Statistics
    stats = {
        'files': 0,
        'commands': 0,
        'violations': defaultdict(list),
        'duplicates': defaultdict(list),
        'alternatives_ids': 0,
        'alternatives_text': 0,
        'prerequisites_ids': 0,
        'prerequisites_text': 0,
    }

    seen_ids = {}
    all_ids = set()
    referenced_ids = set()

    # Scan all JSON files
    for json_file in sorted(commands_dir.rglob('*.json')):
        stats['files'] += 1
        try:
            with open(json_file) as f:
                data = json.load(f)

            for cmd in data.get('commands', []):
                stats['commands'] += 1
                cmd_id = cmd.get('id', 'MISSING_ID')

                # Check for duplicate IDs
                if cmd_id in seen_ids:
                    stats['violations']['duplicate_ids'].append({
                        'id': cmd_id,
                        'file1': seen_ids[cmd_id],
                        'file2': str(json_file.relative_to(commands_dir))
                    })
                else:
                    seen_ids[cmd_id] = str(json_file.relative_to(commands_dir))
                    all_ids.add(cmd_id)

                # Check alternatives
                if cmd.get('alternatives'):
                    alts = cmd['alternatives']
                    if all(looks_like_id(a) for a in alts):
                        stats['alternatives_ids'] += 1
                        referenced_ids.update(alts)
                    else:
                        stats['alternatives_text'] += 1
                        stats['violations']['alternatives_text'].append({
                            'id': cmd_id,
                            'file': str(json_file.relative_to(commands_dir)),
                            'alternatives': alts
                        })

                # Check prerequisites
                if cmd.get('prerequisites'):
                    prereqs = cmd['prerequisites']
                    if all(looks_like_id(p) for p in prereqs):
                        stats['prerequisites_ids'] += 1
                        referenced_ids.update(prereqs)
                    else:
                        stats['prerequisites_text'] += 1
                        stats['violations']['prerequisites_text'].append({
                            'id': cmd_id,
                            'file': str(json_file.relative_to(commands_dir)),
                            'prerequisites': prereqs
                        })

        except Exception as e:
            print(f"Error processing {json_file}: {e}")

    # Find orphaned references
    orphaned = referenced_ids - all_ids
    if orphaned:
        stats['violations']['orphaned_references'] = sorted(orphaned)

    # Generate markdown checklist
    output = []
    output.append("# Migration Fixes - Detailed Checklist\n")
    output.append(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    output.append(f"**Total Commands**: {stats['commands']}\n")
    output.append(f"**Total Violations**: {sum(len(v) for v in stats['violations'].values())}\n")
    output.append("\n---\n")

    # Summary
    output.append("## Summary\n")
    output.append("| Violation Type | Count | Status |\n")
    output.append("|----------------|-------|--------|\n")
    for vtype, items in stats['violations'].items():
        count = len(items)
        output.append(f"| {vtype.replace('_', ' ').title()} | {count} | ❌ |\n")
    output.append("\n---\n")

    # Duplicate IDs
    if stats['violations'].get('duplicate_ids'):
        output.append("## 🔴 Duplicate IDs\n")
        output.append(f"\n**Total**: {len(stats['violations']['duplicate_ids'])}\n\n")

        for i, item in enumerate(stats['violations']['duplicate_ids'], 1):
            output.append(f"### {i}. `{item['id']}`\n\n")
            output.append(f"- [ ] **ID**: `{item['id']}`\n")
            output.append(f"- [ ] **Location 1**: `{item['file1']}`\n")
            output.append(f"- [ ] **Location 2**: `{item['file2']}`\n")
            output.append(f"- [ ] **Action**: Rename or remove duplicate\n")
            output.append("\n")

        output.append("\n---\n")

    # Alternatives using text
    if stats['violations'].get('alternatives_text'):
        output.append("## 🟡 Alternatives Using Text\n")
        output.append(f"\n**Total**: {len(stats['violations']['alternatives_text'])}\n\n")

        for i, item in enumerate(stats['violations']['alternatives_text'], 1):
            output.append(f"### {i}. `{item['id']}`\n\n")
            output.append(f"- [ ] **Command ID**: `{item['id']}`\n")
            output.append(f"- [ ] **File**: `{item['file']}`\n")
            output.append(f"- [ ] **Current alternatives (text)**:\n")
            for alt in item['alternatives']:
                output.append(f"  - `{alt}`\n")
            output.append(f"- [ ] **Action**: Replace with command IDs or create missing commands\n")
            output.append("\n")

        output.append("\n---\n")

    # Prerequisites using text
    if stats['violations'].get('prerequisites_text'):
        output.append("## 🟡 Prerequisites Using Text\n")
        output.append(f"\n**Total**: {len(stats['violations']['prerequisites_text'])}\n\n")

        for i, item in enumerate(stats['violations']['prerequisites_text'], 1):
            output.append(f"### {i}. `{item['id']}`\n\n")
            output.append(f"- [ ] **Command ID**: `{item['id']}`\n")
            output.append(f"- [ ] **File**: `{item['file']}`\n")
            output.append(f"- [ ] **Current prerequisites (text)**:\n")
            for prereq in item['prerequisites']:
                output.append(f"  - `{prereq}`\n")
            output.append(f"- [ ] **Action**: Replace with command IDs or create missing commands\n")
            output.append("\n")

        output.append("\n---\n")

    # Orphaned references
    if stats['violations'].get('orphaned_references'):
        output.append("## 🟡 Orphaned References\n")
        output.append(f"\n**Total**: {len(stats['violations']['orphaned_references'])}\n\n")

        for i, ref_id in enumerate(stats['violations']['orphaned_references'], 1):
            output.append(f"### {i}. `{ref_id}`\n\n")
            output.append(f"- [ ] **Referenced ID**: `{ref_id}`\n")
            output.append(f"- [ ] **Status**: Referenced but doesn't exist\n")
            output.append(f"- [ ] **Action**: Create command or fix typo\n")
            output.append("\n")

        output.append("\n---\n")

    # Progress tracking
    output.append("## Progress Tracking\n\n")
    output.append("### Phase 1: Duplicate IDs\n")
    output.append(f"- [ ] Fixed: 0 / {len(stats['violations'].get('duplicate_ids', []))}\n")
    output.append(f"- [ ] Remaining: {len(stats['violations'].get('duplicate_ids', []))}\n\n")

    output.append("### Phase 2: Alternatives\n")
    output.append(f"- [ ] Fixed: 0 / {len(stats['violations'].get('alternatives_text', []))}\n")
    output.append(f"- [ ] Remaining: {len(stats['violations'].get('alternatives_text', []))}\n\n")

    output.append("### Phase 3: Prerequisites\n")
    output.append(f"- [ ] Fixed: 0 / {len(stats['violations'].get('prerequisites_text', []))}\n")
    output.append(f"- [ ] Remaining: {len(stats['violations'].get('prerequisites_text', []))}\n\n")

    output.append("### Phase 4: Orphaned References\n")
    output.append(f"- [ ] Fixed: 0 / {len(stats['violations'].get('orphaned_references', []))}\n")
    output.append(f"- [ ] Remaining: {len(stats['violations'].get('orphaned_references', []))}\n\n")

    output.append("\n---\n")
    output.append(f"\n**Last Updated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    # Write to file
    with open(output_file, 'w') as f:
        f.writelines(output)

    print(f"✓ Checklist generated: {output_file}")
    print(f"  Total violations: {sum(len(v) for v in stats['violations'].values())}")
    print(f"  File size: {output_file.stat().st_size:,} bytes")

if __name__ == '__main__':
    main()
