#!/usr/bin/env python3
"""
JSON Stats - Quick statistics and error detection for JSON command files

Usage: python3 json_stats.py [--verbose]
"""

import json
import sys
from pathlib import Path
from collections import defaultdict, Counter
from typing import Dict, List, Set

# ANSI colors
class Colors:
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    RED = '\033[31m'
    BLUE = '\033[36m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

def looks_like_id(text: str) -> bool:
    """Check if text looks like command ID (kebab-case, no spaces)"""
    return ' ' not in text and '<' not in text and len(text) < 50

def main():
    verbose = '--verbose' in sys.argv

    # Statistics
    stats = {
        'files': 0,
        'commands': 0,
        'categories': Counter(),
        'tags': Counter(),
        'oscp_relevance': Counter(),

        # Field presence
        'has_alternatives': 0,
        'has_prerequisites': 0,
        'has_next_steps': 0,
        'has_variables': 0,
        'has_flag_explanations': 0,

        # Schema violations
        'violations': defaultdict(list),
        'duplicates': defaultdict(list),

        # Alternatives/prerequisites analysis
        'alternatives_ids': 0,
        'alternatives_text': 0,
        'prerequisites_ids': 0,
        'prerequisites_text': 0,
    }

    seen_ids: Dict[str, str] = {}  # id -> file
    all_ids: Set[str] = set()
    referenced_ids: Set[str] = set()  # IDs referenced in alternatives/prerequisites

    # Scan all JSON files
    commands_dir = Path('/home/kali/Desktop/OSCP/crack/db/data/commands')

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
                        'file2': str(json_file)
                    })
                else:
                    seen_ids[cmd_id] = str(json_file)
                    all_ids.add(cmd_id)

                # Category stats
                category = cmd.get('category', 'MISSING')
                stats['categories'][category] += 1

                # OSCP relevance
                oscp = cmd.get('oscp_relevance', 'MISSING')
                stats['oscp_relevance'][oscp] += 1

                # Tags
                for tag in cmd.get('tags', []):
                    stats['tags'][tag] += 1

                # Field presence
                if cmd.get('alternatives'):
                    stats['has_alternatives'] += 1

                    # Check if alternatives are IDs or text
                    alts = cmd['alternatives']
                    if all(looks_like_id(a) for a in alts):
                        stats['alternatives_ids'] += 1
                        referenced_ids.update(alts)
                    else:
                        stats['alternatives_text'] += 1
                        if verbose:
                            stats['violations']['alternatives_text'].append({
                                'id': cmd_id,
                                'file': str(json_file.relative_to(commands_dir)),
                                'alternatives': alts[:2]  # First 2 only
                            })

                if cmd.get('prerequisites'):
                    stats['has_prerequisites'] += 1

                    # Check if prerequisites are IDs or text
                    prereqs = cmd['prerequisites']
                    if all(looks_like_id(p) for p in prereqs):
                        stats['prerequisites_ids'] += 1
                        referenced_ids.update(prereqs)
                    else:
                        stats['prerequisites_text'] += 1
                        if verbose:
                            stats['violations']['prerequisites_text'].append({
                                'id': cmd_id,
                                'file': str(json_file.relative_to(commands_dir)),
                                'prerequisites': prereqs[:2]
                            })

                if cmd.get('next_steps'):
                    stats['has_next_steps'] += 1

                if cmd.get('variables'):
                    stats['has_variables'] += 1

                if cmd.get('flag_explanations'):
                    stats['has_flag_explanations'] += 1

                # Missing required fields
                if not cmd.get('id'):
                    stats['violations']['missing_id'].append(str(json_file))
                if not cmd.get('name'):
                    stats['violations']['missing_name'].append(cmd_id)
                if not cmd.get('command'):
                    stats['violations']['missing_command'].append(cmd_id)
                if not cmd.get('description'):
                    stats['violations']['missing_description'].append(cmd_id)

        except json.JSONDecodeError as e:
            stats['violations']['invalid_json'].append({
                'file': str(json_file),
                'error': str(e)
            })
        except Exception as e:
            stats['violations']['parse_errors'].append({
                'file': str(json_file),
                'error': str(e)
            })

    # Find orphaned references (alternatives/prerequisites pointing to non-existent commands)
    orphaned = referenced_ids - all_ids
    if orphaned:
        stats['violations']['orphaned_references'] = sorted(orphaned)

    # Print report
    print(f"\n{Colors.BOLD}{'=' * 70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BLUE}JSON COMMAND FILES - QUICK STATS{Colors.RESET}")
    print(f"{Colors.BOLD}{'=' * 70}{Colors.RESET}\n")

    # Basic stats
    print(f"{Colors.BOLD}Basic Statistics:{Colors.RESET}")
    print(f"  Files scanned:      {stats['files']}")
    print(f"  Total commands:     {Colors.GREEN}{stats['commands']}{Colors.RESET}")

    # Category breakdown
    print(f"\n{Colors.BOLD}Commands by Category:{Colors.RESET}")
    for category, count in stats['categories'].most_common():
        pct = count / stats['commands'] * 100
        bar = '█' * int(pct / 2)
        print(f"  {category:20s} {count:4d} ({pct:5.1f}%) {Colors.BLUE}{bar}{Colors.RESET}")

    # OSCP relevance
    print(f"\n{Colors.BOLD}OSCP Relevance:{Colors.RESET}")
    for relevance in ['high', 'medium', 'low', 'MISSING']:
        count = stats['oscp_relevance'][relevance]
        if count > 0:
            pct = count / stats['commands'] * 100
            color = Colors.GREEN if relevance == 'high' else Colors.YELLOW if relevance == 'medium' else Colors.DIM
            print(f"  {relevance:10s} {count:4d} ({pct:5.1f}%) {color}{'█' * int(pct/2)}{Colors.RESET}")

    # Top tags
    print(f"\n{Colors.BOLD}Top 10 Tags:{Colors.RESET}")
    for tag, count in stats['tags'].most_common(10):
        pct = count / stats['commands'] * 100
        print(f"  {tag:25s} {count:4d} ({pct:5.1f}%)")

    # Field presence
    print(f"\n{Colors.BOLD}Field Presence:{Colors.RESET}")
    fields = [
        ('alternatives', stats['has_alternatives']),
        ('prerequisites', stats['has_prerequisites']),
        ('next_steps', stats['has_next_steps']),
        ('variables', stats['has_variables']),
        ('flag_explanations', stats['has_flag_explanations']),
    ]
    for field, count in fields:
        pct = count / stats['commands'] * 100
        print(f"  {field:20s} {count:4d} ({pct:5.1f}%)")

    # Schema compliance
    print(f"\n{Colors.BOLD}Schema Compliance:{Colors.RESET}")

    # Alternatives
    if stats['has_alternatives'] > 0:
        id_pct = stats['alternatives_ids'] / stats['has_alternatives'] * 100
        text_pct = stats['alternatives_text'] / stats['has_alternatives'] * 100
        print(f"  Alternatives:")
        print(f"    {Colors.GREEN}✓ Using IDs (correct):{Colors.RESET}  {stats['alternatives_ids']:4d} ({id_pct:5.1f}%)")
        print(f"    {Colors.RED}✗ Using text (wrong):{Colors.RESET}   {stats['alternatives_text']:4d} ({text_pct:5.1f}%)")

    # Prerequisites
    if stats['has_prerequisites'] > 0:
        id_pct = stats['prerequisites_ids'] / stats['has_prerequisites'] * 100
        text_pct = stats['prerequisites_text'] / stats['has_prerequisites'] * 100
        print(f"  Prerequisites:")
        print(f"    {Colors.GREEN}✓ Using IDs (correct):{Colors.RESET}  {stats['prerequisites_ids']:4d} ({id_pct:5.1f}%)")
        print(f"    {Colors.RED}✗ Using text (wrong):{Colors.RESET}   {stats['prerequisites_text']:4d} ({text_pct:5.1f}%)")

    # Violations summary
    total_violations = sum(len(v) if isinstance(v, list) else 1 for v in stats['violations'].values())

    if total_violations > 0:
        print(f"\n{Colors.BOLD}{Colors.RED}Schema Violations Found: {total_violations}{Colors.RESET}")

        for violation_type, items in stats['violations'].items():
            count = len(items) if isinstance(items, list) else 1
            if count > 0:
                print(f"  {Colors.RED}✗{Colors.RESET} {violation_type}: {count}")

        if verbose and stats['violations']:
            print(f"\n{Colors.BOLD}📋 VIOLATIONS CHECKLIST{Colors.RESET}")
            print(f"{Colors.BOLD}{'='*70}{Colors.RESET}")

            # Duplicate IDs checklist
            if stats['violations'].get('duplicate_ids'):
                print(f"\n{Colors.BOLD}{Colors.RED}🔴 DUPLICATE IDs ({len(stats['violations']['duplicate_ids'])}){Colors.RESET}")
                for i, item in enumerate(stats['violations']['duplicate_ids'], 1):
                    print(f"\n[ ] Fix #{i}: {Colors.BOLD}{item['id']}{Colors.RESET}")
                    print(f"    📍 Location 1: {item['file1']}")
                    print(f"    📍 Location 2: {item['file2']}")
                    print(f"    ✏️  Action: Rename or remove duplicate")

            # Alternatives using text checklist
            if stats['violations'].get('alternatives_text'):
                print(f"\n{Colors.BOLD}{Colors.YELLOW}🟡 ALTERNATIVES USING TEXT ({len(stats['violations']['alternatives_text'])}){Colors.RESET}")
                print(f"  Showing first 10 violations:")
                for i, item in enumerate(stats['violations']['alternatives_text'][:10], 1):
                    print(f"\n[ ] Fix #{i}: {Colors.BOLD}{item['id']}{Colors.RESET}")
                    print(f"    📁 File: {item['file']}")
                    print(f"    ❌ Current alternatives (text):")
                    for alt in item['alternatives']:
                        print(f"       - {alt}")
                    print(f"    ✏️  Action: Replace with command IDs or create missing commands")
                if len(stats['violations']['alternatives_text']) > 10:
                    print(f"\n    ... and {len(stats['violations']['alternatives_text']) - 10} more violations")

            # Prerequisites using text checklist
            if stats['violations'].get('prerequisites_text'):
                print(f"\n{Colors.BOLD}{Colors.YELLOW}🟡 PREREQUISITES USING TEXT ({len(stats['violations']['prerequisites_text'])}){Colors.RESET}")
                print(f"  Showing first 10 violations:")
                for i, item in enumerate(stats['violations']['prerequisites_text'][:10], 1):
                    print(f"\n[ ] Fix #{i}: {Colors.BOLD}{item['id']}{Colors.RESET}")
                    print(f"    📁 File: {item['file']}")
                    print(f"    ❌ Current prerequisites (text):")
                    for prereq in item['prerequisites']:
                        print(f"       - {prereq}")
                    print(f"    ✏️  Action: Replace with command IDs or create missing commands")
                if len(stats['violations']['prerequisites_text']) > 10:
                    print(f"\n    ... and {len(stats['violations']['prerequisites_text']) - 10} more violations")

            # Orphaned references checklist
            if stats['violations'].get('orphaned_references'):
                orphaned_list = stats['violations']['orphaned_references']
                print(f"\n{Colors.BOLD}{Colors.YELLOW}🟡 ORPHANED REFERENCES ({len(orphaned_list)}){Colors.RESET}")
                print(f"  Showing first 10 orphaned IDs:")
                for i, ref in enumerate(orphaned_list[:10], 1):
                    print(f"\n[ ] Fix #{i}: {Colors.BOLD}{ref}{Colors.RESET}")
                    print(f"    ❌ Referenced but doesn't exist")
                    print(f"    ✏️  Action: Create command or fix typo")
                if len(orphaned_list) > 10:
                    print(f"\n    ... and {len(orphaned_list) - 10} more orphaned references")
    else:
        print(f"\n{Colors.GREEN}✓ No schema violations found!{Colors.RESET}")

    # Summary
    print(f"\n{Colors.BOLD}{'=' * 70}{Colors.RESET}")
    migration_ready = total_violations == 0
    if migration_ready:
        print(f"{Colors.GREEN}✓ JSON files ready for Neo4j migration{Colors.RESET}")
    else:
        print(f"{Colors.RED}✗ JSON files need fixing before migration{Colors.RESET}")
        print(f"{Colors.YELLOW}  Run with --verbose for detailed violation list{Colors.RESET}")
    print(f"{Colors.BOLD}{'=' * 70}{Colors.RESET}\n")

if __name__ == '__main__':
    main()
