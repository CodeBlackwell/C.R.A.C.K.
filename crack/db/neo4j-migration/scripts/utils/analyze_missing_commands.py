#!/usr/bin/env python3
"""
Analyze failed mapping report and generate prioritized action plan.
Context-aware categorization of missing command references.
"""

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

def categorize_failed_mapping(text: str) -> tuple[str, str]:
    """
    Categorize a failed mapping text.
    Returns: (category, action)
    """
    text_lower = text.lower()

    # HTML/XSS payloads - REMOVE
    if text.startswith('<') and '>' in text and any(x in text_lower for x in ['onload', 'onerror', 'svg', 'script']):
        return ('payload_html', 'REMOVE')

    # Code snippets - REMOVE
    if any(x in text for x in ['()', 'import ', 'def ', 'class ']):
        if any(lang in text_lower for lang in ['python', 'ruby', 'perl', 'php']):
            return ('code_snippet', 'REMOVE')

    # URLs - MOVE TO NOTES
    if text.startswith(('http://', 'https://', 'www.')):
        return ('url', 'MOVE_TO_NOTES')

    # Manual instructions - REMOVE
    if text_lower.startswith(('manual ', 'manually ', 'check ', 'verify ', 'ensure ', 'test ', 'review ')):
        return ('instruction', 'REMOVE')

    # State conditions - REMOVE
    if any(x in text_lower for x in ['obtained', 'available', 'installed', 'running', 'imported']):
        if not text.startswith(('import ', 'Install ', 'run ')):
            return ('state_condition', 'REMOVE')

    # PowerShell module imports - CREATE HIGH PRIORITY
    if text.startswith('Import ') or 'Import-Module' in text:
        return ('powershell_import', 'CREATE_TIER1')

    # Get-* PowerShell cmdlets - CREATE HIGH PRIORITY
    if text.startswith('Get-') and any(c.isupper() for c in text[4:]):
        return ('powershell_cmdlet', 'CREATE_TIER1')

    # Tool name only (single word, lowercase) - NEEDS CONTEXT
    if len(text.split()) == 1 and text.islower() and text.isalpha():
        return ('tool_name_only', 'NEEDS_CONTEXT')

    # Command with full syntax - CREATE (priority based on frequency)
    if any(x in text for x in ['<', '>', '-', '/']):
        return ('command_full', 'CREATE_TIERED')

    # Likely command ID format - MAP OR CREATE
    if re.match(r'^[a-z]+(-[a-z]+)+$', text):
        return ('command_id_format', 'MAP_OR_CREATE')

    # Default: needs manual review
    return ('unknown', 'MANUAL_REVIEW')


def main():
    report_path = Path('db/neo4j-migration/data/mapping_report.json')

    with open(report_path) as f:
        data = json.load(f)

    failed = data['failed_mappings']

    print("="*80)
    print(f"CONTEXT-AWARE FAILED MAPPING ANALYSIS ({len(failed)} total)")
    print("="*80)

    # Categorize all failed mappings
    categorized = defaultdict(list)
    actions = defaultdict(list)

    for item in failed:
        category, action = categorize_failed_mapping(item['old_value'])
        categorized[category].append(item)
        actions[action].append(item)

    # Print category breakdown
    print("\n" + "="*80)
    print("CATEGORY BREAKDOWN")
    print("="*80)
    for cat, items in sorted(categorized.items(), key=lambda x: -len(x[1])):
        print(f"  {cat:25} {len(items):4} items")

    print("\n" + "="*80)
    print("ACTION BREAKDOWN")
    print("="*80)
    for action, items in sorted(actions.items(), key=lambda x: -len(x[1])):
        print(f"  {action:25} {len(items):4} items")

    # Count frequency of each text
    text_counts = Counter([item['old_value'] for item in failed])

    # Tier by frequency
    tier1 = []  # 10+ references
    tier2 = []  # 5-9 references
    tier3 = []  # 2-4 references
    tier4 = []  # 1 reference

    for text, count in text_counts.items():
        item = next(x for x in failed if x['old_value'] == text)
        category, action = categorize_failed_mapping(text)

        tier_item = {
            'text': text,
            'count': count,
            'category': category,
            'action': action,
            'sample_file': item['file']
        }

        if count >= 10:
            tier1.append(tier_item)
        elif count >= 5:
            tier2.append(tier_item)
        elif count >= 2:
            tier3.append(tier_item)
        else:
            tier4.append(tier_item)

    # Print tiers
    print("\n" + "="*80)
    print("TIER 1: HIGH PRIORITY (10+ references)")
    print("="*80)
    for item in sorted(tier1, key=lambda x: -x['count']):
        print(f"  {item['count']:3}x | {item['action']:15} | {item['text'][:50]}")

    print("\n" + "="*80)
    print("TIER 2: MEDIUM PRIORITY (5-9 references)")
    print("="*80)
    for item in sorted(tier2, key=lambda x: -x['count']):
        print(f"  {item['count']:3}x | {item['action']:15} | {item['text'][:50]}")

    print("\n" + "="*80)
    print("TIER 3: LOW PRIORITY (2-4 references)")
    print("="*80)
    print(f"  {len(tier3)} unique texts with 2-4 references each")
    print(f"  Sample (first 10):")
    for item in sorted(tier3, key=lambda x: -x['count'])[:10]:
        print(f"    {item['count']:3}x | {item['action']:15} | {item['text'][:45]}")

    print("\n" + "="*80)
    print("TIER 4: SINGLE REFERENCE (1 reference)")
    print("="*80)
    print(f"  {len(tier4)} unique texts with 1 reference each")

    # Action summary
    print("\n" + "="*80)
    print("RECOMMENDED ACTION PLAN")
    print("="*80)

    create_tier1 = [x for x in tier1 + tier2 if 'CREATE' in x['action']]
    remove_all = [x for x in failed if categorize_failed_mapping(x['old_value'])[1] == 'REMOVE']
    needs_context = [x for x in tier1 + tier2 if 'NEEDS_CONTEXT' in x['action']]

    print(f"\n1. CREATE TIER 1 COMMANDS: {len(create_tier1)} commands")
    print(f"   - PowerShell imports/cmdlets, high-frequency tools")
    print(f"   - Estimated time: 2-3 hours")

    print(f"\n2. REMOVE NON-COMMANDS: {len(remove_all)} items")
    print(f"   - Payloads, code snippets, instructions, state conditions")
    print(f"   - Estimated time: 30 minutes (automated)")

    print(f"\n3. RESOLVE CONTEXT-DEPENDENT: {len(needs_context)} items")
    print(f"   - Tool names without actions, needs manual review")
    print(f"   - Estimated time: 1 hour")

    print(f"\n4. CREATE TIER 2 COMMANDS: {len([x for x in tier2 if 'CREATE' in x['action']])} commands")
    print(f"   - Medium frequency (5-9 refs)")
    print(f"   - Estimated time: 1-2 hours")

    print(f"\n5. HANDLE TIER 3/4: {len(tier3) + len(tier4)} items")
    print(f"   - Low frequency, may not need creation")
    print(f"   - Suggested: Generate minimal stubs or leave as text")
    print(f"   - Estimated time: 2 hours (automated)")

    # Save detailed report
    output = {
        'summary': {
            'total_failed': len(failed),
            'tier1_count': len(tier1),
            'tier2_count': len(tier2),
            'tier3_count': len(tier3),
            'tier4_count': len(tier4),
        },
        'tiers': {
            'tier1': tier1,
            'tier2': tier2,
            'tier3_count': len(tier3),
            'tier4_count': len(tier4),
        },
        'by_action': {
            action: [{'text': x['old_value'], 'file': x['file']} for x in items]
            for action, items in actions.items()
        },
        'by_category': {
            cat: [{'text': x['old_value'], 'file': x['file']} for x in items]
            for cat, items in categorized.items()
        }
    }

    output_path = Path('db/neo4j-migration/data/missing_commands_analysis.json')
    with open(output_path, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"\n{'='*80}")
    print(f"Detailed report saved to: {output_path}")
    print(f"{'='*80}")


if __name__ == '__main__':
    main()
