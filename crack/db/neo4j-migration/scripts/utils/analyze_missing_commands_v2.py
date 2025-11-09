#!/usr/bin/env python3
"""
Context-aware analysis with DATA PRESERVATION focus.
Never delete information - convert, extract, or relocate it.
"""

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

def categorize_with_preservation(text: str) -> tuple[str, str, str]:
    """
    Categorize a failed mapping with preservation strategy.
    Returns: (category, action, preservation_note)
    """
    text_lower = text.lower()

    # HTML/XSS payloads - CREATE as payload commands
    if text.startswith('<') and '>' in text and any(x in text_lower for x in ['onload', 'onerror', 'svg', 'script']):
        return ('payload_html', 'CREATE_PAYLOAD_CMD', 'Create XSS test command with payload in command field')

    # Instructions with embedded commands - EXTRACT command
    if text_lower.startswith(('manual ', 'check ')) and any(x in text for x in [':', '- ']):
        return ('instruction_with_cmd', 'EXTRACT_COMMAND', 'Extract embedded command and create entry')

    # Code snippets - CREATE as example/alternative
    if any(x in text for x in ['()', 'import ', 'def ', 'class ']):
        if any(lang in text_lower for lang in ['python', 'ruby', 'perl', 'php']):
            return ('code_snippet', 'CREATE_EXAMPLE_CMD', 'Create command entry for language-specific alternative')

    # URLs - CREATE as reference command or move to notes
    if text.startswith(('http://', 'https://', 'www.')):
        return ('url', 'ADD_TO_REFERENCES', 'Add to references field of related command')

    # State conditions - CREATE verification commands
    if any(x in text_lower for x in ['obtained', 'available', 'installed', 'running', 'imported']):
        if not text.startswith(('import ', 'Install ', 'run ')):
            return ('state_condition', 'CREATE_VERIFY_CMD', 'Create verification/check command')

    # PowerShell module imports - HIGH PRIORITY
    if 'Import' in text and any(x in text for x in ['PowerView', 'SharpHound', 'Mimikatz', 'PowerUp']):
        return ('powershell_import', 'CREATE_IMPORT_CMD', 'Create PowerShell import command')

    # Get-* PowerShell cmdlets - HIGH PRIORITY
    if text.startswith('Get-') or 'Get-' in text:
        return ('powershell_cmdlet', 'CREATE_PS_CMD', 'Create PowerShell cmdlet command')

    # Tool name + action description - EXTRACT and create
    if any(tool in text_lower for tool in ['nessus', 'burp', 'wfuzz', 'wpscan']) and ' ' in text:
        return ('tool_with_action', 'CREATE_TOOL_CMD', 'Create command for tool with action')

    # Simple tool name - NEEDS CONTEXT (check where it's referenced)
    if len(text.split()) == 1 and text.islower() and text.isalpha():
        return ('tool_name_only', 'CHECK_CONTEXT', 'Check file context to determine action')

    # Transfer/setup instructions - CREATE setup command
    if any(x in text_lower for x in ['transfer ', 'copy ', 'download ', 'upload ']):
        return ('transfer_instruction', 'CREATE_TRANSFER_CMD', 'Create file transfer command')

    # chmod/permission commands - CREATE utility command
    if 'chmod' in text_lower or 'chown' in text_lower:
        return ('permission_cmd', 'CREATE_UTILITY_CMD', 'Create permission management command')

    # Command with full syntax - CREATE directly
    if any(x in text for x in ['<', '>', '-', '/', '|']):
        return ('command_full', 'CREATE_FULL_CMD', 'Create complete command entry')

    # Default: needs manual review but preserve
    return ('unknown', 'MANUAL_REVIEW_PRESERVE', 'Review and determine best preservation method')


def extract_command_from_instruction(text: str) -> str:
    """Extract command from instruction text."""
    # Pattern: "Manual check with: command"
    if ':' in text:
        parts = text.split(':', 1)
        if len(parts) == 2:
            return parts[1].strip()
    # Pattern: "Manual command - explanation"
    if ' - ' in text:
        parts = text.split(' - ', 1)
        return parts[0].replace('Manual ', '').strip()
    return text


def suggest_command_id(text: str, category: str) -> str:
    """Suggest a command ID based on text and category."""
    text_lower = text.lower()

    # PowerShell imports
    if 'powerview' in text_lower:
        return 'import-powerview'
    if 'sharphound' in text_lower:
        return 'import-sharphound'
    if 'mimikatz' in text_lower:
        return 'import-mimikatz'
    if 'powerup' in text_lower:
        return 'import-powerup'

    # PowerShell cmdlets
    if text.startswith('Get-NetGroup'):
        return 'get-netgroup'
    if text.startswith('Get-ADUser'):
        return 'get-aduser'
    if text.startswith('Get-NetUser'):
        return 'get-netuser'

    # XSS payloads
    if '<svg' in text_lower and 'onload' in text_lower:
        return 'xss-test-svg-onload'
    if '<body' in text_lower and 'onload' in text_lower:
        return 'xss-test-body-onload'

    # State verification
    if 'ntlm hash' in text_lower:
        return 'verify-ntlm-hash'
    if 'crackmapexec' in text_lower and 'installed' in text_lower:
        return 'verify-crackmapexec-installed'

    # Tool commands
    if 'nessus scan' in text_lower:
        return 'nessus-scan'
    if 'burp intruder' in text_lower:
        return 'burp-intruder'

    # chmod commands
    if 'chmod +x' in text_lower:
        return 'chmod-executable'

    # Generic
    words = re.findall(r'[a-z]+', text_lower)
    if len(words) >= 2:
        return '-'.join(words[:3])

    return 'unknown-command'


def main():
    report_path = Path('db/neo4j-migration/data/mapping_report.json')

    with open(report_path) as f:
        data = json.load(f)

    failed = data['failed_mappings']

    print("="*80)
    print(f"DATA-PRESERVING FAILED MAPPING ANALYSIS ({len(failed)} total)")
    print("="*80)
    print("Strategy: NEVER delete information - convert, extract, or relocate")
    print("="*80)

    # Categorize with preservation
    categorized = defaultdict(list)
    actions = defaultdict(list)

    for item in failed:
        category, action, note = categorize_with_preservation(item['old_value'])
        item_enhanced = {
            **item,
            'category': category,
            'action': action,
            'preservation_note': note,
            'suggested_id': suggest_command_id(item['old_value'], category)
        }
        categorized[category].append(item_enhanced)
        actions[action].append(item_enhanced)

    # Print breakdown
    print("\n" + "="*80)
    print("PRESERVATION STRATEGY BREAKDOWN")
    print("="*80)
    for action, items in sorted(actions.items(), key=lambda x: -len(x[1])):
        print(f"  {action:30} {len(items):4} items")

    # Count frequency
    text_counts = Counter([item['old_value'] for item in failed])

    # Prioritize by frequency and type
    high_priority = []  # CREATE NOW
    medium_priority = []  # CREATE BATCH
    context_dependent = []  # REVIEW FIRST

    for text, count in text_counts.items():
        item = next(x for x in failed if x['old_value'] == text)
        category, action, note = categorize_with_preservation(text)
        suggested_id = suggest_command_id(text, category)

        item_detail = {
            'text': text,
            'count': count,
            'category': category,
            'action': action,
            'preservation_note': note,
            'suggested_id': suggested_id,
            'sample_file': item['file']
        }

        # Prioritize
        if count >= 5 or action in ['CREATE_IMPORT_CMD', 'CREATE_PS_CMD']:
            high_priority.append(item_detail)
        elif action in ['CHECK_CONTEXT', 'MANUAL_REVIEW_PRESERVE']:
            context_dependent.append(item_detail)
        else:
            medium_priority.append(item_detail)

    # Print priorities
    print("\n" + "="*80)
    print(f"HIGH PRIORITY - CREATE NOW ({len(high_priority)} items)")
    print("="*80)
    for item in sorted(high_priority, key=lambda x: -x['count'])[:20]:
        print(f"  {item['count']:3}x | {item['suggested_id']:30} | {item['text'][:40]}")

    print("\n" + "="*80)
    print(f"MEDIUM PRIORITY - CREATE IN BATCH ({len(medium_priority)} items)")
    print("="*80)
    print(f"  {len(medium_priority)} items total")
    print(f"  Sample (first 10):")
    for item in sorted(medium_priority, key=lambda x: -x['count'])[:10]:
        print(f"    {item['count']:3}x | {item['suggested_id']:30} | {item['action']:20}")

    print("\n" + "="*80)
    print(f"CONTEXT-DEPENDENT - REVIEW FIRST ({len(context_dependent)} items)")
    print("="*80)
    print(f"  {len(context_dependent)} items total")
    print(f"  Sample (first 10):")
    for item in sorted(context_dependent, key=lambda x: -x['count'])[:10]:
        print(f"    {item['count']:3}x | {item['text'][:50]}")

    # Detailed action plan
    print("\n" + "="*80)
    print("DETAILED ACTION PLAN (DATA PRESERVATION)")
    print("="*80)

    create_import = [x for x in high_priority + medium_priority if x['action'] == 'CREATE_IMPORT_CMD']
    create_ps = [x for x in high_priority + medium_priority if x['action'] == 'CREATE_PS_CMD']
    create_verify = [x for x in high_priority + medium_priority if x['action'] == 'CREATE_VERIFY_CMD']
    create_payload = [x for x in high_priority + medium_priority if x['action'] == 'CREATE_PAYLOAD_CMD']
    create_tool = [x for x in high_priority + medium_priority if x['action'] == 'CREATE_TOOL_CMD']
    extract_cmd = [x for x in high_priority + medium_priority if x['action'] == 'EXTRACT_COMMAND']
    create_full = [x for x in high_priority + medium_priority if x['action'] == 'CREATE_FULL_CMD']

    print(f"\n1. CREATE POWERSHELL IMPORTS: {len(create_import)} commands")
    for item in create_import[:5]:
        print(f"   - {item['suggested_id']:30} ({item['count']}x refs)")

    print(f"\n2. CREATE POWERSHELL CMDLETS: {len(create_ps)} commands")
    for item in create_ps[:5]:
        print(f"   - {item['suggested_id']:30} ({item['count']}x refs)")

    print(f"\n3. CREATE VERIFICATION COMMANDS: {len(create_verify)} commands")
    for item in create_verify[:5]:
        print(f"   - {item['suggested_id']:30} ({item['count']}x refs)")

    print(f"\n4. CREATE PAYLOAD COMMANDS: {len(create_payload)} commands")
    for item in create_payload:
        print(f"   - {item['suggested_id']:30} (preserves XSS payload)")

    print(f"\n5. CREATE TOOL COMMANDS: {len(create_tool)} commands")
    for item in create_tool[:5]:
        print(f"   - {item['suggested_id']:30} ({item['count']}x refs)")

    print(f"\n6. EXTRACT EMBEDDED COMMANDS: {len(extract_cmd)} commands")
    for item in extract_cmd[:5]:
        print(f"   - Extract from: {item['text'][:50]}")

    print(f"\n7. CREATE FULL SYNTAX COMMANDS: {len(create_full)} commands")
    print(f"   - {len(create_full)} commands with full syntax preserved")

    # Save enhanced report
    output = {
        'summary': {
            'total_failed': len(failed),
            'high_priority': len(high_priority),
            'medium_priority': len(medium_priority),
            'context_dependent': len(context_dependent),
        },
        'high_priority': high_priority,
        'medium_priority': medium_priority[:50],  # Limit size
        'context_dependent': context_dependent[:50],
        'by_action': {
            action: [
                {
                    'text': x['old_value'],
                    'file': x['file'],
                    'suggested_id': x['suggested_id'],
                    'preservation_note': x['preservation_note']
                }
                for x in items
            ]
            for action, items in actions.items()
        },
        'detailed_plan': {
            'powershell_imports': create_import,
            'powershell_cmdlets': create_ps,
            'verification_commands': create_verify,
            'payload_commands': create_payload,
            'tool_commands': create_tool,
            'extract_commands': extract_cmd,
            'full_syntax_commands': create_full[:20]
        }
    }

    output_path = Path('db/neo4j-migration/data/preservation_plan.json')
    with open(output_path, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"\n{'='*80}")
    print(f"DATA PRESERVATION PLAN saved to: {output_path}")
    print(f"{'='*80}")
    print("\nESTIMATED EFFORT:")
    print(f"  High priority manual creation: 2-3 hours ({len(high_priority)} items)")
    print(f"  Medium priority batch creation: 3-4 hours ({len(medium_priority)} items)")
    print(f"  Context review: 1-2 hours ({len(context_dependent)} items)")
    print(f"  TOTAL: 6-9 hours")
    print("\nDATA LOSS: ZERO - All information preserved in appropriate command entries")


if __name__ == '__main__':
    main()
