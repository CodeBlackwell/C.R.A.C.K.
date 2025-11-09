#!/usr/bin/env python3
"""
Remove state conditions from alternatives and prerequisites arrays in JSON command files.
"""

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Tuple

# State condition keywords to identify and remove
STATE_CONDITION_KEYWORDS = [
    "Valid credentials",
    "Network connectivity",
    "Administrator privileges",
    "PowerShell access",
    "Domain user access",
    "Sudo access to",
    "SSH access",
    "Shell access",
    "Root privileges",
    "Administrative access",
    "Local admin",
    "Domain admin",
    "Admin privileges",
    "Admin access",
    "Domain credentials",
    "Local credentials",
    "Remote access",
    "Write access",
    "Read access",
    "Execute permission",
    "Elevated privileges",
    "User privileges",
    "Domain membership",
    "Group membership",
    "Service account",
    "System privileges",
    "SYSTEM privileges",
    "Authenticated session",
    "Active session",
    "Requires",
    "Access to",
    "Permissions to",
    "Ability to",
    "Running as",
    "Logged in as",
]

def is_state_condition(text: str) -> bool:
    """
    Check if text is a state condition (not a command ID).
    Command IDs are typically kebab-case without spaces.
    State conditions typically have spaces and describe states.
    """
    if not isinstance(text, str):
        return False

    # If it's a kebab-case ID without spaces (except in descriptions), it's likely a command ID
    if re.match(r'^[a-z0-9-]+$', text):
        return False

    # Check for state condition keywords
    text_lower = text.lower()
    for keyword in STATE_CONDITION_KEYWORDS:
        if keyword.lower() in text_lower:
            return True

    # If it contains spaces and doesn't look like a command ID, it's likely a state condition
    if ' ' in text and not text.startswith('[') and not text.endswith(']'):
        # Check if it's describing a state rather than a command
        state_patterns = [
            r'(?i)^(valid|network|administrator|powershell|domain|sudo|ssh|shell|root|administrative|local|remote|write|read|execute|elevated|user|system|authenticated|active)',
            r'(?i)(access|privileges?|permissions?|credentials?|membership|account|session)',
            r'(?i)^(requires?|access to|permissions? to|ability to|running as|logged in)',
        ]
        for pattern in state_patterns:
            if re.search(pattern, text):
                return True

    return False

def remove_state_conditions_from_array(array: List[str]) -> Tuple[List[str], int]:
    """
    Remove state conditions from an array, return cleaned array and count removed.
    """
    if not array:
        return array, 0

    original_len = len(array)
    cleaned = [item for item in array if not is_state_condition(item)]
    removed = original_len - len(cleaned)

    return cleaned, removed

def process_command(cmd: Dict) -> Tuple[Dict, int, List[str]]:
    """
    Process a single command, removing state conditions.
    Returns: (modified_command, total_removed, removed_items)
    """
    total_removed = 0
    removed_items = []

    # Process alternatives
    if 'alternatives' in cmd and isinstance(cmd['alternatives'], list):
        original = cmd['alternatives'].copy()
        cleaned, removed = remove_state_conditions_from_array(cmd['alternatives'])
        if removed > 0:
            cmd['alternatives'] = cleaned
            total_removed += removed
            # Track what was removed
            removed_items.extend([item for item in original if item not in cleaned])

    # Process prerequisites
    if 'prerequisites' in cmd and isinstance(cmd['prerequisites'], list):
        original = cmd['prerequisites'].copy()
        cleaned, removed = remove_state_conditions_from_array(cmd['prerequisites'])
        if removed > 0:
            cmd['prerequisites'] = cleaned
            total_removed += removed
            # Track what was removed
            removed_items.extend([item for item in original if item not in cleaned])

    return cmd, total_removed, removed_items

def process_file(filepath: Path) -> Dict:
    """
    Process a single JSON file, removing state conditions.
    Returns summary dict with results.
    """
    result = {
        'filepath': str(filepath),
        'modified': False,
        'commands_affected': 0,
        'total_removed': 0,
        'removed_items': [],
        'error': None
    }

    try:
        # Read original file
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Track if any changes were made
        file_modified = False

        # Process each command
        if isinstance(data, list):
            commands = data
        elif isinstance(data, dict) and 'commands' in data:
            commands = data['commands']
        else:
            result['error'] = "Unknown JSON structure"
            return result

        for cmd in commands:
            modified_cmd, removed_count, removed_items = process_command(cmd)
            if removed_count > 0:
                file_modified = True
                result['commands_affected'] += 1
                result['total_removed'] += removed_count
                result['removed_items'].extend(removed_items)

        # If modified, create backup and write updated file
        if file_modified:
            # Create backup
            backup_path = Path(str(filepath) + '.bak')
            with open(backup_path, 'w', encoding='utf-8') as f:
                json.dump(data if isinstance(data, list) else data, f, ensure_ascii=False)

            # Write updated file
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                f.write('\n')

            result['modified'] = True

    except Exception as e:
        result['error'] = str(e)

    return result

def main():
    """Main execution function."""

    # Find all JSON files
    commands_dir = Path('/home/kali/Desktop/OSCP/crack/reference/data/commands')
    json_files = list(commands_dir.rglob('*.json'))

    print(f"Found {len(json_files)} JSON files to process\n")

    # Process each file
    results = []
    total_files_modified = 0
    total_commands_affected = 0
    total_conditions_removed = 0
    all_removed_items = []

    for filepath in json_files:
        result = process_file(filepath)
        results.append(result)

        if result['modified']:
            total_files_modified += 1
            total_commands_affected += result['commands_affected']
            total_conditions_removed += result['total_removed']
            all_removed_items.extend(result['removed_items'])
            print(f"✓ {filepath.relative_to(commands_dir)}: {result['total_removed']} conditions removed from {result['commands_affected']} commands")

        if result['error']:
            print(f"✗ {filepath.relative_to(commands_dir)}: ERROR - {result['error']}")

    # Generate summary report
    print("\n" + "="*80)
    print("STATE CONDITION REMOVAL SUMMARY")
    print("="*80)
    print(f"\nFiles processed: {len(json_files)}")
    print(f"Files modified: {total_files_modified}")
    print(f"Commands affected: {total_commands_affected}")
    print(f"Total state conditions removed: {total_conditions_removed}")

    # Breakdown by keyword type
    if all_removed_items:
        print("\n" + "-"*80)
        print("REMOVED ITEMS BREAKDOWN:")
        print("-"*80)

        # Count by keyword
        keyword_counts = {}
        for item in all_removed_items:
            matched = False
            for keyword in STATE_CONDITION_KEYWORDS:
                if keyword.lower() in item.lower():
                    keyword_counts[keyword] = keyword_counts.get(keyword, 0) + 1
                    matched = True
                    break
            if not matched:
                keyword_counts['Other'] = keyword_counts.get('Other', 0) + 1

        for keyword, count in sorted(keyword_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"  {keyword}: {count}")

        print("\n" + "-"*80)
        print("SAMPLE REMOVED ITEMS (first 20):")
        print("-"*80)
        for item in all_removed_items[:20]:
            print(f"  - {item}")

    # Save detailed report
    report_path = Path('/home/kali/Desktop/OSCP/crack/state_conditions_removal_report.json')
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump({
            'summary': {
                'files_processed': len(json_files),
                'files_modified': total_files_modified,
                'commands_affected': total_commands_affected,
                'total_removed': total_conditions_removed
            },
            'results': results,
            'all_removed_items': all_removed_items
        }, f, indent=2, ensure_ascii=False)

    print(f"\nDetailed report saved to: {report_path}")
    print("\nBackup files created with .bak extension for all modified files")

if __name__ == '__main__':
    main()
