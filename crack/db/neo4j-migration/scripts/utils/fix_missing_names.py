#!/usr/bin/env python3
"""
Round 1: Auto-fix missing name fields in command definitions.
Generates name from command ID using intelligent title casing.
"""

import json
import re
from pathlib import Path
from typing import Dict, List

def id_to_name(command_id: str) -> str:
    """
    Convert kebab-case ID to proper command name.

    Examples:
        arp-scan-list → Arp Scan List
        get-aduser → Get ADUser
        bloodhound → Bloodhound
        nmap-tcp-syn → Nmap TCP SYN
        smb-server → SMB Server
    """
    # Known acronyms to keep uppercase
    acronyms = {
        'smb', 'ftp', 'ssh', 'rdp', 'tcp', 'udp', 'ip', 'dns', 'http', 'https',
        'sql', 'xss', 'csrf', 'rce', 'lfi', 'rfi', 'xxe', 'ssrf', 'ldap',
        'ad', 'dc', 'acl', 'gpp', 'ntlm', 'kerberos', 'wmi', 'dcom', 'psexec',
        'winrm', 'suid', 'guid', 'sid', 'url', 'uri', 'api', 'jwt', 'xml',
        'json', 'csv', 'pdf', 'dll', 'exe', 'ps1', 'sh', 'bat', 'cmd', 'vbs',
        'ida', 'gdb', 'lldb', 'pdb', 'asp', 'jsp', 'php', 'cgi', 'ssti',
        'idor', 'owasp', 'cve', 'cwe', 'oscp', 'oswe', 'osed', 'oswp'
    }

    # PowerShell cmdlet prefixes
    ps_prefixes = {
        'get', 'set', 'new', 'remove', 'add', 'invoke', 'test', 'start',
        'stop', 'enable', 'disable', 'import', 'export', 'convert', 'select',
        'where', 'foreach', 'measure', 'compare', 'group', 'sort', 'out'
    }

    # Split on hyphens
    parts = command_id.split('-')
    result = []

    for i, part in enumerate(parts):
        part_lower = part.lower()

        # Keep acronyms uppercase
        if part_lower in acronyms:
            result.append(part_lower.upper())
        # PowerShell cmdlet prefix (first word only)
        elif i == 0 and part_lower in ps_prefixes:
            result.append(part.capitalize())
        # Special case: compound words like 'sharphound', 'bloodhound'
        elif 'hound' in part_lower:
            # SharpHound, BloodHound
            idx = part_lower.index('hound')
            if idx > 0:
                result.append(part[:idx].capitalize() + 'Hound')
            else:
                result.append('Hound')
        # Regular word
        else:
            result.append(part.capitalize())

    return ' '.join(result)


def fix_missing_names_in_file(file_path: Path) -> Dict[str, int]:
    """
    Fix missing name fields in a single JSON file.
    Returns: {'fixed': count, 'already_had': count}
    """
    with open(file_path, 'r') as f:
        data = json.load(f)

    stats = {'fixed': 0, 'already_had': 0}
    modified = False

    if 'commands' in data and isinstance(data['commands'], list):
        for cmd in data['commands']:
            if 'id' in cmd:
                if 'name' not in cmd or not cmd['name']:
                    # Generate name from ID
                    cmd['name'] = id_to_name(cmd['id'])
                    stats['fixed'] += 1
                    modified = True
                else:
                    stats['already_had'] += 1

    # Save if modified
    if modified:
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)

    return stats


def main():
    base_path = Path('db/data/commands')

    print("=" * 80)
    print("ROUND 1: AUTO-FIX MISSING NAME FIELDS")
    print("=" * 80)
    print(f"Scanning: {base_path}")
    print()

    # Find all JSON files
    json_files = sorted(base_path.rglob('*.json'))

    total_fixed = 0
    total_already_had = 0
    files_modified = []

    for json_file in json_files:
        try:
            stats = fix_missing_names_in_file(json_file)

            if stats['fixed'] > 0:
                rel_path = json_file.relative_to(base_path)
                files_modified.append((str(rel_path), stats['fixed']))
                print(f"✓ {rel_path}: {stats['fixed']} names generated")

            total_fixed += stats['fixed']
            total_already_had += stats['already_had']

        except Exception as e:
            print(f"✗ {json_file.name}: ERROR - {e}")

    print()
    print("=" * 80)
    print("ROUND 1 RESULTS")
    print("=" * 80)
    print(f"Files scanned: {len(json_files)}")
    print(f"Files modified: {len(files_modified)}")
    print(f"Names generated: {total_fixed}")
    print(f"Already had names: {total_already_had}")
    print(f"Total commands: {total_fixed + total_already_had}")
    print()

    if files_modified:
        print("FILES MODIFIED:")
        for file_path, count in sorted(files_modified, key=lambda x: -x[1])[:20]:
            print(f"  {count:3} - {file_path}")

    print()
    print("=" * 80)
    print("NEXT STEP: Run validation to confirm fix")
    print("  python3 db/neo4j-migration/scripts/utils/validate_schema_compliance.py")
    print("=" * 80)


if __name__ == '__main__':
    main()
