#!/usr/bin/env python3
"""
Round 5: Auto-fix missing variable definitions.
"""

import json
import re
from pathlib import Path
from collections import defaultdict

# Standard variable definitions
STANDARD_VARS = {
    'TARGET': {'description': 'Target IP address or hostname', 'example': '192.168.45.100', 'required': True},
    'LHOST': {'description': 'Attacker IP address', 'example': '10.10.14.5', 'required': True},
    'LPORT': {'description': 'Listening port number', 'example': '4444', 'required': True},
    'PORT': {'description': 'Target port number', 'example': '80', 'required': True},
    'URL': {'description': 'Target URL', 'example': 'http://192.168.45.100', 'required': True},
    'USERNAME': {'description': 'Username for authentication', 'example': 'administrator', 'required': True},
    'USER': {'description': 'Username', 'example': 'admin', 'required': True},
    'PASSWORD': {'description': 'Password for authentication', 'example': 'Password123!', 'required': True},
    'PASS': {'description': 'Password', 'example': 'password', 'required': True},
    'WORDLIST': {'description': 'Path to wordlist file', 'example': '/usr/share/wordlists/rockyou.txt', 'required': True},
    'FILE': {'description': 'File name or path', 'example': 'file.txt', 'required': True},
    'DOMAIN': {'description': 'Domain name', 'example': 'example.com', 'required': True},
    'DC': {'description': 'Domain Controller IP or hostname', 'example': '192.168.45.100', 'required': True},
    'HASH': {'description': 'Hash value', 'example': 'abc123...', 'required': True},
    'HASH_FILE': {'description': 'Path to file containing hashes', 'example': 'hashes.txt', 'required': True},
    'OUTPUT_FILE': {'description': 'Output file path', 'example': 'output.txt', 'required': True},
    'COMMAND': {'description': 'Command to execute', 'example': 'whoami', 'required': True},
    'SERVICE': {'description': 'Service name', 'example': 'apache2', 'required': True},
    'SHARE': {'description': 'SMB share name', 'example': 'C$', 'required': True},
    'SNMP_COMMUNITY': {'description': 'SNMP community string', 'example': 'public', 'required': True},
    'TARGET_SUBNET': {'description': 'Target subnet in CIDR notation', 'example': '192.168.45.0/24', 'required': True},
    'NS': {'description': 'DNS nameserver', 'example': '192.168.45.100', 'required': True},
    'RULE': {'description': 'John the Ripper rule name', 'example': 'best64', 'required': False},
    'PARAM': {'description': 'Parameter name', 'example': 'username', 'required': True},
    'VALUE': {'description': 'Parameter value', 'example': 'admin', 'required': True},
    'PORTS': {'description': 'Port or port range', 'example': '1-65535', 'required': True},
    'PAGE': {'description': 'Web page path', 'example': 'index.php', 'required': True},
    'FAIL_STRING': {'description': 'String indicating failed request', 'example': 'Invalid credentials', 'required': True},
    'DEST_IP': {'description': 'Destination IP address', 'example': '10.10.14.5', 'required': True},
    'DEST_PORT': {'description': 'Destination port', 'example': '80', 'required': True},
    'USER_DN': {'description': 'User Distinguished Name', 'example': 'CN=User,DC=corp,DC=com', 'required': True},
    'GROUPNAME': {'description': 'Group name', 'example': 'Domain Admins', 'required': True},
    'TASK_NAME': {'description': 'Scheduled task name', 'example': 'UpdateTask', 'required': True},
    'IP': {'description': 'IP address', 'example': '192.168.45.100', 'required': True},
    'OBJECT': {'description': 'Active Directory object name', 'example': 'Domain Admins', 'required': True},
    'SID': {'description': 'Security Identifier', 'example': 'S-1-5-21-...', 'required': True},
    'NTLM': {'description': 'NTLM hash', 'example': 'abc123...', 'required': True},
    'ADDRESS': {'description': 'Memory address', 'example': '0x12345678', 'required': True},
    'NEW_VALUE': {'description': 'New value', 'example': '0xDEADBEEF', 'required': True},
    'BYTE2': {'description': 'Second byte value', 'example': '0x12', 'required': True},
    'BYTE3': {'description': 'Third byte value', 'example': '0x34', 'required': True},
}

def fix_missing_variables(base_path: Path) -> dict:
    stats = {
        'files_scanned': 0,
        'files_modified': 0,
        'variables_added': 0,
        'commands_fixed': 0
    }

    for json_file in base_path.rglob('*.json'):
        try:
            with open(json_file) as f:
                data = json.load(f)

            modified = False
            stats['files_scanned'] += 1

            for cmd in data.get('commands', []):
                # Find placeholders in command
                command_text = cmd.get('command', '')
                placeholders = set(re.findall(r'<([A-Z_][A-Z0-9_]*)>', command_text))

                if not placeholders:
                    continue

                # Convert dict format to array format (for stub files)
                if 'variables' in cmd and isinstance(cmd['variables'], dict):
                    # Convert dict to array
                    old_vars = cmd['variables']
                    cmd['variables'] = []
                    for var_name_with_brackets, var_def in old_vars.items():
                        var_name = var_name_with_brackets.strip('<>')
                        cmd['variables'].append({
                            'name': var_name_with_brackets,
                            'description': var_def.get('description', f'{var_name.replace("_", " ").title()}'),
                            'example': var_def.get('example', ''),
                            'required': var_def.get('required', True)
                        })
                    modified = True

                # Find defined variables
                defined_vars = set()
                if 'variables' not in cmd:
                    cmd['variables'] = []

                for var in cmd['variables']:
                    if isinstance(var, dict) and 'name' in var:
                        var_name = var['name'].strip('<>')
                        defined_vars.add(var_name)

                # Missing variables
                missing = placeholders - defined_vars

                if missing:
                    for var_name in sorted(missing):
                        # Add standard definition if available
                        if var_name in STANDARD_VARS:
                            var_def = {
                                'name': f'<{var_name}>',
                                **STANDARD_VARS[var_name]
                            }
                        else:
                            # Create generic definition
                            var_def = {
                                'name': f'<{var_name}>',
                                'description': f'{var_name.replace("_", " ").title()}',
                                'example': '',
                                'required': True
                            }

                        cmd['variables'].append(var_def)
                        stats['variables_added'] += 1
                        modified = True

                    stats['commands_fixed'] += 1

            # Save if modified
            if modified:
                with open(json_file, 'w') as f:
                    json.dump(data, f, indent=2)
                stats['files_modified'] += 1

        except Exception as e:
            print(f"✗ Error processing {json_file.name}: {e}")

    return stats


def main():
    base_path = Path('reference/data/commands')

    print("=" * 80)
    print("ROUND 5: FIX MISSING VARIABLE DEFINITIONS")
    print("=" * 80)
    print(f"Using {len(STANDARD_VARS)} standard variable definitions")
    print()

    stats = fix_missing_variables(base_path)

    print("\n" + "=" * 80)
    print("ROUND 5 RESULTS")
    print("=" * 80)
    print(f"Files scanned: {stats['files_scanned']}")
    print(f"Files modified: {stats['files_modified']}")
    print(f"Commands fixed: {stats['commands_fixed']}")
    print(f"Variables added: {stats['variables_added']}")

    print("\n" + "=" * 80)
    print("NEXT STEP: Run validation to confirm")
    print("  python3 db/neo4j-migration/scripts/utils/validate_schema_compliance.py")
    print("=" * 80)


if __name__ == '__main__':
    main()
