#!/usr/bin/env python3
"""
Bulk Command Stub Generator

Generates minimal command stubs for all failed mappings in the mapping report.
Creates command definitions for alternatives/prerequisites that don't exist yet.

Usage:
    python3 bulk_create_stubs.py
"""

import json
import re
from pathlib import Path
from collections import defaultdict
from datetime import date

# Base directory - scripts/utils -> scripts -> neo4j-migration -> crack (root)
BASE_DIR = Path(__file__).parent.parent.parent.parent.parent
MAPPING_REPORT = BASE_DIR / "db/neo4j-migration/data/mapping_report.json"
OUTPUT_DIR = BASE_DIR / "reference/data/commands"


def normalize_command_id(text: str, suggestion: str = None) -> str:
    """
    Generate a command ID from text or suggestion.

    Args:
        text: The original command text
        suggestion: The suggested command ID from mapping

    Returns:
        Normalized command ID
    """
    if suggestion:
        # Clean up suggestion
        suggestion = suggestion.lower().strip()
        # Remove common suffixes that are duplicates
        suggestion = re.sub(r'-check-check$', '-check', suggestion)
        suggestion = re.sub(r'-list-list$', '-list', suggestion)
        suggestion = re.sub(r'-scan-scan$', '-scan', suggestion)
        return suggestion

    # Extract tool name from text
    # e.g., "fping -a -g <TARGET_SUBNET>" -> "fping"
    text = text.strip()
    parts = text.split()
    if not parts:
        return "unknown-command"

    tool = parts[0].lower()

    # Try to extract action from flags
    action = "default"
    if len(parts) > 1:
        # Look for common action indicators
        for part in parts[1:]:
            if part.startswith('-') and len(part) > 2:
                action = part[1:].replace('-', '')
                break

    return f"{tool}-{action}"


def infer_category(tool: str, command_text: str) -> str:
    """
    Infer category from tool name and command text.

    Args:
        tool: Tool name (e.g., "nmap", "metasploit")
        command_text: Full command text

    Returns:
        Category string
    """
    tool = tool.lower()
    text = command_text.lower()

    # Category mapping
    categories = {
        # Enumeration tools
        'nmap': 'enumeration',
        'gobuster': 'enumeration',
        'ffuf': 'enumeration',
        'wfuzz': 'enumeration',
        'dirb': 'enumeration',
        'dirbuster': 'enumeration',
        'nikto': 'enumeration',
        'dnsenum': 'enumeration',
        'dnsrecon': 'enumeration',
        'fierce': 'enumeration',
        'host': 'enumeration',
        'dig': 'enumeration',
        'enum4linux': 'enumeration',
        'smbclient': 'enumeration',
        'smbmap': 'enumeration',
        'rpcclient': 'enumeration',
        'snmpwalk': 'enumeration',
        'snmp-check': 'enumeration',
        'snmpbulkwalk': 'enumeration',
        'onesixtyone': 'enumeration',
        'ldapsearch': 'enumeration',
        'bloodhound': 'enumeration',
        'powerview': 'enumeration',
        'sharphound': 'enumeration',
        'fping': 'enumeration',
        'arp-scan': 'enumeration',
        'unicornscan': 'enumeration',
        'masscan': 'enumeration',
        'netcat': 'enumeration',
        'nc': 'enumeration',
        'curl': 'enumeration',
        'wget': 'enumeration',

        # Research tools
        'searchsploit': 'research',
        'exploit-db': 'research',
        'nessus': 'research',
        'openvas': 'research',

        # Exploitation tools
        'metasploit': 'exploitation',
        'msfconsole': 'exploitation',
        'msfvenom': 'exploitation',
        'sqlmap': 'exploitation',
        'hydra': 'exploitation',
        'medusa': 'exploitation',
        'john': 'exploitation',
        'hashcat': 'exploitation',
        'impacket': 'exploitation',
        'psexec': 'exploitation',
        'wmiexec': 'exploitation',
        'smbexec': 'exploitation',
        'crackmapexec': 'exploitation',
        'cme': 'exploitation',
        'evil-winrm': 'exploitation',
        'responder': 'exploitation',
        'ntlmrelayx': 'exploitation',
        'burpsuite': 'exploitation',
        'burp': 'exploitation',
        'zap': 'exploitation',
        'commix': 'exploitation',

        # Post-exploitation
        'mimikatz': 'post-exploitation',
        'linpeas': 'post-exploitation',
        'linuxprivchecker': 'post-exploitation',
        'winpeas': 'post-exploitation',
        'powerup': 'post-exploitation',
        'wesng': 'post-exploitation',
        'windows-exploit-suggester': 'post-exploitation',
        'linux-exploit-suggester': 'post-exploitation',
        'pspy': 'post-exploitation',
        'lazagne': 'post-exploitation',
        'secretsdump': 'post-exploitation',

        # Pivoting
        'ssh': 'pivoting',
        'proxychains': 'pivoting',
        'chisel': 'pivoting',
        'socat': 'pivoting',
        'sshuttle': 'pivoting',
        'plink': 'pivoting',
        'netsh': 'pivoting',

        # File transfer
        'scp': 'file-transfer',
        'ftp': 'file-transfer',
        'tftp': 'file-transfer',
        'certutil': 'file-transfer',
        'powershell': 'file-transfer',

        # Utilities
        'python': 'utilities',
        'perl': 'utilities',
        'ruby': 'utilities',
        'bash': 'utilities',
        'cmd': 'utilities',
        'powershell': 'utilities',
    }

    # Check tool name
    if tool in categories:
        return categories[tool]

    # Check for keywords in command text
    if any(word in text for word in ['enum', 'scan', 'discover', 'recon']):
        return 'enumeration'
    if any(word in text for word in ['exploit', 'attack', 'shell', 'reverse']):
        return 'exploitation'
    if any(word in text for word in ['privesc', 'privilege', 'escalate']):
        return 'post-exploitation'
    if any(word in text for word in ['pivot', 'tunnel', 'forward']):
        return 'pivoting'
    if any(word in text for word in ['transfer', 'upload', 'download']):
        return 'file-transfer'

    return 'utilities'


def extract_placeholders(command_text: str) -> list:
    """
    Extract placeholders from command text.

    Args:
        command_text: Full command text with placeholders

    Returns:
        List of placeholder names
    """
    # Find all <PLACEHOLDER> patterns
    placeholders = re.findall(r'<([A-Z_]+)>', command_text)
    return list(set(placeholders))


def generate_variable_definition(placeholder: str) -> dict:
    """
    Generate variable definition for a placeholder.

    Args:
        placeholder: Placeholder name (e.g., "TARGET", "PORT")

    Returns:
        Variable definition dict
    """
    common_vars = {
        'TARGET': {
            'type': 'target',
            'description': 'Target IP address or hostname',
            'required': True
        },
        'PORT': {
            'type': 'port',
            'description': 'Target port number',
            'required': True
        },
        'PORTS': {
            'type': 'port_range',
            'description': 'Port range (e.g., 1-1000, 80,443)',
            'required': True
        },
        'DOMAIN': {
            'type': 'domain',
            'description': 'Target domain name',
            'required': True
        },
        'USERNAME': {
            'type': 'username',
            'description': 'Username for authentication',
            'required': True
        },
        'PASSWORD': {
            'type': 'password',
            'description': 'Password for authentication',
            'required': True
        },
        'WORDLIST': {
            'type': 'file',
            'description': 'Path to wordlist file',
            'required': True
        },
        'FILE': {
            'type': 'file',
            'description': 'File path',
            'required': True
        },
        'OUTPUT': {
            'type': 'file',
            'description': 'Output file path',
            'required': False
        },
        'NS': {
            'type': 'nameserver',
            'description': 'DNS nameserver',
            'required': True
        },
        'SNMP_COMMUNITY': {
            'type': 'string',
            'description': 'SNMP community string',
            'required': True
        },
        'TARGET_SUBNET': {
            'type': 'network',
            'description': 'Target subnet (e.g., 192.168.1.0/24)',
            'required': True
        },
        'HASH': {
            'type': 'hash',
            'description': 'Hash value to crack',
            'required': True
        },
        'LHOST': {
            'type': 'ip',
            'description': 'Local/attacker IP address',
            'required': True
        },
        'LPORT': {
            'type': 'port',
            'description': 'Local/attacker port number',
            'required': True
        },
        'URL': {
            'type': 'url',
            'description': 'Target URL',
            'required': True
        },
    }

    if placeholder in common_vars:
        return common_vars[placeholder]

    # Generic fallback
    return {
        'type': 'string',
        'description': f'{placeholder} value',
        'required': True
    }


def generate_stub(old_value: str, suggestion: str, source_command: dict) -> dict:
    """
    Generate a minimal command stub.

    Args:
        old_value: Original command text
        suggestion: Suggested command ID
        source_command: Original command that referenced this

    Returns:
        Command stub dictionary
    """
    # Generate command ID
    command_id = normalize_command_id(old_value, suggestion)

    # Extract tool name
    tool = old_value.split()[0] if old_value.split() else "unknown"

    # Infer category
    category = infer_category(tool, old_value)

    # Extract placeholders
    placeholders = extract_placeholders(old_value)

    # Generate variables
    variables = {}
    for placeholder in placeholders:
        variables[f'<{placeholder}>'] = generate_variable_definition(placeholder)

    # If no placeholders found, add default TARGET
    if not variables:
        variables['<TARGET>'] = generate_variable_definition('TARGET')
        # Replace first argument that looks like a target with <TARGET>
        parts = old_value.split()
        if len(parts) > 1:
            for i, part in enumerate(parts[1:], 1):
                if not part.startswith('-') and not part.startswith('<'):
                    parts[i] = '<TARGET>'
                    break
            old_value = ' '.join(parts)

    stub = {
        "id": command_id,
        "command": old_value,
        "category": category,
        "tags": [category, tool.lower(), "auto-generated"],
        "description": f"Auto-generated stub for {tool}",
        "variables": variables,
        "output_analysis": [
            f"Review {tool} output for relevant information"
        ],
        "common_uses": [
            f"Alternative to {source_command.get('command_id', 'other commands')}"
        ],
        "alternatives": [],
        "prerequisites": [],
        "next_steps": [],
        "notes": f"AUTO-GENERATED STUB - Needs manual enrichment. Referenced in {source_command.get('file', 'unknown file')}"
    }

    return stub


def main():
    """Main execution function."""
    print("=" * 80)
    print("BULK COMMAND STUB GENERATOR")
    print("=" * 80)

    # Read mapping report
    print(f"\nReading mapping report: {MAPPING_REPORT}")
    with open(MAPPING_REPORT) as f:
        mapping_data = json.load(f)

    failed_mappings = mapping_data.get('failed_mappings', [])
    print(f"Total failed mappings: {len(failed_mappings)}")

    # Group by unique command
    unique_stubs = {}
    category_counts = defaultdict(int)

    for mapping in failed_mappings:
        old_value = mapping.get('old_value', '')
        suggestion = mapping.get('suggestion', '')

        if not old_value:
            continue

        # Generate command ID
        command_id = normalize_command_id(old_value, suggestion)

        # Skip if already processed
        if command_id in unique_stubs:
            continue

        # Generate stub
        stub = generate_stub(old_value, suggestion, mapping)
        unique_stubs[command_id] = stub
        category_counts[stub['category']] += 1

    print(f"\nGenerated {len(unique_stubs)} unique command stubs")
    print("\nDistribution by category:")
    for category, count in sorted(category_counts.items()):
        print(f"  {category:20s}: {count:4d} commands")

    # Group stubs by category
    stubs_by_category = defaultdict(list)
    for stub in unique_stubs.values():
        stubs_by_category[stub['category']].append(stub)

    # Write to files
    print("\nWriting stub files...")
    output_files = []

    for category, stubs in stubs_by_category.items():
        # Sort stubs by ID
        stubs.sort(key=lambda x: x['id'])

        # Create category directory
        category_dir = OUTPUT_DIR / category
        category_dir.mkdir(parents=True, exist_ok=True)

        # Create output file
        output_file = category_dir / f"auto-generated-{category}-stubs.json"

        # Create file structure with metadata
        file_data = {
            "metadata": {
                "generated": str(date.today()),
                "source": "bulk_create_stubs.py",
                "purpose": "Auto-generated command stubs for missing references",
                "status": "needs-manual-enrichment",
                "count": len(stubs),
                "category": category
            },
            "commands": stubs
        }

        # Write file
        with open(output_file, 'w') as f:
            json.dump(file_data, f, indent=2)

        output_files.append(output_file)
        print(f"  {output_file.relative_to(BASE_DIR)}: {len(stubs)} commands")

    print(f"\n{len(output_files)} files created")

    # Show sample stubs
    print("\n" + "=" * 80)
    print("SAMPLE GENERATED STUBS (showing variety)")
    print("=" * 80)

    samples_shown = 0
    for category in sorted(stubs_by_category.keys()):
        if samples_shown >= 10:
            break

        stubs = stubs_by_category[category]
        if stubs:
            sample = stubs[0]
            print(f"\n[{category.upper()}] {sample['id']}")
            print(f"Command: {sample['command']}")
            print(f"Variables: {list(sample['variables'].keys())}")
            print(f"Tags: {', '.join(sample['tags'])}")
            samples_shown += 1

    print("\n" + "=" * 80)
    print("VALIDATION")
    print("=" * 80)

    # Validation
    total_generated = sum(len(stubs) for stubs in stubs_by_category.values())
    print(f"\nTotal commands generated: {total_generated}")
    print(f"Expected (unique stubs): {len(unique_stubs)}")
    print(f"Match: {'✓' if total_generated == len(unique_stubs) else '✗'}")

    # Check JSON validity
    print("\nJSON validity check:")
    all_valid = True
    for output_file in output_files:
        try:
            with open(output_file) as f:
                json.load(f)
            print(f"  ✓ {output_file.name}")
        except json.JSONDecodeError as e:
            print(f"  ✗ {output_file.name}: {e}")
            all_valid = False

    if all_valid:
        print("\n✓ All files are valid JSON")
    else:
        print("\n✗ Some files have JSON errors")

    print("\n" + "=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Generated {len(unique_stubs)} command stubs")
    print(f"Created {len(output_files)} files")
    print(f"Categories: {', '.join(sorted(category_counts.keys()))}")
    print("\nNext steps:")
    print("1. Review generated stubs for accuracy")
    print("2. Enrich stubs with proper descriptions and examples")
    print("3. Run 02_build_command_index.py to update index")
    print("4. Run 03_map_text_to_ids.py to validate mappings")
    print("=" * 80)


if __name__ == '__main__':
    main()
