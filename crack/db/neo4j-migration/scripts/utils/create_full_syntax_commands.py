#!/usr/bin/env python3
"""
Transform full-syntax text entries into proper command definitions.
Phase 2C.1a: Auto-generate 60 post-exploit commands from preservation plan.
"""

import json
import re
from typing import List, Dict, Any, Optional

# Schema-compliant subcategories for post-exploit
SUBCATEGORIES = {
    'docker': 'privilege-escalation',
    'transfer': 'data-exfiltration',
    'http': 'data-exfiltration',
    'ftp': 'data-exfiltration',
    'exfil': 'data-exfiltration',
    'wget': 'data-exfiltration',
    'curl': 'data-exfiltration',
    'scp': 'data-exfiltration',
    'smb': 'data-exfiltration',
    'socat': 'data-exfiltration',
    'base64': 'data-exfiltration',
    'powerup': 'enumeration',
    'watson': 'enumeration',
    'whoami': 'enumeration',
    'sudo': 'privilege-escalation',
    'suid': 'privilege-escalation',
    'credential': 'credential-dumping',
    'password': 'credential-dumping',
    'hash': 'credential-dumping',
    'shadow': 'credential-dumping',
    'cron': 'enumeration',
    'proc': 'enumeration',
    'nfs': 'enumeration',
    'authorized_keys': 'credential-dumping',
    'private key': 'credential-dumping',
    'linpeas': 'enumeration',
    'watch': 'enumeration',
    'capability': 'privilege-escalation',
    'systemctl': 'privilege-escalation',
}

def extract_placeholders(command: str) -> List[str]:
    """Extract all <PLACEHOLDER> patterns from command."""
    return list(set(re.findall(r'<[A-Z_]+(?:[A-Z_0-9]*)>', command)))

def determine_subcategory(text: str, file_path: str) -> str:
    """Determine subcategory based on command content and source file."""
    text_lower = text.lower()
    file_lower = file_path.lower()

    # Check file path first for strong signals
    if 'privilege-escalation' in file_lower or 'privesc' in file_lower:
        return 'privilege-escalation'
    if 'exfiltration' in file_lower or 'transfer' in file_lower:
        return 'data-exfiltration'
    if 'credential' in file_lower:
        return 'credential-dumping'

    # Check text content
    for keyword, category in SUBCATEGORIES.items():
        if keyword in text_lower:
            return category

    # Default
    return 'general'

def determine_oscp_relevance(text: str, subcategory: str) -> str:
    """Determine OSCP relevance based on content."""
    text_lower = text.lower()

    # High relevance indicators
    high_indicators = [
        'docker', 'sudo', 'suid', '/etc/shadow', '/etc/passwd',
        'linpeas', 'credential', 'authorized_keys', 'private key',
        'capability', 'systemctl', 'cron'
    ]

    # Medium relevance indicators
    medium_indicators = [
        'wget', 'curl', 'python', 'http', 'transfer', 'whoami',
        'enumeration', 'nfs', 'proc'
    ]

    for indicator in high_indicators:
        if indicator in text_lower:
            return 'high'

    for indicator in medium_indicators:
        if indicator in text_lower:
            return 'medium'

    return 'low'

def generate_command_id(suggested_id: str, text: str, existing_ids: set) -> str:
    """Generate unique command ID."""
    # Clean up suggested ID
    base_id = suggested_id.lower().strip()
    base_id = re.sub(r'[^a-z0-9-]', '-', base_id)
    base_id = re.sub(r'-+', '-', base_id).strip('-')

    # Make unique if needed
    if base_id not in existing_ids:
        existing_ids.add(base_id)
        return base_id

    # Add suffix
    counter = 2
    while f"{base_id}-{counter}" in existing_ids:
        counter += 1

    unique_id = f"{base_id}-{counter}"
    existing_ids.add(unique_id)
    return unique_id

def create_variable_definition(placeholder: str, command: str, text: str) -> Dict[str, Any]:
    """Create variable definition for a placeholder."""
    # Common placeholder definitions
    definitions = {
        '<FILE>': {
            'description': 'File path or filename',
            'example': 'payload.exe',
            'required': True
        },
        '<LHOST>': {
            'description': 'Local/attacker IP address',
            'example': '10.10.14.5',
            'required': True
        },
        '<URL>': {
            'description': 'Target URL',
            'example': 'http://10.10.10.100/file.txt',
            'required': True
        },
        '<IMAGE_NAME>': {
            'description': 'Docker image name',
            'example': 'alpine',
            'required': True
        },
        '<PATH>': {
            'description': 'Directory or file path',
            'example': '/var/www/html',
            'required': True
        },
        '<PORT>': {
            'description': 'Port number',
            'example': '8000',
            'required': False
        },
        '<SERVICE>': {
            'description': 'Windows service name',
            'example': 'Spooler',
            'required': True
        },
    }

    if placeholder in definitions:
        var_def = definitions[placeholder].copy()
        var_def['name'] = placeholder
        return var_def

    # Generic definition
    name_part = placeholder.strip('<>').lower().replace('_', ' ')
    return {
        'name': placeholder,
        'description': f'{name_part.capitalize()}',
        'example': 'value',
        'required': True
    }

def generate_human_name(command_id: str, text: str) -> str:
    """Generate human-readable command name."""
    # Special cases
    if 'docker' in command_id and 'nsenter' in text:
        return 'Docker Nsenter Container Escape'
    if 'python' in command_id and 'SimpleHTTPServer' in text:
        return 'Python Simple HTTP Server'
    if 'whoami' in command_id and '/all' in text:
        return 'Windows User Enumeration (Full)'

    # General: capitalize and clean
    name = command_id.replace('-', ' ').title()
    return name

def generate_description(text: str, command: str, subcategory: str) -> str:
    """Generate clear description of what command does."""
    text_lower = text.lower()

    # Specific descriptions based on patterns
    if 'docker' in text_lower and 'nsenter' in text_lower:
        return 'Escape Docker container to host system via nsenter by accessing host PID namespace'
    if 'python' in text_lower and 'simplehttpserver' in text_lower:
        return 'Start Python 2 HTTP server for file hosting and transfers'
    if '/etc/shadow' in text_lower and 'cat' in text_lower:
        return 'Attempt to read /etc/shadow file to extract password hashes'
    if 'whoami /all' in text_lower:
        return 'Display complete user identity including groups, privileges, and SID'
    if 'sudo -l' in text_lower:
        return 'List sudo privileges for current user without password prompt'
    if 'getcap' in text_lower:
        return 'Display Linux capabilities assigned to binary for privilege escalation identification'
    if 'linpeas' in text_lower:
        return 'Download and execute LinPEAS privilege escalation enumeration script'
    if 'authorized_keys' in text_lower:
        return 'Locate SSH authorized_keys files for credential discovery and persistence'

    # Generic based on subcategory
    if subcategory == 'privilege-escalation':
        return f'Privilege escalation technique via {text.split()[0] if text.split() else "command"}'
    elif subcategory == 'data-exfiltration':
        return f'Transfer files using {text.split()[0] if text.split() else "command"}'
    elif subcategory == 'enumeration':
        return f'Enumerate system information using {text.split()[0] if text.split() else "command"}'
    elif subcategory == 'credential-dumping':
        return 'Discover or extract credentials from target system'

    return f'Execute {text.split()[0] if text.split() else "command"} for post-exploitation'

def generate_tags(text: str, subcategory: str, oscp_relevance: str) -> List[str]:
    """Generate appropriate tags for command."""
    tags = []
    text_lower = text.lower()

    # Subcategory tag
    if subcategory == 'privilege-escalation':
        tags.append('PRIVESC')
    elif subcategory == 'data-exfiltration':
        tags.append('FILE_TRANSFER')
    elif subcategory == 'enumeration':
        tags.append('ENUMERATION')
    elif subcategory == 'credential-dumping':
        tags.append('CREDENTIALS')

    # Technology tags
    if 'docker' in text_lower:
        tags.extend(['DOCKER', 'CONTAINER_ESCAPE'])
    if 'sudo' in text_lower:
        tags.append('SUDO')
    if 'suid' in text_lower:
        tags.append('SUID')
    if 'capability' in text_lower or 'getcap' in text_lower:
        tags.append('CAPABILITIES')
    if 'python' in text_lower:
        tags.append('PYTHON')
    if 'powershell' in text_lower or '.ps1' in text_lower:
        tags.append('POWERSHELL')
    if 'windows' in text_lower or 'whoami /all' in text_lower:
        tags.append('WINDOWS')
    if 'linux' in text_lower or '/etc/' in text_lower:
        tags.append('LINUX')

    # OSCP relevance tag
    if oscp_relevance == 'high':
        tags.append('OSCP:HIGH')
    elif oscp_relevance == 'medium':
        tags.append('OSCP:MEDIUM')

    # Auto-generated tracking
    tags.append('AUTO_GENERATED')

    return sorted(list(set(tags)))

def is_valid_command(text: str) -> bool:
    """Check if text contains actual command syntax (not just description)."""
    # Skip pure descriptions/references
    skip_patterns = [
        r'^\s*Use\s+',
        r'^\s*Check\s+',
        r'^\s*Search\s+',
        r'^\s*Manual\s+',
        r'^\s*Identified\s+',
        r'^\s*Test\s+',
        r'^\s*Edit\s+',
        r'\(preferred method\)\s*$',
        r'\(simpler\)\s*$',
        r'\(PowerShell-based\)\s*$',
    ]

    for pattern in skip_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            # Check if there's actual command syntax after the description
            if ':' in text:
                # e.g., "Use with -i for SSH key: scp -i key.pem..."
                parts = text.split(':', 1)
                if len(parts) > 1 and len(parts[1].strip()) > 5:
                    return True
            return False

    return True

def extract_command_from_text(text: str) -> str:
    """Extract actual command from text that might have descriptions."""
    # Handle "Description: command" format
    if ':' in text and text.count(':') == 1:
        parts = text.split(':', 1)
        # If first part looks like description, use second part
        if any(word in parts[0].lower() for word in ['use', 'wget via', 'curl via', 'run directly']):
            return parts[1].strip()

    # Handle parenthetical notes
    text = re.sub(r'\s*\([^)]*\)\s*$', '', text)

    return text.strip()

def transform_item(item: Dict[str, Any], existing_ids: set) -> Optional[Dict[str, Any]]:
    """Transform a single preservation plan item into command definition."""
    text = item['text']
    file_path = item['file']
    suggested_id = item['suggested_id']

    # Validate this is a real command
    if not is_valid_command(text):
        return None

    # Extract actual command
    command = extract_command_from_text(text)

    # Generate metadata
    command_id = generate_command_id(suggested_id, text, existing_ids)
    subcategory = determine_subcategory(text, file_path)
    oscp_relevance = determine_oscp_relevance(text, subcategory)

    # Extract placeholders and create variables
    placeholders = extract_placeholders(command)
    variables = [create_variable_definition(ph, command, text) for ph in placeholders]

    # Generate command definition
    cmd_def = {
        'id': command_id,
        'name': generate_human_name(command_id, text),
        'category': 'post-exploit',
        'subcategory': subcategory,
        'command': command,
        'description': generate_description(text, command, subcategory),
        'tags': generate_tags(text, subcategory, oscp_relevance),
        'oscp_relevance': oscp_relevance,
        'notes': f'Auto-generated from full syntax text. Source: {file_path.split("/")[-1]}'
    }

    # Add variables if present
    if variables:
        cmd_def['variables'] = variables

    return cmd_def

def main():
    """Main transformation process."""
    # Load preservation plan items
    input_file = '/tmp/post_exploit_full_cmd.json'
    output_file = '/home/kali/Desktop/OSCP/crack/reference/data/commands/post-exploit/auto-generated-full-syntax-post-exploit.json'

    print("Loading preservation plan items...")
    with open(input_file, 'r') as f:
        items = json.load(f)

    print(f"Found {len(items)} items to process")

    # Transform items
    commands = []
    existing_ids = set()
    skipped = []

    for item in items:
        cmd = transform_item(item, existing_ids)
        if cmd:
            commands.append(cmd)
        else:
            skipped.append(item['text'])

    print(f"\nGenerated {len(commands)} commands")
    print(f"Skipped {len(skipped)} non-command items")

    # Create output structure
    output = {
        'category': 'post-exploit',
        'commands': commands
    }

    # Write output
    with open(output_file, 'w') as f:
        json.dump(output, f, indent=2)

    print(f"\nOutput written to: {output_file}")

    # Generate statistics
    subcategory_counts = {}
    for cmd in commands:
        subcat = cmd['subcategory']
        subcategory_counts[subcat] = subcategory_counts.get(subcat, 0) + 1

    print("\nBreakdown by subcategory:")
    for subcat, count in sorted(subcategory_counts.items()):
        print(f"  {subcat}: {count}")

    # List skipped items
    if skipped:
        print("\nSkipped items (descriptions/references):")
        for text in skipped[:10]:  # Show first 10
            print(f"  - {text}")
        if len(skipped) > 10:
            print(f"  ... and {len(skipped) - 10} more")

    return len(commands), subcategory_counts, skipped

if __name__ == '__main__':
    total, breakdown, skipped = main()
    print(f"\n✓ Successfully created {total} command definitions")
