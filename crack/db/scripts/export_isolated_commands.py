#!/usr/bin/env python3
"""
Export isolated commands (0 relationships) for enrichment planning

Generates prioritized CSV of commands needing relationship enrichment based on:
- OSCP priority (HIGH/MEDIUM/LOW)
- Usage in writeups (validated by real-world application)
- Tool family membership
- Category (tunneling, heuristic-evasion prioritized)
"""

import json
import csv
import sys
from pathlib import Path
from typing import Dict, List, Set

def load_all_commands(commands_dir: Path) -> Dict[str, dict]:
    """Load all commands from JSON files"""
    commands = {}

    for json_file in commands_dir.rglob('*.json'):
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)

                # Handle different JSON structures
                command_list = []
                if 'commands' in data:
                    command_list = data['commands']
                elif isinstance(data, list):
                    command_list = data
                elif 'id' in data:  # Single command object
                    command_list = [data]

                for cmd in command_list:
                    if 'id' in cmd:
                        cmd['_source_file'] = str(json_file.relative_to(commands_dir.parent))
                        commands[cmd['id']] = cmd
        except Exception as e:
            print(f"Error loading {json_file}: {e}", file=sys.stderr)

    return commands

def load_writeup_commands(writeups_dir: Path) -> Set[str]:
    """Load set of command IDs used in writeups"""
    writeup_commands = set()

    if not writeups_dir.exists():
        print(f"Warning: Writeups directory not found: {writeups_dir}", file=sys.stderr)
        return writeup_commands

    for json_file in writeups_dir.rglob('*.json'):
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)

                # Extract command IDs from attack_phases
                if 'attack_phases' in data:
                    for phase in data['attack_phases']:
                        if 'commands_used' in phase:
                            for cmd_usage in phase['commands_used']:
                                if 'command_id' in cmd_usage:
                                    writeup_commands.add(cmd_usage['command_id'])
        except Exception as e:
            print(f"Error loading writeup {json_file}: {e}", file=sys.stderr)

    return writeup_commands

def count_relationships(cmd: dict) -> int:
    """Count total relationships for a command"""
    count = 0

    # Count prerequisites
    if 'prerequisites' in cmd and cmd['prerequisites']:
        count += len(cmd['prerequisites']) if isinstance(cmd['prerequisites'], list) else 1

    # Count alternatives
    if 'alternatives' in cmd and cmd['alternatives']:
        count += len(cmd['alternatives']) if isinstance(cmd['alternatives'], list) else 1

    # Count next_steps
    if 'next_steps' in cmd and cmd['next_steps']:
        count += len(cmd['next_steps']) if isinstance(cmd['next_steps'], list) else 1

    return count

def extract_oscp_priority(tags: List[str]) -> str:
    """Extract OSCP priority from tags"""
    if not tags:
        return 'UNKNOWN'

    for tag in tags:
        if tag.startswith('OSCP:'):
            return tag.split(':')[1]

    return 'UNKNOWN'

def extract_tool_family(cmd_id: str) -> str:
    """Extract tool family from command ID"""
    # Common tool prefixes
    tool_families = [
        'nmap', 'hydra', 'john', 'hashcat', 'sqlmap', 'nikto', 'gobuster',
        'enum4linux', 'smbmap', 'smbclient', 'crackmapexec', 'bloodhound',
        'mimikatz', 'rubeus', 'kerbrute', 'impacket', 'linpeas', 'winpeas',
        'chisel', 'ssh', 'netcat', 'nc', 'curl', 'wget', 'powershell', 'ps'
    ]

    cmd_lower = cmd_id.lower()
    for tool in tool_families:
        if cmd_lower.startswith(tool):
            return tool

    return 'other'

def assign_tier(cmd: dict, writeup_commands: Set[str]) -> int:
    """Assign priority tier (1=highest, 5=lowest)"""
    oscp_priority = extract_oscp_priority(cmd.get('tags', []))
    in_writeup = cmd['id'] in writeup_commands
    category = cmd.get('category', '')
    tool_family = extract_tool_family(cmd['id'])

    # Tier 1: OSCP:HIGH + used in writeups
    if oscp_priority == 'HIGH' and in_writeup:
        return 1

    # Tier 2: OSCP:HIGH not in writeups
    if oscp_priority == 'HIGH':
        return 2

    # Tier 3: Tool family completions (major tools)
    if tool_family in ['hydra', 'hashcat', 'john', 'nmap', 'sqlmap']:
        return 3

    # Tier 4: Critical categories (100% isolated)
    if category in ['tunneling', 'heuristic-evasion', 'pivoting']:
        return 4

    # Tier 5: Remaining
    return 5

def main():
    # Paths
    base_dir = Path(__file__).parent.parent
    commands_dir = base_dir / 'data' / 'commands'
    writeups_dir = base_dir / 'data' / 'writeups'
    output_file = base_dir / 'isolated_commands_prioritized.csv'

    print("Loading commands...")
    commands = load_all_commands(commands_dir)
    print(f"Loaded {len(commands)} commands")

    print("Loading writeup command usage...")
    writeup_commands = load_writeup_commands(writeups_dir)
    print(f"Found {len(writeup_commands)} commands used in writeups")

    print("Identifying isolated commands...")
    isolated = []

    for cmd_id, cmd in commands.items():
        rel_count = count_relationships(cmd)

        if rel_count == 0:
            oscp_priority = extract_oscp_priority(cmd.get('tags', []))
            tier = assign_tier(cmd, writeup_commands)
            tool_family = extract_tool_family(cmd_id)

            isolated.append({
                'command_id': cmd_id,
                'name': cmd.get('name', 'N/A'),
                'category': cmd.get('category', 'N/A'),
                'subcategory': cmd.get('subcategory', 'N/A'),
                'oscp_priority': oscp_priority,
                'used_in_writeups': cmd_id in writeup_commands,
                'tool_family': tool_family,
                'priority_tier': tier,
                'source_file': cmd.get('_source_file', 'N/A')
            })

    print(f"Found {len(isolated)} isolated commands (0 relationships)")

    # Sort by tier, then OSCP priority, then command ID
    isolated.sort(key=lambda x: (x['priority_tier'],
                                  {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, 'UNKNOWN': 3}.get(x['oscp_priority'], 3),
                                  x['command_id']))

    # Write CSV
    print(f"Writing to {output_file}...")
    with open(output_file, 'w', newline='') as f:
        fieldnames = ['command_id', 'name', 'category', 'subcategory', 'oscp_priority',
                     'used_in_writeups', 'tool_family', 'priority_tier', 'source_file']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(isolated)

    # Print summary statistics
    print("\n" + "="*80)
    print("ISOLATED COMMANDS SUMMARY")
    print("="*80)
    print(f"Total isolated: {len(isolated)}")
    print()

    # By tier
    print("By Priority Tier:")
    tier_counts = {}
    for cmd in isolated:
        tier = cmd['priority_tier']
        tier_counts[tier] = tier_counts.get(tier, 0) + 1

    tier_names = {
        1: "Tier 1 (OSCP:HIGH + writeups)",
        2: "Tier 2 (OSCP:HIGH)",
        3: "Tier 3 (Tool families)",
        4: "Tier 4 (Critical categories)",
        5: "Tier 5 (Remaining)"
    }

    for tier in sorted(tier_counts.keys()):
        print(f"  {tier_names.get(tier, f'Tier {tier}'):40} {tier_counts[tier]:>4}")
    print()

    # By OSCP priority
    print("By OSCP Priority:")
    priority_counts = {}
    for cmd in isolated:
        priority = cmd['oscp_priority']
        priority_counts[priority] = priority_counts.get(priority, 0) + 1

    for priority in ['HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']:
        if priority in priority_counts:
            print(f"  {priority:10} {priority_counts[priority]:>4}")
    print()

    # By category
    print("Top 10 Categories:")
    category_counts = {}
    for cmd in isolated:
        category = cmd['category']
        category_counts[category] = category_counts.get(category, 0) + 1

    for category, count in sorted(category_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {category:30} {count:>4}")
    print()

    # By tool family
    print("Top 10 Tool Families:")
    tool_counts = {}
    for cmd in isolated:
        tool = cmd['tool_family']
        tool_counts[tool] = tool_counts.get(tool, 0) + 1

    for tool, count in sorted(tool_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {tool:30} {count:>4}")
    print()

    print(f"CSV exported to: {output_file}")
    print("="*80)

if __name__ == '__main__':
    main()
