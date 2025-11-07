#!/usr/bin/env python3
"""
Formatter for ssh-tunneling-linux.json cheatsheet.

Transforms approach, expected_outcome, why_this_works, and notes fields
to improve readability with strategic newlines and command indentation.

Rules:
1. Insert \n before "Step N:" (except Step 1)
2. Indent commands 2 spaces when they follow a colon
3. Preserve ASCII diagrams unchanged
4. No semantic labels (Outcome:, Limitation:, etc.)
5. Natural paragraph breaks for conceptual boundaries
"""

import json
import re
from pathlib import Path


def format_approach(text: str) -> str:
    """
    Format approach field:
    - Add newline before Step 2+
    - Indent commands after colons (description: command pattern)

    Example:
      "Step 1: Verify Socat: which socat. Step 2: Listen on port: socat -ddd..."
      →
      "Step 1: Verify Socat:\n  which socat\nStep 2: Listen on port:\n  socat -ddd..."
    """
    result = text

    # Add newlines before Step 2+ (handle both period and no-period cases)
    result = re.sub(r'(\.\s+|;\s+)(Step [2-9]:)', r'\1\n\2', result)
    result = re.sub(r'(\.\s+|;\s+)(Step 1[0-9]:)', r'\1\n\2', result)

    # Format command patterns: "description: command"
    # Match patterns like ": which socat", ": ssh -N", ": socat -ddd"
    # Commands typically start with lowercase tool names
    lines = []
    for line in result.split('\n'):
        # Find all ": command" patterns in the line
        parts = []
        last_end = 0

        # Pattern: colon + space + lowercase word (tool name)
        for match in re.finditer(r':\s+([a-z/][a-z0-9_/\-]+(?:\s+[^\.\n]+?)?\.)', line):
            # Add text before this match
            parts.append(line[last_end:match.start()])

            # Extract the command
            command = match.group(1).strip()

            # Check if this looks like a command (has flags/args or is a known tool)
            is_command = (
                ' -' in command or  # Has flags
                command.startswith(('which ', 'ssh ', 'socat ', 'nc ', 'python', 'psql ',
                                    'smbclient ', 'nmap ', 'proxychains ', 'sudo ', 'curl ',
                                    'xfreerdp ', 'mkdir ', 'cp ', 'grep ', 'ss ', 'ip ',
                                    'netstat ', 'iptables ', 'systemctl ', 'passwd ', 'nano '))
            )

            if is_command:
                # Format as: description:\n  command
                parts.append(':\n  ' + command)
            else:
                # Not a command, keep as-is
                parts.append(': ' + command)

            last_end = match.end()

        # Add remaining text
        parts.append(line[last_end:])
        lines.append(''.join(parts))

    result = '\n'.join(lines)

    # Keep "Traffic:" summaries on same line
    result = re.sub(r'\n\s*Traffic:', ' Traffic:', result)

    return result


def format_expected_outcome(text: str) -> str:
    """
    Format expected_outcome field:
    - Add paragraph breaks at major concept boundaries
    - Keep output/results inline
    """
    # Add newline before major sections
    text = re.sub(r'\.\s+Limitation:', '.\n\nLimitation:', text)
    text = re.sub(r'\.\s+Alternative:', '.\n\nAlternative:', text)
    text = re.sub(r'\.\s+Time:', '.\n\nTime:', text)
    text = re.sub(r'\.\s+Success rate:', '.\n\nSuccess rate:', text)

    # Add space after tool output descriptions
    text = re.sub(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+[^\.]*)\.(\s+[A-Z])', r'\1.\n\n\2', text)

    return text


def format_why_this_works(text: str) -> str:
    """
    Format why_this_works field:
    - Add paragraph breaks at explanation boundaries
    """
    # Add newline before major concept explanations
    text = re.sub(r'(\.)(\s+)(SSH|Socat|SOCKS|Firewall|Multi-hop|Classic|Result:)', r'\1\n\n\3', text)

    return text


def format_notes(text: str) -> str:
    """
    Format notes field (Phase sections):
    - Add paragraph breaks at topic changes
    """
    # Add newline before major topics
    text = re.sub(r'(\.)(\s+)(Critical|Progression|Prerequisites|Use case|Testing|Troubleshooting|sshuttle|Performance|SSH connection|Time estimate|OSCP)', r'\1\n\n\3', text)

    return text


def format_cheatsheet(input_path: Path) -> dict:
    """Load, format, and return transformed cheatsheet."""
    with open(input_path, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # Format scenarios
    for scenario in data.get('scenarios', []):
        if 'approach' in scenario:
            original = scenario['approach']
            scenario['approach'] = format_approach(original)

        if 'expected_outcome' in scenario:
            scenario['expected_outcome'] = format_expected_outcome(scenario['expected_outcome'])

        if 'why_this_works' in scenario:
            scenario['why_this_works'] = format_why_this_works(scenario['why_this_works'])

    # Format section notes
    for section in data.get('sections', []):
        if 'notes' in section:
            section['notes'] = format_notes(section['notes'])

    return data


def main():
    """Format ssh-tunneling-linux.json cheatsheet and save."""
    # Cheatsheet is in reference/data/cheatsheets/
    input_file = Path(__file__).parent.parent.parent / 'cheatsheets' / 'ssh-tunneling-linux.json'
    backup_file = input_file.with_suffix('.json.bak')

    print(f"Reading: {input_file}")

    # Backup original (only if not already backed up)
    if not backup_file.exists():
        import shutil
        shutil.copy(input_file, backup_file)
        print(f"Backup created: {backup_file}")
    else:
        print(f"Using existing backup: {backup_file}")

    # Transform
    formatted_data = format_cheatsheet(input_file)

    # Write formatted JSON
    with open(input_file, 'w', encoding='utf-8') as f:
        json.dump(formatted_data, f, indent=2, ensure_ascii=False)

    print(f"✓ Formatted: {input_file}")
    print("\nValidating JSON...")

    # Validate
    try:
        with open(input_file, 'r') as f:
            json.load(f)
        print("✓ JSON valid")
    except json.JSONDecodeError as e:
        print(f"✗ JSON validation failed: {e}")
        print("Restoring backup...")
        import shutil
        shutil.copy(backup_file, input_file)
        return 1

    # Show sample transformation
    print("\nSample transformation (Scenario 1 approach):")
    print("=" * 60)

    with open(backup_file, 'r') as f:
        original = json.load(f)

    orig_approach = original['scenarios'][0]['approach'][:200]
    new_approach = formatted_data['scenarios'][0]['approach'][:250]

    print(f"BEFORE:\n{orig_approach}...")
    print(f"\nAFTER:\n{new_approach}...")

    return 0


if __name__ == '__main__':
    exit(main())
