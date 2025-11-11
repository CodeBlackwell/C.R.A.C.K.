#!/usr/bin/env python3
"""
Command Enrichment CLI
Interactive tool for adding missing fields to commands
"""

import json
from pathlib import Path
from typing import Dict, List, Optional
import sys


class CommandEnricher:
    """Interactive command enrichment tool"""

    FIELD_PROMPTS = {
        'flag_explanations': {
            'prompt': 'Flag explanations (dict of flag: description)',
            'type': 'dict',
            'example': '{"-v": "Verbose output", "-n": "Numeric addresses"}'
        },
        'variables': {
            'prompt': 'Variables (list of dicts with name, description, example, required)',
            'type': 'list',
            'example': '[{"name": "<TARGET>", "description": "Target IP", "example": "192.168.1.1", "required": true}]'
        },
        'prerequisites': {
            'prompt': 'Prerequisites (list of requirements)',
            'type': 'list',
            'example': '["Root/Administrator privileges", "Target service running"]'
        },
        'success_indicators': {
            'prompt': 'Success indicators (list of expected outputs)',
            'type': 'list',
            'example': '["Connection established", "Authentication successful"]'
        },
        'failure_indicators': {
            'prompt': 'Failure indicators (list of error outputs)',
            'type': 'list',
            'example': '["Connection refused", "Permission denied"]'
        },
        'next_steps': {
            'prompt': 'Next steps (list of follow-up actions)',
            'type': 'list',
            'example': '["Analyze output for vulnerabilities", "Test identified services"]'
        },
        'alternatives': {
            'prompt': 'Alternative command IDs (list of similar commands)',
            'type': 'list',
            'example': '["nmap-tcp-syn-scan", "masscan-fast-scan"]'
        },
        'troubleshooting': {
            'prompt': 'Troubleshooting (dict of issue: solution)',
            'type': 'dict',
            'example': '{"Connection timeout": "Check firewall rules", "Permission denied": "Run with sudo"}'
        },
        'use_cases': {
            'prompt': 'Use cases (list of scenarios)',
            'type': 'list',
            'example': '["Initial network discovery", "Verify open ports after exploitation"]'
        },
        'advantages': {
            'prompt': 'Advantages (list of benefits)',
            'type': 'list',
            'example': '["Fast scanning", "Stealth mode available", "Comprehensive service detection"]'
        },
        'disadvantages': {
            'prompt': 'Disadvantages (list of limitations)',
            'type': 'list',
            'example': '["Requires root privileges", "Can be detected by IDS", "Noisy on network"]'
        },
        'output_analysis': {
            'prompt': 'Output analysis (list of interpretation guides)',
            'type': 'list',
            'example': '["Open ports indicate running services", "Filtered ports suggest firewall rules"]'
        },
        'common_uses': {
            'prompt': 'Common uses (list of typical applications)',
            'type': 'list',
            'example': '["Initial reconnaissance", "Service version detection", "Vulnerability scanning"]'
        },
        'references': {
            'prompt': 'References (list of dicts with title/url)',
            'type': 'list',
            'example': '[{"title": "Nmap Documentation", "url": "https://nmap.org/docs.html"}]'
        }
    }

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir

    def find_command_file(self, command_id: str) -> Optional[tuple[Path, Dict]]:
        """Find JSON file containing command by ID"""
        for json_file in self.data_dir.rglob("*.json"):
            if 'auto-generated' not in json_file.name:
                continue

            with open(json_file) as f:
                data = json.load(f)
                for cmd in data.get('commands', []):
                    if cmd.get('id') == command_id:
                        return json_file, data

        return None

    def show_command_status(self, cmd: Dict):
        """Display current command status"""
        print(f"\n{'='*60}")
        print(f"Command: {cmd.get('name', 'Unknown')}")
        print(f"ID: {cmd.get('id', 'Unknown')}")
        print(f"Category: {cmd.get('category', 'Unknown')}")
        print(f"{'='*60}\n")

        print("Current Status:")
        for field, config in self.FIELD_PROMPTS.items():
            value = cmd.get(field)
            status = "✓" if self._is_populated(value) else "✗"
            print(f"  {status} {field:25} {self._format_preview(value)}")

    def _is_populated(self, value) -> bool:
        """Check if field has meaningful content"""
        if value is None:
            return False
        if isinstance(value, str) and not value.strip():
            return False
        if isinstance(value, (list, dict)) and not value:
            return False
        return True

    def _format_preview(self, value) -> str:
        """Format field value for preview"""
        if not self._is_populated(value):
            return "(empty)"

        if isinstance(value, list):
            return f"({len(value)} items)"
        elif isinstance(value, dict):
            return f"({len(value)} entries)"
        elif isinstance(value, str):
            preview = value[:50]
            return f'"{preview}..."' if len(value) > 50 else f'"{preview}"'
        return str(value)

    def enrich_interactive(self, command_id: str, fields: Optional[List[str]] = None):
        """Interactively enrich command"""
        result = self.find_command_file(command_id)
        if not result:
            print(f"Error: Command '{command_id}' not found")
            return False

        json_file, data = result

        # Find command in data
        cmd = next((c for c in data['commands'] if c.get('id') == command_id), None)
        if not cmd:
            return False

        self.show_command_status(cmd)

        # Determine which fields to enrich
        if fields:
            target_fields = [f for f in fields if f in self.FIELD_PROMPTS]
        else:
            # Only prompt for empty fields
            target_fields = [f for f in self.FIELD_PROMPTS.keys() if not self._is_populated(cmd.get(f))]

        if not target_fields:
            print("\nAll fields are populated!")
            return True

        print(f"\nEnriching {len(target_fields)} fields...")
        print("(Enter 'skip' to skip a field, 'quit' to save and exit)\n")

        modified = False

        for field in target_fields:
            config = self.FIELD_PROMPTS[field]
            current = cmd.get(field)

            print(f"\n{'─'*60}")
            print(f"Field: {field}")
            print(f"Type: {config['type']}")
            print(f"Example: {config['example']}")

            if self._is_populated(current):
                print(f"Current: {json.dumps(current, indent=2)}")

            print(f"\n{config['prompt']}:")
            print("(For JSON input, enter on multiple lines, then '.' on blank line to finish)")

            # Multi-line JSON input
            lines = []
            while True:
                try:
                    line = input()
                    if line.strip().lower() == 'skip':
                        print(f"Skipped {field}")
                        break
                    elif line.strip().lower() == 'quit':
                        print("Saving and exiting...")
                        if modified:
                            self._save_data(json_file, data)
                        return True
                    elif line.strip() == '.':
                        # Parse accumulated input
                        json_str = '\n'.join(lines)
                        if json_str.strip():
                            try:
                                value = json.loads(json_str)
                                cmd[field] = value
                                modified = True
                                print(f"✓ Added {field}")
                            except json.JSONDecodeError as e:
                                print(f"Error: Invalid JSON - {e}")
                                print("Skipping this field...")
                        break
                    else:
                        lines.append(line)
                except EOFError:
                    break

        # Save changes
        if modified:
            self._save_data(json_file, data)
            print(f"\n✓ Saved changes to {json_file.name}")
            return True
        else:
            print("\nNo changes made")
            return False

    def _save_data(self, json_file: Path, data: Dict):
        """Save updated data to JSON file"""
        with open(json_file, 'w') as f:
            json.dump(data, f, indent=2)

    def enrich_batch(self, command_ids: List[str], template: Dict):
        """Batch enrich multiple commands with template data"""
        print(f"Batch enriching {len(command_ids)} commands...")

        for cmd_id in command_ids:
            result = self.find_command_file(cmd_id)
            if not result:
                print(f"✗ Command not found: {cmd_id}")
                continue

            json_file, data = result
            cmd = next((c for c in data['commands'] if c.get('id') == cmd_id), None)

            if not cmd:
                continue

            # Apply template fields
            modified = False
            for field, value in template.items():
                if field in self.FIELD_PROMPTS and not self._is_populated(cmd.get(field)):
                    cmd[field] = value
                    modified = True

            if modified:
                self._save_data(json_file, data)
                print(f"✓ Enriched: {cmd_id}")


def main():
    """CLI entry point"""
    import argparse

    parser = argparse.ArgumentParser(description='Enrich command definitions')
    parser.add_argument('command_id', help='Command ID to enrich')
    parser.add_argument('--data-dir', type=Path,
                       default=Path(__file__).parent.parent / 'data' / 'commands',
                       help='Directory containing command JSON files')
    parser.add_argument('--fields', nargs='+',
                       help='Specific fields to enrich (default: all empty fields)')
    parser.add_argument('--show', action='store_true',
                       help='Show current status without enriching')

    args = parser.parse_args()

    enricher = CommandEnricher(args.data_dir)

    if args.show:
        result = enricher.find_command_file(args.command_id)
        if result:
            _, data = result
            cmd = next((c for c in data['commands'] if c.get('id') == args.command_id), None)
            if cmd:
                enricher.show_command_status(cmd)
        else:
            print(f"Error: Command '{args.command_id}' not found")
        return

    enricher.enrich_interactive(args.command_id, args.fields)


if __name__ == '__main__':
    main()
