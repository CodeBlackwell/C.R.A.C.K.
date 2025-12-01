#!/usr/bin/env python3
"""
Migrate cheatsheet section commands from string format to object format.

Before: "sections": [{"title": "...", "commands": ["cmd-id-1", "cmd-id-2"]}]
After:  "sections": [{"title": "...", "commands": [
            {"id": "cmd-id-1", "example": "actual command", "shows": "expected output"},
            {"id": "cmd-id-2", "example": "actual command", "shows": "expected output"}
        ]}]
"""

import json
import re
from pathlib import Path
from typing import Dict, Optional


class CheatsheetMigrator:
    """Migrates cheatsheet section commands to new object format"""

    def __init__(self, base_path: Path):
        self.base_path = base_path
        self.commands_dir = base_path / 'db' / 'data' / 'commands'
        self.cheatsheets_dir = base_path / 'db' / 'data' / 'cheatsheets'
        self.commands_db: Dict[str, Dict] = {}
        self.stats = {'files': 0, 'sections': 0, 'commands_migrated': 0, 'commands_not_found': 0}

    def load_commands_db(self):
        """Load all commands into memory for lookup"""
        print("Loading commands database...")
        for json_file in self.commands_dir.rglob('*.json'):
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)
                for cmd in data.get('commands', []):
                    cmd_id = cmd.get('id')
                    if cmd_id:
                        self.commands_db[cmd_id] = cmd
            except Exception as e:
                print(f"  Warning: Failed to load {json_file.name}: {e}")

        print(f"  Loaded {len(self.commands_db)} commands")

    def fill_placeholders(self, command_text: str, variables: list) -> str:
        """Fill placeholders with example values from variables"""
        result = command_text

        # Build a map of variable names to example values
        var_examples = {}
        for var in variables:
            if isinstance(var, dict):
                name = var.get('name', '').strip('<>')
                example = var.get('example', '')
                if name and example:
                    var_examples[name] = example

        # Common default examples for standard placeholders
        defaults = {
            'TARGET': '10.10.10.5',
            'TARGET_IP': '10.10.10.5',
            'IP': '10.10.10.5',
            'RHOST': '10.10.10.5',
            'LHOST': '192.168.45.5',
            'LPORT': '443',
            'RPORT': '445',
            'PORT': '80',
            'USER': 'admin',
            'USERNAME': 'admin',
            'DOMAIN_USER': 'corp\\administrator',
            'PASSWORD': 'Password123!',
            'PASS': 'Password123!',
            'DOMAIN': 'corp.local',
            'DC_IP': '10.10.10.1',
            'HASH': 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0',
            'WORDLIST': '/usr/share/wordlists/rockyou.txt',
            'FILE': '/tmp/payload.exe',
            'OUTPUT': 'output.txt',
            'URL': 'http://10.10.10.5/vulnerable.php',
            'SHARE': 'C$',
            'COMMAND': 'whoami',
            'PAYLOAD': 'windows/x64/meterpreter/reverse_tcp',
            'INTERFACE': 'tun0',
            'TICKET': 'ticket.kirbi',
            'SPN': 'MSSQLSvc/sql.corp.local:1433',
        }

        # Find all placeholders
        placeholders = re.findall(r'<([A-Z0-9_]+)>', result)

        for ph in placeholders:
            # First try variables from command definition
            if ph in var_examples:
                result = result.replace(f'<{ph}>', var_examples[ph])
            # Then try defaults
            elif ph in defaults:
                result = result.replace(f'<{ph}>', defaults[ph])
            # Leave as-is if no example available
            else:
                result = result.replace(f'<{ph}>', f'[{ph}]')

        return result

    def get_shows_hint(self, cmd: Dict) -> str:
        """Generate a 'shows' hint from command success indicators or notes"""
        # Try success indicators first
        indicators = cmd.get('success_indicators', [])
        if indicators:
            # Take first indicator, truncate if too long
            hint = indicators[0]
            if len(hint) > 60:
                hint = hint[:57] + '...'
            return hint

        # Fall back to a generic hint based on category
        category = cmd.get('category', '')
        category_hints = {
            'enumeration': 'Shows discovered services/users/shares',
            'exploitation': 'Returns shell or confirms vulnerability',
            'post-exploit': 'Displays privilege escalation path or credentials',
            'file-transfer': 'File transfer completes successfully',
            'active-directory': 'Returns AD objects or tickets',
            'web': 'Shows web vulnerability or response',
            'pivoting': 'Tunnel established or port forwarded',
            'password-attacks': 'Credentials found or hash cracked',
        }

        return category_hints.get(category, 'Command executes successfully')

    def migrate_section_command(self, cmd_id: str) -> Optional[Dict]:
        """Convert a string command ID to the new object format"""
        cmd = self.commands_db.get(cmd_id)

        if not cmd:
            self.stats['commands_not_found'] += 1
            # Return a minimal object even if command not found
            return {
                'id': cmd_id,
                'example': f'[Command {cmd_id} not found in database]',
                'shows': 'See command documentation'
            }

        command_text = cmd.get('command', '')
        variables = cmd.get('variables', [])

        example = self.fill_placeholders(command_text, variables)
        shows = self.get_shows_hint(cmd)

        self.stats['commands_migrated'] += 1

        return {
            'id': cmd_id,
            'example': example,
            'shows': shows
        }

    def migrate_file(self, json_file: Path) -> bool:
        """Migrate a single cheatsheet file"""
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
        except Exception as e:
            print(f"  Error reading {json_file.name}: {e}")
            return False

        cheatsheets = data.get('cheatsheets', [])
        if not cheatsheets:
            print(f"  Skipping {json_file.name}: no cheatsheets array")
            return False

        modified = False

        for cs in cheatsheets:
            sections = cs.get('sections', [])
            for section in sections:
                commands = section.get('commands', [])
                new_commands = []

                for cmd in commands:
                    # Skip if already migrated (is a dict)
                    if isinstance(cmd, dict):
                        new_commands.append(cmd)
                        continue

                    # Migrate string to object
                    if isinstance(cmd, str):
                        self.stats['sections'] += 1
                        new_cmd = self.migrate_section_command(cmd)
                        if new_cmd:
                            new_commands.append(new_cmd)
                            modified = True

                section['commands'] = new_commands

        if modified:
            # Write back with nice formatting
            with open(json_file, 'w') as f:
                json.dump(data, f, indent=2)
            self.stats['files'] += 1
            return True

        return False

    def migrate_all(self):
        """Migrate all cheatsheet files"""
        self.load_commands_db()

        print(f"\nMigrating cheatsheets in {self.cheatsheets_dir}...")

        for json_file in sorted(self.cheatsheets_dir.rglob('*.json')):
            rel_path = json_file.relative_to(self.cheatsheets_dir)
            result = self.migrate_file(json_file)
            status = "migrated" if result else "skipped/unchanged"
            print(f"  {rel_path}: {status}")

        print("\n" + "=" * 60)
        print("MIGRATION SUMMARY")
        print("=" * 60)
        print(f"Files modified: {self.stats['files']}")
        print(f"Section commands migrated: {self.stats['commands_migrated']}")
        print(f"Commands not found in DB: {self.stats['commands_not_found']}")


def main():
    base_path = Path(__file__).resolve().parents[2]  # crack/
    migrator = CheatsheetMigrator(base_path)
    migrator.migrate_all()


if __name__ == '__main__':
    main()
