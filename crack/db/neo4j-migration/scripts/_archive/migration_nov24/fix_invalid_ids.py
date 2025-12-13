#!/usr/bin/env python3
"""
Round 2: Fix invalid ID formats.
Strategy: Remove garbage, fix msfvenom paths, fix extensions/underscores.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Tuple

class InvalidIDFixer:
    def __init__(self):
        self.stats = {
            'removed': 0,
            'fixed': 0,
            'manual_review': 0
        }
        self.valid_id_pattern = re.compile(r'^[a-z0-9]+(-[a-z0-9]+)*$')

    def should_remove(self, cmd_id: str, cmd: Dict) -> bool:
        """Determine if this is garbage that should be removed"""
        # Single special characters
        if len(cmd_id) <= 2 and not cmd_id.isalnum():
            return True

        # XSS payloads (not real commands)
        if cmd_id.startswith(('<', '>', '"', "'")):
            return True

        # URL encoded garbage
        if '%25' in cmd_id or '%2e' in cmd_id or '%2f' in cmd_id:
            return True

        # File paths that aren't commands
        if cmd_id.startswith('/') or cmd_id.startswith('\\'):
            return True

        # Incomplete entries (just punctuation)
        if cmd_id in ['#', '"', '$', ':', ';', ',', '.', '-']:
            return True

        # PowerShell syntax (not commands)
        if cmd_id.startswith('[system.') or cmd_id.startswith('$env:'):
            return True

        # Mimikatz/tool syntax fragments
        if '::' in cmd_id or cmd_id.endswith(':'):
            return True

        # Incomplete command fragments
        if cmd_id.startswith(('#-', 'manual:', 'alternative:')):
            return True

        # File extensions alone
        if cmd_id.startswith('.') and len(cmd_id) < 10:
            return True

        # Keyboard shortcuts
        if cmd_id.startswith('ctrl+') or cmd_id.startswith('alt+'):
            return True

        # Reference sites (not commands)
        if cmd_id in ['google:', 'hacktricks:', 'payloadsallthethings:', 'builtwith.com']:
            return True

        return False

    def fix_id(self, cmd_id: str, cmd: Dict) -> Tuple[str, str]:
        """
        Attempt to fix invalid ID.
        Returns: (new_id, action) where action is 'fixed' or 'manual'
        """
        original_id = cmd_id

        # Msfvenom payload paths: cmd/unix/reverse → msfvenom-cmd-unix-reverse
        if '/' in cmd_id and not cmd_id.startswith('/'):
            parts = cmd_id.replace('_', '-').split('/')
            new_id = 'msfvenom-' + '-'.join(parts)
            new_id = new_id.lower()
            if self.valid_id_pattern.match(new_id):
                return (new_id, 'fixed')

        # File extensions: powerup.ps1 → import-powerup, rubeus.exe → rubeus
        if '.' in cmd_id and cmd_id.count('.') == 1:
            base = cmd_id.split('.')[0].lower()
            ext = cmd_id.split('.')[1].lower()

            # PowerShell scripts → import-{name}
            if ext == 'ps1':
                new_id = f'import-{base}' if not base.startswith('import') else base
            # Executables → just the name
            elif ext in ['exe', 'dll']:
                new_id = base
            # ZIP files
            elif ext == 'zip':
                new_id = base
            else:
                new_id = base

            if self.valid_id_pattern.match(new_id):
                return (new_id, 'fixed')

        # Underscores → hyphens
        if '_' in cmd_id:
            new_id = cmd_id.replace('_', '-').lower()
            if self.valid_id_pattern.match(new_id):
                return (new_id, 'fixed')

        # Remove colons at end
        if cmd_id.endswith(':'):
            new_id = cmd_id[:-1].lower()
            if self.valid_id_pattern.match(new_id):
                return (new_id, 'fixed')

        # Remove leading/trailing special chars
        new_id = re.sub(r'^[^a-z0-9]+|[^a-z0-9]+$', '', cmd_id.lower())
        if new_id and self.valid_id_pattern.match(new_id):
            return (new_id, 'fixed')

        # Can't auto-fix
        return (cmd_id, 'manual')

    def process_file(self, file_path: Path) -> Dict:
        """Process a single JSON file"""
        with open(file_path, 'r') as f:
            data = json.load(f)

        commands = data.get('commands', [])
        filtered_commands = []
        file_stats = {'removed': [], 'fixed': [], 'manual': []}

        for cmd in commands:
            cmd_id = cmd.get('id', '')

            # Skip if already valid
            if self.valid_id_pattern.match(cmd_id):
                filtered_commands.append(cmd)
                continue

            # Check if should remove
            if self.should_remove(cmd_id, cmd):
                file_stats['removed'].append({
                    'id': cmd_id,
                    'name': cmd.get('name', ''),
                    'reason': 'Garbage/incomplete entry'
                })
                self.stats['removed'] += 1
                continue

            # Try to fix
            new_id, action = self.fix_id(cmd_id, cmd)

            if action == 'fixed':
                cmd['id'] = new_id
                file_stats['fixed'].append({
                    'old_id': cmd_id,
                    'new_id': new_id,
                    'name': cmd.get('name', '')
                })
                self.stats['fixed'] += 1
                filtered_commands.append(cmd)
            else:
                file_stats['manual'].append({
                    'id': cmd_id,
                    'name': cmd.get('name', ''),
                    'command': cmd.get('command', '')[:60]
                })
                self.stats['manual_review'] += 1
                # Keep for now with original ID
                filtered_commands.append(cmd)

        # Save if modified
        if len(filtered_commands) != len(commands) or file_stats['fixed']:
            data['commands'] = filtered_commands
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)

        return file_stats

def main():
    base_path = Path('db/data/commands')
    fixer = InvalidIDFixer()

    print("=" * 80)
    print("ROUND 2: FIX INVALID ID FORMATS")
    print("=" * 80)

    files_with_changes = {}
    manual_review_items = []

    for json_file in sorted(base_path.rglob('*.json')):
        file_stats = fixer.process_file(json_file)

        if file_stats['removed'] or file_stats['fixed'] or file_stats['manual']:
            rel_path = str(json_file.relative_to(base_path))
            files_with_changes[rel_path] = file_stats

            if file_stats['manual']:
                manual_review_items.extend([
                    (rel_path, item) for item in file_stats['manual']
                ])

    # Print results
    print("\nFILES MODIFIED:")
    print("-" * 80)
    for file_path, stats in sorted(files_with_changes.items()):
        if stats['removed'] or stats['fixed']:
            print(f"\n{file_path}:")
            if stats['removed']:
                print(f"  Removed: {len(stats['removed'])} garbage entries")
            if stats['fixed']:
                print(f"  Fixed: {len(stats['fixed'])} IDs")
                for item in stats['fixed'][:5]:
                    print(f"    {item['old_id']:30} → {item['new_id']}")
                if len(stats['fixed']) > 5:
                    print(f"    ... and {len(stats['fixed']) - 5} more")

    print("\n" + "=" * 80)
    print("ROUND 2 RESULTS")
    print("=" * 80)
    print(f"Removed (garbage): {fixer.stats['removed']}")
    print(f"Fixed (auto): {fixer.stats['fixed']}")
    print(f"Manual review needed: {fixer.stats['manual_review']}")

    if manual_review_items:
        print("\n" + "=" * 80)
        print("MANUAL REVIEW REQUIRED:")
        print("=" * 80)
        for file_path, item in manual_review_items:
            print(f"\nFile: {file_path}")
            print(f"  ID: {item['id']}")
            print(f"  Name: {item['name']}")
            print(f"  Command: {item['command']}")

    print("\n" + "=" * 80)
    print("NEXT STEP: Run validation to confirm")
    print("  python3 db/neo4j-migration/scripts/utils/validate_schema_compliance.py")
    print("=" * 80)

if __name__ == '__main__':
    main()
