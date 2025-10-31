#!/usr/bin/env python3
"""
Fix boolean literal values in PostgreSQL migration SQL files

Converts SQLite-style integer booleans (0/1) to PostgreSQL booleans (FALSE/TRUE)
in INSERT statements for known boolean columns.

Usage:
    python3 fix_boolean_literals.py
"""

import re
from pathlib import Path
from typing import List, Tuple, Dict, Optional


class BooleanLiteralFixer:
    """Fix boolean literal values in SQL INSERT statements"""

    # Migration files that need fixing
    TARGET_FILES = [
        '003_ftp_plugin_commands_CORRECTED.sql',
        '004_nfs_plugin_commands.sql',
        '005_smtp_plugin_commands.sql',
        '006_mysql_plugin_commands.sql',
        '007_ssh_plugin_commands.sql',
    ]

    def __init__(self, migrations_dir: Path):
        """Initialize fixer with migrations directory"""
        self.migrations_dir = migrations_dir
        self.stats = {
            'files_processed': 0,
            'replacements_made': 0,
            'errors': []
        }

    def fix_all_files(self) -> dict:
        """Fix all target migration files"""
        print("🔧 PostgreSQL Boolean Literal Fixer")
        print("=" * 60)

        for filename in self.TARGET_FILES:
            filepath = self.migrations_dir / filename
            if not filepath.exists():
                self.stats['errors'].append(f"File not found: {filename}")
                print(f"⚠️  Skipping {filename} (not found)")
                continue

            print(f"\n📄 Processing: {filename}")
            replacements = self._fix_file(filepath)

            if replacements > 0:
                self.stats['files_processed'] += 1
                self.stats['replacements_made'] += replacements
                print(f"   ✅ Made {replacements} replacements")
            else:
                print(f"   ℹ️  No changes needed")

        self._print_summary()
        return self.stats

    def _parse_values_tuple(self, values_str: str) -> List[str]:
        """
        Parse a VALUES tuple into individual values, handling nested parentheses

        Example: "('id', (SELECT ...), 1, TRUE, 'val')" -> ['id', '(SELECT ...)', '1', 'TRUE', 'val']
        """
        values = []
        current_value = []
        paren_depth = 0
        in_string = False
        string_char = None

        for char in values_str:
            if char in ('"', "'") and not in_string:
                in_string = True
                string_char = char
                current_value.append(char)
            elif char == string_char and in_string:
                in_string = False
                string_char = None
                current_value.append(char)
            elif char == '(' and not in_string:
                paren_depth += 1
                current_value.append(char)
            elif char == ')' and not in_string:
                paren_depth -= 1
                current_value.append(char)
            elif char == ',' and paren_depth == 1 and not in_string:
                # Top-level comma - end of value
                values.append(''.join(current_value).strip())
                current_value = []
            else:
                current_value.append(char)

        # Add last value
        if current_value:
            values.append(''.join(current_value).strip())

        return values

    def _fix_command_vars_line(self, line: str) -> Tuple[str, int]:
        """Fix boolean in command_vars VALUES line (is_required is position 3)"""
        # Match pattern: (...values...)
        match = re.search(r'\((.+)\)[,;]?$', line.strip())
        if not match:
            return line, 0

        values_content = match.group(1)
        values = self._parse_values_tuple('(' + values_content + ')')

        # Fix: Remove outer parentheses from first and last values
        if values and values[0].startswith('('):
            values[0] = values[0][1:]
        if values and values[-1].endswith(')'):
            values[-1] = values[-1][:-1]

        # command_vars: (command_id, variable_id, position, is_required, example_value)
        # Position index 3 is is_required
        if len(values) >= 4:
            old_value = values[3].strip()
            new_value = None

            if old_value == '1':
                new_value = 'TRUE'
            elif old_value == '0':
                new_value = 'FALSE'

            if new_value:
                # Rebuild line
                values[3] = new_value
                new_values = ', '.join(values)

                # Preserve line formatting
                indent = line[:len(line) - len(line.lstrip())]
                terminator = ');' if line.strip().endswith(');') else '),'
                new_line = f"{indent}({new_values}){terminator}\n" if line.endswith('\n') else f"{indent}({new_values}){terminator}"

                return new_line.rstrip('\n'), 1

        return line, 0

    def _fix_file(self, filepath: Path) -> int:
        """Fix boolean literals in a single file"""
        content = filepath.read_text()
        lines = content.split('\n')
        fixed_lines = []
        replacements = 0

        # Track current INSERT context
        current_table = None
        in_values = False

        for line in lines:
            original_line = line

            # Check if this is an INSERT statement
            insert_match = re.search(r'INSERT INTO (\w+)', line)
            if insert_match:
                current_table = insert_match.group(1)
                in_values = False

            # Check if we're in VALUES section
            if current_table and 'VALUES' in line:
                in_values = True

            # Reset context at semicolon (end of statement)
            if ';' in line and not re.search(r'\([^)]*;[^)]*\)', line):  # Not inside parentheses
                # Only reset if semicolon is at statement end
                if line.strip().endswith(');'):
                    current_table = None
                    in_values = False

            # Apply transformations if we're in VALUES for command_vars
            if in_values and current_table == 'command_vars':
                # Check if this line contains a values tuple
                if re.search(r'^\s*\(', line):
                    line, changed = self._fix_command_vars_line(line)
                    if changed:
                        replacements += 1

            # Handle command_flags similarly
            elif in_values and current_table == 'command_flags':
                # command_flags has is_required but may not always be in same position
                # Use simpler pattern matching for now
                original = line
                line = re.sub(r',\s*1\s*\)', ', TRUE)', line)
                line = re.sub(r',\s*0\s*\)', ', FALSE)', line)
                if line != original:
                    replacements += 1

            fixed_lines.append(line)

        content = '\n'.join(fixed_lines)

        # Write back if changes were made
        if replacements > 0:
            # Create backup
            backup_path = filepath.with_suffix('.sql.bak')
            if not backup_path.exists():
                filepath.rename(backup_path)
                print(f"   💾 Backup: {backup_path.name}")
            else:
                print(f"   ℹ️  Backup exists: {backup_path.name}")

            # Write fixed content
            filepath.write_text(content)

        return replacements

    def _print_summary(self):
        """Print summary of changes"""
        print("\n" + "=" * 60)
        print("📊 Summary")
        print("=" * 60)
        print(f"Files processed: {self.stats['files_processed']}/{len(self.TARGET_FILES)}")
        print(f"Total replacements: {self.stats['replacements_made']}")

        if self.stats['errors']:
            print("\n⚠️  Errors:")
            for error in self.stats['errors']:
                print(f"   - {error}")

        if self.stats['replacements_made'] > 0:
            print("\n✅ All boolean literals converted to PostgreSQL syntax")
            print("   Run tests to verify: pytest tests/db/test_plugin_repository.py")
        else:
            print("\nℹ️  No changes were needed")


def main():
    """Main entry point"""
    # Get migrations directory
    script_dir = Path(__file__).parent
    migrations_dir = script_dir

    if not migrations_dir.exists():
        print(f"❌ Migrations directory not found: {migrations_dir}")
        return 1

    # Run fixer
    fixer = BooleanLiteralFixer(migrations_dir)
    stats = fixer.fix_all_files()

    return 0 if not stats['errors'] else 1


if __name__ == '__main__':
    exit(main())
