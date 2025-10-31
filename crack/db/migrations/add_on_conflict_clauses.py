#!/usr/bin/env python3
"""
Add ON CONFLICT clauses to PostgreSQL migration files

Strategy:
- Main tables (commands, variables, tags): UPDATE if data is different (using IS DISTINCT FROM)
- Junction tables (command_tags, command_flags, command_vars, command_indicators): DO NOTHING
"""

import re
from pathlib import Path
from typing import List, Tuple

class OnConflictAdder:
    """Add ON CONFLICT clauses with conditional update logic"""

    MIGRATION_FILES = [
        "003_ftp_plugin_commands_CORRECTED.sql",
        "004_nfs_plugin_commands.sql",
        "005_smtp_plugin_commands.sql",
        "006_mysql_plugin_commands.sql",
        "007_ssh_plugin_commands.sql"
    ]

    def add_commands_conflict(self, content: str) -> Tuple[str, int]:
        """Add ON CONFLICT for commands table with conditional UPDATE"""
        pattern = r'(INSERT INTO commands\s*\([^)]+\)\s*VALUES\s*\([^;]+\));'

        replacement = r'''\1
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name,
    command_template = EXCLUDED.command_template,
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    subcategory = EXCLUDED.subcategory,
    oscp_relevance = EXCLUDED.oscp_relevance,
    notes = EXCLUDED.notes
WHERE (
    commands.name IS DISTINCT FROM EXCLUDED.name OR
    commands.command_template IS DISTINCT FROM EXCLUDED.command_template OR
    commands.description IS DISTINCT FROM EXCLUDED.description OR
    commands.category IS DISTINCT FROM EXCLUDED.category OR
    commands.subcategory IS DISTINCT FROM EXCLUDED.subcategory OR
    commands.oscp_relevance IS DISTINCT FROM EXCLUDED.oscp_relevance OR
    commands.notes IS DISTINCT FROM EXCLUDED.notes
);'''

        new_content, count = re.subn(pattern, replacement, content, flags=re.DOTALL | re.MULTILINE)
        return new_content, count

    def add_variables_conflict(self, content: str) -> Tuple[str, int]:
        """Add ON CONFLICT for variables table"""
        pattern = r'(INSERT INTO variables\s*\([^)]+\)\s*VALUES\s*[^;]+);'

        replacement = r'''\1
ON CONFLICT (name) DO UPDATE SET
    description = EXCLUDED.description,
    data_type = EXCLUDED.data_type,
    default_value = EXCLUDED.default_value,
    source = EXCLUDED.source
WHERE (
    variables.description IS DISTINCT FROM EXCLUDED.description OR
    variables.data_type IS DISTINCT FROM EXCLUDED.data_type OR
    variables.default_value IS DISTINCT FROM EXCLUDED.default_value OR
    variables.source IS DISTINCT FROM EXCLUDED.source
);'''

        new_content, count = re.subn(pattern, replacement, content, flags=re.DOTALL)
        return new_content, count

    def add_tags_conflict(self, content: str) -> Tuple[str, int]:
        """Add ON CONFLICT for tags table"""
        pattern = r'(INSERT INTO tags\s*\([^)]+\)\s*VALUES\s*[^;]+);'

        replacement = r'''\1
ON CONFLICT (name) DO UPDATE SET
    category = EXCLUDED.category,
    description = EXCLUDED.description,
    color = EXCLUDED.color
WHERE (
    tags.category IS DISTINCT FROM EXCLUDED.category OR
    tags.description IS DISTINCT FROM EXCLUDED.description OR
    tags.color IS DISTINCT FROM EXCLUDED.color
);'''

        new_content, count = re.subn(pattern, replacement, content, flags=re.DOTALL)
        return new_content, count

    def add_junction_conflicts(self, content: str) -> Tuple[str, int]:
        """Add DO NOTHING for junction tables"""
        total_count = 0

        # command_tags
        content, count = re.subn(
            r'(INSERT INTO command_tags\s*\([^)]+\)\s*VALUES\s*[^;]+);',
            r'\1 ON CONFLICT (command_id, tag_id) DO NOTHING;',
            content,
            flags=re.DOTALL
        )
        total_count += count

        # command_flags
        content, count = re.subn(
            r'(INSERT INTO command_flags\s*\([^)]+\)\s*VALUES\s*[^;]+);',
            r'\1 ON CONFLICT (command_id, flag) DO NOTHING;',
            content,
            flags=re.DOTALL
        )
        total_count += count

        # command_vars
        content, count = re.subn(
            r'(INSERT INTO command_vars\s*\([^)]+\)\s*VALUES\s*[^;]+);',
            r'\1 ON CONFLICT (command_id, variable_id) DO NOTHING;',
            content,
            flags=re.DOTALL
        )
        total_count += count

        # command_indicators
        content, count = re.subn(
            r'(INSERT INTO command_indicators\s*\([^)]+\)\s*VALUES\s*[^;]+);',
            r'\1 ON CONFLICT DO NOTHING;',
            content,
            flags=re.DOTALL
        )
        total_count += count

        # plugin_task_templates (will fail but that's ok)
        content, count = re.subn(
            r'(INSERT INTO plugin_task_templates\s*\([^)]+\)\s*VALUES\s*[^;]+);',
            r'\1 ON CONFLICT DO NOTHING;',
            content,
            flags=re.DOTALL
        )
        total_count += count

        return content, total_count

    def process_file(self, filepath: Path) -> Tuple[int, str, dict]:
        """Process single migration file"""
        content = filepath.read_text()

        # Track changes per table
        stats = {}

        # Apply transformations in order
        content, count = self.add_commands_conflict(content)
        stats['commands'] = count

        content, count = self.add_variables_conflict(content)
        stats['variables'] = count

        content, count = self.add_tags_conflict(content)
        stats['tags'] = count

        content, count = self.add_junction_conflicts(content)
        stats['junctions'] = count

        total_changes = sum(stats.values())

        return total_changes, content, stats

    def run(self, migrations_dir: Path, dry_run: bool = True):
        """Process all migration files"""
        print("🔧 PostgreSQL ON CONFLICT Clause Generator")
        print("=" * 60)
        print(f"Mode: {'DRY RUN' if dry_run else 'APPLY CHANGES'}")
        print("=" * 60)

        total_clauses = 0

        for filename in self.MIGRATION_FILES:
            filepath = migrations_dir / filename
            if not filepath.exists():
                print(f"\n⚠️  Skipping {filename} (not found)")
                continue

            print(f"\n📄 Processing {filename}...")
            changes, new_content, stats = self.process_file(filepath)

            print(f"   Commands (UPDATE):  {stats['commands']}")
            print(f"   Variables (UPDATE): {stats['variables']}")
            print(f"   Tags (UPDATE):      {stats['tags']}")
            print(f"   Junctions (NOTHING): {stats['junctions']}")
            print(f"   Total:              {changes}")

            if dry_run:
                # Save to /tmp for review
                diff_file = Path(f"/tmp/{filename}")
                diff_file.write_text(new_content)
                print(f"   💾 Preview: {diff_file}")
            else:
                # Create backup
                backup = filepath.with_suffix('.sql.pre_conflict')
                if not backup.exists():
                    filepath.rename(backup)
                    print(f"   💾 Backup: {backup.name}")
                else:
                    print(f"   ℹ️  Backup exists: {backup.name}")

                # Write changes
                filepath.write_text(new_content)
                print(f"   ✅ Added {changes} ON CONFLICT clauses")

            total_clauses += changes

        print("\n" + "=" * 60)
        print(f"📊 Summary: {total_clauses} ON CONFLICT clauses {'would be added' if dry_run else 'added'}")
        print("=" * 60)

        if dry_run:
            print("\n🔍 DRY RUN MODE - No files modified")
            print("   Review changes in /tmp/00*.sql")
            print("   Run with --apply to apply changes")
        else:
            print("\n✅ All changes applied successfully")
            print("   Backups saved with .pre_conflict extension")
            print("\nNext steps:")
            print("   1. Test syntax: psql -d crack_test -f db/migrations/003_*.sql")
            print("   2. Run tests: pytest tests/db/test_plugin_repository.py -xvs")


if __name__ == '__main__':
    import sys

    migrations_dir = Path(__file__).parent
    dry_run = '--apply' not in sys.argv

    adder = OnConflictAdder()
    adder.run(migrations_dir, dry_run=dry_run)
