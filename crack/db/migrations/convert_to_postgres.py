#!/usr/bin/env python3
"""
Automated SQLite to PostgreSQL migration script
Converts syntax in migration SQL files (002-007)
"""

import re
from pathlib import Path

# Migration files to convert
FILES = [
    "002_service_plugins.sql",
    "003_ftp_plugin_commands.sql",
    "003_ftp_plugin_commands_CORRECTED.sql",
    "004_nfs_plugin_commands.sql",
    "005_smtp_plugin_commands.sql",
    "006_mysql_plugin_commands.sql",
    "007_ssh_plugin_commands.sql",
]

def convert_file(filepath):
    """Convert a single SQL file from SQLite to PostgreSQL syntax"""
    print(f"📄 Processing {filepath.name}...")

    # Read file
    content = filepath.read_text()
    original_content = content

    # Create backup
    backup = filepath.with_suffix('.sql.bak')
    backup.write_text(content)

    # 1. Convert AUTOINCREMENT to SERIAL
    content = content.replace('INTEGER PRIMARY KEY AUTOINCREMENT', 'SERIAL PRIMARY KEY')

    # 2. Convert BOOLEAN defaults
    content = re.sub(r'\bBOOLEAN DEFAULT 0\b', 'BOOLEAN DEFAULT FALSE', content)
    content = re.sub(r'\bBOOLEAN DEFAULT 1\b', 'BOOLEAN DEFAULT TRUE', content)

    # 3. Convert INSERT OR IGNORE
    # Pattern: INSERT OR IGNORE INTO table_name ... VALUES ...;
    # Result: INSERT INTO table_name ... VALUES ... ON CONFLICT DO NOTHING;
    content = re.sub(
        r'INSERT OR IGNORE INTO\s+(\w+)\s*\((.*?)\)\s*VALUES\s*\((.*?)\)\s*;',
        r'INSERT INTO \1 (\2) VALUES (\3) ON CONFLICT DO NOTHING;',
        content,
        flags=re.DOTALL
    )

    # 4. Convert INSERT OR REPLACE
    # For commands table: unique key is 'id'
    def replace_insert_or_replace(match):
        table = match.group(1)
        columns_part = match.group(2)
        values_part = match.group(3)

        # Extract column names
        columns = [c.strip() for c in columns_part.split(',')]

        if table == 'commands':
            # Build UPDATE SET clause (exclude id since it's the conflict column)
            update_cols = [c for c in columns if c not in ['id', 'created_at']]
            update_set = ',\n        '.join([f"{col} = EXCLUDED.{col}" for col in update_cols])

            return f"""INSERT INTO {table} (
        {columns_part}
    ) VALUES (
        {values_part}
    )
    ON CONFLICT (id) DO UPDATE SET
        {update_set};"""

        elif table == 'variables':
            # Variables table: unique on 'name'
            update_cols = [c for c in columns if c not in ['id', 'name', 'created_at']]
            update_set = ',\n        '.join([f"{col} = EXCLUDED.{col}" for col in update_cols])

            return f"""INSERT INTO {table} (
        {columns_part}
    ) VALUES (
        {values_part}
    )
    ON CONFLICT (name) DO UPDATE SET
        {update_set};"""

        elif table == 'tags':
            # Tags table: unique on 'name'
            return f"""INSERT INTO {table} (
        {columns_part}
    ) VALUES (
        {values_part}
    )
    ON CONFLICT (name) DO NOTHING;"""

        else:
            # Default: just use DO NOTHING for safety
            return f"""INSERT INTO {table} (
        {columns_part}
    ) VALUES (
        {values_part}
    )
    ON CONFLICT DO NOTHING;"""

    content = re.sub(
        r'INSERT OR REPLACE INTO\s+(\w+)\s*\(\s*(.*?)\s*\)\s*VALUES\s*\(\s*(.*?)\s*\)\s*;',
        replace_insert_or_replace,
        content,
        flags=re.DOTALL
    )

    # Write converted file
    filepath.write_text(content)

    # Report changes
    changes = {
        'AUTOINCREMENT': original_content.count('AUTOINCREMENT'),
        'BOOLEAN DEFAULT 0/1': original_content.count('BOOLEAN DEFAULT 0') + original_content.count('BOOLEAN DEFAULT 1'),
        'INSERT OR IGNORE': original_content.count('INSERT OR IGNORE'),
        'INSERT OR REPLACE': original_content.count('INSERT OR REPLACE'),
    }

    print(f"  ✓ Converted {changes['AUTOINCREMENT']} AUTOINCREMENT → SERIAL")
    print(f"  ✓ Converted {changes['BOOLEAN DEFAULT 0/1']} BOOLEAN defaults")
    print(f"  ✓ Converted {changes['INSERT OR IGNORE']} INSERT OR IGNORE")
    print(f"  ✓ Converted {changes['INSERT OR REPLACE']} INSERT OR REPLACE")
    print(f"  📦 Backup: {backup.name}\n")

    return changes

def main():
    print("🔄 Converting migration files to PostgreSQL syntax...\n")

    migrations_dir = Path(__file__).parent
    total_changes = {
        'AUTOINCREMENT': 0,
        'BOOLEAN DEFAULT 0/1': 0,
        'INSERT OR IGNORE': 0,
        'INSERT OR REPLACE': 0,
    }

    for filename in FILES:
        filepath = migrations_dir / filename
        if not filepath.exists():
            print(f"⚠️  Skipping {filename} (not found)\n")
            continue

        changes = convert_file(filepath)
        for key in total_changes:
            total_changes[key] += changes[key]

    print("\n" + "="*60)
    print("✅ Migration file conversion complete!")
    print("="*60)
    print("\n📊 Total conversions:")
    for key, count in total_changes.items():
        print(f"  • {key}: {count}")
    print("\n⚠️  Recommendation: Review converted files before running migrations")
    print("Backups created: *.sql.bak\n")

if __name__ == '__main__':
    main()
