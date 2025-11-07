#!/usr/bin/env python3
"""
Apply database migration to add command_relation_guidance table.
"""

import sys
from pathlib import Path

# Add parent directory to path for imports
crack_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(crack_root))
db_dir = crack_root / "db"
sys.path.insert(0, str(db_dir))

from config import get_db_config
import psycopg2


def apply_migration(migration_file: Path):
    """Apply SQL migration file to database."""
    try:
        # Read migration SQL
        with open(migration_file, 'r') as f:
            migration_sql = f.read()

        # Connect to database
        config = get_db_config()
        conn = psycopg2.connect(**config)
        cursor = conn.cursor()

        # Execute migration
        cursor.execute(migration_sql)
        conn.commit()

        print(f"✓ Migration applied successfully: {migration_file.name}")

        # Verify table exists
        cursor.execute("""
            SELECT table_name
            FROM information_schema.tables
            WHERE table_name = 'command_relation_guidance';
        """)
        result = cursor.fetchone()

        if result:
            print(f"✓ Table 'command_relation_guidance' created successfully")

            # Check schema version
            cursor.execute("SELECT version, description FROM schema_version ORDER BY version DESC LIMIT 1;")
            version = cursor.fetchone()
            if version:
                print(f"✓ Schema version: {version[0]} - {version[1]}")
        else:
            print("✗ Warning: Table not found after migration")

        conn.close()

    except Exception as e:
        print(f"✗ Migration failed: {e}")
        sys.exit(1)


def main():
    """Apply all pending migrations."""
    migrations_dir = Path(__file__).parent.parent / "migrations"

    if not migrations_dir.exists():
        print(f"✗ Migrations directory not found: {migrations_dir}")
        sys.exit(1)

    # Get all migration files
    migration_files = sorted(migrations_dir.glob("*.sql"))

    if not migration_files:
        print("No migrations found.")
        return

    print(f"Found {len(migration_files)} migration(s):")
    for mig_file in migration_files:
        print(f"  - {mig_file.name}")

    print("\nApplying migrations...\n")

    for mig_file in migration_files:
        apply_migration(mig_file)

    print("\n✓ All migrations applied successfully!")


if __name__ == "__main__":
    main()
