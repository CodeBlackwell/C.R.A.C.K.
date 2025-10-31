#!/usr/bin/env python3
"""
SQLite to PostgreSQL Data Migration Script

Migrates all data from ~/.crack/crack.db (SQLite) to PostgreSQL crack database.
Handles foreign key dependencies correctly.

Usage:
    python3 db/migrate_data.py                    # Full migration
    python3 db/migrate_data.py --validate-only    # Validate without migrating
    python3 db/migrate_data.py --skip-confirm     # Skip confirmation prompt
"""

import sqlite3
import psycopg2
import psycopg2.extras
import sys
import argparse
from pathlib import Path
from db.config import get_db_config

class DataMigrator:
    """Migrates data from SQLite to PostgreSQL"""

    # Migration order (respects foreign key dependencies)
    MIGRATION_ORDER = [
        # Independent tables (no FKs)
        'schema_version',
        'tags',
        'variables',
        'services',
        'attack_chains',

        # Commands and related
        'commands',
        'command_flags',
        'command_vars',
        'command_tags',
        'command_indicators',
        'command_relations',

        # Service relationships
        'service_aliases',
        'service_ports',
        'service_commands',

        # Service plugins
        'service_plugins',
        'plugin_task_templates',
        'plugin_task_variables',
        'plugin_output_patterns',

        # Attack chains
        'chain_steps',
        'chain_prerequisites',
        'chain_references',
        'step_dependencies',

        # Findings
        'finding_types',
        'finding_patterns',
        'finding_to_task',

        # Sessions (if any exist)
        'target_sessions',
        'session_ports',
        'session_findings',
        'session_credentials',
        'command_history',
    ]

    def __init__(self, sqlite_path: str = None, pg_config: dict = None):
        """Initialize migrator with database connections"""
        if sqlite_path is None:
            sqlite_path = str(Path.home() / '.crack' / 'crack.db')

        if pg_config is None:
            pg_config = get_db_config()

        print(f"📂 SQLite source: {sqlite_path}")
        print(f"🐘 PostgreSQL target: {pg_config['database']}@{pg_config['host']}")

        self.sqlite_path = sqlite_path
        self.pg_config = pg_config

        # Connections
        self.sqlite_conn = sqlite3.connect(sqlite_path)
        self.sqlite_conn.row_factory = sqlite3.Row

        self.pg_conn = psycopg2.connect(**pg_config)
        self.pg_conn.autocommit = False  # Manual transaction control

        # Statistics
        self.stats = {table: 0 for table in self.MIGRATION_ORDER}
        self.errors = []

    def get_table_row_count(self, conn, table: str) -> int:
        """Get row count for a table"""
        if isinstance(conn, sqlite3.Connection):
            cursor = conn.cursor()
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            return cursor.fetchone()[0]
        else:  # psycopg2
            cursor = conn.cursor()
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            return cursor.fetchone()[0]

    # Boolean columns that need conversion from 0/1 to False/True
    BOOLEAN_COLUMNS = {
        'command_flags': ['is_required'],
        'command_vars': ['is_required'],
        'plugin_task_templates': ['requires_auth'],
        'plugin_task_variables': ['required'],
    }

    def migrate_table(self, table_name: str):
        """Migrate a single table from SQLite to PostgreSQL"""
        print(f"\n📊 Migrating table: {table_name}")

        sqlite_cursor = self.sqlite_conn.cursor()
        pg_cursor = self.pg_conn.cursor()

        try:
            # Get row count
            sqlite_cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
            row_count = sqlite_cursor.fetchone()[0]

            if row_count == 0:
                print(f"  ⚠️  Table {table_name} is empty, skipping")
                return

            print(f"  📦 {row_count} rows to migrate")

            # Get column names and types
            sqlite_cursor.execute(f"PRAGMA table_info({table_name})")
            table_info = sqlite_cursor.fetchall()
            columns = [col[1] for col in table_info]

            # Exclude auto-generated columns (id, created_at, updated_at for some tables)
            exclude_cols = ['created_at', 'updated_at']
            insert_cols = [c for c in columns if c not in exclude_cols or table_name == 'schema_version']

            # Get boolean columns for this table
            boolean_cols = self.BOOLEAN_COLUMNS.get(table_name, [])

            # Fetch all rows
            sqlite_cursor.execute(f"SELECT {', '.join(insert_cols)} FROM {table_name}")
            rows = sqlite_cursor.fetchall()

            # Insert rows (dependency order ensures foreign keys are satisfied)
            placeholders = ', '.join(['%s'] * len(insert_cols))
            insert_sql = f"INSERT INTO {table_name} ({', '.join(insert_cols)}) VALUES ({placeholders})"

            migrated = 0
            for row in rows:
                try:
                    # Convert row to list (handle sqlite3.Row object)
                    row_data = list(row)

                    # Convert boolean columns (SQLite 0/1 → PostgreSQL FALSE/TRUE)
                    for i, col_name in enumerate(insert_cols):
                        if col_name in boolean_cols:
                            if row_data[i] in (0, 1):
                                row_data[i] = bool(row_data[i])

                    pg_cursor.execute(insert_sql, row_data)
                    migrated += 1
                except psycopg2.IntegrityError as e:
                    # Duplicate or constraint violation - log but continue
                    print(f"    ⚠️  Skipped row due to constraint: {str(e)[:100]}")
                    self.pg_conn.rollback()
                    # Need new cursor after rollback
                    pg_cursor = self.pg_conn.cursor()
                    continue
                except Exception as e:
                    print(f"    ❌ Error inserting row: {str(e)[:100]}")
                    self.pg_conn.rollback()
                    pg_cursor = self.pg_conn.cursor()
                    continue

            # Commit
            self.pg_conn.commit()

            # Update stats
            self.stats[table_name] = migrated
            print(f"  ✓ Migrated {migrated}/{row_count} rows")

        except Exception as e:
            error_msg = f"Error migrating {table_name}: {e}"
            print(f"  ❌ {error_msg}")
            self.errors.append(error_msg)
            self.pg_conn.rollback()

    def migrate_all(self):
        """Migrate all tables in dependency order"""
        print("\n" + "="*60)
        print("🚀 Starting data migration...")
        print("="*60)

        for table in self.MIGRATION_ORDER:
            try:
                self.migrate_table(table)
            except Exception as e:
                print(f"❌ Failed to migrate {table}: {e}")
                self.errors.append(f"{table}: {e}")
                continue

        print("\n" + "="*60)
        print("📊 MIGRATION COMPLETE")
        print("="*60)

        # Print statistics
        total_migrated = sum(self.stats.values())
        print(f"\n✅ Total rows migrated: {total_migrated}")
        print(f"\n📋 Per-table breakdown:")
        for table, count in self.stats.items():
            if count > 0:
                print(f"  • {table:30} {count:5} rows")

        if self.errors:
            print(f"\n⚠️  Errors encountered: {len(self.errors)}")
            for error in self.errors[:10]:  # Show first 10
                print(f"  - {error}")
            if len(self.errors) > 10:
                print(f"  ... and {len(self.errors) - 10} more")
        else:
            print("\n✓ No errors!")

    def validate(self):
        """Validate migration by comparing row counts"""
        print("\n" + "="*60)
        print("🔍 Validating migration...")
        print("="*60)

        sqlite_cursor = self.sqlite_conn.cursor()
        pg_cursor = self.pg_conn.cursor()

        mismatches = []

        for table in self.MIGRATION_ORDER:
            try:
                # Get counts
                sqlite_cursor.execute(f"SELECT COUNT(*) FROM {table}")
                sqlite_count = sqlite_cursor.fetchone()[0]

                pg_cursor.execute(f"SELECT COUNT(*) FROM {table}")
                pg_count = pg_cursor.fetchone()[0]

                match = "✓" if sqlite_count == pg_count else "✗"
                print(f"{match} {table:30} SQLite: {sqlite_count:5}  PostgreSQL: {pg_count:5}")

                if sqlite_count != pg_count:
                    mismatches.append(f"{table}: SQLite={sqlite_count}, PG={pg_count}")

            except Exception as e:
                print(f"⚠️  {table:30} Error: {e}")

        if mismatches:
            print(f"\n❌ Validation failed: {len(mismatches)} mismatches")
            for mismatch in mismatches:
                print(f"  - {mismatch}")
            return False
        else:
            print("\n✅ Validation passed! All row counts match.")
            return True

    def close(self):
        """Close database connections"""
        self.sqlite_conn.close()
        self.pg_conn.close()


def main():
    parser = argparse.ArgumentParser(description='Migrate CRACK data from SQLite to PostgreSQL')
    parser.add_argument('--validate-only', action='store_true', help='Only validate, don\'t migrate')
    parser.add_argument('--skip-confirm', action='store_true', help='Skip confirmation prompt')
    args = parser.parse_args()

    migrator = DataMigrator()

    try:
        if args.validate_only:
            migrator.validate()
        else:
            # Confirmation prompt
            if not args.skip_confirm:
                print("\n⚠️  WARNING: This will populate PostgreSQL with data from SQLite.")
                print("   Existing PostgreSQL data will NOT be deleted (constraints may cause skips).")
                response = input("\nContinue? [y/N]: ")
                if response.lower() != 'y':
                    print("Aborted.")
                    sys.exit(0)

            # Migrate
            migrator.migrate_all()

            # Validate
            print("\n")
            migrator.validate()

    finally:
        migrator.close()

    print("\n✅ Migration script complete!\n")


if __name__ == '__main__':
    main()
