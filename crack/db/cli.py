#!/usr/bin/env python3
"""
CRACK Database Management CLI

Provides colorized, user-friendly interface for database operations.
"""

import sys
import argparse
import psycopg2
from pathlib import Path
from .config import get_db_config
from .migrate import CRACKMigration


class Colors:
    """ANSI color codes for terminal output"""
    CYAN = '\033[36m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    RED = '\033[31m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


class DatabaseCLI:
    """Colorized CLI for database management"""

    def __init__(self):
        self.colors = Colors()

    def print_header(self, text: str):
        """Print colored header"""
        print(f"\n{self.colors.BOLD}{self.colors.CYAN}{'═' * 60}{self.colors.RESET}")
        print(f"{self.colors.BOLD}{self.colors.CYAN}{text}{self.colors.RESET}")
        print(f"{self.colors.BOLD}{self.colors.CYAN}{'═' * 60}{self.colors.RESET}\n")

    def print_success(self, text: str):
        """Print success message"""
        print(f"{self.colors.GREEN}✓{self.colors.RESET} {text}")

    def print_error(self, text: str):
        """Print error message"""
        print(f"{self.colors.RED}✗{self.colors.RESET} {text}")

    def print_info(self, text: str):
        """Print info message"""
        print(f"{self.colors.BLUE}ℹ{self.colors.RESET} {text}")

    def print_warning(self, text: str):
        """Print warning message"""
        print(f"{self.colors.YELLOW}⚠{self.colors.RESET} {text}")

    def print_step(self, number: int, text: str):
        """Print numbered step"""
        print(f"{self.colors.BOLD}{self.colors.MAGENTA}{number}.{self.colors.RESET} {text}")

    def status(self):
        """Check database status and display info"""
        self.print_header("Database Status")

        try:
            db_config = get_db_config()
            self.print_info(f"Attempting connection to PostgreSQL...")
            print(f"  {self.colors.DIM}Host: {db_config['host']}{self.colors.RESET}")
            print(f"  {self.colors.DIM}Database: {db_config['dbname']}{self.colors.RESET}")
            print(f"  {self.colors.DIM}User: {db_config['user']}{self.colors.RESET}")

            conn = psycopg2.connect(**db_config)
            cursor = conn.cursor()

            self.print_success("PostgreSQL connection successful")

            # Check if schema exists
            cursor.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_schema = 'public'
                    AND table_name = 'commands'
                );
            """)

            schema_exists = cursor.fetchone()[0]

            if schema_exists:
                # Get command count
                cursor.execute("SELECT COUNT(*) FROM commands")
                cmd_count = cursor.fetchone()[0]

                self.print_success(f"Database schema exists")
                self.print_success(f"Commands in database: {self.colors.BOLD}{cmd_count}{self.colors.RESET}")

                # Get additional stats
                cursor.execute("SELECT COUNT(*) FROM tags")
                tag_count = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM variables")
                var_count = cursor.fetchone()[0]

                print(f"\n{self.colors.DIM}Additional statistics:{self.colors.RESET}")
                print(f"  Tags: {tag_count}")
                print(f"  Variables: {var_count}")

                if cmd_count > 0:
                    print(f"\n{self.colors.GREEN}✓ Database is ready to use!{self.colors.RESET}")
                    print(f"{self.colors.DIM}  Try: crack reference netcat{self.colors.RESET}")
                else:
                    self.print_warning("Database is empty - run 'crack db setup' to import commands")
            else:
                self.print_warning("Database schema not created")
                print(f"{self.colors.DIM}  Run: crack db setup{self.colors.RESET}")

            cursor.close()
            conn.close()

        except psycopg2.OperationalError as e:
            self.print_error(f"Cannot connect to PostgreSQL")
            print(f"  {self.colors.DIM}{str(e)}{self.colors.RESET}")
            print(f"\n{self.colors.YELLOW}Troubleshooting:{self.colors.RESET}")
            self.print_step(1, "Check if PostgreSQL is installed: sudo systemctl status postgresql")
            self.print_step(2, "Start PostgreSQL: sudo systemctl start postgresql")
            self.print_step(3, "Create database: sudo -u postgres createdb crack")
            return 1

        except Exception as e:
            self.print_error(f"Unexpected error: {e}")
            return 1

        return 0

    def setup(self):
        """Complete database setup (schema + import commands)"""
        self.print_header("Database Setup")

        print(f"{self.colors.DIM}This will:{self.colors.RESET}")
        self.print_step(1, "Create database schema (17 tables)")
        self.print_step(2, "Import all commands from JSON files")
        self.print_step(3, "Create command relationships")
        print()

        try:
            db_config = get_db_config()
            self.print_info(f"Connecting to PostgreSQL...")

            migration = CRACKMigration(db_config)

            # Create schema
            print()
            migration.create_schema()

            # Import commands
            print()
            self.print_info("Importing commands from JSON files...")
            migration.migrate_commands()

            # Process relationships
            print()
            migration.process_relations()

            # Show statistics
            print()
            self._print_colorized_stats(migration.stats)

            migration.close()

            print(f"\n{self.colors.GREEN}{self.colors.BOLD}✓ Setup complete!{self.colors.RESET}")
            print(f"{self.colors.DIM}  Try: crack reference netcat{self.colors.RESET}")

            return 0

        except psycopg2.OperationalError as e:
            self.print_error(f"Cannot connect to PostgreSQL")
            print(f"  {self.colors.DIM}{str(e)}{self.colors.RESET}")
            print(f"\n{self.colors.YELLOW}Quick fix:{self.colors.RESET}")
            self.print_step(1, "Create database: sudo -u postgres createdb crack")
            self.print_step(2, "Re-run: crack db setup")
            return 1

        except Exception as e:
            self.print_error(f"Setup failed: {e}")
            return 1

    def reset(self):
        """Reset database (drop and recreate)"""
        self.print_header("Database Reset")

        self.print_warning("This will DELETE all data in the database!")
        confirm = input(f"{self.colors.YELLOW}Type 'yes' to confirm: {self.colors.RESET}")

        if confirm.lower() != 'yes':
            print(f"{self.colors.DIM}Cancelled.{self.colors.RESET}")
            return 0

        try:
            db_config = get_db_config()

            # Connect to postgres database (not crack)
            admin_config = db_config.copy()
            admin_config['dbname'] = 'postgres'

            self.print_info("Connecting as admin...")
            conn = psycopg2.connect(**admin_config)
            conn.set_isolation_level(0)  # Autocommit mode
            cursor = conn.cursor()

            # Drop database
            self.print_info(f"Dropping database '{db_config['dbname']}'...")
            try:
                cursor.execute(f"DROP DATABASE IF EXISTS {db_config['dbname']}")
                self.print_success("Database dropped")
            except Exception as e:
                self.print_warning(f"Could not drop database: {e}")

            # Recreate database
            self.print_info(f"Creating database '{db_config['dbname']}'...")
            cursor.execute(f"CREATE DATABASE {db_config['dbname']}")
            self.print_success("Database created")

            cursor.close()
            conn.close()

            # Run setup
            print()
            return self.setup()

        except Exception as e:
            self.print_error(f"Reset failed: {e}")
            return 1

    def update(self):
        """Update commands from JSON (re-import)"""
        self.print_header("Update Commands")

        self.print_info("Re-importing commands from JSON files...")
        print(f"{self.colors.DIM}  This will update existing commands and add new ones{self.colors.RESET}")
        print()

        try:
            db_config = get_db_config()
            migration = CRACKMigration(db_config)

            # Import commands (ON CONFLICT will update)
            migration.migrate_commands()
            migration.process_relations()

            print()
            self._print_colorized_stats(migration.stats)

            migration.close()

            print(f"\n{self.colors.GREEN}✓ Update complete!{self.colors.RESET}")
            return 0

        except Exception as e:
            self.print_error(f"Update failed: {e}")
            return 1

    def validate(self):
        """Validate database integrity"""
        self.print_header("Database Validation")

        try:
            db_config = get_db_config()
            migration = CRACKMigration(db_config)

            results = migration.validate()

            if results['valid']:
                print(f"\n{self.colors.GREEN}✓ Validation passed!{self.colors.RESET}")
            else:
                print(f"\n{self.colors.RED}✗ Validation failed{self.colors.RESET}")
                for error in results['errors']:
                    self.print_error(error)

            for warning in results['warnings']:
                self.print_warning(warning)

            migration.close()
            return 0 if results['valid'] else 1

        except Exception as e:
            self.print_error(f"Validation failed: {e}")
            return 1

    def _print_colorized_stats(self, stats: dict):
        """Print colorized statistics"""
        print(f"{self.colors.BOLD}{self.colors.CYAN}{'─' * 60}{self.colors.RESET}")
        print(f"{self.colors.BOLD}📊 Statistics{self.colors.RESET}")
        print(f"{self.colors.BOLD}{self.colors.CYAN}{'─' * 60}{self.colors.RESET}")

        items = [
            ("Commands", stats['commands'], self.colors.GREEN),
            ("Flags", stats['flags'], self.colors.BLUE),
            ("Variables", stats['variables'], self.colors.MAGENTA),
            ("Tags", stats['tags'], self.colors.CYAN),
            ("Relations", stats['relations'], self.colors.YELLOW),
            ("Indicators", stats['indicators'], self.colors.BLUE),
        ]

        for label, count, color in items:
            print(f"  {label:<15} {color}{count}{self.colors.RESET}")

        if stats['errors']:
            print(f"\n  {self.colors.RED}Errors:{self.colors.RESET} {len(stats['errors'])}")
            for error in stats['errors'][:3]:
                print(f"    {self.colors.DIM}- {error}{self.colors.RESET}")
            if len(stats['errors']) > 3:
                print(f"    {self.colors.DIM}... and {len(stats['errors']) - 3} more{self.colors.RESET}")

        print(f"{self.colors.BOLD}{self.colors.CYAN}{'─' * 60}{self.colors.RESET}")


def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(
        prog='crack db',
        description='Database management for CRACK Reference System',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  crack db status      Check database connection and stats
  crack db setup       Complete setup (schema + import commands)
  crack db update      Re-import commands from JSON files
  crack db reset       Drop and recreate database
  crack db validate    Validate database integrity
        """
    )

    parser.add_argument(
        'action',
        choices=['status', 'setup', 'update', 'reset', 'validate'],
        help='Database operation to perform'
    )

    args = parser.parse_args()

    cli = DatabaseCLI()

    if args.action == 'status':
        return cli.status()
    elif args.action == 'setup':
        return cli.setup()
    elif args.action == 'update':
        return cli.update()
    elif args.action == 'reset':
        return cli.reset()
    elif args.action == 'validate':
        return cli.validate()


if __name__ == '__main__':
    sys.exit(main())
