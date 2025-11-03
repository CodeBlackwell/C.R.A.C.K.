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
        self.print_step(1, "Create database and user (if needed)")
        self.print_step(2, "Create database schema (17 tables)")
        self.print_step(3, "Import all commands from JSON files")
        self.print_step(4, "Create command relationships")
        print()

        db_config = get_db_config()

        # Try to connect - if it fails, attempt auto-setup
        try:
            self.print_info(f"Testing connection to PostgreSQL...")
            test_conn = psycopg2.connect(**db_config)
            test_conn.close()
            self.print_success("Connection successful")
        except psycopg2.OperationalError as e:
            error_msg = str(e).lower()

            # Check if it's authentication or database doesn't exist
            if 'password authentication failed' in error_msg or 'does not exist' in error_msg:
                print(f"  {self.colors.YELLOW}Database or user not found - attempting automatic setup...{self.colors.RESET}")

                # Try to create database and user automatically
                if not self._auto_setup_database(db_config):
                    self.print_error("Automatic setup failed")
                    print(f"\n{self.colors.YELLOW}Manual setup required:{self.colors.RESET}")
                    print(f"{self.colors.DIM}Run these commands:{self.colors.RESET}")
                    print(f"""
sudo -u postgres psql << 'EOF'
CREATE DATABASE {db_config['dbname']};
CREATE USER {db_config['user']} WITH PASSWORD '{db_config['password']}';
GRANT ALL PRIVILEGES ON DATABASE {db_config['dbname']} TO {db_config['user']};
ALTER DATABASE {db_config['dbname']} OWNER TO {db_config['user']};
\\c {db_config['dbname']}
GRANT ALL ON SCHEMA public TO {db_config['user']};
EOF
""")
                    return 1

                # Test connection again after auto-setup
                try:
                    test_conn = psycopg2.connect(**db_config)
                    test_conn.close()
                    self.print_success("Connection successful after auto-setup")
                except Exception as e:
                    self.print_error(f"Still cannot connect: {e}")
                    return 1
            else:
                self.print_error(f"PostgreSQL connection failed: {e}")
                print(f"\n{self.colors.YELLOW}Troubleshooting:{self.colors.RESET}")
                self.print_step(1, "Check if PostgreSQL is running: sudo systemctl status postgresql")
                self.print_step(2, "Start PostgreSQL: sudo systemctl start postgresql")
                return 1

        # Now proceed with migration
        try:
            print()
            migration = CRACKMigration(db_config)

            # Create schema
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

        except Exception as e:
            self.print_error(f"Setup failed: {e}")
            return 1

    def _auto_setup_database(self, db_config: dict) -> bool:
        """
        Automatically create database and user using postgres admin account

        Returns:
            True if successful, False otherwise
        """
        import subprocess

        self.print_info("Attempting automatic database setup...")

        # Execute commands as bash script for better reliability
        setup_script = f"""
# Create user if doesn't exist
sudo -u postgres psql -tc "SELECT 1 FROM pg_user WHERE usename = '{db_config['user']}'" | grep -q 1 || \\
sudo -u postgres psql -c "CREATE USER {db_config['user']} WITH PASSWORD '{db_config['password']}';"

# Create database if doesn't exist
sudo -u postgres psql -tc "SELECT 1 FROM pg_database WHERE datname = '{db_config['dbname']}'" | grep -q 1 || \\
sudo -u postgres psql -c "CREATE DATABASE {db_config['dbname']};"

# Grant privileges
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE {db_config['dbname']} TO {db_config['user']};"
sudo -u postgres psql -c "ALTER DATABASE {db_config['dbname']} OWNER TO {db_config['user']};"

# Grant schema permissions
sudo -u postgres psql -d {db_config['dbname']} -c "GRANT ALL ON SCHEMA public TO {db_config['user']};"
sudo -u postgres psql -d {db_config['dbname']} -c "GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO {db_config['user']};"
sudo -u postgres psql -d {db_config['dbname']} -c "GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO {db_config['user']};"
"""

        try:
            # Execute setup script via bash
            result = subprocess.run(
                ['bash', '-c', setup_script],
                capture_output=True,
                text=True,
                timeout=30
            )

            if result.returncode == 0:
                self.print_success(f"Created database '{db_config['dbname']}'")
                self.print_success(f"Created user '{db_config['user']}'")
                self.print_success("Granted permissions")
                return True
            else:
                self.print_warning(f"Setup had issues: {result.stderr}")
                return False

        except subprocess.TimeoutExpired:
            self.print_error("Database setup timed out")
            return False
        except FileNotFoundError:
            self.print_error("PostgreSQL 'psql' command not found - is PostgreSQL installed?")
            return False
        except Exception as e:
            self.print_error(f"Automatic setup failed: {e}")
            return False

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
