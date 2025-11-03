#!/usr/bin/env python3
"""
CLI interface for CRACK Reference System
"""

import argparse
import sys
import sqlite3
from pathlib import Path
from rich.console import Console

from crack.reference.core import (
    HybridCommandRegistry,
    PlaceholderEngine,
    CommandValidator,
    ConfigManager,
    ReferenceTheme
)
from crack.reference.cli import (
    ChainsCLI,
    DisplayCLI,
    InteractiveCLI,
    ConfigCLI,
    SearchCLI
)


class ReferenceCLI:
    """Command-line interface for reference system (orchestrator)"""

    def __init__(self):
        self.console = Console()  # Used only for ASCII banner
        self.theme = ReferenceTheme()
        self.config = ConfigManager()
        self.registry = self._initialize_registry()
        self.placeholder_engine = PlaceholderEngine(config_manager=self.config)
        self.validator = CommandValidator()

        # Initialize modular handlers
        self.chains_cli = ChainsCLI(theme=self.theme)
        self.display_cli = DisplayCLI(
            registry=self.registry,
            placeholder_engine=self.placeholder_engine,
            theme=self.theme
        )
        self.interactive_cli = InteractiveCLI(registry=self.registry, theme=self.theme)
        self.config_cli = ConfigCLI(config_manager=self.config, theme=self.theme)
        self.search_cli = SearchCLI(registry=self.registry, theme=self.theme)

        self.parser = self.create_parser()

    def _initialize_registry(self):
        """Initialize registry with auto-detect fallback (SQL → JSON)

        Tries SQL backend first for performance. Falls back to JSON if:
        - Database doesn't exist
        - Database is corrupted/locked
        - Database is empty
        - Import errors occur

        Returns:
            Registry instance (SQLCommandRegistryAdapter or HybridCommandRegistry)
        """
        # Try SQL backend first (recommended) - PostgreSQL
        try:
            from crack.reference.core.sql_adapter import SQLCommandRegistryAdapter
            from db.config import get_db_config
            import psycopg2

            # Test PostgreSQL connection and integrity
            try:
                db_config = get_db_config()
                test_conn = psycopg2.connect(**db_config)
                cursor = test_conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM commands")
                count = cursor.fetchone()[0]
                cursor.close()
                test_conn.close()

                if count > 0:
                    # PostgreSQL database valid - use SQL adapter
                    print(self.theme.success(f"✓ Using SQL backend ({count} commands loaded)"))
                    return SQLCommandRegistryAdapter(
                        db_config=db_config,
                        config_manager=self.config,
                        theme=self.theme
                    )
                else:
                    print(self.theme.warning("⚠ SQL database empty, falling back to JSON"))
            except psycopg2.Error:
                # PostgreSQL connection failed
                print(self.theme.hint("ℹ PostgreSQL connection failed, using JSON backend"))
                print(self.theme.hint("  To enable faster SQL backend: cd crack && python3 -m db.migrate commands"))

        except ImportError as e:
            # SQL adapter not available
            print(self.theme.hint("ℹ SQL backend not available, using JSON backend"))
        except Exception as e:
            # Generic error
            error_msg = str(e).lower()
            if 'locked' in error_msg:
                print(self.theme.warning("⚠ SQL database locked by another process"))
            elif 'no such table' in error_msg or 'no such column' in error_msg:
                print(self.theme.warning("⚠ SQL database schema outdated"))
                print(self.theme.hint("  Run: python3 -m db.migrate commands"))
            elif 'unable to open' in error_msg:
                print(self.theme.warning("⚠ Cannot read SQL database (check permissions)"))
            else:
                print(self.theme.warning(f"⚠ SQL database error: {e}"))
            print(self.theme.hint("ℹ Falling back to JSON backend"))
        except Exception as e:
            # Unexpected error - fallback gracefully
            print(self.theme.warning(f"⚠ Unexpected SQL error: {e}"))
            print(self.theme.hint("ℹ Falling back to JSON backend"))

        # Fallback: Use JSON-based HybridCommandRegistry
        print(self.theme.hint("✓ Using JSON backend"))
        return HybridCommandRegistry(config_manager=self.config, theme=self.theme)

    def _print_banner(self):
        """Print CRACK Reference banner"""
        print(f"\n{self.theme.primary('═' * 60)}")
        print(f"{self.theme.command_name('CRACK Reference System')} - Command Lookup & Management")
        print(f"{self.theme.primary('═' * 60)}\n")

    def create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser"""
        parser = argparse.ArgumentParser(
            prog='crack-ref',
            description='CRACK Reference System - Command lookup and management',
            formatter_class=argparse.RawDescriptionHelpFormatter
        )

        # Category filter (for explicit flag usage)
        parser.add_argument(
            '-c', '--category',
            choices=['recon', 'web', 'exploitation', 'post-exploit', 'enumeration', 'pivoting', 'file-transfer', 'custom'],
            help='Filter by category'
        )

        # Subcategory filter
        parser.add_argument(
            '-s', '--subcategory',
            help='Filter by subcategory (requires --category)'
        )

        # Tag filters
        parser.add_argument(
            '-t', '--tags',
            nargs='+',
            help='Filter by tags (space-separated): --tags ENUM LINUX'
        )

        parser.add_argument(
            '--exclude-tags',
            nargs='+',
            help='Exclude commands with tags (space-separated)'
        )

        # Output options
        parser.add_argument(
            '-f', '--format',
            choices=['text', 'json', 'markdown'],
            default='text',
            help='Output format'
        )

        parser.add_argument(
            '-v', '--verbose',
            action='store_true',
            help='Show detailed command information'
        )

        # Interactive options
        parser.add_argument(
            '-i', '--interactive',
            action='store_true',
            help='Interactive mode - fill placeholders and offer to execute'
        )

        # Special commands
        parser.add_argument(
            '--quick-wins',
            action='store_true',
            help='Show quick win commands'
        )

        parser.add_argument(
            '--oscp-high',
            action='store_true',
            help='Show OSCP high-relevance commands'
        )

        parser.add_argument(
            '--tree',
            action='store_true',
            help='Show command tree structure'
        )

        # Management commands
        parser.add_argument(
            '--validate',
            action='store_true',
            help='Validate all command files'
        )

        parser.add_argument(
            '--stats',
            action='store_true',
            help='Show registry statistics'
        )

        parser.add_argument(
            '--list-tags',
            action='store_true',
            help='List all available tags'
        )

        # Attack chains filter
        parser.add_argument(
            '--chains',
            nargs='?',
            const=True,
            metavar='QUERY',
            help='List/search/show attack chains: --chains (list all), --chains QUERY (search/show), --chains CHAIN_ID -i (interactive)'
        )

        parser.add_argument(
            '--oscp-relevant',
            action='store_true',
            help='Filter OSCP-relevant items (works with --chain)'
        )

        parser.add_argument(
            '--resume',
            action='store_true',
            help='Resume chain from saved session (use with --chains -i)'
        )

        # Config management
        parser.add_argument(
            '--config',
            choices=['list', 'edit', 'auto'],
            help='Config management: list variables, edit config file, or auto-detect'
        )

        parser.add_argument(
            '--set',
            nargs=2,
            metavar=('VAR', 'VALUE'),
            help='Set a config variable (e.g., --set LHOST 10.10.14.5)'
        )

        parser.add_argument(
            '--get',
            metavar='VAR',
            help='Get a config variable value'
        )

        parser.add_argument(
            '--clear-config',
            action='store_true',
            help='Clear all config variables'
        )

        parser.add_argument(
            '--no-banner',
            action='store_true',
            help='Suppress banner output'
        )

        parser.add_argument(
            '--banner',
            action='store_true',
            help='Show banner output (overrides --no-banner)'
        )

        # Positional arguments
        parser.add_argument(
            'args',
            nargs='*',
            help='[category] [subcategory] or search query'
        )

        return parser

    def run(self, args=None):
        """Main entry point - routes to appropriate handler"""
        # Parse arguments
        if args is None:
            args = sys.argv[1:]

        # Find all positional args (non-flags)
        flags = []
        positional = []
        i = 0
        while i < len(args):
            arg = args[i]
            if arg.startswith('-'):
                flags.append(arg)
                # Check if this flag takes a value
                if arg in ['--set', '--get', '--category', '-c', '--subcategory', '-s',
                          '--tags', '-t', '--exclude-tags', '--format', '-f', '--config', '--chains']:
                    # These flags take values - include next arg
                    i += 1
                    if i < len(args):
                        if arg == '--set':
                            # --set takes TWO values
                            flags.append(args[i])
                            i += 1
                            if i < len(args):
                                flags.append(args[i])
                        elif arg in ['--tags', '-t', '--exclude-tags']:
                            # These take multiple values - consume until next flag
                            while i < len(args) and not args[i].startswith('-'):
                                flags.append(args[i])
                                i += 1
                            i -= 1  # Back up one since loop will increment
                        else:
                            flags.append(args[i])
            else:
                # Positional argument
                positional.append(arg)
            i += 1

        # Reconstruct args: flags only (positional will go into 'args' field)
        reconstructed_args = flags

        # Parse with argparse
        parsed = self.parser.parse_args(reconstructed_args)

        # Manually set positional args
        parsed.args = positional

        args = parsed

        # Show banner unless suppressed (--banner overrides --no-banner)
        if args.banner or not args.no_banner:
            self._print_banner()

        # Handle config commands
        if args.config:
            return self.config_cli.handle_config(args.config)

        if args.set:
            return self.config_cli.set_config_var(args.set[0], args.set[1])

        if args.get:
            return self.config_cli.get_config_var(args.get)

        if args.clear_config:
            return self.config_cli.clear_config()

        # Handle special actions
        if args.stats:
            return self.search_cli.show_stats()

        if args.validate:
            return self.validate_commands()

        if args.list_tags:
            return self.search_cli.list_tags()

        if args.quick_wins:
            return self.search_cli.show_quick_wins(args.format, args.verbose)

        if args.oscp_high:
            return self.search_cli.show_oscp_high(args.format, args.verbose)

        if args.tree:
            return self.display_cli.show_command_tree(self.registry)

        # Handle chains flag
        if hasattr(args, 'chains') and args.chains is not None:
            # --chains flag present
            query = None
            if isinstance(args.chains, str):
                # --chains QUERY syntax (e.g., --chains sqli)
                query = args.chains
            elif args.args:
                # --chains with positional args: crack reference --chains sqli
                query = ' '.join(args.args)
            # else: --chains with no args (list all chains)

            # Check if interactive mode requested
            if args.interactive:
                # Interactive chain execution
                if not query:
                    print(self.theme.error("Specify chain ID for interactive mode: crack reference --chains CHAIN_ID -i"))
                    return 1

                # Ensure chains are loaded
                self.chains_cli._ensure_loaded()

                # Try to get chain by ID
                chain = self.chains_cli.registry.get_chain(query)
                if not chain:
                    print(self.theme.error(f"Chain not found: {query}"))
                    print(self.theme.hint("Use 'crack reference --chains' to list available chains"))
                    return 1

                # Launch interactive execution
                return self.chains_cli.execute_interactive(
                    chain_id=chain['id'],
                    target=None,  # Will prompt
                    resume=args.resume if hasattr(args, 'resume') else False
                )
            else:
                # Standard list/show behavior
                return self.chains_cli.list_or_show(
                    query=query,
                    format=args.format,
                    verbose=args.verbose
                )

        # Handle interactive mode - if -i with no search criteria, open REPL
        if args.interactive and not (args.args or args.category or args.tags):
            return self.interactive_cli.interactive_mode(search_handler=self.search_cli)

        # Parse positional args to determine category/subcategory/query
        category = args.category
        subcategory = args.subcategory
        query = None
        selection_number = None

        # Check if --tags has a number at the end (argparse captures it as part of tags)
        if args.tags and args.tags[-1].isdigit() and len(args.tags[-1]) <= 3:
            selection_number = args.tags[-1]
            args.tags = args.tags[:-1]  # Remove selection from tags

        if args.args:
            # Check if last arg is a digit (selection number when used with --tag or category)
            if args.args[-1].isdigit() and len(args.args[-1]) <= 3:  # Reasonable selection number
                selection_number = args.args[-1]
                args.args = args.args[:-1]  # Remove selection from args

            # Check if first arg is a valid category
            if args.args and args.args[0] in self.registry.categories.keys():
                category = args.args[0]

                # Check if second arg is a valid subcategory for this category
                if len(args.args) > 1:
                    subcats = self.registry.get_subcategories(category)
                    if args.args[1] in subcats:
                        subcategory = args.args[1]
                    else:
                        # Not a subcategory, treat as search query
                        query = ' '.join(args.args[1:])
            elif args.args:
                # First arg is not a category, treat all as search query
                query = ' '.join(args.args)

        # If selection number provided, append to query for existing logic to handle
        if selection_number:
            if query:
                query = f"{query} {selection_number}"
            elif args.tags:
                # For tag filtering with number, pass as part of query
                query = selection_number

        # Check if query is a direct command ID before searching
        if query and not category and not args.tags:
            # Try direct command ID lookup first
            cmd = self.registry.get_command(query)
            if cmd:
                if args.interactive:
                    # Enter fill mode
                    return self.interactive_cli.fill_command_with_execute(cmd.id)
                else:
                    # Show full details (colorized, verbose)
                    return self.display_cli.show_command_details(cmd)

        # Search/filter commands
        if query or category or args.tags:
            return self.search_cli.search_commands(
                query=query,
                category=category,
                subcategory=subcategory,
                tags=args.tags,
                exclude_tags=args.exclude_tags,
                format=args.format,
                verbose=args.verbose,
                interactive=args.interactive
            )

        # No arguments - show help
        self.parser.print_help()

    def validate_commands(self) -> int:
        """Validate all command files

        Returns:
            Exit code (0 for success, 1 for errors)
        """
        data_path = Path(__file__).parent / 'data' / 'commands'
        results = self.validator.validate_directory(data_path)

        if not results:
            print("✅ All command files are valid!")
            return 0
        else:
            print("⚠️  Validation issues found:")
            for file, errors in results.items():
                print(f"\n{file}:")
                for error in errors:
                    print(f"  - {error}")
            return 1

def main():
    """Main entry point for CLI"""
    cli = ReferenceCLI()
    cli.run()


if __name__ == '__main__':
    main()
