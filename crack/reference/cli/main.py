#!/usr/bin/env python3
"""
CLI interface for CRACK Reference System
"""

import argparse
import sys
import sqlite3
import logging
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
    SearchCLI,
    GraphCLI
)

logger = logging.getLogger(__name__)


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
        self.graph_cli = GraphCLI(registry=self.registry, theme=self.theme)

        self.parser = self.create_parser()

    def _initialize_registry(self):
        """Initialize registry: Neo4j → JSON fallback (minimalist)

        Auto-detection:
        1. Neo4jCommandRegistryAdapter (graph database - best for complex queries)
        2. HybridCommandRegistry (JSON - always available fallback)

        Returns:
            Registry instance (Neo4jCommandRegistryAdapter or HybridCommandRegistry)
        """
        # Try Neo4j first
        try:
            from crack.reference.core import Neo4jCommandRegistryAdapter

            adapter = Neo4jCommandRegistryAdapter(
                config_manager=self.config,
                theme=self.theme
            )

            # Test connection
            if adapter.health_check():
                stats = adapter.get_stats()
                cmd_count = stats.get('total_commands', 0)
                print(self.theme.success(f"✓ Using Neo4j backend ({cmd_count} commands)"))
                return adapter
            else:
                logger.debug("Neo4j health check failed")
                print(self.theme.hint("ℹ Neo4j unhealthy, using JSON fallback"))

        except Exception as e:
            logger.debug(f"Neo4j unavailable: {e}")
            print(self.theme.hint("ℹ Neo4j unavailable, using JSON fallback"))

        # Fallback: JSON
        print(self.theme.hint("✓ Using JSON backend"))
        # Use crack root as base path since commands live in data/commands/
        from pathlib import Path
        crack_root = Path(__file__).parent.parent.parent
        return HybridCommandRegistry(base_path=crack_root, config_manager=self.config, theme=self.theme)

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

        # Backend status
        parser.add_argument(
            '--status',
            action='store_true',
            help='Show backend status and statistics'
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

        # Graph pattern operations (Neo4j)
        parser.add_argument(
            '--graph',
            choices=[
                'multi-hop', 'shortest-path', 'prereqs', 'parallel',
                'service-rec', 'tag-hierarchy', 'success-corr',
                'coverage-gaps', 'circular-deps', 'var-usage'
            ],
            help='Execute Neo4j graph pattern (requires Neo4j backend)'
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
                          '--tags', '-t', '--exclude-tags', '--format', '-f', '--config', '--chains', '--graph']:
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
        if args.status:
            return self.show_status()

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

        # Handle graph pattern flag
        if hasattr(args, 'graph') and args.graph:
            return self.graph_cli.execute_pattern(args.graph, args)

        # Handle chains flag
        if hasattr(args, 'chains') and args.chains is not None:
            # --chains flag present
            query = None
            if isinstance(args.chains, str):
                # --chains QUERY syntax (e.g., --chains sqli)
                # Also append any additional positional args (for "lateral 3" syntax)
                query_parts = [args.chains]
                if args.args:
                    query_parts.extend(args.args)
                query = ' '.join(query_parts)
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
            # Skip auto-generated stubs - prefer full search results
            if cmd and 'auto-generated' not in cmd.tags:
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

    def show_status(self) -> int:
        """Show backend status and statistics (minimalist)

        Returns:
            Exit code (0 for success)
        """
        from crack.reference.core import Neo4jCommandRegistryAdapter

        print(f"\n{self.theme.bold_white('CRACK Reference Backend Status')}\n")
        print("=" * 60)
        print(f"\nBackend: {type(self.registry).__name__}")
        print(f"Status: {self.theme.success('✓ Active')}")

        # Show stats if available
        if hasattr(self.registry, 'get_stats'):
            try:
                stats = self.registry.get_stats()
                if stats:
                    print(f"\nStatistics:")
                    for key, value in stats.items():
                        print(f"  {key}: {value}")
            except Exception as e:
                print(f"  (Statistics unavailable: {e})")

        # Show health for Neo4j
        if isinstance(self.registry, Neo4jCommandRegistryAdapter):
            health = self.registry.health_check()
            print(f"\nHealth: {self.theme.success('✓ Connected') if health else self.theme.error('✗ Disconnected')}")

        print("\n" + "=" * 60 + "\n")
        return 0

def main():
    """Main entry point for CLI"""
    cli = ReferenceCLI()
    cli.run()


if __name__ == '__main__':
    main()
