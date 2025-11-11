"""
CLI search handler for command filtering and lookup
"""

from typing import List, Optional

from reference.cli.base import BaseCLIHandler
from reference.core.registry import Command


class SearchCLI(BaseCLIHandler):
    """Handler for command search and filtering operations"""

    def __init__(self, registry=None, theme=None):
        """Initialize search handler

        Args:
            registry: HybridCommandRegistry instance
            theme: ReferenceTheme instance
        """
        super().__init__(theme)
        self.registry = registry

    def search_commands(self, query=None, category=None, subcategory=None, tags=None,
                       exclude_tags=None, format='text', verbose=False, interactive=False):
        """Search and display commands

        Args:
            query: Search query string
            category: Category filter
            subcategory: Subcategory filter
            tags: List of tags to filter by
            exclude_tags: List of tags to exclude
            format: Output format (text, json, markdown)
            verbose: Show detailed information
            interactive: Enable interactive mode

        Returns:
            Exit code or None
        """
        commands = []
        selection = None

        # Check if query ends with a number (for numbered selection)
        if query and query.split()[-1].isdigit():
            parts = query.rsplit(None, 1)
            actual_query = parts[0] if len(parts) > 1 else None
            selection = int(parts[-1]) - 1  # Convert to 0-indexed
            query = actual_query  # This may be None if query was ONLY a number

        if category:
            commands = self.registry.filter_by_category(category, subcategory)

            # If only category provided and subcategories exist, show them
            if not subcategory and not query and selection is None and not interactive:
                subcats = self.registry.get_subcategories(category)
                if subcats and not commands:
                    # Category has subcategories but no root commands
                    print(f"\n{category.upper()} has the following subcategories:")
                    for subcat in subcats:
                        count = len(self.registry.filter_by_category(category, subcat))
                        print(f"  - {subcat}: {count} commands")
                    print(f"\nUsage: crack reference {category} [subcategory]")
                    return
                elif subcats:
                    # Show commands but also mention subcategories
                    print(f"\nShowing commands in {category.upper()}")
                    print(f"Subcategories available: {', '.join(subcats)}\n")

        elif tags:
            commands = self.registry.filter_by_tags(tags, exclude_tags)
        elif query:
            commands = self.registry.search(query)
        else:
            commands = list(self.registry.commands.values())

        # Apply additional query filter if both tags and query provided
        if query and tags:
            commands = [cmd for cmd in commands if cmd.matches_search(query)]

        if not commands:
            print("No commands found matching criteria")
            return

        # If selection specified, show details and enter interactive fill
        if selection is not None:
            if 0 <= selection < len(commands):
                # Show full details + fill placeholders + offer to execute
                from .interactive import InteractiveCLI
                interactive_cli = InteractiveCLI(registry=self.registry, theme=self.theme)
                return interactive_cli.fill_command_with_execute(commands[selection].id)
            else:
                print(f"Invalid selection: {selection + 1} (only {len(commands)} command(s) found)")
                return

        # If interactive mode enabled, enter selection workflow
        if interactive and commands:
            from .interactive import InteractiveCLI
            interactive_cli = InteractiveCLI(registry=self.registry, theme=self.theme)
            return interactive_cli.interactive_select_and_fill(commands)

        # Otherwise display commands
        from .display import DisplayCLI
        display = DisplayCLI(registry=self.registry, theme=self.theme)
        display.display_commands(commands, format, verbose)

    def show_quick_wins(self, format='text', verbose=False) -> int:
        """Show quick win commands

        Args:
            format: Output format (text, json, markdown)
            verbose: Show detailed information

        Returns:
            Exit code (0 for success)
        """
        commands = self.registry.get_quick_wins()
        if commands:
            print(f"\n=== Quick Win Commands ({len(commands)}) ===")
            from .display import DisplayCLI
            display = DisplayCLI(registry=self.registry, theme=self.theme)
            display.display_commands(commands, format, verbose)
        else:
            print("No quick win commands found")
        return 0

    def show_oscp_high(self, format='text', verbose=False) -> int:
        """Show OSCP high-relevance commands

        Args:
            format: Output format (text, json, markdown)
            verbose: Show detailed information

        Returns:
            Exit code (0 for success)
        """
        commands = self.registry.get_oscp_high()
        if commands:
            print(f"\n=== OSCP High Relevance Commands ({len(commands)}) ===")
            from .display import DisplayCLI
            display = DisplayCLI(registry=self.registry, theme=self.theme)
            display.display_commands(commands, format, verbose)
        else:
            print("No OSCP high-relevance commands found")
        return 0

    def list_tags(self) -> int:
        """List all unique tags

        Returns:
            Exit code (0 for success)
        """
        all_tags = set()
        for cmd in self.registry.commands.values():
            all_tags.update(cmd.tags)

        print("\nAvailable Tags:")
        for tag in sorted(all_tags):
            count = len([c for c in self.registry.commands.values() if tag in c.tags])
            print(f"  {tag}: {count} commands")
        return 0

    def show_stats(self) -> int:
        """Show registry statistics

        Returns:
            Exit code (0 for success)
        """
        stats = self.registry.get_stats()

        print("\n=== CRACK Reference Statistics ===")
        print(f"Total Commands: {stats['total_commands']}")

        print("\nCommands by Category:")
        for cat, count in stats['by_category'].items():
            print(f"  {cat}: {count}")

            # Show subcategories if they exist
            if cat in stats.get('by_subcategory', {}):
                for subcat, subcount in stats['by_subcategory'][cat].items():
                    print(f"    └─ {subcat}: {subcount}")

        print("\nTop Tags:")
        for tag, count in stats['top_tags']:
            print(f"  {tag}: {count}")

        print(f"\nQuick Wins: {stats['quick_wins']}")
        print(f"OSCP High Relevance: {stats['oscp_high']}")
        return 0
