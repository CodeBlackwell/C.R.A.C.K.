#!/usr/bin/env python3
"""
CLI interface for CRACK Reference System
"""

import argparse
import sys
import json
from pathlib import Path
from typing import List, Optional
from rich.console import Console

from crack.reference.core import (
    HybridCommandRegistry,
    PlaceholderEngine,
    CommandValidator,
    MarkdownCommandParser,
    ConfigManager,
    ReferenceTheme
)


class ReferenceCLI:
    """Command-line interface for reference system"""

    def __init__(self):
        self.console = Console()  # Used only for ASCII banner
        self.theme = ReferenceTheme()
        self.config = ConfigManager()
        self.registry = HybridCommandRegistry(config_manager=self.config, theme=self.theme)
        self.placeholder_engine = PlaceholderEngine(config_manager=self.config)
        self.validator = CommandValidator()
        self.parser = self.create_parser()

    def create_parser(self) -> argparse.ArgumentParser:
        """Create argument parser"""
        parser = argparse.ArgumentParser(
            prog='crack-ref',
            description='CRACK Reference System - Command lookup and management',
            formatter_class=argparse.RawDescriptionHelpFormatter
        )

        # Positional arguments (category, subcategory, or search query)
        parser.add_argument(
            'args',
            nargs='*',
            help='[category] [subcategory] or search query'
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
            help='Interactive mode'
        )

        parser.add_argument(
            '--fill',
            metavar='COMMAND_ID',
            help='Fill placeholders for a command'
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

        return parser

    def run(self, args=None):
        """Main entry point"""
        args = self.parser.parse_args(args)

        # Handle config commands first
        if args.config:
            return self.handle_config(args.config)

        if args.set:
            return self.set_config_var(args.set[0], args.set[1])

        if args.get:
            return self.get_config_var(args.get)

        if args.clear_config:
            return self.clear_config()

        # Handle special actions
        if args.stats:
            return self.show_stats()

        if args.validate:
            return self.validate_commands()

        if args.list_tags:
            return self.list_tags()

        if args.quick_wins:
            return self.show_quick_wins(args.format, args.verbose)

        if args.oscp_high:
            return self.show_oscp_high(args.format, args.verbose)

        if args.tree:
            return self.show_command_tree()

        if args.fill:
            return self.fill_command(args.fill)

        if args.interactive:
            return self.interactive_mode()

        # Parse positional args to determine category/subcategory/query
        category = args.category
        subcategory = args.subcategory
        query = None

        if args.args:
            # Check if first arg is a valid category
            if args.args[0] in self.registry.categories.keys():
                category = args.args[0]

                # Check if second arg is a valid subcategory for this category
                if len(args.args) > 1:
                    subcats = self.registry.get_subcategories(category)
                    if args.args[1] in subcats:
                        subcategory = args.args[1]
                    else:
                        # Not a subcategory, treat as search query
                        query = ' '.join(args.args[1:])
            else:
                # First arg is not a category, treat all as search query
                query = ' '.join(args.args)

        # Search/filter commands
        if query or category or args.tags:
            return self.search_commands(
                query=query,
                category=category,
                subcategory=subcategory,
                tags=args.tags,
                exclude_tags=args.exclude_tags,
                format=args.format,
                verbose=args.verbose
            )

        # No arguments - show help
        self.parser.print_help()

    def search_commands(self, query=None, category=None, subcategory=None, tags=None,
                       exclude_tags=None, format='text', verbose=False):
        """Search and display commands"""
        commands = []
        selection = None

        # Check if query ends with a number (for numbered selection)
        if query and query.split()[-1].isdigit():
            parts = query.rsplit(None, 1)
            actual_query = parts[0] if len(parts) > 1 else None
            selection = int(parts[-1]) - 1  # Convert to 0-indexed
            query = actual_query

        if category:
            commands = self.registry.filter_by_category(category, subcategory)

            # If only category provided and subcategories exist, show them
            if not subcategory and not query and selection is None:
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

        # If selection specified, open interactive fill for that command
        if selection is not None:
            if 0 <= selection < len(commands):
                return self.fill_command(commands[selection].id)
            else:
                print(f"Invalid selection: {selection + 1} (only {len(commands)} command(s) found)")
                return

        self.display_commands(commands, format, verbose)

    def display_commands(self, commands, format='text', verbose=False):
        """Display commands in requested format"""
        if format == 'json':
            data = [cmd.to_dict() for cmd in commands]
            print(json.dumps(data, indent=2))

        elif format == 'markdown':
            for cmd in commands:
                print(f"## {cmd.name}")
                print(f"```bash\n{cmd.command}\n```")
                print(f"{cmd.description}\n")
                if verbose:
                    if cmd.tags:
                        print(f"**Tags**: {', '.join(cmd.tags)}")
                    if cmd.oscp_relevance:
                        print(f"**OSCP**: {cmd.oscp_relevance.upper()}")
                    print()

        else:  # text format
            for i, cmd in enumerate(commands, 1):
                print(f"\n{self.theme.muted(f'{i}.')} [{self.theme.primary(cmd.id)}] {self.theme.command_name(cmd.name)}")
                print(f"   {self.theme.secondary(cmd.command)}")

                if verbose:
                    print(f"   {'━' * 70}")
                    print(f"   Description: {cmd.description}")

                    # Show autofilled command
                    filled = self.placeholder_engine.substitute(cmd.command)
                    if filled != cmd.command:
                        print(f"\n   Autofilled Example:")
                        print(f"   {filled}")

                    # Prerequisites
                    if cmd.prerequisites:
                        print(f"\n   Prerequisites:")
                        for j, prereq in enumerate(cmd.prerequisites, 1):
                            # Auto-fill prerequisites too
                            prereq_filled = self.placeholder_engine.substitute(prereq)
                            print(f"     {j}. {prereq_filled}")

                    # Variables
                    if cmd.variables:
                        print(f"\n   Variables:")
                        for var in cmd.variables:
                            req_str = "(required)" if var.required else "(optional)"
                            example = f" [e.g., {var.example}]" if var.example else ""
                            print(f"     <{var.name.strip('<>')}> - {var.description}{example} {req_str}")

                    # Flag explanations
                    if cmd.flag_explanations:
                        print(f"\n   Flags:")
                        for flag, explanation in cmd.flag_explanations.items():
                            print(f"     {flag}: {explanation}")

                    # Success/Failure indicators
                    if cmd.success_indicators:
                        print(f"\n   ✓ Success Indicators:")
                        for indicator in cmd.success_indicators:
                            print(f"     • {indicator}")

                    if cmd.failure_indicators:
                        print(f"\n   ✗ Failure Indicators:")
                        for indicator in cmd.failure_indicators:
                            print(f"     • {indicator}")

                    # Troubleshooting
                    if cmd.troubleshooting:
                        print(f"\n   Troubleshooting:")
                        for error, solution in cmd.troubleshooting.items():
                            # Auto-fill troubleshooting commands
                            solution_filled = self.placeholder_engine.substitute(solution)
                            print(f"     • {error}")
                            print(f"       → {solution_filled}")

                    # Next steps
                    if cmd.next_steps:
                        print(f"\n   Next Steps:")
                        for j, step in enumerate(cmd.next_steps, 1):
                            print(f"     {j}. {step}")

                    # Alternatives (resolve IDs)
                    if cmd.alternatives:
                        print(f"\n   Alternatives:")
                        for j, alt in enumerate(cmd.alternatives, 1):
                            ref = self.registry.get_command(alt)
                            if ref:  # Command ID found
                                print(f"     {j}. [{alt}] {ref.name}")
                            else:  # Free text
                                print(f"     {j}. {alt}")

                    # Tags and OSCP relevance
                    if cmd.tags:
                        print(f"\n   Tags: {', '.join(cmd.tags)}")
                    if cmd.oscp_relevance:
                        print(f"   OSCP Relevance: {cmd.oscp_relevance.upper()}")

                    # Notes
                    if cmd.notes:
                        print(f"\n   Notes: {cmd.notes}")

    def fill_command(self, command_id: str):
        """Interactively fill command placeholders"""
        cmd = self.registry.get_command(command_id)
        if not cmd:
            # Try searching for partial match
            matches = self.registry.search(command_id)
            if matches:
                if len(matches) == 1:
                    cmd = matches[0]
                else:
                    print(f"{self.theme.warning('Multiple matches found for')} '{command_id}':")
                    for match in matches[:5]:
                        print(f"  {self.theme.hint('-')} {self.theme.primary(match.id)}: {match.name}")
                    return
            else:
                print(f"{self.theme.error('Command not found:')} {self.theme.warning(command_id)}")
                return

        filled = self.registry.interactive_fill(cmd)
        print(f"\n{self.theme.primary('Copy this command:')}")
        print(f"  {self.theme.command_name(filled)}")

    def interactive_mode(self):
        """Interactive command browser"""
        print("CRACK Reference System - Interactive Mode")
        print("Type 'help' for commands, 'quit' to exit\n")

        while True:
            try:
                user_input = input("crack-ref> ").strip()

                if user_input in ['quit', 'exit', 'q']:
                    break

                if user_input == 'help':
                    self.show_interactive_help()
                    continue

                if user_input == 'categories':
                    self.show_categories()
                    continue

                if user_input == 'tags':
                    self.list_tags()
                    continue

                if user_input.startswith('cat '):
                    category = user_input.split(' ', 1)[1]
                    self.search_commands(category=category, verbose=True)
                    continue

                if user_input.startswith('tag '):
                    tag = user_input.split(' ', 1)[1]
                    self.search_commands(tags=[tag], verbose=True)
                    continue

                if user_input.startswith('fill '):
                    cmd_id = user_input.split(' ', 1)[1]
                    self.fill_command(cmd_id)
                    continue

                # Default: search
                if user_input:
                    self.search_commands(query=user_input, verbose=False)

            except KeyboardInterrupt:
                print("\nUse 'quit' to exit")
            except EOFError:
                break

        print("\nGoodbye!")

    def show_interactive_help(self):
        """Show help for interactive mode"""
        print("""
Interactive Commands:
  <query>           - Search for commands
  cat <category>    - Show commands in category
  tag <tag>         - Show commands with tag
  fill <command>    - Fill command placeholders
  categories        - List all categories
  tags             - List all tags
  help             - Show this help
  quit             - Exit interactive mode
        """)

    def show_categories(self):
        """Show available categories"""
        print("\nAvailable Categories:")
        for cat in self.registry.categories.keys():
            count = len(self.registry.filter_by_category(cat))
            print(f"  - {cat}: {count} commands")

    def show_quick_wins(self, format='text', verbose=False):
        """Show quick win commands"""
        commands = self.registry.get_quick_wins()
        if commands:
            print(f"\n=== Quick Win Commands ({len(commands)}) ===")
            self.display_commands(commands, format, verbose)
        else:
            print("No quick win commands found")

    def show_oscp_high(self, format='text', verbose=False):
        """Show OSCP high-relevance commands"""
        commands = self.registry.get_oscp_high()
        if commands:
            print(f"\n=== OSCP High Relevance Commands ({len(commands)}) ===")
            self.display_commands(commands, format, verbose)
        else:
            print("No OSCP high-relevance commands found")

    def list_tags(self):
        """List all unique tags"""
        all_tags = set()
        for cmd in self.registry.commands.values():
            all_tags.update(cmd.tags)

        print("\nAvailable Tags:")
        for tag in sorted(all_tags):
            count = len([c for c in self.registry.commands.values() if tag in c.tags])
            print(f"  {tag}: {count} commands")

    def show_stats(self):
        """Show registry statistics"""
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

    def validate_commands(self):
        """Validate all command files"""
        data_path = Path(__file__).parent / 'data' / 'commands'
        results = self.validator.validate_directory(data_path)

        if not results:
            print("✅ All command files are valid!")
        else:
            print("⚠️  Validation issues found:")
            for file, errors in results.items():
                print(f"\n{file}:")
                for error in errors:
                    print(f"  - {error}")

    def handle_config(self, action: str):
        """Handle config actions"""
        if action == 'list':
            self.list_config()
        elif action == 'edit':
            self.edit_config()
        elif action == 'auto':
            self.auto_config()

    def list_config(self):
        """List all config variables"""
        variables = self.config.list_variables()

        print("\n=== CRACK Reference Configuration ===")
        print(f"Config file: {self.config.config_path}\n")

        if not variables:
            print("No variables configured")
            return

        print("Current Variables:")
        for name, var_data in variables.items():
            if isinstance(var_data, dict):
                value = var_data.get('value', '')
                source = var_data.get('source', 'manual')
                description = var_data.get('description', '')

                # Format output
                if value:
                    print(f"  {name:15} = {value:20} [{source}]")
                    if description:
                        print(f"  {'':15}   {description}")
                else:
                    print(f"  {name:15} = {'(not set)':20} [{source}]")
                    if description:
                        print(f"  {'':15}   {description}")
            else:
                print(f"  {name:15} = {var_data}")

        print("\nUse --set VAR VALUE to set a variable")
        print("Use --config edit to open in editor")

    def set_config_var(self, var_name: str, value: str):
        """Set a config variable"""
        # Auto-detect special values
        if value.lower() == 'auto':
            if var_name.upper() == 'LHOST':
                detected = self.config.auto_detect_ip()
                if detected:
                    value = detected
                    print(f"Auto-detected LHOST: {value}")
                else:
                    print("Could not auto-detect IP address")
                    return
            elif var_name.upper() == 'INTERFACE':
                detected = self.config.auto_detect_interface()
                if detected:
                    value = detected
                    print(f"Auto-detected interface: {value}")
                else:
                    print("Could not auto-detect interface")
                    return

        if self.config.set_variable(var_name.upper(), value):
            print(f"✅ Set {var_name.upper()} = {value}")
            print(f"Config saved to: {self.config.config_path}")
        else:
            print(f"❌ Failed to set {var_name}")

    def get_config_var(self, var_name: str):
        """Get a config variable value"""
        value = self.config.get_variable(var_name.upper())
        if value:
            print(f"{var_name.upper()} = {value}")
        else:
            print(f"{var_name.upper()} is not set")

    def clear_config(self):
        """Clear all config variables"""
        confirm = input("Clear all config variables? (y/N): ").strip().lower()
        if confirm == 'y':
            if self.config.clear_variables():
                print("✅ All variables cleared")
            else:
                print("❌ Failed to clear variables")

    def edit_config(self):
        """Open config file in editor"""
        print(f"Opening config file: {self.config.config_path}")
        if self.config.open_editor():
            print("Config reloaded")
        else:
            print("Failed to open editor")

    def auto_config(self):
        """Auto-detect and configure variables"""
        print("Auto-detecting configuration...")
        updates = self.config.auto_configure()

        if updates:
            print("\n✅ Auto-configured:")
            for var, value in updates.items():
                print(f"  {var} = {value}")
            print(f"\nConfig saved to: {self.config.config_path}")
        else:
            print("No values auto-detected")

    def show_command_tree(self):
        """Display command tree structure"""
        print("\n" + "="*60)
        print(" "*20 + "CRACK REFERENCE TREE")
        print("="*60)

        # Organize commands by category
        categories = {}
        for cmd in self.registry.commands.values():
            if cmd.category not in categories:
                categories[cmd.category] = []
            categories[cmd.category].append(cmd)

        # Display each category
        category_names = {
            'recon': '🔍 Reconnaissance',
            'web': '🌐 Web Testing',
            'exploitation': '💥 Exploitation',
            'post-exploit': '🔓 Post-Exploitation',
            'file-transfer': '📁 File Transfer',
            'pivoting': '🔄 Pivoting',
            'custom': '⚙️  Custom'
        }

        for cat_key in ['recon', 'web', 'exploitation', 'post-exploit', 'file-transfer', 'pivoting', 'custom']:
            if cat_key in categories and categories[cat_key]:
                commands = sorted(categories[cat_key], key=lambda x: x.id)
                print(f"\n{category_names.get(cat_key, cat_key)} ({len(commands)} commands)")
                print("─" * 50)

                # Group commands by type
                if cat_key == 'recon':
                    groups = {
                        'Network': ['nmap-', 'port-'],
                        'Services': ['dns-', 'smb-', 'snmp-'],
                        'Other': []
                    }
                elif cat_key == 'web':
                    groups = {
                        'Discovery': ['gobuster-', 'nikto-', 'whatweb-'],
                        'SQLi': ['sqli-', 'sqlmap-'],
                        'Other': ['xss-', 'lfi-', 'wfuzz-', 'curl-']
                    }
                elif cat_key == 'exploitation':
                    groups = {
                        'Shells': ['bash-', 'python-', 'nc-', 'powershell-'],
                        'Payloads': ['msfvenom-', 'php-'],
                        'Tools': ['searchsploit', 'hydra-', 'web-shell']
                    }
                elif cat_key == 'post-exploit':
                    groups = {
                        'Linux': ['linux-'],
                        'Windows': ['windows-']
                    }
                elif cat_key == 'file-transfer':
                    groups = {
                        'HTTP': ['python-http', 'wget-', 'curl-', 'certutil-', 'powershell-download'],
                        'Network': ['smb-', 'ftp-', 'scp-', 'nc-file'],
                        'Encoding': ['base64-', 'debug-', 'dns-', 'php-download', 'perl-', 'vbscript-']
                    }
                else:
                    groups = {'All': []}

                # Assign commands to groups
                grouped = {k: [] for k in groups.keys()}
                for cmd in commands:
                    assigned = False
                    for group_name, prefixes in groups.items():
                        if group_name == 'Other' or group_name == 'All':
                            continue
                        for prefix in prefixes:
                            if cmd.id.startswith(prefix) or cmd.id == prefix:
                                grouped[group_name].append(cmd)
                                assigned = True
                                break
                        if assigned:
                            break
                    if not assigned:
                        if 'Other' in grouped:
                            grouped['Other'].append(cmd)
                        elif 'All' in grouped:
                            grouped['All'].append(cmd)

                # Display groups
                for group_name in groups.keys():
                    if grouped[group_name]:
                        print(f"  ├─ {group_name}:")
                        for i, cmd in enumerate(grouped[group_name]):
                            is_last = (i == len(grouped[group_name]) - 1)
                            prefix = "  │   └─" if is_last else "  │   ├─"
                            # Show tags for important commands
                            tag_str = ""
                            if "QUICK_WIN" in cmd.tags:
                                tag_str = " [QUICK WIN]"
                            elif cmd.oscp_relevance == "high":
                                tag_str = " [HIGH]"
                            print(f"{prefix} {cmd.id}: {cmd.name[:40]}{tag_str}")

        print("\n" + "="*60)
        print(f"\nTotal Commands: {len(self.registry.commands)}")
        print(f"Quick Wins: {len(self.registry.get_quick_wins())}")
        print(f"OSCP High Relevance: {len(self.registry.get_oscp_high())}")
        print("\nUse 'crack reference <query>' to search commands")
        print("Use 'crack reference --fill <command>' to auto-fill placeholders")
        print("="*60)


def main():
    """Main entry point for CLI"""
    cli = ReferenceCLI()
    cli.run()


if __name__ == '__main__':
    main()