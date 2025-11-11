"""
CLI interactive handler for command filling and execution
"""

import subprocess
from typing import List, Optional

from reference.cli.base import BaseCLIHandler
from reference.core.registry import Command


class InteractiveCLI(BaseCLIHandler):
    """Handler for interactive command operations"""

    def __init__(self, registry=None, theme=None):
        """Initialize interactive handler

        Args:
            registry: HybridCommandRegistry instance
            theme: ReferenceTheme instance
        """
        super().__init__(theme)
        self.registry = registry

    def fill_command_with_execute(self, command_id: str) -> Optional[int]:
        """Fill command placeholders and offer to execute

        Shows full command details first, then interactively fills placeholders.

        Args:
            command_id: Command ID to fill and execute

        Returns:
            Exit code (0 for success, 1 for error, None for cancelled)
        """
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
                    return None
            else:
                print(f"{self.theme.error('Command not found:')} {self.theme.warning(command_id)}")
                return None

        # FIRST: Show full command details (same as direct ID lookup)
        from .display import DisplayCLI
        display_cli = DisplayCLI(registry=self.registry, theme=self.theme)
        display_cli.show_command_details(cmd)

        # THEN: Fill placeholders interactively
        try:
            filled = self.registry.interactive_fill(cmd)
        except KeyboardInterrupt:
            print(f"\n{self.theme.warning('[Cancelled by user]')}")
            return None

        # Show final command
        print(f"\n{self.theme.primary('Copy this command:')}")
        print(f"  {self.theme.command_name(filled)}")

        # Offer to execute
        return self._execute_with_confirmation(filled)

    def interactive_select_and_fill(self, commands: List[Command]) -> Optional[int]:
        """Interactive selection from numbered list, fill variables, offer to run

        Args:
            commands: List of Command objects to select from

        Returns:
            Exit code (0 for success, 1 for error, None for cancelled)
        """
        # Step 1: Display numbered list
        from .display import DisplayCLI
        display = DisplayCLI(registry=self.registry, theme=self.theme)
        display.display_commands(commands, format='text', verbose=False)

        # Step 2: Prompt for selection
        print(f"\n{self.theme.prompt(f'Select command by number (1-{len(commands)}) or q to quit: ')}", end='')
        choice = input().strip()

        if choice.lower() == 'q':
            return None

        # Step 3: Validate selection
        try:
            selection = int(choice) - 1
            if 0 <= selection < len(commands):
                cmd = commands[selection]
            else:
                print(f"{self.theme.error(f'Invalid selection: {choice}. Please enter a number between 1 and {len(commands)}.')}")
                return None
        except ValueError:
            print(f"{self.theme.error('Invalid input. Please enter a number or q to quit.')}")
            return None

        # Step 4: Fill placeholders interactively
        try:
            filled = self.registry.interactive_fill(cmd)
        except KeyboardInterrupt:
            print(f"\n{self.theme.warning('[Cancelled by user]')}")
            return None

        # Step 5: Show final command
        print(f"\n{self.theme.primary('Copy this command:')}")
        print(f"  {self.theme.command_name(filled)}")

        # Step 6: Offer to execute
        return self._execute_with_confirmation(filled)

    def interactive_mode(self, search_handler=None):
        """Interactive command browser REPL

        Args:
            search_handler: SearchCLI instance for command lookup
        """
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
                    if search_handler:
                        search_handler.list_tags()
                    else:
                        print("Tag listing requires search handler")
                    continue

                if user_input.startswith('cat '):
                    category = user_input.split(' ', 1)[1]
                    if search_handler:
                        search_handler.search_commands(category=category, verbose=True)
                    else:
                        print("Category search requires search handler")
                    continue

                if user_input.startswith('tag '):
                    tag = user_input.split(' ', 1)[1]
                    if search_handler:
                        search_handler.search_commands(tags=[tag], verbose=True)
                    else:
                        print("Tag search requires search handler")
                    continue

                # Default: search
                if user_input and search_handler:
                    search_handler.search_commands(query=user_input, verbose=False)

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

    def _execute_with_confirmation(self, command: str) -> Optional[int]:
        """Execute command after user confirmation

        Args:
            command: Command string to execute

        Returns:
            Exit code (0 for success, 1 for error, None for cancelled)
        """
        print(f"\n{self.theme.prompt('Run this command? (y/N): ')}", end='')
        try:
            confirm = input().strip().lower()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{self.theme.warning('[Cancelled by user]')}")
            return None

        if confirm == 'y':
            print(f"\n{self.theme.primary('Executing:')} {self.theme.command_name(command)}")
            try:
                result = subprocess.run(command, shell=True)
                return result.returncode
            except Exception as e:
                print(f"{self.theme.error('Execution failed:')} {str(e)}")
                return 1
        else:
            print(f"{self.theme.hint('Command not executed. Copy from above to run manually.')}")
            return None
