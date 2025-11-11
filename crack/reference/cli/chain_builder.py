"""CLI wizard for creating and cloning attack chains."""

import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from crack.reference.cli.base import BaseCLIHandler
from crack.reference.builders.chain_builder import ChainBuilder
from crack.reference.chains.command_resolver import CommandResolver
from crack.reference.core.registry import HybridCommandRegistry


class ChainBuilderCLI(BaseCLIHandler):
    """Interactive CLI wizard for chain creation."""

    CATEGORIES = [
        'privilege_escalation',
        'enumeration',
        'lateral_movement',
        'persistence',
        'exploitation',
        'defense_evasion'
    ]

    PLATFORMS = [
        'linux',
        'windows',
        'web',
        'network',
        'active_directory',
        'multi-platform'
    ]

    DIFFICULTIES = [
        'beginner',
        'intermediate',
        'advanced',
        'expert'
    ]

    def __init__(self, theme=None):
        """Initialize chain builder CLI."""
        super().__init__(theme)
        self.resolver = CommandResolver()
        self.registry = None  # Lazy load
        self.builder: Optional[ChainBuilder] = None

    def _ensure_registry(self):
        """Lazy load command registry."""
        if self.registry is None:
            self.registry = HybridCommandRegistry()

    def create(self) -> int:
        """Create a new chain from scratch."""
        self.print_banner("CREATE NEW ATTACK CHAIN", width=70)

        print(self.theme.muted("This wizard will guide you through creating a new attack chain.\n"))

        # Create builder
        self.builder = ChainBuilder.from_scratch()

        # Collect metadata
        self._prompt_metadata()

        # Add steps
        self._prompt_steps()

        # Validate and save
        return self._validate_and_save()

    def clone(self, chain_id: str) -> int:
        """Clone an existing chain."""
        self.print_banner(f"CLONE ATTACK CHAIN: {chain_id}", width=70)

        try:
            self.builder = ChainBuilder.from_template(chain_id)
        except ValueError as e:
            print(self.format_error(str(e)))
            return 1

        print(self.format_success(f"Loaded template: {self.builder.chain['name']}"))
        print(self.theme.muted(f"Steps: {len(self.builder.chain['steps'])}"))
        print()

        # Prompt for new ID
        while True:
            new_id = input(self.theme.prompt("New chain ID: ")).strip()
            if new_id:
                if self._validate_chain_id_format(new_id):
                    self.builder.set_metadata(id=new_id)
                    break
                else:
                    print(self.format_error("Invalid ID format. Use: platform-category-technique-variant"))
            else:
                print(self.format_error("Chain ID is required."))

        # Optionally modify steps
        modify = input(self.theme.prompt("Modify steps? [y/N]: ")).strip().lower()
        if modify == 'y':
            self._modify_steps_wizard()

        # Optionally update metadata
        update_meta = input(self.theme.prompt("Update metadata (name, description, etc.)? [y/N]: ")).strip().lower()
        if update_meta == 'y':
            self._prompt_metadata(skip_id=True)

        # Validate and save
        return self._validate_and_save()

    def _prompt_metadata(self, skip_id: bool = False):
        """Prompt user for chain metadata."""
        print(self.theme.command_name("\n=== CHAIN METADATA ===\n"))

        # Chain ID
        if not skip_id:
            while True:
                chain_id = input(self.theme.prompt("Chain ID (e.g., linux-privesc-suid-basic): ")).strip()
                if chain_id:
                    if self._validate_chain_id_format(chain_id):
                        self.builder.set_metadata(id=chain_id)
                        break
                    else:
                        print(self.format_error("Invalid ID format. Use: platform-category-technique-variant"))
                else:
                    print(self.format_error("Chain ID is required."))

        # Name
        name = input(self.theme.prompt("Chain name: ")).strip()
        if name:
            self.builder.set_metadata(name=name)

        # Description
        description = input(self.theme.prompt("Description: ")).strip()
        if description:
            self.builder.set_metadata(description=description)

        # Category
        print(self.theme.muted(f"\nAvailable categories: {', '.join(self.CATEGORIES)}"))
        category = self._prompt_choice("Category", self.CATEGORIES, required=True)
        self.builder.set_metadata(category=category)

        # Platform
        print(self.theme.muted(f"\nAvailable platforms: {', '.join(self.PLATFORMS)}"))
        platform = self._prompt_choice("Platform", self.PLATFORMS, required=False)
        if platform:
            self.builder.set_metadata(platform=platform)

        # Difficulty
        print(self.theme.muted(f"\nAvailable difficulties: {', '.join(self.DIFFICULTIES)}"))
        difficulty = self._prompt_choice("Difficulty", self.DIFFICULTIES, required=True)
        self.builder.set_metadata(difficulty=difficulty)

        # Time estimate
        time_est = input(self.theme.prompt("Time estimate (e.g., 15 minutes): ")).strip()
        if time_est:
            self.builder.set_metadata(time_estimate=time_est)

        # OSCP relevance
        oscp = input(self.theme.prompt("OSCP relevant? [Y/n]: ")).strip().lower()
        self.builder.set_metadata(oscp_relevant=(oscp != 'n'))

        # Author
        author = input(self.theme.prompt("Author name (optional): ")).strip()
        if not author:
            # Try to get from git config
            try:
                import subprocess
                result = subprocess.run(['git', 'config', 'user.name'],
                                        capture_output=True, text=True, check=False)
                if result.returncode == 0:
                    author = result.stdout.strip()
            except:
                pass
        if author:
            self.builder.set_metadata(author=author)

        # Tags
        tags_input = input(self.theme.prompt("Tags (comma-separated, optional): ")).strip()
        if tags_input:
            tags = [t.strip().upper() for t in tags_input.split(',') if t.strip()]
            self.builder.set_metadata(tags=tags)

    def _prompt_steps(self):
        """Prompt user to add steps."""
        print(self.theme.command_name("\n=== ADD STEPS ===\n"))
        print(self.theme.muted("Add steps to your attack chain. Press Ctrl+C to finish.\n"))

        step_num = 1
        try:
            while True:
                print(self.theme.primary(f"--- Step {step_num} ---"))

                # Get step details
                step_data = self._prompt_single_step()
                if step_data:
                    self.builder.add_step(step_data)
                    print(self.format_success(f"Added step: {step_data['name']}"))
                    step_num += 1

                # Continue?
                cont = input(self.theme.prompt("\nAdd another step? [Y/n]: ")).strip().lower()
                if cont == 'n':
                    break
                print()

        except KeyboardInterrupt:
            print(self.theme.muted("\n\nFinished adding steps."))

    def _prompt_single_step(self) -> Optional[Dict[str, Any]]:
        """Prompt for a single step's details."""
        # Name (required)
        name = input(self.theme.prompt("Step name: ")).strip()
        if not name:
            print(self.format_error("Step name is required."))
            return None

        # Objective (required)
        objective = input(self.theme.prompt("Objective: ")).strip()
        if not objective:
            print(self.format_error("Objective is required."))
            return None

        # Command reference (required)
        command_ref = self._prompt_command_ref()
        if not command_ref:
            print(self.format_error("Command reference is required."))
            return None

        # Optional fields
        step_data = {
            'name': name,
            'objective': objective,
            'command_ref': command_ref
        }

        # Step ID (optional)
        step_id = input(self.theme.prompt("Step ID (for dependencies, optional): ")).strip()
        if step_id:
            step_data['id'] = step_id

        # Dependencies (optional)
        available_ids = self.builder.get_available_step_ids()
        if available_ids:
            print(self.theme.muted(f"Available step IDs: {', '.join(available_ids)}"))
            deps_input = input(self.theme.prompt("Dependencies (comma-separated IDs, optional): ")).strip()
            if deps_input:
                deps = [d.strip() for d in deps_input.split(',') if d.strip()]
                step_data['dependencies'] = deps

        # Success criteria (optional)
        success = input(self.theme.prompt("Success criteria (optional): ")).strip()
        if success:
            step_data['success_criteria'] = [success]

        return step_data

    def _prompt_command_ref(self) -> Optional[str]:
        """Prompt for command reference with browsing support."""
        print(self.theme.muted("\nCommand reference options:"))
        print(self.theme.muted("  1. Enter command ID directly"))
        print(self.theme.muted("  2. Browse available commands"))

        choice = input(self.theme.prompt("Choice [1/2]: ")).strip()

        if choice == '2':
            return self._browse_commands()
        else:
            cmd_ref = input(self.theme.prompt("Command ID: ")).strip()
            return cmd_ref if cmd_ref else None

    def _browse_commands(self) -> Optional[str]:
        """Browse available commands."""
        self._ensure_registry()

        print(self.theme.command_name("\n=== BROWSE COMMANDS ==="))

        # Search or filter
        search = input(self.theme.prompt("Search term (or Enter to list all): ")).strip()

        commands = []
        if search:
            commands = list(self.registry.search(search))
        else:
            commands = list(self.registry.commands.values())[:20]  # Limit to 20

        if not commands:
            print(self.format_error("No commands found."))
            return None

        # Display commands
        print()
        for i, cmd in enumerate(commands, 1):
            print(f"{self.theme.primary(f'{i}.')} {self.theme.command_name(cmd.name)} {self.theme.muted(f'[{cmd.id}]')}")
            if hasattr(cmd, 'description') and cmd.description:
                print(f"   {self.theme.muted(cmd.description[:60])}")
            if i >= 20:
                print(self.theme.muted(f"\n... and {len(commands) - 20} more"))
                break

        # Select
        selection = input(self.theme.prompt("\nSelect number (or 'q' to cancel): ")).strip()
        if selection.lower() == 'q':
            return None

        try:
            idx = int(selection) - 1
            if 0 <= idx < len(commands):
                selected = commands[idx]
                print(self.format_success(f"Selected: {selected.name}"))
                return selected.id
            else:
                print(self.format_error("Invalid selection."))
                return None
        except ValueError:
            print(self.format_error("Invalid input."))
            return None

    def _modify_steps_wizard(self):
        """Interactive wizard to modify existing steps."""
        print(self.theme.command_name("\n=== MODIFY STEPS ===\n"))

        while True:
            # Show current steps
            steps = self.builder.get_steps()
            if not steps:
                print(self.theme.muted("No steps in chain."))
                return

            print(self.theme.muted("Current steps:"))
            for i, step in enumerate(steps, 1):
                num = self.theme.primary(f'{i}.')
                cmd_ref = self.theme.muted(f"[{step['command_ref']}]")
                print(f"{num} {step['name']} {cmd_ref}")

            print()
            print(self.theme.muted("Options:"))
            print(self.theme.muted("  a - Add step"))
            print(self.theme.muted("  d - Delete step"))
            print(self.theme.muted("  q - Done"))

            action = input(self.theme.prompt("\nChoice: ")).strip().lower()

            if action == 'a':
                step_data = self._prompt_single_step()
                if step_data:
                    self.builder.add_step(step_data)
                    print(self.format_success("Step added."))
            elif action == 'd':
                idx_input = input(self.theme.prompt("Step number to delete: ")).strip()
                try:
                    idx = int(idx_input) - 1
                    self.builder.remove_step(idx)
                    print(self.format_success("Step removed."))
                except (ValueError, IndexError) as e:
                    print(self.format_error(f"Invalid selection: {e}"))
            elif action == 'q':
                break

    def _validate_and_save(self) -> int:
        """Validate chain and save to file."""
        print(self.theme.command_name("\n=== VALIDATION ===\n"))

        # Validate
        errors = self.builder.validate(command_resolver=self.resolver)

        if errors:
            print(self.format_error("Validation failed:"))
            for error in errors:
                print(f"  {self.theme.error('•')} {error}")

            # Ask if they want to save anyway
            save_anyway = input(self.theme.warning("\nSave anyway (not recommended)? [y/N]: ")).strip().lower()
            if save_anyway != 'y':
                print(self.theme.muted("Chain not saved."))
                return 1
        else:
            print(self.format_success("All validations passed!"))

        # Save
        print(self.theme.command_name("\n=== SAVE ===\n"))

        try:
            filepath = self.builder.save()
            print(self.format_success(f"Chain saved to: {filepath}"))
            print(self.theme.muted("\nTo use this chain:"))
            print(self.theme.primary(f"  crack reference --chains {self.builder.chain['id']}"))
            return 0
        except Exception as e:
            print(self.format_error(f"Failed to save: {e}"))
            return 1

    def _prompt_choice(self, label: str, choices: List[str], required: bool = False) -> Optional[str]:
        """Prompt user to select from a list of choices."""
        while True:
            value = input(self.theme.prompt(f"{label}: ")).strip().lower()
            if not value:
                if not required:
                    return None
                else:
                    print(self.format_error(f"{label} is required."))
                    continue
            if value in choices:
                return value
            else:
                print(self.format_error(f"Invalid choice. Must be one of: {', '.join(choices)}"))

    def _validate_chain_id_format(self, chain_id: str) -> bool:
        """Validate chain ID format (platform-category-technique-variant)."""
        import re
        pattern = r'^[a-z0-9]+-[a-z0-9]+-[a-z0-9]+-[a-z0-9]+$'
        return bool(re.match(pattern, chain_id))
