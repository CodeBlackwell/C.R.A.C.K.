"""
Interactive Session - Main state machine loop

Core of the interactive CLI system:
- Main loop: Display → Prompt → Process → Execute → Save
- Session management (save/resume checkpoints)
- Action execution
- Navigation stack
- Context management
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime

from ..core.state import TargetProfile
from ..core.storage import Storage
from ..recommendations.engine import RecommendationEngine
from ..parsers.registry import ParserRegistry
from ..phases.registry import PhaseManager

from .display import DisplayManager
from .prompts import PromptBuilder
from .input_handler import InputProcessor
from .shortcuts import ShortcutHandler
from .decision_trees import DecisionTreeFactory


class InteractiveSession:
    """Interactive session state machine"""

    def __init__(self, target: str, resume: bool = False):
        """
        Initialize interactive session

        Args:
            target: Target IP or hostname
            resume: Whether to resume existing session
        """
        self.target = target

        # Load or create profile
        if TargetProfile.exists(target):
            self.profile = TargetProfile.load(target)
            print(DisplayManager.format_success(f"Loaded profile for {target}"))
        else:
            self.profile = TargetProfile(target)
            self.profile.save()
            print(DisplayManager.format_success(f"Created new profile for {target}"))

        # Initialize components
        self.shortcut_handler = ShortcutHandler(self)
        self.last_action = None

        # Navigation stack (for back button)
        self.nav_stack = ['main']

        # Session checkpoint directory
        self.checkpoint_dir = Path.home() / '.crack' / 'sessions'
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)

        # Resume checkpoint if requested
        if resume:
            self.load_checkpoint()

    def run(self):
        """
        Main interactive loop

        Loop:
        1. Display current context
        2. Generate available actions
        3. Present choices to user
        4. Process input
        5. Execute action
        6. Update state
        7. Save checkpoint
        8. Repeat or exit
        """
        print("\n" + "=" * 70)
        print("CRACK Track - Interactive Mode")
        print("=" * 70)
        print("\nType 'h' for help, 'q' to quit\n")

        running = True

        while running:
            try:
                # 1. Display context
                self.display_context()

                # 2. Get recommendations
                recommendations = RecommendationEngine.get_recommendations(self.profile)

                # 3. Build menu
                prompt_text, choices = PromptBuilder.build_main_menu(self.profile, recommendations)

                # Display menu
                print(DisplayManager.format_menu(choices, title=prompt_text))

                # 4. Get user input
                user_input = InputProcessor.get_input("\nChoice [or shortcut]: ")

                # 5. Process input
                result = self.process_input(user_input, choices, recommendations)

                # 6. Handle result
                if result == 'exit':
                    running = False
                elif result == 'back':
                    self.navigate_back()

                # 7. Save checkpoint after each action
                self.save_checkpoint()

            except KeyboardInterrupt:
                print("\n\nInterrupted. Type 'q' to exit or press Enter to continue...")
                continue
            except Exception as e:
                print(DisplayManager.format_error(f"Unexpected error: {e}"))
                print("Session will continue. Type 'q' to exit safely.")

        # Final save before exit
        self.profile.save()
        print(DisplayManager.format_success("Session saved. Goodbye!"))

    def display_context(self):
        """Display current state banner"""
        banner = PromptBuilder.build_context_display(self.profile, self.last_action)
        print("\n" + banner)

    def process_input(self, user_input: str, choices: list,
                     recommendations: Dict[str, Any]) -> Optional[str]:
        """
        Process user input and route to appropriate handler

        Args:
            user_input: Raw input string
            choices: Available menu choices
            recommendations: Current recommendations

        Returns:
            'exit' to exit, 'back' to go back, None to continue
        """
        # Parse input
        parsed = InputProcessor.parse_any(user_input, {'choices': choices})

        input_type = parsed['type']
        value = parsed['value']

        # Handle shortcuts
        if input_type == 'shortcut':
            continue_session = self.shortcut_handler.handle(value)
            if not continue_session:
                return 'exit'
            return None

        # Handle navigation commands
        if input_type == 'navigation':
            if value in ['exit', 'quit', 'q']:
                return 'exit'
            elif value == 'back':
                return 'back'
            elif value == 'menu':
                self.nav_stack = ['main']
                return None

        # Handle command execution
        if input_type == 'command':
            self.execute_command(value)
            return None

        # Handle choice selection
        if input_type == 'choice':
            choice = value
            return self.handle_choice(choice, recommendations)

        # Invalid input
        print(DisplayManager.format_error(
            f"Invalid choice. Enter number, keyword, or shortcut."))
        return None

    def handle_choice(self, choice: Dict[str, Any],
                     recommendations: Dict[str, Any]) -> Optional[str]:
        """
        Handle user's menu choice

        Args:
            choice: Selected choice dict
            recommendations: Current recommendations

        Returns:
            Navigation command or None
        """
        choice_id = choice['id']

        # Route based on choice ID
        if choice_id == 'exit':
            return 'exit'

        elif choice_id == 'next':
            # Execute next recommended task
            task = recommendations.get('next')
            if task:
                self.execute_task(task)

        elif choice_id == 'quick-wins':
            self.show_quick_wins(recommendations)

        elif choice_id == 'quick-scan':
            self.execute_quick_scan()

        elif choice_id == 'full-scan':
            self.execute_full_scan()

        elif choice_id == 'service-scan':
            self.execute_service_scan()

        elif choice_id == 'import':
            self.import_scan_file()

        elif choice_id == 'finding':
            self.add_finding()

        elif choice_id == 'show-status':
            self.shortcut_handler.show_status()

        elif choice_id == 'enumerate-all':
            self.enumerate_all_services()

        elif choice_id == 'select-tasks':
            self.select_specific_tasks()

        else:
            print(DisplayManager.format_warning(f"Choice '{choice_id}' not implemented yet"))

        return None

    def execute_task(self, task):
        """
        Execute a task

        Args:
            task: TaskNode instance
        """
        print(f"\n{DisplayManager.format_task_summary(task)}")

        command = task.metadata.get('command')
        if not command:
            print(DisplayManager.format_warning("No command defined for this task"))
            return

        # Replace placeholders
        command = command.replace('{TARGET}', self.profile.target)

        print(f"\n{DisplayManager.format_info('Command to execute:')}")
        print(f"  {command}\n")

        # Show flag explanations
        flag_explanations = task.metadata.get('flag_explanations', {})
        if flag_explanations:
            print("Flag Explanations:")
            for flag, explanation in flag_explanations.items():
                print(f"  {flag}: {explanation}")
            print()

        # Confirm execution
        confirm = input(DisplayManager.format_confirmation(
            "Execute this command?", default='Y'
        ))

        if not InputProcessor.parse_confirmation(confirm, default='Y'):
            print("Cancelled")
            return

        # Mark task as in-progress
        task.status = 'in-progress'
        self.profile.save()

        # Execute command
        print(f"\n{DisplayManager.format_info('Executing...')}\n")

        import subprocess
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=False,
                text=True
            )

            if result.returncode == 0:
                print(DisplayManager.format_success("Command completed"))
                task.mark_complete()
                self.last_action = f"Completed: {task.name}"
            else:
                print(DisplayManager.format_warning(
                    f"Command exited with code {result.returncode}"))

                # Ask user if task should be marked complete anyway
                mark_done = input(DisplayManager.format_confirmation(
                    "Mark task as completed?", default='N'
                ))

                if InputProcessor.parse_confirmation(mark_done, default='N'):
                    task.mark_complete()
                    self.last_action = f"Completed: {task.name}"

        except Exception as e:
            print(DisplayManager.format_error(f"Execution failed: {e}"))

        self.profile.save()

    def execute_quick_scan(self):
        """Execute quick port scan"""
        print(DisplayManager.format_info("Starting quick port scan..."))

        command = f"nmap --top-ports 1000 {self.profile.target} -oN quick_scan.nmap"

        print(f"\nCommand: {command}")
        print("\nThis will scan the top 1000 most common ports (1-2 minutes)\n")

        confirm = input(DisplayManager.format_confirmation("Execute?", default='Y'))
        if not InputProcessor.parse_confirmation(confirm, default='Y'):
            return

        # Execute
        import subprocess
        result = subprocess.run(command, shell=True)

        if result.returncode == 0:
            print(DisplayManager.format_success("Scan complete!"))
            print("\nWould you like to import the results now?")

            import_now = input(DisplayManager.format_confirmation("Import?", default='Y'))
            if InputProcessor.parse_confirmation(import_now, default='Y'):
                self.import_scan_file('quick_scan.nmap')

            self.last_action = "Completed quick port scan"

    def execute_full_scan(self):
        """Execute full port scan"""
        print(DisplayManager.format_info("Starting full port scan..."))

        command = f"nmap -p- --min-rate 1000 {self.profile.target} -oA full_scan"

        print(f"\nCommand: {command}")
        print("\nThis will scan all 65535 ports (5-10 minutes)\n")

        confirm = input(DisplayManager.format_confirmation("Execute?", default='Y'))
        if not InputProcessor.parse_confirmation(confirm, default='Y'):
            return

        # Execute
        import subprocess
        result = subprocess.run(command, shell=True)

        if result.returncode == 0:
            print(DisplayManager.format_success("Scan complete!"))
            self.last_action = "Completed full port scan"

    def execute_service_scan(self):
        """Execute service version scan on discovered ports"""
        if not self.profile.ports:
            print(DisplayManager.format_warning("No ports discovered yet"))
            return

        # Build port list
        ports = ','.join(str(p) for p in sorted(self.profile.ports.keys()))
        command = f"nmap -sV -sC -p {ports} {self.profile.target} -oA service_scan"

        print(DisplayManager.format_info("Starting service version scan..."))
        print(f"\nCommand: {command}")
        print(f"\nThis will enumerate services on {len(self.profile.ports)} port(s)\n")

        confirm = input(DisplayManager.format_confirmation("Execute?", default='Y'))
        if not InputProcessor.parse_confirmation(confirm, default='Y'):
            return

        # Execute
        import subprocess
        result = subprocess.run(command, shell=True)

        if result.returncode == 0:
            print(DisplayManager.format_success("Scan complete!"))
            self.last_action = "Completed service version scan"

    def import_scan_file(self, filepath: str = None):
        """Import scan results file"""
        if not filepath:
            filepath = input(PromptBuilder.build_import_prompt()).strip()

        if not filepath or not os.path.exists(filepath):
            print(DisplayManager.format_error(f"File not found: {filepath}"))
            return

        try:
            # Parse file
            print(DisplayManager.format_info(f"Importing {filepath}..."))
            data = ParserRegistry.parse_file(filepath, self.profile.target, self.profile)

            # Save profile
            self.profile.save()

            print(DisplayManager.format_success("Import complete!"))
            print(f"\nDiscovered {len(self.profile.ports)} port(s)")

            self.last_action = f"Imported {os.path.basename(filepath)}"

            # Check for phase advancement
            PhaseManager.advance_phase(self.profile.phase, self.profile)

        except Exception as e:
            print(DisplayManager.format_error(f"Import failed: {e}"))

    def add_finding(self):
        """Add finding through guided entry"""
        # Get finding type
        prompt_text, choices = PromptBuilder.build_finding_type_menu()
        print(DisplayManager.format_menu(choices, title=prompt_text))

        finding_type_input = InputProcessor.get_input("Type: ")
        finding_type_choice = InputProcessor.parse_choice(finding_type_input, choices)

        if not finding_type_choice:
            print(DisplayManager.format_error("Invalid finding type"))
            return

        finding_type = finding_type_choice['id']

        # Handle credential separately (different form)
        if finding_type == 'credential':
            self.add_credential()
            return

        # Get finding details
        form_fields = PromptBuilder.build_finding_form(finding_type)

        data = {}
        for field in form_fields:
            prompt = DisplayManager.format_guided_entry_field(
                field['name'],
                field['type'],
                field['required'],
                example=field.get('example')
            )
            print(prompt)

            value = input(f"{field['name']}: ").strip()

            is_valid, parsed_value = InputProcessor.parse_field_value(
                value,
                field['type'],
                field['required']
            )

            if not is_valid:
                print(DisplayManager.format_error(f"Invalid {field['name']}"))
                return

            data[field['name']] = parsed_value

        # Add finding
        self.profile.add_finding(
            finding_type=finding_type,
            description=data['description'],
            source=data['source']
        )

        self.profile.save()
        print(DisplayManager.format_success(f"Added {finding_type}"))

        self.last_action = f"Documented {finding_type}"

    def add_credential(self):
        """Add credential through guided entry"""
        form_fields = PromptBuilder.build_credential_form()

        data = {}
        for field in form_fields:
            prompt = DisplayManager.format_guided_entry_field(
                field['name'],
                field['type'],
                field['required'],
                example=field.get('example')
            )
            print(prompt)

            value = input(f"{field['name']}: ").strip()

            is_valid, parsed_value = InputProcessor.parse_field_value(
                value,
                field['type'],
                field['required']
            )

            if not is_valid and field['required']:
                print(DisplayManager.format_error(f"Invalid {field['name']}"))
                return

            data[field['name']] = parsed_value

        # Add credential
        self.profile.add_credential(
            username=data['username'],
            password=data.get('password'),
            service=data['service'],
            port=data.get('port'),
            source=data['source']
        )

        self.profile.save()
        print(DisplayManager.format_success("Added credential"))

        self.last_action = "Added credential"

    def show_quick_wins(self, recommendations: Dict[str, Any]):
        """Show and execute quick win tasks"""
        quick_wins = recommendations.get('quick_wins', [])

        if not quick_wins:
            print(DisplayManager.format_warning("No quick wins available"))
            return

        prompt_text, choices = PromptBuilder.build_quick_wins_menu(quick_wins)
        print(DisplayManager.format_menu(choices, title=prompt_text))

        choice_input = InputProcessor.get_input("Choice: ")
        choice = InputProcessor.parse_choice(choice_input, choices)

        if not choice:
            return

        if choice['id'] == 'execute-all':
            for task in quick_wins:
                self.execute_task(task)
        elif choice['id'] == 'back':
            return
        else:
            task = choice.get('task')
            if task:
                self.execute_task(task)

    def enumerate_all_services(self):
        """Execute all pending service enumeration tasks"""
        pending = self.profile.task_tree.get_all_pending()

        if not pending:
            print(DisplayManager.format_warning("No pending tasks"))
            return

        print(f"\nFound {len(pending)} pending task(s)")
        print(DisplayManager.format_confirmation(
            f"Execute all {len(pending)} tasks?", default='N'
        ))

        confirm = input()
        if not InputProcessor.parse_confirmation(confirm, default='N'):
            return

        for task in pending:
            self.execute_task(task)

        self.last_action = f"Executed {len(pending)} tasks"

    def select_specific_tasks(self):
        """Select specific tasks to execute"""
        pending = self.profile.task_tree.get_all_pending()

        if not pending:
            print(DisplayManager.format_warning("No pending tasks"))
            return

        prompt_text, choices = PromptBuilder.build_task_selection_menu(pending)
        print(DisplayManager.format_menu(choices, title=prompt_text))

        choice_input = InputProcessor.get_input("Choice: ")
        choice = InputProcessor.parse_choice(choice_input, choices)

        if choice and choice.get('task'):
            self.execute_task(choice['task'])

    def execute_command(self, cmd_tuple):
        """Execute shell command"""
        command, args = cmd_tuple
        print(DisplayManager.format_info(f"Executing: {command} {' '.join(args)}"))

        import subprocess
        subprocess.run([command] + args)

    def navigate_back(self):
        """Navigate back in navigation stack"""
        if len(self.nav_stack) > 1:
            self.nav_stack.pop()
            print(DisplayManager.format_info("Going back..."))

    def save_checkpoint(self):
        """Save session checkpoint"""
        checkpoint_file = self.checkpoint_dir / f"{self.profile.target}_session.json"

        checkpoint_data = {
            'target': self.profile.target,
            'current_phase': self.profile.phase,
            'nav_stack': self.nav_stack,
            'last_action': self.last_action,
            'timestamp': datetime.now().isoformat()
        }

        with open(checkpoint_file, 'w') as f:
            json.dump(checkpoint_data, f, indent=2)

    def load_checkpoint(self):
        """Load session checkpoint"""
        checkpoint_file = self.checkpoint_dir / f"{self.profile.target}_session.json"

        if not checkpoint_file.exists():
            return

        try:
            with open(checkpoint_file, 'r') as f:
                data = json.load(f)

            self.nav_stack = data.get('nav_stack', ['main'])
            self.last_action = data.get('last_action')

            print(DisplayManager.format_success("Resumed previous session"))

        except Exception as e:
            print(DisplayManager.format_warning(f"Could not load checkpoint: {e}"))
