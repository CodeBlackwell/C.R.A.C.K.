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

    def __init__(self, target: str, resume: bool = False, screened: bool = False):
        """
        Initialize interactive session

        Args:
            target: Target IP or hostname
            resume: Whether to resume existing session
            screened: Whether to use screened terminal mode
        """
        self.target = target
        self.screened_mode = screened

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

        # Initialize executor based on mode
        if screened:
            # Import here to avoid circular dependency
            from ..core.command_executor import CommandExecutor
            from ..core.terminal import ScreenedTerminal
            from ..parsers.output_patterns import OutputPatternMatcher

            # Create screen session for visibility
            import subprocess
            self.screen_session_name = f"crack_{target.replace('.', '_')}"

            # Start screen session with terminal
            print(DisplayManager.format_info("[SCREENED MODE] Initializing persistent terminal..."))

            # Create terminal
            self.terminal = ScreenedTerminal(target)

            # Create executor with terminal
            self.executor = CommandExecutor.create('screened', terminal=self.terminal)

            # Add output parser
            self.executor.set_parser(OutputPatternMatcher())

            # Start terminal
            if self.terminal.start():
                print(DisplayManager.format_success("[SCREENED] Terminal started successfully"))
                print(DisplayManager.format_info(
                    f"\n📺 To view terminal output in another window:\n"
                    f"   screen -x crack_{target.replace('.', '_')}\n"
                    f"   OR\n"
                    f"   tail -f {self.terminal.session_log}\n"
                ))
            else:
                print(DisplayManager.format_error("[SCREENED] Failed to start terminal, falling back to subprocess mode"))
                self.screened_mode = False
                from ..core.command_executor import CommandExecutor
                self.executor = CommandExecutor.create('subprocess')
        else:
            # Use standard subprocess executor
            from ..core.command_executor import CommandExecutor
            self.executor = CommandExecutor.create('subprocess')

        # Navigation stack (for back button)
        self.nav_stack = ['main']

        # Search state
        self.search_query = None
        self.search_results = []

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
            command, args = value
            # Special case for /search command
            if command == 'search':
                self.handle_search()
            else:
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

        # Handle profile-based scans (new dynamic system)
        elif choice_id.startswith('scan-'):
            profile_id = choice_id[5:]  # Remove 'scan-' prefix
            scan_profile = choice.get('scan_profile')
            self.execute_scan(profile_id, scan_profile)

        elif choice_id == 'custom-scan':
            self.execute_custom_scan()

        # Legacy scan handlers (backward compatibility)
        elif choice_id == 'quick-scan':
            self.execute_scan('lab-quick')

        elif choice_id == 'full-scan':
            self.execute_scan('lab-full')

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

        # Show screened mode status
        if self.screened_mode:
            print(DisplayManager.format_info("[SCREENED] Command will run in persistent terminal"))
            print(DisplayManager.format_info("Output will be automatically parsed for findings\n"))

        # Check confirmation mode
        mode = self.profile.metadata.get('confirmation_mode', 'smart')
        proceed = False

        if mode == 'never':
            # Skip all confirmations
            proceed = True
            print(DisplayManager.format_info("[AUTO] Confirmation mode: never - executing automatically"))
        elif mode == 'smart':
            # Skip confirmation for read-only tasks
            tags = task.metadata.get('tags', [])
            if 'READ_ONLY' in tags:
                proceed = True
                print(DisplayManager.format_info("[AUTO] Read-only task - skipping confirmation"))
            else:
                # Ask for confirmation
                confirm = input(DisplayManager.format_confirmation(
                    "Execute this command?", default='Y'
                ))
                proceed = InputProcessor.parse_confirmation(confirm, default='Y')
        else:
            # 'always' or 'batch' mode - always ask
            confirm = input(DisplayManager.format_confirmation(
                "Execute this command?", default='Y'
            ))
            proceed = InputProcessor.parse_confirmation(confirm, default='Y')

        if not proceed:
            print("Cancelled")
            return

        # Mark task as in-progress
        task.status = 'in-progress'
        self.profile.save()

        # Execute command using executor abstraction
        print(f"\n{DisplayManager.format_info('Executing...')}\n")

        if self.screened_mode:
            # Use screened executor
            try:
                result = self.executor.run(task, self.profile.target)

                if result.success:
                    print(DisplayManager.format_success("Command completed successfully"))

                    # Show extracted findings if any
                    if result.findings:
                        print(DisplayManager.format_info("\n[SCREENED] Extracted findings:"))
                        for finding_type, items in result.findings.items():
                            if items and finding_type != 'success':
                                print(f"  • {finding_type}: {len(items)} found")

                                # Auto-add certain findings to profile
                                if finding_type == 'ports':
                                    for port_info in items:
                                        self.profile.add_port(
                                            port_info['port'],
                                            state='open',
                                            service=port_info.get('service'),
                                            version=port_info.get('version'),
                                            source=f"[SCREENED] {command}"
                                        )

                                elif finding_type == 'credentials':
                                    for cred_info in items:
                                        self.profile.add_credential(
                                            username=cred_info['username'],
                                            password=cred_info.get('password'),
                                            source=f"[SCREENED] {command}"
                                        )

                    task.mark_complete()
                    self.last_action = f"Completed: {task.name}"
                else:
                    print(DisplayManager.format_warning("Command failed or returned non-zero exit"))

                    # Show output for debugging
                    if result.output:
                        print("\nOutput (last 10 lines):")
                        for line in result.output[-10:]:
                            print(f"  {line}")

                    # Ask user if task should be marked complete anyway
                    mark_done = input(DisplayManager.format_confirmation(
                        "Mark task as completed anyway?", default='N'
                    ))

                    if InputProcessor.parse_confirmation(mark_done, default='N'):
                        task.mark_complete()
                        self.last_action = f"Completed: {task.name}"

            except Exception as e:
                print(DisplayManager.format_error(f"Screened execution failed: {e}"))

        else:
            # Use subprocess executor (current implementation)
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

    def execute_scan(self, profile_id: str, scan_profile: dict = None):
        """Execute scan using specified profile - GENERIC HANDLER

        Args:
            profile_id: Scan profile ID
            scan_profile: Optional pre-loaded profile dict
        """
        from ..core.scan_profiles import get_profile
        from ..core.command_builder import ScanCommandBuilder
        import subprocess

        # Load profile if not provided
        if scan_profile is None:
            scan_profile = get_profile(profile_id)

        if not scan_profile:
            print(DisplayManager.format_error(f"Unknown scan profile: {profile_id}"))
            return

        print(DisplayManager.format_info(f"Starting {scan_profile['name']}..."))
        print(f"Strategy: {scan_profile['use_case']}")
        print(f"Estimated time: {scan_profile['estimated_time']}")

        # Build command
        builder = ScanCommandBuilder(self.profile.target, scan_profile)
        command = builder.build()

        print(f"\nCommand: {command}\n")

        # Show flag explanations if available
        flag_explanations = scan_profile.get('flag_explanations', {})
        if flag_explanations:
            print("Flag Explanations:")
            for flag, explanation in flag_explanations.items():
                print(f"  {flag}: {explanation}")
            print()

        # Warn if high detection risk
        detection_risk = scan_profile.get('detection_risk', 'medium')
        if detection_risk in ['high', 'very-high']:
            print(DisplayManager.format_warning(
                f"⚠️  WARNING: This scan is NOISY (detection risk: {detection_risk})"
            ))
            print("This scan may trigger IDS/IPS alerts. Only use in labs or with permission.\n")

        # Confirm execution
        confirm = input(DisplayManager.format_confirmation("Execute?", default='Y'))
        if not InputProcessor.parse_confirmation(confirm, default='Y'):
            print("Cancelled")
            return

        # Execute
        print(DisplayManager.format_info("Executing scan...\n"))
        result = subprocess.run(command, shell=True)

        if result.returncode == 0:
            print(DisplayManager.format_success("Scan complete!"))

            # Record scan in history
            self.profile.record_scan(
                profile_id=profile_id,
                command=command,
                result_summary=f"Completed: {scan_profile['name']}"
            )

            # Auto-import if output file created
            output_files = []
            if '-oA' in command:
                # XML format for import
                output_base = command.split('-oA')[1].split()[0]
                output_files.append(f"{output_base}.xml")
            elif '-oN' in command or '-oX' in command:
                # Extract output filename
                import re
                match = re.search(r'-o[NX]\s+(\S+)', command)
                if match:
                    output_files.append(match.group(1))

            # Offer to import
            if output_files:
                print("\nWould you like to import the results now?")
                import_confirm = input(DisplayManager.format_confirmation("Import?", default='Y'))
                if InputProcessor.parse_confirmation(import_confirm, default='Y'):
                    for output_file in output_files:
                        if os.path.exists(output_file):
                            self.import_scan_file(output_file)
                            break

            self.last_action = f"Completed: {scan_profile['name']}"
            self.profile.save()  # Save profile with scan history
        else:
            print(DisplayManager.format_error("Scan failed or was interrupted"))

    def execute_custom_scan(self):
        """Execute user-provided custom nmap command"""
        import subprocess

        print(DisplayManager.format_info("Custom Scan Mode"))
        print("Enter your custom nmap command (or 'cancel' to abort):\n")

        command = input("nmap ").strip()

        if not command or command.lower() == 'cancel':
            print("Cancelled")
            return

        # Build full command
        full_command = f"nmap {command}"

        print(f"\nFull command: {full_command}")
        print(DisplayManager.format_warning(
            "⚠️  Custom commands bypass safety checks. Ensure you know what you're doing.\n"
        ))

        confirm = input(DisplayManager.format_confirmation("Execute?", default='N'))
        if not InputProcessor.parse_confirmation(confirm, default='N'):
            print("Cancelled")
            return

        # Execute
        print(DisplayManager.format_info("Executing...\n"))
        result = subprocess.run(full_command, shell=True)

        if result.returncode == 0:
            print(DisplayManager.format_success("Custom scan complete!"))
            self.last_action = "Completed custom scan"
        else:
            print(DisplayManager.format_error("Scan failed or was interrupted"))

    def execute_quick_scan(self):
        """Execute quick port scan (LEGACY - maintained for backward compatibility)"""
        # Delegate to new generic handler
        self.execute_scan('lab-quick')

    def execute_full_scan(self):
        """Execute full port scan (LEGACY - maintained for backward compatibility)"""
        # Delegate to new generic handler
        self.execute_scan('lab-full')

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

    def _fuzzy_match(self, query: str, text: str) -> tuple:
        """
        Simple fuzzy matching algorithm

        Returns:
            Tuple of (is_match: bool, score: int)
            Score: 0-100, higher is better match
        """
        query = query.lower()
        text = text.lower()

        # Exact match = 100
        if query == text:
            return (True, 100)

        # Substring match = 80
        if query in text:
            return (True, 80)

        # Check for partial matches
        query_chars = list(query)
        text_chars = list(text)

        # Count matching characters in order
        matches = 0
        text_idx = 0

        for q_char in query_chars:
            while text_idx < len(text_chars):
                if text_chars[text_idx] == q_char:
                    matches += 1
                    text_idx += 1
                    break
                text_idx += 1

        # Calculate score based on match ratio
        if matches == len(query_chars):
            # All chars found in order - score 50-70 based on match quality
            match_ratio = matches / max(len(query), len(text))
            score = int(50 + (match_ratio * 20))
            return (True, score)

        # Partial match if >50% chars found
        if matches > len(query_chars) * 0.5:
            score = int((matches / len(query_chars)) * 50)
            return (True, score)

        return (False, 0)

    def search_tasks(self, query: str, min_score: int = 50) -> list:
        """
        Fuzzy search for tasks by name, command, or tags

        Args:
            query: Search query string
            min_score: Minimum match score (0-100)

        Returns:
            List of (TaskNode, score) tuples, sorted by score descending
        """
        query = query.lower()
        results = []

        def search_node(node):
            """Recursively search task tree with fuzzy matching"""
            best_match = (False, 0)

            # Search in task name
            match = self._fuzzy_match(query, node.name)
            if match[1] > best_match[1]:
                best_match = match

            # Search in command
            if node.metadata.get('command'):
                match = self._fuzzy_match(query, node.metadata['command'])
                if match[1] > best_match[1]:
                    best_match = match

            # Search in tags
            for tag in node.metadata.get('tags', []):
                match = self._fuzzy_match(query, tag)
                if match[1] > best_match[1]:
                    best_match = match

            # Search in description
            if node.metadata.get('description'):
                match = self._fuzzy_match(query, node.metadata['description'])
                if match[1] > best_match[1]:
                    best_match = match

            # Add if score meets threshold
            if best_match[0] and best_match[1] >= min_score:
                results.append((node, best_match[1]))

            # Recursively search children
            for child in node.children:
                search_node(child)

        search_node(self.profile.task_tree)

        # Sort by score descending
        results.sort(key=lambda x: x[1], reverse=True)

        # Store for later use
        self.search_query = query
        self.search_results = [r[0] for r in results]  # Store nodes only

        return results  # Return (node, score) tuples

    def filter_tasks(self, filter_type: str, filter_value: str = None) -> list:
        """
        Filter tasks by various criteria

        Args:
            filter_type: Type of filter ('status', 'tag', 'quick_win', 'port')
            filter_value: Value to filter by (e.g., 'pending', 'OSCP:HIGH')

        Returns:
            List of matching TaskNode objects
        """
        results = []

        def filter_node(node):
            """Recursively filter task tree"""
            matched = False

            if filter_type == 'status' and node.status == filter_value:
                matched = True
            elif filter_type == 'tag' and filter_value in node.metadata.get('tags', []):
                matched = True
            elif filter_type == 'quick_win' and 'QUICK_WIN' in node.metadata.get('tags', []):
                matched = True
            elif filter_type == 'port':
                # Extract port from task ID or name
                if f"-{filter_value}" in node.id or f"port {filter_value}" in node.name.lower():
                    matched = True

            if matched:
                results.append(node)

            # Recursively filter children
            for child in node.children:
                filter_node(child)

        filter_node(self.profile.task_tree)
        return results

    def set_confirmation_mode(self, mode: str):
        """Set confirmation mode for task execution

        Args:
            mode: Confirmation mode ('always', 'smart', 'never', 'batch')

        Raises:
            ValueError: If mode is invalid
        """
        valid_modes = ['always', 'smart', 'never', 'batch']
        if mode not in valid_modes:
            raise ValueError(f"Mode must be one of {valid_modes}")

        self.profile.metadata['confirmation_mode'] = mode
        self.profile.save()
        print(DisplayManager.format_success(f"Confirmation mode set to: {mode}"))

    def handle_search(self):
        """Interactive search handler with refinement"""
        print(DisplayManager.format_info("Fuzzy Task Search"))
        print("Search by: task name, command, tags, or description")
        print("Examples: 'gobuster', 'http', 'QUICK_WIN', 'sql'")
        print()

        query = input("Search query (or 'cancel'): ").strip()
        if query.lower() == 'cancel':
            return

        # Perform fuzzy search
        results = self.search_tasks(query, min_score=40)  # Lower threshold for fuzzy

        if not results:
            print(DisplayManager.format_warning(f"No tasks found matching '{query}'"))

            # Suggest lowering threshold
            print("\nTry:")
            print("  1. Broader search term")
            print("  2. Search by tag (QUICK_WIN, OSCP:HIGH)")
            print("  3. 's' - New search")
            return

        # Display results with scores
        print(DisplayManager.format_success(f"Found {len(results)} matching task(s):"))
        print()

        for i, (task, score) in enumerate(results[:20], 1):  # Limit to 20
            status_icon = {
                'completed': '✅',
                'pending': '⏳',
                'in-progress': '🔄'
            }.get(task.status, '❓')

            # Show score as bar
            score_bar = '█' * (score // 10) + '░' * (10 - score // 10)

            print(f"{i:2d}. {status_icon} {task.name} [{score_bar} {score}%]")
            print(f"    ID: {task.id}")

            if task.metadata.get('command'):
                print(f"    Command: {task.metadata['command']}")
            if task.metadata.get('tags'):
                print(f"    Tags: {', '.join(task.metadata['tags'])}")
            print()

        if len(results) > 20:
            print(DisplayManager.format_info(f"... and {len(results) - 20} more results"))

        # Options
        print("\nOptions:")
        print("  [number] - Execute task")
        print("  s        - Refine search")
        print("  c        - Cancel")

        choice = input("\nChoice: ").strip().lower()

        if choice == 's':
            # Recursive refinement
            self.handle_search()
        elif choice == 'c':
            return
        elif choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(results):
                task, _ = results[idx]
                self.execute_task(task)

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
