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
import time
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime
from collections import defaultdict

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
from .history import CommandHistory
from .debug_logger import init_debug_logger, get_debug_logger
from .log_types import LogCategory, LogLevel


class InteractiveSession:
    """Interactive session state machine"""

    # Class variable for test isolation override
    SNAPSHOTS_BASE_DIR = None

    def __init__(self, target: str, resume: bool = False, screened: bool = False, debug_config=None):
        """
        Initialize interactive session

        Args:
            target: Target IP or hostname
            resume: Whether to resume existing session
            screened: Whether to use screened terminal mode
            debug_config: LogConfig for precision debug logging
        """
        self.target = target
        self.screened_mode = screened

        # Initialize debug logger (strategic chokepoint #1: Session initialization)
        self.debug_logger = init_debug_logger(config=debug_config, target=target) if debug_config else init_debug_logger(debug_enabled=False, target=target)
        self.debug_logger.log("Session initialization started", category=LogCategory.SYSTEM_INIT, level=LogLevel.NORMAL, target=target, resume=resume, screened=screened)

        # Load or create profile (strategic chokepoint #2: State loading)
        if TargetProfile.exists(target):
            self.debug_logger.log("Loading existing profile", category=LogCategory.STATE_LOAD, level=LogLevel.NORMAL)
            self.profile = TargetProfile.load(target)
            print(DisplayManager.format_success(f"Loaded profile for {target}"))
            self.debug_logger.log("Profile loaded successfully", category=LogCategory.STATE_LOAD, level=LogLevel.NORMAL,
                                 ports=len(self.profile.ports), findings=len(self.profile.findings), phase=self.profile.phase)
        else:
            self.debug_logger.log("Creating new profile", category=LogCategory.STATE_LOAD, level=LogLevel.NORMAL)
            self.profile = TargetProfile(target)
            self.profile.save()
            print(DisplayManager.format_success(f"Created new profile for {target}"))
            self.debug_logger.log("New profile created and saved", category=LogCategory.STATE_SAVE, level=LogLevel.NORMAL)

        # Initialize components
        self.shortcut_handler = ShortcutHandler(self)
        self.command_history = CommandHistory()
        self.last_action = None

        # Initialize foundation components
        from .components.input_validator import InputValidator
        from .components.error_handler import ErrorHandler
        from .components.loading_indicator import LoadingIndicator
        from .state.checkpoint_manager import CheckpointManager

        self.validator = InputValidator()
        self.error_handler = ErrorHandler(debug_logger=self.debug_logger)
        self.loading_indicator = LoadingIndicator()
        self.checkpoint_mgr = CheckpointManager()

        self.debug_logger.log("Core components initialized", category=LogCategory.SYSTEM_INIT, level=LogLevel.NORMAL)

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

        # Workflow recording state
        self.recording = False
        self.recording_name = None
        self.recording_start = None
        self.recorded_tasks = []

        # Session checkpoint directory
        self.checkpoint_dir = Path.home() / '.crack' / 'sessions'
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)

        # Resume checkpoint if requested
        if resume:
            self.load_checkpoint()
            # Check for interrupted task execution checkpoints
            self._check_interrupted_tasks()

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

                # Display persistent shortcuts footer
                print(DisplayManager.format_shortcuts_footer())

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
                self.error_handler.handle_exception(e, context="main session loop")
                print("Session will continue. Type 'q' to exit safely.")
                input()  # Wait for user to acknowledge error

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

        elif choice_id == 'alternatives':
            # Phase 6.5: Handle alternative commands from main menu
            self.handle_alternative_commands()

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
        # Strategic chokepoint #3: Task execution start
        self.debug_logger.log("Task execution requested", category=LogCategory.EXECUTION_START, level=LogLevel.NORMAL,
                             task_id=task.id, task_name=task.name, task_type=task.metadata.get('type', 'command'))

        print(f"\n{DisplayManager.format_task_summary(task)}")

        # Check if this is a 'scan' type task (needs scan profile selection)
        task_type = task.metadata.get('type', 'command')
        if task_type == 'scan':
            # This is a scan task - redirect to scan profile selection
            scan_profiles = task.metadata.get('scan_profiles', [])
            default_profile = task.metadata.get('default_profile', 'lab-quick')

            if scan_profiles:
                print(DisplayManager.format_info(
                    f"This task requires selecting a scan profile.\n"
                    f"Recommended: {default_profile}"
                ))
                print("\nAvailable scan options shown in main menu (choose one of the numbered scan options)")
                return
            else:
                print(DisplayManager.format_warning("Scan task has no scan profiles defined"))
                return

        command = task.metadata.get('command')
        if not command:
            self.debug_logger.log("Task execution aborted: no command", category=LogCategory.EXECUTION_ERROR, level=LogLevel.MINIMAL,
                                 task_id=task.id)
            print(DisplayManager.format_warning("No command defined for this task"))
            return

        # Phase 5.2: Check if task needs wordlist before execution
        if self._task_needs_wordlist(task):
            if not task.metadata.get('wordlist'):
                print(DisplayManager.format_warning(
                    "\nThis task requires a wordlist but none is selected."
                ))
                print("Hint: Press 'w' to select wordlist, or Enter to use default")

                # Prompt user
                response = input("\nSelect wordlist now? [Y/n]: ").strip()

                if InputProcessor.parse_confirmation(response, default='Y'):
                    # Launch wordlist selection
                    self.shortcut_handler.select_wordlist()

                    # Check if wordlist was selected
                    if not task.metadata.get('wordlist'):
                        print(DisplayManager.format_warning(
                            "No wordlist selected. Using default placeholder."
                        ))
                else:
                    print("Using default wordlist placeholder in command")

        # Replace placeholders
        command = command.replace('{TARGET}', self.profile.target)

        # Phase 5.2: Substitute wordlist placeholder
        if '<WORDLIST>' in command or '{WORDLIST}' in command:
            wordlist_path = task.metadata.get('wordlist', '/usr/share/wordlists/dirb/common.txt')
            command = command.replace('<WORDLIST>', wordlist_path)
            command = command.replace('{WORDLIST}', wordlist_path)

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
            self.debug_logger.log("Task execution cancelled by user", category=LogCategory.EXECUTION_END, level=LogLevel.NORMAL,
                                 task_id=task.id)
            print("Cancelled")
            return

        # Mark task as in-progress
        task.status = 'in-progress'
        task.start_timer()
        self.profile.save()

        # Strategic chokepoint #4: Command execution start
        self.debug_logger.log("Command execution starting", category=LogCategory.EXECUTION_START, level=LogLevel.NORMAL,
                             task_id=task.id, command=command[:100])  # Truncate command for readability

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

                    task.stop_timer()
                    task.mark_complete()
                    self.last_action = f"Completed: {task.name}"
                    # Strategic chokepoint #5: Task completion
                    self.debug_logger.log("Task completed successfully", category=LogCategory.EXECUTION_END, level=LogLevel.NORMAL,
                                         task_id=task.id, elapsed=task.get_elapsed_time() if hasattr(task, 'get_elapsed_time') else None,
                                         findings=len(result.findings) if result.findings else 0)
                else:
                    self.debug_logger.log("Command failed or returned non-zero exit", category=LogCategory.EXECUTION_ERROR, level=LogLevel.MINIMAL,
                                         task_id=task.id, success=result.success)
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
                        task.stop_timer()
                        task.mark_complete()
                        self.last_action = f"Completed: {task.name}"

            except Exception as e:
                self.error_handler.handle_exception(e, context="screened task execution")
                input()  # Wait for user to acknowledge

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

                # Track command execution
                if command:
                    self.command_history.add(
                        command=command,
                        source='task',
                        task_id=task.id,
                        success=(result.returncode == 0)
                    )

                if result.returncode == 0:
                    print(DisplayManager.format_success("Command completed"))
                    task.stop_timer()
                    task.mark_complete()
                    self.last_action = f"Completed: {task.name}"

                    # Record task if workflow recording is active
                    self._record_task(task)
                else:
                    print(DisplayManager.format_warning(
                        f"Command exited with code {result.returncode}"))

                    # Use ErrorHandler to show OSCP-specific suggestions
                    error_msg = f"Task '{task.name}' failed with exit code {result.returncode}"
                    suggestions = self.error_handler.get_suggestions(
                        self.error_handler.categorize_error(
                            subprocess.CalledProcessError(result.returncode, command)
                        ),
                        command
                    )

                    if suggestions:
                        print("\n" + DisplayManager.format_info("Suggested fixes:"))
                        for idx, suggestion in enumerate(suggestions[:3], 1):  # Show top 3
                            print(f"  {idx}. {suggestion}")
                        print()

                    # Ask user if task should be marked complete anyway
                    mark_done = input(DisplayManager.format_confirmation(
                        "Mark task as completed?", default='N'
                    ))

                    if InputProcessor.parse_confirmation(mark_done, default='N'):
                        task.stop_timer()
                        task.mark_complete()
                        self.last_action = f"Completed: {task.name}"

                        # Record task if workflow recording is active
                        self._record_task(task)
                    else:
                        # Mark as failed with metadata
                        task.status = 'failed'
                        task.metadata['failed_at'] = datetime.now().isoformat()
                        task.metadata.setdefault('retry_count', 0)
                        task.metadata['retry_count'] += 1
                        task.metadata['failure_reason'] = f"Exit code {result.returncode}"
                        task.metadata['exit_code'] = result.returncode
                        task.stop_timer()

                        # Log failure
                        self.debug_logger.log("Task marked as failed",
                                             category=LogCategory.EXECUTION_ERROR,
                                             level=LogLevel.NORMAL,
                                             task_id=task.id,
                                             exit_code=result.returncode,
                                             retry_count=task.metadata['retry_count'])

            except Exception as e:
                # Mark task as failed on exception
                task.status = 'failed'
                task.metadata['failed_at'] = datetime.now().isoformat()
                task.metadata.setdefault('retry_count', 0)
                task.metadata['retry_count'] += 1
                task.metadata['failure_reason'] = str(e)
                task.stop_timer()

                # Log and display error with OSCP suggestions
                self.error_handler.handle_exception(e, context="subprocess task execution")
                input()  # Wait for user to acknowledge

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

        # Validate file path
        is_valid, error = self.validator.validate_file_path(filepath, mode='r', must_exist=True)
        if not is_valid:
            self.error_handler.show_error(
                self.error_handler.categorize_error(FileNotFoundError(error)),
                error
            )
            input()  # Wait for user to acknowledge
            return

        try:
            # Parse file with loading indicator
            with LoadingIndicator.spinner(f"Parsing {os.path.basename(filepath)}...") as loader:
                data = ParserRegistry.parse_file(filepath, self.profile.target, self.profile)
                loader.update(message="Saving profile...")

                # Save profile
                self.profile.save()

            print(DisplayManager.format_success("Import complete!"))
            print(f"\nDiscovered {len(self.profile.ports)} port(s)")

            self.last_action = f"Imported {os.path.basename(filepath)}"

            # Check for phase advancement
            PhaseManager.advance_phase(self.profile.phase, self.profile)

        except Exception as e:
            self.error_handler.handle_exception(e, context="scan file import")

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

            # Apply InputValidator for specific fields
            if field['name'] == 'port' and value:
                is_valid, error = self.validator.validate_port(value)
                if not is_valid:
                    self.error_handler.show_error(
                        self.error_handler.categorize_error(ValueError(error)),
                        error
                    )
                    input()  # Wait for user to acknowledge
                    return
                parsed_value = int(value)
            elif field['name'] == 'username' and field['required']:
                # Validate username is not empty
                is_valid, error = self.validator.validate_required({'username': value})
                if not is_valid:
                    self.error_handler.show_error(
                        self.error_handler.categorize_error(ValueError(error)),
                        error
                    )
                    input()  # Wait for user to acknowledge
                    return
                parsed_value = value
            elif field['name'] == 'service' and field['required']:
                # Validate service is not empty
                is_valid, error = self.validator.validate_required({'service': value})
                if not is_valid:
                    self.error_handler.show_error(
                        self.error_handler.categorize_error(ValueError(error)),
                        error
                    )
                    input()  # Wait for user to acknowledge
                    return
                parsed_value = value
            else:
                # Use existing validation
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
            List of (TaskNode, score) tuples, sorted by relevance score descending
        """
        query = query.lower()
        results = []

        def search_node(node):
            """Recursively search task tree with fuzzy matching"""
            # Skip root node
            if node.id == 'root':
                # Only recurse to children
                for child in node.children:
                    search_node(child)
                return

            best_match = (False, 0)

            # Search in task name
            match = self._fuzzy_match(query, node.name)
            if match[1] > best_match[1]:
                best_match = match

            # Search in command (with None check)
            command = node.metadata.get('command')
            if command:
                match = self._fuzzy_match(query, command)
                if match[1] > best_match[1]:
                    best_match = match

            # Search in tags
            for tag in node.metadata.get('tags', []):
                match = self._fuzzy_match(query, tag)
                if match[1] > best_match[1]:
                    best_match = match

            # Search in description (with None check)
            description = node.metadata.get('description')
            if description:
                match = self._fuzzy_match(query, description)
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

        # Return tuples (task, score) for fuzzy search scoring
        return results

    def filter_tasks(self, filter_type: str, filter_value: str = None) -> list:
        """
        Filter tasks by various criteria (ENHANCED)

        Args:
            filter_type: Type of filter ('status', 'tag', 'quick_win', 'port', 'service')
            filter_value: Value to filter by (e.g., 'pending', 'OSCP:HIGH', 'http')

        Returns:
            List of matching TaskNode objects
        """
        results = []

        def filter_node(node):
            """Recursively filter task tree"""
            # Skip root node
            if node.id == 'root':
                # Only recurse to children
                for child in node.children:
                    filter_node(child)
                return

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
            elif filter_type == 'service':
                # NEW: Service filtering
                # Check service in task name, command, or metadata
                service_lower = filter_value.lower()
                command = node.metadata.get('command')
                if (service_lower in node.name.lower() or
                    (command and service_lower in command.lower()) or
                    node.metadata.get('service', '').lower() == service_lower):
                    matched = True

            if matched:
                results.append(node)

            # Recursively filter children
            for child in node.children:
                filter_node(child)

        filter_node(self.profile.task_tree)
        return results

    def _apply_multiple_filters(self, filters: list) -> list:
        """Apply multiple filters with AND logic

        Args:
            filters: List of (filter_type, filter_value) tuples

        Returns:
            List of TaskNode objects matching ALL filters
        """
        # Start with all tasks (gather recursively)
        def get_all_tasks(node):
            tasks = [node] if node.id != 'root' else []
            for child in node.children:
                tasks.extend(get_all_tasks(child))
            return tasks

        results = get_all_tasks(self.profile.task_tree)

        # Apply each filter
        for filter_type, filter_value in filters:
            filtered = self.filter_tasks(filter_type, filter_value)
            # Intersection (AND logic)
            result_ids = {t.id for t in results}
            filtered_ids = {t.id for t in filtered}
            intersection_ids = result_ids & filtered_ids
            results = [t for t in results if t.id in intersection_ids]

        return results

    def handle_filter(self):
        """Interactive task filtering UI"""
        print(DisplayManager.format_info("Task Filter"))
        print("Filter tasks by: status, port, service, or tags\n")

        print("Filter options:")
        print("  1. Status (pending, in-progress, completed)")
        print("  2. Port number (e.g., 80, 443)")
        print("  3. Service (e.g., http, smb, ssh)")
        print("  4. Tag (e.g., QUICK_WIN, OSCP:HIGH)")
        print("  5. Multiple filters (combine filters)")
        print()

        choice = input("Filter by [1-5]: ").strip()

        if choice == '1':
            status = input("Status (pending/in-progress/completed): ").strip().lower()
            results = self.filter_tasks('status', status)

        elif choice == '2':
            port = input("Port: ").strip()
            results = self.filter_tasks('port', port)

        elif choice == '3':
            service = input("Service: ").strip().lower()
            results = self.filter_tasks('service', service)

        elif choice == '4':
            tag = input("Tag: ").strip().upper()
            results = self.filter_tasks('tag', tag)

        elif choice == '5':
            # Multiple filters
            print("\nEnter filters (one per line, empty line to finish):")
            filters = []
            while True:
                filter_input = input("Filter (type:value): ").strip()
                if not filter_input:
                    break
                if ':' in filter_input:
                    ftype, fvalue = filter_input.split(':', 1)
                    filters.append((ftype.strip(), fvalue.strip()))

            # Apply multiple filters
            results = self._apply_multiple_filters(filters)

        else:
            print(DisplayManager.format_error("Invalid choice"))
            return

        # Display results
        if not results:
            print(DisplayManager.format_warning("No matching tasks found"))
            return

        print(DisplayManager.format_success(f"Found {len(results)} matching task(s):"))
        print()

        for i, task in enumerate(results[:20], 1):
            status_icon = {
                'completed': '✅',
                'pending': '⏳',
                'in-progress': '🔄'
            }.get(task.status, '❓')

            print(f"{i:2d}. {status_icon} {task.name}")
            if task.metadata.get('command'):
                print(f"    Command: {task.metadata['command'][:60]}...")
            print()

        if len(results) > 20:
            print(DisplayManager.format_info(f"... and {len(results) - 20} more"))

        # Options
        print("\nOptions:")
        print("  [number] - Execute task")
        print("  f        - New filter")
        print("  c        - Cancel")

        action = input("\nChoice: ").strip().lower()

        if action == 'f':
            self.handle_filter()  # Recursive
        elif action.isdigit():
            idx = int(action) - 1
            if 0 <= idx < len(results):
                self.execute_task(results[idx])


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
            'nav_stack': getattr(self, 'nav_stack', []),
            'last_action': getattr(self, 'last_action', None),
            'command_history': self.command_history.to_dict() if hasattr(self, 'command_history') else {},
            'timestamp': datetime.now().isoformat()
        }

        with open(checkpoint_file, 'w') as f:
            json.dump(checkpoint_data, f, indent=2)

    def handle_command_history(self):
        """Browse and search command history"""
        print(DisplayManager.format_info("Command History"))
        print("Search previous commands or browse recent executions\n")

        print("Options:")
        print("  1. Search commands")
        print("  2. Show recent (last 20)")
        print("  3. Filter by source (template/manual/task)")
        print("  4. Show successful only")
        print()

        choice = input("Choice [1-4]: ").strip()

        if choice == '1':
            # Search
            query = input("\nSearch query: ").strip()
            if not query:
                return

            results = self.command_history.search(query, self._fuzzy_match)

            if not results:
                print(DisplayManager.format_warning(f"No commands matching '{query}'"))
                return

            print(DisplayManager.format_success(f"Found {len(results)} matching command(s):"))
            print()

            for i, (cmd, score) in enumerate(results[:20], 1):
                success_icon = '✓' if cmd['success'] else '✗'
                score_bar = '█' * (score // 10)

                print(f"{i:2d}. [{success_icon}] [{score_bar} {score}%]")
                print(f"    Command: {cmd['command']}")
                print(f"    Source: {cmd['source']} | Time: {cmd['timestamp'][:19]}")
                print()

        elif choice == '2':
            # Recent
            recent = self.command_history.get_recent(20)

            if not recent:
                print(DisplayManager.format_warning("No command history"))
                return

            print(DisplayManager.format_success(f"Recent {len(recent)} command(s):"))
            print()

            for i, cmd in enumerate(recent, 1):
                success_icon = '✓' if cmd['success'] else '✗'
                print(f"{i:2d}. [{success_icon}] {cmd['command']}")
                print(f"    Source: {cmd['source']} | {cmd['timestamp'][:19]}")
                print()

        elif choice == '3':
            # Filter by source
            source = input("\nSource (template/manual/task): ").strip().lower()
            filtered = [cmd for cmd in self.command_history.commands if cmd['source'] == source]

            if not filtered:
                print(DisplayManager.format_warning(f"No commands from source '{source}'"))
                return

            print(DisplayManager.format_success(f"Found {len(filtered)} command(s) from '{source}':"))
            for i, cmd in enumerate(filtered[-20:], 1):
                print(f"{i:2d}. {cmd['command']}")
                print(f"    {cmd['timestamp'][:19]}")
                print()

        elif choice == '4':
            # Successful only
            successful = [cmd for cmd in self.command_history.commands if cmd['success']]

            if not successful:
                print(DisplayManager.format_warning("No successful commands"))
                return

            print(DisplayManager.format_success(f"Found {len(successful)} successful command(s):"))
            for i, cmd in enumerate(successful[-20:], 1):
                print(f"{i:2d}. {cmd['command']}")
                print(f"    {cmd['timestamp'][:19]}")
                print()

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

            # Load command history if available
            if 'command_history' in data:
                self.command_history = CommandHistory.from_dict(data['command_history'])

            print(DisplayManager.format_success("Resumed previous session"))

        except Exception as e:
            self.error_handler.log_error(e, context="checkpoint loading")
            print(DisplayManager.format_warning(f"Could not load checkpoint: {e}"))

    def _check_interrupted_tasks(self):
        """Check for and offer to resume interrupted task execution checkpoints"""
        interrupted = self.checkpoint_mgr.detect_interrupted_session(self.target)

        if not interrupted:
            return

        print(DisplayManager.format_warning(
            f"\n⚠ Found {len(interrupted)} interrupted task(s) from previous session:"
        ))

        # Show up to 5 interrupted tasks
        for task in interrupted[:5]:
            timestamp = task.get('timestamp', 'unknown')
            # Parse ISO timestamp to readable format
            try:
                from datetime import datetime
                dt = datetime.fromisoformat(timestamp)
                timestamp_str = dt.strftime('%Y-%m-%d %H:%M:%S')
            except:
                timestamp_str = timestamp

            print(f"  • {task['task_id']}/{task['stage_id']} - {task['status']} ({timestamp_str})")

        if len(interrupted) > 5:
            print(f"  ... and {len(interrupted) - 5} more")

        print()
        response = input("Resume interrupted tasks? [Y/n]: ").strip()

        if InputProcessor.parse_confirmation(response, default='Y'):
            # Offer to resume each task
            for task_info in interrupted[:3]:  # Only offer first 3 to avoid overwhelming user
                self._offer_task_resume(task_info)

            # Clear remaining checkpoints
            if len(interrupted) > 3:
                print(f"\n{len(interrupted) - 3} other checkpoint(s) will be cleared.")
                for task_info in interrupted[3:]:
                    self.checkpoint_mgr.clear_checkpoint(
                        task_info['task_id'],
                        task_info['stage_id'],
                        self.target
                    )
        else:
            # User declined - clear all checkpoints
            print("Clearing all interrupted task checkpoints...")
            count = self.checkpoint_mgr.clear_all_checkpoints(self.target)
            print(DisplayManager.format_success(f"Cleared {count} checkpoint(s)"))

    def _offer_task_resume(self, task_info: Dict[str, str]):
        """Offer to resume a specific interrupted task"""
        print(f"\n─── Task: {task_info['task_id']} ───")
        print(f"Stage: {task_info['stage_id']}")

        # Load checkpoint state
        state = self.checkpoint_mgr.load_checkpoint(
            task_info['task_id'],
            task_info['stage_id'],
            self.target
        )

        if not state:
            print(DisplayManager.format_warning("Checkpoint data corrupted or missing"))
            return

        # Show checkpoint details
        print(f"Status: {state.get('status', 'unknown')}")
        command = state.get('command', 'N/A')
        if len(command) > 80:
            command = command[:77] + '...'
        print(f"Command: {command}")

        partial_output = state.get('partial_output', '')
        if partial_output:
            line_count = len(partial_output.split('\n'))
            print(f"Output captured: {line_count} lines")

        print()
        response = input("Resume this task? [Y/n]: ").strip()

        if InputProcessor.parse_confirmation(response, default='Y'):
            print(DisplayManager.format_info(
                "\n[Task resume feature]"
                "\nThis will be implemented when task execution is refactored"
                "\nfor checkpoint support. For now, the checkpoint will be cleared"
                "\nand you can manually re-run the task."
            ))
            # TODO: Implement actual task resume when execution supports it
            # For now, just clear the checkpoint
            self.checkpoint_mgr.clear_checkpoint(
                task_info['task_id'],
                task_info['stage_id'],
                self.target
            )
            print(DisplayManager.format_success("Checkpoint cleared. Re-run task manually."))
        else:
            # Clear checkpoint if user declined
            self.checkpoint_mgr.clear_checkpoint(
                task_info['task_id'],
                task_info['stage_id'],
                self.target
            )
            print("Checkpoint cleared.")

    def handle_time_tracker(self):
        """Time tracking dashboard - show time statistics"""
        from .time_tracker import TimeStats

        print(DisplayManager.format_info("Time Tracker Dashboard"))
        print("Track time spent on target enumeration\n")

        # Calculate stats
        total_time = TimeStats.get_total_time(self.profile.task_tree)
        breakdown = TimeStats.get_phase_breakdown(self.profile.task_tree)
        longest = TimeStats.get_longest_tasks(self.profile.task_tree, 10)
        running = TimeStats.get_running_tasks(self.profile.task_tree)
        avg_time = TimeStats.get_average_task_time(self.profile.task_tree)
        estimated_remaining = TimeStats.estimate_remaining_time(self.profile.task_tree)

        # Total time
        print(f"{DisplayManager.format_success('Total Time Spent:')}")
        print(f"  {TimeStats.format_duration(total_time)}\n")

        # Average task time
        if avg_time:
            print(f"{DisplayManager.format_info('Average Task Time:')}")
            print(f"  {TimeStats.format_duration(avg_time)}\n")

        # Estimated remaining
        if estimated_remaining:
            print(f"{DisplayManager.format_info('Estimated Time Remaining:')}")
            print(f"  {TimeStats.format_duration(estimated_remaining)} ({len(self.profile.task_tree.get_all_pending())} pending tasks)\n")

        # Breakdown by phase/category
        if breakdown:
            print(f"{DisplayManager.format_info('Time by Category:')}")
            # Sort by time descending
            sorted_breakdown = sorted(breakdown.items(), key=lambda x: x[1], reverse=True)
            for category, seconds in sorted_breakdown:
                formatted = TimeStats.format_duration(seconds)
                percentage = (seconds / total_time * 100) if total_time > 0 else 0
                bar_length = int(percentage / 5)  # 20 chars max
                bar = '█' * bar_length + '░' * (20 - bar_length)
                print(f"  {category:15s} {bar} {formatted} ({percentage:.0f}%)")
            print()

        # Longest tasks
        if longest:
            print(f"{DisplayManager.format_info('Longest Running Tasks:')}")
            for i, (task, duration) in enumerate(longest, 1):
                formatted = TimeStats.format_duration(duration)
                status_icon = {
                    'completed': '✅',
                    'in-progress': '🔄',
                    'pending': '⏳'
                }.get(task.status, '❓')
                print(f"  {i:2d}. {status_icon} {task.name:45s} {formatted}")
            print()

        # Running tasks
        if running:
            print(f"{DisplayManager.format_warning('Currently Running:')}")
            for task in running:
                print(f"  • {task.name} - {task.get_formatted_duration()}")
            print()
        elif total_time == 0:
            print(DisplayManager.format_info("No tasks timed yet. Execute tasks to start tracking time.\n"))

    def handle_port_lookup(self):
        """Port lookup reference tool"""
        from .port_reference import PortReference

        print(DisplayManager.format_info("Port Lookup Reference"))
        print("Quick reference for common OSCP ports\n")

        print("Options:")
        print("  1. Lookup by port number")
        print("  2. Search by service name")
        print("  3. Show all common ports")
        print()

        choice = input("Choice [1-3]: ").strip()

        if choice == '1':
            # Lookup by port
            port_input = input("\nPort number: ").strip()
            try:
                port = int(port_input)
            except ValueError:
                print(DisplayManager.format_error("Invalid port number"))
                return

            port_info = PortReference.lookup(port)
            if not port_info:
                print(DisplayManager.format_warning(f"No reference data for port {port}"))
                print(f"\nTry running: nmap -p {port} --script banner {self.target}")
                return

            # Display port information
            self._display_port_info(port_info)

        elif choice == '2':
            # Search by service
            service = input("\nService name (e.g., http, smb, ssh): ").strip()
            results = PortReference.search_by_service(service)

            if not results:
                print(DisplayManager.format_warning(f"No ports found for service '{service}'"))
                return

            print(DisplayManager.format_success(f"Found {len(results)} port(s) for '{service}':"))
            print()

            for port_info in results:
                print(f"Port {port_info.port} - {port_info.service}")
                print(f"  {port_info.description}")
                print()

            # Ask if user wants details on specific port
            if len(results) == 1:
                detail_input = input("Show detailed enumeration commands? [Y/n]: ").strip()
                if InputProcessor.parse_confirmation(detail_input, default='Y'):
                    self._display_port_info(results[0])

        elif choice == '3':
            # Show all
            all_ports = PortReference.list_all()

            print(DisplayManager.format_success(f"Common OSCP ports ({len(all_ports)} total):"))
            print()

            for port_info in all_ports:
                print(f"{port_info.port:5d} - {port_info.service:15s} {port_info.description}")

            print("\nType 'pl' again and enter a port number for detailed enumeration commands")

    def _display_port_info(self, port_info):
        """Display detailed port information"""
        print(f"\n{DisplayManager.format_success(f'Port {port_info.port} - {port_info.service}')}")
        print(f"{port_info.description}\n")

        # Enumeration commands
        print(f"{DisplayManager.format_info('Enumeration Commands:')}")
        for i, cmd in enumerate(port_info.enum_commands, 1):
            # Replace <TARGET> with actual target if available
            display_cmd = cmd.replace('<TARGET>', self.target)
            print(f"  {i}. {display_cmd}")
        print()

        # Quick wins
        if port_info.quick_wins:
            print(f"{DisplayManager.format_info('Quick Wins:')}")
            for win in port_info.quick_wins:
                # Replace <TARGET> in quick wins too
                display_win = win.replace('<TARGET>', self.target)
                print(f"  ⚡ {display_win}")
            print()

        # Common vulnerabilities
        if port_info.common_vulns:
            print(f"{DisplayManager.format_info('Common Vulnerabilities:')}")
            for vuln in port_info.common_vulns:
                print(f"  🔴 {vuln}")
            print()

    def handle_quick_execute(self, command: str = None):
        """
        Execute shell command without task creation (shortcut: qe)

        Args:
            command: Optional command to execute directly
        """
        print(DisplayManager.format_info("Quick Execute"))
        print("=" * 50)

        # Get command
        if not command:
            command = input("\nEnter command to execute (or 'c' to cancel): ").strip()

        if command.lower() == 'c':
            print("Cancelled")
            return

        # Validate
        if not self._validate_command(command):
            return

        # Show command
        print(f"\nCommand: {command}\n")

        # Confirm based on mode
        mode = self.profile.metadata.get('confirmation_mode', 'smart')
        if mode != 'never':
            print(DisplayManager.format_warning("This will execute immediately without task tracking."))
            confirm = input(DisplayManager.format_confirmation("Execute?", default='Y'))
            if not InputProcessor.parse_confirmation(confirm, default='Y'):
                print("Cancelled")
                return

        # Execute
        exit_code, stdout, stderr = self._execute_command(command)

        # Show result
        if exit_code == 0:
            print(f"\n{DisplayManager.format_success(f'Command completed (exit code: {exit_code})')}")
        else:
            print(f"\n{DisplayManager.format_error(f'Command failed (exit code: {exit_code})')}")
            if stderr:
                print(f"Error: {stderr}")

        # Optional logging
        self._log_execution(command, exit_code, stdout, stderr)

        self.last_action = f"Quick execute: {command[:50]}"

    def _execute_command(self, command: str) -> tuple:
        """
        Execute command and return (exit_code, output, stderr)

        Args:
            command: Shell command to execute

        Returns:
            Tuple of (exit_code, stdout, stderr)
        """
        import subprocess

        try:
            print(DisplayManager.format_info("Executing..."))
            print("─" * 50)

            # Execute with real-time output
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Line buffered
            )

            # Capture output
            stdout_lines = []
            stderr_lines = []

            # Read stdout in real-time
            for line in process.stdout:
                print(line, end='')
                stdout_lines.append(line)

            # Wait for completion
            process.wait()

            # Read any stderr
            stderr = process.stderr.read()
            if stderr:
                stderr_lines.append(stderr)
                print(stderr, end='')

            print("─" * 50)

            exit_code = process.returncode
            stdout_text = ''.join(stdout_lines)
            stderr_text = ''.join(stderr_lines)

            return (exit_code, stdout_text, stderr_text)

        except KeyboardInterrupt:
            print("\n\n⚠ Command interrupted by user")
            process.terminate()
            return (-1, "", "Interrupted by user")
        except Exception as e:
            self.error_handler.log_error(e, context="command execution")
            print(f"\n✗ Execution error: {e}")
            return (-1, "", str(e))

    def _log_execution(self, command: str, exit_code: int, output: str, stderr: str):
        """
        Optionally log execution to profile notes

        Args:
            command: Executed command
            exit_code: Exit code from command
            output: stdout from command
            stderr: stderr from command
        """
        confirm = input(DisplayManager.format_confirmation("Log to profile notes?", default='N'))

        if not InputProcessor.parse_confirmation(confirm, default='N'):
            return

        # Create note
        timestamp = datetime.now().isoformat()
        note = f"""Quick Execute: {command}
Exit Code: {exit_code}
Output: {output[:500]}{"..." if len(output) > 500 else ""}
{"Error: " + stderr if stderr else ""}
"""

        self.profile.add_note(
            note=note,
            source='quick-execute'
        )
        self.profile.save()

        print(DisplayManager.format_success("Command logged to notes"))

    def _validate_command(self, command: str) -> bool:
        """
        Basic command validation (optional safety check)

        Args:
            command: Command to validate

        Returns:
            True if command is safe to execute
        """
        if not command or not command.strip():
            print(DisplayManager.format_error("Command cannot be empty"))
            return False

        # Optional: warn about dangerous commands
        dangerous_patterns = ['rm -rf /', 'dd if=/dev/zero', 'mkfs', ':(){']
        for pattern in dangerous_patterns:
            if pattern in command:
                print(DisplayManager.format_warning(f"⚠ Potentially destructive command detected: {pattern}"))
                confirm = input("Are you sure? [y/N]: ")
                if not InputProcessor.parse_confirmation(confirm, default='N'):
                    return False

        return True

    def handle_quick_export(self):
        """Export current view/data to file or clipboard (shortcut: qx)"""
        print(DisplayManager.format_info("Quick Export"))
        print("=" * 50)

        # Show export menu
        choices = [
            {'id': 'status', 'label': 'Full status report (markdown)'},
            {'id': 'tasks', 'label': 'Task tree (text tree format)'},
            {'id': 'findings', 'label': 'Findings only (markdown list)'},
            {'id': 'credentials', 'label': 'Credentials only (markdown table)'},
            {'id': 'notes', 'label': 'Notes only (markdown list)'},
            {'id': 'ports', 'label': 'Port scan results (text)'},
            {'id': 'profile', 'label': 'Full profile (JSON)'}
        ]

        print("\nSelect what to export:")
        for i, choice in enumerate(choices, 1):
            print(f"  {i}. {choice['label']}")

        # Get selection
        user_input = input("\nChoice [1-7]: ").strip()
        if not user_input.isdigit() or int(user_input) < 1 or int(user_input) > len(choices):
            print("Invalid choice")
            return

        selected = choices[int(user_input) - 1]
        export_type = selected['id']

        # Get export destination
        has_clipboard = self._has_clipboard()

        print("\nExport to:")
        if has_clipboard:
            print("  [c] Clipboard")
        print("  [f] File (default)")
        if has_clipboard:
            print("  [b] Both")
        print("  [x] Cancel")

        dest = input("\nDestination [f]: ").strip().lower() or 'f'

        if dest == 'x':
            print("Cancelled")
            return

        # Get format
        if export_type != 'profile':  # Profile is always JSON
            print("\nExport format:")
            print("  [t] Plain text")
            print("  [m] Markdown (default)")
            print("  [j] JSON")

            format_choice = input("\nFormat [m]: ").strip().lower() or 'm'
            format_map = {'t': 'text', 'm': 'markdown', 'j': 'json'}
            format_type = format_map.get(format_choice, 'markdown')
        else:
            format_type = 'json'

        # Generate content
        print(f"\nExporting {export_type} to {format_type}...")

        content = self._generate_export_content(export_type, format_type)

        if not content:
            print(DisplayManager.format_warning(f"No {export_type} to export"))
            return

        # Export to clipboard
        if dest in ['c', 'b'] and has_clipboard:
            if self._copy_to_clipboard(content):
                print(DisplayManager.format_success("✓ Copied to clipboard"))
            else:
                print(DisplayManager.format_warning("✗ Clipboard copy failed"))

        # Export to file
        if dest in ['f', 'b']:
            ext_map = {'text': 'txt', 'markdown': 'md', 'json': 'json'}
            ext = ext_map.get(format_type, 'txt')

            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{export_type}_{timestamp}.{ext}"

            export_path = self._get_export_dir() / filename
            export_path.write_text(content)

            print(DisplayManager.format_success(f"✓ Exported to: {export_path}"))
            print(f"  Size: {len(content)} bytes")

            # Offer to view
            view = input("\nView file? [y/N]: ").strip().lower()
            if view == 'y':
                print("\n" + "─" * 50)
                print(content)
                print("─" * 50)

        self.last_action = f"Exported {export_type}"

    def _get_export_dir(self) -> Path:
        """Get export directory for current target"""
        export_base = Path.home() / '.crack' / 'exports'
        target_dir = export_base / self.target
        target_dir.mkdir(parents=True, exist_ok=True)
        return target_dir

    def _has_clipboard(self) -> bool:
        """Check if clipboard tools available"""
        import shutil
        return shutil.which('xclip') is not None or shutil.which('xsel') is not None

    def _copy_to_clipboard(self, content: str) -> bool:
        """Copy content to clipboard"""
        import subprocess
        import shutil

        try:
            # Try xclip first
            if shutil.which('xclip'):
                subprocess.run(
                    ['xclip', '-selection', 'clipboard'],
                    input=content,
                    text=True,
                    check=True
                )
                return True
            # Fallback to xsel
            elif shutil.which('xsel'):
                subprocess.run(
                    ['xsel', '--clipboard', '--input'],
                    input=content,
                    text=True,
                    check=True
                )
                return True
        except subprocess.CalledProcessError:
            return False

        return False

    def _generate_export_content(self, export_type: str, format_type: str) -> str:
        """Generate export content based on type and format"""
        if export_type == 'status':
            return self._format_status(format_type)
        elif export_type == 'tasks':
            return self._format_task_tree(format_type)
        elif export_type == 'findings':
            return self._format_findings(format_type)
        elif export_type == 'credentials':
            return self._format_credentials(format_type)
        elif export_type == 'notes':
            return self._format_notes(format_type)
        elif export_type == 'ports':
            return self._format_ports(format_type)
        elif export_type == 'profile':
            return json.dumps(self.profile.to_dict(), indent=2)

        return ""

    def _format_status(self, format_type: str = 'markdown') -> str:
        """Format full status report"""
        from ..formatters.console import ConsoleFormatter
        from ..recommendations.engine import RecommendationEngine

        recommendations = RecommendationEngine.get_recommendations(self.profile)

        if format_type == 'json':
            return json.dumps({
                'profile': self.profile.to_dict(),
                'recommendations': recommendations
            }, indent=2)

        else:  # text/markdown
            return ConsoleFormatter.format_profile(self.profile, recommendations)

    def _format_task_tree(self, format_type: str = 'text') -> str:
        """Format task tree for export"""
        if format_type == 'json':
            return json.dumps(self.profile.task_tree.to_dict(), indent=2)

        else:  # text/markdown (same tree format)
            from ..formatters.console import ConsoleFormatter
            return ConsoleFormatter.format_task_tree(self.profile.task_tree)

    def _format_findings(self, format_type: str = 'markdown') -> str:
        """Format findings for export"""
        if format_type == 'json':
            return json.dumps(self.profile.findings, indent=2)

        elif format_type == 'markdown':
            output = f"# Findings - {self.profile.target}\n\n"
            output += f"Exported: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"

            if not self.profile.findings:
                output += "No findings documented yet.\n"
                return output

            for i, finding in enumerate(self.profile.findings, 1):
                output += f"## {i}. {finding.get('type', 'Finding').title()}\n\n"
                output += f"**Description**: {finding['description']}\n\n"
                output += f"**Source**: {finding['source']}\n\n"
                output += f"**Timestamp**: {finding['timestamp']}\n\n"
                if 'port' in finding:
                    output += f"**Port**: {finding['port']}\n\n"
                output += "---\n\n"

            return output

        else:  # text
            output = f"Findings - {self.profile.target}\n"
            output += "=" * 50 + "\n\n"

            for i, finding in enumerate(self.profile.findings, 1):
                output += f"{i}. [{finding.get('type', 'Finding')}] {finding['description']}\n"
                output += f"   Source: {finding['source']}\n"
                output += f"   Time: {finding['timestamp']}\n\n"

            return output

    def _format_credentials(self, format_type: str = 'markdown') -> str:
        """Format credentials for export"""
        if format_type == 'json':
            return json.dumps(self.profile.credentials, indent=2)

        elif format_type == 'markdown':
            output = f"# Credentials - {self.profile.target}\n\n"
            output += f"Exported: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"

            if not self.profile.credentials:
                output += "No credentials documented yet.\n"
                return output

            output += "| Username | Password | Service | Port | Source |\n"
            output += "|----------|----------|---------|------|--------|\n"

            for cred in self.profile.credentials:
                username = cred.get('username', 'N/A')
                password = cred.get('password') or 'N/A'
                service = cred.get('service', 'N/A')
                port = cred.get('port', 'N/A')
                source = cred.get('source', 'N/A')
                output += f"| {username} | {password} | {service} | {port} | {source} |\n"

            return output

        else:  # text
            output = f"Credentials - {self.profile.target}\n"
            output += "=" * 50 + "\n\n"

            for i, cred in enumerate(self.profile.credentials, 1):
                output += f"{i}. {cred.get('username', 'N/A')} / {cred.get('password', 'N/A')}\n"
                output += f"   Service: {cred.get('service', 'N/A')}\n"
                output += f"   Port: {cred.get('port', 'N/A')}\n"
                output += f"   Source: {cred.get('source', 'N/A')}\n\n"

            return output

    def _format_notes(self, format_type: str = 'markdown') -> str:
        """Format notes for export"""
        if format_type == 'json':
            return json.dumps(self.profile.notes, indent=2)

        elif format_type == 'markdown':
            output = f"# Notes - {self.profile.target}\n\n"
            output += f"Exported: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"

            if not self.profile.notes:
                output += "No notes yet.\n"
                return output

            for i, note in enumerate(self.profile.notes, 1):
                output += f"## {i}. Note\n\n"
                output += f"{note['note']}\n\n"
                output += f"**Source**: {note['source']}\n\n"
                output += f"**Timestamp**: {note['timestamp']}\n\n"
                output += "---\n\n"

            return output

        else:  # text
            output = f"Notes - {self.profile.target}\n"
            output += "=" * 50 + "\n\n"

            for i, note in enumerate(self.profile.notes, 1):
                output += f"{i}. {note['note']}\n"
                output += f"   Source: {note['source']}\n"
                output += f"   Time: {note['timestamp']}\n\n"

            return output

    def _format_ports(self, format_type: str = 'text') -> str:
        """Format port scan results for export"""
        if format_type == 'json':
            return json.dumps(self.profile.ports, indent=2)

        elif format_type == 'markdown':
            output = f"# Port Scan Results - {self.profile.target}\n\n"
            output += f"Exported: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"

            if not self.profile.ports:
                output += "No ports discovered yet.\n"
                return output

            output += "| Port | State | Service | Version | Source |\n"
            output += "|------|-------|---------|---------|--------|\n"

            for port, info in sorted(self.profile.ports.items()):
                state = info.get('state', 'unknown')
                service = info.get('service', 'unknown')
                version = info.get('version', '')
                source = info.get('source', 'N/A')
                output += f"| {port} | {state} | {service} | {version} | {source} |\n"

            return output

        else:  # text
            output = f"Port Scan Results - {self.profile.target}\n"
            output += "=" * 50 + "\n\n"

            for port, info in sorted(self.profile.ports.items()):
                output += f"PORT {port}/{info.get('protocol', 'tcp')}\n"
                output += f"  State: {info.get('state', 'unknown')}\n"
                output += f"  Service: {info.get('service', 'unknown')}\n"
                if info.get('version'):
                    output += f"  Version: {info['version']}\n"
                output += f"  Source: {info.get('source', 'N/A')}\n\n"

            return output

    def _get_retryable_tasks(self) -> list:
        """Get tasks that can be retried (failed or completed)"""
        all_tasks = self.profile.task_tree.get_all_tasks()

        retryable = []
        for task in all_tasks:
            # Failed tasks (priority)
            if task.status == 'failed':
                retryable.append(task)
            # Completed tasks (can re-run)
            elif task.status == 'completed' and task.metadata.get('command'):
                retryable.append(task)

        # Sort: failed first (by failed_at descending), then completed (by last_run descending)
        # Tasks without timestamps go to end of their category
        def sort_key(t):
            if t.status == 'failed':
                # Priority 0 = failed tasks come first
                # For timestamp, invert so newest is first (empty string '' sorts last)
                failed_at = t.metadata.get('failed_at', '')
                # Invert timestamp: prepend '-' to make newer sort before older
                return (0, failed_at if failed_at else '', -1 if failed_at else 0)
            else:
                # Priority 1 = completed tasks come second
                last_run = t.metadata.get('last_run', t.metadata.get('completed_at', ''))
                return (1, last_run if last_run else '', -1 if last_run else 0)

        # Sort ascending by priority, descending within each priority by timestamp
        retryable.sort(key=sort_key, reverse=False)
        # Now manually reverse timestamps within each category
        failed_tasks = [t for t in retryable if t.status == 'failed']
        completed_tasks = [t for t in retryable if t.status == 'completed']

        # Sort each group by timestamp descending (newest first)
        failed_tasks.sort(key=lambda t: t.metadata.get('failed_at', ''), reverse=True)
        completed_tasks.sort(key=lambda t: t.metadata.get('last_run', t.metadata.get('completed_at', '')), reverse=True)

        # Combine: failed first, then completed
        retryable = failed_tasks + completed_tasks

        return retryable

    def _display_retry_menu(self, tasks: list) -> dict:
        """Display menu of retryable tasks"""
        print(DisplayManager.format_info("Task Retry"))
        print("=" * 50)

        if not tasks:
            print(DisplayManager.format_warning("No failed or completed tasks to retry"))
            return None

        # Separate failed and completed
        failed = [t for t in tasks if t.status == 'failed']
        completed = [t for t in tasks if t.status == 'completed']

        idx = 1
        task_map = {}

        if failed:
            print("\n❌ Failed tasks:")
            for task in failed:
                exit_code = task.metadata.get('exit_code', 'unknown')
                command = task.metadata.get('command', 'N/A')
                error = task.metadata.get('error', 'No error details')
                last_run = task.metadata.get('last_run', task.metadata.get('completed_at', 'Unknown'))

                print(f"  {idx}. {task.name} (Exit code: {exit_code})")
                print(f"     Command: {command[:80]}{'...' if len(command) > 80 else ''}")
                print(f"     Error: {error[:100]}{'...' if len(error) > 100 else ''}")
                print(f"     Last attempt: {last_run}\n")

                task_map[idx] = task
                idx += 1

        if completed:
            print("\n✓ Completed tasks (can re-run):")
            for task in completed[:5]:  # Limit to 5 most recent
                command = task.metadata.get('command', 'N/A')
                last_run = task.metadata.get('last_run', task.metadata.get('completed_at', 'Unknown'))

                print(f"  {idx}. {task.name} (Exit code: 0)")
                print(f"     Command: {command[:80]}{'...' if len(command) > 80 else ''}")
                print(f"     Last run: {last_run}\n")

                task_map[idx] = task
                idx += 1

        return task_map

    def _edit_command(self, current_command: str) -> Optional[str]:
        """Allow user to edit command inline"""
        print("\nCurrent command:")
        print(current_command)
        print()
        print("Common fixes:")
        print("  - Fix file paths")
        print("  - Adjust parameters")
        print("  - Change wordlist")
        print("  - Modify output location")
        print()

        new_command = input("Edit command (or press Enter to keep): ").strip()

        if not new_command:
            return current_command

        # Show changes
        if new_command != current_command:
            print("\nNew command:")
            print(new_command)
            print()

            # Optional: highlight changes (simple diff)
            print("Changes detected:")
            old_parts = current_command.split()
            new_parts = new_command.split()

            for i, (old, new) in enumerate(zip(old_parts, new_parts)):
                if old != new:
                    print(f"  - {old} → {new}")

            print()

        return new_command

    def _retry_task(self, task, command: str = None) -> bool:
        """Retry task execution with optional new command"""
        if command is None:
            command = task.metadata.get('command')

        if not command:
            print(DisplayManager.format_error("No command found for task"))
            return False

        # Replace placeholders
        command = command.replace('{TARGET}', self.profile.target)
        command = command.replace('<TARGET>', self.profile.target)

        print(f"Executing {task.name}...")
        print("─" * 50)

        # Execute using subprocess
        import subprocess
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True
            )

            print(result.stdout)
            if result.stderr:
                print(result.stderr)

            print("─" * 50)

            # Update task status
            if result.returncode == 0:
                task.status = 'completed'
                print(DisplayManager.format_success(f"Task completed successfully (exit code: {result.returncode})"))
            else:
                task.status = 'failed'
                # Add failed_at timestamp and increment retry_count
                task.metadata['failed_at'] = datetime.now().isoformat()
                task.metadata.setdefault('retry_count', 0)
                task.metadata['retry_count'] += 1
                task.metadata['failure_reason'] = result.stderr if result.stderr else f"Exit code {result.returncode}"
                print(DisplayManager.format_error(f"Task failed (exit code: {result.returncode})"))

            # Update metadata
            task.metadata['exit_code'] = result.returncode
            task.metadata['last_run'] = datetime.now().isoformat()

            # Preserve original command if this is a retry with edited command
            if 'original_command' not in task.metadata:
                task.metadata['original_command'] = task.metadata.get('command')

            if command != task.metadata.get('original_command'):
                task.metadata['retry_command'] = command

            if result.stderr:
                task.metadata['error'] = result.stderr

            # Add retry history
            if 'retry_history' not in task.metadata:
                task.metadata['retry_history'] = []

            task.metadata['retry_history'].append({
                'timestamp': datetime.now().isoformat(),
                'command': command,
                'exit_code': result.returncode,
                'success': result.returncode == 0
            })

            # Track command in history
            if command:
                self.command_history.add(
                    command=command,
                    source='retry',
                    task_id=task.id,
                    success=(result.returncode == 0)
                )

            # Save
            self.profile.save()
            print(DisplayManager.format_success("Task status updated"))

            return result.returncode == 0

        except Exception as e:
            self.error_handler.handle_exception(e, context="alternative command execution")
            input()  # Wait for user to acknowledge
            return False

    def handle_task_retry(self, task_id: str = None):
        """Retry failed or completed tasks with optional editing"""
        # Get retryable tasks
        tasks = self._get_retryable_tasks()

        if not tasks:
            print(DisplayManager.format_warning("No tasks available to retry"))
            return

        # Display menu
        task_map = self._display_retry_menu(tasks)

        if not task_map:
            return

        # Get selection
        if task_id:
            # Find by task ID
            selected_task = next((t for t in tasks if t.id == task_id), None)
            if not selected_task:
                print(DisplayManager.format_error(f"Task not found: {task_id}"))
                return
        else:
            # Get from menu
            choice = input(f"\nSelect task to retry [1-{len(task_map)}] or task ID: ").strip()

            if choice.isdigit():
                task_num = int(choice)
                selected_task = task_map.get(task_num)
            else:
                # Try as task ID
                selected_task = next((t for t in tasks if t.id == choice), None)

            if not selected_task:
                print("Invalid selection")
                return

        # Show task details
        print(f"\nTask: {selected_task.name}")
        command = selected_task.metadata.get('command', 'N/A')
        print(f"Command: {command}")
        print()

        # Retry options
        print("Options:")
        print("  [r] Retry with same command")
        print("  [e] Edit command before retry")
        print("  [v] View full task metadata")
        print("  [c] Cancel")

        option = input("\nChoice: ").strip().lower()

        if option == 'c':
            print("Cancelled")
            return

        elif option == 'v':
            # Show full metadata
            print("\nFull task metadata:")
            print(json.dumps(selected_task.metadata, indent=2))
            return

        elif option == 'e':
            # Edit command
            new_command = self._edit_command(command)
            confirm = input(DisplayManager.format_confirmation("Confirm retry with new command?", default='Y'))
            if not InputProcessor.parse_confirmation(confirm, default='Y'):
                print("Cancelled")
                return
            command = new_command

        elif option == 'r':
            # Retry as-is
            confirm = input(DisplayManager.format_confirmation("Retry with same command?", default='Y'))
            if not InputProcessor.parse_confirmation(confirm, default='Y'):
                print("Cancelled")
                return

        else:
            print("Invalid option")
            return

        # Execute retry
        success = self._retry_task(selected_task, command)

        if success:
            self.last_action = f"Retried: {selected_task.name} (success)"
        else:
            self.last_action = f"Retried: {selected_task.name} (failed)"

    def handle_progress_dashboard(self):
        """Progress dashboard handler (shortcut: pd)"""
        print(DisplayManager.format_info("Progress Dashboard"))
        print("=" * 50)

        # Calculate overall progress
        all_tasks = self.profile.task_tree.get_all_tasks()
        completed = [t for t in all_tasks if t.status == 'completed']
        in_progress = [t for t in all_tasks if t.status == 'in-progress']
        pending = [t for t in all_tasks if t.status == 'pending']
        failed = [t for t in all_tasks if t.status == 'failed']
        skipped = [t for t in all_tasks if t.status == 'skipped']

        total = len(all_tasks)
        if total == 0:
            print(DisplayManager.format_warning("No tasks available"))
            return

        completion_pct = int((len(completed) / total) * 100)

        # Display current phase
        print(f"\nCurrent Phase: {self.profile.phase.title()}")
        print()

        # Display progress bar
        bar_width = 30
        filled = int(bar_width * completion_pct / 100)
        bar = '█' * filled + '░' * (bar_width - filled)
        print(f"Overall Progress: [{bar}] {completion_pct}%")
        print(f"Tasks: {len(completed)}/{total}")
        print()

        # Status breakdown
        print("Status Breakdown:")
        print(f"  Completed:    {len(completed)}")
        print(f"  In-Progress:  {len(in_progress)}")
        print(f"  Pending:      {len(pending)}")
        print(f"  Failed:       {len(failed)}")
        print(f"  Skipped:      {len(skipped)}")
        print()

        # Group by service
        service_groups = {}
        for task in all_tasks:
            service = task.metadata.get('service', 'other')
            if service not in service_groups:
                service_groups[service] = []
            service_groups[service].append(task)

        if len(service_groups) > 1:
            print("By Service:")
            for service, tasks in sorted(service_groups.items()):
                completed_service = len([t for t in tasks if t.status == 'completed'])
                total_service = len(tasks)
                pct = int((completed_service / total_service) * 100) if total_service > 0 else 0
                port = tasks[0].metadata.get('port', '')
                port_str = f" (:{port})" if port else ""
                print(f"  {service.upper()}{port_str}: {completed_service}/{total_service} ({pct}%)")
            print()

        # Quick wins and high priority
        quick_wins = [t for t in pending if 'QUICK_WIN' in t.metadata.get('tags', [])]
        high_priority = [t for t in pending + in_progress if 'OSCP:HIGH' in t.metadata.get('tags', [])]

        if quick_wins:
            print(f"Quick Wins: {len(quick_wins)} remaining")
        if high_priority:
            print(f"High Priority: {len(high_priority)} pending")

        # Next recommended task
        from ..recommendations.engine import RecommendationEngine
        recommendations = RecommendationEngine.get_recommendations(self.profile)
        next_task = recommendations.get('next')

        if next_task:
            print()
            print("Next Recommended:")
            print(f"  → {next_task.name}")

    def handle_session_snapshot(self):
        """Session snapshot manager (shortcut: ss)"""
        import re

        print(DisplayManager.format_info("Session Snapshot Manager"))
        print("=" * 50)
        print()

        # Show current state
        print(f"Current target: {self.target}")
        print(f"Current phase: {self.profile.phase}")
        print(f"Last action: {self.last_action}")
        print()

        # List existing snapshots
        snapshots = self._list_snapshots()

        if snapshots:
            print("Existing snapshots:")
            for i, snapshot in enumerate(snapshots, 1):
                meta = snapshot['metadata']
                stats = meta.get('stats', {})
                print(f"  {i}. {meta['name']} ({meta['created'][:19]})")
                print(f"     Tasks: {stats.get('total_tasks', 0)}, "
                      f"Findings: {stats.get('findings', 0)}, "
                      f"Credentials: {stats.get('credentials', 0)}")
            print()
        else:
            print("No snapshots yet.")
            print()

        # Show options
        print("Options:")
        print("  [s] Save new snapshot")
        print("  [r] Restore from snapshot")
        print("  [d] Delete snapshot")
        print("  [l] List all snapshots")
        print("  [c] Cancel")
        print()

        choice = InputProcessor.get_input("Choice: ").strip().lower()

        if choice == 's':
            # Save snapshot
            snapshot_name = input("\nSnapshot name: ").strip()

            if not snapshot_name:
                print(DisplayManager.format_error("Snapshot name cannot be empty"))
                return

            self._save_snapshot(snapshot_name)

        elif choice == 'r' and snapshots:
            # Restore snapshot
            print()
            snapshot_choice = input(f"Select snapshot [1-{len(snapshots)}]: ").strip()

            if not snapshot_choice.isdigit():
                print(DisplayManager.format_error("Invalid choice"))
                return

            idx = int(snapshot_choice) - 1
            if not (0 <= idx < len(snapshots)):
                print(DisplayManager.format_error("Invalid choice"))
                return

            # Confirm restore
            selected = snapshots[idx]
            print()
            print(DisplayManager.format_warning("WARNING: Restoring will overwrite current session!"))
            print()
            print("Current state will be lost:")
            all_tasks = self.profile.task_tree.get_all_tasks()
            completed = [t for t in all_tasks if t.status == 'completed']
            print(f"  - {len(all_tasks)} tasks ({len(completed)} completed)")
            print(f"  - {len(self.profile.findings)} findings")
            print(f"  - {len(self.profile.credentials)} credentials")
            print(f"  - Last modified: {self.profile.updated}")
            print()

            meta = selected['metadata']
            stats = meta.get('stats', {})
            print(f"Restore from: {meta['name']} ({meta['created'][:19]})")
            print(f"  - {stats.get('total_tasks', 0)} tasks ({stats.get('completed_tasks', 0)} completed)")
            print(f"  - {stats.get('findings', 0)} findings")
            print(f"  - {stats.get('credentials', 0)} credentials")
            print()

            confirm = input("Proceed? [y/N]: ").strip()
            if not InputProcessor.parse_confirmation(confirm, default='N'):
                print("Cancelled")
                return

            self._restore_snapshot(selected['path'])

        elif choice == 'd' and snapshots:
            # Delete snapshot
            print()
            snapshot_choice = input(f"Select snapshot to delete [1-{len(snapshots)}]: ").strip()

            if not snapshot_choice.isdigit():
                print(DisplayManager.format_error("Invalid choice"))
                return

            idx = int(snapshot_choice) - 1
            if not (0 <= idx < len(snapshots)):
                print(DisplayManager.format_error("Invalid choice"))
                return

            selected = snapshots[idx]
            confirm = input(f"Delete snapshot '{selected['metadata']['name']}'? [y/N]: ").strip()
            if InputProcessor.parse_confirmation(confirm, default='N'):
                snapshot_name = selected['metadata']['name']
                snapshot_path = selected['path']
                snapshot_path.unlink()

                if hasattr(self, 'debug_logger'):
                    from .log_types import LogCategory, LogLevel
                    self.debug_logger.log("Snapshot deleted",
                                         category=LogCategory.STATE_SAVE,
                                         level=LogLevel.NORMAL,
                                         snapshot_name=snapshot_name,
                                         file_path=str(snapshot_path))

                print(DisplayManager.format_success(f"Snapshot deleted: {snapshot_name}"))
            else:
                print("Cancelled")

        elif choice == 'l':
            # Already shown above
            pass

        elif choice == 'c':
            # Cancel
            pass

        else:
            if choice == 'r' and not snapshots:
                print(DisplayManager.format_warning("No snapshots to restore"))
            elif choice == 'd' and not snapshots:
                print(DisplayManager.format_warning("No snapshots to delete"))

    def _get_snapshots_dir(self) -> Path:
        """Get snapshots directory for current target"""
        # Use override if set (for testing), otherwise use default
        if self.SNAPSHOTS_BASE_DIR:
            snapshots_base = self.SNAPSHOTS_BASE_DIR
        else:
            snapshots_base = Path.home() / '.crack' / 'snapshots'

        target_dir = snapshots_base / self.target
        target_dir.mkdir(parents=True, exist_ok=True)
        return target_dir

    def _list_snapshots(self) -> list:
        """List all snapshots for current target"""
        from .log_types import LogCategory, LogLevel

        snapshots_dir = self._get_snapshots_dir()
        snapshots = []

        for snapshot_file in sorted(snapshots_dir.glob('*.json')):
            try:
                data = json.loads(snapshot_file.read_text())
                snapshots.append({
                    'filename': snapshot_file.name,
                    'metadata': data.get('snapshot_metadata', {}),
                    'path': snapshot_file,
                    'file': snapshot_file  # Alias for compatibility
                })
            except json.JSONDecodeError:
                if hasattr(self, 'debug_logger'):
                    self.debug_logger.log("Invalid snapshot file",
                                         category=LogCategory.DATA_PARSE,
                                         level=LogLevel.VERBOSE,
                                         file=str(snapshot_file))
                continue

        # Sort by creation time (newest first)
        snapshots.sort(key=lambda x: x['metadata'].get('created', ''), reverse=True)

        if hasattr(self, 'debug_logger'):
            self.debug_logger.log("Listed snapshots",
                                 category=LogCategory.STATE_LOAD,
                                 level=LogLevel.VERBOSE,
                                 snapshot_count=len(snapshots),
                                 snapshots_dir=str(snapshots_dir))

        return snapshots

    def _save_snapshot(self, snapshot_name: str) -> bool:
        """Save current profile as named snapshot"""
        import re
        from .log_types import LogCategory, LogLevel

        # Validate name
        if not snapshot_name or not snapshot_name.strip():
            if hasattr(self, 'debug_logger'):
                self.debug_logger.log("Snapshot save rejected: empty name",
                                     category=LogCategory.STATE_SAVE,
                                     level=LogLevel.NORMAL)
            print(DisplayManager.format_error("Snapshot name cannot be empty"))
            return False

        # Sanitize name
        safe_name = re.sub(r'[^a-zA-Z0-9_-]', '-', snapshot_name.strip())

        if hasattr(self, 'debug_logger'):
            self.debug_logger.log("Saving snapshot",
                                 category=LogCategory.STATE_SAVE,
                                 level=LogLevel.NORMAL,
                                 original_name=snapshot_name,
                                 sanitized_name=safe_name)

        # Create snapshot
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{self.target}_{safe_name}_{timestamp}.json"

        snapshot_path = self._get_snapshots_dir() / filename

        # Gather stats
        all_tasks = self.profile.task_tree.get_all_tasks()
        completed = [t for t in all_tasks if t.status == 'completed']

        snapshot_data = {
            'snapshot_metadata': {
                'name': safe_name,
                'created': datetime.now().isoformat(),
                'description': f"Snapshot: {safe_name}",
                'stats': {
                    'total_tasks': len(all_tasks),
                    'completed_tasks': len(completed),
                    'findings': len(self.profile.findings),
                    'credentials': len(self.profile.credentials),
                    'phase': self.profile.phase
                }
            },
            'profile_data': self.profile.to_dict()  # Full profile
        }

        snapshot_path.write_text(json.dumps(snapshot_data, indent=2))

        if hasattr(self, 'debug_logger'):
            self.debug_logger.log("Snapshot saved successfully",
                                 category=LogCategory.STATE_SAVE,
                                 level=LogLevel.NORMAL,
                                 snapshot_name=safe_name,
                                 file_path=str(snapshot_path),
                                 total_tasks=len(all_tasks),
                                 completed_tasks=len(completed),
                                 findings=len(self.profile.findings),
                                 credentials=len(self.profile.credentials))

        print(DisplayManager.format_success(f"Snapshot saved: {safe_name}"))
        print(f"  Location: {snapshot_path}")
        print(f"  Tasks: {len(all_tasks)}, Findings: {len(self.profile.findings)}, Credentials: {len(self.profile.credentials)}")

        return True

    def _restore_snapshot(self, snapshot_path: Path) -> bool:
        """Restore profile from snapshot"""
        from .log_types import LogCategory, LogLevel

        try:
            if hasattr(self, 'debug_logger'):
                self.debug_logger.log("Restoring snapshot",
                                     category=LogCategory.STATE_LOAD,
                                     level=LogLevel.NORMAL,
                                     snapshot_path=str(snapshot_path))

            data = json.loads(snapshot_path.read_text())
            profile_data = data['profile_data']

            # Restore profile using from_dict
            self.profile = TargetProfile.from_dict(profile_data)

            # Save restored profile
            self.profile.save()

            # Update session state
            self.last_action = f"Restored snapshot: {data['snapshot_metadata']['name']}"

            # Save checkpoint only if checkpoint_dir exists
            if hasattr(self, 'checkpoint_dir') and self.checkpoint_dir:
                self.save_checkpoint()

            # Show stats
            all_tasks = self.profile.task_tree.get_all_tasks()
            completed = [t for t in all_tasks if t.status == 'completed']

            if hasattr(self, 'debug_logger'):
                self.debug_logger.log("Snapshot restored successfully",
                                     category=LogCategory.STATE_LOAD,
                                     level=LogLevel.NORMAL,
                                     snapshot_name=data['snapshot_metadata']['name'],
                                     total_tasks=len(all_tasks),
                                     completed_tasks=len(completed),
                                     findings=len(self.profile.findings),
                                     credentials=len(self.profile.credentials))

            print(DisplayManager.format_success("Snapshot restored successfully"))
            print(f"  Tasks: {len(all_tasks)} ({len(completed)} completed)")
            print(f"  Findings: {len(self.profile.findings)}")
            print(f"  Credentials: {len(self.profile.credentials)}")
            print(f"  Phase: {self.profile.phase}")

            return True
        except Exception as e:
            if hasattr(self, 'debug_logger'):
                self.debug_logger.log("Snapshot restore failed",
                                     category=LogCategory.STATE_LOAD,
                                     level=LogLevel.NORMAL,
                                     error=str(e),
                                     error_type=type(e).__name__)
            self.error_handler.handle_exception(e, context="snapshot restore")
            input()  # Wait for user to acknowledge
            return False

    def handle_batch_execute(self, selection: str = None):
        """Execute multiple tasks in batch with dependency resolution

        Args:
            selection: Optional pre-selected tasks (for testing/automation)
        """
        print(DisplayManager.format_info("Batch Execute"))
        print("=" * 50)

        # Get executable tasks (pending with commands)
        all_tasks = self.profile.task_tree.get_all_tasks()
        pending = [t for t in all_tasks if t.status == 'pending' and t.metadata.get('command')]

        if not pending:
            print(DisplayManager.format_warning("No pending tasks to execute"))
            return

        # Display tasks with dependencies
        print("\nPending tasks:")
        for i, task in enumerate(pending, 1):
            deps = task.metadata.get('depends_on', [])
            deps_str = f" (depends on: {', '.join(str(d) for d in deps)})" if deps else " (no deps)"
            tags = task.metadata.get('tags', [])
            tag_str = f" [{', '.join(tags)}]" if tags else ""

            print(f"  {i}. ⏸ {task.name}{deps_str}{tag_str}")

        print("\nSelection options:")
        print("  - Numbers: 1,3,5 or 1-5")
        print("  - Keywords: all, pending, quick, high")
        print("  - By service: http, smb, ssh")

        # Get selection
        if not selection:
            selection = input("\nSelect tasks: ").strip()

        if not selection or selection.lower() == 'cancel':
            print("Cancelled")
            return

        # Parse selection
        selected = self._parse_batch_selection(selection, pending)

        if not selected:
            print("No tasks selected")
            return

        # Show selected tasks
        print(f"\nSelected {len(selected)} tasks:")
        for task in selected:
            print(f"  ✓ {task.name}")

        # Resolve dependencies and create execution plan
        steps = self._resolve_dependencies(selected)

        # Show execution plan
        print("\nExecution plan:")
        for i, step in enumerate(steps, 1):
            if len(step) == 1:
                print(f"  Step {i}: {step[0].name} (1 task, sequential)")
            else:
                print(f"  Step {i}: ({len(step)} tasks, parallel)")
                for task in step:
                    print(f"    - {task.name}")

        print(f"\nTotal tasks: {len(selected)}")

        # Confirm execution
        confirm = input(DisplayManager.format_confirmation("Execute batch?", default='Y'))
        if not InputProcessor.parse_confirmation(confirm, default='Y'):
            print("Cancelled")
            return

        # Execute batch
        print("\nExecuting batch...\n")

        results = self._execute_batch(steps)

        # Save profile
        self.profile.save()

        # Summary
        print("\nBatch execution complete!\n")
        print("Results:")
        print(f"  ✓ Succeeded: {len(results['succeeded'])} tasks")
        print(f"  ✗ Failed: {len(results['failed'])} tasks")
        print(f"  ⊘ Skipped: {len(results['skipped'])} tasks")

        elapsed = results['total_time']
        print(f"\nTotal time: {int(elapsed // 60)}m {int(elapsed % 60)}s")

        self.last_action = f"Batch execute: {len(results['succeeded'])}/{len(selected)} succeeded"

    def _parse_batch_selection(self, user_input: str, tasks: List) -> List:
        """Parse batch selection input

        Args:
            user_input: User input string
            tasks: List of available tasks

        Returns:
            List of selected TaskNode objects
        """
        user_input = user_input.strip().lower()

        selected = []

        # Keyword selection
        if user_input == 'all':
            selected = tasks
        elif user_input == 'pending':
            selected = [t for t in tasks if t.status == 'pending']
        elif user_input == 'quick':
            selected = [t for t in tasks if 'QUICK_WIN' in t.metadata.get('tags', [])]
        elif user_input == 'high':
            selected = [t for t in tasks if 'OSCP:HIGH' in t.metadata.get('tags', [])]

        # Service-based selection
        elif user_input in ['http', 'smb', 'ssh', 'ftp', 'sql']:
            selected = [t for t in tasks if user_input in t.name.lower() or
                       user_input in t.metadata.get('service', '').lower()]

        # Numeric selection (reuse InputProcessor.parse_multi_select)
        else:
            indices = InputProcessor.parse_multi_select(user_input, len(tasks))
            selected = [tasks[i-1] for i in indices if 0 < i <= len(tasks)]

        return selected

    def _resolve_dependencies(self, tasks: List) -> List[List]:
        """Resolve task dependencies and create execution steps

        Args:
            tasks: List of TaskNode objects to execute

        Returns:
            List of steps, where each step is a list of tasks that can run in parallel
        """
        # Build dependency map
        task_ids = {t.id for t in tasks}

        # Create execution steps
        steps = []
        remaining = set(tasks)
        completed = set()

        while remaining:
            # Find tasks with no unmet dependencies
            ready = []
            for task in remaining:
                deps = task.metadata.get('depends_on', [])

                # Check if all dependencies are completed or not in our selection
                deps_met = all(dep_id in completed or dep_id not in task_ids for dep_id in deps)

                if deps_met:
                    ready.append(task)

            if not ready:
                # Circular dependency or error
                print(DisplayManager.format_warning("Warning: Some tasks have unmet dependencies"))
                # Add remaining tasks anyway (best effort)
                ready = list(remaining)

            steps.append(ready)

            for task in ready:
                remaining.remove(task)
                completed.add(task.id)

        return steps

    def _execute_batch(self, steps: List[List]) -> Dict[str, Any]:
        """Execute batch of tasks in steps with parallel execution where possible

        Args:
            steps: List of execution steps (each step is a list of tasks)

        Returns:
            Dict with results summary
        """
        import concurrent.futures
        import time

        # Debug logging: Batch execution start
        self.debug_logger.log("Batch execution started",
                             category=LogCategory.EXECUTION_START,
                             level=LogLevel.NORMAL,
                             total_steps=len(steps),
                             total_tasks=sum(len(step) for step in steps))

        results = {
            'succeeded': [],
            'failed': [],
            'skipped': []
        }

        total_tasks = sum(len(step) for step in steps)
        completed_count = 0
        start_time = time.time()
        task_times = []  # Track individual task durations for ETA

        try:
            for step_num, step_tasks in enumerate(steps, 1):
                step_size = len(step_tasks)

                # Calculate ETA based on average task time
                if task_times and completed_count < total_tasks:
                    avg_time = sum(task_times) / len(task_times)
                    remaining = total_tasks - completed_count
                    eta_seconds = int(avg_time * remaining)
                    eta_str = f" | ETA: {eta_seconds//60}m {eta_seconds%60}s"
                else:
                    eta_str = ""

                print(f"\n[{completed_count+1}-{completed_count+step_size}/{total_tasks}]{eta_str}")

                if step_size == 1:
                    # Sequential execution with timing
                    task = step_tasks[0]
                    task_start = time.time()

                    self.debug_logger.log("Executing task",
                                         category=LogCategory.EXECUTION_START,
                                         level=LogLevel.VERBOSE,
                                         task_id=task.id,
                                         task_name=task.name,
                                         mode="sequential")

                    # Use LoadingIndicator spinner
                    with self.loading_indicator.spinner(f"⏳ {task.name}...") as loader:
                        success = self._execute_single_task(task)
                        task_duration = time.time() - task_start
                        task_times.append(task_duration)

                        loader.update(message=f"✓ {task.name} ({int(task_duration)}s)" if success else f"✗ {task.name} (failed)")

                    if success:
                        print(f"  ✓ {task.name} ({int(task_duration)}s)")
                        results['succeeded'].append(task)
                        self.debug_logger.log("Task completed",
                                             category=LogCategory.EXECUTION_END,
                                             level=LogLevel.NORMAL,
                                             task_id=task.id,
                                             duration=task_duration,
                                             success=True)
                    else:
                        print(f"  ✗ {task.name} (exit code {task.metadata.get('exit_code', 'unknown')})")
                        results['failed'].append(task)
                        self.debug_logger.log("Task failed",
                                             category=LogCategory.EXECUTION_ERROR,
                                             level=LogLevel.NORMAL,
                                             task_id=task.id,
                                             duration=task_duration,
                                             exit_code=task.metadata.get('exit_code'))

                    completed_count += 1

                else:
                    # Parallel execution with progress bar
                    self.debug_logger.log("Parallel execution starting",
                                         category=LogCategory.EXECUTION_START,
                                         level=LogLevel.VERBOSE,
                                         parallel_tasks=step_size,
                                         max_workers=4)

                    print(f"⏳ Running {step_size} tasks in parallel...")

                    # Use LoadingIndicator progress bar
                    with self.loading_indicator.progress(total=step_size, message=f"Executing {step_size} tasks...") as loader:
                        parallel_completed = 0

                        # Use thread pool for parallel execution
                        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                            # Submit all tasks
                            futures = {}
                            for task in step_tasks:
                                future = executor.submit(self._execute_single_task, task)
                                futures[future] = task

                            # Wait for completion with progress updates
                            for future in concurrent.futures.as_completed(futures):
                                task = futures[future]
                                task_start = getattr(task, '_batch_start_time', time.time())
                                task_duration = time.time() - task_start
                                task_times.append(task_duration)

                                try:
                                    success = future.result()
                                    parallel_completed += 1
                                    loader.update(parallel_completed, f"Completed {parallel_completed}/{step_size}")

                                    if success:
                                        print(f"  ✓ {task.name} ({int(task_duration)}s)")
                                        results['succeeded'].append(task)
                                    else:
                                        print(f"  ✗ {task.name} (failed)")
                                        results['failed'].append(task)
                                except Exception as e:
                                    parallel_completed += 1
                                    loader.update(parallel_completed, f"Completed {parallel_completed}/{step_size}")
                                    print(f"  ✗ {task.name} (error: {e})")
                                    results['failed'].append(task)
                                    self.debug_logger.log("Task exception",
                                                         category=LogCategory.EXECUTION_ERROR,
                                                         level=LogLevel.NORMAL,
                                                         task_id=task.id,
                                                         error=str(e))

                                completed_count += 1

        except KeyboardInterrupt:
            # Graceful Ctrl+C handling
            print("\n\n⊘ Batch execution interrupted by user")
            self.debug_logger.log("Batch execution interrupted",
                                 category=LogCategory.EXECUTION_ERROR,
                                 level=LogLevel.NORMAL,
                                 completed=completed_count,
                                 total=total_tasks)

            # Mark remaining tasks as skipped
            all_tasks_flat = [t for step in steps for t in step]
            completed_ids = {t.id for t in results['succeeded']} | {t.id for t in results['failed']}
            results['skipped'] = [t for t in all_tasks_flat if t.id not in completed_ids]

        end_time = time.time()
        elapsed = end_time - start_time

        results['total_time'] = elapsed

        # Debug logging: Batch execution complete
        self.debug_logger.log("Batch execution completed",
                             category=LogCategory.EXECUTION_END,
                             level=LogLevel.NORMAL,
                             succeeded=len(results['succeeded']),
                             failed=len(results['failed']),
                             skipped=len(results['skipped']),
                             total_time=elapsed)

        return results

    def _execute_single_task(self, task) -> bool:
        """Execute a single task and return success status

        Args:
            task: TaskNode to execute

        Returns:
            True if successful, False otherwise
        """
        import subprocess

        command = task.metadata.get('command')
        if not command:
            return False

        # Replace placeholders
        command = command.replace('{TARGET}', self.profile.target)

        try:
            task.status = 'in-progress'
            task.start_timer()

            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )

            task.stop_timer()

            if result.returncode == 0:
                task.status = 'completed'
                task.mark_complete()
                return True
            else:
                task.status = 'failed'
                task.metadata['exit_code'] = result.returncode
                task.metadata['error'] = result.stderr
                return False

        except subprocess.TimeoutExpired:
            task.stop_timer()
            task.status = 'failed'
            task.metadata['error'] = 'Timeout (5 minutes)'
            return False
        except Exception as e:
            task.stop_timer()
            task.status = 'failed'
            task.metadata['error'] = str(e)
            return False

    def handle_finding_correlator(self):
        """Analyze and correlate findings to identify attack chains"""
        print(DisplayManager.format_info("Finding Correlator"))
        print("=" * 50)
        print()

        # Count data
        num_ports = len(self.profile.ports)
        num_findings = len(self.profile.findings)
        num_creds = len(self.profile.credentials)

        print(f"Analyzing {num_ports} ports, {num_findings} findings, {num_creds} credentials...")
        print()

        # Find correlations
        correlations = self._find_correlations()

        if not correlations:
            print(DisplayManager.format_warning("No correlations found"))
            print("\nTips:")
            print("  - Ensure scan results are imported")
            print("  - Document findings as you discover them")
            print("  - Correlator works best with complete enumeration")
            return

        # Rank by priority
        correlations = self._rank_correlations(correlations)

        print(f"🔗 Correlations Found:\n")

        # Display correlations
        for i, corr in enumerate(correlations, 1):
            priority_icon = {
                'high': '🔴',
                'medium': '🟡',
                'low': '🟢'
            }.get(corr['priority'], '⚪')

            print(f"{i}. {corr['title']} {priority_icon}")

            for j, elem in enumerate(corr['elements']):
                if j == 0:
                    print(f"   ├─ {elem}")
                elif j == len(corr['elements']) - 1:
                    print(f"   └─ {elem}")
                else:
                    print(f"   ├─ {elem}")

            print(f"   └─ → TRY: {corr['recommendation']}")
            print()

        # Summary recommendations
        print("Recommendations:")
        high_priority = [c for c in correlations if c['priority'] == 'high']
        medium_priority = [c for c in correlations if c['priority'] == 'medium']

        if high_priority:
            for corr in high_priority:
                print(f"  → High Priority: {corr['title']} (Correlation #{correlations.index(corr)+1})")

        if medium_priority:
            for corr in medium_priority[:3]:  # Limit to top 3
                print(f"  → Medium Priority: {corr['title']} (Correlation #{correlations.index(corr)+1})")

        print()

        # Offer to create tasks
        if high_priority:
            create_tasks = input(DisplayManager.format_confirmation("Create tasks for high-priority correlations?", default='Y'))

            if InputProcessor.parse_confirmation(create_tasks, default='Y'):
                self._create_correlation_tasks(high_priority)

        self.last_action = f"Analyzed correlations: {len(correlations)} found"

    def _find_correlations(self) -> List[Dict[str, Any]]:
        """Find correlations between discoveries"""
        correlations = []

        # Get data
        ports = self.profile.ports
        findings = self.profile.findings
        credentials = self.profile.credentials

        # Pattern 1: Service + Credentials
        for cred in credentials:
            username = cred.get('username')
            password = cred.get('password')
            cred_service = cred.get('service', '').lower()

            # Check for compatible services
            for port, info in ports.items():
                service = info.get('service', '').lower()

                # Don't correlate with the same service the cred came from
                if service in ['smb', 'ssh', 'mysql', 'ftp', 'rdp', 'vnc', 'mssql', 'postgresql'] and service != cred_service:
                    correlations.append({
                        'type': 'service_credential',
                        'priority': 'high',
                        'title': f'{service.upper()} + Credentials',
                        'elements': [
                            f'Port {port} ({service}) is open',
                            f'Username \'{username}\' discovered',
                            f'Password available' if password else 'Hash/token available'
                        ],
                        'recommendation': self._get_service_auth_command(service, port, username, password)
                    })

        # Pattern 2: CVE + Version
        for port, info in ports.items():
            version = info.get('version', '')
            product = info.get('product', '')
            service = info.get('service', '')

            if version and (product or service):
                # Check for known CVEs (simple pattern matching)
                cve_pattern = self._check_known_vulnerabilities(product or service, version)
                if cve_pattern:
                    correlations.append({
                        'type': 'cve_match',
                        'priority': 'high',
                        'title': f'Technology Match: {product or service} {version}',
                        'elements': [
                            f'Service: {product or service} {version} (Port {port})',
                            f'{cve_pattern["cve_id"]}: {cve_pattern["description"]}'
                        ],
                        'recommendation': f"searchsploit {product or service} {version}"
                    })

        # Pattern 3: Credential Reuse
        if credentials:
            for cred in credentials:
                username = cred.get('username')
                password = cred.get('password')
                source_service = cred.get('service', 'HTTP').lower()

                # Find other services
                other_services = []
                for port, info in ports.items():
                    service = info.get('service', '').lower()
                    if service in ['ssh', 'mysql', 'smb', 'ftp', 'rdp', 'mssql', 'postgresql'] and service != source_service:
                        other_services.append(f'{service.upper()} ({port})')

                if other_services and len(other_services) > 0:
                    correlations.append({
                        'type': 'credential_reuse',
                        'priority': 'medium',
                        'title': 'Credential Reuse Opportunity',
                        'elements': [
                            f'Credential: {username}/{password or "hash"} (found on {source_service.upper()})',
                            f'Open services: {", ".join(other_services[:3])}{"..." if len(other_services) > 3 else ""}'
                        ],
                        'recommendation': 'Try credentials on other services'
                    })
                    break  # Only create one credential reuse correlation

        # Pattern 4: Directory + Upload
        upload_findings = [f for f in findings if 'upload' in f.get('description', '').lower() or
                           'writable' in f.get('description', '').lower()]

        web_ports = [p for p, i in ports.items() if i.get('service', '').lower() in ['http', 'https']]

        if upload_findings and web_ports:
            correlations.append({
                'type': 'upload_directory',
                'priority': 'medium',
                'title': 'Upload Directory Pattern',
                'elements': [
                    'Writable/upload directory found',
                    f'Web service available on port(s): {", ".join(str(p) for p in web_ports)}'
                ],
                'recommendation': 'Upload web shell for RCE (check file type restrictions)'
            })

        # Pattern 5: Weak Auth
        basic_auth = [f for f in findings if 'basic auth' in f.get('description', '').lower() or
                      'authentication' in f.get('description', '').lower()]

        if basic_auth and web_ports:
            correlations.append({
                'type': 'weak_auth',
                'priority': 'medium',
                'title': 'Weak Authentication Pattern',
                'elements': [
                    'HTTP authentication detected',
                    'No lockout policy observed'
                ],
                'recommendation': 'Credential brute-force with hydra or medusa'
            })

        # Pattern 6: LFI + Writable
        lfi_findings = [f for f in findings if 'lfi' in f.get('description', '').lower() or
                        'file inclusion' in f.get('description', '').lower() or
                        'traversal' in f.get('description', '').lower()]
        writable_dirs = [f for f in findings if 'writable' in f.get('description', '').lower() or
                         'upload' in f.get('description', '').lower()]

        if lfi_findings and writable_dirs:
            correlations.append({
                'type': 'lfi_upload',
                'priority': 'high',
                'title': 'LFI + Shell Upload',
                'elements': [
                    'LFI/Path traversal vulnerability detected',
                    'Writable directory found'
                ],
                'recommendation': 'Upload shell and include via LFI: <?php system($_GET["cmd"]); ?>'
            })

        # Pattern 7: SQLi + Database Port
        sqli_findings = [f for f in findings if 'sql' in f.get('description', '').lower() and
                         'injection' in f.get('description', '').lower()]
        db_ports = {p: i for p, i in ports.items() if i.get('service', '').lower() in ['mysql', 'mssql', 'postgresql']}

        if sqli_findings and db_ports:
            db_port = list(db_ports.keys())[0]
            db_service = db_ports[db_port].get('service', 'database')
            correlations.append({
                'type': 'sqli_db',
                'priority': 'high',
                'title': f'SQL Injection + {db_service.upper()} Service',
                'elements': [
                    'SQL injection vulnerability found',
                    f'Open {db_service} port: {db_port}'
                ],
                'recommendation': f'Extract credentials via SQLi, then direct {db_service} connection'
            })

        # Pattern 8: Username Enum + Weak Passwords
        user_findings = [f for f in findings if 'username' in f.get('description', '').lower() or
                         'user' in f.get('type', '').lower() or
                         f.get('type') == 'user']

        auth_services = [p for p, i in ports.items() if i.get('service', '').lower() in ['ssh', 'smb', 'ftp', 'rdp']]

        if user_findings and auth_services and not credentials:
            correlations.append({
                'type': 'user_enum',
                'priority': 'medium',
                'title': 'Username Enumeration Detected',
                'elements': [
                    f'{len(user_findings)} valid username(s) discovered',
                    f'Auth services: {", ".join(str(p) for p in auth_services[:3])}',
                    'No passwords found yet'
                ],
                'recommendation': 'Password spraying with common passwords'
            })

        return correlations

    def _get_service_auth_command(self, service: str, port: int, username: str, password: str) -> str:
        """Generate authentication command for service"""
        target = self.profile.target

        commands = {
            'smb': f'smbclient //{target}/C$ -U {username}{"%" + password if password else ""}',
            'ssh': f'ssh {username}@{target} {"-p " + str(port) if port != 22 else ""}',
            'mysql': f'mysql -h {target} -u {username} {"-p" + password if password else "-p"}',
            'mssql': f'impacket-mssqlclient {username}:{password or "hash"}@{target}',
            'postgresql': f'psql -h {target} -U {username} {"" if not password else ""}',
            'ftp': f'ftp {username}@{target}',
            'rdp': f'rdesktop -u {username} {"-p " + password if password else ""} {target}',
            'vnc': f'vncviewer {target}:{port}'
        }

        return commands.get(service, f'Try {username}/{password or "hash"} on {service}')

    def _check_known_vulnerabilities(self, product: str, version: str) -> Optional[Dict]:
        """Check for known vulnerabilities (simple pattern matching)"""
        # Known CVE patterns (expand this database)
        known_cves = {
            ('Apache httpd', '2.4.41'): {
                'cve_id': 'CVE-2021-41773',
                'description': 'Path traversal vulnerability'
            },
            ('Apache httpd', '2.4.49'): {
                'cve_id': 'CVE-2021-41773',
                'description': 'Path traversal and RCE'
            },
            ('OpenSSH', '7.4'): {
                'cve_id': 'CVE-2018-15473',
                'description': 'Username enumeration'
            },
            ('ProFTPD', '1.3.5'): {
                'cve_id': 'CVE-2015-3306',
                'description': 'Remote code execution'
            },
            ('vsftpd', '2.3.4'): {
                'cve_id': 'Backdoor',
                'description': 'Backdoored version with command execution'
            },
            ('Samba smbd', '3.0.20'): {
                'cve_id': 'CVE-2007-2447',
                'description': 'Command execution via username'
            },
            ('Microsoft Windows RPC', '5.0'): {
                'cve_id': 'MS08-067',
                'description': 'Remote code execution (EternalBlue family)'
            }
        }

        # Normalize product name
        product_lower = product.lower()

        # Simple version matching
        for (known_product, known_version), cve_data in known_cves.items():
            if known_product.lower() in product_lower and known_version in version:
                return cve_data

        # Partial version match (for ranges)
        for (known_product, known_version), cve_data in known_cves.items():
            if known_product.lower() in product_lower:
                # Check version prefix match
                if version.startswith(known_version.split('.')[0]):
                    return cve_data

        return None

    def _rank_correlations(self, correlations: List[Dict]) -> List[Dict]:
        """Rank correlations by priority and exploitability"""
        priority_order = {'high': 0, 'medium': 1, 'low': 2}

        return sorted(correlations, key=lambda c: (
            priority_order.get(c['priority'], 99),
            -len(c['elements'])  # More elements = more interesting
        ))

    def _create_correlation_tasks(self, correlations: List[Dict]):
        """Create tasks for high-priority correlations"""
        from ..core.task_tree import TaskNode

        created_count = 0

        for corr in correlations:
            # Create task based on correlation type
            task_id = f"correlation-{corr['type']}-{int(time.time())}"

            # Build task metadata
            metadata = {
                'command': corr['recommendation'],
                'description': corr['title'],
                'tags': ['CORRELATION', 'OSCP:HIGH'] if corr['priority'] == 'high' else ['CORRELATION'],
                'correlation_type': corr['type']
            }

            # Create task node
            task_node = TaskNode(
                task_id=task_id,
                name=f"[CORRELATION] {corr['title']}",
                task_type='command'
            )

            # Set metadata after creation
            task_node.metadata.update(metadata)

            # Add to task tree
            self.profile.task_tree.add_child(task_node)

            print(DisplayManager.format_success(f"✓ Created task: {corr['title']}"))
            created_count += 1

        self.profile.save()
        print(f"\n✓ Created {created_count} correlation task(s)")

    def handle_success_analyzer(self):
        """Analyze task success rates and provide optimization insights"""
        print(DisplayManager.format_info("Success Analyzer"))
        print("=" * 50)
        print()

        # Get all tasks (completed and failed)
        all_tasks = self.profile.task_tree.get_all_tasks()
        analyzed_tasks = [t for t in all_tasks if t.status in ['completed', 'failed']]

        if not analyzed_tasks:
            print(DisplayManager.format_warning("No completed or failed tasks to analyze"))
            print("\nRun some tasks first to generate statistics")
            return

        print(f"Task Analysis (based on {len(analyzed_tasks)} tasks)\n")

        # Analysis by tool
        print("By Tool:")
        by_tool = self._group_by_tool(analyzed_tasks)

        # Sort by success rate
        tool_stats = []
        for tool, tasks in by_tool.items():
            stats = self._calculate_success_rate(tasks)
            tool_stats.append((tool, stats))

        tool_stats.sort(key=lambda x: (-x[1]['rate'], -x[1]['total']))

        for tool, stats in tool_stats[:10]:  # Top 10
            rate_str = f"{stats['rate']:.0f}%"
            count_str = f"({stats['success']}/{stats['total']})"
            time_str = self._format_duration(stats['avg_time'])

            print(f"  {tool:15} {rate_str:>4} success {count_str:>8}   Avg time: {time_str}")

        # Analysis by category/phase
        print("\nBy Category:")
        categories = {
            'Discovery': [t for t in analyzed_tasks if 'scan' in t.name.lower() or 'discovery' in t.metadata.get('phase', '')],
            'Enumeration': [t for t in analyzed_tasks if 'enum' in t.name.lower()],
            'Exploitation': [t for t in analyzed_tasks if 'exploit' in t.name.lower() or 'brute' in t.name.lower()]
        }

        for category, tasks in categories.items():
            if tasks:
                stats = self._calculate_success_rate(tasks)
                print(f"  {category:12} {stats['rate']:.0f}% success ({stats['success']}/{stats['total']})")

        # Analysis by service
        print("\nBy Service:")
        by_service = defaultdict(list)
        for task in analyzed_tasks:
            service = task.metadata.get('service', 'general')
            port = task.metadata.get('port', '')
            key = f"{service.upper()} ({port})" if port else service.upper()
            by_service[key].append(task)

        for service, tasks in sorted(by_service.items())[:5]:  # Top 5
            stats = self._calculate_success_rate(tasks)
            if stats['total'] > 0:
                print(f"  {service:15} {stats['rate']:.0f}% success ({stats['success']}/{stats['total']})")

        # Quick wins analysis
        print("\nQuick Wins:")
        quick_wins = [t for t in analyzed_tasks if 'QUICK_WIN' in t.metadata.get('tags', [])]
        if quick_wins:
            qw_stats = self._calculate_success_rate(quick_wins)
            print(f"  ✓ {qw_stats['rate']:.0f}% success rate ({qw_stats['success']}/{qw_stats['total']})")
            print(f"  ✓ Avg time: {self._format_duration(qw_stats['avg_time'])}")

            if qw_stats['rate'] > 80:
                print("  → Recommendation: Prioritize quick wins first")

        # Recommendations
        print("\nRecommendations:")

        # Most reliable tools
        reliable = [(tool, stats) for tool, stats in tool_stats if stats['rate'] == 100 and stats['total'] >= 3]
        if reliable:
            tools_str = ", ".join([t[0] for t in reliable[:3]])
            print(f"  ⚡ Most reliable: {tools_str} (100% success)")

        # Needs review
        unreliable = [(tool, stats) for tool, stats in tool_stats if stats['rate'] < 50 and stats['total'] >= 3]
        if unreliable:
            for tool, stats in unreliable[:2]:
                print(f"  ⚠ Needs review: {tool} ({stats['rate']:.0f}% success - check parameters)")

        # Time investment
        if tool_stats:
            slowest = max(tool_stats, key=lambda x: x[1]['avg_time'])
            if slowest[1]['avg_time'] > 60:
                print(f"  📊 Time investment: {slowest[0]} averages {self._format_duration(slowest[1]['avg_time'])} per task")

        # Best ROI
        if quick_wins and qw_stats['rate'] > 80:
            print(f"  🎯 Best ROI: Quick win tasks ({qw_stats['rate']:.0f}% success, {self._format_duration(qw_stats['avg_time'])} avg)")

        self.last_action = "Analyzed task success rates"

    def _group_by_tool(self, tasks: List) -> Dict[str, List]:
        """Group tasks by tool/command type"""
        grouped = defaultdict(list)

        for task in tasks:
            # Extract tool name from command or task name
            command = task.metadata.get('command', '')
            tool = self._extract_tool_name(command)

            if not tool:
                # Try from task name
                tool = self._extract_tool_from_name(task.name)

            grouped[tool].append(task)

        return dict(grouped)

    def _extract_tool_name(self, command: str) -> str:
        """Extract tool name from command"""
        if not command:
            return 'unknown'

        # Common OSCP tools
        tools = [
            'nmap', 'gobuster', 'nikto', 'enum4linux', 'smbclient',
            'searchsploit', 'sqlmap', 'hydra', 'john', 'hashcat',
            'feroxbuster', 'ffuf', 'wpscan', 'dirbuster', 'whatweb',
            'dirb', 'wfuzz', 'crackmapexec', 'metasploit', 'msfconsole',
            'exploit', 'nc', 'netcat', 'curl', 'wget'
        ]

        command_lower = command.lower()
        for tool in tools:
            if tool in command_lower:
                return tool

        # Fallback: first word
        return command.split()[0] if command else 'unknown'

    def _extract_tool_from_name(self, name: str) -> str:
        """Extract tool name from task name"""
        if not name:
            return 'unknown'

        # Look for tool names in task name
        tools = [
            'nmap', 'gobuster', 'nikto', 'enum4linux', 'smbclient',
            'searchsploit', 'sqlmap', 'hydra', 'john', 'hashcat',
            'feroxbuster', 'ffuf', 'wpscan', 'whatweb', 'dirb'
        ]

        name_lower = name.lower()
        for tool in tools:
            if tool in name_lower:
                return tool

        return 'general'

    def _calculate_success_rate(self, tasks: List) -> Dict[str, Any]:
        """Calculate success statistics for task group"""
        if not tasks:
            return {
                'total': 0,
                'success': 0,
                'failed': 0,
                'rate': 0,
                'avg_time': 0
            }

        success = [t for t in tasks if t.status == 'completed']
        failed = [t for t in tasks if t.status == 'failed']

        # Calculate average time
        times = []
        for task in tasks:
            start = task.metadata.get('start_time')
            end = task.metadata.get('end_time')
            if start and end:
                try:
                    start_dt = datetime.fromisoformat(start)
                    end_dt = datetime.fromisoformat(end)
                    duration = (end_dt - start_dt).total_seconds()
                    times.append(duration)
                except (ValueError, TypeError):
                    # Skip invalid timestamps
                    pass

        avg_time = sum(times) / len(times) if times else 0

        return {
            'total': len(tasks),
            'success': len(success),
            'failed': len(failed),
            'rate': (len(success) / len(tasks) * 100) if tasks else 0,
            'avg_time': avg_time
        }

    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format"""
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            secs = int(seconds % 60)
            return f"{minutes}m {secs}s" if secs > 0 else f"{minutes}m"
        else:
            hours = int(seconds / 3600)
            minutes = int((seconds % 3600) / 60)
            return f"{hours}h {minutes}m"

    def handle_workflow_recorder(self, action: str = None, name: str = None):
        """Workflow recorder/player - record and replay task sequences"""
        print(DisplayManager.format_info("Workflow Recorder"))
        print("=" * 50)
        print()

        if not action:
            # Show menu
            print("Actions:")
            print("  start <name>  - Start recording workflow")
            print("  stop          - Stop current recording")
            print("  list          - List saved workflows")
            print("  play <name>   - Replay workflow on current target")
            print("  delete <name> - Delete workflow")
            print("  export <name> - Export workflow to share")
            print()

            action_input = input("Action: ").strip().split()
            if not action_input:
                return

            action = action_input[0]
            name = action_input[1] if len(action_input) > 1 else None

        if action == 'start':
            if not name:
                name = input("Workflow name: ").strip()
            self._start_recording(name)

        elif action == 'stop':
            self._stop_recording()

        elif action == 'list':
            self._list_workflows()

        elif action == 'play':
            if not name:
                name = input("Workflow name: ").strip()
            self._play_workflow(name)

        elif action == 'delete':
            if not name:
                name = input("Workflow name: ").strip()
            self._delete_workflow(name)

        elif action == 'export':
            if not name:
                name = input("Workflow name: ").strip()
            self._export_workflow(name)

        else:
            print(DisplayManager.format_error(f"Unknown action: {action}"))

    def _start_recording(self, name: str):
        """Start recording workflow"""
        if self.recording:
            print(DisplayManager.format_warning("Already recording. Stop first."))
            return

        # Sanitize name
        import re
        safe_name = re.sub(r'[^a-zA-Z0-9_-]', '-', name.strip())

        self.recording = True
        self.recording_name = safe_name
        self.recording_start = datetime.now()
        self.recorded_tasks = []

        print(DisplayManager.format_success(f"🔴 Recording workflow: {safe_name}"))
        print("Execute tasks normally. They will be recorded.")
        print("Type 'wr stop' when done.")

    def _stop_recording(self):
        """Stop recording and save workflow"""
        if not self.recording:
            print(DisplayManager.format_warning("Not currently recording"))
            return

        if not self.recorded_tasks:
            print(DisplayManager.format_warning("No tasks recorded"))
            self.recording = False
            return

        # Build workflow
        workflow = {
            'name': self.recording_name,
            'description': input("Description: ").strip() or f"Workflow: {self.recording_name}",
            'created': self.recording_start.isoformat(),
            'original_target': self.profile.target,
            'tasks': self.recorded_tasks,
            'variables': self._extract_variables(self.recorded_tasks),
            'stats': {
                'total_tasks': len(self.recorded_tasks),
                'total_time': sum(t.get('estimated_time', 0) for t in self.recorded_tasks),
                'success_rate': 100  # Initial
            }
        }

        # Save
        workflow_dir = Path.home() / '.crack' / 'workflows'
        workflow_dir.mkdir(parents=True, exist_ok=True)

        workflow_path = workflow_dir / f"{self.recording_name}.workflow.json"
        workflow_path.write_text(json.dumps(workflow, indent=2))

        print(DisplayManager.format_success(f"✓ Workflow saved: {self.recording_name}"))
        print(f"  Location: {workflow_path}")
        print(f"  Tasks: {len(self.recorded_tasks)}")

        self.recording = False
        self.recording_name = None
        self.recorded_tasks = []

    def _record_task(self, task):
        """Record task to workflow"""
        if not self.recording:
            return

        command = task.metadata.get('command')
        if not command:
            return

        # Replace target-specific values with placeholders
        command_template = self._templatize_command(command, self.profile.target)

        recorded = {
            'name': task.name,
            'command': command_template,
            'order': len(self.recorded_tasks) + 1,
            'variables': self._find_variables(command_template),
            'estimated_time': task.metadata.get('estimated_time', 60),
            'tags': task.metadata.get('tags', [])
        }

        self.recorded_tasks.append(recorded)
        print(f"  📝 Recorded: {task.name}")

    def _templatize_command(self, command: str, target: str) -> str:
        """Replace target-specific values with placeholders"""
        import re

        # Replace target IP
        templatized = command.replace(target, '<TARGET>')

        # Replace common paths with placeholders
        templatized = re.sub(r'/usr/share/wordlists/[^\s]+', '<WORDLIST>', templatized)
        templatized = re.sub(r'/tmp/[^\s]+', '<OUTPUT>', templatized)

        # Replace ports
        templatized = re.sub(r'\b(80|443|22|445|21|3306|1433|8080|3389)\b', '<PORT>', templatized)

        # Replace common IPs (attacker IP)
        templatized = re.sub(r'\b192\.168\.\d{1,3}\.\d{1,3}\b', '<LHOST>', templatized)
        templatized = re.sub(r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '<LHOST>', templatized)

        return templatized

    def _find_variables(self, command: str) -> List[str]:
        """Find all variables in command template"""
        import re
        return list(set(re.findall(r'<([A-Z_]+)>', command)))

    def _extract_variables(self, tasks: List[Dict]) -> Dict:
        """Extract all variables used in workflow"""
        variables = {}

        for task in tasks:
            for var in task.get('variables', []):
                if var not in variables:
                    variables[var] = {
                        'description': self._get_variable_description(var),
                        'example': self._get_variable_example(var),
                        'required': True
                    }

        return variables

    def _get_variable_description(self, var: str) -> str:
        """Get description for variable"""
        descriptions = {
            'TARGET': 'Target IP or hostname',
            'LHOST': 'Local/attacker IP address',
            'LPORT': 'Local port for listener',
            'PORT': 'Target port number',
            'WORDLIST': 'Path to wordlist file',
            'OUTPUT': 'Output file path',
            'URL': 'Full URL',
            'USERNAME': 'Username',
            'PASSWORD': 'Password'
        }
        return descriptions.get(var, f'{var} value')

    def _get_variable_example(self, var: str) -> str:
        """Get example for variable"""
        examples = {
            'TARGET': '192.168.45.100',
            'LHOST': '192.168.45.200',
            'LPORT': '4444',
            'PORT': '80',
            'WORDLIST': '/usr/share/wordlists/dirb/common.txt',
            'OUTPUT': '/tmp/output.txt',
            'URL': 'http://192.168.45.100',
            'USERNAME': 'admin',
            'PASSWORD': 'password123'
        }
        return examples.get(var, 'value')

    def _list_workflows(self):
        """List all saved workflows"""
        workflow_dir = Path.home() / '.crack' / 'workflows'
        if not workflow_dir.exists():
            print(DisplayManager.format_warning("No workflows found"))
            return

        workflow_files = list(workflow_dir.glob('*.workflow.json'))
        if not workflow_files:
            print(DisplayManager.format_warning("No workflows found"))
            return

        print(f"Saved Workflows ({len(workflow_files)}):\n")

        for workflow_file in sorted(workflow_files):
            try:
                workflow = json.loads(workflow_file.read_text())
                print(f"• {workflow['name']}")
                print(f"  Description: {workflow.get('description', 'N/A')}")
                print(f"  Tasks: {workflow['stats']['total_tasks']}")
                print(f"  Estimated time: {workflow['stats']['total_time']}s")
                print(f"  Created: {workflow.get('created', 'N/A')[:10]}")
                print()
            except Exception as e:
                print(f"• {workflow_file.stem} (error loading: {e})")
                print()

    def _play_workflow(self, name: str):
        """Replay workflow on current target"""
        workflow_path = Path.home() / '.crack' / 'workflows' / f"{name}.workflow.json"

        if not workflow_path.exists():
            print(DisplayManager.format_error(f"Workflow not found: {name}"))
            return

        # Load workflow
        try:
            workflow = json.loads(workflow_path.read_text())
        except Exception as e:
            self.error_handler.handle_exception(e, context="workflow loading")
            input()  # Wait for user to acknowledge
            return

        print(f"Workflow: {workflow['name']}")
        print(f"Description: {workflow['description']}")
        print(f"Tasks: {len(workflow['tasks'])}")
        print()

        # Collect variable values
        print("Enter values for variables:")
        variable_values = {}

        for var_name, var_info in workflow.get('variables', {}).items():
            prompt = f"  <{var_name}>"
            if var_info.get('description'):
                prompt += f" ({var_info['description']})"
            if var_info.get('example'):
                prompt += f" [e.g., {var_info['example']}]"
            if var_info.get('default'):
                prompt += f" [default: {var_info['default']}]"
            prompt += ": "

            value = input(prompt).strip()

            if not value:
                if var_info.get('default'):
                    value = var_info['default']
                elif var_info.get('required'):
                    print(DisplayManager.format_error(f"<{var_name}> is required"))
                    return

            variable_values[var_name] = value

        # Confirm
        print(f"\nReady to execute {len(workflow['tasks'])} tasks")
        confirm = input(DisplayManager.format_confirmation("Execute workflow?", default='Y'))

        if not InputProcessor.parse_confirmation(confirm, default='Y'):
            print("Cancelled")
            return

        # Execute tasks
        print("\nExecuting workflow...\n")

        for task_def in workflow['tasks']:
            # Substitute variables
            command = task_def['command']
            for var, value in variable_values.items():
                command = command.replace(f'<{var}>', value)

            print(f"[{task_def['order']}/{len(workflow['tasks'])}] {task_def['name']}")
            print(f"  Command: {command}")

            # Execute
            import subprocess
            result = subprocess.run(command, shell=True, capture_output=True, text=True)

            if result.returncode == 0:
                print(f"  ✓ Success")
            else:
                print(f"  ✗ Failed (exit code: {result.returncode})")

            # Show output if available
            if result.stdout:
                print(f"  Output: {result.stdout[:200]}")

            print()

        print(DisplayManager.format_success("Workflow complete!"))
        self.last_action = f"Executed workflow: {name}"

    def _delete_workflow(self, name: str):
        """Delete a workflow"""
        workflow_path = Path.home() / '.crack' / 'workflows' / f"{name}.workflow.json"

        if not workflow_path.exists():
            print(DisplayManager.format_error(f"Workflow not found: {name}"))
            return

        # Confirm deletion
        confirm = input(DisplayManager.format_confirmation(f"Delete workflow '{name}'?", default='N'))

        if not InputProcessor.parse_confirmation(confirm, default='N'):
            print("Cancelled")
            return

        workflow_path.unlink()
        print(DisplayManager.format_success(f"Deleted workflow: {name}"))

    def _export_workflow(self, name: str):
        """Export workflow to share"""
        workflow_path = Path.home() / '.crack' / 'workflows' / f"{name}.workflow.json"

        if not workflow_path.exists():
            print(DisplayManager.format_error(f"Workflow not found: {name}"))
            return

        # Load workflow
        workflow = json.loads(workflow_path.read_text())

        # Export location
        export_path = input("Export path [./workflow_export.json]: ").strip() or "./workflow_export.json"

        # Write to export location
        Path(export_path).write_text(json.dumps(workflow, indent=2))

        print(DisplayManager.format_success(f"Exported to: {export_path}"))
        print(f"\nShare this file with teammates to replay the workflow on other targets.")

    def handle_smart_suggest(self):
        """AI-lite suggestions based on current state (pattern matching)"""
        from .smart_suggest_handler import get_suggestion_rules, create_suggestion_tasks

        print(DisplayManager.format_info("Smart Suggest"))
        print("=" * 50)
        print()

        print("Analyzing current state...")
        print()

        # Load suggestion rules
        rules = get_suggestion_rules(self.profile.target)

        # Evaluate rules
        suggestions = []
        for rule in rules:
            try:
                if rule['condition'](self.profile):
                    suggestions.append(rule)
            except Exception:
                # Skip rules that fail evaluation
                continue

        if not suggestions:
            print(DisplayManager.format_success("✓ No gaps found - enumeration looks comprehensive"))
            print("\nTips:")
            print("  - Review findings for exploitation opportunities")
            print("  - Check for credential reuse")
            print("  - Consider privilege escalation paths")
            return

        # Sort by priority
        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        suggestions.sort(key=lambda r: priority_order.get(r['priority'], 99))

        # Display suggestions
        print(f"Found {len(suggestions)} suggestion(s):\n")

        for i, rule in enumerate(suggestions, 1):
            priority_icon = {
                'critical': '🔴',
                'high': '🟠',
                'medium': '🟡',
                'low': '🟢'
            }.get(rule['priority'], '⚪')

            print(f"{i}. {priority_icon} {rule['suggestion']}")
            print(f"   Command: {rule['command']}")
            print(f"   Reasoning: {rule['reasoning']}")
            print()

        # Offer to create tasks
        create = input(DisplayManager.format_confirmation("Create tasks for suggestions?", default='Y'))

        if InputProcessor.parse_confirmation(create, default='Y'):
            created = create_suggestion_tasks(self.profile, suggestions)
            print(f"\n✓ Created {created} tasks from suggestions")

        self.last_action = f"Generated {len(suggestions)} suggestions"

    def handle_alternative_commands(self):
        """Browse and execute alternative commands (shortcut: alt) (Phase 6.5 enhanced)"""
        from ..alternatives.registry import AlternativeCommandRegistry
        from ..alternatives.context import ContextResolver
        from ..alternatives.executor import AlternativeExecutor
        from ..reference.core.config import ConfigManager

        print(DisplayManager.format_info("Alternative Commands"))
        print("=" * 60)

        # Load alternatives if not already loaded
        AlternativeCommandRegistry.load_all()

        # Get stats
        stats = AlternativeCommandRegistry.get_stats()
        if stats['total_alternatives'] == 0:
            print(DisplayManager.format_warning(
                "No alternative commands available yet.\n"
                "See: /home/kali/OSCP/crack/track/alternatives/commands/README.md"
            ))
            return

        print(f"Available: {stats['total_alternatives']} alternatives in {stats['total_categories']} categories\n")

        # Check if current task has alternatives (Phase 6.5: Auto-link if needed)
        current_task_alts = []
        if hasattr(self, 'current_task') and self.current_task:
            # Get alternative_ids from task metadata
            alt_ids = self.current_task.metadata.get('alternative_ids', [])

            # Auto-link if not present (Phase 6.5)
            if not alt_ids:
                alt_ids = AlternativeCommandRegistry.auto_link_to_task(self.current_task)
                if alt_ids:
                    self.current_task.metadata['alternative_ids'] = alt_ids
                    print(DisplayManager.format_success(
                        f"Auto-linked {len(alt_ids)} alternatives to current task"
                    ))

            # Get actual AlternativeCommand objects
            current_task_alts = [
                AlternativeCommandRegistry.get(aid)
                for aid in alt_ids
                if AlternativeCommandRegistry.get(aid) is not None
            ]

        # Build menu choices
        choices = []

        # Option 1: Alternatives for current task (if any)
        if current_task_alts:
            choices.append({
                'id': 'current-task',
                'label': f'Alternatives for current task ({len(current_task_alts)} available)',
                'description': f'Task: {self.current_task.name}'
            })

        # Option 2: Browse by category
        choices.append({
            'id': 'browse-category',
            'label': 'Browse by category',
            'description': 'Web enum, privesc, file transfer, etc.'
        })

        # Option 3: Search alternatives
        choices.append({
            'id': 'search',
            'label': 'Search alternatives',
            'description': 'Search by name or description'
        })

        # Option 4: Back
        choices.append({
            'id': 'back',
            'label': 'Back',
            'description': None
        })

        # Display menu
        print(DisplayManager.format_menu(choices, title="What would you like to do?"))

        # Get selection
        choice_input = InputProcessor.get_input("Select: ")
        choice = InputProcessor.parse_choice(choice_input, choices)

        if not choice or choice['id'] == 'back':
            return

        # Handle choice
        if choice['id'] == 'current-task':
            self._execute_alternative_menu(current_task_alts)

        elif choice['id'] == 'browse-category':
            self._browse_alternatives_by_category()

        elif choice['id'] == 'search':
            self._search_alternatives()

    def _browse_alternatives_by_category(self):
        """Browse alternatives by category"""
        from ..alternatives.registry import AlternativeCommandRegistry

        # Get categories
        categories = AlternativeCommandRegistry.list_categories()

        if not categories:
            print(DisplayManager.format_warning("No categories available"))
            return

        # Build menu
        choices = [
            {'id': cat, 'label': cat.replace('_', ' ').title(), 'description': None}
            for cat in categories
        ]
        choices.append({'id': 'back', 'label': 'Back', 'description': None})

        print("\n" + DisplayManager.format_menu(choices, title="Select Category"))

        # Get selection
        choice_input = InputProcessor.get_input("Category: ")
        choice = InputProcessor.parse_choice(choice_input, choices)

        if not choice or choice['id'] == 'back':
            return

        # Get alternatives for category
        alternatives = AlternativeCommandRegistry.get_by_category(choice['id'])

        if not alternatives:
            print(DisplayManager.format_warning(f"No alternatives in category: {choice['id']}"))
            return

        self._execute_alternative_menu(alternatives)

    def _search_alternatives(self):
        """Search alternatives by query"""
        from ..alternatives.registry import AlternativeCommandRegistry

        query = input("\nSearch query: ").strip()

        if not query:
            return

        results = AlternativeCommandRegistry.search(query)

        if not results:
            print(DisplayManager.format_warning(f"No alternatives found for: {query}"))
            return

        print(f"\nFound {len(results)} alternative(s):\n")
        self._execute_alternative_menu(results)

    def _execute_alternative_menu(self, alternatives: list):
        """Display alternatives menu and execute selection (Phase 6.5 enhanced)"""
        from ..alternatives.context import ContextResolver
        from ..alternatives.executor import AlternativeExecutor
        from ..reference.core.config import ConfigManager

        # Build choices from alternatives
        choices = []
        for alt in alternatives:
            tag_str = ', '.join(alt.tags[:3]) if alt.tags else ''
            choices.append({
                'id': alt.id,
                'label': alt.name,
                'description': f"{alt.description} [{tag_str}]",
                'alternative': alt
            })

        choices.append({'id': 'back', 'label': 'Back', 'description': None})

        # Display menu
        print("\n" + DisplayManager.format_menu(choices, title="Select Alternative Command"))

        # Get selection
        choice_input = InputProcessor.get_input("Alternative: ")
        choice = InputProcessor.parse_choice(choice_input, choices)

        if not choice or choice['id'] == 'back':
            return

        alt_cmd = choice['alternative']

        # Display command details
        print(f"\n{DisplayManager.format_info(f'Alternative: {alt_cmd.name}')}")
        print(f"Description: {alt_cmd.description}")
        print(f"Command: {alt_cmd.command_template}\n")

        if alt_cmd.success_indicators:
            print("Success indicators:")
            for indicator in alt_cmd.success_indicators:
                print(f"  ✓ {indicator}")
            print()

        # Build context resolver (Phase 6.5: context hints passed to resolve())
        config = ConfigManager()
        current_task = getattr(self, 'current_task', None)

        context = ContextResolver(
            profile=self.profile,
            task=current_task,
            config=config
        )

        # Execute with dynamic variable filling
        try:
            result = AlternativeExecutor.execute(
                alt_cmd,
                context=context,
                interactive=True
            )

            if result.cancelled:
                print("\nExecution cancelled")
                return

            if result.success:
                print(f"\n{DisplayManager.format_success('Command executed successfully')}")
                if result.output:
                    print(f"\nOutput:\n{result.output}")

                # Log to profile
                self.profile.add_note(
                    note=f"Executed alternative: {alt_cmd.name}\nCommand: {result.command}",
                    source="alternative commands"
                )
                self.profile.save()
                self.last_action = f"Executed alternative: {alt_cmd.name}"

            else:
                print(f"\n{DisplayManager.format_warning('Command failed')}")
                if result.error:
                    print(f"Error: {result.error}")

        except Exception as e:
            self.error_handler.handle_exception(e, context="alternative command execution with context")
            input()  # Wait for user to acknowledge

    def _task_needs_wordlist(self, task) -> bool:
        """
        Check if task needs a wordlist (Phase 5.2)

        Detection methods:
        1. Check for <WORDLIST> or {WORDLIST} placeholder in command
        2. Check wordlist_purpose metadata field
        3. Check tool patterns (gobuster, wfuzz, hydra, etc.)

        Args:
            task: TaskNode instance

        Returns:
            True if task needs wordlist, False otherwise
        """
        # Check metadata for wordlist placeholder
        command = task.metadata.get('command', '') or ''
        if '<WORDLIST>' in command or '{WORDLIST}' in command:
            return True

        # Check wordlist_purpose field
        if task.metadata.get('wordlist_purpose'):
            return True

        # Check tool patterns
        wordlist_tools = [
            'gobuster', 'wfuzz', 'ffuf', 'dirb', 'dirbuster',
            'hydra', 'medusa', 'ncrack', 'patator',
            'john', 'hashcat',  # password cracking
            'amass', 'sublist3r',  # subdomain enum
        ]

        # Check task ID
        task_id_lower = task.id.lower()
        if any(tool in task_id_lower for tool in wordlist_tools):
            return True

        # Check command
        command_lower = command.lower()
        if any(tool in command_lower for tool in wordlist_tools):
            return True

        # Check for -w or --wordlist flags
        if '-w ' in command or '--wordlist' in command:
            return True

        return False
