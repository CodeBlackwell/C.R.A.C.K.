"""
Shortcut Handler - Keyboard shortcuts for efficiency

Single-key shortcuts for common actions:
- s: Show status
- t: Show task tree
- r: Show recommendations
- n: Execute next recommended task
- c: Change confirmation mode
- x: Command templates (quick OSCP commands)
- b: Go back
- h: Show help
- q: Quit
"""

from typing import Dict, Tuple, Callable, Any
from .display import DisplayManager


class ShortcutHandler:
    """Handle keyboard shortcuts in interactive mode"""

    def __init__(self, session):
        """
        Initialize handler with session context

        Args:
            session: InteractiveSession instance
        """
        self.session = session

        # Define shortcuts with enhanced metadata
        # Structure: key → {description, handler, scope, priority}
        # Scopes: 'global', 'dashboard', 'task-list', 'workspace', 'findings', 'debug_mode', 'basic_mode'
        self.shortcuts: Dict[str, Dict[str, Any]] = {
            # Global shortcuts (always available)
            'h': {'description': 'Show help', 'handler': 'show_help', 'scope': 'global', 'priority': 1},
            's': {'description': 'Show full status', 'handler': 'show_status', 'scope': 'global', 'priority': 2},
            't': {'description': 'Show task tree', 'handler': 'show_tree', 'scope': 'global', 'priority': 3},
            'q': {'description': 'Quit and save', 'handler': 'quit', 'scope': 'global', 'priority': 4},
            'b': {'description': 'Go back', 'handler': 'go_back', 'scope': 'global', 'priority': 5},

            # Dashboard-specific shortcuts
            'n': {'description': 'Execute next recommended task', 'handler': 'do_next', 'scope': 'dashboard', 'priority': 10},
            'r': {'description': 'Show recommendations', 'handler': 'show_recommendations', 'scope': 'dashboard', 'priority': 11},

            # Basic mode shortcuts (only visible in basic/simple mode)
            'c': {'description': 'Change confirmation mode', 'handler': 'change_confirmation', 'scope': 'basic_mode', 'priority': 20},
            'x': {'description': 'Command templates', 'handler': 'show_templates', 'scope': 'basic_mode', 'priority': 21},
            'w': {'description': 'Select wordlist', 'handler': 'select_wordlist', 'scope': 'basic_mode', 'priority': 22},

            # Multi-char shortcuts (require : prefix)
            'alt': {'description': 'Alternative commands', 'handler': 'alternative_commands', 'scope': 'global', 'priority': 30},
            'ch': {'description': 'Command history', 'handler': 'command_history', 'scope': 'global', 'priority': 31},
            'pl': {'description': 'Port lookup reference', 'handler': 'port_lookup', 'scope': 'global', 'priority': 32},
            'qn': {'description': 'Quick note', 'handler': 'quick_note', 'scope': 'global', 'priority': 33},
            'pd': {'description': 'Progress dashboard', 'handler': 'progress_dashboard', 'scope': 'global', 'priority': 34},

            # Advanced features (lower priority)
            'tf': {'description': 'Task filter', 'handler': 'task_filter', 'scope': 'task-list', 'priority': 40},
            'tt': {'description': 'Time tracker dashboard', 'handler': 'time_tracker', 'scope': 'dashboard', 'priority': 41},
            'qx': {'description': 'Quick export', 'handler': 'quick_export', 'scope': 'global', 'priority': 42},
            'fc': {'description': 'Finding correlator', 'handler': 'finding_correlator', 'scope': 'findings', 'priority': 43},
            'qe': {'description': 'Quick execute', 'handler': 'quick_execute', 'scope': 'workspace', 'priority': 44},
            'ss': {'description': 'Session snapshot', 'handler': 'session_snapshot', 'scope': 'global', 'priority': 45},
            'tr': {'description': 'Task retry', 'handler': 'task_retry', 'scope': 'workspace', 'priority': 46},
            'be': {'description': 'Batch execute tasks', 'handler': 'batch_execute', 'scope': 'task-list', 'priority': 47},
            'sa': {'description': 'Success analyzer', 'handler': 'success_analyzer', 'scope': 'dashboard', 'priority': 48},
            'wr': {'description': 'Workflow recorder', 'handler': 'workflow_recorder', 'scope': 'global', 'priority': 49},
            'sg': {'description': 'Smart suggest', 'handler': 'smart_suggest', 'scope': 'dashboard', 'priority': 50},

            # Dangerous operations (lowest priority)
            'R': {'description': 'Reset session (WARNING: deletes ALL data)', 'handler': 'reset_session', 'scope': 'global', 'priority': 99},
        }

    def handle(self, shortcut_key: str) -> bool:
        """
        Handle shortcut execution

        Args:
            shortcut_key: Single character shortcut

        Returns:
            True if shortcut was handled, False if session should continue
        """
        if shortcut_key not in self.shortcuts:
            return True  # Continue session

        # Get shortcut metadata (supports both old tuple format and new dict format)
        shortcut_meta = self.shortcuts[shortcut_key]

        # Backwards compatibility: handle both tuple and dict formats
        if isinstance(shortcut_meta, tuple):
            _, handler_ref = shortcut_meta
        else:
            handler_ref = shortcut_meta['handler']

        # Support both string method names and callable handlers
        if callable(handler_ref):
            # Direct callable (e.g., for TUI-specific shortcuts)
            handler = handler_ref
        else:
            # String method name (original behavior)
            handler = getattr(self, handler_ref, None)
            if not handler:
                print(f"Shortcut '{shortcut_key}' not implemented yet")
                return True

        # Execute handler
        result = handler()

        # Some handlers return False to signal exit
        if result is False:
            return False

        return True

    def show_status(self):
        """Show complete status including ports, findings, task tree"""
        from ..formatters.console import ConsoleFormatter
        from ..recommendations.engine import RecommendationEngine

        profile = self.session.profile

        # Get recommendations
        recommendations = RecommendationEngine.get_recommendations(profile)

        # Format and display
        output = ConsoleFormatter.format_profile(profile, recommendations)
        print("\n" + output)

    def show_tree(self):
        """Show task tree only"""
        from ..formatters.console import ConsoleFormatter

        profile = self.session.profile

        # Format task tree
        output = ConsoleFormatter.format_task_tree(profile.task_tree)
        print("\n" + output)

    def show_recommendations(self):
        """Show current recommendations"""
        from ..recommendations.engine import RecommendationEngine
        from ..formatters.console import ConsoleFormatter

        profile = self.session.profile

        # Get recommendations
        recommendations = RecommendationEngine.get_recommendations(profile)

        # Format recommendations
        output = ConsoleFormatter.format_recommendations(recommendations, profile)
        print("\n" + output)

    def do_next(self):
        """Execute next recommended task"""
        from ..recommendations.engine import RecommendationEngine

        profile = self.session.profile

        # Get recommendations
        recommendations = RecommendationEngine.get_recommendations(profile)

        next_task = recommendations.get('next')
        if not next_task:
            print(DisplayManager.format_warning("No recommended tasks available"))
            return

        # Show task details
        print(DisplayManager.format_task_summary(next_task))

        # Confirm execution
        confirm = DisplayManager.format_confirmation(
            f"Execute this task?",
            default='Y'
        )

        from .input_handler import InputProcessor
        user_input = input(confirm)
        if InputProcessor.parse_confirmation(user_input, default='Y'):
            # Execute task
            self.session.execute_task(next_task)
        else:
            print("Cancelled")

    def change_confirmation(self):
        """Change confirmation mode for task execution"""
        from .input_handler import InputProcessor

        # Show current mode
        current_mode = self.session.profile.metadata.get('confirmation_mode', 'smart')
        print(DisplayManager.format_info(f"Current confirmation mode: {current_mode}"))
        print()

        # Show mode options
        print("Available modes:")
        print("  1. always - Always confirm before executing (default behavior)")
        print("  2. smart  - Skip confirmation for read-only tasks (recommended)")
        print("  3. never  - Never confirm, execute all tasks automatically (fast)")
        print("  4. batch  - Single confirmation for multiple tasks")
        print()

        # Get user choice
        choice = input("Select mode [1-4 or name]: ").strip().lower()

        # Map choice to mode
        mode_map = {
            '1': 'always',
            '2': 'smart',
            '3': 'never',
            '4': 'batch',
            'always': 'always',
            'smart': 'smart',
            'never': 'never',
            'batch': 'batch'
        }

        mode = mode_map.get(choice)
        if not mode:
            print(DisplayManager.format_error("Invalid choice"))
            return

        # Set mode
        try:
            self.session.set_confirmation_mode(mode)

            # Show explanation
            if mode == 'smart':
                print(DisplayManager.format_info(
                    "\nSmart mode enabled: Read-only tasks will execute without confirmation"
                ))
            elif mode == 'never':
                print(DisplayManager.format_warning(
                    "\nNever mode enabled: All tasks will execute automatically without confirmation"
                ))

        except ValueError as e:
            print(DisplayManager.format_error(str(e)))

    def go_back(self):
        """Go back in navigation"""
        # This will be handled by the session's navigation stack
        print(DisplayManager.format_info("Going back..."))
        return 'back'

    def show_help(self):
        """Show help text"""
        from .prompts import PromptBuilder

        help_text = PromptBuilder.build_help_text()
        print(help_text)

    def quit(self):
        """Quit interactive mode with save prompt"""
        # Confirm exit
        confirm = DisplayManager.format_confirmation(
            "Save and exit interactive mode?",
            default='Y'
        )

        from .input_handler import InputProcessor
        user_input = input(confirm)

        if InputProcessor.parse_confirmation(user_input, default='Y'):
            # Save profile
            self.session.profile.save()
            print(DisplayManager.format_success("Session saved"))
            return False  # Signal exit
        else:
            print("Continuing session...")
            return True  # Continue session

    def show_templates(self):
        """Show command template menu"""
        from .templates import TemplateRegistry
        from .input_handler import InputProcessor

        # Get all templates
        templates = TemplateRegistry.list_all()

        if not templates:
            print(DisplayManager.format_warning("No templates available"))
            return

        # Build menu choices
        choices = []
        for template in templates:
            choices.append({
                'id': template.id,
                'label': template.name,
                'description': f"{template.description} [{template.category}]",
                'template': template
            })

        choices.append({'id': 'back', 'label': 'Back', 'description': None})

        # Display menu
        print(DisplayManager.format_menu(choices, title="\nCommand Templates - Quick OSCP Commands"))

        # Get selection
        choice_input = InputProcessor.get_input("Template: ")
        choice = InputProcessor.parse_choice(choice_input, choices)

        if choice and choice['id'] != 'back':
            template = choice['template']
            self._fill_template(template)

    def _fill_template(self, template):
        """Interactive template variable filling"""
        from .input_handler import InputProcessor

        print(f"\n{DisplayManager.format_info(f'Template: {template.name}')}")
        print(f"{template.description}\n")

        # Show command with placeholders
        print(f"{DisplayManager.format_info('Command template:')}")
        print(f"  {template.command}\n")

        # Show flag explanations if available
        if template.flag_explanations:
            print("Flag Explanations:")
            for flag, explanation in template.flag_explanations.items():
                print(f"  {flag}: {explanation}")
            print()

        # Show estimated time
        if template.estimated_time:
            print(f"Estimated time: {template.estimated_time}\n")

        # Collect variable values
        print("Enter values for placeholders:")
        values = {}

        for var in template.variables:
            var_name = var['name']
            var_desc = var.get('description', '')
            var_example = var.get('example', '')
            var_required = var.get('required', True)

            # Build prompt
            prompt = f"  {var_name}"
            if var_desc:
                prompt += f" ({var_desc})"
            if var_example:
                prompt += f" [e.g., {var_example}]"
            if not var_required:
                prompt += " [optional]"
            prompt += ": "

            value = input(prompt).strip()

            # Validate required fields
            if not value and var_required:
                print(DisplayManager.format_error(f"{var_name} is required"))
                return

            if value:
                values[var_name] = value

        # Generate final command
        final_command = template.fill(values)
        print(f"\n{DisplayManager.format_success('Final command:')}")
        print(f"  {final_command}")

        # Show alternatives if available
        if template.alternatives:
            print(f"\n{DisplayManager.format_info('Manual alternatives:')}")
            for alt in template.alternatives:
                alt_filled = alt
                for key, value in values.items():
                    alt_filled = alt_filled.replace(f"<{key}>", value)
                print(f"  • {alt_filled}")
            print()

        # Show success indicators
        if template.success_indicators:
            print(f"{DisplayManager.format_info('Success indicators:')}")
            for indicator in template.success_indicators:
                print(f"  ✓ {indicator}")
            print()

        # Confirm execution
        confirm = input(DisplayManager.format_confirmation("Execute command?", default='N'))
        if InputProcessor.parse_confirmation(confirm, default='N'):
            # Execute command
            import subprocess
            try:
                print(f"\n{DisplayManager.format_info('Executing...')}\n")
                result = subprocess.run(final_command, shell=True)

                if result.returncode == 0:
                    print(DisplayManager.format_success("Command completed successfully"))
                else:
                    print(DisplayManager.format_warning(f"Command exited with code {result.returncode}"))

                # Log to profile
                self.session.profile.add_note(
                    note=f"Executed template: {template.name}\nCommand: {final_command}",
                    source="command templates"
                )
                self.session.profile.save()
                self.session.last_action = f"Executed: {template.name}"

            except Exception as e:
                print(DisplayManager.format_error(f"Execution failed: {e}"))
        else:
            print("\nCancelled. Command copied to history.")
            # Log template usage even if not executed
            self.session.profile.add_note(
                note=f"Generated command from template: {template.name}\nCommand: {final_command}",
                source="command templates"
            )
            self.session.profile.save()

    def command_history(self):
        """Browse command history (shortcut: ch)"""
        self.session.handle_command_history()

    def quick_note(self):
        """Add quick note without forms (shortcut: qn)"""
        from .input_handler import InputProcessor

        print(DisplayManager.format_info("Quick Note"))
        print("Add a timestamped note without forms\n")

        # Single-line input
        note_text = input("Note: ").strip()

        if not note_text:
            print(DisplayManager.format_warning("Note cannot be empty"))
            return

        # Optionally ask for source (or use default)
        source = input("Source [optional, press Enter for 'quick-note']: ").strip()
        if not source:
            source = 'quick-note'

        # Add to profile
        self.session.profile.add_note(
            note=note_text,
            source=source
        )
        self.session.profile.save()

        print(DisplayManager.format_success(f"Note added: {note_text[:50]}..."))
        self.session.last_action = "Added quick note"

    def task_filter(self):
        """Filter tasks by criteria (shortcut: tf)"""
        self.session.handle_filter()

    def get_shortcuts_help(self) -> str:
        """Get formatted shortcuts help text"""
        # Convert dict format to tuple format for backwards compatibility
        shortcuts_compat = {}
        for key, meta in self.shortcuts.items():
            if isinstance(meta, dict):
                shortcuts_compat[key] = (meta['description'], meta['handler'])
            else:
                shortcuts_compat[key] = meta
        return DisplayManager.format_shortcuts_help(shortcuts_compat)

    def port_lookup(self):
        """Port reference lookup (shortcut: pl)"""
        self.session.handle_port_lookup()

    def time_tracker(self):
        """Time tracking dashboard (shortcut: tt)"""
        self.session.handle_time_tracker()

    def progress_dashboard(self):
        """Progress overview (shortcut: pd)"""
        self.session.handle_progress_dashboard()

    def quick_export(self):
        """Quick export to file/clipboard (shortcut: qx)"""
        self.session.handle_quick_export()

    def finding_correlator(self):
        """Finding correlation analysis (shortcut: fc)"""
        self.session.handle_finding_correlator()

    def quick_execute(self):
        """Quick execute command without task tracking (shortcut: qe)"""
        self.session.handle_quick_execute()

    def session_snapshot(self):
        """Session snapshot manager (shortcut: ss)"""
        self.session.handle_session_snapshot()

    def task_retry(self):
        """Retry failed tasks with command editing (shortcut: tr)"""
        self.session.handle_task_retry()

    def batch_execute(self):
        """Batch execute tasks with dependency resolution (shortcut: be)"""
        self.session.handle_batch_execute()

    def success_analyzer(self):
        """Success rate analysis (shortcut: sa)"""
        self.session.handle_success_analyzer()

    def workflow_recorder(self):
        """Workflow recorder/player (shortcut: wr)"""
        self.session.handle_workflow_recorder()

    def smart_suggest(self):
        """Smart suggestions based on pattern matching (shortcut: sg)"""
        self.session.handle_smart_suggest()

    def alternative_commands(self):
        """Browse and execute alternative commands (shortcut: alt)"""
        self.session.handle_alternative_commands()

    def select_wordlist(self):
        """
        Select wordlist for current/selected task (shortcut: w)

        Phase 5.1: Wordlist selection integration
        - Get current task or prompt for task selection
        - Launch WordlistSelector.interactive_select()
        - Update task metadata with selection
        - Display confirmation message
        """
        import time
        from .input_handler import InputProcessor

        print(DisplayManager.format_info("Wordlist Selection"))

        # Get pending tasks that need wordlists
        pending_tasks = self.session.profile.task_tree.get_all_pending()
        wordlist_tasks = [
            task for task in pending_tasks
            if self._task_needs_wordlist(task)
        ]

        if not wordlist_tasks:
            print(DisplayManager.format_warning(
                "No pending tasks require wordlists.\n"
                "Wordlists are needed for: gobuster, wfuzz, hydra, medusa, etc."
            ))
            return

        # Select task
        if len(wordlist_tasks) == 1:
            task = wordlist_tasks[0]
            print(f"Task: {task.name}")
        else:
            print("\nTasks that need wordlists:\n")
            for i, task in enumerate(wordlist_tasks, 1):
                current_wordlist = task.metadata.get('wordlist', 'not set')
                print(f"  {i}. {task.name}")
                print(f"     Current: {current_wordlist}")

            choice_input = input("\nSelect task [1-{}]: ".format(len(wordlist_tasks))).strip()
            try:
                choice_idx = int(choice_input) - 1
                if 0 <= choice_idx < len(wordlist_tasks):
                    task = wordlist_tasks[choice_idx]
                else:
                    print(DisplayManager.format_error("Invalid choice"))
                    return
            except ValueError:
                print(DisplayManager.format_error("Invalid input"))
                return

        # Try to import WordlistSelector with retry logic
        print(DisplayManager.format_info("Loading wordlist system..."))

        max_retries = 15  # 30 minutes / 2 minutes per retry
        retry_interval = 120  # 2 minutes in seconds
        attempt = 0

        wordlist_manager = None
        wordlist_selector = None

        while attempt < max_retries:
            try:
                from ..wordlists.manager import WordlistManager
                from ..wordlists.selector import WordlistSelector

                # Initialize manager
                if wordlist_manager is None:
                    wordlist_manager = WordlistManager()

                # Initialize selector
                wordlist_selector = WordlistSelector(wordlist_manager, task=task)

                # If we get here, import succeeded
                break

            except ImportError as e:
                attempt += 1
                if attempt >= max_retries:
                    print(DisplayManager.format_error(
                        "WordlistSelector not available after 30 minutes.\n"
                        "Phase 2 implementation may still be in progress.\n"
                        "Please set wordlist manually in task metadata."
                    ))
                    return

                print(DisplayManager.format_warning(
                    f"WordlistSelector not ready (attempt {attempt}/{max_retries}).\n"
                    f"Retrying in 2 minutes... (Agent-1 may still be implementing Phase 2)"
                ))
                time.sleep(retry_interval)

        # Launch interactive selection
        try:
            selected = wordlist_selector.interactive_select()

            if selected:
                # Update task metadata
                task.metadata['wordlist'] = selected.path
                task.metadata['wordlist_name'] = selected.name
                task.metadata['wordlist_line_count'] = selected.line_count

                # Save profile
                self.session.profile.save()

                print(DisplayManager.format_success(
                    f"Wordlist selected: {selected.name}\n"
                    f"Path: {selected.path}\n"
                    f"Lines: {selected.line_count:,}\n"
                    f"Category: {selected.category}"
                ))

                self.session.last_action = f"Selected wordlist: {selected.name}"
            else:
                print(DisplayManager.format_warning("Wordlist selection cancelled"))

        except Exception as e:
            print(DisplayManager.format_error(f"Wordlist selection failed: {e}"))

    def _task_needs_wordlist(self, task) -> bool:
        """
        Check if task needs a wordlist

        Detection methods:
        1. Check for <WORDLIST> placeholder in command
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

    def reset_session(self):
        """
        Reset session to absolute zero (WARNING: deletes ALL data)

        Requires double confirmation:
        1. Type "RESET" to confirm understanding
        2. Final Y/N confirmation

        Works in all modes (basic, TUI, screened)
        """
        from ..core.storage import Storage
        from ..core.state import TargetProfile

        # Strong warning message
        print("\n" + "=" * 60)
        print(DisplayManager.format_error("⚠️  SESSION RESET WARNING ⚠️"))
        print("=" * 60)
        print(DisplayManager.format_warning(
            "\nThis will DELETE ALL enumeration data for this target:\n"
            "  • All discovered ports and services\n"
            "  • All findings and vulnerabilities\n"
            "  • All credentials and notes\n"
            "  • Complete task history\n"
            "  • Command execution logs\n"
            "\nThis action CANNOT be undone!\n"
        ))

        # First confirmation: Type "RESET"
        print(DisplayManager.format_info("Type 'RESET' (all caps) to confirm you understand:"))
        first_confirm = input("> ").strip()

        if first_confirm != "RESET":
            print(DisplayManager.format_success("Reset cancelled - session preserved"))
            return

        # Second confirmation: Y/N
        print(DisplayManager.format_info("\nAre you absolutely sure? [y/N]: "))
        second_confirm = input("> ").strip().lower()

        if second_confirm not in ['y', 'yes']:
            print(DisplayManager.format_success("Reset cancelled - session preserved"))
            return

        # Perform reset
        target = self.session.target
        print(DisplayManager.format_info(f"\nDeleting profile for {target}..."))

        # Delete stored profile
        Storage.delete(target)

        # Create fresh profile
        self.session.profile = TargetProfile(target)
        self.session.profile.save()

        # Reinitialize session components
        self.session.last_action = None
        if hasattr(self.session, 'command_history'):
            self.session.command_history.clear()

        print(DisplayManager.format_success(
            f"\n✓ Session reset complete\n"
            f"✓ Clean profile created for {target}\n"
            f"✓ Ready to start enumeration from zero\n"
        ))

        self.session.last_action = "Session reset to zero"
