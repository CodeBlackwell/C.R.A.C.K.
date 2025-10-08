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

        # Define shortcuts: key → (description, handler_method_name)
        self.shortcuts: Dict[str, Tuple[str, str]] = {
            's': ('Show full status', 'show_status'),
            't': ('Show task tree', 'show_tree'),
            'r': ('Show recommendations', 'show_recommendations'),
            'n': ('Execute next recommended task', 'do_next'),
            'c': ('Change confirmation mode', 'change_confirmation'),
            'x': ('Command templates', 'show_templates'),
            'ch': ('Command history', 'command_history'),
            'pl': ('Port lookup reference', 'port_lookup'),
            'tf': ('Task filter', 'task_filter'),
            'qn': ('Quick note', 'quick_note'),
            'tt': ('Time tracker dashboard', 'time_tracker'),
            'pd': ('Progress dashboard', 'progress_dashboard'),
            'qx': ('Quick export', 'quick_export'),
            'fc': ('Finding correlator', 'finding_correlator'),
            'qe': ('Quick execute', 'quick_execute'),
            'ss': ('Session snapshot', 'session_snapshot'),
            'tr': ('Task retry', 'task_retry'),
            'be': ('Batch execute tasks', 'batch_execute'),
            'sa': ('Success analyzer', 'success_analyzer'),
            'wr': ('Workflow recorder', 'workflow_recorder'),
            'sg': ('Smart suggest', 'smart_suggest'),
            'b': ('Go back', 'go_back'),
            'h': ('Show help', 'show_help'),
            'q': ('Quit and save', 'quit')
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

        _, handler_name = self.shortcuts[shortcut_key]

        # Get handler method
        handler = getattr(self, handler_name, None)
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
        return DisplayManager.format_shortcuts_help(self.shortcuts)

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
