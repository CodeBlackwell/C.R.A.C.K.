"""
Shortcut Handler - Keyboard shortcuts for efficiency

Single-key shortcuts for common actions:
- s: Show status
- t: Show task tree
- r: Show recommendations
- n: Execute next recommended task
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

    def get_shortcuts_help(self) -> str:
        """Get formatted shortcuts help text"""
        return DisplayManager.format_shortcuts_help(self.shortcuts)
