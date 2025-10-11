"""
Base Panel Mixin - Provides shortcut declaration interface for panels

All panels should inherit from PanelShortcutMixin and override get_available_shortcuts()
to declare which shortcuts are valid in their context.

This enables dynamic footer rendering based on current panel.
"""

from typing import List


class PanelShortcutMixin:
    """
    Mixin providing default shortcut behavior for panels

    Panels should override get_available_shortcuts() to declare their specific shortcuts.

    Example:
        class TaskListPanel(PanelShortcutMixin):
            @classmethod
            def get_available_shortcuts(cls) -> List[str]:
                return [
                    # Global shortcuts (always available)
                    'h', 's', 't', 'q', 'b',
                    # Panel-specific
                    'f',  # Filter tasks
                    's',  # Sort tasks
                    '/',  # Search tasks
                ]
    """

    @classmethod
    def get_available_shortcuts(cls) -> List[str]:
        """
        Get list of shortcut keys valid in this panel

        Override in subclasses to declare panel-specific shortcuts.
        Default implementation returns only global shortcuts.

        Returns:
            List of shortcut keys (e.g., ['h', 's', 't', 'q', 'b'])
        """
        # Global shortcuts always available
        return ['h', 's', 't', 'q', 'b']
