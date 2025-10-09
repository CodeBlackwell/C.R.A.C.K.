"""
TUI Layout Manager - Windowed interface layout builder

Creates and manages Rich Layout structure for windowed TUI mode:
- Header: Title + key target info
- Body: Split into Context | Task Tree | Main Panel
- Footer: Persistent keyboard shortcuts

Similar UX to Metasploit/tmux - no terminal flooding.
"""

from typing import Optional
from rich.layout import Layout
from rich.console import Console


class TUILayoutManager:
    """Manage windowed TUI layout with Rich"""

    def __init__(self, console: Optional[Console] = None):
        """
        Initialize layout manager

        Args:
            console: Rich Console instance (creates new if None)
        """
        self.console = console or Console()
        self.layout = self._build_initial_layout()

    def _build_initial_layout(self) -> Layout:
        """
        Build initial layout structure

        Returns:
            Rich Layout with 3-tier structure (header, body, footer)
        """
        # Root layout
        layout = Layout()

        # Split into 3 main rows: header, body, footer
        layout.split_column(
            Layout(name='header', size=3),
            Layout(name='body'),
            Layout(name='footer', size=3)
        )

        # Split body into sidebar (left) and main (right)
        layout['body'].split_row(
            Layout(name='sidebar', ratio=1),
            Layout(name='main', ratio=2)
        )

        # Split sidebar into context and tree panels
        layout['sidebar'].split_column(
            Layout(name='context', ratio=1),
            Layout(name='tree', ratio=2)
        )

        # Split main panel into menu and output
        layout['main'].split_column(
            Layout(name='menu', ratio=1),
            Layout(name='output', ratio=1, minimum_size=10)
        )

        return layout

    def update_header(self, content):
        """Update header panel"""
        self.layout['header'].update(content)

    def update_context(self, content):
        """Update context panel (target info, progress, etc.)"""
        self.layout['context'].update(content)

    def update_tree(self, content):
        """Update task tree panel"""
        self.layout['tree'].update(content)

    def update_menu(self, content):
        """Update main menu/actions panel"""
        self.layout['menu'].update(content)

    def update_output(self, content):
        """Update command output panel"""
        self.layout['output'].update(content)

    def update_footer(self, content):
        """Update footer shortcuts panel"""
        self.layout['footer'].update(content)

    def get_layout(self) -> Layout:
        """
        Get current layout

        Returns:
            Rich Layout instance
        """
        return self.layout

    def reset(self):
        """Reset layout to initial state"""
        self.layout = self._build_initial_layout()

    @property
    def terminal_size(self) -> tuple:
        """
        Get terminal size

        Returns:
            Tuple of (width, height)
        """
        return (self.console.width, self.console.height)

    def supports_tui(self) -> bool:
        """
        Check if terminal supports TUI features

        Returns:
            True if TUI supported, False otherwise
        """
        import sys

        # Must be TTY
        if not sys.stdin.isatty():
            return False

        # Minimum terminal size (80x24)
        width, height = self.terminal_size
        if width < 80 or height < 24:
            return False

        # Test Rich features
        try:
            from rich.live import Live
            return True
        except ImportError:
            return False
