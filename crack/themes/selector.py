"""
Interactive Theme Selector for CRACK

Minimal, DRY implementation with arrow key navigation and live preview.
"""

import sys
import tty
import termios
from typing import Optional, Tuple


class ThemeSelector:
    """Interactive theme selector with arrow key navigation and preview"""

    def __init__(self):
        from .manager import ThemeManager
        self.theme_mgr = ThemeManager()
        self.themes = self.theme_mgr.list_themes()
        self.current_theme = self.theme_mgr.get_theme_name()

        # Find index of current theme
        self.selected_index = 0
        for i, theme in enumerate(self.themes):
            if theme['name'] == self.current_theme:
                self.selected_index = i
                break

    def _get_key(self) -> str:
        """Get single keypress (handles arrow keys)"""
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)

            # Handle escape sequences (arrow keys)
            if ch == '\x1b':
                ch2 = sys.stdin.read(1)
                if ch2 == '[':
                    ch3 = sys.stdin.read(1)
                    return f'\x1b[{ch3}'
            return ch
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)

    def _render_preview(self, theme_name: str) -> str:
        """Generate preview text for a theme"""
        from .manager import ThemeManager
        from .colors import Colors

        # Create temporary theme manager with selected theme
        preview_mgr = ThemeManager()
        preview_mgr.set_theme(theme_name)

        # Generate preview using theme colors
        primary = Colors.from_rich(preview_mgr.get_color('primary'))
        secondary = Colors.from_rich(preview_mgr.get_color('secondary'))
        success = Colors.from_rich(preview_mgr.get_color('success'))
        warning = Colors.from_rich(preview_mgr.get_color('warning'))
        danger = Colors.from_rich(preview_mgr.get_color('danger'))
        muted = Colors.from_rich(preview_mgr.get_color('muted'))

        preview = [
            f"{primary}● Primary{Colors.RESET}  {secondary}● Secondary{Colors.RESET}",
            f"{success}✓ Success{Colors.RESET}  {warning}⚠ Warning{Colors.RESET}  {danger}✗ Error{Colors.RESET}",
            f"{muted}(Muted text for hints){Colors.RESET}"
        ]

        return "\n    ".join(preview)

    def _clear_screen(self):
        """Clear terminal screen"""
        print("\033[2J\033[H", end='')

    def _render(self):
        """Render the theme selection UI"""
        self._clear_screen()

        # Header
        print("\033[1m\033[96m" + "═" * 70 + "\033[0m")
        print("\033[1m\033[96m" + " " * 20 + "CRACK THEME SELECTOR" + " " * 30 + "\033[0m")
        print("\033[1m\033[96m" + "═" * 70 + "\033[0m\n")

        # Instructions
        print("\033[2m↑/↓: Navigate  │  Enter: Select  │  q/ESC: Cancel\033[0m\n")

        # Theme list
        for i, theme in enumerate(self.themes):
            is_selected = (i == self.selected_index)
            is_current = (theme['name'] == self.current_theme)

            # Selection indicator
            if is_selected:
                prefix = "\033[1m\033[36m▶\033[0m "
            else:
                prefix = "  "

            # Theme name (bold if selected)
            name = theme['name']
            if is_selected:
                name = f"\033[1m{name}\033[0m"

            # Current theme marker
            current_marker = " \033[32m(current)\033[0m" if is_current else ""

            # Description
            desc = theme.get('description', '')
            desc_text = f"\033[2m{desc}\033[0m" if desc else ""

            print(f"{prefix}{name}{current_marker}")
            if desc_text:
                print(f"    {desc_text}")

            # Show preview for selected theme
            if is_selected:
                print(f"\n    \033[2mPreview:\033[0m")
                print(f"    {self._render_preview(theme['name'])}\n")

        print()

    def run(self) -> Optional[str]:
        """
        Run interactive theme selector

        Returns:
            Selected theme name, or None if cancelled
        """
        try:
            self._render()

            while True:
                key = self._get_key()

                # Arrow up
                if key == '\x1b[A':
                    if self.selected_index > 0:
                        self.selected_index -= 1
                        self._render()

                # Arrow down
                elif key == '\x1b[B':
                    if self.selected_index < len(self.themes) - 1:
                        self.selected_index += 1
                        self._render()

                # Enter - select
                elif key == '\r' or key == '\n':
                    selected_theme = self.themes[self.selected_index]['name']
                    return selected_theme

                # q or ESC - cancel
                elif key == 'q' or key == '\x1b':
                    return None

        except KeyboardInterrupt:
            return None
        finally:
            # Ensure terminal is restored
            print()


def interactive_theme_selector() -> bool:
    """
    Launch interactive theme selector and apply selection

    Returns:
        True if theme was changed, False if cancelled
    """
    from .manager import ThemeManager

    # Check if running in interactive terminal
    if not sys.stdin.isatty():
        print("\n\033[31m✗ Error: Interactive theme selector requires a TTY terminal\033[0m")
        print("\033[2mTry running this command directly in your terminal, not through a pipe or script.\033[0m\n")
        return False

    selector = ThemeSelector()
    selected = selector.run()

    if selected:
        theme_mgr = ThemeManager()
        old_theme = theme_mgr.get_theme_name()

        if selected != old_theme:
            success = theme_mgr.set_theme(selected)
            if success:
                print(f"\n\033[32m✓ Theme changed from '{old_theme}' to '{selected}'\033[0m")
                print(f"\033[2mSaved to ~/.crack/config.json\033[0m\n")
                return True
            else:
                print(f"\n\033[31m✗ Failed to set theme '{selected}'\033[0m\n")
                return False
        else:
            print(f"\n\033[33m→ Theme '{selected}' already active\033[0m\n")
            return False
    else:
        print("\n\033[2mTheme selection cancelled\033[0m\n")
        return False


__all__ = ['ThemeSelector', 'interactive_theme_selector']
