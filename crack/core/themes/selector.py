"""
Interactive Theme Selector for CRACK

Minimal, DRY implementation with arrow key navigation, live preview, and filtering.
Supports both built-in and pywal themes (250+ themes available with pywal16).
"""

import sys
import tty
import termios
from typing import Optional, Tuple, List, Dict, Any


class ThemeSelector:
    """Interactive theme selector with arrow key navigation, filtering, and preview"""

    def __init__(self):
        from .manager import ThemeManager
        from .presets import is_pywal_available

        self.theme_mgr = ThemeManager()
        self.all_themes = self.theme_mgr.list_themes()
        self.current_theme = self.theme_mgr.get_theme_name()
        self.pywal_available = is_pywal_available()

        # Filtering state
        self.filter_text = ""
        self.show_mode = "all"  # "all", "builtin", "pywal"

        # Apply initial filter
        self.themes = self._filter_themes()

        # Pagination state
        self.page_size = 10  # Show 10 themes per page
        self.current_page = 0

        # Find index of current theme
        self.selected_index = 0
        for i, theme in enumerate(self.themes):
            if theme['name'] == self.current_theme:
                self.selected_index = i
                # Set current page to show the selected theme
                self.current_page = i // self.page_size
                break

    def _filter_themes(self) -> List[Dict[str, Any]]:
        """Filter themes based on current filter text and mode"""
        filtered = []

        for theme in self.all_themes:
            # Apply mode filter
            is_pywal = theme['name'].startswith('pw_')

            if self.show_mode == "builtin" and is_pywal:
                continue
            elif self.show_mode == "pywal" and not is_pywal:
                continue

            # Apply text filter
            if self.filter_text:
                search_text = f"{theme['name']} {theme.get('display_name', '')} {theme.get('description', '')}".lower()
                if self.filter_text.lower() not in search_text:
                    continue

            filtered.append(theme)

        return filtered

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
        """Generate preview text for a theme (read-only, no persistence)"""
        from .presets import get_theme
        from .colors import Colors

        # Get theme directly without persisting to config
        theme = get_theme(theme_name)

        # Generate preview using theme colors
        primary = Colors.from_rich(theme['colors'].get('primary', 'cyan'))
        secondary = Colors.from_rich(theme['colors'].get('secondary', 'blue'))
        success = Colors.from_rich(theme['colors'].get('success', 'green'))
        warning = Colors.from_rich(theme['colors'].get('warning', 'yellow'))
        danger = Colors.from_rich(theme['colors'].get('danger', 'red'))
        muted = Colors.from_rich(theme['colors'].get('muted', 'dim'))

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

        # Stats bar
        builtin_count = sum(1 for t in self.all_themes if not t['name'].startswith('pw_'))
        pywal_count = sum(1 for t in self.all_themes if t['name'].startswith('pw_'))
        total_count = len(self.all_themes)

        stats = f"Total: {total_count}  │  Built-in: {builtin_count}"
        if pywal_count > 0:
            stats += f"  │  Pywal: {pywal_count}"

        print(f"\033[2m{stats}\033[0m\n")

        # Filter bar
        if self.show_mode != "all":
            mode_text = self.show_mode.capitalize()
            print(f"\033[33mFilter: {mode_text}\033[0m  ", end="")

        if self.filter_text:
            print(f"\033[33mSearch: '{self.filter_text}'\033[0m", end="")

        if self.show_mode != "all" or self.filter_text:
            print(f"  \033[2m(Showing {len(self.themes)}/{total_count})\033[0m\n")
        else:
            print()

        # Instructions
        if self.pywal_available and pywal_count > 0:
            print("\033[2m↑/↓: Navigate  │  ←/→: Page  │  Enter: Select  │  /: Search  │  f: Filter  │  c: Clear  │  q/ESC: Cancel\033[0m\n")
        else:
            print("\033[2m↑/↓: Navigate  │  ←/→: Page  │  Enter: Select  │  /: Search  │  c: Clear  │  q/ESC: Cancel\033[0m\n")

        # Calculate pagination
        total_pages = (len(self.themes) + self.page_size - 1) // self.page_size
        page_start = self.current_page * self.page_size
        page_end = min(page_start + self.page_size, len(self.themes))

        # Page indicator
        if total_pages > 1:
            print(f"\033[2mPage {self.current_page + 1}/{total_pages}\033[0m\n")
        else:
            print()

        # Theme list (current page only)
        for i in range(page_start, page_end):
            theme = self.themes[i]
            is_selected = (i == self.selected_index)
            is_current = (theme['name'] == self.current_theme)
            is_pywal = theme['name'].startswith('pw_')

            # Selection indicator
            if is_selected:
                prefix = "\033[1m\033[36m▶\033[0m "
            else:
                prefix = "  "

            # Theme name (bold if selected)
            name = theme['name']
            if is_pywal:
                # Strip pw_ prefix for display, add badge
                display_name = name[3:] if name.startswith('pw_') else name
                name = f"{display_name} \033[35m[pywal]\033[0m"

            if is_selected:
                name = f"\033[1m{name}\033[0m"

            # Current theme marker
            current_marker = " \033[32m(current)\033[0m" if is_current else ""

            # Description (truncated)
            desc = theme.get('description', '')
            if len(desc) > 60:
                desc = desc[:57] + "..."
            desc_text = f"\033[2m{desc}\033[0m" if desc else ""

            print(f"{prefix}{name}{current_marker}")
            if desc_text and not is_selected:  # Only show desc if not selected (save space)
                print(f"    {desc_text}")

            # Show preview for selected theme
            if is_selected:
                print(f"\n    \033[2mPreview:\033[0m")
                print(f"    {self._render_preview(theme['name'])}\n")

        print()

    def _prompt_search(self) -> str:
        """Prompt user for search text"""
        self._clear_screen()
        print("\n\033[1m\033[96mSearch themes:\033[0m")
        print("\033[2mEnter search text (or press Enter to cancel):\033[0m\n")
        print(f"  > ", end='', flush=True)

        # Read input in cooked mode
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
            search_text = input().strip()
            return search_text
        finally:
            pass

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
                        # Update page if needed
                        self.current_page = self.selected_index // self.page_size
                        self._render()

                # Arrow down
                elif key == '\x1b[B':
                    if self.selected_index < len(self.themes) - 1:
                        self.selected_index += 1
                        # Update page if needed
                        self.current_page = self.selected_index // self.page_size
                        self._render()

                # Arrow left (previous page)
                elif key == '\x1b[D':
                    if self.current_page > 0:
                        self.current_page -= 1
                        # Move selection to first item on new page
                        self.selected_index = self.current_page * self.page_size
                        self._render()

                # Arrow right (next page)
                elif key == '\x1b[C':
                    total_pages = (len(self.themes) + self.page_size - 1) // self.page_size
                    if self.current_page < total_pages - 1:
                        self.current_page += 1
                        # Move selection to first item on new page
                        self.selected_index = self.current_page * self.page_size
                        self._render()

                # Page Up (previous page)
                elif key == '\x1b[5':
                    if self.current_page > 0:
                        self.current_page -= 1
                        # Move selection to first item on new page
                        self.selected_index = self.current_page * self.page_size
                        self._render()

                # Page Down (next page)
                elif key == '\x1b[6':
                    total_pages = (len(self.themes) + self.page_size - 1) // self.page_size
                    if self.current_page < total_pages - 1:
                        self.current_page += 1
                        # Move selection to first item on new page
                        self.selected_index = self.current_page * self.page_size
                        self._render()

                # Home (jump to start)
                elif key == '\x1b[H':
                    self.selected_index = 0
                    self.current_page = 0
                    self._render()

                # End (jump to end)
                elif key == '\x1b[F':
                    self.selected_index = len(self.themes) - 1
                    self.current_page = self.selected_index // self.page_size
                    self._render()

                # / - search
                elif key == '/':
                    search = self._prompt_search()
                    if search:
                        self.filter_text = search
                        self.themes = self._filter_themes()
                        self.selected_index = 0
                        self.current_page = 0
                    self._render()

                # f - toggle filter mode
                elif key == 'f':
                    pywal_count = sum(1 for t in self.all_themes if t['name'].startswith('pw_'))
                    if pywal_count > 0:  # Only toggle if pywal themes exist
                        if self.show_mode == "all":
                            self.show_mode = "builtin"
                        elif self.show_mode == "builtin":
                            self.show_mode = "pywal"
                        else:
                            self.show_mode = "all"

                        self.themes = self._filter_themes()
                        self.selected_index = 0
                        self.current_page = 0
                        self._render()

                # c - clear filters
                elif key == 'c':
                    self.filter_text = ""
                    self.show_mode = "all"
                    self.themes = self._filter_themes()
                    # Try to re-select current theme
                    self.selected_index = 0
                    for i, theme in enumerate(self.themes):
                        if theme['name'] == self.current_theme:
                            self.selected_index = i
                            break
                    self.current_page = self.selected_index // self.page_size
                    self._render()

                # Enter - select
                elif key == '\r' or key == '\n':
                    if len(self.themes) > 0:
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
    from .presets import is_pywal_available

    # Check if running in interactive terminal
    if not sys.stdin.isatty():
        print("\n\033[31m✗ Error: Interactive theme selector requires a TTY terminal\033[0m")
        print("\033[2mTry running this command directly in your terminal, not through a pipe or script.\033[0m\n")
        return False

    # Show pywal status if not available (should be rare since it's a dependency)
    if not is_pywal_available():
        print("\n\033[33m⚠ Warning: Pywal16 not found (should be installed by default)\033[0m")
        print("\033[2m   Reinstall CRACK to enable 250+ themes: pip install -e .\033[0m\n")

    selector = ThemeSelector()
    selected = selector.run()

    if selected:
        theme_mgr = ThemeManager()
        old_theme = theme_mgr.get_theme_name()

        if selected != old_theme:
            success = theme_mgr.set_theme(selected)
            if success:
                is_pywal_theme = selected.startswith('pw_')
                theme_type = " [pywal]" if is_pywal_theme else ""
                print(f"\n\033[32m✓ Theme changed from '{old_theme}' to '{selected}'{theme_type}\033[0m")
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
