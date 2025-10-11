"""
Profile Selection Panel - Full-screen scan profile browser

Layout:
- Content (variable): Paginated profile list (4 per page)
- Footer (fixed 3 lines): All available commands

Features:
- Arrow key navigation (↑↓)
- Page Up/Down for pagination
- Filter by tag ('f' key): OSCP:HIGH, STEALTH, etc.
- Sort by time/risk/priority ('s' key)
- Detail overlay ('i' key): Full profile with all flags
- Quick select (1-4 keys)

Navigation flow:
Task Workspace → Profile Selection → Return with selection
"""

from typing import Dict, Any, Optional, List, Tuple, Union
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich import box
from rich.text import Text
import time


class ProfileSelectionPanel:
    """Full-screen profile selection interface"""

    # Profiles per page
    PROFILES_PER_PAGE = 4

    def __init__(self, console, theme, hotkey_handler, debug_logger, target: str):
        """
        Initialize profile selector

        Args:
            console: Rich console instance
            theme: ThemeManager instance
            hotkey_handler: HotkeyHandler instance
            debug_logger: DebugLogger instance
            target: Target hostname/IP for command preview
        """
        self.console = console
        self.theme = theme
        self.hotkey_handler = hotkey_handler
        self.debug_logger = debug_logger
        self.target = target

        # Selection state
        self.selected_idx = 0
        self.current_page = 0
        self.filter_tag = None  # None = show all
        self.sort_mode = 'priority'  # 'priority' | 'time' | 'risk'

        # Available profiles (will be filtered/sorted)
        self.all_profiles = []
        self.filtered_profiles = []

    def select_profile(self, available_profiles: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Interactive profile selection with pagination

        Args:
            available_profiles: List of scan profile dictionaries

        Returns:
            Selected profile dict or None if cancelled

        Keys:
            ↑/↓ - Navigate profiles
            PgUp/PgDn - Change page
            Enter - Select profile
            i - Show detail overlay
            f - Filter by tag
            s - Change sort order
            b - Back/Cancel
        """
        from ..log_types import LogCategory, LogLevel

        self.debug_logger.log(
            "Profile selector opened",
            category=LogCategory.UI_PANEL,
            level=LogLevel.NORMAL,
            profile_count=len(available_profiles)
        )

        self.all_profiles = available_profiles
        self._apply_filter_and_sort()

        if not self.filtered_profiles:
            self.console.print(self.theme.warning("No profiles available"))
            return None

        # Initial render
        self.console.clear()
        self.console.print(self._build_panel())

        while True:
            key = self.hotkey_handler.read_key()

            if not key:
                break

            # Handle escape sequences (arrow keys, page up/down)
            if key == '\x1b':
                time.sleep(0.01)
                next1 = self.hotkey_handler.read_key(timeout=0.05)
                next2 = self.hotkey_handler.read_key(timeout=0.05) if next1 else None

                if next1 == '[' and next2:
                    if next2 == 'A':  # Up arrow
                        self._navigate_up()
                        self.console.clear()
                        self.console.print(self._build_panel())
                        continue
                    elif next2 == 'B':  # Down arrow
                        self._navigate_down()
                        self.console.clear()
                        self.console.print(self._build_panel())
                        continue
                    elif next2 == '5':  # Page Up (ESC[5~)
                        next3 = self.hotkey_handler.read_key(timeout=0.05)
                        if next3 == '~':
                            self._page_up()
                            self.console.clear()
                            self.console.print(self._build_panel())
                            continue
                    elif next2 == '6':  # Page Down (ESC[6~)
                        next3 = self.hotkey_handler.read_key(timeout=0.05)
                        if next3 == '~':
                            self._page_down()
                            self.console.clear()
                            self.console.print(self._build_panel())
                            continue

                # ESC without arrow = cancel
                self.debug_logger.log(
                    "Profile selector cancelled (ESC)",
                    category=LogCategory.UI_INPUT,
                    level=LogLevel.NORMAL
                )
                break

            elif key in ['\r', '\n']:  # Enter - select profile
                selected_profile = self.filtered_profiles[self.selected_idx]
                self.debug_logger.log(
                    "Profile selected (Enter)",
                    category=LogCategory.UI_INPUT,
                    level=LogLevel.NORMAL,
                    profile_id=selected_profile['id']
                )
                return selected_profile

            elif key.lower() == 'b':  # Back/Cancel
                self.debug_logger.log(
                    "Profile selector cancelled (back button)",
                    category=LogCategory.UI_INPUT,
                    level=LogLevel.NORMAL
                )
                break

            elif key.lower() == 'i':  # Show detail overlay
                self._show_profile_detail()
                self.console.clear()
                self.console.print(self._build_panel())

            elif key.lower() == 'f':  # Toggle filter
                self._cycle_filter()
                self.console.clear()
                self.console.print(self._build_panel())

            elif key.lower() == 's':  # Toggle sort
                self._cycle_sort()
                self.console.clear()
                self.console.print(self._build_panel())

            elif key.isdigit():  # Numeric selection (within current page)
                idx = int(key) - 1
                page_start = self.current_page * self.PROFILES_PER_PAGE
                global_idx = page_start + idx

                if 0 <= global_idx < len(self.filtered_profiles):
                    self.selected_idx = global_idx
                    self.debug_logger.log(
                        "Numeric profile selection",
                        category=LogCategory.UI_INPUT,
                        level=LogLevel.VERBOSE,
                        key=key,
                        selected_idx=self.selected_idx
                    )
                    self.console.clear()
                    self.console.print(self._build_panel())

        return None

    def _build_panel(self) -> Layout:
        """Build profile selection panel with current page and footer"""

        # Main layout with content and footer
        main_layout = Layout()
        main_layout.split_column(
            Layout(name='content'),
            Layout(name='footer', size=3)
        )

        # Build content table
        table = Table(show_header=False, box=None, padding=(0, 1), expand=True)
        table.add_column("Content", style="white")

        # Calculate page range
        total_profiles = len(self.filtered_profiles)
        total_pages = (total_profiles + self.PROFILES_PER_PAGE - 1) // self.PROFILES_PER_PAGE
        page_start = self.current_page * self.PROFILES_PER_PAGE
        page_end = min(page_start + self.PROFILES_PER_PAGE, total_profiles)

        # Show current profiles on page
        for global_idx in range(page_start, page_end):
            profile = self.filtered_profiles[global_idx]
            local_idx = global_idx - page_start
            self._add_profile_row(table, profile, global_idx, local_idx + 1)

        # Build title with page info
        title_text = f"📋 Profile Selection (Page {self.current_page + 1}/{total_pages})"
        if self.filter_tag:
            title_text += f" | Filter: {self.filter_tag}"
        title_text += f" | Sort: {self.sort_mode.title()}"

        # Content panel
        content_panel = Panel(
            table,
            title=f"[bold {self.theme.get_color('primary')}]{title_text}[/]",
            border_style=self.theme.panel_border(),
            box=box.ROUNDED,
            padding=(1, 2)
        )
        main_layout['content'].update(content_panel)

        # Footer with all commands
        footer_panel = self._build_footer(total_pages)
        main_layout['footer'].update(footer_panel)

        return main_layout

    def _build_footer(self, total_pages: int) -> Panel:
        """Build footer panel with all available commands"""
        from rich.columns import Columns
        from rich.text import Text

        # Build command list
        commands = []

        # Navigation
        if self.current_page > 0:
            commands.append(f"PgUp:{self.theme.primary('Prev page')}")
        if self.current_page < total_pages - 1:
            commands.append(f"PgDn:{self.theme.primary('Next page')}")

        commands.extend([
            f"↑↓:{self.theme.primary('Navigate')}",
            f"1-{self.PROFILES_PER_PAGE}:{self.theme.primary('Quick select')}",
            f"Enter:{self.theme.primary('Select')}",
            f"i:{self.theme.primary('Details')}",
            f"f:{self.theme.primary('Filter')}",
            f"s:{self.theme.primary('Sort')}",
            f"b:{self.theme.primary('Back')}"
        ])

        # Format as two-line layout
        line1 = "     ".join(commands[:4])
        line2 = "     ".join(commands[4:])

        footer_content = f"{line1}\n{line2}"

        return Panel(
            footer_content,
            title=f"[bold {self.theme.get_color('primary')}]All Commands[/]",
            border_style=self.theme.panel_border(),
            box=box.ROUNDED,
            padding=(0, 2)
        )

    def _add_profile_row(self, table: Table, profile: Dict[str, Any], global_idx: int, display_num: int):
        """Add a single profile to the table"""
        from ...core.command_builder import ScanCommandBuilder

        profile_id = profile['id']
        profile_name = profile['name']
        use_case = profile['use_case']
        estimated_time = profile['estimated_time']
        detection_risk = profile.get('detection_risk', 'medium')
        tags = profile.get('tags', [])

        # Build command preview
        try:
            builder = ScanCommandBuilder(self.target, profile)
            command_preview = builder.build()
            if len(command_preview) > 80:
                command_preview = command_preview[:77] + '...'
        except Exception:
            command_preview = '[Error building command]'

        # Cursor and selection highlight
        if global_idx == self.selected_idx:
            cursor = self.theme.primary("→")
            name_display = f"[bold {self.theme.get_color('primary')}]{display_num}. {profile_name}[/]"
        else:
            cursor = " "
            name_display = f"{self.theme.muted(f'{display_num}.')} {profile_name}"

        # OSCP badge
        oscp_badge = ""
        if 'OSCP:HIGH' in tags:
            oscp_badge = f"[bold {self.theme.get_color('success')}]🎯 HIGH[/]"
        elif 'OSCP:MEDIUM' in tags:
            oscp_badge = f"[{self.theme.get_color('warning')}]🎯 MED[/]"

        # Risk badge
        risk_colors = {
            'very-low': self.theme.get_color('success'),
            'low': self.theme.get_color('success'),
            'medium': self.theme.get_color('warning'),
            'high': self.theme.get_color('danger'),
            'very-high': self.theme.get_color('danger')
        }
        risk_color = risk_colors.get(detection_risk, self.theme.get_color('muted'))
        risk_text = detection_risk.upper().replace('-', ' ')

        # Add rows
        table.add_row(f"{cursor} {name_display}")
        table.add_row(f"   {self.theme.muted('Command:')} {self.theme.primary(command_preview)}")

        # Badges line
        badges = [
            badge for badge in [
                oscp_badge,
                f"[{self.theme.get_color('primary')}]⏱ {estimated_time}[/]",
                f"[{risk_color}]🔔 {risk_text}[/]"
            ] if badge
        ]
        if badges:
            table.add_row(f"   {' | '.join(badges)}")

        # Use case
        table.add_row(f"   {self.theme.muted(use_case[:90] + '...' if len(use_case) > 90 else use_case)}")

        # Spacing
        table.add_row("")

    def _show_profile_detail(self):
        """Show full profile detail overlay"""
        from ..overlays.profile_detail_overlay import ProfileDetailOverlay

        profile = self.filtered_profiles[self.selected_idx]

        self.console.clear()
        self.console.print(ProfileDetailOverlay.render(profile, self.theme))
        self.console.print(self.theme.muted("\nPress any key to return..."))

        # Wait for dismissal
        self.hotkey_handler.read_key()

    def _navigate_up(self):
        """Navigate to previous profile"""
        if self.selected_idx > 0:
            self.selected_idx -= 1
            # Update page if needed
            self.current_page = self.selected_idx // self.PROFILES_PER_PAGE

    def _navigate_down(self):
        """Navigate to next profile"""
        if self.selected_idx < len(self.filtered_profiles) - 1:
            self.selected_idx += 1
            # Update page if needed
            self.current_page = self.selected_idx // self.PROFILES_PER_PAGE

    def _page_up(self):
        """Go to previous page"""
        if self.current_page > 0:
            self.current_page -= 1
            self.selected_idx = self.current_page * self.PROFILES_PER_PAGE

    def _page_down(self):
        """Go to next page"""
        total_pages = (len(self.filtered_profiles) + self.PROFILES_PER_PAGE - 1) // self.PROFILES_PER_PAGE
        if self.current_page < total_pages - 1:
            self.current_page += 1
            self.selected_idx = self.current_page * self.PROFILES_PER_PAGE

    def _cycle_filter(self):
        """Cycle through filter options"""
        filters = [None, 'OSCP:HIGH', 'OSCP:MEDIUM', 'STEALTH', 'QUICK_WIN']
        try:
            current_idx = filters.index(self.filter_tag)
            next_idx = (current_idx + 1) % len(filters)
        except ValueError:
            next_idx = 0

        self.filter_tag = filters[next_idx]
        self._apply_filter_and_sort()

        # Reset to first page
        self.selected_idx = 0
        self.current_page = 0

    def _cycle_sort(self):
        """Cycle through sort options"""
        sorts = ['priority', 'time', 'risk']
        try:
            current_idx = sorts.index(self.sort_mode)
            next_idx = (current_idx + 1) % len(sorts)
        except ValueError:
            next_idx = 0

        self.sort_mode = sorts[next_idx]
        self._apply_filter_and_sort()

        # Reset to first page
        self.selected_idx = 0
        self.current_page = 0

    def _apply_filter_and_sort(self):
        """Apply current filter and sort to profile list"""
        # Filter
        if self.filter_tag:
            self.filtered_profiles = [
                p for p in self.all_profiles
                if self.filter_tag in p.get('tags', [])
            ]
        else:
            self.filtered_profiles = self.all_profiles.copy()

        # Sort
        if self.sort_mode == 'priority':
            # Sort by OSCP:HIGH first, then OSCP:MEDIUM, then others
            def priority_key(p):
                tags = p.get('tags', [])
                if 'OSCP:HIGH' in tags:
                    return 0
                elif 'OSCP:MEDIUM' in tags:
                    return 1
                else:
                    return 2
            self.filtered_profiles.sort(key=priority_key)

        elif self.sort_mode == 'time':
            # Sort by estimated time (parse duration strings)
            def time_key(p):
                time_str = p.get('estimated_time', '999 hours')
                # Extract first number
                import re
                match = re.search(r'(\d+)', time_str)
                return int(match.group(1)) if match else 999
            self.filtered_profiles.sort(key=time_key)

        elif self.sort_mode == 'risk':
            # Sort by detection risk (low to high)
            risk_order = {
                'very-low': 0,
                'low': 1,
                'medium': 2,
                'high': 3,
                'very-high': 4
            }
            def risk_key(p):
                risk = p.get('detection_risk', 'medium')
                return risk_order.get(risk, 2)
            self.filtered_profiles.sort(key=risk_key)
