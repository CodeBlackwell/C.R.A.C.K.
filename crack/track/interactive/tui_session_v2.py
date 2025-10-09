"""
TUI Session V2 - Rebuilt from scratch, starting simple

Phase 1: Minimal viable TUI
- Header (title + target)
- Simple menu (numbered choices)
- Footer (shortcuts)

Build incrementally from what worked in config panel.
"""

import time
from typing import Optional, List, Dict, Any
from io import StringIO
from contextlib import redirect_stdout

from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich import box

from ..core.state import TargetProfile
from ..core.storage import Storage
from ..recommendations.engine import RecommendationEngine

from .session import InteractiveSession
from .prompts import PromptBuilder
from .input_handler import InputProcessor
from .tui_config import ConfigPanel
from .panels.dashboard_panel import DashboardPanel
from .overlays.status_overlay import StatusOverlay
from .overlays.help_overlay import HelpOverlay
from .overlays.tree_overlay import TreeOverlay
from .overlays.execution_overlay import ExecutionOverlay
from .debug_logger import init_debug_logger, get_debug_logger


class TUISessionV2(InteractiveSession):
    """Minimal TUI - Phase 1"""

    def __init__(self, target: str, resume: bool = False, screened: bool = False, debug: bool = False):
        """Initialize minimal TUI session"""
        # Initialize parent session
        super().__init__(target, resume, screened)

        # TUI components
        self.console = Console()
        self.debug_mode = debug
        self.show_help = False
        self.config_confirmed = False  # Config Panel must be shown first

        # Initialize debug logger
        self.debug_logger = init_debug_logger(debug_enabled=debug, target=target)
        if debug:
            self.debug_logger.section("TUI SESSION INITIALIZATION")
            self.debug_logger.info(f"Target: {target}")
            self.debug_logger.info(f"Resume: {resume}")
            self.debug_logger.info(f"Screened: {screened}")
            self.debug_logger.info(f"Debug: {debug}")

    def run(self):
        """Main TUI loop - Phase 1 minimal version"""
        self.debug_logger.section("TUI RUN START")

        # Check terminal support
        if not self._supports_tui():
            self.debug_logger.warning("TUI not supported - falling back to basic mode")
            self.console.print("[yellow]⚠ TUI mode not supported - falling back[/]")
            return super().run()

        self.debug_logger.info(f"Terminal size: {self.console.width}x{self.console.height}")

        try:
            # Build simple layout
            self.debug_logger.debug("Building layout")
            layout = self._build_layout()

            self.debug_logger.debug("Starting Live context")
            with Live(
                layout,
                console=self.console,
                screen=False,
                refresh_per_second=4,
                auto_refresh=False
            ) as live:
                self.debug_logger.log_live_action("STARTED")

                # Phase 1: Show Config Panel FIRST (MANDATORY - Screen 1)
                if not self.config_confirmed:
                    self.debug_logger.log_state_transition("INIT", "CONFIG_PANEL", "mandatory first screen")
                    self._config_panel_loop(live, layout)

                # Phase 2: Main Menu (only after config confirmed)
                if self.config_confirmed:
                    self.debug_logger.log_state_transition("CONFIG_PANEL", "DASHBOARD", "config confirmed")
                    self._main_loop(live, layout)

                self.debug_logger.log_live_action("ENDED")

        except KeyboardInterrupt:
            self.debug_logger.warning("Keyboard interrupt received")
            self.console.print("\n[yellow]Interrupted. Saving...[/]")
        except Exception as e:
            self.debug_logger.exception(f"Unexpected error in TUI run: {e}")
            raise
        finally:
            self.debug_logger.info("Saving profile")
            self.profile.save()
            self.console.print("[bright_green]✓ Session saved. Goodbye![/]")
            self.debug_logger.section("TUI RUN END")

    def _supports_tui(self) -> bool:
        """Check if terminal supports TUI"""
        import sys
        if not sys.stdin.isatty():
            return False
        if self.console.width < 80 or self.console.height < 24:
            return False
        return True

    def _config_panel_loop(self, live: Live, layout: Layout):
        """
        Config Panel Loop - SCREEN 1 (MANDATORY)

        Shows config panel, allows editing, continues when user confirms.
        User CANNOT skip this - required for OSCP workflows.

        Args:
            live: Rich Live context
            layout: Layout object
        """
        # Load config
        config = ConfigPanel.load_config()

        running = True
        while running:
            # Render config panel
            config_panel = ConfigPanel.render_panel(config, self.profile.target)

            # Update header
            header_text = f"[bold cyan]CRACK Track TUI[/] | [white]Target:[/] {self.profile.target}"
            header = Panel(header_text, border_style="cyan", box=box.HEAVY)
            layout['header'].update(header)

            # Put config panel in menu area
            layout['menu'].update(config_panel)

            # Footer
            footer_text = "[cyan](1-4)[/] Edit | [cyan](5)[/] Continue | [cyan](q)[/] Quit"
            footer = Panel(footer_text, border_style="cyan", box=box.HEAVY)
            layout['footer'].update(footer)

            # Refresh display
            live.refresh()

            # Stop live to get input
            live.stop()

            # Get input
            self.console.print("\n[bold bright_yellow]Choice:[/] ", end="")
            try:
                user_input = input().strip()
            except (EOFError, KeyboardInterrupt):
                live.start()
                return  # Exit without confirming

            # Resume live
            live.start()

            # Handle input
            if user_input == 'q':
                return  # Exit without confirming

            elif user_input in ['1', '2', '3', '4']:
                # Get variable name
                var_map = {'1': 'LHOST', '2': 'LPORT', '3': 'WORDLIST', '4': 'INTERFACE'}
                var_name = var_map[user_input]

                # Stop live for editing
                live.stop()

                # Get current value
                current = ConfigPanel.get_variable(config, var_name)
                self.console.print(f"\n[cyan]{var_name}:[/] [dim](current: {current})[/]")
                self.console.print("[cyan]New value (or Enter to keep):[/] ", end="")

                try:
                    new_value = input().strip()
                    if new_value:
                        ConfigPanel.set_variable(config, var_name, new_value)
                        ConfigPanel.save_config(config)
                        self.console.print(f"[green]✓ Updated {var_name}[/]")
                    else:
                        self.console.print("[dim]No change[/]")
                except (EOFError, KeyboardInterrupt):
                    pass

                # Small pause
                time.sleep(0.5)

                # Resume live
                live.start()

            elif user_input == '5':
                # Continue to main menu
                self.config_confirmed = True
                return

    def _build_layout(self) -> Layout:
        """
        Build simple 3-panel layout:
        - Header (top)
        - Menu (center)
        - Footer (bottom)
        """
        layout = Layout()
        layout.split_column(
            Layout(name='header', size=3),
            Layout(name='menu'),
            Layout(name='footer', size=3)
        )
        return layout

    def _main_loop(self, live: Live, layout: Layout):
        """Main interaction loop"""
        self.debug_logger.section("MAIN LOOP START")

        # Store live context for _execute_choice to access
        self._live = live

        running = True
        iteration = 0

        while running:
            iteration += 1
            self.debug_logger.debug(f"Loop iteration {iteration}")

            # Refresh display
            self.debug_logger.debug("Refreshing panels")
            self._refresh_panels(layout)

            self.debug_logger.log_live_action("REFRESH")
            live.refresh()

            # Stop live to get input
            self.debug_logger.log_live_action("STOP", "before input")
            live.stop()

            # Get user input
            self.console.print("\n[bold bright_yellow]Choice:[/] ", end="")
            try:
                self.debug_logger.debug("Waiting for user input...")
                user_input = input().strip()
                self.debug_logger.log_user_input(user_input, context="main_loop")
            except (EOFError, KeyboardInterrupt):
                self.debug_logger.warning("EOF or interrupt during input")
                live.start()
                running = False
                continue

            # Resume live
            self.debug_logger.log_live_action("START", "after input")
            live.start()

            # Process input
            if user_input:
                self.debug_logger.debug(f"Processing input: '{user_input}'")
                result = self._process_input(user_input)
                self.debug_logger.debug(f"Process input result: {result}")
                if result == 'exit':
                    self.debug_logger.info("Exit requested")
                    running = False

        self.debug_logger.section("MAIN LOOP END")

    def _refresh_panels(self, layout: Layout):
        """Refresh all panels with current state"""
        # 1. Header
        header = self._render_header()
        layout['header'].update(header)

        # 2. Menu
        menu = self._render_menu()
        layout['menu'].update(menu)

        # 3. Footer
        footer = self._render_footer()
        layout['footer'].update(footer)

    def _render_header(self) -> Panel:
        """Render header panel"""
        title = f"[bold cyan]CRACK Track TUI V2[/] | [white]Target:[/] {self.profile.target}"
        return Panel(
            title,
            border_style="cyan",
            box=box.HEAVY
        )

    def _render_menu(self) -> Panel:
        """Render dashboard panel with recommendations"""
        # Get recommendations
        self._current_recommendations = RecommendationEngine.get_recommendations(self.profile)

        # Check if we have tasks
        all_tasks = self.profile.task_tree.get_all_tasks()

        if not all_tasks or len(all_tasks) == 0:
            # Empty state
            panel, choices = DashboardPanel.render_empty_state(self.profile)
        else:
            # Normal dashboard with recommendations
            panel, choices = DashboardPanel.render(self.profile, self._current_recommendations)

        # Store choices for input processing
        self._current_choices = choices

        return panel

    def _render_footer(self) -> Panel:
        """Render footer with shortcuts"""
        shortcuts = "[cyan](h)[/] Help | [cyan](s)[/] Status | [cyan](t)[/] Tree | [cyan](q)[/] Quit"
        return Panel(
            shortcuts,
            border_style="cyan",
            box=box.HEAVY
        )

    def _process_input(self, user_input: str) -> Optional[str]:
        """Process user input"""
        self.debug_logger.debug(f"_process_input called with: '{user_input}'")

        # Quit
        if user_input.lower() == 'q':
            self.debug_logger.info("Quit command received")
            return 'exit'

        # Help toggle
        if user_input.lower() == 'h':
            self.debug_logger.info("Help overlay requested")
            self._show_help()
            return None

        # Status shortcut
        if user_input.lower() == 's':
            self.debug_logger.info("Status overlay requested")
            self._show_status()
            return None

        # Tree shortcut
        if user_input.lower() == 't':
            self.debug_logger.info("Tree overlay requested")
            self._show_tree()
            return None

        # Try to parse as choice number
        try:
            choice_num = int(user_input)
            self.debug_logger.debug(f"Parsed as choice number: {choice_num}")

            if 1 <= choice_num <= len(self._current_choices):
                choice = self._current_choices[choice_num - 1]
                self.debug_logger.info(f"Executing choice {choice_num}: {choice.get('label')}")
                self._execute_choice(choice_num - 1)
            else:
                self.debug_logger.warning(f"Choice {choice_num} out of range (1-{len(self._current_choices)})")
                self.console.print(f"[red]Invalid choice: {choice_num}[/]")
        except (ValueError, AttributeError) as e:
            self.debug_logger.warning(f"Failed to parse input: {e}")
            self.console.print(f"[red]Invalid input: {user_input}[/]")

        return None

    def _execute_choice(self, index: int):
        """Execute a menu choice"""
        choice = self._current_choices[index]

        self.debug_logger.section("EXECUTE CHOICE")
        self.debug_logger.info(f"Choice index: {index}")
        self.debug_logger.info(f"Choice ID: {choice.get('id')}")
        self.debug_logger.info(f"Choice label: {choice.get('label')}")

        # Use ExecutionOverlay to handle task execution outside Live context
        # This prevents the freeze issue where Live display conflicts with terminal I/O
        self.debug_logger.info("Delegating to ExecutionOverlay")
        ExecutionOverlay.execute_choice(self._live, self, choice)

        self.debug_logger.info("Returned from ExecutionOverlay")

    def _show_help(self):
        """Show help overlay"""
        help_panel = HelpOverlay.render()
        self.console.print(help_panel)
        input()  # Wait for keypress

    def _show_status(self):
        """Show status overlay"""
        status_panel = StatusOverlay.render(self.profile)
        self.console.print(status_panel)
        input()  # Wait for keypress

    def _show_tree(self):
        """Show task tree overlay"""
        tree_panel = TreeOverlay.render(self.profile)
        self.console.print(tree_panel)
        input()  # Wait for keypress
