"""
TUI Session V2 - Rebuilt from scratch, starting simple

Phase 1: Minimal viable TUI
- Header (title + target)
- Simple menu (numbered choices)
- Footer (shortcuts)

Build incrementally from what worked in config panel.
"""

import time
import subprocess
from typing import Optional, List, Dict, Any, Tuple
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
from ..core.events import EventBus
from ..recommendations.engine import RecommendationEngine
from ..parsers.output_patterns import OutputPatternMatcher
from ..services.findings_processor import FindingsProcessor

from .session import InteractiveSession
from .prompts import PromptBuilder
from .input_handler import InputProcessor
from .tui_config import ConfigPanel
from .panels.dashboard_panel import DashboardPanel
from .panels.task_workspace_panel import TaskWorkspacePanel
from .panels.task_list_panel import TaskListPanel
from .panels.findings_panel import FindingsPanel
from .panels.template_browser_panel import TemplateBrowserPanel
from .panels.template_detail_panel import TemplateDetailPanel
from .overlays.status_overlay import StatusOverlay
from .overlays.help_overlay import HelpOverlay
from .overlays.tree_overlay import TreeOverlay
from .overlays.execution_overlay import ExecutionOverlay
from .overlays.output_overlay import OutputOverlay
from .debug_logger import init_debug_logger, get_debug_logger
from .log_types import LogCategory, LogLevel
from .hotkey_input import HotkeyInputHandler
from .components.resize_handler import ResizeHandler, TerminalSizeError
from .themes.helpers import format_hotkey, format_menu_number


class TUISessionV2(InteractiveSession):
    """Minimal TUI - Phase 1"""

    def __init__(self, target: str, resume: bool = False, screened: bool = False, debug: bool = False, debug_config=None):
        """Initialize minimal TUI session"""
        # Initialize parent session with debug_config
        super().__init__(target, resume, screened, debug_config=debug_config)

        # TUI components
        self.console = Console()
        self.debug_mode = debug
        self.show_help = False
        self.config_confirmed = False  # Config Panel must be shown first

        # Debug logger inherited from parent, but initialize hotkey handler with it
        self.hotkey_handler = HotkeyInputHandler(debug_logger=self.debug_logger)

        # Resize handler for terminal resize events
        self.resize_handler = ResizeHandler()
        self.terminal_too_small = False  # Flag for graceful degradation

        # Initialize findings processor (listens for finding_added events)
        self.findings_processor = FindingsProcessor(target=target)
        self.debug_logger.log("FindingsProcessor initialized", category=LogCategory.SYSTEM_INIT, level=LogLevel.VERBOSE)

        # Initialize theme manager (loads theme from config)
        from .themes import ThemeManager
        self.theme = ThemeManager(debug_logger=self.debug_logger)
        self.debug_logger.log("ThemeManager initialized", category=LogCategory.SYSTEM_INIT, level=LogLevel.VERBOSE,
                             theme=self.theme.get_theme_name())

        # Strategic logging: TUI initialization
        self.debug_logger.log("TUI session initialization", category=LogCategory.SYSTEM_INIT, level=LogLevel.NORMAL,
                             target=target, resume=resume, screened=screened, debug=debug)

    def run(self):
        """Main TUI loop - Phase 1 minimal version"""
        # Strategic chokepoint: Main TUI loop entry
        self.debug_logger.log("TUI main loop starting", category=LogCategory.SYSTEM_INIT, level=LogLevel.NORMAL)

        # Check for interrupted task execution checkpoints (BEFORE Live context starts)
        if hasattr(self, 'checkpoint_mgr'):
            self._check_interrupted_tasks_tui()

        # Check minimum terminal size
        try:
            self.resize_handler.check_minimum_size()
            width, height = self.resize_handler.get_terminal_size()
            self.debug_logger.log("Terminal validated", category=LogCategory.SYSTEM_INIT, level=LogLevel.VERBOSE,
                                 width=width, height=height)
        except TerminalSizeError as e:
            self.debug_logger.log("Terminal too small", category=LogCategory.SYSTEM_ERROR, level=LogLevel.MINIMAL,
                                 error=str(e))
            self.console.print(self.theme.warning(f"⚠ {str(e)}"))
            return super().run()

        # Check terminal support
        if not self._supports_tui():
            self.debug_logger.log("TUI not supported - falling back", category=LogCategory.SYSTEM_ERROR, level=LogLevel.MINIMAL,
                                 terminal_width=self.console.width, terminal_height=self.console.height)
            self.console.print(self.theme.warning("⚠ TUI mode not supported - falling back"))
            return super().run()

        # Set up resize handler before Live context
        self.resize_handler.setup_handler(self._handle_resize)
        self.debug_logger.log("Resize handler registered", category=LogCategory.SYSTEM_INIT, level=LogLevel.VERBOSE)

        try:
            # Build simple layout
            self.debug_logger.log("Building TUI layout", category=LogCategory.UI_RENDER, level=LogLevel.VERBOSE)
            layout = self._build_layout()
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

                self.debug_logger.log("Live display ended", category=LogCategory.UI_LIVE, level=LogLevel.VERBOSE)

        except KeyboardInterrupt:
            self.debug_logger.log("TUI interrupted by user (Ctrl+C)", category=LogCategory.SYSTEM_SHUTDOWN, level=LogLevel.NORMAL)
            self.console.print(f"\n{self.theme.warning('Interrupted. Saving...')}")
        except Exception as e:
            self.debug_logger.log("Unexpected TUI error", category=LogCategory.SYSTEM_ERROR, level=LogLevel.MINIMAL, error=str(e), exception=True)
            raise
        finally:
            # Unregister resize handler to restore default signal handling
            self.resize_handler.unregister_handler()
            self.debug_logger.log("Resize handler unregistered", category=LogCategory.SYSTEM_SHUTDOWN, level=LogLevel.VERBOSE)

            self.debug_logger.log("TUI shutdown - saving profile", category=LogCategory.STATE_SAVE, level=LogLevel.NORMAL)
            self.profile.save()
            self.console.print(self.theme.success("✓ Session saved. Goodbye!"))
            self.debug_logger.log("TUI session ended", category=LogCategory.SYSTEM_SHUTDOWN, level=LogLevel.NORMAL)

    def _supports_tui(self) -> bool:
        """Check if terminal supports TUI"""
        import sys
        if not sys.stdin.isatty():
            return False
        if self.console.width < 80 or self.console.height < 24:
            return False
        return True

    def _handle_resize(self, width: int, height: int):
        """
        Handle terminal resize events

        Args:
            width: New terminal width in columns
            height: New terminal height in rows

        Called automatically by ResizeHandler when SIGWINCH signal is received.
        Checks minimum size and sets flag for graceful degradation if needed.
        """
        self.debug_logger.log("Terminal resized", category=LogCategory.SYSTEM_INIT, level=LogLevel.VERBOSE,
                             width=width, height=height)

        # Check if terminal meets minimum size requirements
        if width < ResizeHandler.MIN_WIDTH or height < ResizeHandler.MIN_HEIGHT:
            self.terminal_too_small = True
            self.debug_logger.log("Terminal below minimum size", category=LogCategory.SYSTEM_ERROR, level=LogLevel.MINIMAL,
                                 width=width, height=height,
                                 min_width=ResizeHandler.MIN_WIDTH, min_height=ResizeHandler.MIN_HEIGHT)
        else:
            # Reset flag if terminal is now large enough
            if self.terminal_too_small:
                self.debug_logger.log("Terminal size restored", category=LogCategory.SYSTEM_INIT, level=LogLevel.NORMAL,
                                     width=width, height=height)
            self.terminal_too_small = False

        # The Live context automatically handles re-rendering on resize
        # No explicit refresh needed - Rich detects terminal size changes

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
            # Render config panel (pass theme)
            config_panel = ConfigPanel.render_panel(config, self.profile.target, theme=self.theme)

            # Update header
            header_text = f"{self.theme.emphasis('CRACK Track TUI')} | {self.theme.muted('Target:')} {self.profile.target}"
            header = Panel(header_text, border_style=self.theme.panel_border(), box=box.HEAVY)
            layout['header'].update(header)

            # Put config panel in menu area
            layout['menu'].update(config_panel)

            # Footer
            footer_text = f"{format_hotkey(self.theme, '1-5')}:Edit | {format_hotkey(self.theme, '6')}:Continue | {format_hotkey(self.theme, 'q')}:Quit | {self.theme.muted(':')}command"
            footer = Panel(footer_text, border_style=self.theme.panel_border(), box=box.HEAVY)
            layout['footer'].update(footer)

            # Refresh display
            live.refresh()

            # Stop live to get input
            live.stop()

            # Get input (vim-style hotkeys)
            self.console.print(f"{self.theme.muted('Press key (or : for command):')} ", end="")
            try:
                # Read single key
                key = self.hotkey_handler.read_key()
                if key is None:
                    live.start()
                    return  # Exit without confirming

                # Filter out ENTER/newline (treat as no input)
                if key in ['\r', '\n']:
                    user_input = ''
                # Handle : command mode
                elif key == ':':
                    user_input = self.hotkey_handler.read_command(":")
                else:
                    user_input = key

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
                self.console.print(f"\n{self.theme.primary(f'{var_name}:')} {self.theme.muted(f'(current: {current})')}")
                self.console.print(f"{self.theme.primary('New value (or Enter to keep):')} ", end="")

                try:
                    new_value = input().strip()
                    if new_value:
                        ConfigPanel.set_variable(config, var_name, new_value)
                        ConfigPanel.save_config(config)
                        self.console.print(self.theme.success(f"✓ Updated {var_name}"))
                    else:
                        self.console.print(self.theme.muted("No change"))
                except (EOFError, KeyboardInterrupt):
                    pass

                # Small pause
                time.sleep(0.5)

                # Resume live
                live.start()

            elif user_input == '5':
                # Theme selection
                live.stop()
                self._select_theme_interactive(config)
                live.start()

            elif user_input == '6':
                # Continue to main menu
                self.config_confirmed = True
                return

    def _select_theme_interactive(self, config: Dict[str, Any]):
        """
        Interactive theme selection with arrow key navigation

        Args:
            config: Config dictionary

        Keys:
            ↑/↓ - Navigate themes
            Enter - Select theme
            b - Back to config
        """
        from .themes import list_themes
        from rich.table import Table
        import time

        self.debug_logger.log("Interactive theme selector opened", category=LogCategory.UI_PANEL, level=LogLevel.NORMAL)

        available_themes = list_themes()
        current_theme_name = config.get('theme', {}).get('current', 'oscp')

        self.debug_logger.log("Theme selector initialized", category=LogCategory.UI_PANEL, level=LogLevel.VERBOSE,
                             current_theme=current_theme_name, available_count=len(available_themes))

        # Find current theme index
        selected_idx = 0
        for i, theme_info in enumerate(available_themes):
            if theme_info['name'] == current_theme_name:
                selected_idx = i
                break

        def build_theme_panel():
            """Build theme selection panel with current selection highlighted"""
            table = Table(show_header=False, box=None, padding=(0, 1))
            table.add_column("Cursor", style=f"bold {self.theme.get_color('primary')}", width=4)
            table.add_column("Theme", style=self.theme.get_color('text'), width=15)
            table.add_column("Description", style=self.theme.get_color('muted'))

            for idx, theme_info in enumerate(available_themes):
                theme_name = theme_info['name']
                display_name = theme_info['display_name']
                description = theme_info['description']

                # Highlight selected theme
                if idx == selected_idx:
                    cursor = self.theme.primary("→")
                    theme_display = f"[bold {self.theme.get_color('primary')}]{display_name}[/]"
                else:
                    cursor = " "
                    theme_display = display_name

                # Mark current theme
                if theme_name == current_theme_name:
                    theme_display += self.theme.success(" ✓")

                table.add_row(cursor, theme_display, description)

            # Add preview section
            table.add_row("", "", "")
            table.add_row("", self.theme.emphasis("Preview:"), "")
            table.add_row("", self.theme.primary("Primary"), self.theme.muted("Panel borders, hotkeys"))
            table.add_row("", self.theme.success("Success"), self.theme.muted("Completed tasks"))
            table.add_row("", self.theme.warning("Warning"), self.theme.muted("Pending tasks"))
            table.add_row("", self.theme.danger("Danger"), self.theme.muted("Failed tasks, errors"))

            return Panel(
                table,
                title=f"[bold {self.theme.get_color('primary')}] Theme Selection [/]",
                subtitle=self.theme.muted("↑↓:Navigate | Enter:Select | b:Back"),
                border_style=self.theme.panel_border(),
                box=box.ROUNDED
            )

        # Direct console control - no Live wrapper needed
        # Print panel once initially
        self.console.clear()
        self.console.print(build_theme_panel())

        while True:
            # Wait for key
            key = self.hotkey_handler.read_key()

            if not key:
                break

            # Handle escape sequences (arrow keys)
            if key == '\x1b':  # ESC character - might be arrow key
                # Wait briefly for rest of escape sequence to arrive
                time.sleep(0.01)  # 10ms is enough for escape sequence

                # Use hotkey_handler to read next chars (already in raw mode)
                next1 = self.hotkey_handler.read_key(timeout=0.05)
                next2 = self.hotkey_handler.read_key(timeout=0.05) if next1 else None

                self.debug_logger.log("ESC sequence detected", category=LogCategory.UI_INPUT,
                                     level=LogLevel.TRACE, next1=repr(next1), next2=repr(next2))

                if next1 == '[' and next2:
                    if next2 == 'A':  # Up arrow
                        selected_idx = (selected_idx - 1) % len(available_themes)
                        self.debug_logger.log("Arrow key navigation: UP", category=LogCategory.UI_INPUT,
                                             level=LogLevel.TRACE, selected_idx=selected_idx,
                                             theme=available_themes[selected_idx]['name'])
                        # Clear and reprint panel with new selection
                        self.console.clear()
                        self.console.print(build_theme_panel())
                        continue
                    elif next2 == 'B':  # Down arrow
                        selected_idx = (selected_idx + 1) % len(available_themes)
                        self.debug_logger.log("Arrow key navigation: DOWN", category=LogCategory.UI_INPUT,
                                             level=LogLevel.TRACE, selected_idx=selected_idx,
                                             theme=available_themes[selected_idx]['name'])
                        # Clear and reprint panel with new selection
                        self.console.clear()
                        self.console.print(build_theme_panel())
                        continue
                # If not arrow key, treat ESC as cancel
                self.debug_logger.log("Theme selector cancelled (ESC)", category=LogCategory.UI_INPUT,
                                     level=LogLevel.NORMAL)
                break

            elif key in ['\r', '\n']:  # Enter - select theme
                selected_theme = available_themes[selected_idx]['name']
                selected_display = available_themes[selected_idx]['display_name']

                self.debug_logger.log("Theme selected (Enter)", category=LogCategory.UI_INPUT, level=LogLevel.NORMAL,
                                     from_theme=current_theme_name, to_theme=selected_theme)

                # Update theme in memory and config
                ConfigPanel.set_variable(config, 'THEME', selected_theme)
                ConfigPanel.save_config(config)

                # Reload theme manager (will log internally)
                from .themes import ThemeManager
                self.theme = ThemeManager(debug_logger=self.debug_logger)

                # Show confirmation
                self.console.print(f"\n{self.theme.success(f'✓ Theme changed to {selected_display}')} ", end="")
                self.hotkey_handler.read_key()  # Wait for any key

                self.debug_logger.log("Theme selector closed (theme changed)", category=LogCategory.UI_PANEL,
                                     level=LogLevel.NORMAL, new_theme=selected_theme)

                # Exit selector and return to config panel
                break

            elif key.lower() == 'b':  # Back to config
                self.debug_logger.log("Theme selector cancelled (back button)", category=LogCategory.UI_INPUT,
                                     level=LogLevel.NORMAL)
                break

            # Also support numeric selection for backward compatibility
            elif key.isdigit():
                idx = int(key) - 1
                if 0 <= idx < len(available_themes):
                    selected_idx = idx
                    self.debug_logger.log("Numeric theme selection", category=LogCategory.UI_INPUT,
                                         level=LogLevel.VERBOSE, key=key, selected_idx=selected_idx,
                                         theme=available_themes[selected_idx]['name'])
                    # Clear and reprint panel with new selection
                    self.console.clear()
                    self.console.print(build_theme_panel())

    def _build_layout(self) -> Layout:
        """
        Build 3-panel layout with dynamic footer sizing:
        - Header (top, fixed 3 rows)
        - Menu (center, flexible)
        - Footer (bottom, dynamic based on command count)
        """
        layout = Layout()

        # Calculate footer size dynamically
        footer_size = self._calculate_footer_size()

        layout.split_column(
            Layout(name='header', size=3),
            Layout(name='menu'),
            Layout(name='footer', size=footer_size)
        )
        return layout

    def _calculate_footer_size(self) -> int:
        """
        Calculate footer height based on number of commands

        Returns:
            Number of rows needed for footer (minimum 3, dynamically sized)
        """
        # Count total shortcuts
        total_shortcuts = len(self.shortcut_handler.shortcuts) + 3  # +3 for TUI-specific

        # 6 commands per row
        commands_per_row = 6
        rows_needed = (total_shortcuts + commands_per_row - 1) // commands_per_row

        # Add 2 for panel borders and title
        footer_height = rows_needed + 2

        # Minimum 3 rows, maximum 10 rows (to leave room for menu)
        return max(3, min(footer_height, 10))

    def _main_loop(self, live: Live, layout: Layout):
        """Main interaction loop"""
        # Strategic chokepoint: Main interaction loop start
        self.debug_logger.log("Main interaction loop started", category=LogCategory.SYSTEM_INIT, level=LogLevel.NORMAL)

        # Store live context AND layout for _execute_choice to access
        self._live = live
        self._layout = layout

        running = True
        iteration = 0

        # Initial render before loop starts
        self._refresh_panels(layout)
        live.refresh()

        while running:
            iteration += 1
            # Only log every 10 iterations to avoid spam
            if iteration % 10 == 0:
                self.debug_logger.log(f"Loop iteration {iteration}", category=LogCategory.UI_RENDER, level=LogLevel.TRACE)

            # Stop live to get input
            live.stop()

            # Get user input (vim-style hotkeys)
            self.console.print(f"{self.theme.muted('Press key (or : for command):')} ", end="")
            try:
                # Read single key
                key = self.hotkey_handler.read_key()

                if key is None:
                    # EOF or timeout
                    self.debug_logger.log("Input timeout or EOF", category=LogCategory.UI_INPUT, level=LogLevel.MINIMAL)
                    live.start()
                    running = False
                    continue

                # Filter out ENTER/newline (treat as no input)
                if key in ['\r', '\n']:
                    user_input = ''
                # Handle : command mode
                elif key == ':':
                    user_input = self.hotkey_handler.read_command(":")
                    # Strategic logging: Command mode input
                    self.debug_logger.log("Command mode input", category=LogCategory.UI_INPUT, level=LogLevel.VERBOSE, command=user_input)
                # Handle multi-digit numbers (buffer with timeout)
                elif key.isdigit():
                    user_input = self.hotkey_handler.read_number(key, timeout=0.5)
                    # Strategic logging: Numeric input
                    self.debug_logger.log("Numeric input", category=LogCategory.UI_INPUT, level=LogLevel.VERBOSE, number=user_input)
                else:
                    # Single-key shortcut (alphabetic or other)
                    user_input = key
                    # Strategic logging: Shortcut key
                    self.debug_logger.log("Shortcut key pressed", category=LogCategory.UI_INPUT, level=LogLevel.VERBOSE, key=user_input)

            except (EOFError, KeyboardInterrupt):
                self.debug_logger.log("Input interrupted", category=LogCategory.UI_INPUT, level=LogLevel.MINIMAL)
                live.start()
                running = False
                continue

            # Resume live
            live.start()

            # Process input
            if user_input:
                result = self._process_input(user_input)
                if result == 'exit':
                    self.debug_logger.log("Exit requested from input processing", category=LogCategory.SYSTEM_SHUTDOWN, level=LogLevel.NORMAL)
                    running = False
                    continue

            # Refresh display AFTER processing input (avoids duplication from error messages)
            self._refresh_panels(layout)
            live.refresh()

        self.debug_logger.log("Main interaction loop ended", category=LogCategory.SYSTEM_SHUTDOWN, level=LogLevel.NORMAL)

    def _task_workspace_loop(self, live: Live, layout: Layout, task):
        """
        Task workspace interaction loop

        State machine: empty → streaming → complete

        Args:
            live: Rich Live context
            layout: Layout object
            task: TaskNode instance to work on
        """
        self.debug_logger.section("TASK WORKSPACE LOOP START")
        self.debug_logger.info(f"Task: {task.name}")
        self.debug_logger.info(f"Task ID: {task.id}")

        # Initialize state
        output_state = 'empty'
        output_lines = []
        elapsed = 0.0
        exit_code = None
        findings = []

        self.debug_logger.log_state_transition("INIT", "EMPTY", "workspace opened")

        running = True
        iteration = 0

        while running:
            iteration += 1
            self.debug_logger.debug(f"Workspace loop iteration {iteration}")
            self.debug_logger.debug(f"Current state: {output_state}")

            # Define valid shortcuts based on state
            valid_shortcuts = {
                'b': 'Back to dashboard',
                ':': 'Command mode',
            }

            # Add numeric choices based on menu
            if output_state == 'empty':
                valid_shortcuts['1-3'] = 'Actions'
            elif output_state == 'complete':
                valid_shortcuts['1-4'] = 'Actions'
                valid_shortcuts['n'] = 'Next task'
                valid_shortcuts['l'] = 'List tasks'

            # Render workspace panel with current state
            self.debug_logger.debug("Rendering TaskWorkspacePanel")
            workspace_layout, choices = TaskWorkspacePanel.render(
                task=task,
                output_state=output_state,
                output_lines=output_lines,
                elapsed=elapsed,
                exit_code=exit_code,
                findings=findings,
                target=self.profile.target,
                theme=self.theme
            )
            self.debug_logger.debug(f"TaskWorkspacePanel returned {len(choices)} choices")

            # Update all layout sections
            self.debug_logger.debug("Updating layout sections")
            layout['header'].update(self._render_header())
            layout['menu'].update(workspace_layout)
            layout['footer'].update(self._render_footer(valid_shortcuts))

            # Refresh display
            self.debug_logger.log_live_action("REFRESH", "workspace display")
            live.refresh()

            # Stop live to get input
            self.debug_logger.log_live_action("STOP", "before workspace input")
            live.stop()

            # Build dynamic prompt based on state
            if output_state == 'complete':
                prompt_text = self.theme.muted("Press key (1-4:Actions, n:Next, l:List, b:Back, :cmd):") + " "
            else:
                prompt_text = self.theme.muted("Press key (1-3:Actions, b:Back, :cmd):") + " "

            # Get user input (vim-style hotkeys)
            self.console.print(prompt_text, end="")
            try:
                self.debug_logger.debug("Waiting for workspace hotkey input...")

                # Read single key
                key = self.hotkey_handler.read_key()

                if key is None:
                    # EOF or timeout
                    self.debug_logger.warning("EOF or timeout during workspace hotkey input")
                    live.start()
                    running = False
                    continue

                # Filter out ENTER/newline (treat as no input)
                if key in ['\r', '\n']:
                    self.debug_logger.debug(f"ENTER key detected (ord={ord(key)}), ignoring")
                    user_input = ''
                # Handle : command mode
                elif key == ':':
                    self.debug_logger.debug("Command mode activated in workspace")
                    user_input = self.hotkey_handler.read_command(":")
                # Handle multi-digit numbers (buffer with timeout)
                elif key.isdigit():
                    self.debug_logger.debug(f"Digit detected in workspace: {key}, checking for multi-digit")
                    user_input = self.hotkey_handler.read_number(key, timeout=0.5)
                else:
                    # Single-key shortcut
                    user_input = key

                self.debug_logger.log_user_input(user_input, context="task_workspace_hotkey")

            except (EOFError, KeyboardInterrupt):
                self.debug_logger.warning("EOF or interrupt during workspace hotkey input")
                live.start()
                running = False
                continue

            # Resume live
            self.debug_logger.log_live_action("START", "after workspace input")
            live.start()

            # Process input
            if not user_input:
                self.debug_logger.debug("Empty input, continuing loop")
                continue

            self.debug_logger.debug(f"Processing workspace input: '{user_input}'")

            # Handle 'b' (back to dashboard)
            if user_input.lower() == 'b':
                self.debug_logger.info("Back to dashboard requested")
                self.debug_logger.log_state_transition(output_state, "DASHBOARD", "back button pressed")
                running = False
                continue

            # Handle 'n' (next task) - only valid when complete
            if user_input.lower() == 'n' and output_state == 'complete':
                self.debug_logger.info("Next task requested from workspace")
                # Mark current task as complete
                task.status = 'completed'
                self.profile.save()
                # Exit workspace to return to dashboard, which will execute next task
                running = False
                continue
            elif user_input.lower() == 'n' and output_state != 'complete':
                self.debug_logger.warning("'n' pressed but not in complete state")
                live.stop()
                self.console.print(f"\n{self.theme.warning('\"n\" is only available after task completion')}")
                self.console.print(self.theme.muted("Press Enter to continue..."))
                input()
                live.start()
                continue

            # Handle 'l' (list tasks) - only valid when complete
            if user_input.lower() == 'l' and output_state == 'complete':
                self.debug_logger.info("List tasks requested from workspace")
                self.debug_logger.log_state_transition("TASK_WORKSPACE", "TASK_LIST", "l shortcut pressed")
                # Navigate to task list
                self._task_list_loop(live, layout)
                self.debug_logger.log_state_transition("TASK_LIST", "TASK_WORKSPACE", "returned from task list")
                continue
            elif user_input.lower() == 'l' and output_state != 'complete':
                self.debug_logger.warning("'l' pressed but not in complete state")
                live.stop()
                self.console.print(f"\n{self.theme.warning('\"l\" is only available after task completion')}")
                self.console.print(self.theme.muted("Press Enter to continue..."))
                input()
                live.start()
                continue

            # Try to parse as choice number
            try:
                choice_num = int(user_input)
                self.debug_logger.debug(f"Parsed as choice number: {choice_num}")

                if 1 <= choice_num <= len(choices):
                    choice = choices[choice_num - 1]
                    choice_id = choice.get('id')
                    self.debug_logger.info(f"Workspace choice selected: {choice_id} - {choice.get('label')}")

                    # Handle different choice actions
                    if choice_id.startswith('scan-'):
                        # Scan profile selected - inject command and execute
                        profile_id = choice_id[5:]  # Remove 'scan-' prefix
                        scan_profile = choice.get('scan_profile')

                        self.debug_logger.info(f"Scan profile selected: {profile_id} - {scan_profile['name']}")

                        # Build command using ScanCommandBuilder
                        from ..core.command_builder import ScanCommandBuilder
                        builder = ScanCommandBuilder(self.profile.target, scan_profile)
                        command = builder.build()

                        self.debug_logger.info(f"Generated command: {command}")

                        # Inject command into task metadata
                        task.metadata['command'] = command
                        task.metadata['scan_profile_used'] = profile_id
                        task.metadata['scan_profile_name'] = scan_profile['name']
                        task.metadata['scan_profile_strategy'] = scan_profile['use_case']
                        task.metadata['scan_profile_time'] = scan_profile['estimated_time']
                        task.metadata['scan_profile_risk'] = scan_profile.get('detection_risk', 'medium')
                        self.profile.save()

                        self.debug_logger.info(f"Scan profile metadata stored - executing immediately")

                        # Execute with streaming (no blocking confirmation)
                        try:
                            output_lines, elapsed, exit_code, findings = self._execute_task_streaming(
                                live, layout, task
                            )

                            # Update state to complete
                            output_state = 'complete'

                            self.debug_logger.log_state_transition("streaming", "complete", f"exit_code={exit_code}")
                            self.debug_logger.info(f"Execution complete - exit_code={exit_code}, elapsed={elapsed:.1f}s")
                            self.debug_logger.info(f"Output lines captured: {len(output_lines)}")
                            self.debug_logger.info(f"Findings detected: {len(findings)}")

                            # Save profile after execution
                            self.profile.save()
                            self.debug_logger.debug("Profile saved after execution")

                        except KeyboardInterrupt:
                            self.debug_logger.warning("Execution interrupted by user (Ctrl+C)")
                            task.stop_timer()
                            task.status = 'skipped'

                            # Stop live to show message clearly
                            live.stop()
                            self.console.print(f"\n{self.theme.warning('⚠ Execution interrupted')}")
                            self.console.print(self.theme.muted("Press Enter to continue..."))
                            input()
                            live.start()

                            # Reset to empty state
                            output_state = 'empty'
                            output_lines = []
                            elapsed = 0.0
                            exit_code = None
                            findings = []

                            self.debug_logger.log_state_transition("streaming", "empty", "interrupted by user")

                    elif choice_id == 'execute':
                        self.debug_logger.info("Execute action selected - starting streaming execution")
                        command = task.metadata.get('command', 'N/A')
                        self.debug_logger.info(f"Command template: {command}")

                        try:
                            # Execute with streaming
                            output_lines, elapsed, exit_code, findings = self._execute_task_streaming(
                                live, layout, task
                            )

                            # Update state to complete
                            output_state = 'complete'

                            self.debug_logger.log_state_transition("streaming", "complete", f"exit_code={exit_code}")
                            self.debug_logger.info(f"Execution complete - exit_code={exit_code}, elapsed={elapsed:.1f}s")
                            self.debug_logger.info(f"Output lines captured: {len(output_lines)}")
                            self.debug_logger.info(f"Findings detected: {len(findings)}")

                            # Save profile after execution
                            self.profile.save()
                            self.debug_logger.debug("Profile saved after execution")

                        except KeyboardInterrupt:
                            self.debug_logger.warning("Execution interrupted by user (Ctrl+C)")
                            task.stop_timer()
                            task.status = 'skipped'

                            # Stop live to show message clearly
                            live.stop()
                            self.console.print(f"\n{self.theme.warning('⚠ Execution interrupted')}")
                            self.console.print(self.theme.muted("Press Enter to continue..."))
                            input()
                            live.start()

                            # Reset to empty state
                            output_state = 'empty'
                            output_lines = []
                            elapsed = 0.0
                            exit_code = None
                            findings = []

                            self.debug_logger.log_state_transition("streaming", "empty", "interrupted by user")

                    elif choice_id == 'back':
                        self.debug_logger.info("Back action selected")
                        self.debug_logger.log_state_transition(output_state, "DASHBOARD", "back action")
                        running = False

                    else:
                        self.debug_logger.warning(f"Unhandled choice ID: {choice_id}")

                        # Stop live to show message clearly
                        live.stop()
                        self.console.print(f"\n{self.theme.warning(f'⚠ Action \"{choice_id}\" not yet implemented in Stage 2')}")
                        self.console.print(self.theme.muted("This will be added in future stages. Press Enter to continue..."))
                        input()
                        live.start()
                else:
                    self.debug_logger.warning(f"Choice {choice_num} out of range (1-{len(choices)})")

                    # Stop live to show error clearly
                    live.stop()
                    self.console.print(self.theme.danger(f"Invalid choice: {choice_num}"))
                    self.console.print(self.theme.muted(f"Please choose 1-{len(choices)} or 'b' for back. Press Enter..."))
                    input()
                    live.start()

            except ValueError as e:
                self.debug_logger.warning(f"Failed to parse workspace input: {e}")

                # Stop live to show error clearly
                live.stop()
                self.console.print(self.theme.danger(f"Invalid input: {user_input}"))
                self.console.print(self.theme.muted("Please enter a number or 'b' for back. Press Enter..."))
                input()
                live.start()

        self.debug_logger.section("TASK WORKSPACE LOOP END")
        self.debug_logger.info("Returning to dashboard")

    def _task_list_loop(self, live: Live, layout: Layout):
        """
        Task list browser loop

        Allows browsing, filtering, sorting all tasks with pagination

        Args:
            live: Rich Live context
            layout: Layout object
        """
        self.debug_logger.section("TASK LIST LOOP START")

        # Initialize state
        filter_state = None  # No filters initially
        sort_by = 'priority'  # Default sort
        page = 1

        running = True
        iteration = 0

        while running:
            iteration += 1
            self.debug_logger.debug(f"Task list loop iteration {iteration}")

            # Render task list panel
            self.debug_logger.debug(f"Rendering TaskListPanel (sort={sort_by}, page={page})")
            panel, choices = TaskListPanel.render(
                profile=self.profile,
                filter_state=filter_state,
                sort_by=sort_by,
                page=page,
                theme=self.theme
            )
            self.debug_logger.debug(f"TaskListPanel returned {len(choices)} choices")

            # Update layout
            layout['header'].update(self._render_header())
            layout['menu'].update(panel)
            layout['footer'].update(self._render_footer())

            # Refresh display
            self.debug_logger.log_live_action("REFRESH", "task list display")
            live.refresh()

            # Stop live to get input
            self.debug_logger.log_live_action("STOP", "before task list input")
            live.stop()

            # Get user input (vim-style hotkeys)
            self.console.print(f"\n{self.theme.muted('Press key (1-10:Select, f:Filter, s:Sort, b:Back):')} ", end="")
            try:
                self.debug_logger.debug("Waiting for task list hotkey input...")

                # Read single key
                key = self.hotkey_handler.read_key()

                if key is None:
                    # EOF or timeout
                    self.debug_logger.warning("EOF or timeout during task list input")
                    live.start()
                    running = False
                    continue

                # Filter out ENTER/newline (treat as no input)
                if key in ['\r', '\n']:
                    self.debug_logger.debug(f"ENTER key detected (ord={ord(key)}), ignoring")
                    user_input = ''
                # Handle : command mode
                elif key == ':':
                    self.debug_logger.debug("Command mode activated in task list")
                    user_input = self.hotkey_handler.read_command(":")
                # Handle multi-digit numbers (buffer with timeout)
                elif key.isdigit():
                    self.debug_logger.debug(f"Digit detected in task list: {key}, checking for multi-digit")
                    user_input = self.hotkey_handler.read_number(key, timeout=0.5)
                else:
                    # Single-key shortcut
                    user_input = key

                self.debug_logger.log_user_input(user_input, context="task_list_hotkey")

            except (EOFError, KeyboardInterrupt):
                self.debug_logger.warning("EOF or interrupt during task list input")
                live.start()
                running = False
                continue

            # Resume live
            self.debug_logger.log_live_action("START", "after task list input")
            live.start()

            # Process input
            if not user_input:
                self.debug_logger.debug("Empty input, continuing loop")
                continue

            self.debug_logger.debug(f"Processing task list input: '{user_input}'")

            # Handle shortcuts
            if user_input.lower() == 'b':
                self.debug_logger.info("Back to dashboard requested")
                self.debug_logger.log_state_transition("TASK_LIST", "DASHBOARD", "back button pressed")
                running = False
                continue

            elif user_input.lower() == 'f':
                self.debug_logger.info("Filter menu requested (placeholder)")
                live.stop()
                self.console.print(f"\n{self.theme.warning('Filter menu not yet implemented')}")
                self.console.print(self.theme.muted("Press Enter to continue..."))
                input()
                live.start()
                continue

            elif user_input.lower() == 's':
                self.debug_logger.info("Sort menu requested (placeholder)")
                live.stop()
                self.console.print(f"\n{self.theme.warning('Sort menu not yet implemented')}")
                self.console.print(self.theme.muted("Press Enter to continue..."))
                input()
                live.start()
                continue

            elif user_input.lower() == 'n':
                self.debug_logger.info("Next page requested")
                # Find next page choice
                next_choice = next((c for c in choices if c.get('action') == 'next_page'), None)
                if next_choice:
                    page = next_choice['page']
                    self.debug_logger.debug(f"Moving to page {page}")
                else:
                    self.debug_logger.debug("No next page available")
                continue

            elif user_input.lower() == 'p':
                self.debug_logger.info("Previous page requested")
                # Find prev page choice
                prev_choice = next((c for c in choices if c.get('action') == 'prev_page'), None)
                if prev_choice:
                    page = prev_choice['page']
                    self.debug_logger.debug(f"Moving to page {page}")
                else:
                    self.debug_logger.debug("No previous page available")
                continue

            # Try to parse as task selection number
            try:
                choice_num = int(user_input)
                self.debug_logger.debug(f"Parsed as choice number: {choice_num}")

                if 1 <= choice_num <= len(choices):
                    choice = choices[choice_num - 1]
                    choice_action = choice.get('action')
                    self.debug_logger.info(f"Task list choice selected: {choice_action}")

                    # Handle select_task action
                    if choice_action == 'select_task':
                        task = choice.get('task')
                        if task:
                            self.debug_logger.info(f"Navigating to workspace for task: {task.name}")
                            self.debug_logger.log_state_transition("TASK_LIST", "TASK_WORKSPACE", f"selected: {task.name}")

                            # Navigate to task workspace
                            self._task_workspace_loop(live, layout, task)

                            self.debug_logger.log_state_transition("TASK_WORKSPACE", "TASK_LIST", "returned from workspace")
                            self.debug_logger.info("Returned from task workspace to task list")
                            # Stay in task list loop, don't exit
                        else:
                            self.debug_logger.warning("select_task choice has no task object")

                    else:
                        self.debug_logger.warning(f"Unhandled action: {choice_action}")

                else:
                    self.debug_logger.warning(f"Choice {choice_num} out of range (1-{len(choices)})")

                    live.stop()
                    self.console.print(self.theme.danger(f"Invalid choice: {choice_num}"))
                    self.console.print(self.theme.muted(f"Please choose 1-{len(choices)} or 'b' for back. Press Enter..."))
                    input()
                    live.start()

            except ValueError as e:
                self.debug_logger.warning(f"Failed to parse task list input: {e}")

                live.stop()
                self.console.print(self.theme.danger(f"Invalid input: {user_input}"))
                self.console.print(self.theme.muted("Please enter a number or shortcut. Press Enter..."))
                input()
                live.start()

        self.debug_logger.section("TASK LIST LOOP END")
        self.debug_logger.info("Returning to dashboard")

    def _findings_loop(self, live: Live, layout: Layout):
        """
        Findings browser loop

        Allows browsing and filtering findings with pagination

        Args:
            live: Rich Live context
            layout: Layout object
        """
        self.debug_logger.section("FINDINGS LOOP START")

        # Initialize state
        filter_type = 'all'  # No filters initially
        page = 1

        running = True
        iteration = 0

        while running:
            iteration += 1
            self.debug_logger.debug(f"Findings loop iteration {iteration}")

            # Render findings panel
            self.debug_logger.debug(f"Rendering FindingsPanel (filter={filter_type}, page={page})")
            panel, choices = FindingsPanel.render(
                profile=self.profile,
                filter_type=filter_type,
                page=page,
                theme=self.theme
            )
            self.debug_logger.debug(f"FindingsPanel returned {len(choices)} choices")

            # Update layout
            layout['header'].update(self._render_header())
            layout['menu'].update(panel)
            layout['footer'].update(self._render_footer())

            # Refresh display
            self.debug_logger.log_live_action("REFRESH", "findings display")
            live.refresh()

            # Stop live to get input
            self.debug_logger.log_live_action("STOP", "before findings input")
            live.stop()

            # Get user input (vim-style hotkeys)
            self.console.print(f"\n{self.theme.muted('Press key (f:Filter, e:Export, b:Back):')} ", end="")
            try:
                self.debug_logger.debug("Waiting for findings hotkey input...")

                # Read single key
                key = self.hotkey_handler.read_key()

                if key is None:
                    # EOF or timeout
                    self.debug_logger.warning("EOF or timeout during findings input")
                    live.start()
                    running = False
                    continue

                # Filter out ENTER/newline (treat as no input)
                if key in ['\r', '\n']:
                    self.debug_logger.debug(f"ENTER key detected (ord={ord(key)}), ignoring")
                    user_input = ''
                # Handle : command mode
                elif key == ':':
                    self.debug_logger.debug("Command mode activated in findings")
                    user_input = self.hotkey_handler.read_command(":")
                # Handle multi-digit numbers (buffer with timeout)
                elif key.isdigit():
                    self.debug_logger.debug(f"Digit detected in findings: {key}, checking for multi-digit")
                    user_input = self.hotkey_handler.read_number(key, timeout=0.5)
                else:
                    # Single-key shortcut
                    user_input = key

                self.debug_logger.log_user_input(user_input, context="findings_hotkey")

            except (EOFError, KeyboardInterrupt):
                self.debug_logger.warning("EOF or interrupt during findings input")
                live.start()
                running = False
                continue

            # Resume live
            self.debug_logger.log_live_action("START", "after findings input")
            live.start()

            # Process input
            if not user_input:
                self.debug_logger.debug("Empty input, continuing loop")
                continue

            self.debug_logger.debug(f"Processing findings input: '{user_input}'")

            # Handle shortcuts
            if user_input.lower() == 'b':
                self.debug_logger.info("Back to dashboard requested")
                self.debug_logger.log_state_transition("FINDINGS", "DASHBOARD", "back button pressed")
                running = False
                continue

            elif user_input.lower() == 'f':
                self.debug_logger.info("Filter menu requested (placeholder)")
                live.stop()
                self.console.print(f"\n{self.theme.warning('Filter menu not yet implemented')}")
                self.console.print(self.theme.muted("Press Enter to continue..."))
                input()
                live.start()
                continue

            elif user_input.lower() == 'e':
                self.debug_logger.info("Export requested (placeholder)")
                live.stop()
                self.console.print(f"\n{self.theme.warning('Export not yet implemented')}")
                self.console.print(self.theme.muted("Press Enter to continue..."))
                input()
                live.start()
                continue

            elif user_input.lower() == 'n':
                self.debug_logger.info("Next page requested")
                # Find next page choice
                next_choice = next((c for c in choices if c.get('action') == 'next_page'), None)
                if next_choice:
                    page = next_choice['page']
                    self.debug_logger.debug(f"Moving to page {page}")
                else:
                    self.debug_logger.debug("No next page available")
                continue

            elif user_input.lower() == 'p':
                self.debug_logger.info("Previous page requested")
                # Find prev page choice
                prev_choice = next((c for c in choices if c.get('action') == 'prev_page'), None)
                if prev_choice:
                    page = prev_choice['page']
                    self.debug_logger.debug(f"Moving to page {page}")
                else:
                    self.debug_logger.debug("No previous page available")
                continue

            # Try to parse as finding selection number (future feature)
            try:
                choice_num = int(user_input)
                self.debug_logger.debug(f"Parsed as choice number: {choice_num}")

                if 1 <= choice_num <= len(choices):
                    choice = choices[choice_num - 1]
                    choice_action = choice.get('action')
                    self.debug_logger.info(f"Findings choice selected: {choice_action}")

                    # Handle view action (future feature)
                    if choice_action == 'view':
                        self.debug_logger.info("View finding details (placeholder)")
                        live.stop()
                        self.console.print(f"\n{self.theme.warning('Finding details view not yet implemented')}")
                        self.console.print(self.theme.muted("Press Enter to continue..."))
                        input()
                        live.start()

                    else:
                        self.debug_logger.warning(f"Unhandled action: {choice_action}")

                else:
                    self.debug_logger.warning(f"Choice {choice_num} out of range (1-{len(choices)})")

                    live.stop()
                    self.console.print(self.theme.danger(f"Invalid choice: {choice_num}"))
                    self.console.print(self.theme.muted(f"Please choose 1-{len(choices)} or 'b' for back. Press Enter..."))
                    input()
                    live.start()

            except ValueError as e:
                self.debug_logger.warning(f"Failed to parse findings input: {e}")

                live.stop()
                self.console.print(self.theme.danger(f"Invalid input: {user_input}"))
                self.console.print(self.theme.muted("Please enter a number or shortcut. Press Enter..."))
                input()
                live.start()

        self.debug_logger.section("FINDINGS LOOP END")
    def _template_browser_loop(self, live: Live, layout: Layout):
        """
        Template browser loop - navigate and select command templates

        Args:
            live: Rich Live context
            layout: Layout object
        """
        self.debug_logger.section("TEMPLATE BROWSER LOOP START")

        # Initialize state
        category = 'all'  # Show all templates initially
        page = 1

        running = True
        iteration = 0

        while running:
            iteration += 1
            self.debug_logger.debug(f"Template browser loop iteration {iteration}")

            # Render template browser panel
            self.debug_logger.debug(f"Rendering TemplateBrowserPanel (category={category}, page={page})")
            panel, choices = TemplateBrowserPanel.render(
                category=category,
                page=page,
                theme=self.theme
            )
            self.debug_logger.debug(f"TemplateBrowserPanel returned {len(choices)} choices")

            # Update layout
            layout['header'].update(self._render_header())
            layout['menu'].update(panel)
            layout['footer'].update(self._render_footer())

            # Refresh display
            self.debug_logger.log_live_action("REFRESH", "template browser display")
            live.refresh()

            # Stop live to get input
            self.debug_logger.log_live_action("STOP", "before template browser input")
            live.stop()

            # Get user input (vim-style hotkeys)
            self.console.print(f"\n{self.theme.muted('Press key (1-12:Select, c:Category, s:Search, b:Back):')} ", end="")
            try:
                self.debug_logger.debug("Waiting for template browser hotkey input...")

                # Read single key
                key = self.hotkey_handler.read_key()

                if key is None:
                    # EOF or timeout
                    self.debug_logger.warning("EOF or timeout during template browser input")
                    live.start()
                    running = False
                    continue

                # Filter out ENTER/newline (treat as no input)
                if key in ['\r', '\n']:
                    self.debug_logger.debug(f"ENTER key detected (ord={ord(key)}), ignoring")
                    user_input = ''
                # Handle : command mode
                elif key == ':':
                    self.debug_logger.debug("Command mode activated in template browser")
                    user_input = self.hotkey_handler.read_command(":")
                # Handle multi-digit numbers (buffer with timeout)
                elif key.isdigit():
                    self.debug_logger.debug(f"Digit detected in template browser: {key}, checking for multi-digit")
                    user_input = self.hotkey_handler.read_number(key, timeout=0.5)
                else:
                    # Single-key shortcut
                    user_input = key

                self.debug_logger.log_user_input(user_input, context="template_browser_hotkey")

            except (EOFError, KeyboardInterrupt):
                self.debug_logger.warning("EOF or interrupt during template browser input")
                live.start()
                running = False
                continue

            # Resume live
            self.debug_logger.log_live_action("START", "after template browser input")
            live.start()

            # Process input
            if not user_input:
                self.debug_logger.debug("Empty input, continuing loop")
                continue

            self.debug_logger.debug(f"Processing template browser input: '{user_input}'")

            # Handle shortcuts
            if user_input.lower() == 'b':
                self.debug_logger.info("Back to dashboard requested")
                self.debug_logger.log_state_transition("TEMPLATE_BROWSER", "DASHBOARD", "back button pressed")
                running = False
                continue

            elif user_input.lower() == 'c':
                self.debug_logger.info("Category filter requested")
                live.stop()

                self.console.print(f"\n{self.theme.emphasis('Select Category:')}")
                self.console.print(f"  {format_menu_number(self.theme, 1)} All templates")
                self.console.print(f"  {format_menu_number(self.theme, 2)} Recon (nmap, service detection)")
                self.console.print(f"  {format_menu_number(self.theme, 3)} Web (gobuster, nikto, whatweb)")
                self.console.print(f"  {format_menu_number(self.theme, 4)} Enumeration (SMB, LDAP, etc.)")
                self.console.print(f"  {format_menu_number(self.theme, 5)} Exploitation (shells, exploits)")
                self.console.print()

                cat_choice = input("Choice [1-5]: ").strip()
                category_map = {
                    '1': 'all',
                    '2': 'recon',
                    '3': 'web',
                    '4': 'enumeration',
                    '5': 'exploitation'
                }

                if cat_choice in category_map:
                    category = category_map[cat_choice]
                    page = 1  # Reset to first page when changing category
                    self.debug_logger.info(f"Category changed to: {category}")
                else:
                    self.console.print(self.theme.danger("Invalid choice"))

                self.console.print(self.theme.muted("Press Enter to continue..."))
                input()
                live.start()
                continue

            elif user_input.lower() == 's':
                self.debug_logger.info("Search requested (placeholder)")
                live.stop()
                self.console.print(f"\n{self.theme.warning('Search not yet implemented')}")
                self.console.print(self.theme.muted("Press Enter to continue..."))
                input()
                live.start()
                continue

            elif user_input.lower() == 'n':
                self.debug_logger.info("Next page requested")
                # Find next page choice
                next_choice = next((c for c in choices if c.get('action') == 'next_page'), None)
                if next_choice:
                    page = next_choice['page']
                    self.debug_logger.debug(f"Moving to page {page}")
                else:
                    self.debug_logger.debug("No next page available")
                continue

            elif user_input.lower() == 'p':
                self.debug_logger.info("Previous page requested")
                # Find prev page choice
                prev_choice = next((c for c in choices if c.get('action') == 'prev_page'), None)
                if prev_choice:
                    page = prev_choice['page']
                    self.debug_logger.debug(f"Moving to page {page}")
                else:
                    self.debug_logger.debug("No previous page available")
                continue

            # Try to parse as template selection number
            try:
                choice_num = int(user_input)
                self.debug_logger.debug(f"Parsed as choice number: {choice_num}")

                if 1 <= choice_num <= len(choices):
                    choice = choices[choice_num - 1]
                    choice_action = choice.get('action')
                    self.debug_logger.info(f"Template browser choice selected: {choice_action}")

                    # Handle select template action
                    if choice_action == 'select':
                        template = choice.get('template')
                        if template:
                            self.debug_logger.info(f"Navigating to template detail for: {template.name}")
                            self.debug_logger.log_state_transition("TEMPLATE_BROWSER", "TEMPLATE_DETAIL", f"selected: {template.name}")

                            # Navigate to template detail
                            self._template_detail_loop(live, layout, template)

                            self.debug_logger.log_state_transition("TEMPLATE_DETAIL", "TEMPLATE_BROWSER", "returned from detail")
                            self.debug_logger.info("Returned from template detail to browser")
                            # Stay in browser loop, don't exit
                        else:
                            self.debug_logger.warning("select choice has no template object")

                    else:
                        self.debug_logger.warning(f"Unhandled action: {choice_action}")

                else:
                    self.debug_logger.warning(f"Choice {choice_num} out of range (1-{len(choices)})")

                    live.stop()
                    self.console.print(self.theme.danger(f"Invalid choice: {choice_num}"))
                    self.console.print(self.theme.muted(f"Please choose 1-{len(choices)} or 'b' for back. Press Enter..."))
                    input()
                    live.start()

            except ValueError as e:
                self.debug_logger.warning(f"Failed to parse template browser input: {e}")

                live.stop()
                self.console.print(self.theme.danger(f"Invalid input: {user_input}"))
                self.console.print(self.theme.muted("Please enter a number or shortcut. Press Enter..."))
                input()
                live.start()

        self.debug_logger.section("TEMPLATE BROWSER LOOP END")
        self.debug_logger.info("Returning to dashboard")

    def _template_detail_loop(self, live: Live, layout: Layout, template):
        """
        Template detail loop - fill variables and execute template

        Args:
            live: Rich Live context
            layout: Layout object
            template: CommandTemplate instance
        """
        self.debug_logger.section("TEMPLATE DETAIL LOOP START")
        self.debug_logger.info(f"Template: {template.name}")

        # Initialize state
        filled_values = None  # Will be filled when user completes form
        execution_result = None  # Will be set after execution

        running = True
        iteration = 0

        while running:
            iteration += 1
            self.debug_logger.debug(f"Template detail loop iteration {iteration}")

            # Render template detail panel
            self.debug_logger.debug(f"Rendering TemplateDetailPanel (filled={filled_values is not None}, executed={execution_result is not None})")
            panel, choices = TemplateDetailPanel.render(
                template=template,
                filled_values=filled_values,
                execution_result=execution_result,
                theme=self.theme
            )
            self.debug_logger.debug(f"TemplateDetailPanel returned {len(choices)} choices")

            # Update layout
            layout['header'].update(self._render_header())
            layout['menu'].update(panel)
            layout['footer'].update(self._render_footer())

            # Refresh display
            self.debug_logger.log_live_action("REFRESH", "template detail display")
            live.refresh()

            # Stop live to get input
            self.debug_logger.log_live_action("STOP", "before template detail input")
            live.stop()

            # Get user input (vim-style hotkeys)
            self.console.print(f"\n{self.theme.muted('Press key (see menu for options):')} ", end="")
            try:
                self.debug_logger.debug("Waiting for template detail hotkey input...")

                # Read single key
                key = self.hotkey_handler.read_key()

                if key is None:
                    # EOF or timeout
                    self.debug_logger.warning("EOF or timeout during template detail input")
                    live.start()
                    running = False
                    continue

                # Filter out ENTER/newline (treat as no input)
                if key in ['\r', '\n']:
                    self.debug_logger.debug(f"ENTER key detected (ord={ord(key)}), ignoring")
                    user_input = ''
                # Handle : command mode
                elif key == ':':
                    self.debug_logger.debug("Command mode activated in template detail")
                    user_input = self.hotkey_handler.read_command(":")
                else:
                    # Single-key shortcut
                    user_input = key

                self.debug_logger.log_user_input(user_input, context="template_detail_hotkey")

            except (EOFError, KeyboardInterrupt):
                self.debug_logger.warning("EOF or interrupt during template detail input")
                live.start()
                running = False
                continue

            # Resume live
            self.debug_logger.log_live_action("START", "after template detail input")
            live.start()

            # Process input
            if not user_input:
                self.debug_logger.debug("Empty input, continuing loop")
                continue

            self.debug_logger.debug(f"Processing template detail input: '{user_input}'")

            # Handle shortcuts
            if user_input.lower() == 'b':
                self.debug_logger.info("Back to template browser requested")
                self.debug_logger.log_state_transition("TEMPLATE_DETAIL", "TEMPLATE_BROWSER", "back button pressed")
                running = False
                continue

            elif user_input.lower() == 'f':
                self.debug_logger.info("Fill variables requested")
                live.stop()

                # Collect variable values
                filled_values = {}
                self.console.print(f"\n{self.theme.emphasis('Fill Template Variables:')}\n")

                for var in template.variables:
                    var_name = var['name']
                    var_desc = var.get('description', '')
                    var_example = var.get('example', '')
                    var_required = var.get('required', True)

                    # Build prompt
                    prompt = f"  {self.theme.primary(var_name)}"
                    if var_desc:
                        prompt += f" ({var_desc})"
                    if var_example:
                        prompt += f" {self.theme.muted(f'e.g., {var_example}')}"
                    if not var_required:
                        prompt += f" {self.theme.muted('(optional)')}"
                    prompt += ": "

                    self.console.print(prompt, end="")
                    value = input().strip()

                    # Validate required fields
                    if not value and var_required:
                        self.console.print(self.theme.danger(f"✗ {var_name} is required"))
                        self.console.print(self.theme.muted("Press Enter to try again..."))
                        input()
                        filled_values = None
                        break

                    if value:
                        filled_values[var_name] = value

                if filled_values:
                    self.console.print(f"\n{self.theme.success('✓ Variables filled successfully')}")
                    self.console.print(self.theme.muted("Press Enter to continue..."))
                    input()

                live.start()
                continue

            elif user_input.lower() == 'e':
                self.debug_logger.info("Execute requested")

                if not filled_values:
                    live.stop()
                    self.console.print(f"\n{self.theme.danger('Cannot execute: variables not filled')}")
                    self.console.print(self.theme.muted("Press 'f' to fill variables first. Press Enter..."))
                    input()
                    live.start()
                    continue

                # Execute command
                final_command = template.fill(filled_values)
                self.debug_logger.info(f"Executing template command: {final_command}")

                live.stop()
                self.console.print(f"\n{self.theme.emphasis('Executing:')} {self.theme.success(final_command)}\n")

                import time
                start_time = time.time()

                try:
                    result = subprocess.run(final_command, shell=True, capture_output=True, text=True)
                    elapsed = time.time() - start_time

                    execution_result = {
                        'exit_code': result.returncode,
                        'elapsed': elapsed,
                        'output_lines': (result.stdout + result.stderr).split('\n') if result.stdout or result.stderr else []
                    }

                    if result.returncode == 0:
                        self.console.print(f"\n{self.theme.success(f'✓ Command executed successfully ({elapsed:.2f}s)')}")
                    else:
                        self.console.print(f"\n{self.theme.warning(f'Command completed with exit code {result.returncode} ({elapsed:.2f}s)')}")

                    # Log to profile
                    self.profile.add_note(
                        note=f"Template: {template.name}\nCommand: {final_command}\nExit code: {result.returncode}",
                        source="scan templates"
                    )
                    self.profile.save()

                except Exception as e:
                    self.console.print(f"\n{self.theme.danger(f'✗ Execution failed: {e}')}")
                    execution_result = {
                        'exit_code': 1,
                        'elapsed': time.time() - start_time,
                        'output_lines': [f"Error: {str(e)}"]
                    }

                self.console.print(self.theme.muted("Press Enter to continue..."))
                input()
                live.start()
                continue

            elif user_input.lower() == 'c':
                self.debug_logger.info("Copy to clipboard requested (placeholder)")
                live.stop()
                self.console.print(f"\n{self.theme.warning('Copy to clipboard not yet implemented')}")
                self.console.print(self.theme.muted("Press Enter to continue..."))
                input()
                live.start()
                continue

            elif user_input.lower() == 'r':
                self.debug_logger.info("Reset requested")
                filled_values = None
                execution_result = None
                self.debug_logger.debug("State reset")
                continue

            elif user_input.lower() == 'v':
                self.debug_logger.info("View full output requested (placeholder)")
                live.stop()
                self.console.print(f"\n{self.theme.warning('Full output viewer not yet implemented')}")
                self.console.print(self.theme.muted("Use 'o' shortcut from dashboard to view execution history. Press Enter..."))
                input()
                live.start()
                continue

            elif user_input.lower() == 's':
                self.debug_logger.info("Save output requested (placeholder)")
                live.stop()
                self.console.print(f"\n{self.theme.warning('Save output not yet implemented')}")
                self.console.print(self.theme.muted("Press Enter to continue..."))
                input()
                live.start()
                continue

            else:
                self.debug_logger.warning(f"Unknown template detail input: {user_input}")
                live.stop()
                self.console.print(self.theme.danger(f"Invalid input: {user_input}"))
                self.console.print(self.theme.muted("Press Enter to continue..."))
                input()
                live.start()

        self.debug_logger.section("TEMPLATE DETAIL LOOP END")
        self.debug_logger.info("Returning to template browser")

    def _execute_task_streaming(
        self,
        live: Live,
        layout: Layout,
        task
    ) -> Tuple[List[str], float, int, List[Dict]]:
        """
        Execute task with real-time streaming output

        Args:
            live: Rich Live context (for display updates)
            layout: Layout object (for workspace updates)
            task: TaskNode instance

        Returns:
            Tuple of (output_lines, elapsed, exit_code, findings)
        """
        # Strategic chokepoint: Streaming execution start
        self.debug_logger.log("Streaming execution started", category=LogCategory.EXECUTION_START, level=LogLevel.NORMAL,
                             task_id=task.id, task_name=task.name)

        # 1. Extract and validate command
        command = task.metadata.get('command')
        if not command:
            self.debug_logger.log("Task execution failed: no command", category=LogCategory.EXECUTION_ERROR, level=LogLevel.MINIMAL, task_id=task.id)
            return (["Error: No command defined"], 0.0, 1, [])

        # Replace {TARGET} placeholder
        original_command = command
        command = command.replace('{TARGET}', self.profile.target)

        # 2. Start timer and update task status
        task.start_timer()
        task.status = 'in-progress'
        self.debug_logger.log("Command prepared for execution", category=LogCategory.EXECUTION_START, level=LogLevel.VERBOSE,
                             task_id=task.id, command_length=len(command))

        # 3. Initialize state
        output_lines = []
        start_time = time.time()
        line_count = 0
        last_refresh = 0.0  # Throttle refreshes to reduce jitter

        try:
            # 4. Create subprocess with streaming
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Combine stderr with stdout
                text=True,
                bufsize=1  # Line buffered
            )

            self.debug_logger.log("Subprocess started", category=LogCategory.EXECUTION_START, level=LogLevel.VERBOSE, pid=process.pid)

            # 5. Stream output line-by-line
            for line in process.stdout:
                line_count += 1
                output_lines.append(line.rstrip())
                elapsed = time.time() - start_time

                # Log every 100 lines (avoid spam, but track progress)
                if line_count % 100 == 0:
                    self.debug_logger.log(f"Output streaming", category=LogCategory.EXECUTION_OUTPUT, level=LogLevel.TRACE,
                                         lines_received=line_count, elapsed=f"{elapsed:.1f}s")

                # Throttle display updates to reduce jitter (max 10 refreshes/sec)
                if elapsed - last_refresh >= 0.1:  # 100ms minimum between refreshes
                    # Update workspace display (streaming state)
                    workspace_layout, choices = TaskWorkspacePanel.render(
                        task=task,
                        output_state='streaming',
                        output_lines=output_lines,
                        elapsed=elapsed,
                        exit_code=None,
                        findings=[],
                        target=self.profile.target,
                        theme=self.theme
                    )

                    layout['header'].update(self._render_header())
                    layout['menu'].update(workspace_layout)
                    layout['footer'].update(self._render_footer())
                    live.refresh()
                    last_refresh = elapsed

            # 6. Wait for process completion
            process.wait()
            exit_code = process.returncode
            elapsed = time.time() - start_time

            # Strategic chokepoint: Execution completion
            self.debug_logger.log("Subprocess completed", category=LogCategory.EXECUTION_END, level=LogLevel.NORMAL,
                                 exit_code=exit_code, lines_captured=line_count, elapsed=f"{elapsed:.2f}s")

            # Final refresh with complete state (ensures all output shown)
            workspace_layout, choices = TaskWorkspacePanel.render(
                task=task,
                output_state='streaming',  # Still streaming state (findings not analyzed yet)
                output_lines=output_lines,
                elapsed=elapsed,
                exit_code=None,
                findings=[],
                target=self.profile.target,
                theme=self.theme
            )
            layout['header'].update(self._render_header())
            layout['menu'].update(workspace_layout)
            layout['footer'].update(self._render_footer())
            live.refresh()
            self.debug_logger.debug("Final refresh completed")

        except Exception as e:
            self.debug_logger.exception(f"Exception during streaming execution: {e}")
            elapsed = time.time() - start_time
            exit_code = 1
            output_lines.append(f"Error: {str(e)}")

        # 7. Stop timer and update task status
        task.stop_timer()
        task.status = 'completed' if exit_code == 0 else 'failed'
        self.debug_logger.info(f"Task status set to '{task.status}'")

        # 8. Analyze output for findings
        # Show progress indicator during post-processing
        layout['footer'].update(Panel("🔍 Analyzing findings...", style="cyan", box=box.ROUNDED))
        live.refresh()
        self.debug_logger.debug("Analyzing output for findings")

        try:
            pattern_matcher = OutputPatternMatcher()
            findings_dict = pattern_matcher.analyze(output_lines, task)

            # Convert findings dict to list format for display
            findings = []
            for finding_type, items in findings_dict.items():
                if finding_type != 'success' and items:
                    if isinstance(items, list):
                        for item in items:
                            findings.append({
                                'type': finding_type,
                                'data': item
                            })
                            # Save finding to profile
                            try:
                                self.profile.add_finding(
                                    finding_type=finding_type,
                                    description=str(item),
                                    source=f"{command} (Task: {task.id})"
                                )
                            except Exception as e:
                                self.debug_logger.warning(f"Failed to save finding: {e}")

            self.debug_logger.info(f"Findings detected and saved: {len(findings)}")
        except Exception as e:
            self.debug_logger.exception(f"Exception during finding analysis: {e}")
            findings = []

        # Restore normal footer after analysis
        layout['footer'].update(self._render_footer())
        live.refresh()

        # 9. Save execution to task history for output overlay
        self.debug_logger.debug("Saving execution to task history")
        try:
            task.add_execution(
                command=command,
                output_lines=output_lines,
                exit_code=exit_code,
                duration=elapsed
            )
            self.debug_logger.info(f"Execution saved to history (context: {task.get_latest_execution().get('context_label')})")
        except Exception as e:
            self.debug_logger.warning(f"Failed to save execution history: {e}")

        self.debug_logger.section("STREAMING EXECUTION END")

        # 10. Emit task completion event for plugins
        self.debug_logger.debug("Emitting task_completed event")
        try:
            EventBus.emit('task_completed', {
                'task': task,
                'task_id': task.id,
                'output': output_lines,
                'findings': findings_dict,
                'target': self.profile.target,
                'command': command,
                'exit_code': exit_code
            })
            self.debug_logger.info("task_completed event emitted")
        except Exception as e:
            self.debug_logger.warning(f"Failed to emit task_completed event: {e}")

        # 11. Return results
        return (output_lines, elapsed, exit_code, findings)

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
        from rich.text import Text
        from rich.align import Align

        # CRACK = Comprehensive Recon & Attack Creation Kit
        # TRACK = Targeted Reconnaissance And Command Konsole
        # TUI = Tactical User Interface
        line1 = f"{self.theme.muted('C.R.A.C.K.')} {self.theme.emphasis('Comprehensive Recon & Attack Creation Kit')} | {self.theme.muted('T.R.A.C.K.')} {self.theme.emphasis('Targeted Reconnaissance And Command Konsole')} | {self.theme.muted('T.U.I.')} {self.theme.emphasis('Tactical User Interface')}"
        target_line = f"{self.theme.primary('Target:')} {self.theme.emphasis(self.profile.target)}"

        # Create text objects for centering
        from rich.console import RenderableType
        content = f"{line1}\n{target_line}"

        return Panel(
            Align.center(content),
            border_style=self.theme.panel_border(),
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
            panel, choices = DashboardPanel.render_empty_state(self.profile, theme=self.theme)
        else:
            # Normal dashboard with recommendations
            panel, choices = DashboardPanel.render(self.profile, self._current_recommendations, theme=self.theme)

        # Store choices for input processing
        self._current_choices = choices

        return panel

    def _render_footer(self, valid_shortcuts: Optional[Dict[str, str]] = None) -> Panel:
        """
        Render footer with context-aware shortcuts

        Args:
            valid_shortcuts: Dict of {key: description} for current context.
                           If None, shows ALL shortcuts (dashboard default)

        Displays:
        - Only shortcuts valid in current context
        - 6 commands per row for better density
        - Priority-ordered for common workflows
        """
        from rich.table import Table

        # Default to all shortcuts if not specified (dashboard mode)
        if valid_shortcuts is None:
            valid_shortcuts = self._get_dashboard_shortcuts()

        # Create table for multi-row layout (6 columns)
        table = Table.grid(padding=(0, 1), expand=True)
        for _ in range(6):
            table.add_column(style="cyan", ratio=1)

        # Format shortcuts
        all_shortcuts = []
        for key, description in valid_shortcuts.items():
            if len(key) == 1:
                formatted = f"{format_hotkey(self.theme, key)}:{description}"
            elif key.startswith(':'):
                # Already prefixed with :
                formatted = f"{format_hotkey(self.theme, key)}:{description}"
            elif '-' in key:
                # Range like "1-4"
                formatted = f"{self.theme.muted(key)}:{description}"
            else:
                # Multi-char shortcut needs : prefix
                formatted = f"{format_hotkey(self.theme, f':{key}')}:{description}"
            all_shortcuts.append(formatted)

        # Split into rows of 6 columns
        rows = []
        for i in range(0, len(all_shortcuts), 6):
            chunk = all_shortcuts[i:i+6]
            # Pad with empty strings if needed
            while len(chunk) < 6:
                chunk.append("")
            rows.append(chunk)

        # Add all rows to table
        for row in rows:
            table.add_row(*row)

        return Panel(
            table,
            title=self.theme.emphasis("All Commands (h:Help for details)"),
            border_style=self.theme.panel_border(),
            box=box.HEAVY
        )

    def _get_dashboard_shortcuts(self) -> Dict[str, str]:
        """
        Get all available shortcuts for dashboard view

        Returns:
            Dictionary of {key: description} for all dashboard shortcuts
        """
        shortcuts = {}

        # Priority shortcuts (shown first)
        priority_order = [
            'n', 'h', 's', 't', 'x', 'alt', 'ch', 'qn', 'pd', 'q', 'b',
            'l', 'f', 'o', 'i', 'd', '-'
        ]

        # Add priority shortcuts from ShortcutHandler
        for key in priority_order:
            if key in self.shortcut_handler.shortcuts:
                description, _ = self.shortcut_handler.shortcuts[key]
                shortcuts[key] = description

        # Add TUI-specific shortcuts (not in ShortcutHandler)
        tui_shortcuts = {
            'l': 'Browse all tasks',
            'f': 'Browse findings',
            'o': 'Output overlay',
            'i': 'Import scan results',
            'd': 'Document finding',
            '-': 'Config panel',
        }

        for key, desc in tui_shortcuts.items():
            if key not in shortcuts:
                shortcuts[key] = desc

        # Add remaining shortcuts alphabetically
        for key, (description, _) in sorted(self.shortcut_handler.shortcuts.items()):
            if key not in shortcuts:
                shortcuts[key] = description

        # Add special commands
        shortcuts[':!cmd'] = 'Console injection'
        shortcuts[':theme'] = 'Switch theme'
        shortcuts[':themes'] = 'List themes'
        shortcuts['1-9'] = 'Menu select'

        return shortcuts

    def _process_input(self, user_input: str) -> Optional[str]:
        """Process user input - supports numbers, letter hotkeys, and : commands"""
        self.debug_logger.debug(f"_process_input called with: '{user_input}'")

        # Theme commands (:theme and :themes)
        if user_input == 'themes':
            self.debug_logger.info("List themes command")
            self._list_themes()
            return None

        if user_input.startswith('theme'):
            # Parse :theme <name> command
            parts = user_input.split(maxsplit=1)
            if len(parts) == 2:
                theme_name = parts[1].strip()
                self.debug_logger.info(f"Switch theme command: {theme_name}")
                self._switch_theme(theme_name)
            else:
                # No theme name - show current theme
                self.debug_logger.info("Show current theme")
                self._show_current_theme()
            return None

        # Console injection (:! command)
        if user_input.startswith('!'):
            command = user_input[1:].strip()  # Strip the '!' prefix
            self.debug_logger.info(f"Console injection requested: {command}")
            self._execute_console_injection(command)
            return None

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

        # Progress dashboard shortcut
        if user_input.lower() == 'p':
            self.debug_logger.info("Progress dashboard requested")
            self.handle_progress_dashboard()
            return None

        # Output overlay shortcut
        if user_input.lower() == 'o':
            self.debug_logger.info("Output overlay requested")
            self._show_output()
            return None

        # Config panel shortcut
        if user_input == '-':
            self.debug_logger.info("Config panel requested")
            self.debug_logger.log_state_transition("DASHBOARD", "CONFIG_PANEL", "- shortcut pressed")

            # Re-open config panel (allows editing settings mid-session)
            if hasattr(self, '_live') and hasattr(self, '_layout'):
                self._config_panel_loop(self._live, self._layout)

            self.debug_logger.log_state_transition("CONFIG_PANEL", "DASHBOARD", "returned from config panel")
            return None

        # Template browser shortcut
        if user_input.lower() == 'x':
            self.debug_logger.info("Template browser requested")
            self.debug_logger.log_state_transition("DASHBOARD", "TEMPLATE_BROWSER", "x shortcut pressed")

            # Navigate to template browser
            self._template_browser_loop(self._live, self._layout)

            self.debug_logger.log_state_transition("TEMPLATE_BROWSER", "DASHBOARD", "returned from template browser")
            return None

        # Letter hotkeys for Dashboard actions
        # Map letters to choice IDs for faster navigation
        hotkey_map = {
            'n': 'next',              # Execute next task
            'l': 'browse-tasks',      # Browse all tasks (l for "list")
            'f': 'browse-findings',   # Browse findings
            'w': 'quick-wins',        # Quick wins
            'i': 'import',            # Import scan results
            'd': 'finding',           # Document finding
        }

        # Check if input is a letter hotkey
        if user_input.lower() in hotkey_map:
            choice_id = hotkey_map[user_input.lower()]
            self.debug_logger.info(f"Letter hotkey '{user_input}' mapped to choice ID: {choice_id}")

            # Find the matching choice by ID
            for idx, choice in enumerate(self._current_choices):
                if choice.get('id') == choice_id:
                    self.debug_logger.info(f"Executing choice via hotkey: {choice.get('label')}")
                    self._execute_choice(idx)
                    return None

            # Hotkey mapped but choice not available
            self.debug_logger.warning(f"Hotkey '{user_input}' maps to '{choice_id}' but choice not available")

            # Stop Live to show error clearly
            if hasattr(self, '_live'):
                self._live.stop()

            self.console.print(f"\n{self.theme.warning('Action not available in current context')}")
            self.console.print(self.theme.muted("Press Enter to continue..."))
            input()

            # Restart Live
            if hasattr(self, '_live'):
                self._live.start()

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

                # Stop Live to show error clearly
                if hasattr(self, '_live'):
                    self._live.stop()

                self.console.print(self.theme.danger(f"Invalid choice: {choice_num}"))
                self.console.print(self.theme.muted(f"Please choose 1-{len(self._current_choices)} or press a valid shortcut. Press Enter..."))
                input()

                # Restart Live
                if hasattr(self, '_live'):
                    self._live.start()
        except (ValueError, AttributeError):
            # Not a number - try delegating to ShortcutHandler
            # This handles all the shortcuts not explicitly processed above
            # (r, x, c, ch, pl, tf, qn, tt, qx, fc, qe, ss, tr, be, sa, wr, sg, alt, R, etc.)
            if user_input in self.shortcut_handler.shortcuts:
                self.debug_logger.info(f"Delegating '{user_input}' to ShortcutHandler")

                # Shortcuts from basic mode expect terminal I/O, not Live context
                # Stop Live temporarily to allow input() and print()
                if hasattr(self, '_live'):
                    self._live.stop()

                try:
                    # Execute shortcut via handler
                    continue_session = self.shortcut_handler.handle(user_input)

                    # Some shortcuts return False to signal exit
                    if not continue_session:
                        self.debug_logger.info("Shortcut handler requested exit")
                        if hasattr(self, '_live'):
                            self._live.start()
                        return 'exit'

                except Exception as e:
                    self.debug_logger.warning(f"Shortcut handler error: {e}")
                    self.console.print(self.theme.danger(f"Error executing '{user_input}': {e}"))

                finally:
                    # Always restart Live context
                    if hasattr(self, '_live'):
                        self._live.start()
            else:
                # Not a shortcut either - unknown input
                self.debug_logger.warning(f"Unknown input: {user_input}")

                # Stop Live to show error clearly
                if hasattr(self, '_live'):
                    self._live.stop()

                self.console.print(self.theme.danger(f"Invalid input: {user_input}"))
                self.console.print(self.theme.muted("Press any valid key or Enter to continue..."))
                input()

                # Restart Live
                if hasattr(self, '_live'):
                    self._live.start()

        return None

    def _execute_choice(self, index: int):
        """Execute a menu choice"""
        choice = self._current_choices[index]

        # Strategic chokepoint: Choice execution (major decision point)
        choice_id = choice.get('id')
        self.debug_logger.log("Choice execution", category=LogCategory.UI_INPUT, level=LogLevel.NORMAL,
                             index=index, choice_id=choice_id, label=choice.get('label'))

        # Check if this is workspace navigation (Execute next task)
        if choice_id == 'next':
            task = choice.get('task')
            if task:
                self.debug_logger.log_state_transition("DASHBOARD", "TASK_WORKSPACE", f"execute next: {task.name}")

                # Enter workspace loop with SAME Live and Layout
                self._task_workspace_loop(self._live, self._layout, task)

                self.debug_logger.log_state_transition("TASK_WORKSPACE", "DASHBOARD", "returned from workspace")
                return
            else:
                self.debug_logger.log("Invalid choice: no task object", category=LogCategory.UI_INPUT, level=LogLevel.MINIMAL, choice_id=choice_id)

        # Check if this is task list navigation (Browse all tasks)
        elif choice.get('id') == 'browse-tasks':
            self.debug_logger.info("Navigating to task list browser")
            self.debug_logger.log_state_transition("DASHBOARD", "TASK_LIST", "browse tasks selected")

            # Enter task list loop with SAME Live and Layout
            self._task_list_loop(self._live, self._layout)

            self.debug_logger.log_state_transition("TASK_LIST", "DASHBOARD", "returned from task list")
            self.debug_logger.info("Returned from task list browser")
            return

        # Check if this is findings navigation (Browse findings)
        elif choice.get('id') == 'browse-findings':
            self.debug_logger.info("Navigating to findings browser")
            self.debug_logger.log_state_transition("DASHBOARD", "FINDINGS", "browse findings selected")

            # Enter findings loop with SAME Live and Layout
            self._findings_loop(self._live, self._layout)

            self.debug_logger.log_state_transition("FINDINGS", "DASHBOARD", "returned from findings")
            self.debug_logger.info("Returned from findings browser")
            return

        # Use ExecutionOverlay to handle task execution outside Live context
        # This prevents the freeze issue where Live display conflicts with terminal I/O
        self.debug_logger.info("Delegating to ExecutionOverlay")
        ExecutionOverlay.execute_choice(self._live, self, choice, theme=self.theme)

        self.debug_logger.info("Returned from ExecutionOverlay")

    def _show_help(self):
        """Show help overlay with dynamic shortcuts"""
        # Stop Live context to allow overlay display
        if hasattr(self, '_live'):
            self._live.stop()

        try:
            help_panel = HelpOverlay.render(shortcut_handler=self.shortcut_handler, theme=self.theme)
            self.console.print(help_panel)
            self.console.print(f"\n{self.theme.muted('Press any key to dismiss (or \"h\" to toggle off)...')} ", end="")
            dismiss_key = self.hotkey_handler.read_key()  # Single keypress (consistent with TUI)
            self.debug_logger.log("Help overlay dismissed", category=LogCategory.UI_PANEL, level=LogLevel.NORMAL,
                                 dismiss_key=dismiss_key)
        finally:
            # Resume Live context
            if hasattr(self, '_live'):
                self._live.start()

        # Toggle behavior: pressing 'h' again just closes (no re-execution)
        if dismiss_key and dismiss_key.lower() == 'h':
            self.debug_logger.log("Toggle dismiss: same key pressed, overlay closed",
                                 category=LogCategory.UI_INPUT, level=LogLevel.VERBOSE, key=dismiss_key)
            return  # Just close, don't re-execute

        # Smart dismiss: if dismiss key is a valid command, execute it
        if dismiss_key and dismiss_key not in ['\r', '\n', ' ']:
            self.debug_logger.log("Smart dismiss: processing dismiss key as command",
                                 category=LogCategory.UI_INPUT, level=LogLevel.VERBOSE, key=dismiss_key)
            self._process_input(dismiss_key)

    def _show_status(self):
        """Show status overlay"""
        # Stop Live context to allow overlay display
        if hasattr(self, '_live'):
            self._live.stop()

        try:
            status_panel = StatusOverlay.render(self.profile, theme=self.theme)
            self.console.print(status_panel)
            self.console.print(f"\n{self.theme.muted('Press any key to dismiss (or \"s\" to toggle off)...')} ", end="")
            dismiss_key = self.hotkey_handler.read_key()  # Single keypress (consistent with TUI)
            self.debug_logger.log("Status overlay dismissed", category=LogCategory.UI_PANEL, level=LogLevel.NORMAL,
                                 dismiss_key=dismiss_key)
        finally:
            # Resume Live context
            if hasattr(self, '_live'):
                self._live.start()

        # Toggle behavior: pressing 's' again just closes (no re-execution)
        if dismiss_key and dismiss_key.lower() == 's':
            self.debug_logger.log("Toggle dismiss: same key pressed, overlay closed",
                                 category=LogCategory.UI_INPUT, level=LogLevel.VERBOSE, key=dismiss_key)
            return  # Just close, don't re-execute

        # Smart dismiss: if dismiss key is a valid command, execute it
        if dismiss_key and dismiss_key not in ['\r', '\n', ' ']:
            self.debug_logger.log("Smart dismiss: processing dismiss key as command",
                                 category=LogCategory.UI_INPUT, level=LogLevel.VERBOSE, key=dismiss_key)
            self._process_input(dismiss_key)

    def _show_tree(self):
        """Show task tree overlay"""
        # Stop Live context to allow overlay display
        if hasattr(self, '_live'):
            self._live.stop()

        try:
            tree_panel = TreeOverlay.render(self.profile, theme=self.theme)
            self.console.print(tree_panel)
            self.console.print(f"\n{self.theme.muted('Press any key to dismiss (or \"t\" to toggle off)...')} ", end="")
            dismiss_key = self.hotkey_handler.read_key()  # Single keypress (consistent with TUI)
            self.debug_logger.log("Tree overlay dismissed", category=LogCategory.UI_PANEL, level=LogLevel.NORMAL,
                                 dismiss_key=dismiss_key)
        finally:
            # Resume Live context
            if hasattr(self, '_live'):
                self._live.start()

        # Toggle behavior: pressing 't' again just closes (no re-execution)
        if dismiss_key and dismiss_key.lower() == 't':
            self.debug_logger.log("Toggle dismiss: same key pressed, overlay closed",
                                 category=LogCategory.UI_INPUT, level=LogLevel.VERBOSE, key=dismiss_key)
            return  # Just close, don't re-execute

        # Smart dismiss: if dismiss key is a valid command, execute it
        if dismiss_key and dismiss_key not in ['\r', '\n', ' ']:
            self.debug_logger.log("Smart dismiss: processing dismiss key as command",
                                 category=LogCategory.UI_INPUT, level=LogLevel.VERBOSE, key=dismiss_key)
            self._process_input(dismiss_key)

    def _show_output(self):
        """Show output overlay with interactive navigation"""
        from .overlays.output_overlay import OutputOverlay

        # Stop Live context to allow full-screen overlay
        if hasattr(self, '_live'):
            self._live.stop()

        try:
            # Run interactive output viewer
            OutputOverlay.render_and_navigate(
                console=self.console,
                profile=self.profile,
                theme=self.theme
            )
        finally:
            # Resume Live context
            if hasattr(self, '_live'):
                self._live.start()

    def _list_themes(self):
        """List all available themes with current theme highlighted"""
        from .themes.presets import BUILT_IN_THEMES

        self.debug_logger.log("List themes command invoked", category=LogCategory.UI_COMMAND, level=LogLevel.NORMAL)

        # Stop Live context
        if hasattr(self, '_live'):
            self._live.stop()

        try:
            current_theme = self.theme.get_theme_name()

            self.debug_logger.log("Displaying theme list", category=LogCategory.UI_RENDER, level=LogLevel.VERBOSE,
                                 current_theme=current_theme, theme_count=len(BUILT_IN_THEMES))

            self.console.print(f"\n{self.theme.emphasis('Available Themes:')}\n")

            for theme_id, theme_data in BUILT_IN_THEMES.items():
                name = theme_data['name']
                desc = theme_data.get('description', 'No description')

                if theme_id == current_theme:
                    # Highlight current theme
                    self.console.print(f"  {self.theme.success('✓')} {self.theme.primary(theme_id)} - {self.theme.emphasis(name)}")
                    self.console.print(f"    {self.theme.muted(desc)} {self.theme.success('[ACTIVE]')}")
                else:
                    self.console.print(f"    {self.theme.muted(theme_id)} - {name}")
                    self.console.print(f"    {self.theme.muted(desc)}")

            self.console.print(f"\n{self.theme.muted('Use')} {self.theme.primary(':theme <name>')} {self.theme.muted('to switch')}")
            self.console.print(f"{self.theme.muted('Press any key to dismiss...')} ", end="")
            self.hotkey_handler.read_key()  # Single keypress

        finally:
            # Resume Live context
            if hasattr(self, '_live'):
                self._live.start()

    def _switch_theme(self, theme_name: str):
        """Switch to a different theme"""
        self.debug_logger.log("Switch theme command invoked", category=LogCategory.UI_COMMAND, level=LogLevel.NORMAL,
                             theme_name=theme_name)

        # Stop Live context
        if hasattr(self, '_live'):
            self._live.stop()

        try:
            if self.theme.set_theme(theme_name):
                self.debug_logger.log("✓ Theme switch successful (via command)", category=LogCategory.THEME_SWITCH,
                                     level=LogLevel.NORMAL, theme_name=theme_name)
                self.console.print(f"\n{self.theme.success('✓ Theme switched to:')} {self.theme.emphasis(theme_name)}")
                self.console.print(self.theme.muted("Changes take effect immediately"))
            else:
                self.debug_logger.log("✗ Theme switch failed: invalid theme (via command)", category=LogCategory.THEME_SWITCH,
                                     level=LogLevel.NORMAL, theme_name=theme_name)
                self.console.print(f"\n{self.theme.danger('✗ Invalid theme:')} {theme_name}")
                self.console.print(f"{self.theme.muted('Use')} {self.theme.primary(':themes')} {self.theme.muted('to see available themes')}")

            self.console.print(f"\n{self.theme.muted('Press any key to continue...')} ", end="")
            self.hotkey_handler.read_key()  # Single keypress

        finally:
            # Resume Live context
            if hasattr(self, '_live'):
                self._live.start()

    def _show_current_theme(self):
        """Show current theme name"""
        self.debug_logger.log("Show current theme command invoked", category=LogCategory.UI_COMMAND, level=LogLevel.NORMAL)

        # Stop Live context
        if hasattr(self, '_live'):
            self._live.stop()

        try:
            current_theme = self.theme.get_theme_name()

            self.debug_logger.log("Displaying current theme", category=LogCategory.UI_RENDER, level=LogLevel.VERBOSE,
                                 theme_name=current_theme)

            self.console.print(f"\n{self.theme.muted('Current theme:')} {self.theme.emphasis(current_theme)}")
            self.console.print(f"{self.theme.muted('Use')} {self.theme.primary(':themes')} {self.theme.muted('to see all available themes')}")
            self.console.print(f"{self.theme.muted('Press any key to continue...')} ", end="")
            self.hotkey_handler.read_key()  # Single keypress

        finally:
            # Resume Live context
            if hasattr(self, '_live'):
                self._live.start()

    def _execute_console_injection(self, command: str):
        """Execute console injection command"""
        from .overlays.console_injection import ConsoleInjection

        # Stop Live context to allow full terminal access
        if hasattr(self, '_live'):
            self._live.stop()

        try:
            # Execute command with optional save to history
            ConsoleInjection.execute(
                console=self.console,
                command=command,
                profile=self.profile,
                theme=self.theme
            )

            # Save profile (in case user saved to history)
            self.profile.save()

        finally:
            # Resume Live context
            if hasattr(self, '_live'):
                self._live.start()

    def handle_progress_dashboard(self):
        """
        Display progress dashboard overlay showing task completion metrics

        Shows:
        - Overall progress (completed/total tasks)
        - ASCII progress bar visualization
        - Tasks grouped by service (HTTP, SMB, SSH, etc.)
        - Quick wins (low-effort, high-value tasks)
        - High-priority tasks
        - Next recommended task

        Strategic logging:
        - Entry: Dashboard display start
        - Data: Task counts and metrics
        """
        # Strategic chokepoint: Progress dashboard entry
        self.debug_logger.log("Progress dashboard requested",
                             category=LogCategory.UI_PANEL,
                             level=LogLevel.NORMAL)

        # Stop Live context to allow overlay display
        if hasattr(self, '_live'):
            self._live.stop()

        dismiss_key = None  # Initialize for smart dismiss logic
        try:
            # Calculate progress metrics
            all_tasks = self.profile.task_tree.get_all_tasks()
            total = len(all_tasks)
            completed = len([t for t in all_tasks if t.status == 'completed'])
            in_progress = len([t for t in all_tasks if t.status == 'in-progress'])
            pending = len([t for t in all_tasks if t.status == 'pending'])

            # Log metrics
            self.debug_logger.log("Progress metrics calculated",
                                 category=LogCategory.UI_PANEL,
                                 level=LogLevel.VERBOSE,
                                 total=total, completed=completed, pending=pending)

            # Build panel
            table = Table(show_header=False, box=None, padding=(0, 2))
            table.add_column("Label", style="bold cyan", width=20)
            table.add_column("Value")

            # Progress metrics
            percent = int((completed / total * 100)) if total > 0 else 0
            table.add_row("Total Tasks", str(total))
            table.add_row("Completed", f"{completed} ({percent}%)")
            table.add_row("In Progress", str(in_progress))
            table.add_row("Pending", str(pending))

            # ASCII progress bar (40 chars wide)
            bar_width = 40
            filled = int(bar_width * completed / total) if total > 0 else 0
            empty = bar_width - filled
            bar = f"{self.theme.success('█' * filled)}{self.theme.muted('░' * empty)}"
            table.add_row("", bar)

            # Group by service
            service_tasks = {}
            for task in all_tasks:
                # Extract service from task ID or metadata
                service = task.metadata.get('service', 'general')
                if service not in service_tasks:
                    service_tasks[service] = {'total': 0, 'done': 0}
                service_tasks[service]['total'] += 1
                if task.status == 'completed':
                    service_tasks[service]['done'] += 1

            # Service breakdown
            if service_tasks:
                table.add_row("", "")
                table.add_row("[bold]Service Breakdown[/]", "")
                for svc, counts in sorted(service_tasks.items())[:5]:  # Top 5
                    svc_percent = int((counts['done'] / counts['total'] * 100)) if counts['total'] > 0 else 0
                    table.add_row(f"  {svc.upper()}", f"{counts['done']}/{counts['total']} ({svc_percent}%)")

            # Quick wins (pending, QUICK_WIN tag)
            quick_wins = [t for t in all_tasks if t.status == 'pending' and 'QUICK_WIN' in t.metadata.get('tags', [])]
            if quick_wins:
                table.add_row("", "")
                table.add_row("[bold]Quick Wins[/]", f"{len(quick_wins)} available")

            # High priority (pending, OSCP:HIGH tag)
            high_pri = [t for t in all_tasks if t.status == 'pending' and any('OSCP:HIGH' in tag for tag in t.metadata.get('tags', []))]
            if high_pri:
                table.add_row("[bold]High Priority[/]", f"{len(high_pri)} pending")

            # Next recommended
            next_task = self.profile.task_tree.get_next_actionable(self.profile.task_tree)
            if next_task:
                table.add_row("", "")
                table.add_row("[bold]Next Task[/]", next_task.name[:40] + "..." if len(next_task.name) > 40 else next_task.name)

            panel = Panel(table, title="[bold]Progress Dashboard[/]", border_style="magenta")

            # Display and wait
            self.console.print(panel)
            self.console.print(f"\n{self.theme.muted('Press any key to dismiss (or \"p\" to toggle off)...')} ", end="")
            dismiss_key = self.hotkey_handler.read_key()  # Single keypress (consistent with TUI)

            # Strategic chokepoint: Dashboard closed
            self.debug_logger.log("Progress dashboard closed",
                                 category=LogCategory.UI_PANEL,
                                 level=LogLevel.NORMAL,
                                 dismiss_key=dismiss_key)
        finally:
            # Resume Live context
            if hasattr(self, '_live'):
                self._live.start()

        # Toggle behavior: pressing 'p' again just closes (no re-execution)
        if dismiss_key and dismiss_key.lower() == 'p':
            self.debug_logger.log("Toggle dismiss: same key pressed, overlay closed",
                                 category=LogCategory.UI_INPUT, level=LogLevel.VERBOSE, key=dismiss_key)
            return  # Just close, don't re-execute

        # Smart dismiss: if dismiss key is a valid command, execute it
        if dismiss_key and dismiss_key not in ['\r', '\n', ' ']:
            self.debug_logger.log("Smart dismiss: processing dismiss key as command",
                                 category=LogCategory.UI_INPUT, level=LogLevel.VERBOSE, key=dismiss_key)
            self._process_input(dismiss_key)

    def _check_interrupted_tasks_tui(self):
        """
        TUI-specific checkpoint detection (uses Rich console, called BEFORE Live context)

        This method is called at the start of run(), before the Live context begins,
        so we can use regular input() for prompts without conflicts.
        """
        self.debug_logger.section("CHECKPOINT DETECTION (TUI)")

        interrupted = self.checkpoint_mgr.detect_interrupted_session(self.target)
        self.debug_logger.info(f"Detected {len(interrupted)} interrupted tasks")

        if not interrupted:
            self.debug_logger.info("No interrupted tasks found")
            return

        # Display using Rich console
        self.console.print()
        self.console.print(f"[bold yellow]⚠ Found {len(interrupted)} interrupted task(s) from previous session:[/]")
        self.console.print()

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

            status_color = {
                'running': 'yellow',
                'paused': 'cyan',
                'error': 'red'
            }.get(task.get('status'), 'white')

            self.console.print(f"  • [bold]{task['task_id']}[/]/[dim]{task['stage_id']}[/] - [{status_color}]{task['status']}[/] [dim]({timestamp_str})[/]")

        if len(interrupted) > 5:
            self.console.print(f"  [dim]... and {len(interrupted) - 5} more[/]")

        self.console.print()
        response = input("Resume interrupted tasks? [Y/n]: ").strip()

        if not response or response.lower() == 'y':
            # Offer to resume each task
            self.debug_logger.info("User chose to resume tasks")
            for task_info in interrupted[:3]:  # Only offer first 3
                self._offer_task_resume_tui(task_info)

            # Clear remaining checkpoints
            if len(interrupted) > 3:
                self.console.print(f"\n[dim]{len(interrupted) - 3} other checkpoint(s) will be cleared.[/]")
                for task_info in interrupted[3:]:
                    self.checkpoint_mgr.clear_checkpoint(
                        task_info['task_id'],
                        task_info['stage_id'],
                        self.target
                    )
                self.debug_logger.info(f"Cleared {len(interrupted) - 3} additional checkpoints")
        else:
            # User declined - clear all checkpoints
            self.debug_logger.info("User declined to resume, clearing all checkpoints")
            self.console.print(self.theme.muted("Clearing all interrupted task checkpoints..."))
            count = self.checkpoint_mgr.clear_all_checkpoints(self.target)
            self.console.print(self.theme.success(f"✓ Cleared {count} checkpoint(s)"))

        self.console.print()  # Add spacing before continuing to config panel

    def _offer_task_resume_tui(self, task_info: Dict[str, str]):
        """TUI-specific task resume offer (uses Rich console)"""
        task_id = task_info['task_id']
        self.console.print(f"\n{self.theme.primary(f'──── Task: {task_id} ────')}")
        self.console.print(f"{self.theme.muted('Stage:')} {task_info['stage_id']}")

        # Load checkpoint state
        state = self.checkpoint_mgr.load_checkpoint(
            task_info['task_id'],
            task_info['stage_id'],
            self.target
        )

        if not state:
            self.console.print(self.theme.warning("⚠ Checkpoint data corrupted or missing"))
            return

        # Show checkpoint details
        self.console.print(f"{self.theme.muted('Status:')} {state.get('status', 'unknown')}")
        command = state.get('command', 'N/A')
        if len(command) > 80:
            command = command[:77] + '...'
        self.console.print(f"{self.theme.muted('Command:')} {self.theme.primary(command)}")

        partial_output = state.get('partial_output', '')
        if partial_output:
            line_count = len(partial_output.split('\n'))
            self.console.print(f"{self.theme.muted('Output captured:')} {line_count} lines")

        self.console.print()
        response = input("Resume this task? [Y/n]: ").strip()

        if not response or response.lower() == 'y':
            self.console.print()
            self.console.print(self.theme.info("ℹ Task resume feature"))
            self.console.print(self.theme.muted("This will be implemented when task execution is refactored"))
            self.console.print(self.theme.muted("for checkpoint support. For now, the checkpoint will be cleared"))
            self.console.print(self.theme.muted("and you can manually re-run the task."))
            self.console.print()
            # TODO: Implement actual task resume
            self.checkpoint_mgr.clear_checkpoint(
                task_info['task_id'],
                task_info['stage_id'],
                self.target
            )
            self.console.print(self.theme.success("✓ Checkpoint cleared. Re-run task manually."))
            self.debug_logger.info(f"Cleared checkpoint for {task_info['task_id']}/{task_info['stage_id']}")
        else:
            # Clear checkpoint if user declined
            self.checkpoint_mgr.clear_checkpoint(
                task_info['task_id'],
                task_info['stage_id'],
                self.target
            )
            self.console.print(self.theme.muted("Checkpoint cleared."))
            self.debug_logger.info(f"User declined, cleared checkpoint for {task_info['task_id']}/{task_info['stage_id']}")
