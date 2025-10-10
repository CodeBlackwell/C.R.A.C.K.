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
from ..recommendations.engine import RecommendationEngine
from ..parsers.output_patterns import OutputPatternMatcher

from .session import InteractiveSession
from .prompts import PromptBuilder
from .input_handler import InputProcessor
from .tui_config import ConfigPanel
from .panels.dashboard_panel import DashboardPanel
from .panels.task_workspace_panel import TaskWorkspacePanel
from .panels.task_list_panel import TaskListPanel
from .panels.findings_panel import FindingsPanel
from .overlays.status_overlay import StatusOverlay
from .overlays.help_overlay import HelpOverlay
from .overlays.tree_overlay import TreeOverlay
from .overlays.execution_overlay import ExecutionOverlay
from .overlays.output_overlay import OutputOverlay
from .debug_logger import init_debug_logger, get_debug_logger
from .log_types import LogCategory, LogLevel
from .hotkey_input import HotkeyInputHandler
from .components.resize_handler import ResizeHandler, TerminalSizeError


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
            self.console.print(f"[yellow]⚠ {str(e)}[/]")
            return super().run()

        # Check terminal support
        if not self._supports_tui():
            self.debug_logger.log("TUI not supported - falling back", category=LogCategory.SYSTEM_ERROR, level=LogLevel.MINIMAL,
                                 terminal_width=self.console.width, terminal_height=self.console.height)
            self.console.print("[yellow]⚠ TUI mode not supported - falling back[/]")
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
                screen=True,  # Full-screen mode for proper clearing
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
            self.console.print("\n[yellow]Interrupted. Saving...[/]")
        except Exception as e:
            self.debug_logger.log("Unexpected TUI error", category=LogCategory.SYSTEM_ERROR, level=LogLevel.MINIMAL, error=str(e), exception=True)
            raise
        finally:
            # Unregister resize handler to restore default signal handling
            self.resize_handler.unregister_handler()
            self.debug_logger.log("Resize handler unregistered", category=LogCategory.SYSTEM_SHUTDOWN, level=LogLevel.VERBOSE)

            self.debug_logger.log("TUI shutdown - saving profile", category=LogCategory.STATE_SAVE, level=LogLevel.NORMAL)
            self.profile.save()
            self.console.print("[bright_green]✓ Session saved. Goodbye![/]")
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
            # Render config panel
            config_panel = ConfigPanel.render_panel(config, self.profile.target)

            # Update header
            header_text = f"[bold cyan]CRACK Track TUI[/] | [white]Target:[/] {self.profile.target}"
            header = Panel(header_text, border_style="cyan", box=box.HEAVY)
            layout['header'].update(header)

            # Put config panel in menu area
            layout['menu'].update(config_panel)

            # Footer
            footer_text = "[cyan]1-4[/]:Edit | [cyan]5[/]:Continue | [cyan]q[/]:Quit | [dim]:[/]command"
            footer = Panel(footer_text, border_style="cyan", box=box.HEAVY)
            layout['footer'].update(footer)

            # Refresh display
            live.refresh()

            # Stop live to get input
            live.stop()

            # Get input (vim-style hotkeys)
            self.console.print("\n[dim]Press key (or : for command):[/] ", end="")
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
        # Strategic chokepoint: Main interaction loop start
        self.debug_logger.log("Main interaction loop started", category=LogCategory.SYSTEM_INIT, level=LogLevel.NORMAL)

        # Store live context AND layout for _execute_choice to access
        self._live = live
        self._layout = layout

        running = True
        iteration = 0

        while running:
            iteration += 1
            # Only log every 10 iterations to avoid spam
            if iteration % 10 == 0:
                self.debug_logger.log(f"Loop iteration {iteration}", category=LogCategory.UI_RENDER, level=LogLevel.TRACE)

            # Refresh display
            self._refresh_panels(layout)

            live.refresh()

            # Stop live to get input
            live.stop()

            # Get user input (vim-style hotkeys)
            self.console.print("\n[dim]Press key (or : for command):[/] ", end="")
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
                    # Single-key shortcut
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

            # Render workspace panel with current state
            self.debug_logger.debug("Rendering TaskWorkspacePanel")
            workspace_layout, choices = TaskWorkspacePanel.render(
                task=task,
                output_state=output_state,
                output_lines=output_lines,
                elapsed=elapsed,
                exit_code=exit_code,
                findings=findings
            )
            self.debug_logger.debug(f"TaskWorkspacePanel returned {len(choices)} choices")

            # Update all layout sections
            self.debug_logger.debug("Updating layout sections")
            layout['header'].update(self._render_header())
            layout['menu'].update(workspace_layout)
            layout['footer'].update(self._render_footer())

            # Refresh display
            self.debug_logger.log_live_action("REFRESH", "workspace display")
            live.refresh()

            # Stop live to get input
            self.debug_logger.log_live_action("STOP", "before workspace input")
            live.stop()

            # Get user input (vim-style hotkeys)
            self.console.print("\n[dim]Press key (b:Back, or : for command):[/] ", end="")
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

            # Try to parse as choice number
            try:
                choice_num = int(user_input)
                self.debug_logger.debug(f"Parsed as choice number: {choice_num}")

                if 1 <= choice_num <= len(choices):
                    choice = choices[choice_num - 1]
                    choice_id = choice.get('id')
                    self.debug_logger.info(f"Workspace choice selected: {choice_id} - {choice.get('label')}")

                    # Handle different choice actions
                    if choice_id == 'execute':
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
                            self.console.print("\n[yellow]⚠ Execution interrupted[/]")
                            self.console.print("[dim]Press Enter to continue...[/]")
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
                        self.console.print(f"\n[yellow]⚠ Action '{choice_id}' not yet implemented in Stage 2[/]")
                        self.console.print("[dim]This will be added in future stages. Press Enter to continue...[/]")
                        input()
                        live.start()
                else:
                    self.debug_logger.warning(f"Choice {choice_num} out of range (1-{len(choices)})")

                    # Stop live to show error clearly
                    live.stop()
                    self.console.print(f"\n[red]Invalid choice: {choice_num}[/]")
                    self.console.print(f"[dim]Please choose 1-{len(choices)} or 'b' for back. Press Enter...[/]")
                    input()
                    live.start()

            except ValueError as e:
                self.debug_logger.warning(f"Failed to parse workspace input: {e}")

                # Stop live to show error clearly
                live.stop()
                self.console.print(f"\n[red]Invalid input: {user_input}[/]")
                self.console.print(f"[dim]Please enter a number or 'b' for back. Press Enter...[/]")
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
                page=page
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
            self.console.print("\n[dim]Press key (1-10:Select, f:Filter, s:Sort, b:Back):[/] ", end="")
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
                self.console.print("\n[yellow]Filter menu not yet implemented[/]")
                self.console.print("[dim]Press Enter to continue...[/]")
                input()
                live.start()
                continue

            elif user_input.lower() == 's':
                self.debug_logger.info("Sort menu requested (placeholder)")
                live.stop()
                self.console.print("\n[yellow]Sort menu not yet implemented[/]")
                self.console.print("[dim]Press Enter to continue...[/]")
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
                    self.console.print(f"\n[red]Invalid choice: {choice_num}[/]")
                    self.console.print(f"[dim]Please choose 1-{len(choices)} or 'b' for back. Press Enter...[/]")
                    input()
                    live.start()

            except ValueError as e:
                self.debug_logger.warning(f"Failed to parse task list input: {e}")

                live.stop()
                self.console.print(f"\n[red]Invalid input: {user_input}[/]")
                self.console.print(f"[dim]Please enter a number or shortcut. Press Enter...[/]")
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
                page=page
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
            self.console.print("\n[dim]Press key (f:Filter, e:Export, b:Back):[/] ", end="")
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
                self.console.print("\n[yellow]Filter menu not yet implemented[/]")
                self.console.print("[dim]Press Enter to continue...[/]")
                input()
                live.start()
                continue

            elif user_input.lower() == 'e':
                self.debug_logger.info("Export requested (placeholder)")
                live.stop()
                self.console.print("\n[yellow]Export not yet implemented[/]")
                self.console.print("[dim]Press Enter to continue...[/]")
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
                        self.console.print("\n[yellow]Finding details view not yet implemented[/]")
                        self.console.print("[dim]Press Enter to continue...[/]")
                        input()
                        live.start()

                    else:
                        self.debug_logger.warning(f"Unhandled action: {choice_action}")

                else:
                    self.debug_logger.warning(f"Choice {choice_num} out of range (1-{len(choices)})")

                    live.stop()
                    self.console.print(f"\n[red]Invalid choice: {choice_num}[/]")
                    self.console.print(f"[dim]Please choose 1-{len(choices)} or 'b' for back. Press Enter...[/]")
                    input()
                    live.start()

            except ValueError as e:
                self.debug_logger.warning(f"Failed to parse findings input: {e}")

                live.stop()
                self.console.print(f"\n[red]Invalid input: {user_input}[/]")
                self.console.print(f"[dim]Please enter a number or shortcut. Press Enter...[/]")
                input()
                live.start()

        self.debug_logger.section("FINDINGS LOOP END")
        self.debug_logger.info("Returning to dashboard")

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
                        findings=[]
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
                findings=[]
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

            self.debug_logger.info(f"Findings detected: {len(findings)}")
        except Exception as e:
            self.debug_logger.exception(f"Exception during finding analysis: {e}")
            findings = []

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

        # 10. Return results
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
        """Render footer with vim-style shortcuts"""
        shortcuts = "[cyan]n[/]:Next | [cyan]l[/]:List | [cyan]f[/]:Findings | [cyan]o[/]:Output | [cyan]p[/]:Progress | [cyan]h[/]:Help | [cyan]s[/]:Status | [cyan]t[/]:Tree | [cyan]q[/]:Quit | [dim]:[/]cmd"
        return Panel(
            shortcuts,
            border_style="cyan",
            box=box.HEAVY
        )

    def _process_input(self, user_input: str) -> Optional[str]:
        """Process user input - supports numbers, letter hotkeys, and : commands"""
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
            self.console.print(f"[yellow]Action not available in current context[/]")
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
                profile=self.profile
            )
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
        bar = f"[green]{'█' * filled}[/][dim]{'░' * empty}[/]"
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
        input()  # Wait for keypress

        # Strategic chokepoint: Dashboard closed
        self.debug_logger.log("Progress dashboard closed",
                             category=LogCategory.UI_PANEL,
                             level=LogLevel.NORMAL)

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
            self.console.print("[dim]Clearing all interrupted task checkpoints...[/]")
            count = self.checkpoint_mgr.clear_all_checkpoints(self.target)
            self.console.print(f"[green]✓ Cleared {count} checkpoint(s)[/]")

        self.console.print()  # Add spacing before continuing to config panel

    def _offer_task_resume_tui(self, task_info: Dict[str, str]):
        """TUI-specific task resume offer (uses Rich console)"""
        self.console.print(f"\n[bold cyan]──── Task: {task_info['task_id']} ────[/]")
        self.console.print(f"[dim]Stage:[/] {task_info['stage_id']}")

        # Load checkpoint state
        state = self.checkpoint_mgr.load_checkpoint(
            task_info['task_id'],
            task_info['stage_id'],
            self.target
        )

        if not state:
            self.console.print("[yellow]⚠ Checkpoint data corrupted or missing[/]")
            return

        # Show checkpoint details
        self.console.print(f"[dim]Status:[/] {state.get('status', 'unknown')}")
        command = state.get('command', 'N/A')
        if len(command) > 80:
            command = command[:77] + '...'
        self.console.print(f"[dim]Command:[/] [cyan]{command}[/]")

        partial_output = state.get('partial_output', '')
        if partial_output:
            line_count = len(partial_output.split('\n'))
            self.console.print(f"[dim]Output captured:[/] {line_count} lines")

        self.console.print()
        response = input("Resume this task? [Y/n]: ").strip()

        if not response or response.lower() == 'y':
            self.console.print()
            self.console.print("[cyan]ℹ Task resume feature[/]")
            self.console.print("[dim]This will be implemented when task execution is refactored[/]")
            self.console.print("[dim]for checkpoint support. For now, the checkpoint will be cleared[/]")
            self.console.print("[dim]and you can manually re-run the task.[/]")
            self.console.print()
            # TODO: Implement actual task resume
            self.checkpoint_mgr.clear_checkpoint(
                task_info['task_id'],
                task_info['stage_id'],
                self.target
            )
            self.console.print("[green]✓ Checkpoint cleared. Re-run task manually.[/]")
            self.debug_logger.info(f"Cleared checkpoint for {task_info['task_id']}/{task_info['stage_id']}")
        else:
            # Clear checkpoint if user declined
            self.checkpoint_mgr.clear_checkpoint(
                task_info['task_id'],
                task_info['stage_id'],
                self.target
            )
            self.console.print("[dim]Checkpoint cleared.[/]")
            self.debug_logger.info(f"User declined, cleared checkpoint for {task_info['task_id']}/{task_info['stage_id']}")
