"""
TUI Session - Windowed interface using Rich Live

Wraps existing InteractiveSession logic with TUI rendering.
No terminal flooding - updates panels in-place using Rich Live.
"""

import time
from typing import Optional, Dict, Any
from io import StringIO
from contextlib import redirect_stdout

from rich.console import Console
from rich.live import Live

from ..core.state import TargetProfile
from ..core.storage import Storage
from ..recommendations.engine import RecommendationEngine
from ..parsers.registry import ParserRegistry

from .session import InteractiveSession
from .tui_layout import TUILayoutManager
from .tui_panels import TUIPanels
from .tui_config import ConfigPanel
from .tui_input import create_input_handler
from .prompts import PromptBuilder
from .input_handler import InputProcessor


class TUISession(InteractiveSession):
    """TUI-enabled interactive session with windowed interface"""

    def __init__(self, target: str, resume: bool = False, screened: bool = False, debug: bool = False):
        """
        Initialize TUI session

        Args:
            target: Target IP or hostname
            resume: Whether to resume existing session
            screened: Whether to use screened terminal mode
            debug: Enable debug output
        """
        # Initialize parent session
        super().__init__(target, resume, screened)

        # TUI components
        self.console = Console()
        self.layout_manager = TUILayoutManager(self.console)
        self.output_lines = []  # Command output buffer
        self.show_help = False  # Help panel toggle
        self.debug_mode = debug  # Debug mode flag
        self.config_confirmed = False  # Whether user confirmed config

    def run(self):
        """
        Main TUI loop with Rich Live display

        Replaces parent's print-based loop with windowed interface.
        """
        # Check TUI support
        if not self.layout_manager.supports_tui():
            self.console.print("[yellow]⚠ TUI mode not supported in this terminal[/]")
            self.console.print("[yellow]Falling back to basic mode...[/]")
            # Fall back to parent's basic mode
            return super().run()

        try:
            # Note: screen=False allows stdin to work normally
            with Live(
                self.layout_manager.get_layout(),
                console=self.console,
                screen=False,  # Don't take over screen to allow input
                refresh_per_second=4,
                auto_refresh=False  # Manual refresh only - prevents input interference
            ) as live:
                # Phase 1: Show config panel first (simple test)
                if not self.config_confirmed:
                    self._config_panel_loop(live)

                # Phase 2: Main menu (only after config confirmed)
                if self.config_confirmed:
                    self._tui_loop(live)
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Interrupted. Saving session...[/]")
        finally:
            self.profile.save()
            self.console.print("[bright_green]✓ Session saved. Goodbye![/]")

    def _config_panel_loop(self, live: Live):
        """
        Config panel loop - Phase 1 simple test

        Shows config panel, allows editing, continues when user confirms.

        Args:
            live: Rich Live context
        """
        # Load config
        config = ConfigPanel.load_config()

        running = True
        while running:
            # Render config panel
            config_panel = ConfigPanel.render_panel(config, self.profile.target)

            # Update all panels - use config panel as main display
            header = TUIPanels.render_header(self.profile.target, "Configuration")
            self.layout_manager.update_header(header)

            # Put config panel in center
            self.layout_manager.update_menu(config_panel)

            # Clear other panels for now
            from rich.panel import Panel
            from rich import box
            empty = Panel("", border_style="dim", box=box.ROUNDED)
            self.layout_manager.update_context(empty)
            self.layout_manager.update_tree(empty)
            self.layout_manager.update_output(empty)

            # Footer
            footer = TUIPanels.render_footer([
                ('1-4', 'Edit'),
                ('5', 'Continue'),
                ('q', 'Quit')
            ])
            self.layout_manager.update_footer(footer)

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
                return  # Exit

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

    def _tui_loop(self, live: Live):
        """
        Main TUI event loop

        Args:
            live: Rich Live context
        """
        running = True

        while running:
            # Refresh panels before waiting for input
            self._refresh_panels()
            live.refresh()  # Manual display update (no auto-refresh interference)

            # Stop live display to allow clean input
            live.stop()

            # Print prompt below panels and get input (blocks until Enter)
            self.console.print("\n[bold bright_yellow]Choice [or shortcut]:[/] ", end="")
            try:
                user_input = input().strip() or None
            except EOFError:
                # EOF means exit
                live.start()
                running = False
                continue
            except KeyboardInterrupt:
                # Ctrl+C means exit
                live.start()
                running = False
                continue

            # Resume live display
            live.start()

            if user_input:
                # Process input
                result = self._process_tui_input(user_input)

                if result == 'exit':
                    running = False
                elif result == 'refresh':
                    # Panel will refresh on next loop
                    pass

    def _refresh_panels(self):
        """Refresh all TUI panels with current state"""
        # Header
        header = TUIPanels.render_header(
            self.profile.target,
            self.profile.phase
        )
        self.layout_manager.update_header(header)

        # Context panel
        context = TUIPanels.render_context(self.profile)
        self.layout_manager.update_context(context)

        # Task tree panel
        tree = TUIPanels.render_task_tree(self.profile)
        self.layout_manager.update_tree(tree)

        # Main menu panel (or help)
        if self.show_help:
            menu = TUIPanels.render_help()
        else:
            # Get recommendations and build menu
            recommendations = RecommendationEngine.get_recommendations(self.profile)
            prompt_text, choices = PromptBuilder.build_main_menu(self.profile, recommendations)
            menu = TUIPanels.render_menu(choices, title=prompt_text)
            # Store for input processing
            self._current_choices = choices
            self._current_recommendations = recommendations

        self.layout_manager.update_menu(menu)

        # Output panel
        output = TUIPanels.render_output(self.output_lines)
        self.layout_manager.update_output(output)

        # Footer (with debug status if enabled)
        if self.debug_mode:
            footer = TUIPanels.render_footer(debug_mode=True)
        else:
            footer = TUIPanels.render_footer()
        self.layout_manager.update_footer(footer)

    def _process_tui_input(self, user_input: str) -> Optional[str]:
        """
        Process user input in TUI mode

        Args:
            user_input: Raw input string

        Returns:
            'exit' to quit, 'refresh' to update, None to continue
        """
        # Toggle help
        if user_input.lower() == 'h':
            self.show_help = not self.show_help
            return 'refresh'

        # Close help if showing
        if self.show_help:
            self.show_help = False
            return 'refresh'

        # Quit
        if user_input.lower() == 'q':
            return 'exit'

        # Toggle debug mode (uppercase D)
        if user_input == 'D':
            self.debug_mode = not self.debug_mode
            status = "enabled" if self.debug_mode else "disabled"
            self.output_lines.append(f"[yellow]Debug mode {status}[/]")
            return 'refresh'

        # Reset session (uppercase R only - prevents accidental resets)
        if user_input == 'R':
            # Handle reset specially in TUI mode (needs Live display control)
            result = self._handle_reset()
            return 'refresh' if result else 'exit'

        # Debug: Show input received
        if self.debug_mode:
            self.output_lines.append(f"[dim cyan][DEBUG] Input received: '{user_input}'[/]")

        # Parse input against current choices
        try:
            parsed = InputProcessor.parse_any(
                user_input,
                {'choices': self._current_choices}
            )

            # Debug: Show parsed result
            if self.debug_mode:
                self.output_lines.append(
                    f"[dim cyan][DEBUG] Parsed: type='{parsed['type']}', "
                    f"value={str(parsed.get('value', 'None'))[:50]}[/]"
                )

            if parsed['type'] == 'choice':
                choice = parsed['value']  # Fixed: use 'value' key

                # Debug: Show choice details
                if self.debug_mode:
                    self.output_lines.append(
                        f"[dim cyan][DEBUG] Choice: id='{choice.get('id')}', "
                        f"label='{choice.get('label')}'[/]"
                    )
                    self.output_lines.append(f"[dim cyan][DEBUG] Calling process_input()...[/]")

                # Capture stdout from choice processing (uses print())
                output_buffer = StringIO()
                try:
                    with redirect_stdout(output_buffer):
                        # Process choice using parent logic
                        result = self.process_input(
                            user_input,
                            self._current_choices,
                            self._current_recommendations
                        )

                    # Add captured output to panel
                    captured = output_buffer.getvalue()
                    if captured:
                        for line in captured.strip().split('\n'):
                            if line.strip():
                                self.output_lines.append(line)

                    # Debug: Show result
                    if self.debug_mode:
                        self.output_lines.append(f"[dim cyan][DEBUG] process_input() returned: {result}[/]")

                    # Add to output
                    self.output_lines.append(f"[cyan]> Executed: {choice.get('label', 'Unknown')}[/]")

                    # Save checkpoint
                    self.save_checkpoint()

                except Exception as e:
                    self.output_lines.append(f"[red]✗ Choice execution error: {e}[/]")
                    if self.debug_mode:
                        import traceback
                        tb = traceback.format_exc()
                        for line in tb.split('\n')[:15]:  # More lines for choice errors
                            if line.strip():
                                self.output_lines.append(f"[dim red][DEBUG] {line}[/]")

                return 'refresh'

            elif parsed['type'] == 'shortcut':
                # Handle shortcuts
                shortcut = parsed['value']  # Fixed: use 'value' key

                # Debug: Show shortcut
                if self.debug_mode:
                    self.output_lines.append(f"[dim cyan][DEBUG] Shortcut: '{shortcut}'[/]")

                # Capture stdout from shortcut handler (they use print())
                output_buffer = StringIO()
                try:
                    with redirect_stdout(output_buffer):
                        handled = self.shortcut_handler.handle(shortcut)

                    # Add captured output to panel
                    captured = output_buffer.getvalue()
                    if captured:
                        for line in captured.strip().split('\n'):
                            if line.strip():
                                self.output_lines.append(line)

                    if self.debug_mode:
                        self.output_lines.append(f"[dim cyan][DEBUG] Shortcut handled: {handled}[/]")

                    if not handled:
                        return 'exit'

                except Exception as e:
                    self.output_lines.append(f"[red]✗ Shortcut error: {e}[/]")
                    if self.debug_mode:
                        import traceback
                        tb = traceback.format_exc()
                        for line in tb.split('\n')[:10]:
                            if line.strip():
                                self.output_lines.append(f"[dim red][DEBUG] {line}[/]")

                return 'refresh'

        except Exception as e:
            self.output_lines.append(f"[red]✗ Error: {e}[/]")
            # Debug: Show full traceback
            if self.debug_mode:
                import traceback
                tb = traceback.format_exc()
                for line in tb.split('\n')[:10]:  # Limit to 10 lines
                    if line.strip():
                        self.output_lines.append(f"[dim red][DEBUG] {line}[/]")
            return 'refresh'

        return 'refresh'

    def _handle_reset(self) -> bool:
        """
        Handle session reset in TUI mode

        Returns:
            True to continue session, False to exit
        """
        from ..core.storage import Storage
        from ..core.state import TargetProfile

        # Print warning
        self.console.print("\n" + "=" * 60)
        self.console.print("[bold red]⚠️  SESSION RESET WARNING ⚠️[/]")
        self.console.print("=" * 60)
        self.console.print("[yellow]\nThis will DELETE ALL enumeration data for this target:")
        self.console.print("  • All discovered ports and services")
        self.console.print("  • All findings and vulnerabilities")
        self.console.print("  • All credentials and notes")
        self.console.print("  • Complete task history")
        self.console.print("  • Command execution logs")
        self.console.print("\nThis action CANNOT be undone![/]\n")

        # First confirmation: Type "RESET"
        self.console.print("[cyan]Type 'RESET' (all caps) to confirm you understand:[/]")
        first_confirm = input("> ").strip()

        if first_confirm != "RESET":
            self.console.print("[green]Reset cancelled - session preserved[/]")
            input("\nPress Enter to continue...")
            return True

        # Second confirmation: Y/N
        self.console.print("\n[cyan]Are you absolutely sure? [y/N]:[/]")
        second_confirm = input("> ").strip().lower()

        if second_confirm not in ['y', 'yes']:
            self.console.print("[green]Reset cancelled - session preserved[/]")
            input("\nPress Enter to continue...")
            return True

        # Perform reset
        target = self.profile.target
        self.console.print(f"\n[cyan]Deleting profile for {target}...[/]")

        # Delete stored profile
        Storage.delete(target)

        # Create fresh profile
        self.profile = TargetProfile(target)
        self.profile.save()

        # Clear output buffer
        self.output_lines = []

        self.console.print("[bright_green]\n✓ Session reset complete[/]")
        self.console.print(f"[bright_green]✓ Clean profile created for {target}[/]")
        self.console.print("[bright_green]✓ Ready to start enumeration from zero\n[/]")

        input("Press Enter to continue...")
        return True

    def add_output(self, text: str):
        """
        Add text to output panel

        Args:
            text: Output text to append
        """
        self.output_lines.append(text)

        # Keep output buffer reasonable (last 100 lines)
        if len(self.output_lines) > 100:
            self.output_lines = self.output_lines[-100:]
