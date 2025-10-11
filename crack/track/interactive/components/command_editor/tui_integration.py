"""
CommandEditor TUI Integration

Provides Rich rendering callbacks for the command editor system.
Wraps the pure logic components with interactive TUI elements.
"""

from typing import Optional, Dict, List
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.syntax import Syntax

from .editor import CommandEditor
from .quick_editor import EditResult


class CommandEditorTUI:
    """
    TUI wrapper for CommandEditor with Rich rendering.

    Provides interactive callbacks for user input and displays
    menus, prompts, and previews using Rich components.
    """

    def __init__(
        self,
        command: str,
        metadata: Dict,
        profile: Optional['TargetProfile'] = None,
        console: Optional[Console] = None
    ):
        """
        Initialize TUI wrapper.

        Args:
            command: Original command string
            metadata: Task metadata (must contain 'tool' key)
            profile: Optional TargetProfile
            console: Rich console instance (creates new if None)
        """
        self.command = command
        self.metadata = metadata
        self.profile = profile
        self.console = console or Console()

        # Create editor with TUI callbacks
        self.editor = CommandEditor(
            command=command,
            metadata=metadata,
            profile=profile
        )

    def edit(self) -> Optional[EditResult]:
        """
        Run command editor with TUI rendering.

        Returns:
            EditResult with user's final choice
        """
        # Show editor header
        self._show_header()

        # Patch tier editors with TUI callbacks before running
        self._patch_tier_callbacks()

        # Run editor orchestrator
        result = self.editor.edit()

        # Show result message
        if result:
            self._show_result(result)

        return result

    def _show_header(self):
        """Display command editor header"""
        tool = self.metadata.get('tool', 'unknown')

        header = Panel(
            f"[cyan]Command Editor[/cyan]\n\n"
            f"Tool: [yellow]{tool}[/yellow]\n"
            f"Command: [dim]{self.command}[/dim]\n\n"
            f"[dim]Tip: Use 'a' to escalate to advanced editor, 'r' for raw editor, 'c' to cancel[/dim]",
            title="📝 Edit Command",
            border_style="cyan"
        )
        self.console.print(header)
        self.console.print()

    def _show_result(self, result: EditResult):
        """Display result message"""
        if result.action == "execute":
            self.console.print(f"[green]✓[/green] Command updated: [cyan]{result.command}[/cyan]")
        elif result.action == "cancel":
            self.console.print("[yellow]Cancelled[/yellow]")

    def _patch_tier_callbacks(self):
        """Patch tier editor run methods with TUI rendering"""
        original_run_tier = self.editor._run_tier

        def patched_run_tier(tier: str) -> EditResult:
            """Run tier with TUI callbacks injected"""
            if tier == "quick":
                return self._run_quick_editor()
            elif tier == "advanced":
                return self._run_advanced_editor()
            elif tier == "raw":
                return self._run_raw_editor()
            else:
                return original_run_tier(tier)

        self.editor._run_tier = patched_run_tier

    def _run_quick_editor(self) -> EditResult:
        """Run QuickEditor with TUI rendering"""
        from .quick_editor import QuickEditor
        from .parser import CommandParser

        # Create editor with TUI callbacks
        editor = QuickEditor(
            command=self.editor.current_command,
            metadata=self.editor.metadata,
            input_callback=self._prompt_input,
            choice_callback=self._prompt_choice
        )

        # Parse and extract params
        parsed = CommandParser.parse(self.editor.current_command)
        editable_params = editor._extract_common_params(parsed)

        if not editable_params:
            # No params - escalate to advanced
            return EditResult(command=None, action="escalate", next_tier="advanced")

        # Display parameter menu
        self._show_param_menu(editable_params)

        # Run editor logic
        return editor.run()

    def _run_advanced_editor(self) -> EditResult:
        """Run AdvancedEditor with TUI rendering"""
        from .advanced_editor import AdvancedEditor

        # For now, escalate to raw (advanced editor needs schema-driven form rendering)
        self.console.print("[yellow]Advanced editor (schema-driven forms) coming soon![/yellow]")
        self.console.print("[dim]Escalating to raw text editor...[/dim]\n")
        return EditResult(command=self.editor.current_command, action="escalate", next_tier="raw")

    def _run_raw_editor(self) -> EditResult:
        """Run RawEditor with TUI rendering"""
        from .raw_editor import RawEditor
        from .validator import CommandValidator

        self.console.print(Panel(
            "[cyan]Raw Editor[/cyan]\n\n"
            "[dim]Edit command directly. Press Enter twice when done.[/dim]",
            title="✏ Raw Text Editor",
            border_style="cyan"
        ))
        self.console.print()

        # Show current command
        syntax = Syntax(self.editor.current_command, "bash", theme="monokai", line_numbers=True)
        self.console.print(syntax)
        self.console.print()

        # Get edited command
        self.console.print("[yellow]Enter new command:[/yellow]")
        lines = []
        while True:
            line = Prompt.ask("", default="")
            if line == "" and len(lines) > 0:
                break  # Empty line after input = done
            if line == "" and len(lines) == 0:
                # First line empty = cancel
                return EditResult(command=None, action="cancel")
            lines.append(line)

        new_command = "\n".join(lines) if lines else self.editor.current_command

        # Validate command
        validation = CommandValidator.validate_syntax(new_command)

        if not validation.is_valid:
            self.console.print(f"[red]✗ Validation errors:[/red]")
            for error in validation.errors:
                self.console.print(f"  [red]•[/red] {error}")

            if not Confirm.ask("Execute anyway?", default=False):
                return EditResult(command=None, action="cancel")

        # Show warnings
        if validation.warnings:
            self.console.print(f"[yellow]⚠ Warnings:[/yellow]")
            for warning in validation.warnings:
                self.console.print(f"  [yellow]•[/yellow] {warning}")

        return EditResult(command=new_command, action="execute")

    def _show_param_menu(self, params: Dict[str, str]):
        """Display parameter menu"""
        table = Table(title="Editable Parameters", show_header=True, header_style="bold cyan")
        table.add_column("#", style="cyan", width=3)
        table.add_column("Parameter", style="yellow")
        table.add_column("Current Value", style="dim")

        for idx, (param_name, value) in enumerate(params.items(), 1):
            table.add_row(str(idx), param_name, value or "[dim]<empty>[/dim]")

        self.console.print(table)
        self.console.print()

    def _prompt_input(self, prompt: str) -> str:
        """Callback for input prompt"""
        return Prompt.ask(f"[cyan]{prompt}[/cyan]", default="")

    def _prompt_choice(self, prompt: str) -> str:
        """Callback for choice prompt"""
        choices_hint = "[dim](1-5: param, a: advanced, r: raw, c: cancel)[/dim]"
        return Prompt.ask(
            f"[cyan]{prompt}[/cyan] {choices_hint}",
            default="c"
        ).lower().strip()
