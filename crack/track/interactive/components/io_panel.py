"""
I/O Panel Component for CRACK Track TUI

Provides three rendering states for command output in the Task Workspace:
1. Empty state (before execution)
2. Streaming state (during execution)
3. Complete state (after execution)

This component renders in the bottom 80% of the vertical split view.
"""

from typing import List, Dict
from rich.panel import Panel
from rich.text import Text
from rich import box


class IOPanel:
    """I/O streaming panel for command output - bottom section of vertical split"""

    @staticmethod
    def _format_elapsed(seconds: float) -> str:
        """Convert seconds to MM:SS format

        Args:
            seconds: Elapsed time in seconds

        Returns:
            Formatted time string in MM:SS format
        """
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes:02d}:{secs:02d}"

    @staticmethod
    def render_empty() -> Panel:
        """Render empty state before task execution

        Returns:
            Panel with placeholder content and execution prompt
        """
        content = Text()
        content.append("No output yet.\n\n", style="dim")
        content.append("Press (1) to execute this stage", style="cyan")

        return Panel(
            content,
            title="[bold]Command Output[/bold]",
            border_style="blue",
            box=box.ROUNDED
        )

    @staticmethod
    def render_streaming(lines: List[str], elapsed: float) -> Panel:
        """Render live streaming output with auto-scroll

        Args:
            lines: Output lines collected so far
            elapsed: Elapsed time in seconds

        Returns:
            Panel with streaming output and live status indicator
        """
        content = Text()

        # Status indicator with spinner and elapsed time
        elapsed_str = IOPanel._format_elapsed(elapsed)
        content.append(f"Running [⣾] {elapsed_str} elapsed\n", style="yellow bold")
        content.append("─" * 70 + "\n", style="dim")

        # Show last ~30 lines of output (terminal height aware)
        display_lines = lines[-30:] if len(lines) > 30 else lines

        for line in display_lines:
            # Preserve line content exactly as received
            content.append(line + "\n")

        # Separator
        content.append("\n" + "─" * 70 + "\n", style="dim")

        # Auto-scroll indicator
        content.append("[Auto-scrolling to bottom ↓]", style="cyan dim")

        return Panel(
            content,
            title="[bold yellow]Command Output [LIVE][/bold yellow]",
            border_style="yellow",
            box=box.ROUNDED
        )

    @staticmethod
    def render_complete(
        lines: List[str],
        exit_code: int,
        elapsed: float,
        findings: List[Dict]
    ) -> Panel:
        """Render complete output with results

        Args:
            lines: All output lines
            exit_code: Command exit code (0 = success)
            elapsed: Total execution time in seconds
            findings: List of auto-detected findings (dicts with 'type', 'description')

        Returns:
            Panel with complete output, exit code, and findings summary
        """
        content = Text()

        # Completion banner with color based on exit code
        success = exit_code == 0
        banner_style = "green bold" if success else "red bold"
        banner_icon = "✓" if success else "✗"

        content.append(f"{banner_icon} Stage Complete\n", style=banner_style)

        # Exit code and status
        status_text = "Success" if success else "Failed"
        status_style = "green" if success else "red"
        content.append(f"Exit Code: {exit_code} ({status_text})\n", style=status_style)

        # Execution time
        elapsed_str = IOPanel._format_elapsed(elapsed)
        content.append(f"Execution Time: {elapsed_str}\n", style="cyan")

        # Separator
        content.append("\n" + "─" * 70 + "\n", style="dim")

        # Last ~30 lines of output for context
        display_lines = lines[-30:] if len(lines) > 30 else lines

        for line in display_lines:
            content.append(line + "\n")

        # Separator
        content.append("\n" + "─" * 70 + "\n", style="dim")

        # Auto-detected findings section
        content.append("Auto-Detected Findings:\n", style="bold cyan")

        if findings:
            for finding in findings:
                finding_type = finding.get('type', 'unknown')
                description = finding.get('description', 'No description')
                content.append(f"  • {finding_type.title()}: {description}\n", style="green")
        else:
            content.append("  (No auto-detected findings)\n", style="dim")

        # Scroll indicator
        content.append("\n(Scroll ↑↓) | (e) Expand", style="cyan dim")

        # Border style based on success/failure
        border_style = "green" if success else "red"

        return Panel(
            content,
            title="[bold]Command Output [COMPLETE][/bold]",
            border_style=border_style,
            box=box.ROUNDED
        )
