"""
TUI Panel Renderers - Convert data to Rich panels

Renders each panel component:
- Header: Title + target
- Context: Target info, progress, stats
- Tree: Task checklist with status
- Menu: Numbered action choices
- Output: Command execution output
- Footer: Keyboard shortcuts
"""

from typing import List, Dict, Any, Optional
from datetime import datetime

from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.console import Group
from rich import box

from crack.utils.colors import Colors


class TUIPanels:
    """Render TUI panels with Rich"""

    # Status symbols
    SYMBOLS = {
        'pending': '[ ]',
        'in_progress': '[~]',
        'completed': '[✓]',
        'skipped': '[✗]',
        'failed': '[✗]'
    }

    @classmethod
    def render_header(cls, target: str, phase: str = None) -> Panel:
        """
        Render header panel with title + key info

        Args:
            target: Target IP/hostname
            phase: Current enumeration phase

        Returns:
            Rich Panel
        """
        title = "[bold cyan]CRACK Track - Interactive Mode (TUI)[/]"
        if target:
            title += f" | [bold white]Target:[/] {target}"
        if phase:
            title += f" | [bold white]Phase:[/] {phase.replace('-', ' ').title()}"

        return Panel(
            title,
            border_style="cyan",
            box=box.HEAVY
        )

    @classmethod
    def render_context(cls, profile) -> Panel:
        """
        Render context panel with target info and stats

        Args:
            profile: TargetProfile instance

        Returns:
            Rich Panel
        """
        lines = []

        # Target and phase
        lines.append(f"[bold cyan]Target:[/] [white]{profile.target}[/]")
        lines.append(f"[bold cyan]Phase:[/] [white]{profile.phase.replace('-', ' ').title()}[/]")

        # Progress
        progress = profile.get_progress()
        total = progress['total']
        completed = progress['completed']
        pct = (completed / total * 100) if total > 0 else 0
        lines.append(f"[bold cyan]Progress:[/] [bright_green]{completed}/{total}[/] [dim]({pct:.0f}%)[/]")

        # Time elapsed
        try:
            created = datetime.fromisoformat(profile.created)
            elapsed = datetime.now() - created
            hours = int(elapsed.total_seconds() // 3600)
            minutes = int((elapsed.total_seconds() % 3600) // 60)
            time_str = f"{hours:02d}:{minutes:02d}:00"
            lines.append(f"[bold cyan]Time:[/] [white]{time_str}[/]")
        except:
            lines.append(f"[bold cyan]Time:[/] [white]--:--:--[/]")

        # Ports discovered
        port_count = len(profile.ports) if profile.ports else 0
        lines.append(f"[bold cyan]Ports:[/] [bright_yellow]{port_count}[/]")

        # Findings
        finding_count = len(profile.findings) if profile.findings else 0
        lines.append(f"[bold cyan]Findings:[/] [bright_magenta]{finding_count}[/]")

        # Credentials
        cred_count = len(profile.credentials) if profile.credentials else 0
        lines.append(f"[bold cyan]Creds:[/] [bright_red]{cred_count}[/]")

        content = "\n".join(lines)

        return Panel(
            content,
            title="[bold]Context[/]",
            border_style="green",
            box=box.ROUNDED
        )

    @classmethod
    def render_task_tree(cls, profile) -> Panel:
        """
        Render task tree panel with task status

        Args:
            profile: TargetProfile instance

        Returns:
            Rich Panel
        """
        lines = []

        # Get tasks
        all_tasks = profile.task_tree.get_all_tasks()

        if not all_tasks:
            lines.append("[dim]No tasks yet[/]")
        else:
            # Count by status
            pending = sum(1 for t in all_tasks if t.status == 'pending')
            in_progress = sum(1 for t in all_tasks if t.status == 'in-progress')
            completed = sum(1 for t in all_tasks if t.status == 'completed')

            lines.append(f"[bright_green]✓ {completed}[/] completed")
            lines.append(f"[bright_cyan]~ {in_progress}[/] in progress")
            lines.append(f"[bright_yellow]• {pending}[/] pending")
            lines.append("")

            # Show recent/active tasks (max 10)
            recent_tasks = []

            # First add in-progress tasks
            for task in all_tasks:
                if task.status == 'in-progress':
                    recent_tasks.append(task)

            # Then add pending tasks
            for task in all_tasks:
                if task.status == 'pending' and len(recent_tasks) < 10:
                    recent_tasks.append(task)

            # Then add recent completed tasks
            for task in reversed(all_tasks):
                if task.status == 'completed' and len(recent_tasks) < 10:
                    recent_tasks.append(task)
                if len(recent_tasks) >= 10:
                    break

            # Render tasks
            for task in recent_tasks[:8]:  # Show max 8 in panel
                symbol = cls.SYMBOLS.get(task.status, '[ ]')

                # Color based on status
                if task.status == 'completed':
                    line = f"[bright_green]{symbol}[/] [dim]{task.name[:30]}[/]"
                elif task.status == 'in-progress':
                    line = f"[bright_cyan]{symbol}[/] [bold]{task.name[:30]}[/]"
                elif task.status == 'pending':
                    line = f"[bright_yellow]{symbol}[/] {task.name[:30]}"
                else:
                    line = f"[dim]{symbol} {task.name[:30]}[/]"

                lines.append(line)

            if len(recent_tasks) > 8:
                lines.append(f"[dim]...and {len(recent_tasks) - 8} more[/]")

        content = "\n".join(lines)

        return Panel(
            content,
            title="[bold]Task Tree[/]",
            border_style="blue",
            box=box.ROUNDED
        )

    @classmethod
    def render_menu(cls, choices: List[Dict[str, Any]], title: str = "Actions") -> Panel:
        """
        Render main menu panel with numbered choices

        Args:
            choices: List of choice dicts with 'label' and 'description'
            title: Panel title

        Returns:
            Rich Panel
        """
        lines = []

        for i, choice in enumerate(choices, 1):
            label = choice.get('label', choice.get('name', str(choice.get('id'))))
            description = choice.get('description', '')

            # Numbered menu item
            line = f"[bold bright_white]{i}.[/] {label}"
            lines.append(line)

            # Description (indented, dimmed)
            if description:
                # Truncate long descriptions
                if len(description) > 50:
                    description = description[:47] + "..."
                lines.append(f"   [dim cyan]→ {description}[/]")

        content = "\n".join(lines)

        return Panel(
            content,
            title=f"[bold]{title}[/]",
            border_style="magenta",
            box=box.ROUNDED
        )

    @classmethod
    def render_output(cls, lines: List[str], max_lines: int = 20) -> Panel:
        """
        Render command output panel (scrollable)

        Args:
            lines: Output lines to display
            max_lines: Maximum lines to show (scrolls)

        Returns:
            Rich Panel
        """
        if not lines:
            content = "[dim]No output yet. Execute a command to see results.[/]"
        else:
            # Show last N lines (scrolling effect)
            visible_lines = lines[-max_lines:] if len(lines) > max_lines else lines
            content = "\n".join(visible_lines)

            # Add scroll indicator if truncated
            if len(lines) > max_lines:
                content = f"[dim]...({len(lines) - max_lines} more lines above)[/]\n" + content

        return Panel(
            content,
            title="[bold]Command Output[/]",
            border_style="yellow",
            box=box.ROUNDED
        )

    @classmethod
    def render_footer(cls, shortcuts: List[tuple] = None, debug_mode: bool = False) -> Panel:
        """
        Render footer panel with essential keyboard shortcuts

        Args:
            shortcuts: List of (key, description) tuples
            debug_mode: Whether debug mode is enabled

        Returns:
            Rich Panel
        """
        if shortcuts is None:
            shortcuts = [
                ('s', 'Status'),
                ('t', 'Tree'),
                ('n', 'Next'),
                ('h', 'Help'),
                ('q', 'Quit')
            ]

        # Format shortcuts
        formatted = []
        for key, desc in shortcuts:
            formatted.append(f"[bold cyan]({key})[/] {desc}")

        content = " | ".join(formatted) + " | [dim]Press [bold](h)[/] for full shortcuts[/]"

        # Add debug indicator if enabled
        if debug_mode:
            content += " | [bold yellow]🐛 DEBUG MODE[/]"

        return Panel(
            content,
            border_style="cyan",
            box=box.HEAVY
        )

    @classmethod
    def render_help(cls) -> Panel:
        """
        Render comprehensive help panel with ALL shortcuts

        Returns:
            Rich Panel
        """
        help_text = """[bold cyan]KEYBOARD SHORTCUTS:[/]

[bold yellow]Core Navigation[/]
  [cyan]s[/] - Show full status and task tree
  [cyan]t[/] - Show task tree only
  [cyan]r[/] - Show recommendations
  [cyan]b[/] - Go back to previous menu
  [cyan]h[/] - Toggle this help panel
  [cyan]D[/] - [bold yellow]Toggle debug mode[/] (shows detailed execution flow)
  [cyan]R[/] - [bold red]Reset session[/] (WARNING: deletes ALL data, requires confirmation)
  [cyan]q[/] - Quit and save session

[bold yellow]Task Actions[/]
  [cyan]n[/] - Execute next recommended task
  [cyan]c[/] - Change confirmation mode
  [cyan]x[/] - Command templates (quick OSCP commands)

[bold yellow]Data Entry[/]
  [cyan]qn[/] - Quick note (add note without forms)
  [cyan]w[/] - Select wordlist (for gobuster, hydra, etc.)

[bold yellow]Alternative Commands[/]
  [cyan]alt[/] - Alternative commands (browse and execute)

[bold yellow]Analysis & Search[/]
  [cyan]ch[/] - Command history (browse and search)
  [cyan]pl[/] - Port lookup reference (common OSCP ports)
  [cyan]tf[/] - Task filter (filter by status, port, service)
  [cyan]fc[/] - Finding correlator (analyze findings)
  [cyan]sg[/] - Smart suggest (pattern-based suggestions)
  [cyan]sa[/] - Success analyzer (task success rates)

[bold yellow]Workflow Management[/]
  [cyan]tt[/] - Time tracker dashboard
  [cyan]pd[/] - Progress dashboard (visual overview)
  [cyan]ss[/] - Session snapshot (save/restore checkpoints)
  [cyan]wr[/] - Workflow recorder (record/replay sequences)

[bold yellow]Execution Tools[/]
  [cyan]qe[/] - Quick execute (run commands without tasks)
  [cyan]tr[/] - Task retry (retry failed tasks with editing)
  [cyan]be[/] - Batch execute (multiple tasks with dependencies)

[bold yellow]Export & Documentation[/]
  [cyan]qx[/] - Quick export (export view to file/clipboard)

[dim]Press any key or [bold]h[/] again to close help[/]"""

        return Panel(
            help_text,
            title="[bold white on blue] CRACK Track - Keyboard Shortcuts Reference [/]",
            border_style="blue",
            box=box.DOUBLE
        )
