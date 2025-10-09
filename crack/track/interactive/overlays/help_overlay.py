"""
Help Overlay - Keyboard shortcuts reference (h shortcut)

Shows:
- Navigation shortcuts
- Dashboard shortcuts
- Task workspace shortcuts (when Phase 4 implemented)
- Advanced shortcuts

Non-state-changing overlay - dismisses on keypress.
"""

from rich.panel import Panel
from rich import box


class HelpOverlay:
    """Help information overlay"""

    @classmethod
    def render(cls) -> Panel:
        """
        Render help overlay panel

        Returns:
            Rich Panel for overlay display
        """
        help_text = """[bold cyan]KEYBOARD SHORTCUTS[/]

[bold yellow]Navigation:[/]
  [cyan]h[/] - Show this help
  [cyan]s[/] - Quick status
  [cyan]t[/] - Task tree
  [cyan]q[/] - Quit and save
  [cyan]b[/] - Back to previous menu

[bold yellow]Dashboard:[/]
  [cyan]1-9[/] - Select menu option
  [cyan]n[/] - Execute next recommended task
  [cyan]r[/] - Refresh recommendations

[bold yellow]Task Management:[/]
  [cyan]alt[/] - Alternative commands (browse and execute)
  [cyan]tf[/] - Task filter (by status, port, service, tags)
  [cyan]tr[/] - Task retry (retry failed tasks)
  [cyan]be[/] - Batch execute (run multiple tasks)

[bold yellow]Quick Actions:[/]
  [cyan]qn[/] - Quick note (add note without forms)
  [cyan]qe[/] - Quick execute (run command without task)
  [cyan]qx[/] - Quick export (export to file/clipboard)

[bold yellow]Analysis Tools:[/]
  [cyan]fc[/] - Finding correlator (analyze findings)
  [cyan]sa[/] - Success analyzer (task optimization)
  [cyan]sg[/] - Smart suggest (pattern-based suggestions)

[bold yellow]Workflow Tools:[/]
  [cyan]ch[/] - Command history (browse and search)
  [cyan]wr[/] - Workflow recorder (record/replay)
  [cyan]ss[/] - Session snapshot (save/restore)
  [cyan]tt[/] - Time tracker (time management)
  [cyan]pd[/] - Progress dashboard (visual overview)

[bold yellow]Reference:[/]
  [cyan]pl[/] - Port lookup (common OSCP ports)
  [cyan]x[/] - Command templates (quick OSCP commands)
  [cyan]w[/] - Wordlist selector

[bold yellow]Special Commands:[/]
  [cyan]menu[/] - Return to main menu
  [cyan]back[/] - Go back
  [cyan]exit[/] - Exit interactive mode
  [cyan]!cmd[/] - Execute shell command

[dim]Press any key to close this help screen[/]"""

        return Panel(
            help_text,
            title="[bold blue]CRACK Track TUI - Help[/]",
            subtitle="[dim]For full documentation: track/docs/[/]",
            border_style="blue",
            box=box.DOUBLE
        )

    @classmethod
    def render_dashboard_help(cls) -> Panel:
        """
        Render dashboard-specific help

        Returns:
            Rich Panel with dashboard help
        """
        help_text = """[bold cyan]DASHBOARD HELP[/]

[bold yellow]Actions:[/]
  [cyan]1[/] - Execute next recommended task
  [cyan]2[/] - Browse all tasks
  [cyan]3[/] - Quick wins (fast, high-value tasks)
  [cyan]4[/] - Import scan results
  [cyan]5[/] - Document finding
  [cyan]6[/] - Browse findings
  [cyan]7[/] - Full status
  [cyan]8[/] - Help
  [cyan]9[/] - Exit

[bold yellow]Shortcuts:[/]
  [cyan]s[/] - Quick status overlay
  [cyan]t[/] - Task tree overlay
  [cyan]h[/] - Full help overlay
  [cyan]q[/] - Quit with save prompt

[bold yellow]Tips:[/]
  • Next recommended task is based on priority, phase, and dependencies
  • Quick wins (⚡) are fast, high-value tasks
  • OSCP HIGH priority (🎯) tasks are exam-critical
  • All findings require SOURCE field (OSCP requirement)

[dim]Press any key to close[/]"""

        return Panel(
            help_text,
            title="[bold blue]Dashboard Help[/]",
            subtitle="[dim]Press 'h' for full help[/]",
            border_style="blue",
            box=box.ROUNDED
        )
