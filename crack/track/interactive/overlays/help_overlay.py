"""
Help Overlay - Keyboard shortcuts reference (h shortcut)

Shows:
- Navigation shortcuts
- Dashboard shortcuts
- Task workspace shortcuts (when Phase 4 implemented)
- Advanced shortcuts

Non-state-changing overlay - dismisses on keypress.

DYNAMIC GENERATION:
- Shortcuts extracted from ShortcutHandler.shortcuts at runtime
- Single source of truth - no hardcoded duplicates
- Auto-updates when shortcuts are added/removed
"""

from typing import Optional, Dict, Tuple
from rich.panel import Panel
from rich import box


class HelpOverlay:
    """Help information overlay"""

    # Category definitions for organizing shortcuts
    CATEGORIES = {
        'navigation': {
            'title': 'Navigation & Views',
            'shortcuts': ['s', 't', 'r', 'h', 'b', 'q'],
            'icon': '🧭'
        },
        'tasks': {
            'title': 'Task Actions',
            'shortcuts': ['n', 'x', 'tf', 'tr', 'be'],
            'icon': '⚡'
        },
        'quick': {
            'title': 'Quick Tools',
            'shortcuts': ['qn', 'qe', 'qx'],
            'icon': '🚀'
        },
        'analysis': {
            'title': 'Analysis & Tracking',
            'shortcuts': ['ch', 'pl', 'tt', 'pd', 'fc', 'sa', 'sg'],
            'icon': '📊'
        },
        'session': {
            'title': 'Session Management',
            'shortcuts': ['ss', 'c', 'w', 'alt', 'wr'],
            'icon': '⚙️'
        },
        'danger': {
            'title': 'Dangerous Operations',
            'shortcuts': ['R'],
            'icon': '⚠️'
        }
    }

    @classmethod
    def render(cls, shortcut_handler=None) -> Panel:
        """
        Render help overlay panel with dynamic shortcuts

        Args:
            shortcut_handler: ShortcutHandler instance (optional)
                             If provided, shortcuts are dynamically extracted
                             If None, falls back to static help text

        Returns:
            Rich Panel for overlay display
        """
        if shortcut_handler:
            # Dynamic generation from ShortcutHandler
            help_text = cls._build_dynamic_help(shortcut_handler.shortcuts)
        else:
            # Fallback to static help text (backward compatibility)
            help_text = cls._build_static_help()

        return Panel(
            help_text,
            title="[bold blue]CRACK Track TUI - Help[/]",
            subtitle="[dim]For full documentation: track/docs/[/]",
            border_style="blue",
            box=box.DOUBLE
        )

    @classmethod
    def _build_dynamic_help(cls, shortcuts: Dict[str, Tuple[str, str]]) -> str:
        """
        Build help text dynamically from shortcuts dictionary

        Args:
            shortcuts: Dict mapping shortcut keys to (description, handler) tuples

        Returns:
            Formatted help text string

        Dynamic approach:
        - Shows ALL shortcuts from ShortcutHandler
        - Organizes known shortcuts by category
        - Auto-includes any uncategorized shortcuts
        - No shortcuts are hidden
        """
        lines = ["[bold cyan]KEYBOARD SHORTCUTS[/]\n"]

        # Track which shortcuts have been shown
        shown_shortcuts = set()

        # Organize shortcuts by category (for known shortcuts)
        for category_key, category_info in cls.CATEGORIES.items():
            title = category_info['title']
            icon = category_info['icon']
            category_shortcuts = category_info['shortcuts']

            # Add category header
            lines.append(f"[bold yellow]{icon} {title}:[/]")

            # Add shortcuts in this category
            for key in category_shortcuts:
                if key in shortcuts:
                    description, _ = shortcuts[key]
                    shown_shortcuts.add(key)

                    # Format with color based on key length
                    if len(key) == 1:
                        formatted_key = f"[cyan]{key}[/]"
                    else:
                        formatted_key = f"[cyan]:{key}[/]"

                    # Highlight dangerous operations
                    if category_key == 'danger':
                        lines.append(f"  {formatted_key} - [red]{description}[/]")
                    else:
                        lines.append(f"  {formatted_key} - {description}")

            lines.append("")  # Blank line between categories

        # AUTO-INCLUDE any shortcuts not in categories (dynamic discovery)
        uncategorized = []
        for key, (description, _) in sorted(shortcuts.items()):
            if key not in shown_shortcuts:
                if len(key) == 1:
                    formatted_key = f"[cyan]{key}[/]"
                else:
                    formatted_key = f"[cyan]:{key}[/]"
                uncategorized.append(f"  {formatted_key} - {description}")

        if uncategorized:
            lines.append("[bold yellow]📦 Other Commands:[/]")
            lines.extend(uncategorized)
            lines.append("")

        # Add TUI-specific shortcuts (not in ShortcutHandler)
        lines.append("[bold yellow]🖥️  TUI-Specific Shortcuts:[/]")
        lines.append("  [cyan]:[/] - Command mode (vim-style)")
        lines.append("  [cyan]:!cmd[/] - Console injection (execute command)")
        lines.append("  [cyan]o[/] - Output overlay (view task execution history)")
        lines.append("  [cyan]p[/] - Progress dashboard (visual metrics)")
        lines.append("  [cyan]1-9[/] - Select numbered menu option")
        lines.append("")

        # Add note about multi-character shortcuts
        lines.append("[bold yellow]📝 Multi-Character Shortcuts:[/]")
        lines.append("  Multi-char shortcuts (ch, qn, pl, alt, etc.) must use [cyan]:[/] command mode")
        lines.append("  Examples: [cyan]:ch[/] [cyan]:qn[/] [cyan]:pl[/] [cyan]:alt[/]")
        lines.append("  Single-char shortcuts work instantly: [cyan]s[/] [cyan]t[/] [cyan]h[/] [cyan]q[/]")
        lines.append("")

        # Add footer with total count
        total_shortcuts = len(shortcuts) + 5  # +5 for TUI-specific
        lines.append(f"[dim]Total: {total_shortcuts} commands available[/]")

        return "\n".join(lines)

    @classmethod
    def _build_static_help(cls) -> str:
        """
        Build static help text (fallback for backward compatibility)

        Returns:
            Formatted help text string
        """
        help_text = """[bold cyan]KEYBOARD SHORTCUTS[/]

[bold yellow]Global Navigation:[/]
  [cyan]h[/] - Show this help
  [cyan]s[/] - Quick status overlay
  [cyan]t[/] - Task tree overlay
  [cyan]q[/] - Quit and save
  [cyan]b[/] - Back to previous panel
  [cyan]:[/] - Command mode (vim-style)

[bold yellow]Dashboard - Letter Hotkeys:[/]
  [cyan]n[/] - Execute [bold]N[/]ext recommended task
  [cyan]l[/] - Browse all tasks ([bold]L[/]ist)
  [cyan]f[/] - Browse [bold]F[/]indings
  [cyan]w[/] - Quick [bold]W[/]ins (fast, high-value tasks)
  [cyan]i[/] - [bold]I[/]mport scan results
  [cyan]d[/] - [bold]D[/]ocument finding
  [cyan]c[/] - [bold]C[/]redentials entry
  [cyan]alt[/] - [bold]Alt[/]ernative commands (manual methods)

[bold yellow]Dashboard - Number Keys:[/]
  [cyan]1-9[/] - Select numbered menu option

[bold yellow]Foundation Shortcuts (Stage 1):[/]
  [cyan]pd[/] - Progress dashboard (visual metrics)
  [cyan]ss[/] - Session snapshot (save/restore)
  [cyan]tr[/] - Task retry (edit failed tasks)

[bold yellow]Core Features (Stage 2):[/]
  [cyan]qn[/] - Quick note (rapid note-taking)
  [cyan]tf[/] - Task filter (multi-criteria search)
  [cyan]ch[/] - Command history (searchable log)
  [cyan]be[/] - Batch execute (multi-task run)

[bold yellow]Enhanced Tools (Stage 3):[/]
  [cyan]tt[/] - Time tracker (session timing)
  [cyan]qx[/] - Quick export (findings/status)
  [cyan]fc[/] - Finding correlator (attack chains)
  [cyan]pl[/] - Port lookup (OSCP reference)
  [cyan]qe[/] - Quick execute (one-off commands)

[bold yellow]Task List Panel:[/]
  [cyan]1-10[/] - Select task from list
  [cyan]f[/] - Filter tasks (status, port, service, tags)
  [cyan]s[/] - Sort tasks (priority, name, port, time)
  [cyan]n[/] - Next page
  [cyan]p[/] - Previous page
  [cyan]b[/] - Back to dashboard

[bold yellow]Findings Panel:[/]
  [cyan]f[/] - Filter findings (type, port, service)
  [cyan]e[/] - Export findings
  [cyan]n[/] - Next page
  [cyan]p[/] - Previous page
  [cyan]b[/] - Back to dashboard

[bold yellow]Task Workspace:[/]
  [cyan]1[/] - Execute task
  [cyan]2[/] - Save output
  [cyan]3[/] - Add finding
  [cyan]4[/] - Mark complete
  [cyan]b[/] - Back to task list

[bold yellow]Debug Logging:[/]
  Launch with [cyan]--debug[/] for precision logging
  • Logs saved to [cyan].debug_logs/[/] directory
  • [cyan]--debug-categories=UI:VERBOSE[/] - Filter by category
  • [cyan]--debug-output=both[/] - Stream to console too
  • Categories: UI, STATE, EXECUTION, PERFORMANCE
  • Levels: MINIMAL, NORMAL, VERBOSE, TRACE"""

        return help_text

    @classmethod
    def render_dashboard_help(cls) -> Panel:
        """
        Render dashboard-specific help

        Returns:
            Rich Panel with dashboard help
        """
        help_text = """[bold cyan]DASHBOARD HELP[/]

[bold yellow]Number Keys (Menu Selection):[/]
  [cyan]1[/] - Execute next recommended task
  [cyan]2[/] - Browse all tasks
  [cyan]3[/] - Quick wins (fast, high-value tasks)
  [cyan]4[/] - Import scan results
  [cyan]5[/] - Document finding
  [cyan]6[/] - Browse findings
  [cyan]7[/] - Full status
  [cyan]8[/] - Help
  [cyan]9[/] - Exit

[bold yellow]Letter Hotkeys (Direct Actions):[/]
  [cyan]n[/] - Execute [bold]N[/]ext task (same as 1)
  [cyan]l[/] - Browse task [bold]L[/]ist (same as 2)
  [cyan]f[/] - Browse [bold]F[/]indings (same as 6)
  [cyan]w[/] - Quick [bold]W[/]ins (same as 3)
  [cyan]i[/] - [bold]I[/]mport scans (same as 4)
  [cyan]d[/] - [bold]D[/]ocument finding (same as 5)

[bold yellow]Global Shortcuts:[/]
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
