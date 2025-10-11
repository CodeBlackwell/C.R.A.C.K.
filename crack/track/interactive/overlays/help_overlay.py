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
        'debug': {
            'title': 'Debug Tools (--debug mode only)',
            'shortcuts': ['D'],
            'icon': '🐛'
        },
        'danger': {
            'title': 'Dangerous Operations',
            'shortcuts': ['R'],
            'icon': '⚠️'
        }
    }

    @classmethod
    def render(cls, shortcut_handler=None, theme=None) -> Panel:
        """
        Render help overlay panel with dynamic shortcuts

        Args:
            shortcut_handler: ShortcutHandler instance (optional)
                             If provided, shortcuts are dynamically extracted
                             If None, falls back to static help text
            theme: ThemeManager instance (optional for backward compat)

        Returns:
            Rich Panel for overlay display
        """
        # Fallback theme for backward compatibility
        if theme is None:
            from ..themes import ThemeManager
            theme = ThemeManager()

        if shortcut_handler:
            # Dynamic generation from ShortcutHandler
            help_text = cls._build_dynamic_help(shortcut_handler.shortcuts, theme)
        else:
            # Fallback to static help text (backward compatibility)
            help_text = cls._build_static_help(theme)

        return Panel(
            help_text,
            title=f"[bold {theme.get_color('info')}]CRACK Track TUI - Help[/]",
            subtitle=theme.muted("For full documentation: track/docs/"),
            border_style=theme.overlay_border(),
            box=box.DOUBLE
        )

    @classmethod
    def _build_dynamic_help(cls, shortcuts: Dict[str, Tuple[str, str]], theme) -> str:
        """
        Build help text dynamically from shortcuts dictionary

        Args:
            shortcuts: Dict mapping shortcut keys to (description, handler) tuples
            theme: ThemeManager instance

        Returns:
            Formatted help text string

        Dynamic approach:
        - Shows ALL shortcuts from ShortcutHandler
        - Organizes known shortcuts by category
        - Auto-includes any uncategorized shortcuts
        - No shortcuts are hidden
        """
        from ..themes.helpers import format_hotkey

        hotkey_color = theme.get_component_color('hotkey')
        warning_color = theme.get_color('warning')
        danger_color = theme.get_color('danger')

        lines = [f"[bold {theme.get_color('primary')}]KEYBOARD SHORTCUTS[/]\n"]

        # Track which shortcuts have been shown
        shown_shortcuts = set()

        # Organize shortcuts by category (for known shortcuts)
        for category_key, category_info in cls.CATEGORIES.items():
            title = category_info['title']
            icon = category_info['icon']
            category_shortcuts = category_info['shortcuts']

            # Add category header
            lines.append(f"[bold {warning_color}]{icon} {title}:[/]")

            # Add shortcuts in this category
            for key in category_shortcuts:
                if key in shortcuts:
                    description, _ = shortcuts[key]
                    shown_shortcuts.add(key)

                    # Format with color based on key length
                    if len(key) == 1:
                        formatted_key = f"[{hotkey_color}]{key}[/]"
                    else:
                        formatted_key = f"[{hotkey_color}]:{key}[/]"

                    # Highlight dangerous operations
                    if category_key == 'danger':
                        lines.append(f"  {formatted_key} - [{danger_color}]{description}[/]")
                    else:
                        lines.append(f"  {formatted_key} - {description}")

            lines.append("")  # Blank line between categories

        # AUTO-INCLUDE any shortcuts not in categories (dynamic discovery)
        uncategorized = []
        for key, (description, _) in sorted(shortcuts.items()):
            if key not in shown_shortcuts:
                if len(key) == 1:
                    formatted_key = f"[{hotkey_color}]{key}[/]"
                else:
                    formatted_key = f"[{hotkey_color}]:{key}[/]"
                uncategorized.append(f"  {formatted_key} - {description}")

        if uncategorized:
            lines.append(f"[bold {warning_color}]📦 Other Commands:[/]")
            lines.extend(uncategorized)
            lines.append("")

        # Add TUI-specific shortcuts (not in ShortcutHandler)
        lines.append(f"[bold {warning_color}]🖥️  TUI-Specific Shortcuts:[/]")
        lines.append(f"  [{hotkey_color}]:[/] - Command mode (vim-style)")
        lines.append(f"  [{hotkey_color}]:!cmd[/] - Console injection (execute command)")
        lines.append(f"  [{hotkey_color}]o[/] - Output overlay (view task execution history)")
        lines.append(f"  [{hotkey_color}]p[/] - Progress dashboard (visual metrics)")
        lines.append(f"  [{hotkey_color}]1-9[/] - Select numbered menu option")
        lines.append("")

        # Add note about multi-character shortcuts
        lines.append(f"[bold {warning_color}]📝 Multi-Character Shortcuts:[/]")
        lines.append(f"  Multi-char shortcuts (ch, qn, pl, alt, etc.) must use [{hotkey_color}]:[/] command mode")
        lines.append(f"  Examples: [{hotkey_color}]:ch[/] [{hotkey_color}]:qn[/] [{hotkey_color}]:pl[/] [{hotkey_color}]:alt[/]")
        lines.append(f"  Single-char shortcuts work instantly: [{hotkey_color}]s[/] [{hotkey_color}]t[/] [{hotkey_color}]h[/] [{hotkey_color}]q[/]")
        lines.append("")

        # Add footer with total count
        total_shortcuts = len(shortcuts) + 5  # +5 for TUI-specific
        lines.append(theme.muted(f"Total: {total_shortcuts} commands available"))

        return "\n".join(lines)

    @classmethod
    def _build_static_help(cls, theme) -> str:
        """
        Build static help text (fallback for backward compatibility)

        Args:
            theme: ThemeManager instance

        Returns:
            Formatted help text string
        """
        hk = theme.get_component_color('hotkey')
        warn = theme.get_color('warning')

        help_text = f"""[bold {theme.get_color('primary')}]KEYBOARD SHORTCUTS[/]

[bold {warn}]Global Navigation:[/]
  [{hk}]h[/] - Show this help
  [{hk}]s[/] - Quick status overlay
  [{hk}]t[/] - Task tree overlay
  [{hk}]q[/] - Quit and save
  [{hk}]b[/] - Back to previous panel
  [{hk}]:[/] - Command mode (vim-style)

[bold {warn}]Dashboard - Letter Hotkeys:[/]
  [{hk}]n[/] - Execute [bold]N[/]ext recommended task
  [{hk}]l[/] - Browse all tasks ([bold]L[/]ist)
  [{hk}]f[/] - Browse [bold]F[/]indings
  [{hk}]w[/] - Quick [bold]W[/]ins (fast, high-value tasks)
  [{hk}]i[/] - [bold]I[/]mport scan results
  [{hk}]d[/] - [bold]D[/]ocument finding
  [{hk}]c[/] - [bold]C[/]redentials entry
  [{hk}]alt[/] - [bold]Alt[/]ernative commands (manual methods)

[bold {warn}]Dashboard - Number Keys:[/]
  [{hk}]1-9[/] - Select numbered menu option

[bold {warn}]Foundation Shortcuts (Stage 1):[/]
  [{hk}]pd[/] - Progress dashboard (visual metrics)
  [{hk}]ss[/] - Session snapshot (save/restore)
  [{hk}]tr[/] - Task retry (edit failed tasks)

[bold {warn}]Core Features (Stage 2):[/]
  [{hk}]qn[/] - Quick note (rapid note-taking)
  [{hk}]tf[/] - Task filter (multi-criteria search)
  [{hk}]ch[/] - Command history (searchable log)
  [{hk}]be[/] - Batch execute (multi-task run)

[bold {warn}]Enhanced Tools (Stage 3):[/]
  [{hk}]tt[/] - Time tracker (session timing)
  [{hk}]qx[/] - Quick export (findings/status)
  [{hk}]fc[/] - Finding correlator (attack chains)
  [{hk}]pl[/] - Port lookup (OSCP reference)
  [{hk}]qe[/] - Quick execute (one-off commands)

[bold {warn}]Task List Panel:[/]
  [{hk}]1-10[/] - Select task from list
  [{hk}]f[/] - Filter tasks (status, port, service, tags)
  [{hk}]s[/] - Sort tasks (priority, name, port, time)
  [{hk}]n[/] - Next page
  [{hk}]p[/] - Previous page
  [{hk}]b[/] - Back to dashboard

[bold {warn}]Findings Panel:[/]
  [{hk}]f[/] - Filter findings (type, port, service)
  [{hk}]e[/] - Export findings
  [{hk}]n[/] - Next page
  [{hk}]p[/] - Previous page
  [{hk}]b[/] - Back to dashboard

[bold {warn}]Task Workspace:[/]
  [{hk}]1[/] - Execute task
  [{hk}]2[/] - Save output
  [{hk}]3[/] - Add finding
  [{hk}]4[/] - Mark complete
  [{hk}]b[/] - Back to task list

[bold {warn}]Debug Logging:[/]
  Launch with [{hk}]--debug[/] for precision logging
  • Logs saved to [{hk}].debug_logs/[/] directory
  • [{hk}]--debug-categories=UI:VERBOSE[/] - Filter by category
  • [{hk}]--debug-output=both[/] - Stream to console too
  • Categories: UI, STATE, EXECUTION, PERFORMANCE
  • Levels: MINIMAL, NORMAL, VERBOSE, TRACE"""

        return help_text

    @classmethod
    def render_dashboard_help(cls, theme=None) -> Panel:
        """
        Render dashboard-specific help

        Args:
            theme: ThemeManager instance (optional for backward compat)

        Returns:
            Rich Panel with dashboard help
        """
        # Fallback theme for backward compatibility
        if theme is None:
            from ..themes import ThemeManager
            theme = ThemeManager()

        hk = theme.get_component_color('hotkey')
        warn = theme.get_color('warning')

        help_text = f"""[bold {theme.get_color('primary')}]DASHBOARD HELP[/]

[bold {warn}]Number Keys (Menu Selection):[/]
  [{hk}]1[/] - Execute next recommended task
  [{hk}]2[/] - Browse all tasks
  [{hk}]3[/] - Quick wins (fast, high-value tasks)
  [{hk}]4[/] - Import scan results
  [{hk}]5[/] - Document finding
  [{hk}]6[/] - Browse findings
  [{hk}]7[/] - Full status
  [{hk}]8[/] - Help
  [{hk}]9[/] - Exit

[bold {warn}]Letter Hotkeys (Direct Actions):[/]
  [{hk}]n[/] - Execute [bold]N[/]ext task (same as 1)
  [{hk}]l[/] - Browse task [bold]L[/]ist (same as 2)
  [{hk}]f[/] - Browse [bold]F[/]indings (same as 6)
  [{hk}]w[/] - Quick [bold]W[/]ins (same as 3)
  [{hk}]i[/] - [bold]I[/]mport scans (same as 4)
  [{hk}]d[/] - [bold]D[/]ocument finding (same as 5)

[bold {warn}]Global Shortcuts:[/]
  [{hk}]s[/] - Quick status overlay
  [{hk}]t[/] - Task tree overlay
  [{hk}]h[/] - Full help overlay
  [{hk}]q[/] - Quit with save prompt

[bold {warn}]Tips:[/]
  • Next recommended task is based on priority, phase, and dependencies
  • Quick wins (⚡) are fast, high-value tasks
  • OSCP HIGH priority (🎯) tasks are exam-critical
  • All findings require SOURCE field (OSCP requirement)

{theme.muted('Press any key to close')}"""

        return Panel(
            help_text,
            title=f"[bold {theme.get_color('info')}]Dashboard Help[/]",
            subtitle=theme.muted("Press 'h' for full help"),
            border_style=theme.overlay_border(),
            box=box.ROUNDED
        )
