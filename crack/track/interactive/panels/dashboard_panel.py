"""
Dashboard Panel - Main hub for CRACK Track TUI

Central navigation hub with:
- Phase banner and progress
- Recommended task card (next high-value action)
- Numbered action menu (1-9)
- Context-aware options

Follows hub-and-spoke navigation model from TUI_ARCHITECTURE.md
"""

from typing import Dict, Any, Optional, Tuple, List
from rich.panel import Panel
from rich.table import Table
from rich import box


class DashboardPanel:
    """Dashboard rendering and menu generation"""

    @classmethod
    def render(cls, profile, recommendations: Dict[str, Any], theme=None) -> Tuple[Panel, List[Dict]]:
        """
        Render complete dashboard panel

        Args:
            profile: TargetProfile instance
            recommendations: Recommendations from RecommendationEngine
            theme: ThemeManager instance (optional for backward compat)

        Returns:
            Tuple of (Rich Panel, choices list for input processing)
        """
        # Fallback theme for backward compatibility
        if theme is None:
            from ..themes import ThemeManager
            theme = ThemeManager()
        # Get progress data
        progress = profile.get_progress()
        total = progress['total']
        completed = progress['completed']
        pct = int((completed / total * 100) if total > 0 else 0)

        # Build main table
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Section", style=theme.get_color('text'), width=80)

        # 1. Recommended Task Card (if available)
        next_task = recommendations.get('next')
        if next_task:
            table.add_row(cls._render_recommendation_card(next_task, theme))
            table.add_row("")  # Blank line

        # 2. Action Menu
        choices = cls._build_action_menu(profile, recommendations, table, theme)

        # Build panel with phase info
        phase_display = profile.phase.replace('-', ' ').title()
        title = f"[bold {theme.get_color('primary')}]T.R.A.C.K.[/] {theme.muted('Targeted Reconnaissance And Command Konsole')} | [{theme.get_color('text')}]{phase_display}[/]"
        subtitle = theme.muted(f"Progress: {completed}/{total} tasks ({pct}%) | Ports: {len(profile.ports)} | Findings: {len(profile.findings)}")

        return Panel(
            table,
            title=title,
            subtitle=subtitle,
            border_style=theme.panel_border(),
            box=box.ROUNDED
        ), choices

    @classmethod
    def _render_recommendation_card(cls, task, theme) -> str:
        """
        Render rich recommendation card for next task

        Args:
            task: TaskNode instance
            theme: ThemeManager instance

        Returns:
            Formatted card string
        """
        # Get task metadata
        tags = task.metadata.get('tags', [])
        time_est = task.metadata.get('time_estimate', 'Unknown')
        command = task.metadata.get('command') or ''  # Handle None case
        description = task.metadata.get('description', task.name)

        # Build tag badges using theme helpers
        from ..themes.helpers import format_priority_badge
        badges = []
        if 'QUICK_WIN' in tags:
            badges.append(format_priority_badge(theme, 'QUICK_WIN'))
        if 'OSCP:HIGH' in tags:
            badges.append(format_priority_badge(theme, 'OSCP:HIGH'))
        if 'OSCP:MEDIUM' in tags:
            badges.append(format_priority_badge(theme, 'OSCP:MEDIUM'))

        badge_str = ' '.join(badges) if badges else theme.muted('Standard Priority')

        # Truncate command for preview (first 70 chars)
        cmd_preview = command[:70] + '...' if len(command) > 70 else command

        # Build card
        card_lines = [
            theme.emphasis("🎯 NEXT RECOMMENDED TASK"),
            "┌─────────────────────────────────────────────────────────────────────────┐",
            f"│ [bold]{task.name}[/]",
            f"│ {theme.muted(description)}",
            f"│",
            f"│ {badge_str} | {theme.primary('Time:')} ~{time_est}",
        ]

        # Add command preview if available
        if cmd_preview:
            cmd_color = theme.get_component_color('command')
            card_lines.append(f"│ {theme.muted('Command:')} [{cmd_color}]{cmd_preview}[/]")

        card_lines.append("└─────────────────────────────────────────────────────────────────────────┘")

        return "\n".join(card_lines)

    @classmethod
    def _build_action_menu(cls, profile, recommendations: Dict[str, Any], table: Table, theme) -> List[Dict]:
        """
        Build action menu and add to table

        Args:
            profile: TargetProfile instance
            recommendations: Recommendations dict
            table: Table to add rows to
            theme: ThemeManager instance

        Returns:
            List of choice dictionaries for input processing
        """
        from ..themes.helpers import format_menu_number

        choices = []
        menu_num = 1

        # Get recommendation data
        next_task = recommendations.get('next')
        quick_wins = recommendations.get('quick_wins', [])
        all_pending = profile.task_tree.get_all_pending()

        # 1. Execute next task (if available)
        if next_task:
            table.add_row(f"{format_menu_number(theme, menu_num)} Execute next recommended task")
            choices.append({
                'id': 'next',
                'label': 'Execute next recommended task',
                'task': next_task
            })
            menu_num += 1

        # 2. Browse all tasks
        task_count = len(all_pending)
        table.add_row(f"{format_menu_number(theme, menu_num)} Browse all tasks {theme.muted(f'({task_count} available)')}")
        choices.append({
            'id': 'browse-tasks',
            'label': f'Browse all tasks ({task_count} available)'
        })
        menu_num += 1

        # 3. Quick wins (if available)
        if quick_wins:
            qw_count = len(quick_wins)
            table.add_row(f"{format_menu_number(theme, menu_num)} Quick wins ⚡ {theme.muted(f'({qw_count} available)')}")
            choices.append({
                'id': 'quick-wins',
                'label': f'Quick wins ({qw_count} available)'
            })
            menu_num += 1

        # 4. Import scan results
        table.add_row(f"{format_menu_number(theme, menu_num)} Import scan results")
        choices.append({
            'id': 'import',
            'label': 'Import scan results'
        })
        menu_num += 1

        # 5. Document finding
        table.add_row(f"{format_menu_number(theme, menu_num)} Document finding")
        choices.append({
            'id': 'finding',
            'label': 'Document finding'
        })
        menu_num += 1

        # 6. Browse findings
        finding_count = len(profile.findings)
        table.add_row(f"{format_menu_number(theme, menu_num)} Browse findings {theme.muted(f'({finding_count} total)')}")
        choices.append({
            'id': 'browse-findings',
            'label': f'Browse findings ({finding_count} total)'
        })
        menu_num += 1

        # 7. Full status
        table.add_row(f"{format_menu_number(theme, menu_num)} Full status")
        choices.append({
            'id': 'show-status',
            'label': 'Full status'
        })
        menu_num += 1

        # 8. Help
        table.add_row(f"{format_menu_number(theme, menu_num)} Help")
        choices.append({
            'id': 'help',
            'label': 'Help'
        })
        menu_num += 1

        # 9. Exit
        table.add_row(f"{format_menu_number(theme, menu_num)} Exit")
        choices.append({
            'id': 'exit',
            'label': 'Exit'
        })

        return choices

    @classmethod
    def render_empty_state(cls, profile, theme=None) -> Tuple[Panel, List[Dict]]:
        """
        Render dashboard when no tasks are available

        Args:
            profile: TargetProfile instance
            theme: ThemeManager instance (optional for backward compat)

        Returns:
            Tuple of (Rich Panel, choices list)
        """
        # Fallback theme for backward compatibility
        if theme is None:
            from ..themes import ThemeManager
            theme = ThemeManager()

        from ..themes.helpers import format_menu_number

        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Section", style=theme.get_color('text'), width=80)

        # Empty state message
        table.add_row(f"[bold {theme.get_color('warning')}]👋 Welcome to CRACK Track TUI![/]")
        table.add_row("")
        table.add_row(theme.muted("No tasks available yet. Import a scan file to get started."))
        table.add_row("")

        # Basic menu
        choices = [
            {'id': 'import', 'label': 'Import scan results'},
            {'id': 'help', 'label': 'Help'},
            {'id': 'exit', 'label': 'Exit'}
        ]

        for i, choice in enumerate(choices, 1):
            table.add_row(f"{format_menu_number(theme, i)} {choice['label']}")

        phase_display = profile.phase.replace('-', ' ').title()
        title = f"[bold {theme.get_color('primary')}]T.R.A.C.K.[/] {theme.muted('Targeted Reconnaissance And Command Konsole')} | [{theme.get_color('text')}]{phase_display}[/]"
        subtitle = theme.muted(f"Target: {profile.target} | No tasks yet - import scan to begin")

        return Panel(
            table,
            title=title,
            subtitle=subtitle,
            border_style=theme.panel_border(),
            box=box.ROUNDED
        ), choices
