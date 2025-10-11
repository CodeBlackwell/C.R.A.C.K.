"""
Tree Overlay - Task tree visualization (t shortcut)

Shows:
- Hierarchical task tree
- Status indicators (✓ complete, ~ in-progress, • pending, ✗ failed)
- Color coding (green/cyan/yellow/red/dim)
- First 20 tasks (with pagination support)

Non-state-changing overlay - dismisses on keypress.
"""

from typing import List
from rich.panel import Panel
from rich.tree import Tree
from rich import box


class TreeOverlay:
    """Task tree visualization overlay"""

    @classmethod
    def render(cls, profile, max_tasks: int = 20, theme=None) -> Panel:
        """
        Render task tree overlay panel

        Args:
            profile: TargetProfile instance
            max_tasks: Maximum number of tasks to display
            theme: ThemeManager instance (optional for backward compat)

        Returns:
            Rich Panel for overlay display
        """
        # Fallback theme for backward compatibility
        if theme is None:
            from ..themes import ThemeManager
            theme = ThemeManager()

        # Get all tasks
        all_tasks = profile.task_tree.get_all_tasks()

        if not all_tasks:
            # Empty state
            tree_text = theme.muted("No tasks yet.") + "\n\n"
            tree_text += theme.primary("Import a scan file to generate tasks automatically.")

            return Panel(
                tree_text,
                title=f"[bold {theme.get_color('info')}]Task Tree[/]",
                subtitle=theme.muted("Press any key to close"),
                border_style=theme.overlay_border(),
                box=box.ROUNDED
            )

        # Build tree visualization
        tree_lines = []
        shown_tasks = all_tasks[:max_tasks]

        for task in shown_tasks:
            # Get status symbol and color
            symbol, color = cls._get_status_symbol(task.status, theme)

            # Get task info
            name = task.name
            tags = task.metadata.get('tags', [])

            # Add tag badges
            badges = []
            if 'QUICK_WIN' in tags:
                badges.append('⚡')
            if 'OSCP:HIGH' in tags:
                badges.append('🎯')

            badge_str = ''.join(badges)

            # Build line
            indent = cls._get_indent_level(task)
            indent_str = "  " * indent

            line = f"{indent_str}[{color}]{symbol}[/] {name}"
            if badge_str:
                line += f" {badge_str}"

            tree_lines.append(line)

        # Add "more tasks" indicator
        if len(all_tasks) > max_tasks:
            remaining = len(all_tasks) - max_tasks
            tree_lines.append("")
            tree_lines.append(theme.muted(f"... and {remaining} more tasks"))

        tree_text = "\n".join(tree_lines)

        # Add legend with themed colors
        legend = "\n\n" + theme.muted("Legend: ")
        legend += f"[{theme.task_state_color('completed')}]✓[/] Complete | "
        legend += f"[{theme.task_state_color('in-progress')}]~[/] In-Progress | "
        legend += f"[{theme.task_state_color('pending')}]•[/] Pending | "
        legend += f"[{theme.task_state_color('failed')}]✗[/] Failed"
        tree_text += legend

        # Progress summary
        progress = profile.get_progress()
        total = progress['total']
        completed = progress['completed']
        pct = int((completed / total * 100) if total > 0 else 0)

        subtitle = theme.muted(f"Showing {len(shown_tasks)}/{total} tasks | {completed} completed ({pct}%) | Press any key to close")

        return Panel(
            tree_text,
            title=f"[bold {theme.get_color('info')}]Task Tree[/]",
            subtitle=subtitle,
            border_style=theme.overlay_border(),
            box=box.ROUNDED
        )

    @classmethod
    def _get_status_symbol(cls, status: str, theme) -> tuple:
        """
        Get status symbol and color

        Args:
            status: Task status
            theme: ThemeManager instance

        Returns:
            Tuple of (symbol, color)
        """
        symbol_map = {
            'completed': '✓',
            'in-progress': '~',
            'pending': '•',
            'failed': '✗',
            'blocked': '⊗',
            'skipped': '○'
        }

        symbol = symbol_map.get(status, '•')
        color = theme.task_state_color(status)

        return (symbol, color)

    @classmethod
    def _get_indent_level(cls, task) -> int:
        """
        Calculate indent level for hierarchical display

        Args:
            task: TaskNode instance

        Returns:
            Indent level (0 = root level)
        """
        # Count parent nodes to determine depth
        level = 0
        current = task

        while hasattr(current, 'parent') and current.parent is not None:
            level += 1
            current = current.parent

        return level

    @classmethod
    def render_filtered(cls, profile, filter_status: str = None, max_tasks: int = 20, theme=None) -> Panel:
        """
        Render filtered task tree

        Args:
            profile: TargetProfile instance
            filter_status: Status to filter by (completed, pending, etc.)
            max_tasks: Maximum tasks to display
            theme: ThemeManager instance (optional for backward compat)

        Returns:
            Rich Panel with filtered tree
        """
        # Fallback theme for backward compatibility
        if theme is None:
            from ..themes import ThemeManager
            theme = ThemeManager()
        # Get filtered tasks
        if filter_status == 'completed':
            tasks = profile.task_tree.get_completed_tasks()
        elif filter_status == 'pending':
            tasks = profile.task_tree.get_all_pending()
        elif filter_status == 'in-progress':
            # Get tasks with in-progress status
            all_tasks = profile.task_tree.get_all_tasks()
            tasks = [t for t in all_tasks if t.status == 'in-progress']
        else:
            tasks = profile.task_tree.get_all_tasks()

        # Build tree lines
        tree_lines = []
        shown_tasks = tasks[:max_tasks]

        for task in shown_tasks:
            symbol, color = cls._get_status_symbol(task.status, theme)
            name = task.name

            # Add tags
            tags = task.metadata.get('tags', [])
            badges = []
            if 'QUICK_WIN' in tags:
                badges.append('⚡')
            if 'OSCP:HIGH' in tags:
                badges.append('🎯')

            badge_str = ''.join(badges)

            indent = cls._get_indent_level(task)
            indent_str = "  " * indent

            line = f"{indent_str}[{color}]{symbol}[/] {name}"
            if badge_str:
                line += f" {badge_str}"

            tree_lines.append(line)

        if not tree_lines:
            tree_text = theme.muted(f"No {filter_status} tasks found.")
        else:
            tree_text = "\n".join(tree_lines)

            if len(tasks) > max_tasks:
                remaining = len(tasks) - max_tasks
                tree_text += "\n\n" + theme.muted(f"... and {remaining} more")

        # Title with filter
        filter_label = f" - {filter_status.title()}" if filter_status else ""
        title = f"[bold {theme.get_color('info')}]Task Tree{filter_label}[/]"

        subtitle = theme.muted(f"Showing {len(shown_tasks)}/{len(tasks)} tasks | Press any key to close")

        return Panel(
            tree_text,
            title=title,
            subtitle=subtitle,
            border_style=theme.overlay_border(),
            box=box.ROUNDED
        )
