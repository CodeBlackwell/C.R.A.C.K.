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
    def render(cls, profile, max_tasks: int = 20) -> Panel:
        """
        Render task tree overlay panel

        Args:
            profile: TargetProfile instance
            max_tasks: Maximum number of tasks to display

        Returns:
            Rich Panel for overlay display
        """
        # Get all tasks
        all_tasks = profile.task_tree.get_all_tasks()

        if not all_tasks:
            # Empty state
            tree_text = "[dim]No tasks yet.[/]\n\n"
            tree_text += "[cyan]Import a scan file to generate tasks automatically.[/]"

            return Panel(
                tree_text,
                title="[bold blue]Task Tree[/]",
                subtitle="[dim]Press any key to close[/]",
                border_style="blue",
                box=box.ROUNDED
            )

        # Build tree visualization
        tree_lines = []
        shown_tasks = all_tasks[:max_tasks]

        for task in shown_tasks:
            # Get status symbol and color
            symbol, color = cls._get_status_symbol(task.status)

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
            tree_lines.append(f"[dim]... and {remaining} more tasks[/]")

        tree_text = "\n".join(tree_lines)

        # Add legend
        legend = "\n\n[dim]Legend: [green]✓[/] Complete | [cyan]~[/] In-Progress | [yellow]•[/] Pending | [red]✗[/] Failed[/]"
        tree_text += legend

        # Progress summary
        progress = profile.get_progress()
        total = progress['total']
        completed = progress['completed']
        pct = int((completed / total * 100) if total > 0 else 0)

        subtitle = f"[dim]Showing {len(shown_tasks)}/{total} tasks | {completed} completed ({pct}%) | Press any key to close[/]"

        return Panel(
            tree_text,
            title="[bold blue]Task Tree[/]",
            subtitle=subtitle,
            border_style="blue",
            box=box.ROUNDED
        )

    @classmethod
    def _get_status_symbol(cls, status: str) -> tuple:
        """
        Get status symbol and color

        Args:
            status: Task status

        Returns:
            Tuple of (symbol, color)
        """
        status_map = {
            'completed': ('✓', 'green'),
            'in-progress': ('~', 'cyan'),
            'pending': ('•', 'yellow'),
            'failed': ('✗', 'red'),
            'blocked': ('⊗', 'red'),
            'skipped': ('○', 'dim')
        }

        return status_map.get(status, ('•', 'yellow'))

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
    def render_filtered(cls, profile, filter_status: str = None, max_tasks: int = 20) -> Panel:
        """
        Render filtered task tree

        Args:
            profile: TargetProfile instance
            filter_status: Status to filter by (completed, pending, etc.)
            max_tasks: Maximum tasks to display

        Returns:
            Rich Panel with filtered tree
        """
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
            symbol, color = cls._get_status_symbol(task.status)
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
            tree_text = f"[dim]No {filter_status} tasks found.[/]"
        else:
            tree_text = "\n".join(tree_lines)

            if len(tasks) > max_tasks:
                remaining = len(tasks) - max_tasks
                tree_text += f"\n\n[dim]... and {remaining} more[/]"

        # Title with filter
        filter_label = f" - {filter_status.title()}" if filter_status else ""
        title = f"[bold blue]Task Tree{filter_label}[/]"

        subtitle = f"[dim]Showing {len(shown_tasks)}/{len(tasks)} tasks | Press any key to close[/]"

        return Panel(
            tree_text,
            title=title,
            subtitle=subtitle,
            border_style="blue",
            box=box.ROUNDED
        )
