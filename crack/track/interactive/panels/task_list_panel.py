"""
Task List Panel - Browse and filter all tasks

Features:
- Filterable task table (status, port, service, priority, tags)
- Sortable columns (priority, name, port, time_estimate)
- Pagination (10 tasks per page)
- Selection for workspace navigation
- Multi-stage task indicators

Follows hub-spoke navigation - this is a spoke panel.
"""

from typing import Dict, Any, Optional, Tuple, List
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text


class TaskListPanel:
    """Task list rendering and filtering"""

    # Status icons mapping
    STATUS_ICONS = {
        'completed': '✓',
        'in-progress': '~',
        'failed': '✗',
        'pending': '•',
        'skipped': '-'
    }

    # Status colors mapping
    STATUS_COLORS = {
        'completed': 'green',
        'in-progress': 'yellow',
        'failed': 'red',
        'pending': 'white',
        'skipped': 'bright_black'
    }

    # Priority colors
    PRIORITY_COLORS = {
        'HIGH': 'bright_red',
        'MEDIUM': 'yellow',
        'LOW': 'bright_black'
    }

    @classmethod
    def render(
        cls,
        profile,
        filter_state: Optional[Dict[str, Any]] = None,
        sort_by: str = 'priority',
        page: int = 1,
        page_size: int = 10
    ) -> Tuple[Panel, List[Dict]]:
        """
        Render task list panel with filtering and pagination

        Args:
            profile: TargetProfile instance
            filter_state: Filter configuration dict
            sort_by: Sort field ('priority', 'name', 'port', 'time_estimate')
            page: Current page number (1-indexed)
            page_size: Tasks per page (default 10)

        Returns:
            Tuple of (Rich Panel, choices list for input processing)
        """
        # Initialize filter state if not provided
        if filter_state is None:
            filter_state = {
                'status': 'all',
                'port': None,
                'service': None,
                'priority': None,
                'tags': []
            }

        # Get all tasks
        all_tasks = profile.task_tree.get_all_tasks()

        # Apply filters
        filtered_tasks = cls._apply_filters(all_tasks, filter_state)

        # Apply sorting
        sorted_tasks = cls._apply_sort(filtered_tasks, sort_by)

        # Paginate
        total_tasks = len(sorted_tasks)
        total_pages = max(1, (total_tasks + page_size - 1) // page_size)
        page = max(1, min(page, total_pages))  # Clamp to valid range

        start_idx = (page - 1) * page_size
        end_idx = min(start_idx + page_size, total_tasks)
        page_tasks = sorted_tasks[start_idx:end_idx]

        # Determine panel state
        if total_tasks == 0:
            return cls._render_empty_state(profile, filter_state)
        else:
            return cls._render_task_table(
                profile,
                page_tasks,
                filter_state,
                sort_by,
                page,
                total_pages,
                total_tasks,
                start_idx
            )

    @classmethod
    def _apply_filters(cls, tasks: List, filter_state: Dict[str, Any]) -> List:
        """
        Apply filters to task list

        Args:
            tasks: List of TaskNode instances
            filter_state: Filter configuration

        Returns:
            Filtered list of tasks
        """
        filtered = tasks

        # Filter by status
        status_filter = filter_state.get('status', 'all')
        if status_filter != 'all':
            filtered = [t for t in filtered if t.status == status_filter]

        # Filter by port
        port_filter = filter_state.get('port')
        if port_filter is not None:
            filtered = [
                t for t in filtered
                if cls._extract_port_from_task(t) == port_filter
            ]

        # Filter by service
        service_filter = filter_state.get('service')
        if service_filter:
            filtered = [
                t for t in filtered
                if cls._extract_service_from_task(t) == service_filter
            ]

        # Filter by priority
        priority_filter = filter_state.get('priority')
        if priority_filter:
            filtered = [
                t for t in filtered
                if t.metadata.get('priority') == priority_filter
            ]

        # Filter by tags
        tag_filters = filter_state.get('tags', [])
        if tag_filters:
            filtered = [
                t for t in filtered
                if any(tag in t.metadata.get('tags', []) for tag in tag_filters)
            ]

        return filtered

    @classmethod
    def _apply_sort(cls, tasks: List, sort_by: str) -> List:
        """
        Sort task list by specified field

        Args:
            tasks: List of TaskNode instances
            sort_by: Sort field name

        Returns:
            Sorted list of tasks
        """
        if sort_by == 'priority':
            # Sort by priority (HIGH -> MEDIUM -> LOW)
            priority_order = {'HIGH': 0, 'MEDIUM': 1, 'LOW': 2, None: 3}
            return sorted(
                tasks,
                key=lambda t: priority_order.get(t.metadata.get('priority'), 3)
            )
        elif sort_by == 'name':
            return sorted(tasks, key=lambda t: t.name.lower())
        elif sort_by == 'port':
            return sorted(tasks, key=lambda t: cls._extract_port_from_task(t) or 0)
        elif sort_by == 'time_estimate':
            return sorted(tasks, key=lambda t: cls._parse_time_estimate(t))
        else:
            # Default to original order
            return tasks

    @classmethod
    def _render_task_table(
        cls,
        profile,
        tasks: List,
        filter_state: Dict[str, Any],
        sort_by: str,
        page: int,
        total_pages: int,
        total_tasks: int,
        start_idx: int
    ) -> Tuple[Panel, List[Dict]]:
        """
        Render task table with tasks

        Args:
            profile: TargetProfile instance
            tasks: List of tasks for current page
            filter_state: Current filter state
            sort_by: Current sort field
            page: Current page number
            total_pages: Total number of pages
            total_tasks: Total number of tasks (after filtering)
            start_idx: Starting index in full list

        Returns:
            Tuple of (Panel, choices)
        """
        # Create table
        table = Table(show_header=True, box=box.SIMPLE, padding=(0, 1))

        # Define columns
        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("St", width=3, justify="center")
        table.add_column("Task Name", style="white", min_width=30)
        table.add_column("Port", width=6, justify="right")
        table.add_column("Pri", width=6, justify="center")
        table.add_column("Tags", width=15)
        table.add_column("Stage", width=8, justify="center")

        # Build choices list
        choices = []

        # Add tasks to table
        for idx, task in enumerate(tasks, 1):
            # Status icon
            icon = cls.STATUS_ICONS.get(task.status, '?')
            color = cls.STATUS_COLORS.get(task.status, 'white')
            status_cell = f"[{color}]{icon}[/]"

            # Task name (truncate if too long)
            task_name = task.name
            if len(task_name) > 35:
                task_name = task_name[:32] + "..."

            # Port
            port = cls._extract_port_from_task(task)
            port_str = str(port) if port else "-"

            # Priority
            priority = task.metadata.get('priority', 'MED')
            priority_abbr = priority[:3] if priority else 'MED'
            priority_color = cls.PRIORITY_COLORS.get(priority, 'white')
            priority_cell = f"[{priority_color}]{priority_abbr}[/]"

            # Tags (show first 2)
            tags = task.metadata.get('tags', [])
            tag_display = ' '.join([f'[cyan]{tag}[/]' for tag in tags[:2]])
            if not tag_display:
                tag_display = '[dim]-[/]'

            # Multi-stage indicator
            stage_info = cls._get_stage_info(task)

            # Add row
            table.add_row(
                str(idx),
                status_cell,
                task_name,
                port_str,
                priority_cell,
                tag_display,
                stage_info
            )

            # Add to choices
            choices.append({
                'id': f'select-{idx}',
                'label': f'Select task: {task.name}',
                'task': task
            })

        # Build filter/sort status line
        filter_info = cls._build_filter_status(filter_state, sort_by, total_tasks)

        # Add spacing and footer menu
        table.add_row("", "", "", "", "", "", "")  # Blank row

        # Build footer
        footer_table = Table(show_header=False, box=None, padding=(0, 1))
        footer_table.add_column("Actions", style="white")

        footer_table.add_row(f"[dim]{filter_info}[/]")
        footer_table.add_row("")

        # Action menu
        footer_table.add_row("[bold bright_white]1-{0}.[/] Select task".format(len(tasks)))
        choices.append({'id': 'select', 'label': 'Select task by number'})

        footer_table.add_row("[bold bright_white]f.[/] Filter tasks")
        choices.append({'id': 'filter', 'label': 'Filter tasks'})

        footer_table.add_row("[bold bright_white]s.[/] Sort options")
        choices.append({'id': 'sort', 'label': 'Sort options'})

        footer_table.add_row("[bold bright_white]/.[/] Search tasks")
        choices.append({'id': 'search', 'label': 'Search tasks'})

        # Pagination
        if total_pages > 1:
            if page > 1:
                footer_table.add_row("[bold bright_white]p.[/] Previous page")
                choices.append({'id': 'prev-page', 'label': 'Previous page'})
            if page < total_pages:
                footer_table.add_row("[bold bright_white]n.[/] Next page")
                choices.append({'id': 'next-page', 'label': 'Next page'})

        footer_table.add_row("[bold bright_white]b.[/] Back to dashboard")
        choices.append({'id': 'back', 'label': 'Back to dashboard'})

        # Combine table and footer
        combined_table = Table(show_header=False, box=None, padding=(0, 0))
        combined_table.add_column("Content")
        combined_table.add_row(table)
        combined_table.add_row(footer_table)

        # Build panel
        breadcrumb = "Dashboard > Task List"
        page_info = f"Page {page}/{total_pages}" if total_pages > 1 else "All Tasks"
        title = f"[bold cyan]{breadcrumb}[/] | [white]{page_info}[/]"
        subtitle = f"[dim]Showing {len(tasks)} of {total_tasks} tasks | Sort: {sort_by}[/]"

        return Panel(
            combined_table,
            title=title,
            subtitle=subtitle,
            border_style="cyan",
            box=box.ROUNDED
        ), choices

    @classmethod
    def _render_empty_state(
        cls,
        profile,
        filter_state: Dict[str, Any]
    ) -> Tuple[Panel, List[Dict]]:
        """
        Render empty state (no tasks or all filtered out)

        Args:
            profile: TargetProfile instance
            filter_state: Current filter state

        Returns:
            Tuple of (Panel, choices)
        """
        # Check if this is due to filtering or truly empty
        all_tasks = profile.task_tree.get_all_tasks()
        is_filtered_empty = len(all_tasks) > 0

        # Build message
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Content", style="white")

        if is_filtered_empty:
            table.add_row("[yellow]No tasks match current filters[/]")
            table.add_row("")
            table.add_row(f"[dim]Total tasks: {len(all_tasks)}[/]")
            table.add_row(f"[dim]Active filters: {cls._describe_filters(filter_state)}[/]")
        else:
            table.add_row("[yellow]No tasks yet[/]")
            table.add_row("")
            table.add_row("[dim]Import scan results or add tasks manually to get started[/]")

        table.add_row("")

        # Action menu
        choices = []

        if is_filtered_empty:
            table.add_row("[bold bright_white]c.[/] Clear filters")
            choices.append({'id': 'clear-filters', 'label': 'Clear filters'})

        table.add_row("[bold bright_white]f.[/] Filter tasks")
        choices.append({'id': 'filter', 'label': 'Filter tasks'})

        table.add_row("[bold bright_white]b.[/] Back to dashboard")
        choices.append({'id': 'back', 'label': 'Back to dashboard'})

        # Build panel
        breadcrumb = "Dashboard > Task List"
        title = f"[bold cyan]{breadcrumb}[/]"
        subtitle = "[dim]No tasks to display[/]"

        return Panel(
            table,
            title=title,
            subtitle=subtitle,
            border_style="cyan",
            box=box.ROUNDED
        ), choices

    @classmethod
    def _extract_port_from_task(cls, task) -> Optional[int]:
        """
        Extract port number from task ID or metadata

        Args:
            task: TaskNode instance

        Returns:
            Port number or None
        """
        # Try metadata first
        if hasattr(task, 'metadata'):
            port = task.metadata.get('port')
            if port is not None:
                return int(port)

        # Try extracting from task ID (e.g., 'gobuster-80' -> 80)
        if hasattr(task, 'id') and task.id:
            parts = task.id.split('-')
            for part in parts:
                if part.isdigit():
                    return int(part)

        return None

    @classmethod
    def _extract_service_from_task(cls, task) -> Optional[str]:
        """
        Extract service name from task metadata

        Args:
            task: TaskNode instance

        Returns:
            Service name or None
        """
        if hasattr(task, 'metadata'):
            return task.metadata.get('service')
        return None

    @classmethod
    def _parse_time_estimate(cls, task) -> int:
        """
        Parse time estimate to minutes for sorting

        Args:
            task: TaskNode instance

        Returns:
            Estimated minutes (default 0)
        """
        if not hasattr(task, 'metadata'):
            return 0

        time_est = task.metadata.get('time_estimate', '')
        if not time_est or time_est == 'Unknown':
            return 0

        # Parse formats like "5 min", "2-5 min", "1 hour"
        time_est = str(time_est).lower()

        # Extract first number
        import re
        match = re.search(r'(\d+)', time_est)
        if not match:
            return 0

        value = int(match.group(1))

        # Convert to minutes
        if 'hour' in time_est:
            return value * 60
        elif 'min' in time_est:
            return value
        else:
            return value  # Assume minutes

    @classmethod
    def _get_stage_info(cls, task) -> str:
        """
        Get multi-stage task indicator

        Args:
            task: TaskNode instance

        Returns:
            Stage info string (e.g., "[2/3]" or "-")
        """
        if not hasattr(task, 'metadata'):
            return '[dim]-[/]'

        stages = task.metadata.get('stages')
        current_stage = task.metadata.get('current_stage')

        if stages and current_stage:
            total = len(stages) if isinstance(stages, list) else stages
            return f"[cyan][{current_stage}/{total}][/]"

        return '[dim]-[/]'

    @classmethod
    def _build_filter_status(
        cls,
        filter_state: Dict[str, Any],
        sort_by: str,
        total_tasks: int
    ) -> str:
        """
        Build filter status description

        Args:
            filter_state: Current filter state
            sort_by: Current sort field
            total_tasks: Total filtered tasks

        Returns:
            Filter status string
        """
        parts = [f"Showing {total_tasks} tasks"]

        # Add active filters
        active_filters = []

        status_filter = filter_state.get('status', 'all')
        if status_filter != 'all':
            active_filters.append(f"status={status_filter}")

        if filter_state.get('port'):
            active_filters.append(f"port={filter_state['port']}")

        if filter_state.get('service'):
            active_filters.append(f"service={filter_state['service']}")

        if filter_state.get('priority'):
            active_filters.append(f"priority={filter_state['priority']}")

        if filter_state.get('tags'):
            active_filters.append(f"tags={','.join(filter_state['tags'])}")

        if active_filters:
            parts.append(f"Filters: {', '.join(active_filters)}")

        parts.append(f"Sort: {sort_by}")

        return " | ".join(parts)

    @classmethod
    def _describe_filters(cls, filter_state: Dict[str, Any]) -> str:
        """
        Describe active filters in human-readable format

        Args:
            filter_state: Current filter state

        Returns:
            Human-readable filter description
        """
        filters = []

        if filter_state.get('status', 'all') != 'all':
            filters.append(f"status={filter_state['status']}")

        if filter_state.get('port'):
            filters.append(f"port={filter_state['port']}")

        if filter_state.get('service'):
            filters.append(f"service={filter_state['service']}")

        if filter_state.get('priority'):
            filters.append(f"priority={filter_state['priority']}")

        if filter_state.get('tags'):
            filters.append(f"tags={','.join(filter_state['tags'])}")

        return ', '.join(filters) if filters else 'None'
