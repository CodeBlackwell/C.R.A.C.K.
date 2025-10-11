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

from .base_panel import PanelShortcutMixin


class TaskListPanel(PanelShortcutMixin):
    """Task list rendering and filtering"""

    @classmethod
    def get_available_shortcuts(cls) -> List[str]:
        """
        Get shortcuts valid in task list panel

        Returns:
            List of shortcut keys available in task list
        """
        return [
            # Global shortcuts (always available)
            'h', 's', 't', 'q', 'b',
            # Task list-specific actions
            'f',      # Filter tasks
            's',      # Sort tasks
            '/',      # Search tasks
            't',      # Toggle tree view
            'p',      # Previous page (if pagination active)
            'n',      # Next page (if pagination active)
            # Number range for selection
            '1-9',    # Select task by number
        ]

    # Status icons mapping
    STATUS_ICONS = {
        'completed': '✓',
        'in-progress': '~',
        'failed': '✗',
        'pending': '•',
        'skipped': '-'
    }

    @classmethod
    def render(
        cls,
        profile,
        filter_state: Optional[Dict[str, Any]] = None,
        sort_by: str = 'priority',
        page: int = 1,
        page_size: int = 10,
        show_hierarchy: bool = False,
        theme=None
    ) -> Tuple[Panel, List[Dict]]:
        """
        Render task list panel with filtering and pagination

        Args:
            profile: TargetProfile instance
            filter_state: Filter configuration dict
            sort_by: Sort field ('priority', 'name', 'port', 'time_estimate')
            page: Current page number (1-indexed)
            page_size: Tasks per page (default 10)
            show_hierarchy: Show tree structure with indentation (default False)
            theme: ThemeManager instance (optional for backward compat)

        Returns:
            Tuple of (Rich Panel, choices list for input processing)
        """
        # Fallback theme for backward compatibility
        if theme is None:
            from ..themes import ThemeManager
            theme = ThemeManager()

        # Initialize filter state if not provided
        if filter_state is None:
            filter_state = {
                'status': 'all',
                'port': None,
                'service': None,
                'priority': None,
                'tags': []
            }

        # Get all tasks (with hierarchy info if requested)
        if show_hierarchy:
            # Get tasks as list of (task, depth) tuples preserving tree order
            all_tasks = cls._get_tasks_with_depth(profile.task_tree)
        else:
            # Flat list (backward compatible)
            all_tasks = [(task, 0) for task in profile.task_tree.get_all_tasks()]

        # Apply filters
        filtered_tasks = cls._apply_filters_with_depth(all_tasks, filter_state)

        # Apply sorting (if not showing hierarchy, sort is allowed)
        if show_hierarchy:
            # Keep tree order when showing hierarchy
            sorted_tasks = filtered_tasks
        else:
            # Extract tasks, sort, re-wrap with depth=0
            tasks_only = [t for t, d in filtered_tasks]
            tasks_sorted = cls._apply_sort(tasks_only, sort_by)
            sorted_tasks = [(t, 0) for t in tasks_sorted]

        # Paginate
        total_tasks = len(sorted_tasks)
        total_pages = max(1, (total_tasks + page_size - 1) // page_size)
        page = max(1, min(page, total_pages))  # Clamp to valid range

        start_idx = (page - 1) * page_size
        end_idx = min(start_idx + page_size, total_tasks)
        page_tasks = sorted_tasks[start_idx:end_idx]

        # Determine panel state
        if total_tasks == 0:
            return cls._render_empty_state(profile, filter_state, theme=theme)
        else:
            return cls._render_task_table(
                profile,
                page_tasks,
                filter_state,
                sort_by,
                page,
                total_pages,
                total_tasks,
                start_idx,
                show_hierarchy=show_hierarchy,
                theme=theme
            )

    @classmethod
    def _get_tasks_with_depth(cls, root_node, current_depth: int = 0) -> List[Tuple]:
        """
        Get tasks in tree order with depth information

        Args:
            root_node: TaskNode (usually task_tree root)
            current_depth: Current depth in tree (0 = root)

        Returns:
            List of (task, depth) tuples in DFS order
        """
        tasks_with_depth = []

        # Skip root node (id='root')
        if root_node.id != 'root':
            tasks_with_depth.append((root_node, current_depth))

        # Recursively add children
        for child in root_node.children:
            tasks_with_depth.extend(cls._get_tasks_with_depth(child, current_depth + 1))

        return tasks_with_depth

    @classmethod
    def _apply_filters_with_depth(cls, tasks_with_depth: List[Tuple], filter_state: Dict[str, Any]) -> List[Tuple]:
        """
        Apply filters to task list with depth

        Args:
            tasks_with_depth: List of (task, depth) tuples
            filter_state: Filter configuration

        Returns:
            Filtered list of (task, depth) tuples
        """
        filtered = []

        for task, depth in tasks_with_depth:
            # Apply same filters as _apply_filters
            # Filter by status
            status_filter = filter_state.get('status', 'all')
            if status_filter != 'all' and task.status != status_filter:
                continue

            # Filter by port
            port_filter = filter_state.get('port')
            if port_filter is not None and cls._extract_port_from_task(task) != port_filter:
                continue

            # Filter by service
            service_filter = filter_state.get('service')
            if service_filter and cls._extract_service_from_task(task) != service_filter:
                continue

            # Filter by priority
            priority_filter = filter_state.get('priority')
            if priority_filter and task.metadata.get('priority') != priority_filter:
                continue

            # Filter by tags
            tag_filters = filter_state.get('tags', [])
            if tag_filters and not any(tag in task.metadata.get('tags', []) for tag in tag_filters):
                continue

            # Passed all filters
            filtered.append((task, depth))

        return filtered

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
        start_idx: int,
        show_hierarchy: bool = False,
        theme=None
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
            show_hierarchy: Show tree structure with indentation
            theme: ThemeManager instance (optional for backward compat)

        Returns:
            Tuple of (Panel, choices)
        """
        # Fallback theme for backward compatibility
        if theme is None:
            from ..themes import ThemeManager
            theme = ThemeManager()

        # Create table
        table = Table(show_header=True, box=box.SIMPLE, padding=(0, 1))

        # Define columns
        muted_color = theme.get_color('muted')
        text_color = theme.get_color('text')
        table.add_column("#", style=muted_color, width=4, justify="right")
        table.add_column("St", width=3, justify="center")
        table.add_column("Task Name", style=text_color, min_width=30)
        table.add_column("Port", width=6, justify="right")
        table.add_column("Pri", width=6, justify="center")
        table.add_column("Tags", width=15)
        table.add_column("Stage", width=8, justify="center")

        # Build choices list
        choices = []

        # Add tasks to table
        for idx, task_tuple in enumerate(tasks, 1):
            # Unpack task and depth
            if isinstance(task_tuple, tuple):
                task, depth = task_tuple
            else:
                # Backward compatibility: if not tuple, assume depth=0
                task, depth = task_tuple, 0

            # Status icon
            icon = cls.STATUS_ICONS.get(task.status, '?')
            color = theme.task_state_color(task.status)
            status_cell = f"[{color}]{icon}[/]"

            # Task name with optional indentation for hierarchy
            if depth > 0:
                # Hierarchy mode - apply indentation and truncation
                indent = "  " * depth
                tree_prefix = theme.muted("└─ ")
                max_length = 60 - (len(indent) + len(tree_prefix))  # Increased limit
                if len(task.name) > max_length:
                    task_name = f"{indent}{tree_prefix}{task.name[:max_length-3]}..."
                else:
                    task_name = f"{indent}{tree_prefix}{task.name}"
            else:
                # Flat mode - show full task name (no truncation)
                task_name = task.name

            # Port
            port = cls._extract_port_from_task(task)
            port_str = str(port) if port else "-"

            # Priority
            priority = task.metadata.get('priority', 'MED')
            priority_abbr = priority[:3] if priority else 'MED'
            priority_color = cls._get_priority_color(priority, theme)
            priority_cell = f"[{priority_color}]{priority_abbr}[/]"

            # Tags (show first 2)
            tags = task.metadata.get('tags', [])
            tag_color = theme.get_component_color('tag')
            tag_display = ' '.join([f'[{tag_color}]{tag}[/]' for tag in tags[:2]])
            if not tag_display:
                tag_display = theme.muted('-')

            # Multi-stage indicator
            stage_info = cls._get_stage_info(task, theme)

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
                'action': 'select_task',
                'task': task
            })

        # Build filter/sort status line
        filter_info = cls._build_filter_status(filter_state, sort_by, total_tasks)

        # Add spacing and footer menu
        table.add_row("", "", "", "", "", "", "")  # Blank row

        # Build footer
        footer_table = Table(show_header=False, box=None, padding=(0, 1))
        footer_table.add_column("Actions", style=text_color)

        footer_table.add_row(theme.muted(filter_info))
        footer_table.add_row("")

        # Action menu
        from ..themes.helpers import format_menu_number
        footer_table.add_row(f"{format_menu_number(theme, f'1-{len(tasks)}')} Select task")
        choices.append({'id': 'select', 'label': 'Select task by number', 'action': 'select'})

        footer_table.add_row(f"{format_menu_number(theme, 'f')} Filter tasks")
        choices.append({'id': 'filter', 'label': 'Filter tasks', 'action': 'filter'})

        footer_table.add_row(f"{format_menu_number(theme, 's')} Sort options")
        choices.append({'id': 'sort', 'label': 'Sort options', 'action': 'sort'})

        footer_table.add_row(f"{format_menu_number(theme, '/')} Search tasks")
        choices.append({'id': 'search', 'label': 'Search tasks', 'action': 'search'})

        # Tree view toggle
        tree_status = "hierarchical" if show_hierarchy else "flat"
        footer_table.add_row(f"{format_menu_number(theme, 't')} Toggle tree view ({tree_status})")
        choices.append({'id': 'toggle-tree', 'label': f'Toggle tree view (current: {tree_status})', 'action': 'toggle_hierarchy'})

        # Pagination
        if total_pages > 1:
            if page > 1:
                footer_table.add_row(f"{format_menu_number(theme, 'p')} Previous page")
                choices.append({'id': 'prev-page', 'label': 'Previous page', 'action': 'prev_page', 'page': page - 1})
            if page < total_pages:
                footer_table.add_row(f"{format_menu_number(theme, 'n')} Next page")
                choices.append({'id': 'next-page', 'label': 'Next page', 'action': 'next_page', 'page': page + 1})

        footer_table.add_row(f"{format_menu_number(theme, 'b')} Back to dashboard")
        choices.append({'id': 'back', 'label': 'Back to dashboard', 'action': 'back'})

        # Combine table and footer
        combined_table = Table(show_header=False, box=None, padding=(0, 0))
        combined_table.add_column("Content")
        combined_table.add_row(table)
        combined_table.add_row(footer_table)

        # Build panel
        breadcrumb = "Dashboard > Task List"
        page_info = f"Page {page}/{total_pages}" if total_pages > 1 else "All Tasks"
        title = f"[bold {theme.get_color('primary')}]{breadcrumb}[/] | [{text_color}]{page_info}[/]"
        subtitle = theme.muted(f"Showing {len(tasks)} of {total_tasks} tasks | Sort: {sort_by}")

        return Panel(
            combined_table,
            title=title,
            subtitle=subtitle,
            border_style=theme.panel_border(),
            box=box.ROUNDED
        ), choices

    @classmethod
    def _render_empty_state(
        cls,
        profile,
        filter_state: Dict[str, Any],
        theme=None
    ) -> Tuple[Panel, List[Dict]]:
        """
        Render empty state (no tasks or all filtered out)

        Args:
            profile: TargetProfile instance
            filter_state: Current filter state
            theme: ThemeManager instance (optional for backward compat)

        Returns:
            Tuple of (Panel, choices)
        """
        # Fallback theme for backward compatibility
        if theme is None:
            from ..themes import ThemeManager
            theme = ThemeManager()

        # Check if this is due to filtering or truly empty
        all_tasks = profile.task_tree.get_all_tasks()
        is_filtered_empty = len(all_tasks) > 0

        # Build message
        table = Table(show_header=False, box=None, padding=(0, 2))
        text_color = theme.get_color('text')
        table.add_column("Content", style=text_color)

        if is_filtered_empty:
            table.add_row(theme.warning("No tasks match current filters"))
            table.add_row("")
            table.add_row(theme.muted(f"Total tasks: {len(all_tasks)}"))
            table.add_row(theme.muted(f"Active filters: {cls._describe_filters(filter_state)}"))
        else:
            table.add_row(theme.warning("No tasks yet"))
            table.add_row("")
            table.add_row(theme.muted("Import scan results or add tasks manually to get started"))

        table.add_row("")

        # Action menu
        from ..themes.helpers import format_menu_number
        choices = []

        if is_filtered_empty:
            table.add_row(f"{format_menu_number(theme, 'c')} Clear filters")
            choices.append({'id': 'clear-filters', 'label': 'Clear filters', 'action': 'clear_filters'})

        table.add_row(f"{format_menu_number(theme, 'f')} Filter tasks")
        choices.append({'id': 'filter', 'label': 'Filter tasks', 'action': 'filter'})

        table.add_row(f"{format_menu_number(theme, 'b')} Back to dashboard")
        choices.append({'id': 'back', 'label': 'Back to dashboard', 'action': 'back'})

        # Build panel
        breadcrumb = "Dashboard > Task List"
        title = f"[bold {theme.get_color('primary')}]{breadcrumb}[/]"
        subtitle = theme.muted("No tasks to display")

        return Panel(
            table,
            title=title,
            subtitle=subtitle,
            border_style=theme.panel_border(),
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
    def _get_stage_info(cls, task, theme) -> str:
        """
        Get multi-stage task indicator

        Args:
            task: TaskNode instance
            theme: ThemeManager instance

        Returns:
            Stage info string (e.g., "[2/3]" or "-")
        """
        if not hasattr(task, 'metadata'):
            return theme.muted('-')

        stages = task.metadata.get('stages')
        current_stage = task.metadata.get('current_stage')

        if stages and current_stage:
            total = len(stages) if isinstance(stages, list) else stages
            info_color = theme.get_color('info')
            return f"[{info_color}][{current_stage}/{total}][/]"

        return theme.muted('-')

    @classmethod
    def _get_priority_color(cls, priority: str, theme) -> str:
        """
        Get color for priority level

        Args:
            priority: Priority string (HIGH, MEDIUM, LOW)
            theme: ThemeManager instance

        Returns:
            Color name
        """
        if priority == 'HIGH':
            return theme.get_color('danger')
        elif priority == 'MEDIUM':
            return theme.get_color('warning')
        elif priority == 'LOW':
            return theme.get_color('muted')
        else:
            return theme.get_color('text')

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
