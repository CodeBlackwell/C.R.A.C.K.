"""
Task Workspace Panel - Vertical split task execution view

Vertical layout (REVISED from horizontal spec):
- Top 20%: Task details + action menu
- Bottom 80%: I/O streaming panel (from components.io_panel)

Follows hub-spoke navigation - this is a spoke panel.
"""

from typing import Dict, Any, Optional, Tuple, List
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich import box
from rich.text import Text

from ..components.io_panel import IOPanel


class TaskWorkspacePanel:
    """Task execution workspace with vertical split layout"""

    @classmethod
    def render(
        cls,
        task,  # TaskNode instance
        output_state: str = 'empty',
        output_lines: Optional[List[str]] = None,
        elapsed: float = 0.0,
        exit_code: Optional[int] = None,
        findings: Optional[List[Dict]] = None
    ) -> Tuple[Layout, List[Dict]]:
        """
        Render complete task workspace with vertical split

        Args:
            task: TaskNode instance with task metadata
            output_state: 'empty' | 'streaming' | 'complete'
            output_lines: List of output lines (if any)
            elapsed: Elapsed time in seconds (for streaming/complete)
            exit_code: Command exit code (for complete state)
            findings: Auto-detected findings (for complete state)

        Returns:
            Tuple of (Layout with top/bottom sections, action choices list)
        """
        # Build vertical layout
        layout = Layout()
        layout.split_column(
            Layout(name='task_details', size=12),  # Fixed height for task info
            Layout(name='io_panel')                # Remaining space for output
        )

        # Render top panel (task details + actions)
        task_panel, choices = cls._render_task_details(task, output_state)
        layout['task_details'].update(task_panel)

        # Render bottom panel (I/O streaming)
        io_panel = cls._render_io_section(
            output_state,
            output_lines or [],
            elapsed,
            exit_code,
            findings or []
        )
        layout['io_panel'].update(io_panel)

        return layout, choices

    @classmethod
    def _render_task_details(cls, task, output_state: str) -> Tuple[Panel, List[Dict]]:
        """
        Render task details panel (top section)

        Args:
            task: TaskNode instance
            output_state: Current output state

        Returns:
            Tuple of (Panel, choices list)
        """
        # Extract task metadata
        task_name = task.name if hasattr(task, 'name') else str(task)
        description = task.metadata.get('description', '') if hasattr(task, 'metadata') else ''
        command = task.metadata.get('command', 'N/A') if hasattr(task, 'metadata') else 'N/A'
        time_est = task.metadata.get('time_estimate', 'Unknown') if hasattr(task, 'metadata') else 'Unknown'
        priority = task.metadata.get('priority', 'MEDIUM') if hasattr(task, 'metadata') else 'MEDIUM'
        tags = task.metadata.get('tags', []) if hasattr(task, 'metadata') else []

        # Build content table
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Content", style="white")

        # Task info section
        if description:
            table.add_row(f"[dim]Description:[/] {description}")

        # Command (truncate if too long)
        cmd_display = command[:70] + '...' if len(command) > 70 else command
        table.add_row(f"[dim]Command:[/] [bright_black]{cmd_display}[/]")

        # Metadata line
        priority_color = {
            'HIGH': 'bright_red',
            'MEDIUM': 'yellow',
            'LOW': 'bright_black'
        }.get(priority, 'white')

        tag_str = ' '.join([f'[cyan]{tag}[/]' for tag in tags[:2]]) if tags else '[dim]No tags[/]'
        table.add_row(f"[{priority_color}]Priority: {priority}[/] | [dim]Time:[/] ~{time_est} | {tag_str}")

        table.add_row("")  # Blank line

        # Action menu
        choices = cls._build_action_menu(task, output_state, table)

        # Build panel
        breadcrumb = f"Dashboard > Task Workspace > {task_name}"
        return Panel(
            table,
            title=f"[bold cyan]{breadcrumb}[/]",
            border_style="cyan",
            box=box.ROUNDED
        ), choices

    @classmethod
    def _build_action_menu(cls, task, output_state: str, table: Table) -> List[Dict]:
        """
        Build context-aware action menu

        Args:
            task: TaskNode instance
            output_state: Current output state ('empty', 'streaming', 'complete')
            table: Table to add menu items to

        Returns:
            List of choice dictionaries
        """
        choices = []
        menu_num = 1

        # Actions depend on output state
        if output_state == 'empty':
            # Before execution
            table.add_row(f"[bold bright_white]{menu_num}.[/] Execute this task")
            choices.append({'id': 'execute', 'label': 'Execute this task', 'task': task})
            menu_num += 1

            table.add_row(f"[bold bright_white]{menu_num}.[/] Edit command")
            choices.append({'id': 'edit', 'label': 'Edit command'})
            menu_num += 1

            table.add_row(f"[bold bright_white]{menu_num}.[/] View alternatives")
            choices.append({'id': 'alternatives', 'label': 'View alternatives'})
            menu_num += 1

        elif output_state == 'complete':
            # After execution
            table.add_row(f"[bold bright_white]{menu_num}.[/] Re-execute")
            choices.append({'id': 'execute', 'label': 'Re-execute', 'task': task})
            menu_num += 1

            table.add_row(f"[bold bright_white]{menu_num}.[/] Save output")
            choices.append({'id': 'save', 'label': 'Save output'})
            menu_num += 1

            table.add_row(f"[bold bright_white]{menu_num}.[/] Add finding")
            choices.append({'id': 'finding', 'label': 'Add finding'})
            menu_num += 1

            table.add_row(f"[bold bright_white]{menu_num}.[/] Mark complete")
            choices.append({'id': 'mark-done', 'label': 'Mark complete'})
            menu_num += 1

        # Always show back option
        table.add_row(f"[bold bright_white]b.[/] Back to dashboard")
        choices.append({'id': 'back', 'label': 'Back to dashboard'})

        return choices

    @classmethod
    def _render_io_section(
        cls,
        output_state: str,
        lines: List[str],
        elapsed: float,
        exit_code: Optional[int],
        findings: List[Dict]
    ) -> Panel:
        """
        Render I/O panel using IOPanel component

        Args:
            output_state: 'empty' | 'streaming' | 'complete'
            lines: Output lines
            elapsed: Elapsed time
            exit_code: Exit code (if complete)
            findings: Findings list (if complete)

        Returns:
            Panel from IOPanel component
        """
        if output_state == 'empty':
            return IOPanel.render_empty()

        elif output_state == 'streaming':
            return IOPanel.render_streaming(lines, elapsed)

        elif output_state == 'complete':
            return IOPanel.render_complete(
                lines=lines,
                exit_code=exit_code or 0,
                elapsed=elapsed,
                findings=findings
            )

        else:
            # Fallback for unknown state
            return IOPanel.render_empty()
