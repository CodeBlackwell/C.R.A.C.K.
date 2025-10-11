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
from ..themes.helpers import format_menu_number, format_command


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
        findings: Optional[List[Dict]] = None,
        target: Optional[str] = None,
        theme=None
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
            target: Target hostname/IP (for scan profile command preview)
            theme: ThemeManager instance (optional, will create if None)

        Returns:
            Tuple of (Layout with top/bottom sections, action choices list)
        """
        # Initialize theme if not provided
        if theme is None:
            from ..themes import ThemeManager
            theme = ThemeManager()

        # Build vertical layout
        layout = Layout()
        layout.split_column(
            Layout(name='task_details', size=12),  # Fixed height for task info
            Layout(name='io_panel')                # Remaining space for output
        )

        # Render top panel (task details + actions)
        task_panel, choices = cls._render_task_details(task, output_state, target, theme)
        layout['task_details'].update(task_panel)

        # Render bottom panel (I/O streaming)
        io_panel = cls._render_io_section(
            output_state,
            output_lines or [],
            elapsed,
            exit_code,
            findings or [],
            theme
        )
        layout['io_panel'].update(io_panel)

        return layout, choices

    @classmethod
    def _render_task_details(cls, task, output_state: str, target: Optional[str] = None, theme=None) -> Tuple[Panel, List[Dict]]:
        """
        Render task details panel (top section)

        Args:
            task: TaskNode instance
            output_state: Current output state
            target: Target hostname/IP (for scan profile command preview)
            theme: ThemeManager instance

        Returns:
            Tuple of (Panel, choices list)
        """
        # Initialize theme if not provided
        if theme is None:
            from ..themes import ThemeManager
            theme = ThemeManager()
        # Extract task metadata
        task_name = task.name if hasattr(task, 'name') else str(task)
        description = task.metadata.get('description', '') if hasattr(task, 'metadata') else ''
        command = (task.metadata.get('command') or 'N/A') if hasattr(task, 'metadata') else 'N/A'
        time_est = task.metadata.get('time_estimate', 'Unknown') if hasattr(task, 'metadata') else 'Unknown'
        priority = task.metadata.get('priority', 'MEDIUM') if hasattr(task, 'metadata') else 'MEDIUM'
        tags = task.metadata.get('tags', []) if hasattr(task, 'metadata') else []

        # Build content table
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Content", style="white")

        # Task info section
        if description:
            table.add_row(f"{theme.muted('Description:')} {description}")

        # Show scan profile details if this is a scan task
        scan_profile_name = task.metadata.get('scan_profile_name') if hasattr(task, 'metadata') else None
        if scan_profile_name:
            scan_strategy = task.metadata.get('scan_profile_strategy', 'Unknown strategy')
            scan_time = task.metadata.get('scan_profile_time', 'Unknown')
            scan_risk = task.metadata.get('scan_profile_risk', 'medium')

            # Display scan profile banner
            table.add_row("")  # Blank line
            menu_num_color = theme.get_component_color('menu_number')
            table.add_row(f"[bold {theme.get_color('success')}]▶ Scan Profile:[/] [bold {menu_num_color}]{scan_profile_name}[/]")
            table.add_row(f"  {theme.muted('Strategy:')} {scan_strategy}")
            table.add_row(f"  {theme.muted('Estimated:')} {scan_time}")

            # Warn if high detection risk
            if scan_risk in ['high', 'very-high']:
                table.add_row(f"  {theme.warning('⚠ Detection Risk:')} [bold {theme.get_color('warning')}]{scan_risk.upper()}[/] {theme.muted('(may trigger IDS/IPS)')}")
            else:
                table.add_row(f"  {theme.muted('Detection Risk:')} {scan_risk}")
            table.add_row("")  # Blank line

        # Command (truncate if too long)
        cmd_display = command[:70] + '...' if len(command) > 70 else command
        table.add_row(f"{theme.muted('Command:')} {format_command(theme, cmd_display)}")

        # Metadata line
        priority_color = {
            'HIGH': theme.get_color('danger'),
            'MEDIUM': theme.get_color('warning'),
            'LOW': theme.get_color('muted')
        }.get(priority, 'white')

        tag_str = ' '.join([f"{theme.primary(tag)}" for tag in tags[:2]]) if tags else theme.muted('No tags')
        table.add_row(f"[{priority_color}]Priority: {priority}[/] | {theme.muted('Time:')} ~{time_est} | {tag_str}")

        table.add_row("")  # Blank line

        # Action menu
        choices = cls._build_action_menu(task, output_state, table, target, theme)

        # Build panel
        breadcrumb = f"Dashboard > Task Workspace > {task_name}"
        return Panel(
            table,
            title=f"[bold {theme.get_color('primary')}]{breadcrumb}[/]",
            border_style=theme.panel_border(),
            box=box.ROUNDED
        ), choices

    @classmethod
    def _build_action_menu(cls, task, output_state: str, table: Table, target: Optional[str] = None, theme=None) -> List[Dict]:
        """
        Build context-aware action menu

        Args:
            task: TaskNode instance
            output_state: Current output state ('empty', 'streaming', 'complete')
            table: Table to add menu items to
            target: Target hostname/IP (for scan profile command preview)
            theme: ThemeManager instance

        Returns:
            List of choice dictionaries
        """
        # Initialize theme if not provided
        if theme is None:
            from ..themes import ThemeManager
            theme = ThemeManager()
        choices = []
        menu_num = 1

        # Actions depend on output state
        if output_state == 'empty':
            # Check if this is a strategic choice task (requires profile selection)
            command = task.metadata.get('command') if hasattr(task, 'metadata') else None
            allow_custom = task.metadata.get('allow_custom', False) if hasattr(task, 'metadata') else False

            if command is None and allow_custom:
                # Strategic choice task - load scan profiles dynamically
                from ...core.scan_profiles import ScanProfileRegistry
                from ...core.command_builder import ScanCommandBuilder

                # Load ALL available scan profiles
                registry = ScanProfileRegistry()
                available_profiles = registry.get_all_profiles()

                # Use provided target or placeholder
                if not target:
                    target = 'TARGET'

                # Add header
                table.add_row(f"[bold {theme.get_color('warning')}]Select scan strategy:[/]")
                table.add_row("")  # Blank line

                # Add each profile as a choice
                for scan_profile in available_profiles:
                    profile_id = scan_profile['id']
                    profile_name = scan_profile['name']
                    use_case = scan_profile['use_case']
                    estimated_time = scan_profile['estimated_time']

                    # Build the actual command for preview
                    try:
                        builder = ScanCommandBuilder(target, scan_profile)
                        command_preview = builder.build()
                        # Truncate if too long (keep first 80 chars)
                        if len(command_preview) > 80:
                            command_preview = command_preview[:77] + '...'
                    except Exception:
                        command_preview = '[Error building command]'

                    # Format with name, command, description
                    table.add_row(f"{format_menu_number(theme, menu_num)} {profile_name}")
                    table.add_row(f"   {theme.muted('Command:')} {theme.primary(command_preview)}")
                    table.add_row(f"   {theme.muted(f'{use_case} ({estimated_time})')}")
                    table.add_row("")  # Blank line between profiles

                    choices.append({
                        'id': f'scan-{profile_id}',
                        'label': profile_name,
                        'scan_profile': scan_profile,
                        'task': task
                    })
                    menu_num += 1

                # Add custom option
                table.add_row("")  # Blank line
                table.add_row(f"{format_menu_number(theme, menu_num)} Custom scan command")
                choices.append({'id': 'custom-scan', 'label': 'Custom scan command'})
                menu_num += 1

            else:
                # Standard task - show normal execute option
                table.add_row(f"{format_menu_number(theme, menu_num)} Execute this task")
                choices.append({'id': 'execute', 'label': 'Execute this task', 'task': task})
                menu_num += 1

                table.add_row(f"{format_menu_number(theme, menu_num)} Edit command")
                choices.append({'id': 'edit', 'label': 'Edit command'})
                menu_num += 1

                table.add_row(f"{format_menu_number(theme, menu_num)} View alternatives")
                choices.append({'id': 'alternatives', 'label': 'View alternatives'})
                menu_num += 1

        elif output_state == 'complete':
            # After execution
            table.add_row(f"{format_menu_number(theme, menu_num)} Re-execute")
            choices.append({'id': 'execute', 'label': 'Re-execute', 'task': task})
            menu_num += 1

            table.add_row(f"{format_menu_number(theme, menu_num)} Save output")
            choices.append({'id': 'save', 'label': 'Save output'})
            menu_num += 1

            table.add_row(f"{format_menu_number(theme, menu_num)} Add finding")
            choices.append({'id': 'finding', 'label': 'Add finding'})
            menu_num += 1

            table.add_row(f"{format_menu_number(theme, menu_num)} Mark complete")
            choices.append({'id': 'mark-done', 'label': 'Mark complete'})
            menu_num += 1

        # Always show back option
        menu_num_color = theme.get_component_color('menu_number')
        table.add_row(f"[{menu_num_color}]b.[/] Back to dashboard")
        choices.append({'id': 'back', 'label': 'Back to dashboard'})

        return choices

    @classmethod
    def _render_io_section(
        cls,
        output_state: str,
        lines: List[str],
        elapsed: float,
        exit_code: Optional[int],
        findings: List[Dict],
        theme=None
    ) -> Panel:
        """
        Render I/O panel using IOPanel component

        Args:
            output_state: 'empty' | 'streaming' | 'complete'
            lines: Output lines
            elapsed: Elapsed time
            exit_code: Exit code (if complete)
            findings: Findings list (if complete)
            theme: ThemeManager instance (passed to IOPanel)

        Returns:
            Panel from IOPanel component
        """
        # Initialize theme if not provided
        if theme is None:
            from ..themes import ThemeManager
            theme = ThemeManager()

        # Note: IOPanel not yet refactored to use theme, will pass theme in future refactor
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
