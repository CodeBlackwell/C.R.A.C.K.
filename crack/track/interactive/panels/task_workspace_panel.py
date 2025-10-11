"""
Task Workspace Panel - Vertical split task execution view

Vertical layout:
- Task details (fixed 12 lines): Task info + action menu
- I/O panel (variable): Command output streaming
- Footer (fixed 3 lines): All available commands

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
from .base_panel import PanelShortcutMixin


class TaskWorkspacePanel(PanelShortcutMixin):
    """Task execution workspace with vertical split layout"""

    @classmethod
    def get_available_shortcuts(cls) -> List[str]:
        """
        Get shortcuts valid in task workspace

        Returns:
            List of shortcut keys available in workspace
        """
        return [
            # Global shortcuts (always available)
            'h', 's', 't', 'q', 'b',
            # Workspace-specific actions
            'e',      # Edit command
            'n',      # Next task
            'l',      # List tasks
            'o',      # Output overlay
            'v',      # View task details
            # Multi-char shortcuts (require : prefix)
            ':alt',   # Alternative commands
            ':qn',    # Quick note
            ':tr',    # Task retry
            # Number range for menu selection
            '1-9',    # Select menu option
        ]

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

        # Build vertical layout with footer
        layout = Layout()
        layout.split_column(
            Layout(name='task_details', size=12),  # Fixed height for task info
            Layout(name='io_panel'),               # Remaining space for output
            Layout(name='footer', size=3)          # Footer with commands
        )

        # Render top panel (task details + actions)
        task_panel, choices = cls._render_task_details(task, output_state, target, theme)
        layout['task_details'].update(task_panel)

        # Render middle panel (I/O streaming)
        io_panel = cls._render_io_section(
            output_state,
            output_lines or [],
            elapsed,
            exit_code,
            findings or [],
            theme
        )
        layout['io_panel'].update(io_panel)

        # Render footer with all commands
        footer_panel = cls._build_footer(choices, output_state, theme)
        layout['footer'].update(footer_panel)

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
                # Strategic choice task - show "Select scan profile" action
                from ...core.scan_profiles import ScanProfileRegistry

                # Load profiles to count them
                registry = ScanProfileRegistry()
                task_profile_ids = task.metadata.get('scan_profiles') if hasattr(task, 'metadata') else None

                if task_profile_ids:
                    # Task-specific profiles
                    profile_count = len(task_profile_ids)
                else:
                    # All available profiles
                    profile_count = len(registry.get_all_profiles())

                # Single action to open profile selector
                table.add_row(f"{format_menu_number(theme, menu_num)} Select scan profile ({profile_count} available)")
                choices.append({
                    'id': 'select-profile',
                    'label': f'Select scan profile ({profile_count} available)',
                    'task': task,
                    'profile_count': profile_count
                })
                menu_num += 1

            else:
                # Standard task - show normal execute option
                table.add_row(f"{format_menu_number(theme, menu_num)} Execute this task")
                choices.append({'id': 'execute', 'label': 'Execute this task', 'task': task})
                menu_num += 1

                # If this is a scan task with a profile selected, allow changing profile
                scan_profile_name = task.metadata.get('scan_profile_name') if hasattr(task, 'metadata') else None
                if allow_custom and scan_profile_name:
                    table.add_row(f"{format_menu_number(theme, menu_num)} Change scan profile")
                    choices.append({'id': 'select-profile', 'label': 'Change scan profile'})
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

    @classmethod
    def _build_footer(cls, choices: List[Dict], output_state: str, theme=None) -> Panel:
        """Build footer panel with all available commands"""
        # Initialize theme if not provided
        if theme is None:
            from ..themes import ThemeManager
            theme = ThemeManager()

        # Extract command shortcuts from choices
        commands = []

        # Add numbered actions with their actual labels
        action_choices = [c for c in choices if c['id'] != 'back']
        for i, choice in enumerate(action_choices, start=1):
            label = choice.get('label', 'Action')
            # Truncate long labels for footer display
            if len(label) > 30:
                label = label[:27] + '...'
            commands.append(f"{i}:{theme.primary(label)}")

        # Add common commands
        commands.extend([
            f":::{theme.primary('Command mode')}",
            f"b:{theme.primary('Back to dashboard')}"
        ])

        # Format as two lines if too many commands
        if len(commands) > 4:
            # Split into two lines
            mid = (len(commands) + 1) // 2
            line1 = "     ".join(commands[:mid])
            line2 = "     ".join(commands[mid:])
            footer_content = f"{line1}\n{line2}"
        else:
            # Single line for simpler cases
            footer_content = "     ".join(commands)

        return Panel(
            footer_content,
            title=f"[bold {theme.get_color('primary')}]All Commands[/] {theme.muted('(h:Help for details)')}",
            border_style=theme.panel_border(),
            box=box.ROUNDED,
            padding=(0, 2)
        )
