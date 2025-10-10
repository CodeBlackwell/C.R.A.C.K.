"""
Template Detail Panel - Show template details and handle variable input

Displays selected template with variable input form and command preview.
Follows hub-spoke navigation - this is a spoke panel.
"""

from typing import Dict, Any, List, Tuple, Optional
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text


class TemplateDetailPanel:
    """Template detail panel with variable input"""

    @classmethod
    def render(
        cls,
        template,  # CommandTemplate instance
        filled_values: Optional[Dict[str, str]] = None,
        execution_result: Optional[Dict[str, Any]] = None
    ) -> Tuple[Panel, List[Dict]]:
        """
        Render template detail panel with variable input form

        Args:
            template: CommandTemplate instance
            filled_values: Dict of variable_name -> value (if already filled)
            execution_result: Result of command execution if completed

        Returns:
            Tuple of (Panel, action choices list)
        """
        # Build panel content
        table = Table(show_header=False, box=None, padding=(0, 1))
        table.add_column("Content", style="white", width=100)

        # Template header
        table.add_row(f"[bold cyan]{template.name}[/]")
        table.add_row(f"[dim]{template.description}[/]")
        table.add_row("")

        # Metadata
        icon = cls._get_category_icon(template.category)
        table.add_row(f"{icon} Category: [cyan]{template.category.upper()}[/]  |  ⏱ Time: [yellow]{template.estimated_time}[/]")

        # Tags
        if template.tags:
            tags_str = " ".join([f"[magenta]#{tag}[/]" for tag in template.tags])
            table.add_row(f"Tags: {tags_str}")

        table.add_row("")

        # Command template (with syntax highlighting)
        table.add_row("[bold]Command Template:[/]")
        table.add_row(f"[bright_black]$ [/][green]{template.command}[/]")
        table.add_row("")

        # Variables section
        if template.variables:
            table.add_row("[bold]Required Variables:[/]")
            for var in template.variables:
                var_name = var['name']
                var_desc = var.get('description', '')
                var_example = var.get('example', '')
                var_required = var.get('required', True)

                # Show filled value if available
                if filled_values and var_name in filled_values:
                    filled_value = filled_values[var_name]
                    table.add_row(f"  • [cyan]{var_name}[/]: [green]{filled_value}[/] ✓")
                else:
                    req_indicator = "[red]*[/]" if var_required else "[dim](optional)[/]"
                    var_line = f"  • [cyan]{var_name}[/] {req_indicator}"
                    if var_desc:
                        var_line += f" - {var_desc}"
                    if var_example:
                        var_line += f" [dim]e.g., {var_example}[/]"
                    table.add_row(var_line)

            table.add_row("")

        # Flag explanations
        if template.flag_explanations:
            table.add_row("[bold]Flag Explanations:[/]")
            for flag, explanation in template.flag_explanations.items():
                table.add_row(f"  • [yellow]{flag}[/]: {explanation}")
            table.add_row("")

        # Filled command preview (if values provided)
        if filled_values:
            try:
                final_command = template.fill(filled_values)
                table.add_row("[bold]Final Command:[/]")
                table.add_row(f"[bright_black]$ [/][bright_green]{final_command}[/]")
                table.add_row("")
            except Exception as e:
                table.add_row(f"[red]Error filling template: {e}[/]")
                table.add_row("")

        # Success indicators
        if template.success_indicators:
            table.add_row("[bold]Success Indicators:[/]")
            for indicator in template.success_indicators:
                table.add_row(f"  ✓ {indicator}")
            table.add_row("")

        # Manual alternatives
        if template.alternatives:
            table.add_row("[bold]Manual Alternatives:[/]")
            for alt in template.alternatives:
                # Fill alternatives with values if available
                if filled_values:
                    alt_filled = alt
                    for key, value in filled_values.items():
                        alt_filled = alt_filled.replace(f"<{key}>", value)
                    table.add_row(f"  • [dim]{alt_filled}[/]")
                else:
                    table.add_row(f"  • [dim]{alt}[/]")
            table.add_row("")

        # Execution result (if available)
        if execution_result:
            exit_code = execution_result.get('exit_code', 1)
            elapsed = execution_result.get('elapsed', 0.0)
            output_lines = execution_result.get('output_lines', [])

            if exit_code == 0:
                table.add_row(f"[bold green]✓ Execution successful[/] [dim]({elapsed:.2f}s)[/]")
            else:
                table.add_row(f"[bold red]✗ Execution failed[/] [dim](exit code: {exit_code}, {elapsed:.2f}s)[/]")

            # Show first/last few lines of output
            if output_lines:
                table.add_row("")
                table.add_row("[bold]Output Preview:[/]")
                preview_lines = output_lines[:3] + ['...'] + output_lines[-3:] if len(output_lines) > 6 else output_lines
                for line in preview_lines:
                    table.add_row(f"[dim]{line}[/]")

            table.add_row("")

        # Build action menu
        choices = cls._build_action_menu(table, template, filled_values, execution_result)

        # Build panel
        breadcrumb = f"Dashboard > Scan Templates > {template.name}"
        panel = Panel(
            table,
            title=f"[bold cyan]{breadcrumb}[/]",
            border_style="cyan",
            box=box.ROUNDED
        )

        return panel, choices

    @classmethod
    def _build_action_menu(
        cls,
        table: Table,
        template,
        filled_values: Optional[Dict[str, str]],
        execution_result: Optional[Dict[str, Any]]
    ) -> List[Dict]:
        """
        Build context-aware action menu

        Args:
            table: Table to add menu items to
            template: CommandTemplate instance
            filled_values: Filled variable values (if any)
            execution_result: Execution result (if any)

        Returns:
            List of choice dictionaries
        """
        choices = []

        # Add separator
        table.add_row("[dim]" + "─" * 80 + "[/]")

        # If variables not filled yet, offer to fill them
        if not filled_values:
            table.add_row(f"[bold bright_white]f.[/] Fill variables and preview command")
            choices.append({
                'id': 'f',
                'label': 'Fill variables',
                'action': 'fill_variables',
                'template': template
            })

        # If variables are filled, offer execution
        if filled_values and not execution_result:
            # Check if all required variables are filled
            required_vars = [v['name'] for v in template.variables if v.get('required', True)]
            all_filled = all(var in filled_values for var in required_vars)

            if all_filled:
                table.add_row(f"[bold bright_white]e.[/] Execute command")
                choices.append({
                    'id': 'e',
                    'label': 'Execute command',
                    'action': 'execute',
                    'template': template,
                    'filled_values': filled_values
                })

                table.add_row(f"[bold bright_white]c.[/] Copy command to clipboard")
                choices.append({
                    'id': 'c',
                    'label': 'Copy to clipboard',
                    'action': 'copy',
                    'template': template,
                    'filled_values': filled_values
                })

                table.add_row(f"[bold bright_white]r.[/] Reset and re-enter variables")
                choices.append({
                    'id': 'r',
                    'label': 'Reset variables',
                    'action': 'reset'
                })
            else:
                table.add_row(f"[red]⚠ Not all required variables are filled[/]")
                table.add_row(f"[bold bright_white]f.[/] Fill remaining variables")
                choices.append({
                    'id': 'f',
                    'label': 'Fill variables',
                    'action': 'fill_variables',
                    'template': template
                })

        # If execution completed, offer to view full output
        if execution_result:
            table.add_row(f"[bold bright_white]v.[/] View full output")
            choices.append({
                'id': 'v',
                'label': 'View full output',
                'action': 'view_output',
                'execution_result': execution_result
            })

            table.add_row(f"[bold bright_white]s.[/] Save output to file")
            choices.append({
                'id': 's',
                'label': 'Save output',
                'action': 'save_output',
                'execution_result': execution_result
            })

            table.add_row(f"[bold bright_white]r.[/] Run again")
            choices.append({
                'id': 'r',
                'label': 'Run again',
                'action': 'reset'
            })

        # Always show back option
        table.add_row(f"[bold bright_white]b.[/] Back to template browser")
        choices.append({
            'id': 'b',
            'label': 'Back to browser',
            'action': 'back'
        })

        return choices

    @classmethod
    def _get_category_icon(cls, category: str) -> str:
        """
        Get emoji icon for category

        Args:
            category: Template category

        Returns:
            Emoji icon string
        """
        icons = {
            'recon': '🔍',
            'web': '🌐',
            'enumeration': '📋',
            'exploitation': '💥'
        }
        return icons.get(category.lower(), '•')
