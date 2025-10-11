"""
Profile Detail Overlay - Full scan profile information view

Shows complete profile details including:
- All flag explanations
- Success/failure indicators
- Alternative approaches
- Next steps
- OSCP-specific notes
"""

from typing import Dict, Any, Optional
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text


class ProfileDetailOverlay:
    """Display comprehensive scan profile details"""

    @classmethod
    def render(cls, profile: Dict[str, Any], theme=None) -> Panel:
        """Render complete profile details overlay

        Args:
            profile: Scan profile dictionary with all metadata
            theme: ThemeManager instance (optional)

        Returns:
            Panel with complete profile information
        """
        # Initialize theme if not provided
        if theme is None:
            from ..themes import ThemeManager
            theme = ThemeManager()

        # Build content table
        table = Table(show_header=False, box=None, padding=(0, 1), expand=True)
        table.add_column("Content", style="white")

        # Profile header
        profile_name = profile.get('name', 'Unknown Profile')
        profile_id = profile.get('id', 'unknown')
        table.add_row(f"[bold {theme.get_color('primary')}]{profile_name}[/]")
        table.add_row(f"{theme.muted(f'Profile ID: {profile_id}')}")
        table.add_row("")  # Blank line

        # Use case
        use_case = profile.get('use_case', 'N/A')
        table.add_row(f"[bold {theme.get_color('success')}]Use Case:[/]")
        table.add_row(f"  {use_case}")
        table.add_row("")

        # Command
        base_command = profile.get('base_command', 'N/A')
        table.add_row(f"[bold {theme.get_color('success')}]Command:[/]")
        table.add_row(f"  {theme.primary(base_command)}")
        table.add_row("")

        # Metadata badges
        estimated_time = profile.get('estimated_time', 'Unknown')
        detection_risk = profile.get('detection_risk', 'medium')
        tags = profile.get('tags', [])

        # OSCP priority
        oscp_priority = None
        if 'OSCP:HIGH' in tags:
            oscp_priority = f"[bold {theme.get_color('success')}]🎯 OSCP:HIGH[/] (Exam-critical)"
        elif 'OSCP:MEDIUM' in tags:
            oscp_priority = f"[{theme.get_color('warning')}]🎯 OSCP:MEDIUM[/] (Useful)"

        # Detection risk (color-coded)
        risk_colors = {
            'very-low': theme.get_color('success'),
            'low': theme.get_color('success'),
            'medium': theme.get_color('warning'),
            'high': theme.get_color('danger'),
            'very-high': theme.get_color('danger')
        }
        risk_color = risk_colors.get(detection_risk, theme.get_color('muted'))
        risk_text = detection_risk.upper().replace('-', ' ')

        table.add_row(f"[bold {theme.get_color('success')}]Details:[/]")
        table.add_row(f"  ⏱ Time: {estimated_time}")
        table.add_row(f"  🔔 Detection Risk: [{risk_color}]{risk_text}[/]")
        if oscp_priority:
            table.add_row(f"  {oscp_priority}")
        table.add_row("")

        # Flag explanations (ALL flags, not just first 2)
        flag_explanations = profile.get('flag_explanations', {})
        if flag_explanations:
            table.add_row(f"[bold {theme.get_color('success')}]Flag Explanations:[/]")
            for flag, explanation in flag_explanations.items():
                # Wrap long explanations
                if len(explanation) > 70:
                    # Split into multiple lines
                    words = explanation.split()
                    current_line = []
                    for word in words:
                        test_line = ' '.join(current_line + [word])
                        if len(test_line) <= 70:
                            current_line.append(word)
                        else:
                            table.add_row(f"  {theme.primary(flag)}: {' '.join(current_line)}")
                            current_line = [word]
                    if current_line:
                        table.add_row(f"    {' '.join(current_line)}")
                else:
                    table.add_row(f"  {theme.primary(flag)}: {explanation}")
            table.add_row("")

        # Success indicators
        success_indicators = profile.get('success_indicators', [])
        if success_indicators:
            table.add_row(f"[bold {theme.get_color('success')}]✓ Success Indicators:[/]")
            for indicator in success_indicators:
                table.add_row(f"  • {indicator}")
            table.add_row("")

        # Failure indicators
        failure_indicators = profile.get('failure_indicators', [])
        if failure_indicators:
            table.add_row(f"[bold {theme.get_color('danger')}]✗ Failure Indicators:[/]")
            for indicator in failure_indicators:
                table.add_row(f"  • {indicator}")
            table.add_row("")

        # Alternatives
        alternatives = profile.get('alternatives', [])
        if alternatives:
            table.add_row(f"[bold {theme.get_color('warning')}]Alternative Approaches:[/]")
            for alt in alternatives:
                table.add_row(f"  • {alt}")
            table.add_row("")

        # Next steps
        next_steps = profile.get('next_steps', [])
        if next_steps:
            table.add_row(f"[bold {theme.get_color('primary')}]Next Steps:[/]")
            for step in next_steps:
                table.add_row(f"  • {step}")
            table.add_row("")

        # OSCP notes (critical information)
        notes = profile.get('notes', '')
        if notes:
            table.add_row(f"[bold {theme.get_color('warning')}]OSCP Notes:[/]")
            # Wrap notes if too long
            if len(notes) > 80:
                words = notes.split()
                current_line = []
                for word in words:
                    test_line = ' '.join(current_line + [word])
                    if len(test_line) <= 80:
                        current_line.append(word)
                    else:
                        table.add_row(f"  {' '.join(current_line)}")
                        current_line = [word]
                if current_line:
                    table.add_row(f"  {' '.join(current_line)}")
            else:
                table.add_row(f"  {notes}")
            table.add_row("")

        # Footer hint
        table.add_row("")
        table.add_row(f"[dim]{theme.muted('Press any key to close | Press number to select this profile')}[/]")

        # Build panel
        return Panel(
            table,
            title=f"[bold {theme.get_color('primary')}]📋 Profile Details[/]",
            border_style=theme.panel_border(),
            box=box.ROUNDED,
            padding=(1, 2)
        )
