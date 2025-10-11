"""
Status Overlay - Quick status summary (s shortcut)

Shows:
- Target and phase info
- Progress statistics
- Discovered ports (with services)
- Findings breakdown
- Credentials count
- Time elapsed (if tracked)

Non-state-changing overlay - dismisses on keypress.
"""

from datetime import datetime
from typing import Optional
from rich.panel import Panel
from rich.table import Table
from rich import box


class StatusOverlay:
    """Status information overlay"""

    @classmethod
    def render(cls, profile, theme=None) -> Panel:
        """
        Render status overlay panel

        Args:
            profile: TargetProfile instance
            theme: ThemeManager instance (optional for backward compat)

        Returns:
            Rich Panel for overlay display
        """
        # Fallback theme for backward compatibility
        if theme is None:
            from ..themes import ThemeManager
            theme = ThemeManager()
        # Get progress data
        progress = profile.get_progress()
        total = progress['total']
        completed = progress['completed']
        pending = progress['pending']
        pct = int((completed / total * 100) if total > 0 else 0)

        # Build status table
        table = Table(show_header=False, box=None, padding=(0, 2))
        label_style = f"bold {theme.get_color('primary')}"
        table.add_column("Label", style=label_style, width=20)
        table.add_column("Value", style=theme.get_color('text'))

        # Basic info
        table.add_row("Target:", profile.target)
        table.add_row("Phase:", profile.phase.replace('-', ' ').title())
        table.add_row("Status:", profile.status.title())
        table.add_row("", "")

        # Progress
        table.add_row("Progress:", f"{completed}/{total} tasks ({pct}%)")
        table.add_row("  Completed:", theme.success(str(completed)))
        table.add_row("  Pending:", theme.warning(str(pending)))
        table.add_row("  In-Progress:", theme.primary(str(progress.get('in_progress', 0))))
        table.add_row("", "")

        # Ports
        port_count = len(profile.ports)
        table.add_row("Ports Discovered:", f"{port_count}")

        if profile.ports:
            # Show first 5 ports with details
            from ..themes.helpers import format_port_state
            sorted_ports = sorted(profile.ports.keys())[:5]
            for port in sorted_ports:
                info = profile.ports[port]
                service = info.get('service', 'unknown')
                version = info.get('version', '')
                state = info.get('state', 'unknown')

                # Format port line with theme colors
                port_line = format_port_state(theme, port, state, service, version)
                table.add_row("", f"  • {port_line}")

            if port_count > 5:
                table.add_row("", theme.muted(f"  ... and {port_count - 5} more"))

        table.add_row("", "")

        # Findings
        finding_count = len(profile.findings)
        table.add_row("Findings:", f"{finding_count}")

        if profile.findings:
            # Count by type
            from ..themes.helpers import format_finding_type
            finding_types = {}
            for finding in profile.findings:
                f_type = finding.get('type', 'general')
                finding_types[f_type] = finding_types.get(f_type, 0) + 1

            for f_type, count in finding_types.items():
                formatted = format_finding_type(theme, f_type, count)
                table.add_row("", f"  {formatted}")

        table.add_row("", "")

        # Credentials
        cred_count = len(profile.credentials)
        table.add_row("Credentials:", theme.warning(str(cred_count)))

        table.add_row("", "")

        # Time tracking
        created_time = cls._parse_timestamp(profile.created)
        updated_time = cls._parse_timestamp(profile.updated)

        if created_time:
            table.add_row("Created:", created_time.strftime("%Y-%m-%d %H:%M"))
        if updated_time:
            table.add_row("Last Updated:", updated_time.strftime("%Y-%m-%d %H:%M"))

            # Calculate elapsed time
            if created_time:
                elapsed = updated_time - created_time
                hours = int(elapsed.total_seconds() // 3600)
                minutes = int((elapsed.total_seconds() % 3600) // 60)
                table.add_row("Time Elapsed:", f"{hours}h {minutes}m")

        return Panel(
            table,
            title=f"[bold {theme.get_color('success')}]Quick Status[/]",
            subtitle=theme.muted("Press any key to close"),
            border_style=theme.overlay_border(),
            box=box.ROUNDED
        )

    @classmethod
    def _get_finding_icon(cls, finding_type: str) -> str:
        """Get icon for finding type"""
        icons = {
            'vulnerability': '🔓',
            'directory': '📁',
            'credential': '🔑',
            'user': '👤',
            'note': '📝',
            'general': '•'
        }
        return icons.get(finding_type, '•')

    @classmethod
    def _parse_timestamp(cls, timestamp_str: str) -> Optional[datetime]:
        """Parse ISO timestamp string"""
        if not timestamp_str:
            return None

        try:
            return datetime.fromisoformat(timestamp_str)
        except (ValueError, TypeError):
            return None
