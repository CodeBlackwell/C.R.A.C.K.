"""
Findings Panel - Display and manage enumeration findings

Shows findings discovered during enumeration with filtering, pagination, and export.
Follows hub-spoke navigation - this is a spoke panel.
"""

from typing import Dict, Any, List, Tuple
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich import box
from rich.text import Text
from datetime import datetime


class FindingsPanel:
    """Findings panel with filtering and pagination"""

    # Items per page for pagination
    ITEMS_PER_PAGE = 10

    @classmethod
    def render(
        cls,
        profile,  # TargetProfile instance
        filter_type: str = 'all',
        page: int = 1
    ) -> Tuple[Panel, List[Dict]]:
        """
        Render findings panel with filtering and pagination

        Args:
            profile: TargetProfile instance with findings data
            filter_type: Filter by type ('all', 'vulnerability', 'directory', 'credential', 'user', 'note')
            page: Current page number (1-indexed)

        Returns:
            Tuple of (Panel, action choices list)
        """
        # Get findings from profile
        all_findings = profile.findings if hasattr(profile, 'findings') else []

        # Sort by timestamp (newest first)
        sorted_findings = sorted(
            all_findings,
            key=lambda f: f.get('timestamp', ''),
            reverse=True
        )

        # Filter findings
        filtered_findings = cls._filter_findings(sorted_findings, filter_type)

        # Calculate pagination
        total_findings = len(filtered_findings)
        total_pages = max(1, (total_findings + cls.ITEMS_PER_PAGE - 1) // cls.ITEMS_PER_PAGE)
        current_page = max(1, min(page, total_pages))

        # Get findings for current page
        start_idx = (current_page - 1) * cls.ITEMS_PER_PAGE
        end_idx = start_idx + cls.ITEMS_PER_PAGE
        page_findings = filtered_findings[start_idx:end_idx]

        # Build panel content
        table = cls._build_findings_table(page_findings, start_idx)

        # Build action menu
        choices = cls._build_action_menu(
            table,
            total_findings,
            current_page,
            total_pages,
            filter_type,
            page_findings
        )

        # Build subtitle with stats
        if filter_type == 'all':
            subtitle = f"Total: {total_findings} findings"
        else:
            subtitle = f"Showing {total_findings} {filter_type} findings"

        if total_pages > 1:
            subtitle += f" | Page {current_page}/{total_pages}"

        # Build panel
        breadcrumb = "Dashboard > Findings"
        panel = Panel(
            table,
            title=f"[bold cyan]{breadcrumb}[/]",
            subtitle=f"[dim]{subtitle}[/]",
            border_style="cyan",
            box=box.ROUNDED
        )

        return panel, choices

    @classmethod
    def _build_findings_table(cls, findings: List[Dict], start_idx: int) -> Table:
        """
        Build findings table with formatted columns

        Args:
            findings: List of findings for current page
            start_idx: Starting index for numbering

        Returns:
            Rich Table with findings
        """
        table = Table(show_header=True, box=box.SIMPLE, padding=(0, 1))
        table.add_column("#", style="dim", width=3, justify="right")
        table.add_column("Type", style="white", width=15)
        table.add_column("Description", style="white", width=50)
        table.add_column("Source", style="bright_black", width=25)
        table.add_column("Time", style="bright_black", width=12)

        if not findings:
            # Empty state
            table.add_row("", "", "[dim italic]No findings yet - start enumeration to discover vulnerabilities[/]", "", "")
            return table

        # Add findings to table
        for idx, finding in enumerate(findings, start=start_idx + 1):
            finding_type = finding.get('type', 'general')
            description = finding.get('description', 'N/A')
            source = finding.get('source', 'N/A')
            timestamp = finding.get('timestamp', '')

            # Get icon for type
            icon = cls._get_finding_icon(finding_type)
            type_display = f"{icon} {finding_type.capitalize()}"

            # Truncate long descriptions
            description_display = cls._truncate(description, 48)
            source_display = cls._truncate(source, 23)

            # Format timestamp (show relative time)
            time_display = cls._format_timestamp(timestamp)

            # Add row with proper styling
            table.add_row(
                str(idx),
                type_display,
                description_display,
                source_display,
                time_display
            )

        return table

    @classmethod
    def _build_action_menu(
        cls,
        table: Table,
        total_findings: int,
        current_page: int,
        total_pages: int,
        filter_type: str,
        page_findings: List[Dict]
    ) -> List[Dict]:
        """
        Build context-aware action menu

        Args:
            table: Table to add menu items to
            total_findings: Total number of filtered findings
            current_page: Current page number
            total_pages: Total number of pages
            filter_type: Current filter type
            page_findings: Findings on current page

        Returns:
            List of choice dictionaries
        """
        choices = []

        # Add blank line before menu
        table.add_row("", "", "", "", "")

        # Selection options (only if findings exist)
        if page_findings:
            num_items = len(page_findings)
            range_text = f"1-{num_items}" if num_items > 1 else "1"
            table.add_row("", "", f"[bold bright_white]{range_text}.[/] Select finding (view details)", "", "")

            # Add choices for each finding
            for idx, finding in enumerate(page_findings, start=1):
                choices.append({
                    'id': str(idx),
                    'label': f'View finding {idx}',
                    'action': 'view',
                    'finding': finding
                })

        # Filter option
        table.add_row("", "", f"[bold bright_white]f.[/] Filter by type (current: {filter_type})", "", "")
        choices.append({
            'id': 'f',
            'label': 'Filter by type',
            'action': 'filter',
            'current_filter': filter_type
        })

        # Export options (only if findings exist)
        if total_findings > 0:
            table.add_row("", "", f"[bold bright_white]e.[/] Export findings (Markdown/JSON)", "", "")
            choices.append({
                'id': 'e',
                'label': 'Export findings',
                'action': 'export'
            })

            # Correlate findings (future feature - placeholder)
            table.add_row("", "", f"[bold bright_white]c.[/] Correlate findings [dim](coming soon)[/]", "", "")
            choices.append({
                'id': 'c',
                'label': 'Correlate findings',
                'action': 'correlate'
            })

        # Pagination controls (only if multiple pages)
        if total_pages > 1:
            table.add_row("", "", "", "", "")

            if current_page < total_pages:
                table.add_row("", "", f"[bold bright_white]n.[/] Next page ({current_page + 1}/{total_pages})", "", "")
                choices.append({
                    'id': 'n',
                    'label': 'Next page',
                    'action': 'next_page',
                    'page': current_page + 1
                })

            if current_page > 1:
                table.add_row("", "", f"[bold bright_white]p.[/] Previous page ({current_page - 1}/{total_pages})", "", "")
                choices.append({
                    'id': 'p',
                    'label': 'Previous page',
                    'action': 'prev_page',
                    'page': current_page - 1
                })

        # Always show back option
        table.add_row("", "", f"[bold bright_white]b.[/] Back to dashboard", "", "")
        choices.append({
            'id': 'b',
            'label': 'Back to dashboard',
            'action': 'back'
        })

        return choices

    @classmethod
    def _get_finding_icon(cls, finding_type: str) -> str:
        """
        Get emoji icon for finding type

        Args:
            finding_type: Type of finding

        Returns:
            Emoji icon string
        """
        icons = {
            'vulnerability': '🔓',
            'directory': '📁',
            'credential': '🔑',
            'user': '👤',
            'note': '📝'
        }
        return icons.get(finding_type.lower(), '•')

    @classmethod
    def _filter_findings(cls, findings: List[Dict], filter_type: str) -> List[Dict]:
        """
        Filter findings by type

        Args:
            findings: List of all findings
            filter_type: Filter type ('all' or specific type)

        Returns:
            Filtered findings list
        """
        if filter_type == 'all':
            return findings

        return [f for f in findings if f.get('type', '').lower() == filter_type.lower()]

    @classmethod
    def _truncate(cls, text: str, max_len: int) -> str:
        """
        Truncate long text with ellipsis

        Args:
            text: Text to truncate
            max_len: Maximum length

        Returns:
            Truncated text
        """
        if len(text) <= max_len:
            return text
        return text[:max_len-3] + "..."

    @classmethod
    def _format_timestamp(cls, timestamp: str) -> str:
        """
        Format timestamp to relative time or short format

        Args:
            timestamp: ISO format timestamp string

        Returns:
            Formatted time string
        """
        if not timestamp:
            return "Unknown"

        try:
            # Parse ISO timestamp
            dt = datetime.fromisoformat(timestamp)
            now = datetime.now()
            delta = now - dt

            # Format as relative time for recent findings
            if delta.total_seconds() < 60:
                return "Just now"
            elif delta.total_seconds() < 3600:
                mins = int(delta.total_seconds() / 60)
                return f"{mins}m ago"
            elif delta.total_seconds() < 86400:
                hours = int(delta.total_seconds() / 3600)
                return f"{hours}h ago"
            elif delta.days < 7:
                return f"{delta.days}d ago"
            else:
                # Fall back to date format
                return dt.strftime("%Y-%m-%d")
        except (ValueError, AttributeError):
            # If parsing fails, show first 10 chars
            return timestamp[:10] if len(timestamp) >= 10 else timestamp
