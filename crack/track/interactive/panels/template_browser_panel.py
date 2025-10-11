"""
Template Browser Panel - Browse and select OSCP command templates

Displays pre-configured command templates with category filtering.
Follows hub-spoke navigation - this is a spoke panel.
"""

from typing import Dict, Any, List, Tuple
from rich.panel import Panel
from rich.table import Table
from rich import box


class TemplateBrowserPanel:
    """Template browser panel with category filtering"""

    # Items per page for pagination
    ITEMS_PER_PAGE = 12

    @classmethod
    def render(
        cls,
        category: str = 'all',
        page: int = 1,
        theme=None
    ) -> Tuple[Panel, List[Dict]]:
        """
        Render template browser panel with category filtering

        Args:
            category: Filter by category ('all', 'recon', 'web', 'enumeration', 'exploitation')
            page: Current page number (1-indexed)
            theme: ThemeManager instance (optional for backward compat)

        Returns:
            Tuple of (Panel, action choices list)
        """
        # Fallback theme for backward compatibility
        if theme is None:
            from ..themes import ThemeManager
            theme = ThemeManager()
        from ..templates import TemplateRegistry

        # Get all templates
        all_templates = TemplateRegistry.list_all()

        # Filter by category
        if category == 'all':
            filtered_templates = all_templates
        else:
            filtered_templates = [t for t in all_templates if t.category.lower() == category.lower()]

        # Sort by category, then by name
        sorted_templates = sorted(
            filtered_templates,
            key=lambda t: (t.category, t.name)
        )

        # Calculate pagination
        total_templates = len(sorted_templates)
        total_pages = max(1, (total_templates + cls.ITEMS_PER_PAGE - 1) // cls.ITEMS_PER_PAGE)
        current_page = max(1, min(page, total_pages))

        # Get templates for current page
        start_idx = (current_page - 1) * cls.ITEMS_PER_PAGE
        end_idx = start_idx + cls.ITEMS_PER_PAGE
        page_templates = sorted_templates[start_idx:end_idx]

        # Build panel content
        table = cls._build_templates_table(page_templates, start_idx, theme)

        # Build action menu
        choices = cls._build_action_menu(
            table,
            total_templates,
            current_page,
            total_pages,
            category,
            page_templates,
            theme
        )

        # Build subtitle with stats
        if category == 'all':
            subtitle = f"Total: {total_templates} templates"
        else:
            subtitle = f"Showing {total_templates} {category} templates"

        if total_pages > 1:
            subtitle += f" | Page {current_page}/{total_pages}"

        # Build panel
        from ..themes.helpers import format_panel_title
        breadcrumb = "Dashboard > Scan Templates"
        panel = Panel(
            table,
            title=format_panel_title(theme, breadcrumb),
            subtitle=theme.muted(subtitle),
            border_style=theme.panel_border(),
            box=box.ROUNDED
        )

        return panel, choices

    @classmethod
    def _build_templates_table(cls, templates: List[Any], start_idx: int, theme) -> Table:
        """
        Build templates table with formatted columns

        Args:
            templates: List of CommandTemplate instances for current page
            start_idx: Starting index for numbering
            theme: ThemeManager instance

        Returns:
            Rich Table with templates
        """
        table = Table(show_header=True, box=box.SIMPLE, padding=(0, 1))
        table.add_column("#", style=theme.get_color('muted'), width=3, justify="right")
        table.add_column("Name", style=theme.get_color('text'), width=30)
        table.add_column("Description", style=theme.get_color('text'), width=45)
        table.add_column("Category", style=theme.get_color('muted'), width=12)
        table.add_column("Time", style=theme.get_color('muted'), width=8)

        if not templates:
            # Empty state
            table.add_row("", "", theme.muted("[italic]No templates found for this category[/]"), "", "")
            return table

        # Add templates to table
        for idx, template in enumerate(templates, start=start_idx + 1):
            name = template.name
            description = template.description
            category = template.category.upper()
            time_est = template.estimated_time

            # Get icon for category
            icon = cls._get_category_icon(template.category)
            category_display = f"{icon} {category}"

            # Truncate long descriptions
            description_display = cls._truncate(description, 43)

            # Add OSCP:HIGH indicator if tagged
            if any('OSCP:HIGH' in tag for tag in template.tags):
                name = f"⭐ {name}"

            # Add QUICK_WIN indicator if tagged
            if 'QUICK_WIN' in template.tags:
                name = f"⚡ {name}"

            # Add row with proper styling
            table.add_row(
                str(idx),
                name,
                description_display,
                category_display,
                time_est
            )

        return table

    @classmethod
    def _build_action_menu(
        cls,
        table: Table,
        total_templates: int,
        current_page: int,
        total_pages: int,
        category: str,
        page_templates: List[Any],
        theme
    ) -> List[Dict]:
        """
        Build context-aware action menu

        Args:
            table: Table to add menu items to
            total_templates: Total number of filtered templates
            current_page: Current page number
            total_pages: Total number of pages
            category: Current category filter
            page_templates: Templates on current page
            theme: ThemeManager instance

        Returns:
            List of choice dictionaries
        """
        from ..themes.helpers import format_menu_number, format_hotkey
        choices = []

        # Add blank line before menu
        table.add_row("", "", "", "", "")

        # Selection options (only if templates exist)
        if page_templates:
            num_items = len(page_templates)
            range_text = f"1-{num_items}" if num_items > 1 else "1"
            table.add_row("", "", f"{theme.emphasis(range_text + '.')} Select template", "", "")

            # Add choices for each template
            for idx, template in enumerate(page_templates, start=1):
                choices.append({
                    'id': str(idx),
                    'label': f'Select template: {template.name}',
                    'action': 'select',
                    'template': template
                })

        # Category filter option
        table.add_row("", "", f"{format_hotkey(theme, 'c')}. Change category {theme.muted(f'(current: {category})')}", "", "")
        choices.append({
            'id': 'c',
            'label': 'Change category',
            'action': 'filter_category',
            'current_category': category
        })

        # Search option
        table.add_row("", "", f"{format_hotkey(theme, 's')}. Search templates by keyword", "", "")
        choices.append({
            'id': 's',
            'label': 'Search templates',
            'action': 'search'
        })

        # Pagination controls (only if multiple pages)
        if total_pages > 1:
            table.add_row("", "", "", "", "")

            if current_page < total_pages:
                table.add_row("", "", f"{format_hotkey(theme, 'n')}. Next page {theme.muted(f'({current_page + 1}/{total_pages})')}", "", "")
                choices.append({
                    'id': 'n',
                    'label': 'Next page',
                    'action': 'next_page',
                    'page': current_page + 1
                })

            if current_page > 1:
                table.add_row("", "", f"{format_hotkey(theme, 'p')}. Previous page {theme.muted(f'({current_page - 1}/{total_pages})')}", "", "")
                choices.append({
                    'id': 'p',
                    'label': 'Previous page',
                    'action': 'prev_page',
                    'page': current_page - 1
                })

        # Always show back option
        table.add_row("", "", f"{format_hotkey(theme, 'b')}. Back to dashboard", "", "")
        choices.append({
            'id': 'b',
            'label': 'Back to dashboard',
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
