"""
Finding Entry Form Panel - Structured vulnerability/discovery documentation

Features:
- Multi-field form (type, description, source, port, severity, impact)
- Type dropdown (vulnerability, directory, credential, user, note, general)
- Severity dropdown (critical, high, medium, low, info)
- Required source field (OSCP compliance)
- Multi-line description support
- Input validation with real-time feedback
- Save to profile.findings

Follows hub-spoke navigation - this is a spoke panel.
"""

from typing import Dict, Any, Optional, Tuple, List
from rich.panel import Panel
from rich.table import Table
from rich import box


class FindingFormPanel:
    """Finding entry form rendering and input processing"""

    # Finding type options
    FINDING_TYPES = [
        'vulnerability',
        'directory',
        'credential',
        'user',
        'note',
        'general'
    ]

    # Severity levels
    SEVERITY_LEVELS = [
        'critical',
        'high',
        'medium',
        'low',
        'info'
    ]

    # Severity colors for display
    SEVERITY_COLORS = {
        'critical': 'bright_red',
        'high': 'red',
        'medium': 'yellow',
        'low': 'bright_blue',
        'info': 'white'
    }

    # Field definitions (name, label, required, type)
    FIELDS = [
        ('type', 'Type', True, 'dropdown'),
        ('description', 'Description', True, 'text'),
        ('source', 'Source (REQUIRED)', True, 'text'),
        ('port', 'Port (optional)', False, 'numeric'),
        ('severity', 'Severity (optional)', False, 'dropdown'),
        ('impact', 'Impact (optional)', False, 'text')
    ]

    def __init__(self, profile):
        """
        Initialize finding form

        Args:
            profile: TargetProfile instance
        """
        self.profile = profile
        self.form_data: Dict[str, Any] = {
            'type': '',
            'description': '',
            'source': '',
            'port': '',
            'severity': '',
            'impact': ''
        }
        self.current_field = 0  # Index into FIELDS
        self.validation_errors: Dict[str, str] = {}
        self.saved = False  # Track if finding was saved

    @classmethod
    def create(cls, profile) -> 'FindingFormPanel':
        """
        Factory method to create new form instance

        Args:
            profile: TargetProfile instance

        Returns:
            New FindingFormPanel instance
        """
        return cls(profile)

    def render(self) -> Tuple[Panel, List[Dict]]:
        """
        Render finding entry form

        Returns:
            Tuple of (Rich Panel, choices list for input processing)
        """
        # Build form table
        form_table = Table(show_header=False, box=None, padding=(0, 2))
        form_table.add_column("Label", style="white", width=25)
        form_table.add_column("Input", style="white", width=50)

        # Add header
        form_table.add_row(
            "[bold bright_cyan]FINDING ENTRY FORM[/]",
            ""
        )
        form_table.add_row("[dim]Document vulnerabilities and discoveries[/]", "")
        form_table.add_row("", "")  # Blank line

        # Render each field
        for idx, (field_name, label, required, field_type) in enumerate(self.FIELDS):
            self._render_field(form_table, idx, field_name, label, required, field_type)

        # Add spacing
        form_table.add_row("", "")

        # Add validation summary if errors
        if self.validation_errors:
            error_text = "[bold red]Validation Errors:[/]"
            for field, error in self.validation_errors.items():
                error_text += f"\n  • {field}: {error}"
            form_table.add_row("", error_text)
            form_table.add_row("", "")

        # Add success message if saved
        if self.saved:
            form_table.add_row(
                "",
                "[bold green]✓ Finding saved successfully![/]"
            )
            form_table.add_row("", "")

        # Build action menu
        choices = self._build_action_menu(form_table)

        # Build panel
        breadcrumb = "Dashboard > Add Finding"
        title = f"[bold cyan]{breadcrumb}[/]"
        subtitle = f"[dim]Target: {self.profile.target} | Field {self.current_field + 1}/{len(self.FIELDS)}[/]"

        return Panel(
            form_table,
            title=title,
            subtitle=subtitle,
            border_style="cyan",
            box=box.ROUNDED
        ), choices

    def _render_field(
        self,
        table: Table,
        idx: int,
        field_name: str,
        label: str,
        required: bool,
        field_type: str
    ):
        """
        Render individual form field

        Args:
            table: Table to add row to
            idx: Field index
            field_name: Field name in form_data
            label: Display label
            required: Whether field is required
            field_type: Field type (text, numeric, dropdown)
        """
        # Highlight current field
        is_current = (idx == self.current_field)

        # Build label with required indicator
        label_text = label
        if required:
            label_text += " *"

        # Style based on current/error state
        if is_current:
            label_style = "[bold bright_white]"
            indicator = "►"
        else:
            label_style = "[white]"
            indicator = " "

        # Add error indicator
        if field_name in self.validation_errors:
            label_style = "[bold red]"
            indicator = "✗"

        # Get field value
        value = self.form_data.get(field_name, '')

        # Format value based on field type
        if field_type == 'dropdown' and not value:
            # Show placeholder for dropdown
            display_value = "[dim](press Enter to select)[/]"
        elif field_name == 'description' and value:
            # Truncate long descriptions
            display_value = self._truncate_description(value, 50)
        elif field_name == 'severity' and value:
            # Show severity with color
            color = self.SEVERITY_COLORS.get(value, 'white')
            display_value = f"[{color}]{value.upper()}[/]"
        else:
            display_value = value if value else "[dim](empty)[/]"

        # Add validation error inline
        if field_name in self.validation_errors:
            display_value += f" [red]← {self.validation_errors[field_name]}[/]"

        # Build the row
        label_cell = f"{indicator} {label_style}{label_text}[/]"

        # Highlight current field input
        if is_current:
            value_cell = f"[bold bright_white]{display_value}[/]"
        else:
            value_cell = display_value

        table.add_row(label_cell, value_cell)

    def _build_action_menu(self, table: Table) -> List[Dict]:
        """
        Build action menu and add to table

        Args:
            table: Table to add actions to

        Returns:
            List of choice dictionaries
        """
        choices = []

        # Navigation instructions
        table.add_row(
            "[bold bright_white]Navigation:[/]",
            ""
        )
        table.add_row("", "[dim]↑/↓ or Tab: Move between fields[/]")
        table.add_row("", "[dim]Enter: Edit current field[/]")
        table.add_row("", "")

        # Actions
        table.add_row("[bold bright_white]Actions:[/]", "")

        table.add_row("", "[bold bright_white]e.[/] Edit current field")
        choices.append({'id': 'edit', 'label': 'Edit current field'})

        table.add_row("", "[bold bright_white]s.[/] Save finding")
        choices.append({'id': 'save', 'label': 'Save finding'})

        table.add_row("", "[bold bright_white]c.[/] Clear form")
        choices.append({'id': 'clear', 'label': 'Clear form'})

        table.add_row("", "[bold bright_white]b.[/] Back to dashboard")
        choices.append({'id': 'back', 'label': 'Back to dashboard'})

        return choices

    def process_input(self, user_input: str) -> str:
        """
        Process user input for form navigation and actions

        Args:
            user_input: Raw user input string

        Returns:
            Action code ('continue', 'back', 'saved', 'edit-field')
        """
        user_input = user_input.strip().lower()

        # Navigation
        if user_input == 'tab' or user_input == 'down':
            self._next_field()
            return 'continue'
        elif user_input == 'up':
            self._prev_field()
            return 'continue'

        # Actions
        elif user_input == 'e' or user_input == 'enter':
            return 'edit-field'
        elif user_input == 's':
            return 'save'
        elif user_input == 'c':
            self._clear_form()
            return 'continue'
        elif user_input == 'b':
            return 'back'
        else:
            # Unknown input - ignore
            return 'continue'

    def edit_current_field(self, new_value: str) -> bool:
        """
        Update current field with new value

        Args:
            new_value: New field value

        Returns:
            True if value is valid and saved
        """
        field_name, label, required, field_type = self.FIELDS[self.current_field]

        # Validate based on field type
        if field_type == 'numeric' and new_value:
            # Validate port number
            try:
                port = int(new_value)
                if port < 1 or port > 65535:
                    self.validation_errors[field_name] = "Port must be 1-65535"
                    return False
            except ValueError:
                self.validation_errors[field_name] = "Must be a number"
                return False

        elif field_type == 'dropdown':
            # Validate dropdown selections
            if field_name == 'type':
                if new_value and new_value.lower() not in self.FINDING_TYPES:
                    self.validation_errors[field_name] = f"Invalid type (use: {', '.join(self.FINDING_TYPES[:3])}...)"
                    return False
            elif field_name == 'severity':
                if new_value and new_value.lower() not in self.SEVERITY_LEVELS:
                    self.validation_errors[field_name] = f"Invalid severity (use: {', '.join(self.SEVERITY_LEVELS)})"
                    return False

        # Clear any previous error for this field
        if field_name in self.validation_errors:
            del self.validation_errors[field_name]

        # Save value
        self.form_data[field_name] = new_value
        return True

    def get_current_field_info(self) -> Dict[str, Any]:
        """
        Get current field metadata for input prompt

        Returns:
            Dict with field_name, label, type, current_value, options (if dropdown)
        """
        field_name, label, required, field_type = self.FIELDS[self.current_field]

        info = {
            'field_name': field_name,
            'label': label,
            'required': required,
            'type': field_type,
            'current_value': self.form_data.get(field_name, '')
        }

        # Add dropdown options
        if field_type == 'dropdown':
            if field_name == 'type':
                info['options'] = self.FINDING_TYPES
            elif field_name == 'severity':
                info['options'] = self.SEVERITY_LEVELS

        return info

    def validate(self) -> bool:
        """
        Validate all form fields

        Returns:
            True if all required fields are filled and valid
        """
        self.validation_errors.clear()

        # Check required fields
        for field_name, label, required, field_type in self.FIELDS:
            value = self.form_data.get(field_name, '').strip()

            if required and not value:
                self.validation_errors[field_name] = "Required field"

        # Validate port if provided
        port_value = self.form_data.get('port', '').strip()
        if port_value:
            try:
                port = int(port_value)
                if port < 1 or port > 65535:
                    self.validation_errors['port'] = "Must be 1-65535"
            except ValueError:
                self.validation_errors['port'] = "Must be a number"

        # Validate type if provided
        type_value = self.form_data.get('type', '').strip()
        if type_value and type_value.lower() not in self.FINDING_TYPES:
            self.validation_errors['type'] = "Invalid type"

        # Validate severity if provided
        severity_value = self.form_data.get('severity', '').strip()
        if severity_value and severity_value.lower() not in self.SEVERITY_LEVELS:
            self.validation_errors['severity'] = "Invalid severity"

        return len(self.validation_errors) == 0

    def save_to_profile(self) -> bool:
        """
        Save finding to profile if validation passes

        Returns:
            True if saved successfully, False otherwise
        """
        if not self.validate():
            return False

        # Build finding dict
        finding_data = {
            'type': self.form_data['type'].lower(),
            'description': self.form_data['description'],
            'source': self.form_data['source']
        }

        # Add optional fields if present
        if self.form_data.get('port'):
            finding_data['port'] = int(self.form_data['port'])

        if self.form_data.get('severity'):
            finding_data['severity'] = self.form_data['severity'].lower()

        if self.form_data.get('impact'):
            finding_data['impact'] = self.form_data['impact']

        # Save to profile using add_finding method
        # Note: add_finding expects (finding_type, description, source, **kwargs)
        self.profile.add_finding(
            finding_type=finding_data['type'],
            description=finding_data['description'],
            source=finding_data['source'],
            **{k: v for k, v in finding_data.items() if k not in ['type', 'description', 'source']}
        )
        self.profile.save()

        # Mark as saved
        self.saved = True

        return True

    def reset(self):
        """
        Reset form to initial state (clear all fields)

        Alias for _clear_form() for public API consistency
        """
        self._clear_form()

    def _next_field(self):
        """Move to next field (wrap around)"""
        self.current_field = (self.current_field + 1) % len(self.FIELDS)

    def _prev_field(self):
        """Move to previous field (wrap around)"""
        self.current_field = (self.current_field - 1) % len(self.FIELDS)

    def _clear_form(self):
        """Clear all form fields"""
        self.form_data = {
            'type': '',
            'description': '',
            'source': '',
            'port': '',
            'severity': '',
            'impact': ''
        }
        self.validation_errors.clear()
        self.saved = False
        self.current_field = 0

    def _truncate_description(self, text: str, max_len: int) -> str:
        """
        Truncate long description with ellipsis

        Args:
            text: Description text
            max_len: Maximum length

        Returns:
            Truncated description
        """
        # Handle multi-line - show first line only
        first_line = text.split('\n')[0]

        if len(first_line) <= max_len:
            return first_line
        return first_line[:max_len-3] + "..."

    @classmethod
    def render_type_selector(cls, current_selection: Optional[str] = None) -> Tuple[Panel, List[Dict]]:
        """
        Render finding type selection menu

        Args:
            current_selection: Currently selected type (if any)

        Returns:
            Tuple of (Rich Panel, choices list)
        """
        # Build type table
        table = Table(show_header=True, box=box.SIMPLE, padding=(0, 2))
        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("Finding Type", style="white", width=30)
        table.add_column("Description", style="cyan", width=40)

        # Type descriptions
        type_descriptions = {
            'vulnerability': 'Security vulnerability or weakness',
            'directory': 'Discovered directory or file path',
            'credential': 'Found username, password, or key',
            'user': 'Discovered user account',
            'note': 'General observation or note',
            'general': 'Other finding type'
        }

        # Build choices
        choices = []

        for idx, finding_type in enumerate(cls.FINDING_TYPES, 1):
            description = type_descriptions.get(finding_type, '-')

            # Highlight current selection
            if finding_type == current_selection:
                type_name = f"[bold bright_white]{finding_type} (selected)[/]"
            else:
                type_name = finding_type

            table.add_row(str(idx), type_name, description)

            choices.append({
                'id': f'select-{idx}',
                'label': f'Select {finding_type}',
                'type': finding_type
            })

        # Add spacing and footer
        table.add_row("", "", "")
        footer_table = Table(show_header=False, box=None, padding=(0, 2))
        footer_table.add_column("Actions", style="white")

        footer_table.add_row(f"[bold bright_white]1-{len(cls.FINDING_TYPES)}.[/] Select type")
        footer_table.add_row("[bold bright_white]c.[/] Cancel")
        choices.append({'id': 'cancel', 'label': 'Cancel'})

        # Combine tables
        combined = Table(show_header=False, box=None, padding=(0, 0))
        combined.add_column("Content")
        combined.add_row(table)
        combined.add_row(footer_table)

        # Build panel
        title = "[bold cyan]Select Finding Type[/]"
        subtitle = "[dim]Choose the category for this finding[/]"

        return Panel(
            combined,
            title=title,
            subtitle=subtitle,
            border_style="cyan",
            box=box.ROUNDED
        ), choices

    @classmethod
    def render_severity_selector(cls, current_selection: Optional[str] = None) -> Tuple[Panel, List[Dict]]:
        """
        Render severity level selection menu

        Args:
            current_selection: Currently selected severity (if any)

        Returns:
            Tuple of (Rich Panel, choices list)
        """
        # Build severity table
        table = Table(show_header=True, box=box.SIMPLE, padding=(0, 2))
        table.add_column("#", style="dim", width=4, justify="right")
        table.add_column("Severity", style="white", width=20)
        table.add_column("CVSS Range", style="cyan", width=15)
        table.add_column("Description", style="white", width=35)

        # Severity metadata
        severity_metadata = {
            'critical': ('9.0-10.0', 'Immediate exploitation risk'),
            'high': ('7.0-8.9', 'Significant security impact'),
            'medium': ('4.0-6.9', 'Moderate security concern'),
            'low': ('0.1-3.9', 'Minor security issue'),
            'info': ('0.0', 'Informational finding')
        }

        # Build choices
        choices = []

        for idx, severity in enumerate(cls.SEVERITY_LEVELS, 1):
            cvss_range, description = severity_metadata.get(severity, ('-', '-'))
            color = cls.SEVERITY_COLORS.get(severity, 'white')

            # Highlight current selection
            if severity == current_selection:
                severity_name = f"[bold {color}]{severity.upper()} (selected)[/]"
            else:
                severity_name = f"[{color}]{severity.upper()}[/]"

            table.add_row(str(idx), severity_name, cvss_range, description)

            choices.append({
                'id': f'select-{idx}',
                'label': f'Select {severity}',
                'severity': severity
            })

        # Add spacing and footer
        table.add_row("", "", "", "")
        footer_table = Table(show_header=False, box=None, padding=(0, 2))
        footer_table.add_column("Actions", style="white")

        footer_table.add_row(f"[bold bright_white]1-{len(cls.SEVERITY_LEVELS)}.[/] Select severity")
        footer_table.add_row("[bold bright_white]c.[/] Cancel")
        choices.append({'id': 'cancel', 'label': 'Cancel'})

        # Combine tables
        combined = Table(show_header=False, box=None, padding=(0, 0))
        combined.add_column("Content")
        combined.add_row(table)
        combined.add_row(footer_table)

        # Build panel
        title = "[bold cyan]Select Severity Level[/]"
        subtitle = "[dim]Rate the impact of this finding (optional)[/]"

        return Panel(
            combined,
            title=title,
            subtitle=subtitle,
            border_style="cyan",
            box=box.ROUNDED
        ), choices
