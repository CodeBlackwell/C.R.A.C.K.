"""
Credential Entry Form Panel - Structured credential capture with source tracking

Features:
- Multi-field form (username, password, service, source, port, notes)
- Password masking toggle
- Service/protocol dropdown
- Required source field (OSCP compliance)
- Input validation with real-time feedback
- Save to profile.credentials

Follows hub-spoke navigation - this is a spoke panel.
"""

from typing import Dict, Any, Optional, Tuple, List
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text


class CredentialFormPanel:
    """Credential entry form rendering and input processing"""

    # Supported service/protocol types
    SERVICES = [
        'SSH', 'FTP', 'HTTP', 'HTTPS', 'SMB', 'RDP', 'MySQL', 'PostgreSQL',
        'MSSQL', 'Oracle', 'LDAP', 'Kerberos', 'SMTP', 'POP3', 'IMAP',
        'Telnet', 'VNC', 'WinRM', 'Redis', 'MongoDB', 'Other'
    ]

    # Field definitions (name, label, required, type)
    FIELDS = [
        ('username', 'Username', True, 'text'),
        ('password', 'Password', False, 'password'),
        ('service', 'Service/Protocol', False, 'dropdown'),
        ('source', 'Source (REQUIRED)', True, 'text'),
        ('port', 'Port (optional)', False, 'numeric'),
        ('notes', 'Notes (optional)', False, 'text')
    ]

    def __init__(self, profile, theme=None):
        """
        Initialize credential form

        Args:
            profile: TargetProfile instance
            theme: ThemeManager instance (optional for backward compat)
        """
        # Fallback theme for backward compatibility
        if theme is None:
            from ..themes import ThemeManager
            theme = ThemeManager()

        self.profile = profile
        self.theme = theme
        self.form_data: Dict[str, Any] = {
            'username': '',
            'password': '',
            'service': '',
            'source': '',
            'port': '',
            'notes': ''
        }
        self.current_field = 0  # Index into FIELDS
        self.show_password = False  # Password masking toggle
        self.validation_errors: Dict[str, str] = {}
        self.saved = False  # Track if credential was saved

    @classmethod
    def create(cls, profile, theme=None) -> 'CredentialFormPanel':
        """
        Factory method to create new form instance

        Args:
            profile: TargetProfile instance
            theme: ThemeManager instance (optional for backward compat)

        Returns:
            New CredentialFormPanel instance
        """
        return cls(profile, theme)

    def render(self) -> Tuple[Panel, List[Dict]]:
        """
        Render credential entry form

        Returns:
            Tuple of (Rich Panel, choices list for input processing)
        """
        # Clear validation errors before re-render
        # (They'll be regenerated during validation)

        # Build form table
        form_table = Table(show_header=False, box=None, padding=(0, 2))
        form_table.add_column("Label", style=self.theme.get_color('text'), width=25)
        form_table.add_column("Input", style=self.theme.get_color('text'), width=50)

        # Add header
        form_table.add_row(
            self.theme.emphasis("CREDENTIAL ENTRY FORM"),
            ""
        )
        form_table.add_row("", "")  # Blank line

        # Render each field
        for idx, (field_name, label, required, field_type) in enumerate(self.FIELDS):
            self._render_field(form_table, idx, field_name, label, required, field_type)

        # Add spacing
        form_table.add_row("", "")

        # Add validation summary if errors
        if self.validation_errors:
            error_text = f"[bold {self.theme.get_color('danger')}]Validation Errors:[/]"
            for field, error in self.validation_errors.items():
                error_text += f"\n  • {field}: {error}"
            form_table.add_row("", error_text)
            form_table.add_row("", "")

        # Add success message if saved
        if self.saved:
            form_table.add_row(
                "",
                self.theme.success("✓ Credential saved successfully!")
            )
            form_table.add_row("", "")

        # Build action menu
        choices = self._build_action_menu(form_table)

        # Build panel
        breadcrumb = "Dashboard > Add Credential"
        title = f"[bold {self.theme.get_color('primary')}]{breadcrumb}[/]"
        subtitle = self.theme.muted(f"Target: {self.profile.target} | Field {self.current_field + 1}/{len(self.FIELDS)}")

        return Panel(
            form_table,
            title=title,
            subtitle=subtitle,
            border_style=self.theme.panel_border(),
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
            field_type: Field type (text, password, numeric, dropdown)
        """
        # Highlight current field
        is_current = (idx == self.current_field)

        # Build label with required indicator
        label_text = label
        if required:
            label_text += " *"

        # Style based on current/error state
        if is_current:
            label_style = f"[bold {self.theme.get_color('emphasis')}]"
            indicator = "►"
        else:
            label_style = f"[{self.theme.get_color('text')}]"
            indicator = " "

        # Add error indicator
        if field_name in self.validation_errors:
            label_style = f"[bold {self.theme.get_color('danger')}]"
            indicator = "✗"

        # Get field value
        value = self.form_data.get(field_name, '')

        # Format value based on field type
        if field_type == 'password' and value and not self.show_password:
            # Mask password
            display_value = '•' * len(value)
        elif field_type == 'dropdown' and not value:
            # Show placeholder for dropdown
            display_value = self.theme.muted("(press Enter to select)")
        else:
            display_value = value if value else self.theme.muted("(empty)")

        # Add validation error inline
        if field_name in self.validation_errors:
            display_value += f" [{self.theme.get_color('danger')}]← {self.validation_errors[field_name]}[/]"

        # Build the row
        label_cell = f"{indicator} {label_style}{label_text}[/]"

        # Highlight current field input
        if is_current:
            value_cell = f"[bold {self.theme.get_color('emphasis')}]{display_value}[/]"
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
        from ..themes.helpers import format_hotkey

        choices = []

        # Navigation instructions
        table.add_row(
            self.theme.emphasis("Navigation:"),
            ""
        )
        table.add_row("", self.theme.muted("↑/↓ or Tab: Move between fields"))
        table.add_row("", self.theme.muted("Enter: Edit current field"))
        table.add_row("", "")

        # Actions
        table.add_row(self.theme.emphasis("Actions:"), "")

        table.add_row("", f"{format_hotkey(self.theme, 'e')} Edit current field")
        choices.append({'id': 'edit', 'label': 'Edit current field'})

        # Password toggle (only if password field has value)
        if self.form_data.get('password'):
            toggle_text = "Hide password" if self.show_password else "Show password"
            table.add_row("", f"{format_hotkey(self.theme, 'p')} {toggle_text}")
            choices.append({'id': 'toggle-password', 'label': toggle_text})

        table.add_row("", f"{format_hotkey(self.theme, 's')} Save credential")
        choices.append({'id': 'save', 'label': 'Save credential'})

        table.add_row("", f"{format_hotkey(self.theme, 'c')} Clear form")
        choices.append({'id': 'clear', 'label': 'Clear form'})

        table.add_row("", f"{format_hotkey(self.theme, 'b')} Back to dashboard")
        choices.append({'id': 'back', 'label': 'Back to dashboard'})

        return choices

    def process_input(self, user_input: str) -> str:
        """
        Process user input for form navigation and actions

        Args:
            user_input: Raw user input string

        Returns:
            Action code ('continue', 'back', 'saved')
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
        elif user_input == 'p':
            self._toggle_password_visibility()
            return 'continue'
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
            # Service dropdown - validate against SERVICES list
            if new_value and new_value.upper() not in [s.upper() for s in self.SERVICES]:
                self.validation_errors[field_name] = f"Invalid service (use: {', '.join(self.SERVICES[:5])}...)"
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

        # Add service options for dropdown
        if field_type == 'dropdown':
            info['options'] = self.SERVICES

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

        # At least one of password or notes should be present
        # (username alone is not very useful)
        if not self.form_data.get('password') and not self.form_data.get('notes'):
            self.validation_errors['password'] = "Provide password or notes"

        return len(self.validation_errors) == 0

    def save_to_profile(self) -> bool:
        """
        Save credential to profile if validation passes

        Returns:
            True if saved successfully, False otherwise
        """
        if not self.validate():
            return False

        # Build credential dict
        credential_data = {
            'username': self.form_data['username'],
            'source': self.form_data['source']
        }

        # Add optional fields if present
        if self.form_data.get('password'):
            credential_data['password'] = self.form_data['password']

        if self.form_data.get('service'):
            credential_data['service'] = self.form_data['service']

        if self.form_data.get('port'):
            credential_data['port'] = int(self.form_data['port'])

        if self.form_data.get('notes'):
            credential_data['notes'] = self.form_data['notes']

        # Save to profile
        self.profile.add_credential(**credential_data)
        self.profile.save()

        # Mark as saved
        self.saved = True

        return True

    def _next_field(self):
        """Move to next field (wrap around)"""
        self.current_field = (self.current_field + 1) % len(self.FIELDS)

    def _prev_field(self):
        """Move to previous field (wrap around)"""
        self.current_field = (self.current_field - 1) % len(self.FIELDS)

    def _toggle_password_visibility(self):
        """Toggle password masking"""
        self.show_password = not self.show_password

    def _clear_form(self):
        """Clear all form fields"""
        self.form_data = {
            'username': '',
            'password': '',
            'service': '',
            'source': '',
            'port': '',
            'notes': ''
        }
        self.validation_errors.clear()
        self.saved = False
        self.current_field = 0
        self.show_password = False

    @classmethod
    def render_service_selector(cls, current_selection: Optional[str] = None, theme=None) -> Tuple[Panel, List[Dict]]:
        """
        Render service/protocol selection menu

        Args:
            current_selection: Currently selected service (if any)
            theme: ThemeManager instance (optional for backward compat)

        Returns:
            Tuple of (Rich Panel, choices list)
        """
        # Fallback theme for backward compatibility
        if theme is None:
            from ..themes import ThemeManager
            theme = ThemeManager()

        from ..themes.helpers import format_hotkey

        # Build service table
        table = Table(show_header=True, box=box.SIMPLE, padding=(0, 2))
        table.add_column("#", style=theme.get_color('muted'), width=4, justify="right")
        table.add_column("Service/Protocol", style=theme.get_color('text'), width=30)
        table.add_column("Common Port", style=theme.get_color('secondary'), width=15)

        # Service to port mapping (for display only)
        service_ports = {
            'SSH': '22', 'FTP': '21', 'HTTP': '80', 'HTTPS': '443',
            'SMB': '445', 'RDP': '3389', 'MySQL': '3306', 'PostgreSQL': '5432',
            'MSSQL': '1433', 'Oracle': '1521', 'LDAP': '389', 'Kerberos': '88',
            'SMTP': '25', 'POP3': '110', 'IMAP': '143', 'Telnet': '23',
            'VNC': '5900', 'WinRM': '5985', 'Redis': '6379', 'MongoDB': '27017',
            'Other': '-'
        }

        # Build choices
        choices = []

        for idx, service in enumerate(cls.SERVICES, 1):
            port = service_ports.get(service, '-')

            # Highlight current selection
            if service == current_selection:
                service_name = theme.emphasis(f"{service} (selected)")
            else:
                service_name = service

            table.add_row(str(idx), service_name, port)

            choices.append({
                'id': f'select-{idx}',
                'label': f'Select {service}',
                'service': service
            })

        # Add spacing and footer
        table.add_row("", "", "")
        footer_table = Table(show_header=False, box=None, padding=(0, 2))
        footer_table.add_column("Actions", style=theme.get_color('text'))

        footer_table.add_row(f"{theme.emphasis(f'1-{len(cls.SERVICES)}')} Select service")
        footer_table.add_row(f"{format_hotkey(theme, 'c')} Cancel")
        choices.append({'id': 'cancel', 'label': 'Cancel'})

        # Combine tables
        combined = Table(show_header=False, box=None, padding=(0, 0))
        combined.add_column("Content")
        combined.add_row(table)
        combined.add_row(footer_table)

        # Build panel
        title = f"[bold {theme.get_color('primary')}]Select Service/Protocol[/]"
        subtitle = theme.muted("Choose the service this credential is for")

        return Panel(
            combined,
            title=title,
            subtitle=subtitle,
            border_style=theme.panel_border(),
            box=box.ROUNDED
        ), choices
