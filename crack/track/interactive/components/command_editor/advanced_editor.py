"""
AdvancedEditor - Schema-Driven Form-Based Command Editor (Tier 2)

Provides form-based editing with:
- Schema-driven field generation
- Type validation (text, number, path, enum, boolean)
- Field navigation (Tab, Arrow keys)
- Real-time preview updates
- Save as template option

NO TUI RENDERING - Pure logic component
"""

import json
from dataclasses import dataclass, field as dataclass_field
from pathlib import Path
from typing import Optional, Dict, List, Any


@dataclass
class FormField:
    """Represents a single form field"""
    name: str
    type: str  # "text", "number", "path", "enum", "boolean"
    label: str
    value: Any
    required: bool = False
    options: Optional[List[str]] = None  # For enum type
    placeholder: Optional[str] = None
    flag: Optional[str] = None  # Command-line flag (e.g., "-u", "--url")


@dataclass
class EditResult:
    """Result of advanced edit operation"""
    command: Optional[str]
    action: str  # "execute", "escalate", "cancel"
    next_tier: Optional[str] = None  # "advanced", "raw"
    save_behavior: Optional[str] = None  # "once", "update", "template"


class AdvancedEditor:
    """
    Schema-driven form editor for pentesting tool commands.

    Architecture:
    1. Load tool schema from JSON
    2. Build form fields from schema
    3. Handle field editing (no actual UI)
    4. Return structured EditResult

    Reuse Strategy:
    - Schemas define tool parameters (extensible)
    - CommandParser integration (via metadata)
    - No Rich rendering (pure logic)
    """

    def __init__(self, command: str, metadata: Dict):
        """
        Initialize advanced editor.

        Args:
            command: Command string to edit
            metadata: Command metadata (tool, flags, parameters from parser)
        """
        self.command = command
        self.metadata = metadata
        self.form_fields: List[FormField] = []
        self.current_field_index = 0

    def run(self) -> EditResult:
        """
        Main advanced edit flow (NO TUI rendering).

        Returns:
            EditResult with command and action
        """
        # Load schema
        try:
            schema = self._load_tool_schema()
        except FileNotFoundError:
            # Schema not found - escalate to raw editor
            return EditResult(
                command=self.command,
                action="escalate",
                next_tier="raw"
            )

        # Build form from schema
        self.form_fields = self._build_form(schema)

        # Return execute action (actual navigation handled by TUI)
        return EditResult(
            command=self._build_command(),
            action="execute",
            save_behavior="once"
        )

    def _load_tool_schema(self) -> Dict:
        """
        Load JSON schema for tool.

        Returns:
            Schema dict

        Raises:
            FileNotFoundError: If schema doesn't exist
        """
        tool = self.metadata.get('tool', 'unknown')
        schema_path = Path(__file__).parent / "schemas" / f"{tool}.json"

        if not schema_path.exists():
            raise FileNotFoundError(f"Schema not found: {schema_path}")

        with open(schema_path) as f:
            schema = json.load(f)

        # Validate schema structure
        if 'tool' not in schema:
            raise ValueError("Invalid schema: missing 'tool' field")

        return schema

    def _build_form(self, schema: Dict) -> List[FormField]:
        """
        Convert schema to form fields.

        Args:
            schema: Tool schema dict

        Returns:
            List of FormField objects
        """
        fields = []

        # Build parameter fields
        parameters = schema.get('parameters', {})
        for param_name, param_config in parameters.items():
            # Get current value from metadata (try both param name and flag name) or use default
            metadata_params = self.metadata.get('parameters', {})
            flag = param_config.get('flag', '').lstrip('-')  # Remove leading dashes
            current_value = (
                metadata_params.get(param_name) or  # Try full param name
                metadata_params.get(flag) or  # Try flag name without dashes
                param_config.get('default', '')  # Use default
            )

            field = FormField(
                name=param_name,
                type=param_config['type'],
                label=param_config.get('description', param_name.replace('_', ' ').title()),
                value=current_value,
                required=param_config.get('required', False),
                options=param_config.get('options'),
                placeholder=param_config.get('placeholder'),
                flag=param_config.get('flag')  # Store the flag from schema
            )
            fields.append(field)

        # Build flag fields
        flags = schema.get('flags', {})
        for flag_name, flag_config in flags.items():
            # Get current state from metadata or use default
            current_value = self.metadata.get('flags', {}).get(
                flag_name,
                flag_config.get('default', False)
            )

            field = FormField(
                name=flag_name,
                type='boolean',  # Flags are always boolean
                label=flag_config.get('description', flag_name.replace('_', ' ').title()),
                value=current_value,
                required=False,
                flag=flag_config.get('flag')  # Store the flag from schema
            )
            fields.append(field)

        return fields

    def _handle_field_edit(self, field: FormField, new_value: Any) -> bool:
        """
        Update field value with validation.

        Args:
            field: FormField to update
            new_value: New value to set

        Returns:
            True if update successful, False if validation failed
        """
        # Type validation
        if field.type == "number":
            try:
                # Convert to int if possible
                new_value = int(new_value)
            except (ValueError, TypeError):
                return False

        elif field.type == "boolean":
            # Boolean fields toggle
            if not isinstance(new_value, bool):
                return False

        elif field.type == "enum":
            # Enum fields must match options
            if field.options and new_value not in field.options:
                return False

        elif field.type == "path":
            # Path validation (basic - just check non-empty)
            if not new_value or not str(new_value).strip():
                if field.required:
                    return False

        elif field.type == "text":
            # Text validation (basic - just check non-empty if required)
            if field.required and (not new_value or not str(new_value).strip()):
                return False

        # Update field value
        field.value = new_value
        return True

    def navigate_field(self, direction: str) -> int:
        """
        Navigate between fields (NO actual UI).

        Args:
            direction: "next", "prev", or numeric index

        Returns:
            New field index
        """
        if direction == "next":
            self.current_field_index = (self.current_field_index + 1) % len(self.form_fields)
        elif direction == "prev":
            self.current_field_index = (self.current_field_index - 1) % len(self.form_fields)
        else:
            # Direct index selection
            try:
                index = int(direction)
                if 0 <= index < len(self.form_fields):
                    self.current_field_index = index
            except ValueError:
                pass

        return self.current_field_index

    def get_field_by_name(self, name: str) -> Optional[FormField]:
        """
        Get field by parameter/flag name.

        Args:
            name: Field name or flag (with or without dashes)

        Returns:
            FormField or None if not found
        """
        # First try exact match
        for field in self.form_fields:
            if field.name == name:
                return field

        # Try matching against flag (remove dashes for comparison)
        search_flag = f"-{name}" if not name.startswith('-') else name
        for field in self.form_fields:
            if field.flag and field.flag == search_flag:
                return field

        return None

    def _build_command(self) -> str:
        """
        Build command string from form fields.

        Returns:
            Reconstructed command string
        """
        tool = self.metadata.get('tool', '')
        subcommand = self.metadata.get('subcommand', '')

        parts = [tool]
        if subcommand:
            parts.append(subcommand)

        # Add parameters with values
        for field in self.form_fields:
            if field.type == "boolean":
                # Boolean flag
                if field.value and field.flag:
                    parts.append(field.flag)
            else:
                # Parameter with value
                if field.value and field.flag:
                    parts.append(field.flag)
                    parts.append(str(field.value))

        # Add positional arguments from metadata
        arguments = self.metadata.get('arguments', [])
        parts.extend(arguments)

        return ' '.join(parts)

    def get_preview(self) -> str:
        """
        Get real-time preview of command (NO actual display).

        Returns:
            Command preview string
        """
        return self._build_command()

    def toggle_boolean_field(self, field_name: str) -> bool:
        """
        Toggle a boolean field by name or flag.

        Args:
            field_name: Name or flag of boolean field to toggle

        Returns:
            New boolean value, or False if field not found
        """
        field = self.get_field_by_name(field_name)  # Now supports flag lookup
        if field and field.type == "boolean":
            field.value = not field.value
            return field.value
        return False

    def validate_required_fields(self) -> tuple[bool, List[str]]:
        """
        Validate all required fields have values.

        Returns:
            Tuple of (is_valid, list_of_missing_field_identifiers)
            Returns flag names (without dashes) if available, else parameter names
        """
        missing = []
        for field in self.form_fields:
            if field.required and not field.value:
                # Return flag name (without dashes) if available, else param name
                identifier = field.flag.lstrip('-') if field.flag else field.name
                missing.append(identifier)

        return (len(missing) == 0, missing)
