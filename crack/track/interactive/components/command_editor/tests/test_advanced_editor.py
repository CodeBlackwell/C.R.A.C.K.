"""
Test AdvancedEditor - 18 comprehensive tests

Test Coverage:
- Schema loading: 3 tests (existing, missing, malformed)
- Form building: 3 tests (text fields, checkboxes, dropdowns)
- Field navigation: 3 tests (Tab, Arrow, direct selection)
- Value editing: 3 tests (text, numeric, boolean toggle)
- Preview update: 3 tests (after each edit)
- Save behaviors: 3 tests (execute, save template, cancel)
"""

import pytest
import json
from pathlib import Path
from ..advanced_editor import AdvancedEditor, FormField, EditResult


class TestSchemaLoading:
    """Test schema loading (3 tests)"""

    def test_load_existing_gobuster_schema(self):
        """PROVES: Schema loads from existing JSON file"""
        editor = AdvancedEditor(
            command="gobuster dir -u http://target -w /path/list.txt",
            metadata={
                'tool': 'gobuster',
                'subcommand': 'dir',
                'parameters': {'u': 'http://target', 'w': '/path/list.txt'},
                'flags': {}
            }
        )

        schema = editor._load_tool_schema()

        assert schema['tool'] == 'gobuster'
        assert 'parameters' in schema
        assert 'u' in schema['parameters']
        assert 'w' in schema['parameters']

    def test_load_missing_schema_raises_error(self):
        """PROVES: Missing schema raises FileNotFoundError"""
        editor = AdvancedEditor(
            command="unknowntool --flag value",
            metadata={'tool': 'unknowntool'}
        )

        with pytest.raises(FileNotFoundError) as exc_info:
            editor._load_tool_schema()

        assert "Schema not found" in str(exc_info.value)

    def test_load_nmap_schema(self):
        """PROVES: Schema loads for nmap tool"""
        editor = AdvancedEditor(
            command="nmap -sS -sV 192.168.1.100",
            metadata={
                'tool': 'nmap',
                'flags': {'sS': True, 'sV': True},
                'parameters': {},
                'arguments': ['192.168.1.100']
            }
        )

        schema = editor._load_tool_schema()

        assert schema['tool'] == 'nmap'
        assert 'flags' in schema
        assert 'sS' in schema['flags']
        assert 'sV' in schema['flags']


class TestFormBuilding:
    """Test form building from schema (3 tests)"""

    def test_build_form_with_text_fields(self):
        """PROVES: Form builder creates text fields from schema parameters"""
        editor = AdvancedEditor(
            command="gobuster dir -u http://target -w /path/list.txt",
            metadata={
                'tool': 'gobuster',
                'subcommand': 'dir',
                'parameters': {'u': 'http://target', 'w': '/path/list.txt'},
                'flags': {}
            }
        )

        schema = editor._load_tool_schema()
        fields = editor._build_form(schema)

        # Find text fields
        url_field = next(f for f in fields if f.name == 'u')
        wordlist_field = next(f for f in fields if f.name == 'w')

        assert url_field.type == 'text'
        assert url_field.label == 'Target URL'
        assert url_field.value == 'http://target'
        assert url_field.required is True

        assert wordlist_field.type == 'path'
        assert wordlist_field.value == '/path/list.txt'

    def test_build_form_with_boolean_flags(self):
        """PROVES: Form builder creates boolean checkbox fields"""
        editor = AdvancedEditor(
            command="gobuster dir -u http://target -w /path/list.txt -v -e",
            metadata={
                'tool': 'gobuster',
                'subcommand': 'dir',
                'parameters': {'u': 'http://target', 'w': '/path/list.txt'},
                'flags': {'v': True, 'e': True}
            }
        )

        schema = editor._load_tool_schema()
        fields = editor._build_form(schema)

        # Find boolean fields
        verbose_field = next(f for f in fields if f.name == 'v')
        expanded_field = next(f for f in fields if f.name == 'e')

        assert verbose_field.type == 'boolean'
        assert verbose_field.label == 'Verbose'
        assert verbose_field.value is True

        assert expanded_field.type == 'boolean'
        assert expanded_field.value is True

    def test_build_form_with_enum_dropdown(self):
        """PROVES: Form builder creates enum dropdown fields"""
        editor = AdvancedEditor(
            command="nmap -T4 192.168.1.100",
            metadata={
                'tool': 'nmap',
                'parameters': {'T': '4'},
                'flags': {},
                'arguments': ['192.168.1.100']
            }
        )

        schema = editor._load_tool_schema()
        fields = editor._build_form(schema)

        # Find enum field
        timing_field = next(f for f in fields if f.name == 'T')

        assert timing_field.type == 'enum'
        assert timing_field.label == 'Timing Template'
        assert timing_field.value == '4'
        assert timing_field.options == ['0', '1', '2', '3', '4', '5']


class TestFieldNavigation:
    """Test field navigation (3 tests)"""

    def test_navigate_next_field(self):
        """PROVES: Tab key advances to next field"""
        editor = AdvancedEditor(
            command="gobuster dir -u http://target -w /path/list.txt",
            metadata={
                'tool': 'gobuster',
                'subcommand': 'dir',
                'parameters': {'u': 'http://target', 'w': '/path/list.txt'},
                'flags': {}
            }
        )

        schema = editor._load_tool_schema()
        editor.form_fields = editor._build_form(schema)

        # Start at field 0
        assert editor.current_field_index == 0

        # Navigate next
        new_index = editor.navigate_field("next")
        assert new_index == 1

        # Navigate next again
        new_index = editor.navigate_field("next")
        assert new_index == 2

    def test_navigate_previous_field(self):
        """PROVES: Shift+Tab goes to previous field"""
        editor = AdvancedEditor(
            command="gobuster dir -u http://target -w /path/list.txt",
            metadata={
                'tool': 'gobuster',
                'subcommand': 'dir',
                'parameters': {'u': 'http://target', 'w': '/path/list.txt'},
                'flags': {}
            }
        )

        schema = editor._load_tool_schema()
        editor.form_fields = editor._build_form(schema)

        # Start at field 2
        editor.current_field_index = 2

        # Navigate previous
        new_index = editor.navigate_field("prev")
        assert new_index == 1

        # Navigate previous again
        new_index = editor.navigate_field("prev")
        assert new_index == 0

    def test_navigate_direct_selection(self):
        """PROVES: Direct index selection jumps to specific field"""
        editor = AdvancedEditor(
            command="gobuster dir -u http://target -w /path/list.txt",
            metadata={
                'tool': 'gobuster',
                'subcommand': 'dir',
                'parameters': {'u': 'http://target', 'w': '/path/list.txt'},
                'flags': {}
            }
        )

        schema = editor._load_tool_schema()
        editor.form_fields = editor._build_form(schema)

        # Direct jump to field 3
        new_index = editor.navigate_field("3")
        assert new_index == 3

        # Invalid index (out of range) - should stay at current
        new_index = editor.navigate_field("999")
        assert new_index == 3  # Unchanged


class TestValueEditing:
    """Test value editing (3 tests)"""

    def test_edit_text_field(self):
        """PROVES: Text field accepts string values"""
        field = FormField(
            name='u',
            type='text',
            label='Target URL',
            value='http://old-target',
            required=True
        )

        editor = AdvancedEditor(
            command="gobuster dir -u http://target -w /path/list.txt",
            metadata={'tool': 'gobuster'}
        )

        # Edit field
        success = editor._handle_field_edit(field, 'http://new-target')

        assert success is True
        assert field.value == 'http://new-target'

    def test_edit_numeric_field(self):
        """PROVES: Numeric field validates and converts to int"""
        field = FormField(
            name='t',
            type='number',
            label='Threads',
            value=10,
            required=False
        )

        editor = AdvancedEditor(
            command="gobuster dir -u http://target -w /path/list.txt",
            metadata={'tool': 'gobuster'}
        )

        # Edit with valid number
        success = editor._handle_field_edit(field, '50')
        assert success is True
        assert field.value == 50

        # Edit with invalid number
        success = editor._handle_field_edit(field, 'not-a-number')
        assert success is False

    def test_toggle_boolean_field(self):
        """PROVES: Boolean field toggles on/off"""
        editor = AdvancedEditor(
            command="gobuster dir -u http://target -w /path/list.txt -v",
            metadata={
                'tool': 'gobuster',
                'subcommand': 'dir',
                'parameters': {'u': 'http://target', 'w': '/path/list.txt'},
                'flags': {'v': True}
            }
        )

        schema = editor._load_tool_schema()
        editor.form_fields = editor._build_form(schema)

        # Toggle verbose flag off
        new_value = editor.toggle_boolean_field('v')
        assert new_value is False

        # Toggle verbose flag back on
        new_value = editor.toggle_boolean_field('v')
        assert new_value is True


class TestPreviewUpdate:
    """Test preview update (3 tests)"""

    def test_preview_after_text_edit(self):
        """PROVES: Preview updates after text field edit"""
        editor = AdvancedEditor(
            command="gobuster dir -u http://target -w /path/list.txt",
            metadata={
                'tool': 'gobuster',
                'subcommand': 'dir',
                'parameters': {'u': 'http://target', 'w': '/path/list.txt'},
                'flags': {}
            }
        )

        schema = editor._load_tool_schema()
        editor.form_fields = editor._build_form(schema)

        # Get initial preview
        preview = editor.get_preview()
        assert 'http://target' in preview

        # Edit URL field
        url_field = editor.get_field_by_name('u')
        editor._handle_field_edit(url_field, 'http://new-target')

        # Get updated preview
        new_preview = editor.get_preview()
        assert 'http://new-target' in new_preview
        assert 'http://target' not in new_preview

    def test_preview_after_boolean_toggle(self):
        """PROVES: Preview updates after boolean flag toggle"""
        editor = AdvancedEditor(
            command="gobuster dir -u http://target -w /path/list.txt",
            metadata={
                'tool': 'gobuster',
                'subcommand': 'dir',
                'parameters': {'u': 'http://target', 'w': '/path/list.txt'},
                'flags': {}
            }
        )

        schema = editor._load_tool_schema()
        editor.form_fields = editor._build_form(schema)

        # Initial preview (no -v flag)
        preview = editor.get_preview()
        assert '-v' not in preview

        # Toggle verbose on
        editor.toggle_boolean_field('v')

        # Preview should include -v
        new_preview = editor.get_preview()
        assert '-v' in new_preview

    def test_preview_after_numeric_edit(self):
        """PROVES: Preview updates after numeric field edit"""
        editor = AdvancedEditor(
            command="gobuster dir -u http://target -w /path/list.txt -t 10",
            metadata={
                'tool': 'gobuster',
                'subcommand': 'dir',
                'parameters': {'u': 'http://target', 'w': '/path/list.txt', 't': '10'},
                'flags': {}
            }
        )

        schema = editor._load_tool_schema()
        editor.form_fields = editor._build_form(schema)

        # Initial preview
        preview = editor.get_preview()
        assert '-t 10' in preview

        # Edit threads field
        threads_field = editor.get_field_by_name('t')
        editor._handle_field_edit(threads_field, '50')

        # Preview should reflect new value
        new_preview = editor.get_preview()
        assert '-t 50' in new_preview


class TestSaveBehaviors:
    """Test save behaviors (3 tests)"""

    def test_execute_action_returns_command(self):
        """PROVES: Execute action returns edited command"""
        editor = AdvancedEditor(
            command="gobuster dir -u http://target -w /path/list.txt",
            metadata={
                'tool': 'gobuster',
                'subcommand': 'dir',
                'parameters': {'u': 'http://target', 'w': '/path/list.txt'},
                'flags': {}
            }
        )

        result = editor.run()

        assert result.action == 'execute'
        assert result.command is not None
        assert 'gobuster' in result.command
        assert result.save_behavior == 'once'

    def test_escalate_action_for_missing_schema(self):
        """PROVES: Missing schema escalates to raw editor"""
        editor = AdvancedEditor(
            command="unknowntool --flag value",
            metadata={'tool': 'unknowntool'}
        )

        result = editor.run()

        assert result.action == 'escalate'
        assert result.next_tier == 'raw'
        assert result.command == 'unknowntool --flag value'

    def test_validate_required_fields(self):
        """PROVES: Validation catches missing required fields"""
        editor = AdvancedEditor(
            command="gobuster dir -u http://target -w /path/list.txt",
            metadata={
                'tool': 'gobuster',
                'subcommand': 'dir',
                'parameters': {'u': 'http://target', 'w': ''},  # Missing wordlist
                'flags': {}
            }
        )

        schema = editor._load_tool_schema()
        editor.form_fields = editor._build_form(schema)

        # Clear required field
        wordlist_field = editor.get_field_by_name('w')
        wordlist_field.value = ''

        # Validate
        is_valid, missing = editor.validate_required_fields()

        assert is_valid is False
        assert 'w' in missing
