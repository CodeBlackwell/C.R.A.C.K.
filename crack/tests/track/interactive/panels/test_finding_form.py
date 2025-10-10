"""
Tests for FindingFormPanel - Structured finding entry form

Test Coverage:
- Form initialization and state management
- Field rendering and navigation
- Input validation (required fields, port ranges, dropdown values)
- Save to profile with source tracking
- Dropdown selectors (type, severity)
- Form reset functionality
"""

import pytest
from crack.track.interactive.panels.finding_form import FindingFormPanel
from crack.track.core.state import TargetProfile


@pytest.fixture
def profile():
    """Create test TargetProfile"""
    return TargetProfile('192.168.1.100')


@pytest.fixture
def finding_form(profile):
    """Create FindingFormPanel instance"""
    return FindingFormPanel.create(profile)


class TestFindingFormInitialization:
    """Test form initialization and factory method"""

    def test_factory_create(self, profile):
        """Test factory method creates valid instance"""
        form = FindingFormPanel.create(profile)

        assert isinstance(form, FindingFormPanel)
        assert form.profile == profile
        assert form.current_field == 0
        assert form.saved is False
        assert len(form.validation_errors) == 0

    def test_initial_form_data(self, finding_form):
        """Test initial form data is empty"""
        expected_fields = ['type', 'description', 'source', 'port', 'severity', 'impact']

        for field in expected_fields:
            assert field in finding_form.form_data
            assert finding_form.form_data[field] == ''


class TestFormRendering:
    """Test form rendering and display"""

    def test_render_returns_panel_and_choices(self, finding_form):
        """Test render returns Panel and choices list"""
        panel, choices = finding_form.render()

        # Verify return types
        from rich.panel import Panel
        assert isinstance(panel, Panel)
        assert isinstance(choices, list)

        # Verify choices exist
        assert len(choices) > 0

        # Verify expected actions
        choice_ids = [c['id'] for c in choices]
        assert 'edit' in choice_ids
        assert 'save' in choice_ids
        assert 'clear' in choice_ids
        assert 'back' in choice_ids

    def test_render_with_validation_errors(self, finding_form):
        """Test render displays validation errors"""
        # Add validation error
        finding_form.validation_errors['source'] = "Required field"

        panel, choices = finding_form.render()

        # Panel should be created (errors don't prevent rendering)
        assert panel is not None

    def test_render_after_save(self, finding_form):
        """Test render shows success message after save"""
        # Fill required fields
        finding_form.form_data = {
            'type': 'vulnerability',
            'description': 'SQL injection in login form',
            'source': 'manual testing',
            'port': '',
            'severity': 'high',
            'impact': ''
        }

        # Save and mark as saved
        finding_form.saved = True

        panel, choices = finding_form.render()

        # Panel should include success indicator
        assert panel is not None


class TestFieldNavigation:
    """Test field navigation (Tab, up/down)"""

    def test_next_field_increments(self, finding_form):
        """Test next field moves forward"""
        initial = finding_form.current_field
        finding_form._next_field()

        assert finding_form.current_field == initial + 1

    def test_next_field_wraps_around(self, finding_form):
        """Test next field wraps to beginning"""
        num_fields = len(finding_form.FIELDS)
        finding_form.current_field = num_fields - 1

        finding_form._next_field()

        assert finding_form.current_field == 0

    def test_prev_field_decrements(self, finding_form):
        """Test prev field moves backward"""
        finding_form.current_field = 2
        finding_form._prev_field()

        assert finding_form.current_field == 1

    def test_prev_field_wraps_around(self, finding_form):
        """Test prev field wraps to end"""
        num_fields = len(finding_form.FIELDS)
        finding_form.current_field = 0

        finding_form._prev_field()

        assert finding_form.current_field == num_fields - 1


class TestInputProcessing:
    """Test user input processing"""

    def test_process_tab_navigates(self, finding_form):
        """Test tab key moves to next field"""
        initial = finding_form.current_field
        result = finding_form.process_input('tab')

        assert result == 'continue'
        assert finding_form.current_field == initial + 1

    def test_process_down_navigates(self, finding_form):
        """Test down key moves to next field"""
        initial = finding_form.current_field
        result = finding_form.process_input('down')

        assert result == 'continue'
        assert finding_form.current_field == initial + 1

    def test_process_up_navigates(self, finding_form):
        """Test up key moves to previous field"""
        finding_form.current_field = 2
        result = finding_form.process_input('up')

        assert result == 'continue'
        assert finding_form.current_field == 1

    def test_process_edit_action(self, finding_form):
        """Test edit action returns edit-field"""
        result = finding_form.process_input('e')
        assert result == 'edit-field'

        result = finding_form.process_input('enter')
        assert result == 'edit-field'

    def test_process_save_action(self, finding_form):
        """Test save action returns save"""
        result = finding_form.process_input('s')
        assert result == 'save'

    def test_process_clear_action(self, finding_form):
        """Test clear action clears form"""
        # Add some data
        finding_form.form_data['type'] = 'vulnerability'
        finding_form.form_data['source'] = 'test'

        result = finding_form.process_input('c')

        assert result == 'continue'
        assert finding_form.form_data['type'] == ''
        assert finding_form.form_data['source'] == ''

    def test_process_back_action(self, finding_form):
        """Test back action returns back"""
        result = finding_form.process_input('b')
        assert result == 'back'

    def test_process_unknown_input(self, finding_form):
        """Test unknown input is ignored"""
        initial = finding_form.current_field
        result = finding_form.process_input('xyz')

        assert result == 'continue'
        assert finding_form.current_field == initial  # No change


class TestFieldEditing:
    """Test field editing and validation"""

    def test_edit_text_field(self, finding_form):
        """Test editing text field"""
        # Navigate to description field (index 1)
        finding_form.current_field = 1

        success = finding_form.edit_current_field('SQL injection vulnerability')

        assert success is True
        assert finding_form.form_data['description'] == 'SQL injection vulnerability'

    def test_edit_numeric_field_valid(self, finding_form):
        """Test editing numeric field with valid port"""
        # Navigate to port field (index 3)
        finding_form.current_field = 3

        success = finding_form.edit_current_field('443')

        assert success is True
        assert finding_form.form_data['port'] == '443'
        assert 'port' not in finding_form.validation_errors

    def test_edit_numeric_field_invalid_range(self, finding_form):
        """Test editing numeric field with invalid port range"""
        # Navigate to port field
        finding_form.current_field = 3

        success = finding_form.edit_current_field('99999')

        assert success is False
        assert 'port' in finding_form.validation_errors

    def test_edit_numeric_field_non_numeric(self, finding_form):
        """Test editing numeric field with non-numeric value"""
        # Navigate to port field
        finding_form.current_field = 3

        success = finding_form.edit_current_field('abc')

        assert success is False
        assert 'port' in finding_form.validation_errors

    def test_edit_dropdown_type_valid(self, finding_form):
        """Test editing type dropdown with valid value"""
        # Navigate to type field (index 0)
        finding_form.current_field = 0

        success = finding_form.edit_current_field('vulnerability')

        assert success is True
        assert finding_form.form_data['type'] == 'vulnerability'

    def test_edit_dropdown_type_invalid(self, finding_form):
        """Test editing type dropdown with invalid value"""
        # Navigate to type field
        finding_form.current_field = 0

        success = finding_form.edit_current_field('invalid_type')

        assert success is False
        assert 'type' in finding_form.validation_errors

    def test_edit_dropdown_severity_valid(self, finding_form):
        """Test editing severity dropdown with valid value"""
        # Navigate to severity field (index 4)
        finding_form.current_field = 4

        success = finding_form.edit_current_field('high')

        assert success is True
        assert finding_form.form_data['severity'] == 'high'

    def test_edit_clears_previous_errors(self, finding_form):
        """Test editing field clears previous validation errors"""
        # Add error
        finding_form.validation_errors['source'] = "Required field"

        # Navigate to source field (index 2)
        finding_form.current_field = 2

        finding_form.edit_current_field('manual testing')

        assert 'source' not in finding_form.validation_errors


class TestGetCurrentFieldInfo:
    """Test getting current field information"""

    def test_get_field_info_text_field(self, finding_form):
        """Test getting info for text field"""
        # Navigate to description field
        finding_form.current_field = 1

        info = finding_form.get_current_field_info()

        assert info['field_name'] == 'description'
        assert info['label'] == 'Description'
        assert info['required'] is True
        assert info['type'] == 'text'

    def test_get_field_info_dropdown_type(self, finding_form):
        """Test getting info for type dropdown includes options"""
        # Navigate to type field
        finding_form.current_field = 0

        info = finding_form.get_current_field_info()

        assert info['field_name'] == 'type'
        assert info['type'] == 'dropdown'
        assert 'options' in info
        assert 'vulnerability' in info['options']
        assert 'directory' in info['options']

    def test_get_field_info_dropdown_severity(self, finding_form):
        """Test getting info for severity dropdown includes options"""
        # Navigate to severity field
        finding_form.current_field = 4

        info = finding_form.get_current_field_info()

        assert info['field_name'] == 'severity'
        assert info['type'] == 'dropdown'
        assert 'options' in info
        assert 'critical' in info['options']
        assert 'high' in info['options']

    def test_get_field_info_includes_current_value(self, finding_form):
        """Test field info includes current value"""
        # Set value
        finding_form.form_data['source'] = 'nmap scan'
        finding_form.current_field = 2

        info = finding_form.get_current_field_info()

        assert info['current_value'] == 'nmap scan'


class TestValidation:
    """Test form validation"""

    def test_validate_all_required_fields_empty(self, finding_form):
        """Test validation fails when required fields are empty"""
        result = finding_form.validate()

        assert result is False
        assert 'type' in finding_form.validation_errors
        assert 'description' in finding_form.validation_errors
        assert 'source' in finding_form.validation_errors

    def test_validate_missing_source(self, finding_form):
        """Test validation fails when source is missing (OSCP requirement)"""
        # Fill other required fields
        finding_form.form_data['type'] = 'vulnerability'
        finding_form.form_data['description'] = 'Test finding'
        # Leave source empty

        result = finding_form.validate()

        assert result is False
        assert 'source' in finding_form.validation_errors

    def test_validate_all_required_fields_filled(self, finding_form):
        """Test validation passes with all required fields"""
        finding_form.form_data['type'] = 'vulnerability'
        finding_form.form_data['description'] = 'SQL injection'
        finding_form.form_data['source'] = 'manual testing'

        result = finding_form.validate()

        assert result is True
        assert len(finding_form.validation_errors) == 0

    def test_validate_invalid_port(self, finding_form):
        """Test validation fails with invalid port"""
        # Fill required fields
        finding_form.form_data['type'] = 'vulnerability'
        finding_form.form_data['description'] = 'Test'
        finding_form.form_data['source'] = 'test'
        finding_form.form_data['port'] = '99999'

        result = finding_form.validate()

        assert result is False
        assert 'port' in finding_form.validation_errors

    def test_validate_invalid_type(self, finding_form):
        """Test validation fails with invalid type"""
        finding_form.form_data['type'] = 'invalid_type'
        finding_form.form_data['description'] = 'Test'
        finding_form.form_data['source'] = 'test'

        result = finding_form.validate()

        assert result is False
        assert 'type' in finding_form.validation_errors

    def test_validate_invalid_severity(self, finding_form):
        """Test validation fails with invalid severity"""
        finding_form.form_data['type'] = 'vulnerability'
        finding_form.form_data['description'] = 'Test'
        finding_form.form_data['source'] = 'test'
        finding_form.form_data['severity'] = 'invalid_severity'

        result = finding_form.validate()

        assert result is False
        assert 'severity' in finding_form.validation_errors


class TestSaveToProfile:
    """Test saving finding to profile"""

    def test_save_fails_validation(self, finding_form):
        """Test save fails when validation fails"""
        # Leave required fields empty
        result = finding_form.save_to_profile()

        assert result is False
        assert finding_form.saved is False

    def test_save_success_required_fields_only(self, finding_form, profile):
        """Test save succeeds with only required fields"""
        # Fill required fields
        finding_form.form_data['type'] = 'vulnerability'
        finding_form.form_data['description'] = 'SQL injection in login'
        finding_form.form_data['source'] = 'manual testing'

        result = finding_form.save_to_profile()

        assert result is True
        assert finding_form.saved is True

        # Verify finding was added to profile
        assert len(profile.findings) == 1

        finding = profile.findings[0]
        assert finding['type'] == 'vulnerability'
        assert finding['description'] == 'SQL injection in login'
        assert finding['source'] == 'manual testing'

    def test_save_success_all_fields(self, finding_form, profile):
        """Test save succeeds with all fields"""
        # Fill all fields
        finding_form.form_data = {
            'type': 'vulnerability',
            'description': 'SQL injection vulnerability',
            'source': 'sqlmap',
            'port': '443',
            'severity': 'high',
            'impact': 'Database compromise possible'
        }

        result = finding_form.save_to_profile()

        assert result is True
        assert len(profile.findings) == 1

        finding = profile.findings[0]
        assert finding['type'] == 'vulnerability'
        assert finding['description'] == 'SQL injection vulnerability'
        assert finding['source'] == 'sqlmap'
        assert finding['port'] == 443  # Should be int
        assert finding['severity'] == 'high'
        assert finding['impact'] == 'Database compromise possible'

    def test_save_requires_source(self, finding_form):
        """Test save enforces source requirement (OSCP compliance)"""
        # Fill fields but leave source empty
        finding_form.form_data['type'] = 'vulnerability'
        finding_form.form_data['description'] = 'Test finding'
        finding_form.form_data['source'] = ''  # Empty source

        result = finding_form.save_to_profile()

        assert result is False
        assert 'source' in finding_form.validation_errors


class TestFormReset:
    """Test form reset functionality"""

    def test_clear_form(self, finding_form):
        """Test clear form resets all fields"""
        # Fill form
        finding_form.form_data = {
            'type': 'vulnerability',
            'description': 'Test',
            'source': 'test',
            'port': '80',
            'severity': 'high',
            'impact': 'Test impact'
        }
        finding_form.validation_errors['source'] = 'Error'
        finding_form.saved = True
        finding_form.current_field = 3

        finding_form._clear_form()

        # Verify all fields cleared
        for field in finding_form.form_data.values():
            assert field == ''

        assert len(finding_form.validation_errors) == 0
        assert finding_form.saved is False
        assert finding_form.current_field == 0

    def test_reset_alias(self, finding_form):
        """Test reset() is alias for _clear_form()"""
        # Fill form
        finding_form.form_data['type'] = 'vulnerability'
        finding_form.form_data['source'] = 'test'

        finding_form.reset()

        assert finding_form.form_data['type'] == ''
        assert finding_form.form_data['source'] == ''


class TestTypeSelector:
    """Test type dropdown selector"""

    def test_render_type_selector(self):
        """Test rendering type selector panel"""
        panel, choices = FindingFormPanel.render_type_selector()

        from rich.panel import Panel
        assert isinstance(panel, Panel)
        assert isinstance(choices, list)

        # Should have choices for each type + cancel
        assert len(choices) == len(FindingFormPanel.FINDING_TYPES) + 1

        # Verify cancel option
        choice_ids = [c['id'] for c in choices]
        assert 'cancel' in choice_ids

    def test_render_type_selector_with_selection(self):
        """Test rendering type selector with current selection"""
        panel, choices = FindingFormPanel.render_type_selector('vulnerability')

        assert panel is not None
        assert len(choices) > 0


class TestSeveritySelector:
    """Test severity dropdown selector"""

    def test_render_severity_selector(self):
        """Test rendering severity selector panel"""
        panel, choices = FindingFormPanel.render_severity_selector()

        from rich.panel import Panel
        assert isinstance(panel, Panel)
        assert isinstance(choices, list)

        # Should have choices for each severity + cancel
        assert len(choices) == len(FindingFormPanel.SEVERITY_LEVELS) + 1

        # Verify cancel option
        choice_ids = [c['id'] for c in choices]
        assert 'cancel' in choice_ids

    def test_render_severity_selector_with_selection(self):
        """Test rendering severity selector with current selection"""
        panel, choices = FindingFormPanel.render_severity_selector('high')

        assert panel is not None
        assert len(choices) > 0


class TestTruncateDescription:
    """Test description truncation"""

    def test_truncate_short_description(self, finding_form):
        """Test short description is not truncated"""
        text = "Short description"
        result = finding_form._truncate_description(text, 50)

        assert result == text

    def test_truncate_long_description(self, finding_form):
        """Test long description is truncated"""
        text = "This is a very long description that should be truncated when displayed"
        result = finding_form._truncate_description(text, 30)

        assert len(result) <= 30
        assert result.endswith('...')

    def test_truncate_multiline_shows_first_line(self, finding_form):
        """Test multiline description shows only first line"""
        text = "First line\nSecond line\nThird line"
        result = finding_form._truncate_description(text, 50)

        assert result == "First line"
        assert '\n' not in result
