"""
Tests for Credential Entry Form Panel

Validates:
- Form rendering and field navigation
- Password masking functionality
- Input validation (required fields, port range)
- Source field requirement (OSCP compliance)
- Save to profile.credentials
- Form reset functionality
"""

import pytest
from crack.track.core.state import TargetProfile
from crack.track.interactive.panels.credential_form import CredentialFormPanel


class TestCredentialFormPanel:
    """Test credential form panel functionality"""

    @pytest.fixture
    def profile(self, tmp_path):
        """Create temporary target profile"""
        # Create a test profile
        profile = TargetProfile('192.168.45.100')
        return profile

    @pytest.fixture
    def form(self, profile):
        """Create credential form instance"""
        return CredentialFormPanel.create(profile)

    def test_form_initialization(self, form, profile):
        """Test form initializes with correct default state"""
        assert form.profile == profile
        assert form.current_field == 0
        assert form.show_password is False
        assert form.saved is False
        assert len(form.validation_errors) == 0

        # Check all form fields initialized to empty
        assert form.form_data['username'] == ''
        assert form.form_data['password'] == ''
        assert form.form_data['service'] == ''
        assert form.form_data['source'] == ''
        assert form.form_data['port'] == ''
        assert form.form_data['notes'] == ''

    def test_render_returns_panel_and_choices(self, form):
        """Test render method returns Panel and choices list"""
        panel, choices = form.render()

        # Verify return types
        from rich.panel import Panel
        assert isinstance(panel, Panel)
        assert isinstance(choices, list)
        assert len(choices) > 0

        # Verify expected actions present
        choice_ids = [c['id'] for c in choices]
        assert 'edit' in choice_ids
        assert 'save' in choice_ids
        assert 'clear' in choice_ids
        assert 'back' in choice_ids

    def test_field_navigation_next(self, form):
        """Test navigation to next field"""
        # Start at field 0
        assert form.current_field == 0

        # Move to next field
        form._next_field()
        assert form.current_field == 1

        # Move to next field
        form._next_field()
        assert form.current_field == 2

        # Test wrap-around (last field -> first field)
        form.current_field = len(form.FIELDS) - 1
        form._next_field()
        assert form.current_field == 0

    def test_field_navigation_previous(self, form):
        """Test navigation to previous field"""
        # Start at field 1
        form.current_field = 1

        # Move to previous field
        form._prev_field()
        assert form.current_field == 0

        # Test wrap-around (first field -> last field)
        form._prev_field()
        assert form.current_field == len(form.FIELDS) - 1

    def test_password_masking(self, form):
        """Test password masking toggle"""
        # Set password value
        form.form_data['password'] = 'secretpass123'

        # Initially not visible
        assert form.show_password is False

        # Toggle to visible
        form._toggle_password_visibility()
        assert form.show_password is True

        # Toggle back to hidden
        form._toggle_password_visibility()
        assert form.show_password is False

    def test_edit_field_text(self, form):
        """Test editing text field"""
        # Navigate to username field (field 0)
        form.current_field = 0

        # Edit field
        success = form.edit_current_field('admin')
        assert success is True
        assert form.form_data['username'] == 'admin'
        assert 'username' not in form.validation_errors

    def test_edit_field_numeric_valid(self, form):
        """Test editing numeric field with valid port"""
        # Navigate to port field (field 4)
        form.current_field = 4

        # Edit with valid port
        success = form.edit_current_field('22')
        assert success is True
        assert form.form_data['port'] == '22'
        assert 'port' not in form.validation_errors

    def test_edit_field_numeric_invalid(self, form):
        """Test editing numeric field with invalid port"""
        # Navigate to port field (field 4)
        form.current_field = 4

        # Edit with invalid port (out of range)
        success = form.edit_current_field('99999')
        assert success is False
        assert 'port' in form.validation_errors
        assert 'must be 1-65535' in form.validation_errors['port'].lower()

        # Edit with non-numeric
        success = form.edit_current_field('abc')
        assert success is False
        assert 'port' in form.validation_errors
        assert 'must be a number' in form.validation_errors['port'].lower()

    def test_edit_field_dropdown_valid(self, form):
        """Test editing dropdown field with valid service"""
        # Navigate to service field (field 2)
        form.current_field = 2

        # Edit with valid service
        success = form.edit_current_field('SSH')
        assert success is True
        assert form.form_data['service'] == 'SSH'
        assert 'service' not in form.validation_errors

        # Test case-insensitive
        success = form.edit_current_field('http')
        assert success is True
        assert form.form_data['service'] == 'http'

    def test_edit_field_dropdown_invalid(self, form):
        """Test editing dropdown field with invalid service"""
        # Navigate to service field (field 2)
        form.current_field = 2

        # Edit with invalid service
        success = form.edit_current_field('INVALID_SERVICE')
        assert success is False
        assert 'service' in form.validation_errors

    def test_validation_required_fields(self, form):
        """Test validation requires username and source"""
        # Empty form should fail validation
        is_valid = form.validate()
        assert is_valid is False
        assert 'username' in form.validation_errors
        assert 'source' in form.validation_errors

        # Fill username only - still fails
        form.form_data['username'] = 'admin'
        is_valid = form.validate()
        assert is_valid is False
        assert 'username' not in form.validation_errors
        assert 'source' in form.validation_errors

        # Fill source only - still fails (need username)
        form.form_data['username'] = ''
        form.form_data['source'] = '/etc/passwd'
        is_valid = form.validate()
        assert is_valid is False
        assert 'username' in form.validation_errors

    def test_validation_password_or_notes_required(self, form):
        """Test validation requires at least password or notes"""
        # Fill only required fields
        form.form_data['username'] = 'admin'
        form.form_data['source'] = '/etc/passwd'

        # Should fail (need password or notes)
        is_valid = form.validate()
        assert is_valid is False
        assert 'password' in form.validation_errors

        # Add password - should pass
        form.form_data['password'] = 'secretpass'
        is_valid = form.validate()
        assert is_valid is True

        # Remove password, add notes - should pass
        form.form_data['password'] = ''
        form.form_data['notes'] = 'Found in config file'
        is_valid = form.validate()
        assert is_valid is True

    def test_save_to_profile_success(self, form, profile):
        """Test saving valid credential to profile"""
        # Fill valid form data
        form.form_data['username'] = 'admin'
        form.form_data['password'] = 'P@ssw0rd!'
        form.form_data['service'] = 'SSH'
        form.form_data['source'] = '/etc/shadow'
        form.form_data['port'] = '22'
        form.form_data['notes'] = 'Default credentials'

        # Save should succeed
        success = form.save_to_profile()
        assert success is True
        assert form.saved is True

        # Verify saved to profile
        assert len(profile.credentials) == 1
        cred = profile.credentials[0]
        assert cred['username'] == 'admin'
        assert cred['password'] == 'P@ssw0rd!'
        assert cred['service'] == 'SSH'
        assert cred['source'] == '/etc/shadow'
        assert cred['port'] == 22  # Should be int
        assert cred['notes'] == 'Default credentials'

    def test_save_to_profile_validation_failure(self, form, profile):
        """Test saving invalid credential fails"""
        # Empty form
        success = form.save_to_profile()
        assert success is False
        assert form.saved is False

        # Verify not saved to profile
        assert len(profile.credentials) == 0

    def test_save_to_profile_minimal_fields(self, form, profile):
        """Test saving credential with only required fields"""
        # Fill minimal data
        form.form_data['username'] = 'user'
        form.form_data['password'] = 'pass'
        form.form_data['source'] = 'manual'

        # Save should succeed
        success = form.save_to_profile()
        assert success is True

        # Verify saved with only provided fields
        assert len(profile.credentials) == 1
        cred = profile.credentials[0]
        assert cred['username'] == 'user'
        assert cred['password'] == 'pass'
        assert cred['source'] == 'manual'
        assert 'service' not in cred
        assert 'port' not in cred
        assert 'notes' not in cred

    def test_clear_form(self, form):
        """Test clearing form resets all fields"""
        # Fill form
        form.form_data['username'] = 'admin'
        form.form_data['password'] = 'pass'
        form.form_data['service'] = 'SSH'
        form.form_data['source'] = 'file'
        form.form_data['port'] = '22'
        form.form_data['notes'] = 'test'
        form.current_field = 3
        form.saved = True
        form.show_password = True
        form.validation_errors['username'] = 'test error'

        # Clear form
        form._clear_form()

        # Verify all fields reset
        assert form.form_data['username'] == ''
        assert form.form_data['password'] == ''
        assert form.form_data['service'] == ''
        assert form.form_data['source'] == ''
        assert form.form_data['port'] == ''
        assert form.form_data['notes'] == ''
        assert form.current_field == 0
        assert form.saved is False
        assert form.show_password is False
        assert len(form.validation_errors) == 0

    def test_process_input_navigation(self, form):
        """Test input processing for navigation commands"""
        # Tab moves to next field
        result = form.process_input('tab')
        assert result == 'continue'
        assert form.current_field == 1

        # Down moves to next field
        result = form.process_input('down')
        assert result == 'continue'
        assert form.current_field == 2

        # Up moves to previous field
        result = form.process_input('up')
        assert result == 'continue'
        assert form.current_field == 1

    def test_process_input_actions(self, form):
        """Test input processing for action commands"""
        # Edit field
        result = form.process_input('e')
        assert result == 'edit-field'

        result = form.process_input('enter')
        assert result == 'edit-field'

        # Save
        result = form.process_input('s')
        assert result == 'save'

        # Clear
        result = form.process_input('c')
        assert result == 'continue'

        # Back
        result = form.process_input('b')
        assert result == 'back'

    def test_process_input_password_toggle(self, form):
        """Test password toggle input processing"""
        # Add password to enable toggle
        form.form_data['password'] = 'test'

        # Toggle visibility
        assert form.show_password is False
        result = form.process_input('p')
        assert result == 'continue'
        assert form.show_password is True

        # Toggle back
        result = form.process_input('p')
        assert result == 'continue'
        assert form.show_password is False

    def test_get_current_field_info(self, form):
        """Test getting current field metadata"""
        # Navigate to username field (field 0)
        form.current_field = 0
        form.form_data['username'] = 'admin'

        info = form.get_current_field_info()
        assert info['field_name'] == 'username'
        assert info['label'] == 'Username'
        assert info['required'] is True
        assert info['type'] == 'text'
        assert info['current_value'] == 'admin'
        assert 'options' not in info

        # Navigate to service dropdown (field 2)
        form.current_field = 2

        info = form.get_current_field_info()
        assert info['field_name'] == 'service'
        assert info['type'] == 'dropdown'
        assert 'options' in info
        assert 'SSH' in info['options']
        assert 'HTTP' in info['options']

    def test_render_service_selector(self):
        """Test service selector rendering"""
        panel, choices = CredentialFormPanel.render_service_selector()

        # Verify return types
        from rich.panel import Panel
        assert isinstance(panel, Panel)
        assert isinstance(choices, list)

        # Verify all services have choices
        assert len(choices) >= len(CredentialFormPanel.SERVICES)

        # Verify choice structure
        select_choices = [c for c in choices if c['id'].startswith('select-')]
        assert len(select_choices) == len(CredentialFormPanel.SERVICES)

        # Verify cancel choice
        cancel_choices = [c for c in choices if c['id'] == 'cancel']
        assert len(cancel_choices) == 1

    def test_render_service_selector_with_selection(self):
        """Test service selector with current selection"""
        panel, choices = CredentialFormPanel.render_service_selector(current_selection='SSH')

        # Should still work with selection
        assert isinstance(choices, list)
        assert len(choices) >= len(CredentialFormPanel.SERVICES)

    def test_source_field_required_oscp_compliance(self, form, profile):
        """Test source field is required for OSCP compliance"""
        # Fill all fields except source
        form.form_data['username'] = 'admin'
        form.form_data['password'] = 'pass'

        # Validation should fail
        is_valid = form.validate()
        assert is_valid is False
        assert 'source' in form.validation_errors

        # Save should fail
        success = form.save_to_profile()
        assert success is False
        assert len(profile.credentials) == 0

        # Add source
        form.form_data['source'] = 'gobuster scan'

        # Now should succeed
        is_valid = form.validate()
        assert is_valid is True

        success = form.save_to_profile()
        assert success is True
        assert len(profile.credentials) == 1
        assert profile.credentials[0]['source'] == 'gobuster scan'

    def test_password_stored_as_plaintext(self, form, profile):
        """Test password is stored as plaintext (not masked)"""
        # Fill form with password
        form.form_data['username'] = 'admin'
        form.form_data['password'] = 'P@ssw0rd123!'
        form.form_data['source'] = 'manual'

        # Save to profile
        success = form.save_to_profile()
        assert success is True

        # Verify password stored as plaintext
        cred = profile.credentials[0]
        assert cred['password'] == 'P@ssw0rd123!'
        assert '•' not in cred['password']  # Not masked

    def test_multiple_credentials_can_be_saved(self, form, profile):
        """Test multiple credentials can be saved to profile"""
        # Save first credential
        form.form_data['username'] = 'admin'
        form.form_data['password'] = 'pass1'
        form.form_data['source'] = 'source1'
        form.save_to_profile()

        # Clear and save second credential
        form._clear_form()
        form.form_data['username'] = 'user'
        form.form_data['password'] = 'pass2'
        form.form_data['source'] = 'source2'
        form.save_to_profile()

        # Verify both saved
        assert len(profile.credentials) == 2
        assert profile.credentials[0]['username'] == 'admin'
        assert profile.credentials[1]['username'] == 'user'
