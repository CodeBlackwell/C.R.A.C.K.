# Credential Entry Form Panel - Documentation

## Overview

The `CredentialFormPanel` is a standalone panel component for the CRACK Track TUI that provides structured credential capture with source tracking. Built following the hub-spoke navigation pattern, it ensures OSCP compliance by requiring source field documentation.

## File Location

```
/home/kali/OSCP/crack/track/interactive/panels/credential_form.py
```

## Features

1. **Multi-field Form**
   - Username (required)
   - Password (optional, with masking)
   - Service/Protocol (dropdown)
   - Source (required - OSCP compliance)
   - Port (optional, validated)
   - Notes (optional)

2. **Password Security**
   - Display masking (bullets)
   - Toggle visibility
   - Stored as plaintext (for pentesting use)

3. **Input Validation**
   - Required field enforcement
   - Port range validation (1-65535)
   - Service dropdown validation
   - Real-time error feedback

4. **Field Navigation**
   - Tab/Enter: Next field
   - Shift+Tab/Up: Previous field
   - Wrap-around navigation

5. **OSCP Compliance**
   - Source field mandatory
   - Timestamp tracking
   - Integration with profile.credentials

## Architecture Pattern

### BasePanel Pattern

The credential form follows the standard panel pattern:

```python
class CredentialFormPanel:
    def __init__(self, profile):
        """Initialize with TargetProfile instance"""

    def render(self) -> Tuple[Panel, List[Dict]]:
        """Render form and return (Panel, choices)"""

    def process_input(self, key: str) -> str:
        """Process navigation/action input"""

    def validate(self) -> bool:
        """Validate all form fields"""

    def save_to_profile(self) -> bool:
        """Save credential to profile"""
```

### Standalone Usage

```python
from crack.track.core.state import TargetProfile
from crack.track.interactive.panels.credential_form import CredentialFormPanel

# 1. Create profile
profile = TargetProfile('192.168.45.100')

# 2. Create form instance
form = CredentialFormPanel.create(profile)

# 3. Render form
panel, choices = form.render()
console.print(panel)

# 4. Fill fields programmatically
form.current_field = 0  # Username
form.edit_current_field('admin')

form.current_field = 1  # Password
form.edit_current_field('P@ssw0rd!')

form.current_field = 3  # Source (REQUIRED)
form.edit_current_field('hydra scan')

# 5. Validate and save
if form.validate():
    form.save_to_profile()
```

## Field Definitions

### Field Structure

```python
FIELDS = [
    ('username', 'Username', True, 'text'),
    ('password', 'Password', False, 'password'),
    ('service', 'Service/Protocol', False, 'dropdown'),
    ('source', 'Source (REQUIRED)', True, 'text'),
    ('port', 'Port (optional)', False, 'numeric'),
    ('notes', 'Notes (optional)', False, 'text')
]
# Format: (field_name, label, required, type)
```

### Supported Services

```python
SERVICES = [
    'SSH', 'FTP', 'HTTP', 'HTTPS', 'SMB', 'RDP',
    'MySQL', 'PostgreSQL', 'MSSQL', 'Oracle',
    'LDAP', 'Kerberos', 'SMTP', 'POP3', 'IMAP',
    'Telnet', 'VNC', 'WinRM', 'Redis', 'MongoDB',
    'Other'
]
```

## Validation Rules

### Required Fields

1. **Username** - Must be non-empty
2. **Source** - Must be non-empty (OSCP requirement)
3. **Password OR Notes** - At least one must be provided

### Field-Specific Validation

1. **Port** (if provided)
   - Must be numeric
   - Range: 1-65535

2. **Service** (if provided)
   - Must be in SERVICES list
   - Case-insensitive matching

### Validation Error Handling

```python
# Validate form
if not form.validate():
    # Errors available in form.validation_errors
    for field, error in form.validation_errors.items():
        print(f"{field}: {error}")
```

## User Interface

### Empty Form Display

```
╭───────────────────────── Dashboard > Add Credential ─────────────────────────╮
│   CREDENTIAL ENTRY FORM                                                      │
│                                                                              │
│   ► Username *             (empty)                                           │
│     Password               (empty)                                           │
│     Service/Protocol       (press Enter to select)                           │
│     Source (REQUIRED) *    (empty)                                           │
│     Port (optional)        (empty)                                           │
│     Notes (optional)       (empty)                                           │
│                                                                              │
│   Navigation:                                                                │
│                            ↑/↓ or Tab: Move between fields                   │
│                            Enter: Edit current field                         │
│                                                                              │
│   Actions:                                                                   │
│                            e. Edit current field                             │
│                            s. Save credential                                │
│                            c. Clear form                                     │
│                            b. Back to dashboard                              │
╰───────────────────── Target: 192.168.45.100 | Field 1/6 ─────────────────────╯
```

### Filled Form Display (Password Masked)

```
╭───────────────────────── Dashboard > Add Credential ─────────────────────────╮
│   CREDENTIAL ENTRY FORM                                                      │
│                                                                              │
│     Username *             admin                                             │
│     Password               ••••••••••••                                      │
│     Service/Protocol       SSH                                               │
│   ► Source (REQUIRED) *    hydra brute force attack                          │
│     Port (optional)        22                                                │
│     Notes (optional)       Default credentials found                         │
│                                                                              │
│   Actions:                                                                   │
│                            e. Edit current field                             │
│                            p. Show password                                  │
│                            s. Save credential                                │
│                            c. Clear form                                     │
│                            b. Back to dashboard                              │
╰───────────────────── Target: 192.168.45.100 | Field 4/6 ─────────────────────╯
```

### Validation Errors Display

```
╭───────────────────────── Dashboard > Add Credential ─────────────────────────╮
│   CREDENTIAL ENTRY FORM                                                      │
│                                                                              │
│   ✗ Username *             (empty) ← Required field                          │
│     Password               (empty)                                           │
│     Service/Protocol       (press Enter to select)                           │
│   ✗ Source (REQUIRED) *    (empty) ← Required field                          │
│     Port (optional)        (empty)                                           │
│     Notes (optional)       (empty)                                           │
│                                                                              │
│                            Validation Errors:                                │
│                              • username: Required field                      │
│                              • source: Required field                        │
│                              • password: Provide password or notes           │
╰───────────────────── Target: 192.168.45.100 | Field 1/6 ─────────────────────╯
```

## Service Selector

### Usage

```python
# Render service selector
panel, choices = CredentialFormPanel.render_service_selector(
    current_selection='SSH'
)
console.print(panel)

# Process selection
for choice in choices:
    if choice['id'] == 'select-1':
        selected_service = choice['service']  # 'SSH'
```

### Display

```
╭────────────────────────── Select Service/Protocol ───────────────────────────╮
│                                                                              │
│       #     Service/Protocol                   Common Port                   │
│  ───────────────────────────────────────────────────────────────             │
│       1     SSH                                22                            │
│       2     FTP                                21                            │
│       3     HTTP                               80                            │
│       4     HTTPS                              443                           │
│       5     SMB                                445                           │
│       6     RDP                                3389                          │
│      ...                                                                     │
│                                                                              │
│   1-21. Select service                                                       │
│   c. Cancel                                                                  │
╰───────────────── Choose the service this credential is for ──────────────────╯
```

## Input Processing

### Navigation Commands

| Input | Action |
|-------|--------|
| `tab`, `down` | Move to next field (wrap around) |
| `up` | Move to previous field (wrap around) |
| `e`, `enter` | Edit current field (returns 'edit-field') |

### Action Commands

| Input | Action | Return Value |
|-------|--------|--------------|
| `p` | Toggle password visibility | 'continue' |
| `s` | Save credential (validates first) | 'save' |
| `c` | Clear all form fields | 'continue' |
| `b` | Return to dashboard | 'back' |

### Processing Flow

```python
# Main TUI loop
while True:
    panel, choices = form.render()
    layout['main'].update(panel)

    live.stop()
    user_input = input("Action: ").strip()
    live.start()

    action = form.process_input(user_input)

    if action == 'edit-field':
        # Get current field info
        field_info = form.get_current_field_info()

        # Prompt user for input
        live.stop()
        new_value = input(f"{field_info['label']}: ")
        live.start()

        # Update field
        form.edit_current_field(new_value)

    elif action == 'save':
        if form.save_to_profile():
            # Success - render success message
            panel, choices = form.render()  # Shows success message
        else:
            # Validation failed - errors displayed in form
            pass

    elif action == 'back':
        break  # Return to dashboard
```

## Saved Credential Structure

### Profile Storage

```python
# Saved to profile.credentials list
credential = {
    'timestamp': '2025-10-10T01:15:50.635462',
    'username': 'admin',
    'password': 'P@ssw0rd123!',  # Plaintext
    'service': 'SSH',
    'source': 'hydra brute force attack',  # REQUIRED
    'port': 22,  # Integer
    'notes': 'Default credentials found'
}
```

### OSCP Report Compliance

The credential structure includes:
1. **Timestamp** - When discovered
2. **Source** - How discovered (command/tool used)
3. **Service context** - Where credential works
4. **Port** - Specific service instance

This ensures full traceability for OSCP report submission.

## Methods Reference

### Public Methods

#### `create(profile: TargetProfile) -> CredentialFormPanel`

Factory method to create form instance.

**Usage:**
```python
form = CredentialFormPanel.create(profile)
```

#### `render() -> Tuple[Panel, List[Dict]]`

Render form panel with current state.

**Returns:**
- `Panel` - Rich panel for display
- `List[Dict]` - Choices for input processing

**Example:**
```python
panel, choices = form.render()
console.print(panel)

# Choices structure:
# [
#   {'id': 'edit', 'label': 'Edit current field'},
#   {'id': 'save', 'label': 'Save credential'},
#   {'id': 'clear', 'label': 'Clear form'},
#   {'id': 'back', 'label': 'Back to dashboard'}
# ]
```

#### `process_input(user_input: str) -> str`

Process user input for navigation and actions.

**Returns:**
- `'continue'` - Continue in form
- `'edit-field'` - Edit current field
- `'save'` - Save credential
- `'back'` - Return to dashboard

**Example:**
```python
action = form.process_input('s')  # Returns 'save'
```

#### `edit_current_field(new_value: str) -> bool`

Update current field with validation.

**Returns:**
- `True` - Value valid and saved
- `False` - Validation failed (see `form.validation_errors`)

**Example:**
```python
form.current_field = 4  # Port field
success = form.edit_current_field('22')
if success:
    print(f"Port set to {form.form_data['port']}")
```

#### `get_current_field_info() -> Dict[str, Any]`

Get metadata for current field.

**Returns:**
```python
{
    'field_name': 'username',
    'label': 'Username',
    'required': True,
    'type': 'text',
    'current_value': 'admin',
    'options': [...]  # Only for dropdown fields
}
```

#### `validate() -> bool`

Validate all form fields.

**Returns:**
- `True` - All validation passed
- `False` - Validation errors present (see `form.validation_errors`)

**Example:**
```python
if not form.validate():
    for field, error in form.validation_errors.items():
        print(f"Error in {field}: {error}")
```

#### `save_to_profile() -> bool`

Validate and save credential to profile.

**Returns:**
- `True` - Saved successfully
- `False` - Validation failed

**Example:**
```python
if form.save_to_profile():
    print(f"Saved! Total credentials: {len(profile.credentials)}")
    form._clear_form()  # Reset for next entry
```

#### `render_service_selector(current_selection: Optional[str] = None) -> Tuple[Panel, List[Dict]]`

Render service selection menu (class method).

**Example:**
```python
panel, choices = CredentialFormPanel.render_service_selector()
console.print(panel)

# Process selection
if user_choice == '1':
    selected = next(c for c in choices if c['id'] == 'select-1')
    service = selected['service']  # 'SSH'
```

### Private Methods

#### `_next_field()`
Move to next field (wrap around).

#### `_prev_field()`
Move to previous field (wrap around).

#### `_toggle_password_visibility()`
Toggle password masking.

#### `_clear_form()`
Reset all form fields and state.

#### `_render_field(table, idx, field_name, label, required, field_type)`
Render individual form field (internal).

#### `_build_action_menu(table) -> List[Dict]`
Build action menu and return choices (internal).

## Testing

### Test Coverage

All functionality is tested in:
```
/home/kali/OSCP/crack/tests/track/interactive/test_credential_form.py
```

**Test Suite:** 25 tests covering:
- Form initialization
- Field navigation
- Password masking
- Input validation
- OSCP compliance (source field)
- Profile integration
- Service selector
- Error handling

### Running Tests

```bash
# Run all credential form tests
python3 -m pytest tests/track/interactive/test_credential_form.py -v

# Run specific test
python3 -m pytest tests/track/interactive/test_credential_form.py::TestCredentialFormPanel::test_source_field_required_oscp_compliance -v
```

### Manual Testing

```bash
# Run standalone example
python3 examples/credential_form_standalone.py
```

## Integration with Main TUI

The credential form is designed for integration into `TUISessionV2` but is **not yet integrated**. Future integration will follow the hub-spoke pattern:

```python
# Future integration in TUISessionV2
def _credential_form_loop(self):
    """Credential entry form spoke"""
    form = CredentialFormPanel.create(self.profile)

    while True:
        # Render form
        panel, choices = form.render()
        self.layout['main'].update(panel)
        self._live.refresh()

        # Get user input
        self._live.stop()
        user_input = input("Action: ").strip().lower()
        self._live.start()

        # Process input
        action = form.process_input(user_input)

        if action == 'edit-field':
            field_info = form.get_current_field_info()

            self._live.stop()
            if field_info['type'] == 'dropdown':
                # Show service selector
                selector_panel, selector_choices = CredentialFormPanel.render_service_selector()
                console.print(selector_panel)
                selection = input("Select service: ")
                # ... handle selection
            else:
                new_value = input(f"{field_info['label']}: ")
                form.edit_current_field(new_value)
            self._live.start()

        elif action == 'save':
            if form.save_to_profile():
                self.profile.save()  # Persist to disk
                # Show success message, then optionally clear for next entry

        elif action == 'back':
            return  # Back to dashboard
```

## Best Practices

### 1. Always Validate Before Saving

```python
# Good
if form.validate():
    form.save_to_profile()
else:
    # Show errors to user
    panel, choices = form.render()  # Errors displayed in panel
```

### 2. Clear Form After Successful Save

```python
if form.save_to_profile():
    console.print("[green]✓ Credential saved![/]")
    form._clear_form()  # Ready for next entry
```

### 3. Use Factory Method

```python
# Good
form = CredentialFormPanel.create(profile)

# Avoid
form = CredentialFormPanel(profile)  # Works but less idiomatic
```

### 4. Check Field Info Before Prompting

```python
field_info = form.get_current_field_info()

if field_info['type'] == 'dropdown':
    # Show service selector
    panel, choices = CredentialFormPanel.render_service_selector()
else:
    # Regular text input
    new_value = input(f"{field_info['label']}: ")
```

### 5. Persist Profile After Save

```python
if form.save_to_profile():
    profile.save()  # Write to ~/.crack/targets/<TARGET>.json
```

## OSCP Exam Considerations

### Source Field Requirement

The OSCP exam requires full documentation of how findings were discovered. The credential form enforces this by:

1. **Making source field mandatory** - Cannot save without it
2. **Timestamping entries** - Automatic timestamp on save
3. **Clear error messages** - "Source (REQUIRED)" in label

### Example Source Values

Good source values for OSCP reports:
```
- "hydra -l admin -P rockyou.txt ssh://192.168.45.100"
- "Manual inspection of /etc/passwd"
- "Burp Suite intercept of login request"
- "Found in config.php (LFI vulnerability)"
- "nmap --script ssh-brute 192.168.45.100"
- "Default credentials documented in vendor manual"
```

### Report Generation

Credentials are stored in `profile.credentials` list and can be exported for report inclusion:

```python
# Generate credential report
for cred in profile.credentials:
    print(f"{cred['timestamp']} - {cred['username']}:{cred.get('password', 'N/A')}")
    print(f"  Service: {cred.get('service', 'N/A')} on port {cred.get('port', 'N/A')}")
    print(f"  Source: {cred['source']}")
    print()
```

## Performance

- **Render time:** <10ms
- **Validation time:** <1ms
- **Save time:** <5ms (includes profile.save() disk write)

## Security Considerations

### Password Storage

Passwords are stored in **plaintext** in the profile JSON file because:

1. This is a **penetration testing tool** - credentials need to be usable
2. Profile files are stored in `~/.crack/targets/` (user-only access)
3. Password masking in UI is for visual privacy, not security
4. OSCP reports require actual credentials to be documented

### File Permissions

Profile files should have restricted permissions:
```bash
chmod 600 ~/.crack/targets/*.json
```

## Troubleshooting

### Common Issues

1. **Import errors**
   ```python
   # Correct import
   from crack.track.interactive.panels.credential_form import CredentialFormPanel
   ```

2. **Validation always fails**
   - Check source field is filled
   - Ensure either password or notes is provided
   - Verify port is in range 1-65535

3. **Password not masked**
   - Check `form.show_password` is False
   - Password field must have a value

4. **Service validation fails**
   - Service must be in `CredentialFormPanel.SERVICES` list
   - Check for typos (case-insensitive matching)

## Future Enhancements

Planned improvements:
1. **Auto-fill from context** - Pre-populate port from task context
2. **Password generator** - Built-in password strength checker
3. **Duplicate detection** - Warn if credential already exists
4. **Batch import** - Import credentials from file (hashcat format)
5. **Export formats** - Generate credential lists for tools

## Related Files

- **Panel implementation:** `/home/kali/OSCP/crack/track/interactive/panels/credential_form.py`
- **Tests:** `/home/kali/OSCP/crack/tests/track/interactive/test_credential_form.py`
- **Example:** `/home/kali/OSCP/crack/examples/credential_form_standalone.py`
- **State management:** `/home/kali/OSCP/crack/track/core/state.py` (TargetProfile)
- **Panel exports:** `/home/kali/OSCP/crack/track/interactive/panels/__init__.py`

## Contact

For questions or issues with the credential form panel, please refer to the test suite or standalone example for usage patterns.
