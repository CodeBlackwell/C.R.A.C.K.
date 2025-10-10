# Credential Form - Quick Reference Card

## Import

```python
from crack.track.core.state import TargetProfile
from crack.track.interactive.panels import CredentialFormPanel
```

## Basic Usage

```python
# 1. Create profile
profile = TargetProfile('192.168.45.100')

# 2. Create form
form = CredentialFormPanel.create(profile)

# 3. Render
panel, choices = form.render()
console.print(panel)

# 4. Fill fields
form.current_field = 0  # Username
form.edit_current_field('admin')

form.current_field = 1  # Password
form.edit_current_field('password123')

form.current_field = 3  # Source (REQUIRED)
form.edit_current_field('hydra brute force')

# 5. Save
if form.validate():
    form.save_to_profile()
    profile.save()  # Persist to disk
```

## Fields

| Index | Field | Required | Type | Validation |
|-------|-------|----------|------|------------|
| 0 | Username | Yes | text | Non-empty |
| 1 | Password | No* | password | - |
| 2 | Service | No | dropdown | In SERVICES list |
| 3 | Source | Yes | text | Non-empty |
| 4 | Port | No | numeric | 1-65535 |
| 5 | Notes | No* | text | - |

**Either password OR notes required*

## Navigation

```python
# Move between fields
form._next_field()        # Tab/Down
form._prev_field()        # Shift+Tab/Up

# Edit field
form.edit_current_field('value')

# Get field info
info = form.get_current_field_info()
# Returns: {'field_name', 'label', 'required', 'type', 'current_value', 'options'?}
```

## Validation

```python
# Validate all fields
is_valid = form.validate()

# Check errors
if not is_valid:
    for field, error in form.validation_errors.items():
        print(f"{field}: {error}")
```

## Actions

```python
# Process user input
action = form.process_input('s')  # Returns action code

# Action codes:
# 'continue'    - Continue in form
# 'edit-field'  - Edit current field
# 'save'        - Save credential
# 'back'        - Return to dashboard
```

## Password Masking

```python
# Toggle visibility
form._toggle_password_visibility()

# Check state
is_visible = form.show_password  # True/False

# Display uses bullets when False
# Plaintext stored regardless
```

## Service Selector

```python
# Render selector
panel, choices = CredentialFormPanel.render_service_selector()

# Get selected service
if user_choice == '1':
    service = choices[0]['service']  # 'SSH'
```

## Clear Form

```python
# Reset all fields
form._clear_form()
```

## Saved Structure

```python
credential = {
    'timestamp': '2025-10-10T01:15:50.635462',
    'username': 'admin',
    'password': 'P@ssw0rd123!',
    'service': 'SSH',
    'source': 'hydra brute force',
    'port': 22,
    'notes': 'Default creds'
}

# Access from profile
profile.credentials[0]
```

## Common Patterns

### Fill and Save
```python
form.form_data.update({
    'username': 'admin',
    'password': 'pass',
    'source': 'manual test'
})

if form.save_to_profile():
    print("Saved!")
```

### Validation Check
```python
if not form.validate():
    panel, choices = form.render()  # Errors shown in UI
else:
    form.save_to_profile()
```

### Multiple Credentials
```python
# Save first
form.save_to_profile()

# Clear and add another
form._clear_form()
form.form_data['username'] = 'user2'
form.form_data['password'] = 'pass2'
form.form_data['source'] = 'scan2'
form.save_to_profile()

# Both saved
len(profile.credentials)  # 2
```

## Testing

```bash
# Run all tests
python3 -m pytest tests/track/interactive/test_credential_form.py -v

# Run specific test
python3 -m pytest tests/track/interactive/test_credential_form.py::TestCredentialFormPanel::test_validation_required_fields -v

# Run example
python3 examples/credential_form_standalone.py
```

## Files

| File | Purpose |
|------|---------|
| `track/interactive/panels/credential_form.py` | Implementation (519 lines) |
| `tests/track/interactive/test_credential_form.py` | Tests (25 tests) |
| `examples/credential_form_standalone.py` | Example usage |
| `CREDENTIAL_FORM.md` | Full documentation (same directory) |

## OSCP Notes

- **Source field is mandatory** - Form won't save without it
- **Timestamps automatic** - ISO format on save
- **Plaintext storage** - Passwords stored unencrypted
- **Report ready** - Structure suitable for OSCP submission

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Validation fails | Check source field filled, password OR notes present |
| Port validation fails | Must be 1-65535 |
| Service validation fails | Must be in SERVICES list (case-insensitive) |
| Import error | Use `from crack.track.interactive.panels import CredentialFormPanel` |

## Integration Pattern

```python
# In TUISessionV2 (future)
def _credential_form_loop(self):
    form = CredentialFormPanel.create(self.profile)

    while True:
        panel, choices = form.render()
        self.layout['main'].update(panel)

        self._live.stop()
        user_input = input("Action: ").strip()
        self._live.start()

        action = form.process_input(user_input)

        if action == 'edit-field':
            # Handle editing
        elif action == 'save':
            if form.save_to_profile():
                self.profile.save()
        elif action == 'back':
            return  # Back to hub
```

---

**Quick Start:**
```python
from crack.track.interactive.panels import CredentialFormPanel
from crack.track.core.state import TargetProfile

p = TargetProfile('target')
f = CredentialFormPanel.create(p)
panel, choices = f.render()
```
