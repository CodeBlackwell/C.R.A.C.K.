# Finding Entry Form Panel - Quick Reference

## Import
```python
from crack.track.core.state import TargetProfile
from crack.track.interactive.panels.finding_form import FindingFormPanel
```

## Basic Usage

### Create Form
```python
profile = TargetProfile('192.168.1.100')
form = FindingFormPanel.create(profile)
```

### Render Panel
```python
panel, choices = form.render()
# Display panel with Rich Console
# Process choices for user input
```

### Edit Field
```python
# Get current field info
field_info = form.get_current_field_info()

# Update field value
success = form.edit_current_field('new value')
```

### Validate & Save
```python
if form.validate():
    form.save_to_profile()
else:
    print(form.validation_errors)
```

### Reset Form
```python
form.reset()  # Clear all fields
```

## Form Fields

| Field | Type | Required | Values |
|-------|------|----------|--------|
| Type | Dropdown | Yes | vulnerability, directory, credential, user, note, general |
| Description | Text | Yes | Multi-line supported |
| Source | Text | **YES** | Command/location (OSCP required) |
| Port | Numeric | No | 1-65535 |
| Severity | Dropdown | No | critical, high, medium, low, info |
| Impact | Text | No | Free-form description |

## Navigation Keys

| Key | Action |
|-----|--------|
| Tab / Down | Next field (wrap around) |
| Up | Previous field (wrap around) |
| e / Enter | Edit current field |
| s | Save finding |
| c | Clear form |
| b | Back to dashboard |

## Dropdown Selectors

### Type Selector
```python
panel, choices = FindingFormPanel.render_type_selector()
# Returns panel with 6 types + cancel option
```

### Severity Selector
```python
panel, choices = FindingFormPanel.render_severity_selector('high')
# Returns panel with 5 severities + cancel option
# Optional: Pass current selection for highlighting
```

## Input Processing Pattern

```python
# Process user input
action = form.process_input(user_choice)

if action == 'edit-field':
    # Get field info
    field_info = form.get_current_field_info()

    if field_info['type'] == 'dropdown':
        # Show dropdown selector
        if field_info['field_name'] == 'type':
            panel, choices = FindingFormPanel.render_type_selector()
        elif field_info['field_name'] == 'severity':
            panel, choices = FindingFormPanel.render_severity_selector()
    else:
        # Text/numeric input
        new_value = input(f"{field_info['label']}: ")
        form.edit_current_field(new_value)

elif action == 'save':
    if form.save_to_profile():
        print("✓ Finding saved!")
    else:
        print("✗ Validation failed")
        print(form.validation_errors)

elif action == 'back':
    return  # Exit form

elif action == 'continue':
    # Re-render form
    pass
```

## Validation Rules

### Required Fields
- Type (must be valid dropdown value)
- Description (cannot be empty)
- **Source (OSCP requirement - ALWAYS REQUIRED)**

### Optional Fields with Validation
- Port: Must be 1-65535 if provided
- Severity: Must be valid dropdown value if provided

### Validation Errors
```python
form.validation_errors = {
    'source': 'Required field',
    'port': 'Must be 1-65535'
}
```

## Field Info Structure

```python
field_info = {
    'field_name': 'type',
    'label': 'Type',
    'required': True,
    'type': 'dropdown',
    'current_value': 'vulnerability',
    'options': ['vulnerability', 'directory', ...]  # Only for dropdowns
}
```

## Example: Complete Workflow

```python
from crack.track.core.state import TargetProfile
from crack.track.interactive.panels.finding_form import FindingFormPanel

# Setup
profile = TargetProfile('192.168.1.100')
form = FindingFormPanel.create(profile)

# Fill form
form.form_data = {
    'type': 'vulnerability',
    'description': 'SQL injection in login form',
    'source': 'sqlmap --batch --dump -u http://target/login.php',
    'port': '443',
    'severity': 'high',
    'impact': 'Database compromise, credential extraction'
}

# Validate
if form.validate():
    # Save
    if form.save_to_profile():
        print("✓ Finding saved!")
        print(f"Total findings: {len(profile.findings)}")

        # Show saved finding
        finding = profile.findings[-1]
        print(f"Type: {finding['type']}")
        print(f"Source: {finding['source']}")
        print(f"Severity: {finding['severity']}")
else:
    print("Validation errors:")
    for field, error in form.validation_errors.items():
        print(f"  {field}: {error}")
```

## Common Patterns

### Pre-fill Form from Scan Result
```python
form = FindingFormPanel.create(profile)
form.form_data['type'] = 'vulnerability'
form.form_data['description'] = scan_result['description']
form.form_data['source'] = f"nmap -sV -p{port} {target}"
form.form_data['port'] = str(port)
```

### Validation Before Navigation
```python
# Before moving to next screen
if not form.validate():
    print("Please complete required fields:")
    for field in form.validation_errors:
        print(f"  - {field}")
    return  # Stay on form
```

### Dropdown Selection Handler
```python
# Show type selector
panel, choices = FindingFormPanel.render_type_selector()

# User selects choice (e.g., '1')
selected_choice = choices[0]  # select-1
selected_type = selected_choice['type']  # 'vulnerability'

# Update form
form.edit_current_field(selected_type)
```

## Tests

Run tests:
```bash
python -m pytest tests/track/interactive/panels/test_finding_form.py -v
```

Run demo:
```bash
python track/interactive/panels/FINDING_FORM_DEMO.py
```

## Key Design Decisions

1. **Source field is ALWAYS required** - OSCP documentation standard
2. **Validation on save, not on edit** - Better UX, errors shown in context
3. **Dropdown selectors as separate panels** - Consistent with credential/note forms
4. **Port as optional** - Not all findings have port associations
5. **Severity color coding** - Visual severity indication (red=critical, yellow=medium, etc.)

## File Locations

- **Implementation**: `/home/kali/OSCP/crack/track/interactive/panels/finding_form.py`
- **Tests**: `/home/kali/OSCP/crack/tests/track/interactive/panels/test_finding_form.py`
- **Demo**: `/home/kali/OSCP/crack/track/interactive/panels/FINDING_FORM_DEMO.py`
