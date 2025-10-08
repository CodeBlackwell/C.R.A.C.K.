# Command Templates System Changelog

## Overview

The Command Templates System provides reusable OSCP command patterns with variable substitution for common pentesting workflows. This feature enhances CRACK Track Interactive Mode by giving users quick access to pre-configured commands with educational metadata.

## Implementation Details

### Files Created

1. **`crack/track/interactive/templates.py` (475 lines)**
   - `CommandTemplate` class - Single template with variable substitution
   - `TemplateRegistry` class - Central template registry
   - 15+ pre-registered OSCP templates across categories

2. **`tests/track/test_templates.py` (520 lines)**
   - 31 comprehensive tests
   - Tests cover template creation, variable substitution, search, and OSCP workflows
   - All tests passing (31/31 ✓)

### Files Modified

1. **`crack/track/interactive/shortcuts.py`**
   - Added 'x' keyboard shortcut for command templates
   - Implemented `show_templates()` handler
   - Implemented `_fill_template()` for interactive variable filling
   - Templates execute with confirmation and log to profile

2. **`crack/track/interactive/prompts.py`**
   - Updated help text to include 'x' shortcut

3. **`crack/track/interactive/input_handler.py`**
   - Added 'x' to SHORTCUTS list for recognition
   - Updated module docstring

## Features

### Template Categories

Templates organized by OSCP phase:

- **Recon**: Port scanning, service detection
  - `nmap-quick` - Fast TCP SYN scan
  - `nmap-service` - Service version detection
  - `nmap-udp` - UDP port scan

- **Web**: Web enumeration and scanning
  - `gobuster-dir` - Directory brute-forcing
  - `nikto-scan` - Web vulnerability scanning
  - `whatweb` - Technology fingerprinting

- **Enumeration**: Service-specific enumeration
  - `enum4linux` - Complete SMB enumeration
  - `smbclient-list` - List SMB shares
  - `ldapsearch-anon` - Anonymous LDAP queries

- **Exploitation**: Exploit search and shells
  - `searchsploit` - Exploit database search
  - `bash-reverse-shell` - Bash TCP reverse shell
  - `nc-listener` - Netcat listener

### Template Metadata

Each template includes OSCP-relevant fields:

```python
CommandTemplate(
    template_id='unique-id',
    name='Human Readable Name',
    command='command with <PLACEHOLDERS>',
    description='What this command does',
    variables=[{
        'name': 'VARIABLE_NAME',
        'description': 'What this variable is',
        'example': 'Example value',
        'required': True/False
    }],
    category='recon|web|enumeration|exploitation',
    flag_explanations={'flag': 'Why this flag is used'},
    tags=['OSCP:HIGH', 'QUICK_WIN', etc.],
    alternatives=['Manual command alternatives'],
    success_indicators=['What success looks like'],
    estimated_time='Time estimate for exam planning'
)
```

### Interactive Workflow

1. User presses **'x'** in interactive mode
2. System displays template menu organized by category
3. User selects template by number or keyword
4. System shows:
   - Command with placeholders
   - Flag explanations (educational)
   - Estimated time
5. User fills in variables interactively with examples
6. System displays:
   - Final command
   - Manual alternatives (OSCP exam requirement)
   - Success indicators
7. User confirms execution (default: No for safety)
8. Command executes and logs to profile

### Variable Substitution

Templates use `<PLACEHOLDER>` syntax:

```python
template = TemplateRegistry.get('nmap-service')
filled = template.fill({
    'TARGET': '192.168.45.100',
    'PORTS': '22,80,443'
})
# Result: nmap -sV -sC -p 22,80,443 192.168.45.100 -oA nmap_service
```

### Search Functionality

Templates are searchable by:
- Name (case-insensitive)
- Description
- Tags
- Category

```python
TemplateRegistry.search('nmap')      # Find all nmap templates
TemplateRegistry.search('QUICK_WIN') # Find quick win templates
TemplateRegistry.list_by_category('web')  # All web templates
```

## OSCP Exam Features

### 1. Educational Focus

Every template includes flag explanations:

```
Flag Explanations:
  -sS: TCP SYN scan (stealth scan, requires root)
  -p-: Scan all 65535 ports (default is top 1000)
  --min-rate=1000: Send at least 1000 packets per second (faster scan)
```

### 2. Manual Alternatives

Templates provide manual methods for when tools fail (critical for OSCP exam):

```
Manual alternatives:
  • masscan -p1-65535 192.168.45.100 --rate=1000
  • nc -zv 192.168.45.100 1-65535 2>&1 | grep succeeded
```

### 3. Success Indicators

Templates help users verify results:

```
Success indicators:
  ✓ Open ports discovered
  ✓ Scan completes without firewall blocking
```

### 4. Time Estimates

Templates include time estimates for exam planning:

```
Estimated time: 1-5 minutes
```

### 5. Source Tracking

All template executions log to profile with source:

```json
{
  "note": "Executed template: Nmap Quick Scan\nCommand: nmap -sS -p- --min-rate=1000 192.168.45.100 -oA nmap_quick",
  "source": "command templates"
}
```

## Usage Examples

### From Interactive Mode

```bash
crack track -i 192.168.45.100

# Press 'x' to open templates
x

# Select template
1  # Or type "nmap"

# Fill variables
TARGET (Target IP address) [e.g., 192.168.45.100]: 192.168.45.100

# Review and execute
Execute command? [y/N]: y
```

### Programmatic Usage

```python
from crack.track.interactive.templates import TemplateRegistry

# Get specific template
template = TemplateRegistry.get('gobuster-dir')

# Fill variables
command = template.fill({
    'URL': 'http://192.168.45.100',
    'WORDLIST': '/usr/share/wordlists/dirb/common.txt'
})

# Execute
import subprocess
subprocess.run(command, shell=True)
```

### Search Templates

```python
# Search by keyword
results = TemplateRegistry.search('reverse shell')

# Filter by category
web_templates = TemplateRegistry.list_by_category('web')

# Get all categories
categories = TemplateRegistry.get_categories()
```

## Integration Points

### With Interactive Mode

- **Shortcut Key**: 'x' (command templates)
- **Menu Integration**: Accessible from any interactive mode screen
- **Profile Logging**: Template usage tracked in profile notes
- **Session State**: Last action updates with template name

### With Task System

Templates complement auto-generated tasks:
- Tasks provide structured enumeration workflow
- Templates provide quick ad-hoc command execution
- Both use same educational metadata format

### Future Enhancements

Potential future improvements:

1. **Config Integration**
   - Auto-fill from `~/.crack/config.json`
   - Remember last used values per template

2. **Template Customization**
   - User-defined templates in `~/.crack/templates/`
   - Template inheritance and overrides

3. **History Integration**
   - Recently used templates
   - Template execution history

4. **Smart Defaults**
   - Pre-fill TARGET from current profile
   - Suggest PORTS from discovered open ports
   - Suggest WORDLIST based on service type

5. **Category Expansion**
   - Post-exploitation templates
   - Privilege escalation templates
   - File transfer templates
   - Persistence templates

## Testing

All tests passing (31/31):

```bash
pytest tests/track/test_templates.py -v

# Results:
# TestCommandTemplate: 5/5 passed
# TestTemplateRegistry: 8/8 passed
# TestDefaultTemplates: 9/9 passed
# TestTemplateIntegration: 2/2 passed
# TestTemplateUsability: 4/4 passed
# TestRealOSCPWorkflows: 3/3 passed
```

Test coverage includes:
- Template creation and variable substitution
- Registry operations (register, search, filter)
- Default template verification
- OSCP metadata validation
- Real OSCP workflow support

## Performance

- **Template Loading**: Instant (pre-registered on import)
- **Search**: O(n) linear search (fast with ~15 templates)
- **Variable Substitution**: O(m) where m = number of variables
- **No External Dependencies**: Pure Python, stdlib only

## Documentation

- Module docstrings: Comprehensive API documentation
- Template metadata: Self-documenting with examples
- Help text: Integrated into interactive mode help
- Tests: Serve as usage examples

## Backward Compatibility

- No breaking changes to existing CRACK Track functionality
- New feature, additive only
- No changes to profile storage format
- No changes to CLI interface

## Security Considerations

- **Command Execution**: Requires explicit user confirmation (default: No)
- **Shell Injection**: Templates use simple string replacement (user validates final command)
- **Logging**: All executions logged to profile with full command
- **No Auto-execution**: Templates never execute without confirmation

## Lines of Code

- `templates.py`: 475 lines
- `shortcuts.py`: +150 lines (template handlers)
- `test_templates.py`: 520 lines
- **Total**: ~1145 lines

## Summary

The Command Templates System successfully implements a reusable command pattern library for OSCP workflows. Key achievements:

✅ 15+ pre-configured OSCP templates across 4 categories
✅ Full variable substitution with interactive filling
✅ Educational metadata (flags, alternatives, success indicators)
✅ Integration with interactive mode via 'x' shortcut
✅ Comprehensive test coverage (31 tests, 100% passing)
✅ Zero external dependencies
✅ OSCP exam-focused design (manual alternatives, source tracking)

The system enhances CRACK Track by providing quick access to common commands while maintaining the educational focus required for OSCP exam preparation.
