# Smart Suggest (sg) Tool - Implementation Documentation

## Overview
The **Smart Suggest (sg)** tool provides AI-lite, pattern-based suggestions to identify overlooked attack vectors during OSCP enumeration. It analyzes the current target state and recommends missing enumeration steps based on 22 built-in rules.

## Implementation Summary

### Files Created
- `/home/kali/OSCP/crack/track/interactive/smart_suggest_handler.py` (418 lines)
- `/home/kali/OSCP/crack/tests/track/test_smart_suggest.py` (433 lines, 21 tests)

### Files Modified
- `session.py` - Added `handle_smart_suggest()` handler
- `shortcuts.py` - Registered 'sg' shortcut
- `prompts.py` - Added sg help text
- `input_handler.py` - Added 'sg' to shortcuts list

## Architecture

### Pattern-Based Suggestion Engine

The suggestion engine evaluates 22 rules against the current target profile state:

```python
# Rule structure
{
    'id': 'mysql-no-enum',
    'pattern': 'mysql_open_no_tasks',
    'priority': 'high',
    'condition': lambda p: (
        any(port_info.get('service', '').lower() == 'mysql'
            for port_info in p.ports.values()) and
        not any('mysql' in t.name.lower()
            for t in p.task_tree.get_all_pending())
    ),
    'suggestion': 'MySQL port open but no enumeration tasks created',
    'command': 'mysql -h 192.168.45.100 -u root',
    'reasoning': 'MySQL commonly has weak/default credentials worth testing'
}
```

### Built-in Rules (22 Total)

#### Critical Priority (1)
- **findings-no-exploit**: Vulnerabilities documented but no exploitation tasks

#### High Priority (9)
- **mysql-no-enum**: MySQL port without enumeration
- **smb-no-null**: SMB without null session test
- **creds-no-reuse**: Credentials not tested on all services
- **ftp-no-anon**: FTP without anonymous login test
- **version-no-cve**: Service versions without exploit search
- **snmp-no-community**: SNMP without community string enumeration
- **nfs-no-showmount**: NFS without showmount
- **mssql-no-version-check**: MSSQL without xp_cmdshell attempt
- **tomcat-no-default**: Tomcat without default credential test
- **wordpress-no-scan**: WordPress without wpscan

#### Medium Priority (7)
- **http-no-robots**: Web service without robots.txt check
- **high-port-unknown**: High port with unknown service
- **multi-web-incomplete**: Multiple web ports not fully enumerated
- **dir-no-download**: Directories without file downloads
- **ssh-no-enum**: SSH without user enumeration
- **dns-no-axfr**: DNS without zone transfer test
- **ldap-no-enum**: LDAP without directory enumeration
- **creds-missing-source**: Credentials without source documentation

#### Low Priority (3)
- **web-no-screenshot**: Web service without visual recon
- **rdp-no-screenshot**: RDP without screenshot
- **no-manual-tasks**: No manual verification tasks

## Usage

### Interactive Mode

```bash
# Start interactive mode
crack track -i 192.168.45.100

# Use sg shortcut
> sg
```

### Output Format

```
Smart Suggest
==================================================

Analyzing current state...

Found 3 suggestion(s):

1. 🟠 MySQL port open but no enumeration tasks created
   Command: mysql -h 192.168.45.100 -u root
   Reasoning: MySQL commonly has weak/default credentials worth testing

2. 🟠 SMB service found but null session not tested
   Command: smbclient -L //192.168.45.100 -N
   Reasoning: Null sessions can reveal share information without credentials

3. 🟡 Web service found but robots.txt not checked
   Command: curl http://192.168.45.100/robots.txt
   Reasoning: robots.txt often reveals hidden directories

Create tasks for suggestions? [Y/n]:
```

### Priority Icons
- 🔴 Critical
- 🟠 High
- 🟡 Medium
- 🟢 Low

## Features

### 1. Pattern Matching
- Evaluates 22 rules against target profile
- Safe evaluation with exception handling
- Skips rules that fail without errors

### 2. Priority Sorting
- Suggestions sorted by priority: critical → high → medium → low
- Most important suggestions appear first

### 3. Task Creation
- Auto-creates tasks from suggestions
- Tasks tagged with SUGGESTION and OSCP priority
- Includes command, reasoning, and metadata

### 4. Comprehensive Detection
- Shows success message when no gaps found
- Provides tips for next steps

## Testing

### Test Coverage (21 Tests - All Passing)

**Shortcut Registration (3 tests)**
- Verifies sg shortcut exists
- Handler is callable
- Input handler recognition

**Rule Evaluation (9 tests)**
- MySQL suggestion
- SMB null session
- HTTP robots.txt
- Credential reuse
- High port unknown service
- FTP anonymous
- Version CVE search
- Multiple web ports
- Comprehensive enumeration

**Priority Sorting (2 tests)**
- Priority-based sorting
- No suggestions when comprehensive

**Task Creation (2 tests)**
- Single task creation
- Multiple task creation

**Integration (3 tests)**
- Full workflow end-to-end
- Task creation workflow
- No gaps scenario

**Rule Coverage (3 tests)**
- SNMP community string
- NFS showmount
- WordPress wpscan

### Running Tests

```bash
python -m pytest crack/tests/track/test_smart_suggest.py -v
```

**Result**: 21 passed in 0.08s

## Implementation Details

### Handler Method (session.py)

```python
def handle_smart_suggest(self):
    """AI-lite suggestions based on current state (pattern matching)"""
    from .smart_suggest_handler import get_suggestion_rules, create_suggestion_tasks

    print(DisplayManager.format_info("Smart Suggest"))
    print("=" * 50)
    print()

    print("Analyzing current state...")
    print()

    # Load suggestion rules
    rules = get_suggestion_rules(self.profile.target)

    # Evaluate rules
    suggestions = []
    for rule in rules:
        try:
            if rule['condition'](self.profile):
                suggestions.append(rule)
        except Exception:
            continue

    if not suggestions:
        print(DisplayManager.format_success("✓ No gaps found"))
        return

    # Sort by priority
    priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    suggestions.sort(key=lambda r: priority_order.get(r['priority'], 99))

    # Display and optionally create tasks
    # ...
```

### Shortcut Registration (shortcuts.py)

```python
'sg': ('Smart suggest', 'smart_suggest')

def smart_suggest(self):
    """Smart suggestions based on pattern matching (shortcut: sg)"""
    self.session.handle_smart_suggest()
```

## Value Proposition

### For OSCP Students
- **Identifies gaps**: Highlights missing enumeration steps
- **Pattern-based**: Uses proven attack patterns, not AI guessing
- **Educational**: Shows reasoning for each suggestion
- **Time-saving**: Quickly spots overlooked vectors
- **Exam-ready**: All suggestions are OSCP-relevant

### Reliability: 3/5
- Pattern matching is deterministic
- Quality depends on rule coverage
- False positives possible if tasks exist with different naming
- Best used as a checklist, not gospel

## Extension Guide

### Adding New Rules

1. Edit `smart_suggest_handler.py`
2. Add rule to `get_suggestion_rules()` function:

```python
{
    'id': 'unique-rule-id',
    'pattern': 'pattern_description',
    'priority': 'high',  # critical, high, medium, low
    'condition': lambda p: (
        # Your condition logic here
        # Return True if suggestion should trigger
    ),
    'suggestion': 'Human-readable suggestion',
    'command': 'Command to run',
    'reasoning': 'Why this is important'
}
```

3. Add test to `test_smart_suggest.py`
4. Run tests to verify

## Success Criteria - All Met

✅ Pattern-based suggestion engine
✅ 22 built-in rules (exceeds 20 requirement)
✅ Priority-based ranking
✅ Task creation from suggestions
✅ Handles comprehensive enumeration
✅ 21 tests passing (exceeds 14 requirement)
✅ ~418 lines implementation (exceeds 250 requirement)

## Files Reference

**Implementation:**
- `/home/kali/OSCP/crack/track/interactive/smart_suggest_handler.py`
- `/home/kali/OSCP/crack/track/interactive/session.py`
- `/home/kali/OSCP/crack/track/interactive/shortcuts.py`
- `/home/kali/OSCP/crack/track/interactive/prompts.py`
- `/home/kali/OSCP/crack/track/interactive/input_handler.py`

**Tests:**
- `/home/kali/OSCP/crack/tests/track/test_smart_suggest.py`

**Documentation:**
- This file

## Conclusion

The Smart Suggest (sg) tool provides lightweight, pattern-based suggestions to help OSCP students identify overlooked attack vectors. With 22 built-in rules covering common enumeration gaps, priority-based ranking, and automatic task creation, it serves as a valuable checklist during target assessment.

All requirements met. Implementation complete.
