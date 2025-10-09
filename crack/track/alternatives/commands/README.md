# Adding Alternative Commands

## Quick Start

1. Choose a category file (e.g., `web_enumeration.py`)
2. Copy an example command from `TEMPLATE.py`
3. Modify for your alternative
4. Test with: `crack track -i TARGET` → press 'alt'

---

## Command Structure

See `TEMPLATE.py` for full working examples.

### Minimum Required Fields

```python
AlternativeCommand(
    id='unique-id',                  # Kebab-case identifier
    name='Human Readable Name',       # Shown in menu
    command_template='cmd <VAR>',     # Command with placeholders
    description='What this does',     # Help text
    category='web-enumeration'        # Category for organization
)
```

### Complete Example

```python
AlternativeCommand(
    id='alt-manual-curl-dir',
    name='Manual Directory Check (curl)',
    command_template='curl http://<TARGET>:<PORT>/<DIRECTORY>',
    description='Manually test for directory existence without gobuster',
    category='web-enumeration',
    subcategory='directory-discovery',
    variables=[
        Variable(
            name='TARGET',
            description='Target IP or hostname',
            example='192.168.45.100',
            auto_resolve=True,    # Try to auto-fill from context
            required=True
        ),
        Variable(
            name='PORT',
            description='Target port',
            example='80',
            auto_resolve=True,
            required=True
        ),
        Variable(
            name='DIRECTORY',
            description='Directory name to test',
            example='admin',
            auto_resolve=False,   # Always prompt user
            required=True
        )
    ],
    tags=['MANUAL', 'NO_TOOLS', 'OSCP:HIGH', 'QUICK_WIN'],
    os_type='both',  # 'linux', 'windows', or 'both'
    flag_explanations={},  # For commands with flags
    success_indicators=[
        'HTTP 200 OK',
        'Directory listing shown'
    ],
    failure_indicators=[
        'HTTP 404 Not Found',
        'Connection refused'
    ],
    next_steps=[
        'If found: Enumerate directory contents',
        'Check for index.php, config files'
    ],
    parent_task_pattern='gobuster-*'  # Links to gobuster tasks
)
```

---

## Variables

### Auto-Resolved Variables

These are filled automatically when available:

- `<TARGET>` → from `profile.target`
- `<PORT>` → from `task.metadata['port']`
- `<SERVICE>` → from `task.metadata['service']`
- `<VERSION>` → from `task.metadata['version']`
- `<LHOST>` → from config
- `<LPORT>` → from config
- `<WORDLIST>` → from config

### Variable Properties

```python
Variable(
    name='VAR_NAME',           # Without angle brackets
    description='What it is',  # Shown in prompt
    example='example value',   # Shown in prompt
    auto_resolve=True,         # Try to auto-fill from context
    required=True              # Must have value to execute
)
```

**auto_resolve behavior**:
- `True`: System tries to fill from context (profile/task/config). If not found, prompts user.
- `False`: Always prompts user (use for values only user knows, like directory names)

---

## Categories

| Category | Purpose | Example Commands |
|----------|---------|------------------|
| **web-enumeration** | HTTP, directory discovery, parameter fuzzing | curl, wget, browser checks |
| **privilege-escalation** | SUID, sudo, capabilities, kernel exploits | find, getcap, uname |
| **file-transfer** | Moving files to/from target | wget, curl, nc, python server |
| **anti-forensics** | Log clearing, timestamp manipulation | wevtutil, rm, touch |
| **database-enum** | MySQL, PostgreSQL, MSSQL manual queries | mysql, psql, sqlcmd |
| **network-recon** | Manual port scanning, service fingerprinting | nc, telnet, /dev/tcp |

---

## User Workflow Example

User in interactive mode viewing a gobuster task:

1. Press `alt` → sees alternatives menu
2. Selects "Manual Directory Check (curl)"
3. System shows:
   ```
   Enter values for placeholders:
     TARGET (Target IP) [config: 192.168.45.100]:
     PORT (Target port) [e.g., 80]:
     DIRECTORY (Directory name) [e.g., admin]:
   ```
4. User presses Enter for TARGET (uses config value 192.168.45.100)
5. User presses Enter for PORT (auto-filled from task: 80)
6. User types `admin` for DIRECTORY
7. System shows final command:
   ```
   Final command: curl http://192.168.45.100:80/admin
   Execute? [Y/n]:
   ```
8. User presses Enter → command executes
9. Output captured and logged to profile

---

## Tags

Use consistent tags for filtering:

- **OSCP Relevance**: `OSCP:HIGH`, `OSCP:MEDIUM`, `OSCP:LOW`
- **Success Rate**: `QUICK_WIN`, `RELIABLE`
- **Method**: `MANUAL`, `AUTOMATED`, `STEALTH`, `NOISY`
- **OS**: `LINUX`, `WINDOWS`, `BOTH_OS`
- **Phase**: `RECON`, `ENUM`, `EXPLOIT`, `PRIVESC`, `TRANSFER`
- **Tools**: `NO_TOOLS`, `REQUIRES_AUTH`

---

## Best Practices

### 1. Make Commands Self-Contained

✅ **Good**: `curl http://<TARGET>/admin -v`

❌ **Bad**: `cd /tmp && curl ...` (changes state)

### 2. Provide Educational Context

Include:
- `success_indicators`: How to know it worked
- `failure_indicators`: Common failure modes
- `next_steps`: What to do after success
- `flag_explanations`: What each flag means

### 3. Link to Parent Tasks

Use `parent_task_pattern` with glob matching:

```python
parent_task_pattern='gobuster-*'     # Matches gobuster-80, gobuster-443
parent_task_pattern='http-*'         # Matches all HTTP tasks
parent_task_pattern='*-enum-*'       # Matches any enum tasks
```

### 4. Set Appropriate auto_resolve

**auto_resolve=True** for:
- TARGET, PORT, SERVICE (from profile/task)
- LHOST, LPORT, WORDLIST (from config)

**auto_resolve=False** for:
- User-specific values (directory names, file paths)
- Values that vary per execution

---

## Testing Your Commands

```bash
# Run tests
pytest tests/track/test_alternatives.py -v -k your_command_id

# Manual test
crack track -i 192.168.45.100
# Then press 'alt' and select your command
```

---

## Common Patterns

### Simple Command (No Variables)

```python
AlternativeCommand(
    id='alt-check-hostname',
    name='Check Hostname',
    command_template='hostname',
    description='Display current hostname',
    category='network-recon',
    variables=[],  # No variables
    tags=['QUICK_WIN', 'LINUX']
)
```

### Command with Optional Variable

```python
Variable(
    name='TIMEOUT',
    description='Timeout in seconds',
    example='30',
    auto_resolve=False,
    required=False  # Optional
)
```

### Multiple Commands (Shell Chain)

```python
command_template='nc -zv <TARGET> <PORT> && echo "Port open" || echo "Port closed"'
```

---

## File Structure

```
commands/
├── README.md (this file)
├── TEMPLATE.py (copy-paste examples)
├── web_enumeration.py
├── privilege_escalation.py
├── file_transfer.py
├── anti_forensics.py
├── database_enum.py
└── network_recon.py
```

Each file exports: `ALTERNATIVES = [AlternativeCommand(...), ...]`

---

## Need Help?

See `TEMPLATE.py` for complete working examples.

Reference existing alternatives in plugin metadata:
```bash
grep -r "alternatives" /home/kali/OSCP/crack/track/services/*.py
```

Check core implementation:
- Models: `alternatives/models.py`
- Context: `alternatives/context.py`
- Executor: `alternatives/executor.py`
- Registry: `alternatives/registry.py`
