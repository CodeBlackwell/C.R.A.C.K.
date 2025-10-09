# Alternative Commands Quick Start

**5-Minute Guide to Adding Your First Alternative Command**

---

## Step 1: Choose a Category

Pick the category file that matches your command:

- `web_enumeration.py` - HTTP, directories, APIs
- `privilege_escalation.py` - SUID, sudo, capabilities
- `file_transfer.py` - wget, curl, nc, python servers
- `anti_forensics.py` - Log clearing, timestamps
- `database_enum.py` - MySQL, PostgreSQL, MSSQL
- `network_recon.py` - Port scanning, service fingerprinting

---

## Step 2: Copy the Template

Open `commands/TEMPLATE.py` and find an example that matches your needs:

**Example 1: Simple Command (No Variables)**
```python
AlternativeCommand(
    id='alt-example-simple',
    name='Simple Command Example',
    command_template='whoami',
    description='Display current user (no variables needed)',
    category='privilege-escalation',
    tags=['QUICK_WIN', 'LINUX', 'WINDOWS']
)
```

**Example 2: Command with Auto-Resolved Variables**
```python
AlternativeCommand(
    id='alt-example-auto-resolve',
    name='Auto-Resolve Example',
    command_template='nc -zv <TARGET> <PORT>',
    description='Test port connectivity with netcat',
    category='network-recon',
    variables=[
        Variable(
            name='TARGET',
            description='Target IP or hostname',
            example='192.168.45.100',
            auto_resolve=True,  # System fills from profile.target
            required=True
        ),
        Variable(
            name='PORT',
            description='Port to test',
            example='80',
            auto_resolve=True,  # System fills from task metadata
            required=True
        )
    ],
    tags=['MANUAL', 'OSCP:HIGH'],
    os_type='both'
)
```

**Example 3: Command with User-Prompted Variables**
```python
AlternativeCommand(
    id='alt-example-user-prompt',
    name='User Prompt Example',
    command_template='curl http://<TARGET>:<PORT>/<DIRECTORY>',
    description='Manual directory check (user provides directory name)',
    category='web-enumeration',
    variables=[
        Variable(
            name='TARGET',
            auto_resolve=True,  # Auto-filled
            required=True
        ),
        Variable(
            name='PORT',
            auto_resolve=True,  # Auto-filled
            required=True
        ),
        Variable(
            name='DIRECTORY',
            description='Directory name to check',
            example='admin',
            auto_resolve=False,  # ALWAYS prompt user
            required=True
        )
    ],
    tags=['MANUAL', 'NO_TOOLS', 'OSCP:HIGH'],
    os_type='both'
)
```

---

## Step 3: Modify for Your Command

Let's create a sitemap.xml checker:

```python
# In commands/web_enumeration.py

from ..models import AlternativeCommand, Variable

ALTERNATIVES = [
    # ... existing alternatives ...

    # YOUR NEW COMMAND
    AlternativeCommand(
        id='alt-sitemap-check',
        name='Check sitemap.xml',
        command_template='curl http://<TARGET>:<PORT>/sitemap.xml',
        description='Manually check sitemap.xml for site structure',
        category='web-enumeration',
        subcategory='information-disclosure',
        variables=[
            Variable(name='TARGET', auto_resolve=True, required=True),
            Variable(name='PORT', auto_resolve=True, required=True)
        ],
        tags=['MANUAL', 'QUICK_WIN', 'OSCP:HIGH', 'NO_TOOLS'],
        os_type='both',
        success_indicators=[
            'sitemap.xml file found',
            'URL list displayed'
        ],
        failure_indicators=[
            'HTTP 404',
            'File not found'
        ],
        next_steps=[
            'Visit each URL in sitemap',
            'Look for admin/hidden pages'
        ],
        notes='Alternative: Also check /sitemap_index.xml for larger sites',
        parent_task_pattern='http-*'
    ),
]
```

---

## Step 4: Test It

```bash
# Launch interactive mode
crack track -i 192.168.45.100

# Press 'alt'
# Select "Browse by category" → "Web Enumeration"
# Your command appears in the list!

# Select it:
#   Enter values for placeholders:
#     TARGET (Target IP) [config: 192.168.45.100]: [press Enter]
#     PORT (Target port) [e.g., 80]: 80
#
#   Final command: curl http://192.168.45.100:80/sitemap.xml
#   Execute? [Y/n]: y
#
#   [command runs and output shown]
```

---

## Variable Quick Reference

### Auto-Resolved Variables (System Fills These)

```python
# From profile.target
Variable(name='TARGET', auto_resolve=True)

# From task.metadata['port']
Variable(name='PORT', auto_resolve=True)

# From task.metadata['service']
Variable(name='SERVICE', auto_resolve=True)

# From config (LHOST, LPORT, WORDLIST)
Variable(name='LHOST', auto_resolve=True)
Variable(name='LPORT', auto_resolve=True)
```

### User-Prompted Variables (User Provides These)

```python
# User knows what directory to test
Variable(
    name='DIRECTORY',
    description='Directory name',
    example='admin',
    auto_resolve=False,  # Always prompt
    required=True
)

# Optional variable
Variable(
    name='TIMEOUT',
    description='Timeout in seconds',
    example='30',
    auto_resolve=False,
    required=False  # Optional
)
```

---

## Tag Reference

Use these standard tags for filtering:

```python
tags=[
    'OSCP:HIGH',      # High relevance for OSCP
    'OSCP:MEDIUM',    # Medium relevance
    'OSCP:LOW',       # Low relevance

    'QUICK_WIN',      # Fast to execute
    'RELIABLE',       # Usually works

    'MANUAL',         # Manual testing (no tools)
    'AUTOMATED',      # Uses automation tools
    'STEALTH',        # Stealthy approach
    'NOISY',          # Noisy/detectable

    'LINUX',          # Linux-only
    'WINDOWS',        # Windows-only
    'BOTH_OS',        # Works on both

    'NO_TOOLS',       # No external tools needed
    'REQUIRES_AUTH',  # Needs credentials
]
```

---

## Common Patterns

### Command with Multiple Steps

```python
command_template='nc -zv <TARGET> <PORT> && echo "Port open" || echo "Port closed"'
```

### Command with Optional Port

```python
command_template='curl http://<TARGET>:<PORT>/admin'  # Port required
command_template='curl http://<TARGET>/admin'         # No port (uses default 80)
```

### Command with Multiple Variables

```python
variables=[
    Variable(name='TARGET', auto_resolve=True),
    Variable(name='PORT', auto_resolve=True),
    Variable(name='USERNAME', auto_resolve=False),
    Variable(name='PASSWORD', auto_resolve=False)
]
```

---

## Full Example: SSH Banner Grab

```python
# Add to commands/network_recon.py

AlternativeCommand(
    id='alt-ssh-banner-grab',
    name='SSH Banner Grab',
    command_template='nc -nv <TARGET> <PORT>',
    description='Manually grab SSH banner for version detection',
    category='network-recon',
    subcategory='banner-grabbing',
    variables=[
        Variable(
            name='TARGET',
            description='Target IP',
            example='192.168.45.100',
            auto_resolve=True,
            required=True
        ),
        Variable(
            name='PORT',
            description='SSH port',
            example='22',
            auto_resolve=False,  # User specifies (might not be 22)
            required=True
        )
    ],
    tags=['MANUAL', 'OSCP:HIGH', 'NO_TOOLS', 'LINUX', 'BOTH_OS'],
    os_type='both',
    flag_explanations={
        '-n': 'No DNS resolution (faster)',
        '-v': 'Verbose output'
    },
    success_indicators=[
        'SSH banner displayed',
        'Version number shown (e.g., OpenSSH_7.4)'
    ],
    failure_indicators=[
        'Connection refused',
        'Connection timed out',
        'No banner received'
    ],
    next_steps=[
        'Search version in searchsploit',
        'Check for known vulnerabilities',
        'Note version in enumeration.md'
    ],
    notes='Alternative: ssh -v <TARGET> (but this attempts connection)',
    parent_task_pattern='ssh-*'
)
```

---

## Troubleshooting

**Q: My command doesn't appear in the menu**

A: Make sure you:
1. Added it to the `ALTERNATIVES` list in the category file
2. Saved the file
3. No syntax errors in your Python code

**Q: Variables aren't auto-filling**

A: Check that:
1. `auto_resolve=True` is set
2. The variable name matches what's in context (e.g., 'TARGET' not 'TARGET_IP')
3. The profile/task has the data (e.g., profile.target is set)

**Q: Command fails to execute**

A: Verify:
1. All required variables have values
2. Command syntax is correct
3. Command works when run manually in terminal

---

## Where to Get Help

1. **README.md**: Comprehensive developer guide
2. **TEMPLATE.py**: Working examples with all features
3. **Existing commands**: See category files for real examples
4. **Tests**: `tests/track/test_alternatives.py` for reference

---

**That's it!** You can now add alternative commands to CRACK Track. Happy coding! 🚀
