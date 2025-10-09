"""
TEMPLATE for Alternative Commands

COPY THIS FILE or individual examples to create new alternatives.

This file contains complete, working examples demonstrating:
1. Simple command (no variables)
2. Command with auto-resolved variables
3. Command with user-prompted variables
4. Complete example with all fields populated
"""

from ..models import AlternativeCommand, Variable


# ============================================================================
# EXAMPLE 1: Simple Command (No Variables)
# ============================================================================

simple_example = AlternativeCommand(
    id='alt-example-simple',
    name='Simple Command Example',
    command_template='whoami',
    description='Display current user (no variables needed)',
    category='privilege-escalation',
    tags=['QUICK_WIN', 'LINUX', 'WINDOWS']
)


# ============================================================================
# EXAMPLE 2: Command with Auto-Resolved Variables
# ============================================================================

auto_resolve_example = AlternativeCommand(
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
            auto_resolve=True,  # Tries to get from profile.target
            required=True
        ),
        Variable(
            name='PORT',
            description='Port to test',
            example='80',
            auto_resolve=True,  # Tries to get from task metadata
            required=True
        )
    ],
    tags=['MANUAL', 'OSCP:HIGH'],
    os_type='both'
)


# ============================================================================
# EXAMPLE 3: Command with User-Prompted Variables
# ============================================================================

user_prompt_example = AlternativeCommand(
    id='alt-example-user-prompt',
    name='User Prompt Example',
    command_template='curl http://<TARGET>:<PORT>/<DIRECTORY>',
    description='Manual directory check (user provides directory name)',
    category='web-enumeration',
    subcategory='directory-discovery',
    variables=[
        Variable(
            name='TARGET',
            description='Target IP',
            example='192.168.45.100',
            auto_resolve=True,  # Auto-fill from profile
            required=True
        ),
        Variable(
            name='PORT',
            description='Target port',
            example='80',
            auto_resolve=True,  # Auto-fill from task
            required=True
        ),
        Variable(
            name='DIRECTORY',
            description='Directory name to check',
            example='admin',
            auto_resolve=False,  # ALWAYS prompt user (only they know what to test)
            required=True
        )
    ],
    tags=['MANUAL', 'NO_TOOLS', 'OSCP:HIGH'],
    os_type='both'
)


# ============================================================================
# EXAMPLE 4: Complete Example (All Fields Populated)
# ============================================================================

complete_example = AlternativeCommand(
    # Identity
    id='alt-example-complete',
    name='Complete Alternative Command Example',
    command_template='wget http://<TARGET>:<PORT>/<FILE> -O /tmp/<FILE>',
    description='Download file from web server using wget',

    # Categorization
    category='file-transfer',
    subcategory='download',

    # Variables
    variables=[
        Variable(
            name='TARGET',
            description='Target IP or hostname',
            example='192.168.45.100',
            auto_resolve=True,
            required=True
        ),
        Variable(
            name='PORT',
            description='Web server port',
            example='80',
            auto_resolve=True,
            required=True
        ),
        Variable(
            name='FILE',
            description='Filename to download',
            example='linpeas.sh',
            auto_resolve=False,  # User specifies
            required=True
        )
    ],

    # Educational metadata
    tags=['OSCP:HIGH', 'FILE_TRANSFER', 'LINUX'],
    os_type='linux',

    flag_explanations={
        '-O': 'Output file (save to /tmp/<FILE>)',
        'http://': 'Protocol (use https:// for SSL)'
    },

    success_indicators=[
        'File downloaded successfully',
        '100% completion shown',
        'File exists in /tmp/'
    ],

    failure_indicators=[
        'Connection refused',
        'HTTP 404 Not Found',
        'Permission denied on /tmp/'
    ],

    next_steps=[
        'Verify file integrity: md5sum /tmp/<FILE>',
        'Make executable: chmod +x /tmp/<FILE>',
        'Run downloaded tool'
    ],

    notes='Alternative to curl: curl http://<TARGET>:<PORT>/<FILE> -o /tmp/<FILE>',

    # Task linkage
    parent_task_pattern='http-*'  # Links to all HTTP tasks
)


# ============================================================================
# Export for Registry
# ============================================================================

ALTERNATIVES = [
    simple_example,
    auto_resolve_example,
    user_prompt_example,
    complete_example
]


# ============================================================================
# USAGE INSTRUCTIONS
# ============================================================================

"""
To create a new alternative command:

1. Copy one of the examples above
2. Modify the fields for your command
3. Add to ALTERNATIVES list
4. Test: crack track -i TARGET → press 'alt'

Variable Resolution Priority:
1. Task metadata (port, service, version from current task)
2. Profile state (target IP, discovered services)
3. Config (LHOST, LPORT, wordlists from ~/.crack/config.json)
4. User prompt (if not found in 1-3 and interactive=True)

Common Auto-Resolved Variables:
- <TARGET> → profile.target
- <PORT> → task.metadata['port']
- <SERVICE> → task.metadata['service']
- <VERSION> → task.metadata['version']
- <LHOST> → config.variables['LHOST']
- <LPORT> → config.variables['LPORT']

Always Prompt Variables (auto_resolve=False):
- <DIRECTORY> → User knows what to test
- <FILE> → User specifies filename
- <USERNAME> → User provides username
- <PASSWORD> → User provides password
- Custom values only user knows

Tags:
- OSCP:HIGH, OSCP:MEDIUM, OSCP:LOW
- QUICK_WIN, RELIABLE
- MANUAL, AUTOMATED, STEALTH, NOISY
- LINUX, WINDOWS, BOTH_OS
- NO_TOOLS (can run without installing tools)

Testing:
    pytest tests/track/test_alternatives.py -v
"""
