"""
Privilege Escalation Alternative Commands

Manual alternatives for Linux/Windows privilege escalation enumeration.

ADD YOUR COMMANDS HERE by copying examples from TEMPLATE.py
"""

from ..models import AlternativeCommand, Variable


# Example: Find SUID binaries (Linux)
ALTERNATIVES = [
    AlternativeCommand(
        id='alt-find-suid',
        name='Find SUID Binaries',
        command_template='find / -perm -u=s -type f 2>/dev/null',
        description='Manually find all SUID binaries for privilege escalation',
        category='privilege-escalation',
        subcategory='linux-enum',
        variables=[],  # No variables needed
        tags=['MANUAL', 'OSCP:HIGH', 'QUICK_WIN', 'LINUX', 'NO_TOOLS'],
        os_type='linux',
        flag_explanations={
            '-perm -u=s': 'Find files with SUID bit set',
            '-type f': 'Only search for files (not directories)',
            '2>/dev/null': 'Suppress permission denied errors'
        },
        success_indicators=[
            'List of SUID binaries returned',
            'Unusual binaries found (not system defaults)'
        ],
        failure_indicators=[
            'Empty output',
            'Permission denied on all paths'
        ],
        next_steps=[
            'Check each binary against GTFOBins',
            'Test unusual SUID binaries for exploits',
            'Cross-reference with known PrivEsc techniques'
        ],
        notes='Cross-reference findings with https://gtfobins.github.io/',
        parent_task_pattern='*privesc*'
    ),

    AlternativeCommand(
        id='alt-sudo-list',
        name='Check Sudo Privileges',
        command_template='sudo -l',
        description='List sudo privileges without executing commands (instant privesc if NOPASSWD found)',
        category='privilege-escalation',
        subcategory='linux-enum',
        variables=[],
        tags=['MANUAL', 'OSCP:HIGH', 'QUICK_WIN', 'LINUX', 'NO_TOOLS'],
        os_type='linux',
        flag_explanations={
            '-l': 'List allowed commands for current user without executing them'
        },
        success_indicators=[
            'List of allowed commands appears',
            'NOPASSWD entries (execute without password)',
            'Specific binaries listed (check GTFOBins)'
        ],
        failure_indicators=[
            'User not in sudoers file',
            'Password required and unknown'
        ],
        next_steps=[
            'If NOPASSWD binaries found, check https://gtfobins.github.io/',
            'Look for wildcard injection vulnerabilities',
            'Test: sudo <command>'
        ],
        notes='First command to run on shell access - instant win if NOPASSWD found',
        parent_task_pattern='*privesc*'
    ),

    AlternativeCommand(
        id='alt-linux-capabilities',
        name='Find File Capabilities',
        command_template='getcap -r / 2>/dev/null',
        description='Find files with capabilities (alternative to SUID for privilege escalation)',
        category='privilege-escalation',
        subcategory='linux-enum',
        variables=[],
        tags=['MANUAL', 'OSCP:HIGH', 'LINUX', 'NO_TOOLS'],
        os_type='linux',
        flag_explanations={
            'getcap': 'Get file capabilities (special permissions)',
            '-r': 'Recursive search from specified directory',
            '/': 'Start from root directory',
            '2>/dev/null': 'Suppress permission denied errors'
        },
        success_indicators=[
            'Files with capabilities found',
            'CAP_SETUID (instant privesc)',
            'CAP_DAC_READ_SEARCH (read any file)'
        ],
        failure_indicators=[
            'getcap not installed',
            'No capabilities set'
        ],
        next_steps=[
            'If CAP_SETUID found: use binary to escalate',
            'If CAP_DAC_READ_SEARCH: read /etc/shadow',
            'Check GTFOBins for capability exploits'
        ],
        notes='Capabilities bypass traditional permission model. Less common than SUID but equally dangerous.',
        parent_task_pattern='*privesc*'
    ),

    AlternativeCommand(
        id='alt-kernel-version-check',
        name='Check Kernel Version for Exploits',
        command_template='uname -a && cat /proc/version',
        description='Get kernel version and build info for exploit research',
        category='privilege-escalation',
        subcategory='linux-enum',
        variables=[],
        tags=['MANUAL', 'OSCP:HIGH', 'QUICK_WIN', 'LINUX', 'NO_TOOLS'],
        os_type='linux',
        flag_explanations={
            'uname -a': 'All system information (kernel, hostname, architecture)',
            'cat /proc/version': 'Detailed kernel version with GCC version and build date',
            '&&': 'Chain commands - execute second if first succeeds'
        },
        success_indicators=[
            'Kernel version displayed (e.g., 4.4.0-116-generic)',
            'Architecture identified (x86_64, i686)',
            'Build date shown (older = more vulns)'
        ],
        next_steps=[
            'searchsploit "Linux Kernel <version>"',
            'Download linux-exploit-suggester.sh',
            'Check lucyoa/kernel-exploits on GitHub'
        ],
        notes='Essential for kernel exploit research. Old kernels (< 4.x) often have public exploits.',
        parent_task_pattern='*privesc*'
    ),

    AlternativeCommand(
        id='alt-cron-enumeration',
        name='Enumerate Cron Jobs',
        command_template='cat /etc/crontab; ls -la /etc/cron.*; crontab -l',
        description='Find scheduled tasks (writable cron scripts = privesc)',
        category='privilege-escalation',
        subcategory='linux-enum',
        variables=[],
        tags=['MANUAL', 'OSCP:HIGH', 'QUICK_WIN', 'LINUX', 'NO_TOOLS'],
        os_type='linux',
        flag_explanations={
            'cat /etc/crontab': 'View system-wide cron jobs',
            'ls -la /etc/cron.*': 'List cron directories (hourly, daily, weekly, monthly)',
            'crontab -l': 'List current user cron jobs',
            '-l': 'List mode for crontab'
        },
        success_indicators=[
            'Cron jobs listed',
            'Scripts referenced in cron',
            'World-writable scripts found'
        ],
        failure_indicators=[
            'No crontab for user',
            'Permission denied on /etc/crontab'
        ],
        next_steps=[
            'Check script permissions: ls -la /path/to/script',
            'If writable, inject reverse shell',
            'Monitor execution: watch -n 1 ps aux'
        ],
        notes='Look for scripts run by root that are writable. Classic OSCP privesc vector.',
        parent_task_pattern='*privesc*'
    ),

    AlternativeCommand(
        id='alt-nfs-no-root-squash',
        name='Check NFS no_root_squash',
        command_template='cat /etc/exports',
        description='Find NFS exports with no_root_squash (mount as root from attacker machine)',
        category='privilege-escalation',
        subcategory='linux-enum',
        variables=[],
        tags=['MANUAL', 'OSCP:HIGH', 'QUICK_WIN', 'LINUX', 'NO_TOOLS'],
        os_type='linux',
        flag_explanations={
            'cat /etc/exports': 'View NFS export configuration file',
            'no_root_squash': 'Option that allows root user from client to be root on server'
        },
        success_indicators=[
            'NFS exports found',
            'no_root_squash option present',
            'Writable exports with * or attacker IP'
        ],
        failure_indicators=[
            'No NFS configured',
            'Permission denied',
            'root_squash enabled (default secure option)'
        ],
        next_steps=[
            'On attacker: showmount -e <TARGET>',
            'Mount share: mount -t nfs <TARGET>:/share /mnt',
            'Create SUID binary on share as root',
            'Execute SUID binary on target for root shell'
        ],
        notes='Classic OSCP privesc. Requires NFS client on attacker machine. Exploit: create SUID /bin/bash on share.',
        parent_task_pattern='*privesc*'
    ),
]
