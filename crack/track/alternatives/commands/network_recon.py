"""
Network Reconnaissance Alternative Commands

Manual alternatives for port scanning, service enumeration, and network discovery.
Extracted from SMB and SSH plugins.
"""

from ..models import AlternativeCommand, Variable


ALTERNATIVES = [
    # ========== PORT SCANNING ALTERNATIVES ==========

    AlternativeCommand(
        id='alt-nc-port-check',
        name='Netcat Port Check',
        command_template='nc -zv <TARGET> <PORT>',
        description='Manually test if specific port is open using netcat',
        category='network-recon',
        subcategory='port-scanning',
        variables=[
            Variable(name='TARGET', description='Target IP or hostname', example='192.168.45.100', auto_resolve=True, required=True),
            Variable(name='PORT', description='Port to test', example='80', auto_resolve=True, required=True)
        ],
        tags=['MANUAL', 'OSCP:HIGH', 'NO_TOOLS', 'QUICK_WIN'],
        os_type='both',
        flag_explanations={
            '-z': 'Zero-I/O mode (scanning only, no data sent) - faster than full connection',
            '-v': 'Verbose output (shows connection status clearly)'
        },
        success_indicators=[
            'succeeded',
            'open',
            'Connection to <TARGET> <PORT> succeeded'
        ],
        failure_indicators=[
            'Connection refused (port closed)',
            'Connection timed out (firewall blocking)',
            'No route to host'
        ],
        next_steps=[
            'If open: Banner grab with nc -nv <TARGET> <PORT>',
            'Try service-specific enumeration',
            'Test for null sessions or anonymous access'
        ],
        notes='Netcat is universal. For multiple ports: for p in 80 443 8080; do nc -zv <TARGET> $p; done. Alternatives: /dev/tcp check, telnet, curl -v telnet://',
        parent_task_pattern='*scan*'
    ),

    AlternativeCommand(
        id='alt-bash-tcp-check',
        name='Bash TCP Port Check',
        command_template='(echo > /dev/tcp/<TARGET>/<PORT>) && echo "Port <PORT> open" || echo "Port <PORT> closed"',
        description='Pure bash port check using /dev/tcp (no external tools)',
        category='network-recon',
        subcategory='port-scanning',
        variables=[
            Variable(name='TARGET', description='Target IP or hostname', example='192.168.45.100', auto_resolve=True, required=True),
            Variable(name='PORT', description='Port to test', example='22', auto_resolve=True, required=True)
        ],
        tags=['MANUAL', 'OSCP:HIGH', 'NO_TOOLS', 'BASH_ONLY'],
        os_type='linux',
        success_indicators=[
            'Port <PORT> open',
            'No error output'
        ],
        failure_indicators=[
            'Connection refused',
            'Connection timed out'
        ],
        next_steps=[
            'Loop through common ports: for p in 21 22 80 443 445; do ...',
            'Banner grab with: exec 3<>/dev/tcp/<TARGET>/<PORT>; echo -e "" >&3; cat <&3'
        ],
        notes='Built into bash, works when nc unavailable. /dev/tcp requires bash (not sh). For OSCP: useful in restricted shells. Alternatives: nc -zv, timeout with /dev/tcp',
        parent_task_pattern='*scan*'
    ),

    # ========== BANNER GRABBING ALTERNATIVES ==========

    AlternativeCommand(
        id='alt-nc-banner-grab',
        name='Netcat Banner Grab',
        command_template='nc -nv <TARGET> <PORT>',
        description='Grab service banner to identify version (manual alternative to nmap -sV)',
        category='network-recon',
        subcategory='service-enumeration',
        variables=[
            Variable(name='TARGET', description='Target IP or hostname', example='192.168.45.100', auto_resolve=True, required=True),
            Variable(name='PORT', description='Service port', example='22', auto_resolve=True, required=True)
        ],
        tags=['MANUAL', 'OSCP:HIGH', 'QUICK_WIN'],
        os_type='both',
        flag_explanations={
            '-n': 'No DNS resolution (use IP directly, faster)',
            '-v': 'Verbose output (show connection details)'
        },
        success_indicators=[
            'Banner displayed (SSH-2.0-OpenSSH_7.4, 220 FTP, HTTP/1.1)',
            'Version number visible',
            'Server implementation identified'
        ],
        failure_indicators=[
            'Connection refused',
            'No banner displayed (service requires client hello first)',
            'Timeout'
        ],
        next_steps=[
            'Research version with searchsploit <version>',
            'Check CVE databases for version',
            'Try service-specific enumeration'
        ],
        notes='SSH: Press Ctrl+C after banner. HTTP: Type "HEAD / HTTP/1.0" then Enter twice. For OSCP: critical for CVE research. Alternatives: telnet, curl -v telnet://, echo "" | nc',
        parent_task_pattern='service-*'
    ),

    # ========== SMB ENUMERATION ALTERNATIVES ==========

    AlternativeCommand(
        id='alt-smbclient-shares',
        name='SMB Share Enumeration',
        command_template='smbclient -L //<TARGET> -N',
        description='List SMB shares using null session (manual alternative to enum4linux)',
        category='network-recon',
        subcategory='smb-enumeration',
        variables=[
            Variable(name='TARGET', description='Target IP or hostname', example='192.168.45.100', auto_resolve=True, required=True)
        ],
        tags=['MANUAL', 'OSCP:HIGH', 'QUICK_WIN', 'NULL_SESSION'],
        os_type='both',
        flag_explanations={
            '-L': 'List shares on target (equivalent to net view)',
            '-N': 'No password (null session attempt, works if RestrictAnonymous=0)'
        },
        success_indicators=[
            'Sharename       Type      Comment',
            'Share list displayed',
            'No NT_STATUS_ACCESS_DENIED'
        ],
        failure_indicators=[
            'NT_STATUS_ACCESS_DENIED (null sessions disabled)',
            'NT_STATUS_LOGON_FAILURE',
            'Connection refused (SMB not running)'
        ],
        next_steps=[
            'Connect to shares: smbclient //<TARGET>/<SHARE> -N',
            'Test default shares: C$, ADMIN$, IPC$, SYSVOL, NETLOGON',
            'Download files: get, mget *',
            'Check write access: put test.txt'
        ],
        notes='For OSCP: If shares found, document each. SYSVOL/NETLOGON may contain scripts with hardcoded passwords. Alternatives: smbmap, crackmapexec, enum4linux, nmap scripts',
        parent_task_pattern='smb-*'
    ),

    AlternativeCommand(
        id='alt-rpcclient-enum',
        name='RPC User Enumeration',
        command_template='rpcclient -U "" -N <TARGET> -c "enumdomusers"',
        description='Enumerate domain users via RPC null session (manual alternative to enum4linux)',
        category='network-recon',
        subcategory='smb-enumeration',
        variables=[
            Variable(name='TARGET', description='Target IP or hostname', example='192.168.45.100', auto_resolve=True, required=True)
        ],
        tags=['MANUAL', 'OSCP:HIGH', 'USER_ENUM', 'NULL_SESSION'],
        os_type='both',
        flag_explanations={
            '-U ""': 'Empty username (null session)',
            '-N': 'No password (anonymous access)',
            '-c': 'Execute command and exit (non-interactive)'
        },
        success_indicators=[
            'user:[username] rid:[0xrid]',
            'User list displayed',
            'No access denied errors'
        ],
        failure_indicators=[
            'NT_STATUS_ACCESS_DENIED',
            'result was NT_STATUS_INVALID_HANDLE',
            'Could not connect to server'
        ],
        next_steps=[
            'Get user details: rpcclient -U "" -N <TARGET> -c "queryuser 0x<RID>"',
            'Enumerate groups: enumdomgroups',
            'Save usernames for password spraying',
            'Check password policy: getdompwinfo'
        ],
        notes='For OSCP: Common RID ranges: 500=Administrator, 501=Guest, 1000+=regular users. Always test null sessions first. RID cycling: for i in $(seq 500 1100); do rpcclient -N -U "" <TARGET> -c "queryuser 0x$(printf \'%x\\n\' $i)"; done',
        parent_task_pattern='smb-*'
    ),

    # ========== SSH ENUMERATION ALTERNATIVES ==========

    AlternativeCommand(
        id='alt-ssh-keyscan',
        name='SSH Host Key Extraction',
        command_template='ssh-keyscan -t rsa,ecdsa,ed25519 <TARGET>',
        description='Extract SSH host keys (manual alternative to nmap --script ssh-hostkey)',
        category='network-recon',
        subcategory='ssh-enumeration',
        variables=[
            Variable(name='TARGET', description='Target IP or hostname', example='192.168.45.100', auto_resolve=True, required=True)
        ],
        tags=['MANUAL', 'OSCP:MEDIUM', 'QUICK_WIN'],
        os_type='both',
        flag_explanations={
            '-t': 'Key types to retrieve (rsa=RSA keys, ecdsa=Elliptic Curve, ed25519=modern)',
            'rsa,ecdsa,ed25519': 'Comma-separated list of all common key types'
        },
        success_indicators=[
            'RSA host key displayed',
            'Multiple key types returned',
            'Base64-encoded key data visible'
        ],
        failure_indicators=[
            'Connection refused',
            'No keys returned',
            'getaddrinfo failure'
        ],
        next_steps=[
            'Check key strength: ssh-keygen -l -f <(ssh-keyscan <TARGET> 2>/dev/null)',
            'Compare against known compromised keys database',
            'Save for man-in-the-middle scenarios'
        ],
        notes='For OSCP: RSA keys < 2048 bits are weak. Cross-reference keys across multiple targets to find reused infrastructure. Alternatives: nmap --script ssh-hostkey, view fingerprint when connecting',
        parent_task_pattern='ssh-*'
    ),

    AlternativeCommand(
        id='alt-ssh-auth-methods',
        name='SSH Authentication Method Check',
        command_template='ssh -v <TARGET> -p <PORT> 2>&1 | grep -i "authentications that can continue"',
        description='Check supported SSH auth methods (manual alternative to nmap ssh-auth-methods)',
        category='network-recon',
        subcategory='ssh-enumeration',
        variables=[
            Variable(name='TARGET', description='Target IP or hostname', example='192.168.45.100', auto_resolve=True, required=True),
            Variable(name='PORT', description='SSH port', example='22', auto_resolve=True, required=True)
        ],
        tags=['MANUAL', 'OSCP:HIGH', 'QUICK_WIN'],
        os_type='both',
        flag_explanations={
            '-v': 'Verbose mode (shows debug info including auth methods)',
            '-p': 'Port specification (default 22)',
            '2>&1': 'Redirect stderr to stdout (capture verbose output)',
            'grep -i': 'Case-insensitive search for auth methods'
        },
        success_indicators=[
            'publickey',
            'password',
            'keyboard-interactive',
            'Authentications that can continue'
        ],
        failure_indicators=[
            'Connection refused',
            'Permission denied',
            'No output from grep'
        ],
        next_steps=[
            'If password enabled: attempt default creds or brute-force (last resort)',
            'If publickey only: test known SSH keys (Debian weak keys, badkeys)',
            'If keyboard-interactive: may have MFA, try bypass techniques'
        ],
        notes='For OSCP: publickey-only means need to find keys. Password auth = brute-force opportunity. Press Ctrl+C after seeing auth methods. Alternatives: nmap ssh-auth-methods script, ssh -o PreferredAuthentications',
        parent_task_pattern='ssh-*'
    ),

    # ========== NETBIOS ENUMERATION ==========

    AlternativeCommand(
        id='alt-nmblookup',
        name='NetBIOS Name Lookup',
        command_template='nmblookup -A <TARGET>',
        description='Query NetBIOS names and workgroup/domain (manual alternative to nmap nbstat)',
        category='network-recon',
        subcategory='netbios-enumeration',
        variables=[
            Variable(name='TARGET', description='Target IP address', example='192.168.45.100', auto_resolve=True, required=True)
        ],
        tags=['MANUAL', 'OSCP:HIGH', 'QUICK_WIN', 'WINDOWS'],
        os_type='both',
        flag_explanations={
            '-A': 'Lookup by IP address (instead of name, reverse lookup)'
        },
        success_indicators=[
            'NetBIOS name table displayed',
            'Computer name visible',
            'Workgroup/domain name discovered',
            'MAC address shown'
        ],
        failure_indicators=[
            'No reply from host',
            'Lookup failed',
            'Timeout'
        ],
        next_steps=[
            'Identify server role from suffixes: <00>=Workstation, <20>=File Server, <1B>=Domain Master Browser',
            'Note workgroup/domain for credential attacks',
            'Continue to SMB enumeration: smbclient -L //<TARGET> -N'
        ],
        notes='For OSCP: NetBIOS names reveal computer name (useful for password patterns), domain membership, and server roles. Port 137/UDP must be open. Alternatives: nbtscan, nmap nbstat/smb-os-discovery scripts',
        parent_task_pattern='netbios-*'
    ),
]
