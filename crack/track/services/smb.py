"""
SMB service enumeration plugin

Generates tasks for SMB/CIFS enumeration including:
- Share enumeration
- Null session testing
- User enumeration
- Version-specific exploits (EternalBlue, etc.)
"""

from typing import Dict, Any, List
from .base import ServicePlugin
from .registry import ServiceRegistry


@ServiceRegistry.register
class SMBPlugin(ServicePlugin):
    """SMB/CIFS enumeration plugin"""

    @property
    def name(self) -> str:
        return "smb"

    @property
    def default_ports(self) -> List[int]:
        return [139, 445]

    @property
    def service_names(self) -> List[str]:
        return ['smb', 'microsoft-ds', 'netbios-ssn', 'cifs']

    def detect(self, port_info: Dict[str, Any]) -> bool:
        """Detect SMB services"""
        service = port_info.get('service', '').lower()
        port = port_info.get('port')

        if any(svc in service for svc in self.service_names):
            return True

        if port in self.default_ports:
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

        # 1. Share enumeration
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

        # 2. Comprehensive enumeration with enum4linux
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
                'notes': 'enum4linux is noisy - generates significant log entries'
            }
        })

        # 3. Null session testing
        tasks['children'].append({
            'id': f'rpcclient-null-{port}',
            'name': 'Test Null Session (RPC)',
            'type': 'command',
            'metadata': {
                'command': f'rpcclient -U "" -N {target}',
                'description': 'Test null session via RPC',
                'tags': ['MANUAL', 'OSCP:HIGH'],
                'flag_explanations': {
                    '-U ""': 'Empty username',
                    '-N': 'No password'
                },
                'notes': 'If successful, try: enumdomusers, enumdomgroups, queryuser <RID>'
            }
        })

        # 4. Version-specific vulnerability checks
        tasks['children'].append({
            'id': f'smb-vulns-{port}',
            'name': 'SMB Vulnerability Scan',
            'type': 'command',
            'metadata': {
                'command': f'nmap --script smb-vuln-* -p{port} {target} -oN smb_vulns_{port}.txt',
                'description': 'Check for SMB vulnerabilities (EternalBlue, MS08-067, etc.)',
                'tags': ['OSCP:HIGH', 'EXPLOIT'],
                'success_indicators': [
                    'VULNERABLE: MS17-010 (EternalBlue)',
                    'VULNERABLE: MS08-067',
                    'VULNERABLE: CVE-2017-7494 (SambaCry)'
                ],
                'next_steps': [
                    'Research exploit code for detected vulnerabilities',
                    'Verify with Metasploit auxiliary modules'
                ],
                'notes': 'EternalBlue (MS17-010) is common in lab environments'
            }
        })

        # 5. Exploit research if version detected
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
                        'notes': 'Metasploit: exploit/multi/samba/usermap_script'
                    }
                })

        return tasks

    def on_task_complete(self, task_id: str, result: str, target: str) -> List[Dict[str, Any]]:
        """Parse results and spawn additional tasks"""
        new_tasks = []

        # If shares found, add tasks to connect to each
        if 'smbclient-shares' in task_id and 'Sharename' in result:
            # Parse share names (simplified - real implementation would parse output)
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
                    'notes': [
                        'Metasploit: exploit/windows/smb/ms17_010_eternalblue',
                        'Manual: https://github.com/worawit/MS17-010',
                        'Often requires payload tuning for stability'
                    ]
                }
            })

        return new_tasks

    def get_manual_alternatives(self, task_id: str) -> List[str]:
        """Get manual alternatives for SMB enumeration"""
        alternatives = {
            'smbclient': [
                'smbmap -H <target> # Alternative tool',
                'crackmapexec smb <target> --shares',
                'Manual: net view \\\\<target> (from Windows)'
            ],
            'enum4linux': [
                'Manual RPC enumeration: rpcclient -U "" -N <target>',
                'Then: enumdomusers, queryuser <RID>, enumdomgroups',
                'LDAP enumeration if available'
            ],
            'nmap-vuln': [
                'Metasploit auxiliary modules',
                'Manual version comparison against CVE databases'
            ]
        }

        for key, cmds in alternatives.items():
            if key in task_id:
                return cmds

        return []
