"""
FTP service enumeration plugin
"""

from typing import Dict, Any, List
from .base import ServicePlugin
from .registry import ServiceRegistry


@ServiceRegistry.register
class FTPPlugin(ServicePlugin):
    """FTP enumeration plugin"""

    @property
    def name(self) -> str:
        return "ftp"

    @property
    def default_ports(self) -> List[int]:
        return [21]

    @property
    def service_names(self) -> List[str]:
        return ['ftp', 'ftps']

    def detect(self, port_info: Dict[str, Any]) -> bool:
        service = port_info.get('service', '').lower()
        port = port_info.get('port')
        return 'ftp' in service or port in self.default_ports

    def get_task_tree(self, target: str, port: int, service_info: Dict[str, Any]) -> Dict[str, Any]:
        version = service_info.get('version', '')

        tasks = {
            'id': f'ftp-enum-{port}',
            'name': f'FTP Enumeration (Port {port})',
            'type': 'parent',
            'children': [
                {
                    'id': f'ftp-anon-{port}',
                    'name': 'Test Anonymous Login',
                    'type': 'command',
                    'metadata': {
                        'command': f'ftp {target}',
                        'description': 'Try anonymous FTP login (user: anonymous, pass: <blank>)',
                        'tags': ['MANUAL', 'OSCP:HIGH', 'QUICK_WIN'],
                        'notes': [
                            'Username: anonymous',
                            'Password: <blank> or <email>',
                            'If successful: ls, cd, get <file>, mget *'
                        ]
                    }
                },
                {
                    'id': f'ftp-nmap-{port}',
                    'name': 'FTP NSE Scripts',
                    'type': 'command',
                    'metadata': {
                        'command': f'nmap --script ftp-* -p{port} {target}',
                        'description': 'Run FTP-related NSE scripts',
                        'tags': ['OSCP:MEDIUM'],
                        'notes': 'Checks: anonymous login, bounce attack, vsftpd backdoor'
                    }
                }
            ]
        }

        if version:
            tasks['children'].append({
                'id': f'searchsploit-ftp-{port}',
                'name': f'Exploit Research: {version}',
                'type': 'command',
                'metadata': {
                    'command': f'searchsploit {version}',
                    'description': 'Search for FTP exploits',
                    'tags': ['RESEARCH', 'OSCP:HIGH']
                }
            })

            # Check for vsftpd 2.3.4 backdoor
            if 'vsftpd 2.3.4' in version.lower():
                tasks['children'].append({
                    'id': f'vsftpd-backdoor-{port}',
                    'name': 'vsFTPd 2.3.4 Backdoor',
                    'type': 'manual',
                    'metadata': {
                        'description': 'Smiley face backdoor (CVE-2011-2523)',
                        'tags': ['EXPLOIT', 'OSCP:HIGH', 'QUICK_WIN'],
                        'notes': [
                            'Username ending with :) triggers backdoor on port 6200',
                            'Metasploit: exploit/unix/ftp/vsftpd_234_backdoor',
                            'Manual: ftp, login with user:), then nc {target} 6200'
                        ]
                    }
                })

        return tasks

    def on_task_complete(self, task_id: str, result: str, target: str) -> List[Dict[str, Any]]:
        new_tasks = []

        if 'anon' in task_id and '230' in result:  # 230 = Login successful
            port = task_id.split('-')[-1]
            new_tasks.append({
                'id': f'ftp-download-{port}',
                'name': 'Download FTP Files',
                'type': 'manual',
                'metadata': {
                    'description': 'Download all accessible files from FTP',
                    'tags': ['MANUAL', 'OSCP:HIGH'],
                    'notes': [
                        'wget -r ftp://anonymous:@{target}',
                        'Or manual: ftp, then: mget *',
                        'Check for writable directories (potential upload point)'
                    ]
                }
            })

        return new_tasks

    def get_manual_alternatives(self, task_id: str) -> List[str]:
        return [
            'Browser: ftp://<target>',
            'wget -r ftp://anonymous:@<target>',
            'FileZilla or other FTP GUI client'
        ]
