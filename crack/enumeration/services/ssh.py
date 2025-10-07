"""
SSH service enumeration plugin
"""

from typing import Dict, Any, List
from .base import ServicePlugin
from .registry import ServiceRegistry


@ServiceRegistry.register
class SSHPlugin(ServicePlugin):
    """SSH enumeration plugin"""

    @property
    def name(self) -> str:
        return "ssh"

    @property
    def default_ports(self) -> List[int]:
        return [22, 2222]

    @property
    def service_names(self) -> List[str]:
        return ['ssh', 'openssh']

    def detect(self, port_info: Dict[str, Any]) -> bool:
        service = port_info.get('service', '').lower()
        port = port_info.get('port')
        return 'ssh' in service or port in self.default_ports

    def get_task_tree(self, target: str, port: int, service_info: Dict[str, Any]) -> Dict[str, Any]:
        version = service_info.get('version', '')

        tasks = {
            'id': f'ssh-enum-{port}',
            'name': f'SSH Enumeration (Port {port})',
            'type': 'parent',
            'children': [
                {
                    'id': f'ssh-banner-{port}',
                    'name': 'Banner Grab',
                    'type': 'command',
                    'metadata': {
                        'command': f'nc {target} {port}',
                        'description': 'Grab SSH banner for version info',
                        'tags': ['MANUAL', 'QUICK_WIN']
                    }
                },
                {
                    'id': f'ssh-audit-{port}',
                    'name': 'SSH Configuration Audit',
                    'type': 'command',
                    'metadata': {
                        'command': f'nmap --script ssh-auth-methods,ssh2-enum-algos -p{port} {target}',
                        'description': 'Enumerate supported authentication methods and algorithms',
                        'tags': ['OSCP:MEDIUM']
                    }
                }
            ]
        }

        if version:
            tasks['children'].append({
                'id': f'searchsploit-ssh-{port}',
                'name': f'Exploit Research: {version}',
                'type': 'command',
                'metadata': {
                    'command': f'searchsploit {version}',
                    'description': 'Search for SSH version exploits',
                    'tags': ['RESEARCH', 'OSCP:MEDIUM']
                }
            })

        # SSH is primarily an access vector - note credential testing
        tasks['children'].append({
            'id': f'ssh-creds-note-{port}',
            'name': 'SSH Credential Testing',
            'type': 'manual',
            'metadata': {
                'description': 'Test discovered credentials or attempt brute-force',
                'tags': ['MANUAL'],
                'notes': [
                    'Try discovered credentials from other services',
                    'Check for default credentials (admin, root, etc.)',
                    'Brute-force only as last resort: hydra -L users.txt -P passwords.txt ssh://{target}'
                ]
            }
        })

        return tasks

    def on_task_complete(self, task_id: str, result: str, target: str) -> List[Dict[str, Any]]:
        return []

    def get_manual_alternatives(self, task_id: str) -> List[str]:
        return ['ssh -v <target> # Verbose connection attempt to see supported methods']
