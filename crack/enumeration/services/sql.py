"""
SQL database service enumeration plugin (MySQL, PostgreSQL, MSSQL)
"""

from typing import Dict, Any, List
from .base import ServicePlugin
from .registry import ServiceRegistry


@ServiceRegistry.register
class SQLPlugin(ServicePlugin):
    """SQL database enumeration plugin"""

    @property
    def name(self) -> str:
        return "sql"

    @property
    def default_ports(self) -> List[int]:
        return [1433, 3306, 5432, 1521]

    @property
    def service_names(self) -> List[str]:
        return ['mysql', 'postgresql', 'postgres', 'ms-sql', 'mssql', 'oracle']

    def detect(self, port_info: Dict[str, Any]) -> bool:
        service = port_info.get('service', '').lower()
        port = port_info.get('port')

        if any(svc in service for svc in self.service_names):
            return True

        if port in self.default_ports:
            return True

        return False

    def get_task_tree(self, target: str, port: int, service_info: Dict[str, Any]) -> Dict[str, Any]:
        version = service_info.get('version', '')
        service = service_info.get('service', '').lower()

        # Determine database type
        if 'mysql' in service or port == 3306:
            db_type = 'mysql'
            connect_cmd = f'mysql -h {target} -P {port} -u root'
        elif 'postgres' in service or port == 5432:
            db_type = 'postgresql'
            connect_cmd = f'psql -h {target} -p {port} -U postgres'
        elif 'mssql' in service or 'ms-sql' in service or port == 1433:
            db_type = 'mssql'
            connect_cmd = f'impacket-mssqlclient {target} -port {port}'
        else:
            db_type = 'generic'
            connect_cmd = f'# Database-specific client needed'

        tasks = {
            'id': f'sql-enum-{port}',
            'name': f'{db_type.upper()} Enumeration (Port {port})',
            'type': 'parent',
            'children': [
                {
                    'id': f'sql-version-{port}',
                    'name': 'Version Detection',
                    'type': 'command',
                    'metadata': {
                        'command': f'nmap --script {db_type}-info -p{port} {target}',
                        'description': f'Gather {db_type} version and configuration info',
                        'tags': ['OSCP:MEDIUM']
                    }
                },
                {
                    'id': f'sql-anon-{port}',
                    'name': 'Test Anonymous/Default Access',
                    'type': 'manual',
                    'metadata': {
                        'description': f'Try connecting without password or with defaults',
                        'command': connect_cmd,
                        'tags': ['MANUAL', 'OSCP:HIGH', 'QUICK_WIN'],
                        'notes': [
                            'Try default credentials: root:<blank>, admin:admin, sa:<blank>',
                            'If access gained, enumerate databases and tables',
                            'Look for credentials in application databases'
                        ]
                    }
                }
            ]
        }

        if version:
            tasks['children'].append({
                'id': f'searchsploit-sql-{port}',
                'name': f'Exploit Research: {version}',
                'type': 'command',
                'metadata': {
                    'command': f'searchsploit {version}',
                    'description': f'Search for {db_type} exploits',
                    'tags': ['RESEARCH', 'OSCP:MEDIUM']
                }
            })

        # Database-specific enumeration notes
        if db_type == 'mssql':
            tasks['children'].append({
                'id': f'mssql-notes-{port}',
                'name': 'MSSQL-Specific Checks',
                'type': 'manual',
                'metadata': {
                    'description': 'MSSQL enumeration and exploitation paths',
                    'tags': ['MANUAL', 'OSCP:HIGH'],
                    'notes': [
                        'Check xp_cmdshell for RCE: EXEC xp_cmdshell "whoami"',
                        'Enable if disabled: EXEC sp_configure "xp_cmdshell", 1; RECONFIGURE;',
                        'List linked servers: EXEC sp_linkedservers',
                        'Impacket mssqlclient has built-in commands'
                    ]
                }
            })

        return tasks

    def on_task_complete(self, task_id: str, result: str, target: str) -> List[Dict[str, Any]]:
        new_tasks = []

        # If anonymous access succeeds, add database enumeration
        if 'anon' in task_id and 'connected' in result.lower():
            port = task_id.split('-')[-1]
            new_tasks.append({
                'id': f'db-enum-{port}',
                'name': 'Database Enumeration',
                'type': 'manual',
                'metadata': {
                    'description': 'Enumerate databases, tables, and extract data',
                    'tags': ['MANUAL', 'OSCP:HIGH'],
                    'notes': [
                        'SHOW DATABASES; or \\l (postgres)',
                        'USE <database>; SELECT * FROM users;',
                        'Look for password hashes, API keys, credentials'
                    ]
                }
            })

        return new_tasks

    def get_manual_alternatives(self, task_id: str) -> List[str]:
        return [
            'Manual connection with database client',
            'SQL injection if web app connects to this database',
            'Metasploit auxiliary modules for each DB type'
        ]
