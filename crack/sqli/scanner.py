#!/usr/bin/env python3
"""
SQL Injection Scanner Core
Main orchestration logic for SQLi vulnerability detection
"""

import time
import hashlib
import requests
from urllib.parse import urlparse, parse_qs

from .techniques import SQLiTechniques
from .reporter import SQLiReporter

try:
    from ...utils.colors import Colors
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


class SQLiScanner:
    """Core SQL injection scanner orchestration"""

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

        # Session setup
        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64) SQLi Scanner Educational Tool'

        # Parse URL and parameters
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

        # Initialize components
        self.techniques_tester = SQLiTechniques(
            target, self.method, self.session, timeout, delay, verbose, quick
        )
        self.techniques_tester.set_post_params(self.post_params)

        self.reporter = SQLiReporter(target, self.method, self.post_params)

        # State tracking
        self.baseline = None
        self.vulnerabilities = []
        self.tested_count = 0
        self.high_conf_found = 0

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
            raise

    def scan_parameter(self, param, original_value=''):
        """Scan a single parameter for SQL injection"""
        param_findings = []

        print(f"\n{Colors.BLUE}[*] Testing parameter: {param}{Colors.END}")

        # Run different test techniques based on configuration
        if self.technique in ['error', 'all']:
            error_findings = self.techniques_tester.test_error_based(param, original_value)
            param_findings.extend(error_findings)

        if self.technique in ['boolean', 'all']:
            boolean_findings = self.techniques_tester.test_boolean_based(param, self.baseline, original_value)
            param_findings.extend(boolean_findings)

        if self.technique in ['time', 'all']:
            time_findings = self.techniques_tester.test_time_based(param, original_value)
            param_findings.extend(time_findings)

        if self.technique in ['union', 'all']:
            union_findings = self.techniques_tester.test_union_based(param, self.baseline, original_value)
            param_findings.extend(union_findings)

        # Update tested count
        self.tested_count += self.techniques_tester.get_tested_count()

        # Report findings for this parameter
        self.reporter.display_findings(param, param_findings)

        if param_findings:
            highest_confidence = max(f['confidence'] for f in param_findings)

            # Store findings
            self.vulnerabilities.append({
                'param': param,
                'findings': param_findings,
                'max_confidence': highest_confidence
            })

            # Track high-confidence findings for early termination
            if highest_confidence >= 80:
                self.high_conf_found += 1

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
            return params_to_test

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

        return params_to_test

    def generate_report(self, params_tested):
        """Generate final vulnerability report"""
        self.reporter.generate_report(self.vulnerabilities, self.tested_count, params_tested)

    def get_vulnerabilities(self):
        """Return found vulnerabilities"""
        return self.vulnerabilities

    def get_tested_count(self):
        """Return total number of tests performed"""
        return self.tested_count