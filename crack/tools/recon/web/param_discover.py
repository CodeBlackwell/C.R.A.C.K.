#!/usr/bin/env python3
"""
Parameter Discovery Tool - Find hidden GET/POST parameters on web endpoints
OSCP-focused tool for discovering hidden parameters through intelligent fuzzing
"""

import sys
import requests
import argparse
import time
import hashlib
from urllib.parse import urlparse, parse_qs, urlencode
import re

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
        END = '\033[0m'

class ParameterDiscovery:
    def __init__(self, target, method='GET', wordlist=None, verbose=False, quick=False):
        self.target = target.strip()
        self.method = method.upper()
        self.verbose = verbose
        self.quick = quick
        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
        self.discovered = []
        self.baseline = None

        # Quick mode - only high-value parameters (OSCP-focused)
        quick_params = [
            'id', 'page', 'action', 'debug', 'test', 'admin', 'file', 'path',
            'cmd', 'exec', 'command', 'search', 'q', 'user', 'username',
            'redirect', 'url', 'ajax', 'api', 'token', 'auth', 'key'
        ]

        # Full parameter list - common web params
        full_params = [
            'id', 'page', 'action', 'debug', 'test', 'admin', 'file', 'path',
            'include', 'template', 'view', 'mode', 'type', 'cat', 'category',
            'user', 'username', 'name', 'email', 'pass', 'password', 'submit',
            'search', 'q', 'query', 'filter', 'sort', 'order', 'limit', 'offset',
            'redirect', 'return', 'next', 'url', 'uri', 'goto', 'dest', 'destination',
            'redir', 'callback', 'ajax', 'api', 'json', 'xml', 'format', 'output',
            'download', 'export', 'report', 'print', 'pdf', 'doc', 'data', 'info',
            'show', 'display', 'content', 'lang', 'language', 'locale', 'theme',
            'style', 'css', 'js', 'script', 'code', 'exec', 'execute', 'run',
            'cmd', 'command', 'function', 'method', 'process', 'task', 'job',
            'token', 'auth', 'key', 'session', 'sid', 'uid', 'gid', 'role',
            'group', 'perm', 'permission', 'access', 'private', 'public', 'hidden',
            'secret', 'secure', 'safe', 'verify', 'validate', 'check', 'confirm'
        ]

        # Use quick or full params
        self.params = quick_params if quick else full_params

        # Load custom wordlist if provided (overrides quick mode)
        if wordlist:
            try:
                with open(wordlist, 'r') as f:
                    custom = [line.strip() for line in f if line.strip()]
                    self.params = custom
                    print(f"{Colors.BLUE}[+] Loaded {len(custom)} custom parameters{Colors.END}")
            except:
                print(f"{Colors.YELLOW}[!] Could not load wordlist, using defaults{Colors.END}")

    def get_baseline(self):
        """Establish baseline response for comparison"""
        print(f"{Colors.BLUE}[*] Establishing baseline response...{Colors.END}")

        try:
            # Get multiple baseline samples for accuracy
            baselines = []
            for _ in range(3):
                start = time.time()
                if self.method == 'GET':
                    resp = self.session.get(self.target, timeout=10)
                else:
                    resp = self.session.post(self.target, timeout=10)
                elapsed = time.time() - start

                baselines.append({
                    'status': resp.status_code,
                    'length': len(resp.content),
                    'time': elapsed,
                    'hash': hashlib.md5(resp.content).hexdigest(),
                    'lines': resp.text.count('\n')
                })
                time.sleep(0.5)

            # Use median values for stability
            self.baseline = {
                'status': baselines[1]['status'],
                'length': sorted([b['length'] for b in baselines])[1],
                'time': sorted([b['time'] for b in baselines])[1],
                'hash': baselines[1]['hash'],
                'lines': sorted([b['lines'] for b in baselines])[1]
            }

            print(f"  Status: {self.baseline['status']} | Size: {self.baseline['length']} bytes")
            print(f"  Response time: {self.baseline['time']:.2f}s | Lines: {self.baseline['lines']}")

        except Exception as e:
            print(f"{Colors.RED}[!] Failed to establish baseline: {e}{Colors.END}")
            sys.exit(1)

    def test_parameter(self, param):
        """Test a single parameter and detect changes"""
        # Smart payload selection based on parameter name
        if param in ['id', 'uid', 'gid', 'page', 'cat', 'category']:
            payloads = ['1', '999999', '-1', '0']
        elif param in ['debug', 'test', 'admin', 'hidden', 'private']:
            payloads = ['1', 'true', 'yes', 'on']
        elif param in ['file', 'path', 'include', 'template']:
            payloads = ['index.php', '../', '/etc/passwd', 'C:\\windows\\system32\\']
        elif param in ['cmd', 'exec', 'command', 'execute']:
            payloads = ['whoami', 'id', 'echo test', 'dir']
        elif param in ['redirect', 'url', 'uri', 'goto', 'next']:
            payloads = ['http://example.com', '//example.com', '../', '/']
        elif param in ['format', 'output', 'type']:
            payloads = ['json', 'xml', 'txt', 'html']
        else:
            payloads = ['test', '1', 'true', '../']

        changes_detected = []

        for payload in payloads:
            try:
                start = time.time()

                if self.method == 'GET':
                    test_url = f"{self.target}{'&' if '?' in self.target else '?'}{param}={payload}"
                    resp = self.session.get(test_url, timeout=10)
                else:
                    resp = self.session.post(self.target, data={param: payload}, timeout=10)

                elapsed = time.time() - start

                # Calculate changes
                status_change = resp.status_code != self.baseline['status']
                size_diff = abs(len(resp.content) - self.baseline['length'])
                size_change = size_diff > 50  # Significant if >50 bytes
                time_diff = abs(elapsed - self.baseline['time'])
                time_change = time_diff > (self.baseline['time'] * 0.5)  # 50% difference
                content_change = hashlib.md5(resp.content).hexdigest() != self.baseline['hash']
                line_diff = abs(resp.text.count('\n') - self.baseline['lines'])

                # Look for error indicators
                error_patterns = [
                    r'error', r'warning', r'notice', r'exception', r'fatal',
                    r'mysql', r'sql', r'database', r'undefined', r'null'
                ]
                errors_found = any(re.search(p, resp.text, re.I) for p in error_patterns)

                if status_change or size_change or content_change or errors_found:
                    confidence = 0
                    reasons = []

                    if status_change:
                        confidence += 40
                        reasons.append(f"status {self.baseline['status']}→{resp.status_code}")
                    if size_change:
                        confidence += 30
                        reasons.append(f"size Δ{size_diff:+d}")
                    if time_change:
                        confidence += 10
                        reasons.append(f"time Δ{time_diff:+.2f}s")
                    if errors_found:
                        confidence += 30
                        reasons.append("errors detected")
                    if line_diff > 5:
                        confidence += 20
                        reasons.append(f"lines Δ{line_diff:+d}")

                    confidence = min(confidence, 100)

                    changes_detected.append({
                        'payload': payload,
                        'confidence': confidence,
                        'reasons': reasons,
                        'status': resp.status_code,
                        'size': len(resp.content)
                    })

                if self.verbose and content_change:
                    print(f"    {param}={payload} → {resp.status_code} ({len(resp.content)} bytes)")

            except requests.RequestException:
                pass  # Silent fail for individual tests

            time.sleep(0.1)  # Be nice to the server

        return changes_detected

    def discover(self):
        """Main discovery process"""
        mode_str = " (QUICK MODE)" if self.quick else ""
        print(f"\n{Colors.BOLD}[PARAMETER DISCOVERY{mode_str}]{Colors.END}")
        print("=" * 50)
        print(f"Target: {self.target}")
        print(f"Method: {self.method}")
        print(f"Testing {len(self.params)} parameters{' - high-value only' if self.quick else ''}...")
        print("-" * 50)

        self.get_baseline()

        print(f"\n{Colors.BLUE}[*] Testing parameters...{Colors.END}")
        print(f"Command: {self.method} {self.target}?PARAM=PAYLOAD")

        tested = 0
        for param in self.params:
            tested += 1
            if not self.verbose:
                print(f"\r  Progress: {tested}/{len(self.params)} [{param:<20}]", end='', flush=True)

            changes = self.test_parameter(param)

            if changes:
                # Use highest confidence result
                best = max(changes, key=lambda x: x['confidence'])
                self.discovered.append({
                    'param': param,
                    'confidence': best['confidence'],
                    'payload': best['payload'],
                    'reasons': best['reasons'],
                    'all_changes': changes
                })

                if not self.verbose:
                    print()  # New line after progress

                # Display discovery
                color = Colors.GREEN if best['confidence'] >= 70 else Colors.YELLOW
                print(f"{color}  ✓ {param:<15} [Confidence: {best['confidence']}%]{Colors.END}")
                print(f"    → Best payload: {param}={best['payload']}")
                print(f"    → Changes: {', '.join(best['reasons'])}")

        if not self.verbose:
            print()  # Clear progress line

    def generate_report(self):
        """Generate structured report with next steps"""
        print(f"\n{Colors.BOLD}[DISCOVERED PARAMETERS]{Colors.END}")
        print("-" * 50)

        if not self.discovered:
            print(f"{Colors.YELLOW}No parameters discovered - target may not accept parameters{Colors.END}")
            print("\n[NEXT STEPS]")
            print("  • Try POST method if using GET (or vice versa)")
            print("  • Check for API endpoints (/api/, /rest/, /v1/)")
            print("  • Look for forms or AJAX calls in HTML source")
            print("  • Test with authentication/cookies if available")
            return

        # Sort by confidence
        self.discovered.sort(key=lambda x: x['confidence'], reverse=True)

        high_confidence = [d for d in self.discovered if d['confidence'] >= 70]
        medium_confidence = [d for d in self.discovered if 40 <= d['confidence'] < 70]
        low_confidence = [d for d in self.discovered if d['confidence'] < 40]

        if high_confidence:
            print(f"{Colors.GREEN}High Confidence (≥70%):{Colors.END}")
            for item in high_confidence:
                print(f"  • {item['param']:<15} [{item['confidence']}%] - {', '.join(item['reasons'])}")

        if medium_confidence:
            print(f"{Colors.YELLOW}Medium Confidence (40-69%):{Colors.END}")
            for item in medium_confidence:
                print(f"  • {item['param']:<15} [{item['confidence']}%] - {', '.join(item['reasons'])}")

        if low_confidence and self.verbose:
            print(f"Low Confidence (<40%):")
            for item in low_confidence:
                print(f"  • {item['param']:<15} [{item['confidence']}%] - {', '.join(item['reasons'])}")

        print(f"\n{Colors.BOLD}[NEXT STEPS - DECISION TREE]{Colors.END}")
        print("-" * 50)

        # Intelligent next steps based on findings
        suspicious_params = ['cmd', 'exec', 'command', 'file', 'path', 'include', 'template']
        auth_params = ['admin', 'debug', 'test', 'user', 'role', 'auth']
        data_params = ['id', 'cat', 'page', 'search', 'filter']

        found_suspicious = any(d['param'] in suspicious_params for d in self.discovered)
        found_auth = any(d['param'] in auth_params for d in self.discovered)
        found_data = any(d['param'] in data_params for d in self.discovered)

        if found_suspicious:
            print(f"{Colors.RED}⚠ Critical Parameters Found - Test for:{Colors.END}")
            print("  1. Command Injection: ; id ; whoami ; || ping -c 1 127.0.0.1")
            print("  2. Path Traversal: ../../../../etc/passwd")
            print("  3. File Inclusion: php://filter/convert.base64-encode/resource=index")
            print("  4. Template Injection: {{7*7}}, ${7*7}, <%= 7*7 %>")
            print(f"\n  Example: {self.target}?{self.discovered[0]['param']}=;id")

        if found_auth:
            print(f"{Colors.YELLOW}🔐 Authentication/Debug Parameters Found:{Colors.END}")
            print("  1. Test boolean values: 1, true, yes, on, enabled")
            print("  2. Try privilege escalation: admin=1, role=admin")
            print("  3. Enable debug modes: debug=1, test=true")
            print(f"\n  Example: {self.target}?{[d['param'] for d in self.discovered if d['param'] in auth_params][0]}=true")

        if found_data:
            print(f"{Colors.BLUE}📊 Data Parameters Found - Test for:{Colors.END}")
            print("  1. SQL Injection: ' OR '1'='1, 1 AND 1=2, 1 UNION SELECT NULL")
            print("  2. NoSQL Injection: {$ne:1}, {$gt:''}")
            print("  3. IDOR/Access Control: Increment IDs, try 0, -1, 999999")
            print(f"\n  Example: {self.target}?{[d['param'] for d in self.discovered if d['param'] in data_params][0]}=' OR '1'='1")

        print(f"\n{Colors.BOLD}[SUMMARY]{Colors.END}")
        print("-" * 50)
        print(f"Total parameters discovered: {len(self.discovered)}")
        print(f"High confidence findings: {len(high_confidence)}")
        print(f"Testing method used: {self.method}")

        if high_confidence:
            print(f"\n{Colors.GREEN}Priority targets for exploitation:{Colors.END}")
            for item in high_confidence[:3]:
                print(f"  → {item['param']} (test with: {item['param']}={item['payload']})")

def main():
    parser = argparse.ArgumentParser(
        description='Parameter Discovery Tool - Find hidden GET/POST parameters',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 param_discover.py http://target.com/page.php
  python3 param_discover.py http://target.com/page1.php http://target.com/page2.php
  python3 html_enum.py http://target.com | python3 param_discover.py
  cat urls.txt | python3 param_discover.py -m POST
  python3 param_discover.py http://target.com/*.php -w custom_params.txt
        """
    )

    parser.add_argument('targets', nargs='*', help='Target URLs to test (can specify multiple)')
    parser.add_argument('-m', '--method', default='GET', choices=['GET', 'POST'],
                       help='HTTP method to use (default: GET)')
    parser.add_argument('-w', '--wordlist', help='Custom parameter wordlist')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output (show all tests)')
    parser.add_argument('-q', '--quick', action='store_true',
                       help='Quick scan - test only high-value parameters (faster)')

    args = parser.parse_args()

    # Collect targets from arguments and stdin
    targets = []

    # Add command line targets
    if args.targets:
        targets.extend(args.targets)

    # Check if data is being piped in
    if not sys.stdin.isatty():
        import re
        base_url = None
        in_pages_section = False

        # Strip ANSI color codes
        ansi_escape = re.compile(r'\x1b\[[0-9;]*m')

        for line in sys.stdin:
            # Remove ANSI color codes first
            line = ansi_escape.sub('', line).strip()

            if not line:
                continue

            # Track when we enter the PAGES DISCOVERED section
            if '[PAGES DISCOVERED]' in line or 'PAGES DISCOVERED' in line:
                in_pages_section = True
                continue

            # Exit pages section when we hit next section
            if in_pages_section and ('[FORMS]' in line or '[COMMENTS]' in line or
                                      '[ENDPOINTS]' in line or 'FORMS' in line or
                                      'COMMENTS' in line or 'ENDPOINTS' in line):
                in_pages_section = False
                continue

            # Extract base URL from html_enum header
            if 'Start URL:' in line:
                match = re.search(r'Start URL:\s*(https?://[^\s]+)', line)
                if match:
                    base_url = match.group(1).rstrip('/')
                    continue

            # Only process paths from PAGES DISCOVERED section
            if in_pages_section:
                # Handle html_enum format: "1. /path - Title" or "1. / - Title"
                path_match = re.match(r'^\s*\d+\.\s+(/\S*)\s*-', line)
                if path_match and base_url:
                    path = path_match.group(1)
                    if path == '/':
                        targets.append(base_url)
                    else:
                        targets.append(f"{base_url}{path}")
                    continue

    if not targets:
        print(f"{Colors.RED}Error: No targets provided{Colors.END}")
        parser.print_help()
        sys.exit(1)

    # Remove duplicates while preserving order
    seen = set()
    unique_targets = []
    for target in targets:
        if target not in seen:
            seen.add(target)
            unique_targets.append(target)

    targets = unique_targets

    # Summary if multiple targets
    if len(targets) > 1:
        print(f"{Colors.BOLD}[BATCH MODE]{Colors.END}")
        print(f"Testing {len(targets)} targets with {args.method} method")
        print("-" * 50)
        for i, target in enumerate(targets, 1):
            print(f"  {i}. {target}")
        print("-" * 50 + "\n")

    # Track results for summary
    results_summary = []

    # Process each target
    for i, target in enumerate(targets, 1):
        if not target.startswith(('http://', 'https://')):
            target = f'http://{target}'

        if len(targets) > 1:
            print(f"{Colors.BOLD}[{i}/{len(targets)}] Testing: {target}{Colors.END}")
            print("=" * 60)

        try:
            discovery = ParameterDiscovery(target, args.method, args.wordlist, args.verbose, args.quick)
            discovery.discover()
            discovery.generate_report()

            # Track results
            results_summary.append({
                'target': target,
                'found': len(discovery.discovered),
                'params': discovery.discovered
            })

            if len(targets) > 1 and i < len(targets):
                print("\n")

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
            break
        except Exception as e:
            print(f"{Colors.RED}[!] Error testing {target}: {e}{Colors.END}")
            results_summary.append({
                'target': target,
                'found': 0,
                'params': [],
                'error': str(e)
            })
            continue

    # Final summary for multiple targets
    if len(targets) > 1:
        print(f"\n{Colors.BOLD}[FINAL SUMMARY]{Colors.END}")
        print("=" * 60)
        total_params = sum(r['found'] for r in results_summary)
        successful = len([r for r in results_summary if 'error' not in r])

        print(f"Targets tested: {len(targets)}")
        print(f"Successful: {successful}")
        print(f"Total parameters found: {total_params}")

        if total_params > 0:
            print(f"\n{Colors.GREEN}[TARGETS WITH PARAMETERS]{Colors.END}")
            for r in results_summary:
                if r['found'] > 0:
                    print(f"  • {r['target']}: {r['found']} params")
                    for p in r['params']:
                        print(f"    - {p['param']} [Confidence: {p['confidence']:.0f}%]")

        print(f"\n{Colors.BOLD}[RECOMMENDED NEXT STEPS]{Colors.END}")
        if total_params > 0:
            print(f"  {Colors.GREEN}• Focus on endpoints with discovered parameters{Colors.END}")
            print(f"  {Colors.YELLOW}• Test each parameter for injection vulnerabilities{Colors.END}")
            print(f"  {Colors.YELLOW}• Try parameter pollution and HPP attacks{Colors.END}")
        else:
            print(f"  {Colors.YELLOW}• Try POST method if GET was used (or vice versa){Colors.END}")
            print(f"  {Colors.YELLOW}• Look for API endpoints or REST routes{Colors.END}")
            print(f"  {Colors.YELLOW}• Check JavaScript files for AJAX parameters{Colors.END}")

if __name__ == '__main__':
    main()