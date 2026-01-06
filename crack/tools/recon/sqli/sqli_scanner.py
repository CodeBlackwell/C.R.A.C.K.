#!/usr/bin/env python3
"""
SQL Injection Scanner CLI
Command-line interface for SQLi vulnerability detection
"""

import sys
import argparse
import re
from .scanner import SQLiScanner
from .reporter import SQLiReporter

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


def parse_stdin():
    """Parse input from param_discover.py output"""
    targets = []

    if not sys.stdin.isatty():
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


def main():
    parser = argparse.ArgumentParser(
        description='SQL Injection Scanner - Educational SQLi vulnerability detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Test GET parameters in URL
  python3 -m crack.enumeration.sqli "http://target.com/page.php?id=1&name=test"

  # Test POST parameters
  python3 -m crack.enumeration.sqli http://target.com/login.php -d "username=admin&password=pass"

  # Test specific parameters
  python3 -m crack.enumeration.sqli http://target.com/page.php -p id,search,filter

  # Pipeline from param_discover.py
  python3 param_discover.py http://target.com | python3 -m crack.enumeration.sqli

  # Quick scan with specific technique
  python3 -m crack.enumeration.sqli http://target.com/page.php?id=1 -q -t error

  # Verbose scan of POST form
  python3 -m crack.enumeration.sqli http://target.com/form.php -m POST -d "weight=75&height=180" -v

Educational Notes:
  This tool teaches SQL injection detection techniques.
  Always use responsibly and only on authorized targets.
  For professional preparation, understand both manual and automated approaches.
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

    args = parser.parse_args()

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

                params_tested = scanner.scan()
                scanner.generate_report(params_tested)

                if scanner.get_vulnerabilities():
                    all_vulnerabilities.extend(scanner.get_vulnerabilities())

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

            params_tested = scanner.scan()
            scanner.generate_report(params_tested)

            # Save output if requested
            if args.output and scanner.get_vulnerabilities():
                reporter = SQLiReporter(args.target, scanner.method, scanner.post_params)
                reporter.export_results(args.output, scanner.get_vulnerabilities(), scanner.get_tested_count())

        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}[!] Error: {e}{Colors.END}")
            sys.exit(1)


if __name__ == '__main__':
    main()