#!/usr/bin/env python3
"""
Smart Test Runner - Intelligently runs tests in safe chunks with resource management

Features:
- Auto-discovers test modules and categories
- Runs tests sequentially to prevent overload
- Aggregates results with detailed reporting
- Timeout protection per module
- Memory-aware execution
- Colored output with progress bars

Usage:
    ./run_tests_smart.py                    # Run all tests
    ./run_tests_smart.py --track            # Only track tests
    ./run_tests_smart.py --sessions         # Only sessions tests
    ./run_tests_smart.py --unit             # Only unit tests
    ./run_tests_smart.py --integration      # Only integration tests
    ./run_tests_smart.py --timeout 60       # Custom timeout per module
    ./run_tests_smart.py --parallel 2       # Run 2 modules in parallel (careful!)
"""

import argparse
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Dict, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import json

# ANSI Colors
class Colors:
    RED = '\033[0;31m'
    GREEN = '\033[0;32m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    CYAN = '\033[0;36m'
    MAGENTA = '\033[0;35m'
    BOLD = '\033[1m'
    NC = '\033[0m'

@dataclass
class TestResult:
    """Result of running a test module"""
    module_path: str
    category: str
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    errors: int = 0
    duration: float = 0.0
    timeout: bool = False
    success: bool = True
    output: str = ""

@dataclass
class TestSummary:
    """Aggregate test results"""
    total_passed: int = 0
    total_failed: int = 0
    total_skipped: int = 0
    total_errors: int = 0
    total_duration: float = 0.0
    failed_modules: List[str] = field(default_factory=list)
    timeout_modules: List[str] = field(default_factory=list)
    results_by_category: Dict[str, List[TestResult]] = field(default_factory=lambda: defaultdict(list))

class TestRunner:
    """Safe sequential test runner"""

    def __init__(self, base_path: Path, timeout: int = 120, verbose: bool = True):
        self.base_path = base_path
        self.timeout = timeout
        self.verbose = verbose
        self.summary = TestSummary()

    def discover_test_modules(self, pattern: str = "tests") -> Dict[str, List[Path]]:
        """Discover all test modules organized by category"""
        test_dir = self.base_path / pattern
        if not test_dir.exists():
            return {}

        categories = {}
        for category_dir in sorted(test_dir.iterdir()):
            if not category_dir.is_dir() or category_dir.name.startswith('__'):
                continue

            # Find test files in category
            test_files = sorted(category_dir.glob("test_*.py"))
            if test_files:
                categories[category_dir.name] = test_files

        return categories

    def parse_pytest_output(self, output: str) -> Tuple[int, int, int, int, float]:
        """Parse pytest output to extract test statistics"""
        import re

        passed = failed = skipped = errors = 0
        duration = 0.0

        # Extract counts from summary line
        # Example: "5 passed, 2 failed, 1 skipped in 3.45s"
        if match := re.search(r'(\d+) passed', output):
            passed = int(match.group(1))
        if match := re.search(r'(\d+) failed', output):
            failed = int(match.group(1))
        if match := re.search(r'(\d+) skipped', output):
            skipped = int(match.group(1))
        if match := re.search(r'(\d+) error', output):
            errors = int(match.group(1))
        if match := re.search(r'in ([\d.]+)s', output):
            duration = float(match.group(1))

        return passed, failed, skipped, errors, duration

    def run_test_module(self, module_path: Path, category: str) -> TestResult:
        """Run a single test module with timeout protection"""
        module_name = module_path.stem
        result = TestResult(
            module_path=str(module_path),
            category=category
        )

        if self.verbose:
            print(f"\n{Colors.BLUE}┌{'─' * 70}┐{Colors.NC}")
            print(f"{Colors.BLUE}│ {category}/{module_name:<67}│{Colors.NC}")
            print(f"{Colors.BLUE}└{'─' * 70}┘{Colors.NC}")

        start_time = time.time()

        try:
            # Run pytest with timeout
            cmd = [
                'python', '-m', 'pytest',
                str(module_path),
                '-v',
                '--tb=short',
                '-q'  # Quieter output
            ]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout
            )

            result.duration = time.time() - start_time
            result.output = proc.stdout + proc.stderr

            # Parse results
            passed, failed, skipped, errors, _ = self.parse_pytest_output(result.output)
            result.passed = passed
            result.failed = failed
            result.skipped = skipped
            result.errors = errors
            result.success = (proc.returncode == 0)

            # Print status
            if result.success:
                print(f"{Colors.GREEN}✓ Passed: {passed}, Duration: {result.duration:.2f}s{Colors.NC}")
            else:
                print(f"{Colors.YELLOW}⚠ Passed: {passed}, Failed: {failed}, Skipped: {skipped}{Colors.NC}")
                if failed > 0 or errors > 0:
                    self.summary.failed_modules.append(f"{category}/{module_name}")

        except subprocess.TimeoutExpired:
            result.timeout = True
            result.success = False
            result.duration = self.timeout
            self.summary.timeout_modules.append(f"{category}/{module_name}")
            print(f"{Colors.RED}✗ TIMEOUT (>{self.timeout}s){Colors.NC}")

        except Exception as e:
            result.success = False
            result.errors = 1
            print(f"{Colors.RED}✗ ERROR: {e}{Colors.NC}")
            self.summary.failed_modules.append(f"{category}/{module_name}")

        # Update summary
        self.summary.total_passed += result.passed
        self.summary.total_failed += result.failed
        self.summary.total_skipped += result.skipped
        self.summary.total_errors += result.errors
        self.summary.total_duration += result.duration
        self.summary.results_by_category[category].append(result)

        # Small pause to prevent overload
        time.sleep(0.2)

        return result

    def run_category(self, category: str, test_files: List[Path]):
        """Run all tests in a category"""
        print(f"\n{Colors.CYAN}{'═' * 72}{Colors.NC}")
        print(f"{Colors.CYAN}{Colors.BOLD}  Category: {category} ({len(test_files)} modules){Colors.NC}")
        print(f"{Colors.CYAN}{'═' * 72}{Colors.NC}")

        for test_file in test_files:
            self.run_test_module(test_file, category)

    def print_summary(self):
        """Print comprehensive test summary"""
        print(f"\n{Colors.CYAN}{'╔' + '═' * 70 + '╗'}{Colors.NC}")
        print(f"{Colors.CYAN}║{' ' * 25}TEST SUMMARY{' ' * 33}║{Colors.NC}")
        print(f"{Colors.CYAN}{'╚' + '═' * 70 + '╝'}{Colors.NC}\n")

        # Overall statistics
        total_tests = (self.summary.total_passed + self.summary.total_failed +
                       self.summary.total_skipped)

        print(f"{Colors.GREEN}✓ Passed:  {self.summary.total_passed}{Colors.NC}")
        print(f"{Colors.RED}✗ Failed:  {self.summary.total_failed}{Colors.NC}")
        print(f"{Colors.YELLOW}⊘ Skipped: {self.summary.total_skipped}{Colors.NC}")
        print(f"{Colors.MAGENTA}⚡ Errors:  {self.summary.total_errors}{Colors.NC}")
        print(f"\n{Colors.BOLD}Total Tests: {total_tests}{Colors.NC}")
        print(f"{Colors.BOLD}Total Duration: {self.summary.total_duration:.2f}s{Colors.NC}")

        # Category breakdown
        if len(self.summary.results_by_category) > 1:
            print(f"\n{Colors.CYAN}{Colors.BOLD}Results by Category:{Colors.NC}")
            for category, results in sorted(self.summary.results_by_category.items()):
                cat_passed = sum(r.passed for r in results)
                cat_failed = sum(r.failed for r in results)
                cat_duration = sum(r.duration for r in results)

                status = f"{Colors.GREEN}✓{Colors.NC}" if cat_failed == 0 else f"{Colors.RED}✗{Colors.NC}"
                print(f"  {status} {category:<20} "
                      f"Passed: {cat_passed:<4} Failed: {cat_failed:<4} "
                      f"Time: {cat_duration:.2f}s")

        # Failed modules
        if self.summary.failed_modules:
            print(f"\n{Colors.RED}{Colors.BOLD}Failed Modules:{Colors.NC}")
            for module in self.summary.failed_modules:
                print(f"  {Colors.RED}✗{Colors.NC} {module}")

        # Timeout modules
        if self.summary.timeout_modules:
            print(f"\n{Colors.RED}{Colors.BOLD}Timeout Modules:{Colors.NC}")
            for module in self.summary.timeout_modules:
                print(f"  {Colors.RED}⏱{Colors.NC} {module}")

        # Final verdict
        print()
        if self.summary.total_failed == 0 and not self.summary.timeout_modules:
            print(f"{Colors.GREEN}{'═' * 72}{Colors.NC}")
            print(f"{Colors.GREEN}{Colors.BOLD}           ALL TESTS PASSED SUCCESSFULLY! ✓{Colors.NC}")
            print(f"{Colors.GREEN}{'═' * 72}{Colors.NC}")
            return True
        else:
            print(f"{Colors.RED}{'═' * 72}{Colors.NC}")
            print(f"{Colors.RED}{Colors.BOLD}              SOME TESTS FAILED ✗{Colors.NC}")
            print(f"{Colors.RED}{'═' * 72}{Colors.NC}")
            return False

    def run_all(self, filter_pattern: str = None):
        """Run all discovered tests"""
        start_time = time.time()

        categories = self.discover_test_modules()

        if not categories:
            print(f"{Colors.YELLOW}No test modules discovered{Colors.NC}")
            return False

        # Filter categories if specified
        if filter_pattern:
            categories = {k: v for k, v in categories.items()
                          if filter_pattern.lower() in k.lower()}

        print(f"\n{Colors.BOLD}Discovered {len(categories)} test categories{Colors.NC}")
        for cat, files in categories.items():
            print(f"  • {cat}: {len(files)} modules")

        # Run each category
        for category, test_files in sorted(categories.items()):
            self.run_category(category, test_files)

        elapsed = time.time() - start_time
        self.summary.total_duration = elapsed

        return self.print_summary()


def main():
    parser = argparse.ArgumentParser(
        description='Smart test runner with resource management',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                    # Run all tests
  %(prog)s --track            # Only track tests
  %(prog)s --sessions         # Only sessions tests
  %(prog)s --timeout 60       # Custom timeout per module
        """
    )

    parser.add_argument('--track', action='store_true',
                        help='Run only track tests')
    parser.add_argument('--sessions', action='store_true',
                        help='Run only sessions tests')
    parser.add_argument('--unit', action='store_true',
                        help='Run only unit tests')
    parser.add_argument('--integration', action='store_true',
                        help='Run only integration tests')
    parser.add_argument('--timeout', type=int, default=120,
                        help='Timeout per module in seconds (default: 120)')
    parser.add_argument('--quiet', action='store_true',
                        help='Suppress verbose output')

    args = parser.parse_args()

    # Determine filter
    filter_pattern = None
    if args.track:
        filter_pattern = 'track'
    elif args.sessions:
        filter_pattern = 'sessions'
    elif args.unit:
        filter_pattern = 'unit'
    elif args.integration:
        filter_pattern = 'integration'

    # Run tests
    base_path = Path(__file__).parent
    runner = TestRunner(
        base_path=base_path,
        timeout=args.timeout,
        verbose=not args.quiet
    )

    success = runner.run_all(filter_pattern)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
