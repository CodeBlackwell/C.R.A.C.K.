#!/usr/bin/env python3
"""
Validate filled_example Field Presence

Validates that:
1. Commands WITH <PLACEHOLDERS> MUST have a filled_example field
2. Commands WITHOUT <PLACEHOLDERS> MUST NOT have a filled_example field (redundant)

Usage:
    python3 validate_filled_examples.py [options]

Options:
    --json-output PATH    Save JSON report to file
    --verbose             Show all violations (not just first 50)
    --fix-preview         Show auto-fix preview from variables[].example
    --category CATEGORY   Filter by category
"""

import json
import re
import argparse
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional
from datetime import datetime
import sys

# ANSI color codes
class Colors:
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[36m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'

# Regex to match <PLACEHOLDER> patterns (uppercase with underscores/numbers)
PLACEHOLDER_PATTERN = re.compile(r'<[A-Z][A-Z0-9_]*>')


class FilledExampleValidator:
    """Validates filled_example field presence in command JSON files"""

    def __init__(self, base_path: Path, category_filter: Optional[str] = None):
        self.base_path = base_path
        self.commands_dir = base_path / 'data' / 'commands'
        self.category_filter = category_filter

        # Statistics
        self.stats = {
            'total_files': 0,
            'total_commands': 0,
            'with_placeholders': 0,
            'without_placeholders': 0,
            'has_filled_example': 0,
            'missing_filled_example': 0,
            'redundant_filled_example': 0,
            'can_auto_generate': 0,
            'cannot_auto_generate': 0,
        }

        # Violation tracking
        self.missing_violations: List[Dict] = []
        self.redundant_violations: List[Dict] = []
        self.file_violations: Dict[str, List[Dict]] = defaultdict(list)

    def has_placeholders(self, command: str) -> bool:
        """Check if command contains <PLACEHOLDER> patterns"""
        return bool(PLACEHOLDER_PATTERN.search(command))

    def extract_placeholders(self, command: str) -> List[str]:
        """Extract all placeholders from command string"""
        return PLACEHOLDER_PATTERN.findall(command)

    def generate_filled_example(self, command: str, variables: List[Dict]) -> Tuple[str, List[str], List[str]]:
        """
        Generate filled_example from command and variables.
        Returns: (filled_example, used_vars, missing_vars)
        """
        result = command
        used_vars = []
        missing_vars = []

        # Build lookup from variable name to example
        var_lookup = {}
        for var in variables:
            name = var.get('name', '')
            example = var.get('example', '')
            if name:
                var_lookup[name] = example

        # Find all placeholders in command
        placeholders = self.extract_placeholders(command)

        for placeholder in placeholders:
            if placeholder in var_lookup:
                example_value = var_lookup[placeholder]
                if example_value:
                    result = result.replace(placeholder, str(example_value))
                    used_vars.append(f"{placeholder} -> {example_value}")
                else:
                    missing_vars.append(f"{placeholder} (no example value)")
            else:
                missing_vars.append(f"{placeholder} (no variable definition)")

        return result, used_vars, missing_vars

    def validate_command(self, cmd: Dict, file_path: str) -> Optional[Dict]:
        """Validate a single command for filled_example compliance"""
        cmd_id = cmd.get('id', 'unknown')
        command = cmd.get('command', '')
        filled_example = cmd.get('filled_example')
        variables = cmd.get('variables', [])

        has_ph = self.has_placeholders(command)
        has_fe = filled_example is not None and filled_example != ''

        if has_ph:
            self.stats['with_placeholders'] += 1
            if has_fe:
                self.stats['has_filled_example'] += 1
            else:
                # VIOLATION: Has placeholders but missing filled_example
                self.stats['missing_filled_example'] += 1
                placeholders = self.extract_placeholders(command)

                # Try to generate preview
                generated, used_vars, missing_vars = self.generate_filled_example(command, variables)
                can_generate = len(missing_vars) == 0

                if can_generate:
                    self.stats['can_auto_generate'] += 1
                else:
                    self.stats['cannot_auto_generate'] += 1

                violation = {
                    'id': cmd_id,
                    'file': file_path,
                    'command': command,
                    'placeholders': placeholders,
                    'type': 'missing',
                    'can_auto_generate': can_generate,
                    'generated_preview': generated if can_generate else None,
                    'used_vars': used_vars,
                    'missing_vars': missing_vars,
                }
                self.missing_violations.append(violation)
                self.file_violations[file_path].append(violation)
                return violation
        else:
            self.stats['without_placeholders'] += 1
            if has_fe:
                # VIOLATION: No placeholders but has filled_example (redundant)
                self.stats['redundant_filled_example'] += 1
                violation = {
                    'id': cmd_id,
                    'file': file_path,
                    'command': command,
                    'filled_example': filled_example,
                    'type': 'redundant',
                }
                self.redundant_violations.append(violation)
                self.file_violations[file_path].append(violation)
                return violation

        return None

    def validate_file(self, json_file: Path) -> List[Dict]:
        """Validate all commands in a JSON file"""
        violations = []
        rel_path = str(json_file.relative_to(self.base_path))

        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            return [{'error': f'JSON parse error: {e}', 'file': rel_path}]
        except Exception as e:
            return [{'error': f'File read error: {e}', 'file': rel_path}]

        # Extract commands array
        commands = data.get('commands', [])
        if not commands and 'id' in data:
            commands = [data]  # Single command format

        for cmd in commands:
            self.stats['total_commands'] += 1
            violation = self.validate_command(cmd, rel_path)
            if violation:
                violations.append(violation)

        return violations

    def validate_all(self) -> None:
        """Validate all command JSON files"""
        if not self.commands_dir.exists():
            print(f"{Colors.RED}Error: Commands directory not found: {self.commands_dir}{Colors.RESET}")
            sys.exit(1)

        for json_file in sorted(self.commands_dir.rglob('*.json')):
            # Skip backup files
            if '.bak' in str(json_file) or '.backup' in str(json_file):
                continue

            # Apply category filter if specified
            if self.category_filter:
                if self.category_filter not in str(json_file):
                    continue

            self.stats['total_files'] += 1
            self.validate_file(json_file)

    def generate_terminal_report(self, verbose: bool = False, fix_preview: bool = False) -> str:
        """Generate colored terminal report"""
        lines = []

        # Header
        lines.append(f"\n{Colors.BOLD}{'=' * 70}")
        lines.append("FILLED EXAMPLE VALIDATION REPORT")
        lines.append(f"{'=' * 70}{Colors.RESET}\n")

        # Summary
        lines.append(f"{Colors.BOLD}SUMMARY{Colors.RESET}")
        lines.append("-" * 70)
        lines.append(f"Total files scanned:        {self.stats['total_files']}")
        lines.append(f"Total commands scanned:     {self.stats['total_commands']}")
        lines.append(f"Commands with placeholders: {self.stats['with_placeholders']}")
        lines.append(f"Commands without placeholders: {self.stats['without_placeholders']}")
        lines.append("")

        # Violations summary
        lines.append(f"{Colors.BOLD}VIOLATIONS{Colors.RESET}")
        lines.append("-" * 70)

        missing_count = self.stats['missing_filled_example']
        redundant_count = self.stats['redundant_filled_example']

        if missing_count > 0:
            lines.append(f"{Colors.RED}[HIGH] Missing filled_example:    {missing_count} commands{Colors.RESET}")
            lines.append(f"       - Can auto-generate:       {self.stats['can_auto_generate']}")
            lines.append(f"       - Cannot auto-generate:    {self.stats['cannot_auto_generate']}")
        else:
            lines.append(f"{Colors.GREEN}[HIGH] Missing filled_example:    0 commands {Colors.RESET}")

        if redundant_count > 0:
            lines.append(f"{Colors.YELLOW}[LOW]  Redundant filled_example:  {redundant_count} commands{Colors.RESET}")
        else:
            lines.append(f"{Colors.GREEN}[LOW]  Redundant filled_example:  0 commands {Colors.RESET}")

        lines.append("")

        # Top files with missing filled_example
        if self.file_violations:
            lines.append(f"{Colors.BOLD}TOP 10 FILES WITH VIOLATIONS{Colors.RESET}")
            lines.append("-" * 70)

            sorted_files = sorted(
                self.file_violations.items(),
                key=lambda x: len([v for v in x[1] if v.get('type') == 'missing']),
                reverse=True
            )[:10]

            for i, (file_path, violations) in enumerate(sorted_files, 1):
                missing = [v for v in violations if v.get('type') == 'missing']
                redundant = [v for v in violations if v.get('type') == 'redundant']

                lines.append(f"\n{Colors.BLUE}{i}. {file_path}{Colors.RESET}")
                if missing:
                    lines.append(f"   {Colors.RED}Missing: {len(missing)}{Colors.RESET}")
                    for v in missing[:3]:
                        lines.append(f"     - {v['id']}")
                    if len(missing) > 3:
                        lines.append(f"     ... and {len(missing) - 3} more")
                if redundant:
                    lines.append(f"   {Colors.YELLOW}Redundant: {len(redundant)}{Colors.RESET}")

            lines.append("")

        # Detailed missing violations
        if self.missing_violations:
            limit = len(self.missing_violations) if verbose else 50
            lines.append(f"{Colors.BOLD}COMMANDS MISSING filled_example")
            if not verbose and len(self.missing_violations) > 50:
                lines.append(f"(showing first 50 of {len(self.missing_violations)} - use --verbose for all)")
            lines.append(f"{Colors.RESET}")
            lines.append("-" * 70)

            for i, v in enumerate(self.missing_violations[:limit], 1):
                lines.append(f"\n{Colors.RED}[{i}] {v['id']}{Colors.RESET}")
                lines.append(f"    File: {v['file']}")

                # Truncate long commands
                cmd_display = v['command'][:80] + '...' if len(v['command']) > 80 else v['command']
                lines.append(f"    Command: {cmd_display}")
                lines.append(f"    Placeholders: {', '.join(v['placeholders'])}")

                if fix_preview:
                    if v['can_auto_generate']:
                        lines.append(f"\n    {Colors.GREEN}FIX PREVIEW:{Colors.RESET}")
                        preview = v['generated_preview']
                        preview_display = preview[:100] + '...' if len(preview) > 100 else preview
                        lines.append(f"    {Colors.DIM}\"filled_example\": \"{preview_display}\"{Colors.RESET}")
                        lines.append(f"\n    Variables used:")
                        for var in v['used_vars']:
                            lines.append(f"      {var}")
                    else:
                        lines.append(f"\n    {Colors.YELLOW}CANNOT AUTO-GENERATE:{Colors.RESET}")
                        for missing in v['missing_vars']:
                            lines.append(f"      - {missing}")

            if not verbose and len(self.missing_violations) > 50:
                lines.append(f"\n... and {len(self.missing_violations) - 50} more violations")

        # Redundant violations
        if self.redundant_violations:
            lines.append(f"\n{Colors.BOLD}COMMANDS WITH REDUNDANT filled_example{Colors.RESET}")
            lines.append("-" * 70)

            limit = len(self.redundant_violations) if verbose else 20
            for i, v in enumerate(self.redundant_violations[:limit], 1):
                lines.append(f"\n{Colors.YELLOW}[{i}] {v['id']}{Colors.RESET}")
                lines.append(f"    File: {v['file']}")
                cmd_display = v['command'][:60] + '...' if len(v['command']) > 60 else v['command']
                lines.append(f"    Command: {cmd_display}")
                lines.append(f"    {Colors.DIM}(No placeholders - filled_example is redundant){Colors.RESET}")

        # Final status
        lines.append(f"\n{'=' * 70}")
        total_violations = missing_count + redundant_count
        if total_violations == 0:
            lines.append(f"{Colors.GREEN}{Colors.BOLD}STATUS: ALL COMMANDS COMPLIANT{Colors.RESET}")
        else:
            lines.append(f"{Colors.RED}{Colors.BOLD}STATUS: {total_violations} VIOLATIONS FOUND{Colors.RESET}")
        lines.append(f"{'=' * 70}\n")

        return '\n'.join(lines)

    def generate_json_report(self) -> Dict:
        """Generate JSON report for programmatic use"""
        return {
            'timestamp': datetime.now().isoformat(),
            'summary': {
                'total_files': self.stats['total_files'],
                'total_commands': self.stats['total_commands'],
                'with_placeholders': self.stats['with_placeholders'],
                'without_placeholders': self.stats['without_placeholders'],
                'missing_filled_example': self.stats['missing_filled_example'],
                'redundant_filled_example': self.stats['redundant_filled_example'],
                'can_auto_generate': self.stats['can_auto_generate'],
                'cannot_auto_generate': self.stats['cannot_auto_generate'],
            },
            'missing': self.missing_violations,
            'redundant': self.redundant_violations,
            'files_with_violations': dict(self.file_violations),
        }


def main():
    parser = argparse.ArgumentParser(
        description='Validate filled_example field presence in command JSON files'
    )
    parser.add_argument(
        '--json-output',
        type=str,
        help='Save JSON report to specified file'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Show all violations (not just first 50)'
    )
    parser.add_argument(
        '--fix-preview',
        action='store_true',
        help='Show auto-fix preview from variables[].example'
    )
    parser.add_argument(
        '--category',
        type=str,
        help='Filter by category (e.g., web, enumeration, post-exploit)'
    )
    parser.add_argument(
        '--base-path',
        type=str,
        default=None,
        help='Base path to db directory (default: auto-detect)'
    )

    args = parser.parse_args()

    # Auto-detect base path
    if args.base_path:
        base_path = Path(args.base_path)
    else:
        # Try to find db directory relative to script location
        script_dir = Path(__file__).parent
        if (script_dir.parent / 'data' / 'commands').exists():
            base_path = script_dir.parent
        elif (script_dir / 'data' / 'commands').exists():
            base_path = script_dir
        else:
            # Fallback to current directory
            base_path = Path.cwd()
            if not (base_path / 'data' / 'commands').exists():
                print(f"{Colors.RED}Error: Cannot find data/commands directory{Colors.RESET}")
                print(f"Run from db directory or specify --base-path")
                sys.exit(1)

    # Run validation
    validator = FilledExampleValidator(base_path, category_filter=args.category)
    validator.validate_all()

    # Generate and print terminal report
    print(validator.generate_terminal_report(
        verbose=args.verbose,
        fix_preview=args.fix_preview
    ))

    # Save JSON report if requested
    if args.json_output:
        json_report = validator.generate_json_report()
        output_path = Path(args.json_output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(json_report, f, indent=2)
        print(f"{Colors.GREEN}JSON report saved to: {output_path}{Colors.RESET}")

    # Exit with error code if violations found
    total_violations = (
        validator.stats['missing_filled_example'] +
        validator.stats['redundant_filled_example']
    )
    sys.exit(1 if total_violations > 0 else 0)


if __name__ == '__main__':
    main()
