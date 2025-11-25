#!/usr/bin/env python3
"""
Comprehensive command validation script for Neo4j schema compliance.
Validates all command JSON files against the shared schema.
"""

import json
import glob
import sys
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# Import validation function from reference/core/validator.py
import importlib.util
validator_path = Path(__file__).resolve().parent.parent.parent.parent.parent / "reference" / "core" / "validator.py"
spec = importlib.util.spec_from_file_location("validator", validator_path)
validator_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator_module)
CommandValidator = validator_module.CommandValidator

def validate_all_commands(commands_dir: str = "db/data/commands"):
    """Validate all command files and generate comprehensive report."""

    validator = CommandValidator()
    errors_by_type = defaultdict(list)
    errors_by_file = defaultdict(list)
    total_files = 0
    total_commands = 0
    valid_commands = 0
    warnings_count = 0

    # Find all JSON files
    json_files = glob.glob(f'{commands_dir}/**/*.json', recursive=True)

    for json_file in sorted(json_files):
        # Skip backup files
        if json_file.endswith('.bak') or '.backup' in json_file:
            continue

        total_files += 1

        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            error = {
                'file': json_file,
                'command_id': 'N/A',
                'error_type': 'json_syntax',
                'message': f"Invalid JSON: {str(e)}"
            }
            errors_by_type['json_syntax'].append(error)
            errors_by_file[json_file].append(error)
            continue
        except Exception as e:
            error = {
                'file': json_file,
                'command_id': 'N/A',
                'error_type': 'file_error',
                'message': f"File error: {str(e)}"
            }
            errors_by_type['file_error'].append(error)
            errors_by_file[json_file].append(error)
            continue

        # Handle both single command files and command arrays
        commands = data.get('commands', [data] if 'id' in data else [])

        for cmd in commands:
            total_commands += 1

            # Validate using CommandValidator
            try:
                is_valid, error_list = validator.validate_command(cmd)
            except Exception as e:
                # Catch validation errors and report them
                is_valid = False
                error_list = [f"Validation error: {str(e)}"]

            if is_valid and not error_list:
                valid_commands += 1
            else:
                for error_msg in error_list:
                    # Parse error type from message
                    error_type = 'validation_error'
                    if 'Missing required field' in error_msg:
                        error_type = 'missing_field'
                    elif 'placeholder' in error_msg.lower():
                        error_type = 'invalid_placeholder'
                    elif 'duplicate' in error_msg.lower():
                        error_type = 'duplicate_id'
                    elif 'category' in error_msg.lower():
                        error_type = 'invalid_category'
                    elif 'variable' in error_msg.lower() or 'defined but not used' in error_msg:
                        error_type = 'variable_mismatch'
                        warnings_count += 1  # These are warnings
                        continue  # Skip adding to errors
                    elif 'must be a list' in error_msg or 'must be an array' in error_msg:
                        error_type = 'wrong_type'
                    elif 'ID format' in error_msg:
                        error_type = 'invalid_id_format'
                    elif 'Tag should be uppercase' in error_msg:
                        warnings_count += 1  # This is a warning
                        continue  # Skip adding to errors

                    error = {
                        'file': json_file,
                        'command_id': cmd.get('id', 'N/A'),
                        'error_type': error_type,
                        'message': error_msg
                    }
                    errors_by_type[error_type].append(error)
                    errors_by_file[json_file].append(error)

    # Generate report
    total_errors = sum(len(v) for v in errors_by_type.values())
    success_rate = (valid_commands / total_commands * 100) if total_commands > 0 else 0

    report = {
        'timestamp': datetime.now().isoformat(),
        'summary': {
            'files_validated': total_files,
            'commands_validated': total_commands,
            'valid_commands': valid_commands,
            'invalid_commands': total_commands - valid_commands,
            'warnings': warnings_count,
            'success_rate': f"{success_rate:.2f}%"
        },
        'errors': {
            'total': total_errors,
            'by_type': {k: len(v) for k, v in errors_by_type.items()}
        },
        'details': []
    }

    # Add error details (limit to first 100 for readability)
    all_errors = []
    for error_list in errors_by_type.values():
        all_errors.extend(error_list)

    report['details'] = all_errors[:100]
    if len(all_errors) > 100:
        report['details_truncated'] = f"Showing first 100 of {len(all_errors)} errors"

    return report, errors_by_file, errors_by_type

def print_summary(report):
    """Print human-readable summary."""
    print("\n" + "="*80)
    print("COMMAND VALIDATION REPORT")
    print("="*80)
    print(f"Timestamp: {report['timestamp']}")
    print(f"\nFiles Validated: {report['summary']['files_validated']}")
    print(f"Commands Validated: {report['summary']['commands_validated']}")
    print(f"Valid Commands: {report['summary']['valid_commands']}")
    print(f"Invalid Commands: {report['summary']['invalid_commands']}")
    print(f"Warnings (non-blocking): {report['summary']['warnings']}")
    print(f"Success Rate: {report['summary']['success_rate']}")

    print(f"\n--- Errors by Type ---")
    if report['errors']['total'] == 0:
        print("No errors found!")
    else:
        print(f"Total Errors: {report['errors']['total']}")
        for error_type, count in sorted(report['errors']['by_type'].items(),
                                       key=lambda x: x[1], reverse=True):
            print(f"  {error_type}: {count}")

    print("="*80 + "\n")

def print_detailed_errors(errors_by_file, limit=20):
    """Print detailed errors grouped by file."""
    if not errors_by_file:
        return

    print("\n" + "="*80)
    print("DETAILED ERRORS (Top Files)")
    print("="*80)

    # Sort files by error count
    sorted_files = sorted(errors_by_file.items(),
                         key=lambda x: len(x[1]), reverse=True)

    for i, (file_path, errors) in enumerate(sorted_files[:limit]):
        print(f"\n[{i+1}] {file_path}")
        print(f"    Errors: {len(errors)}")
        for error in errors[:5]:  # Show first 5 errors per file
            print(f"    - [{error['error_type']}] {error['command_id']}: {error['message']}")
        if len(errors) > 5:
            print(f"    ... and {len(errors) - 5} more errors")

    print("="*80 + "\n")

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='Validate all command JSON files')
    parser.add_argument('--commands-dir', default='db/data/commands',
                       help='Directory containing command JSON files')
    parser.add_argument('--output', default='validation_report.json',
                       help='Output JSON report file')
    parser.add_argument('--verbose', action='store_true',
                       help='Print detailed error information')
    parser.add_argument('--no-json', action='store_true',
                       help='Skip JSON output file')

    args = parser.parse_args()

    # Run validation
    report, errors_by_file, errors_by_type = validate_all_commands(args.commands_dir)

    # Print summary
    print_summary(report)

    # Print detailed errors if requested
    if args.verbose and errors_by_file:
        print_detailed_errors(errors_by_file)

    # Save JSON report
    if not args.no_json:
        with open(args.output, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"Full report saved to: {args.output}")

    # Exit with error code if validation failed
    sys.exit(1 if report['errors']['total'] > 0 else 0)
