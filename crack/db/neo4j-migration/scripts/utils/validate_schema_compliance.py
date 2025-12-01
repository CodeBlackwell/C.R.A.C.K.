#!/usr/bin/env python3
"""
Schema Validation Script for OSCP Command Database
Validates all command JSON files against schema requirements before Neo4j migration.

Phase 2D.3: Comprehensive validation of all 1,532 commands
"""

import json
import re
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Tuple
import sys

class CheatsheetValidator:
    """Validates cheatsheet JSON files against schema requirements"""

    def __init__(self, base_path: Path, all_command_ids: Set[str] = None):
        self.base_path = base_path
        self.cheatsheets_dir = base_path / 'db' / 'data' / 'cheatsheets'
        self.all_command_ids = all_command_ids or set()
        self.violations: Dict[str, List[Dict]] = defaultdict(list)
        self.stats = defaultdict(int)

    def validate_section_command(self, cmd, section_title: str, cheatsheet_id: str) -> List[Dict]:
        """Validate a single command entry in a section"""
        errors = []

        # Must be an object with 'id' and 'example' fields
        if isinstance(cmd, str):
            errors.append({
                'cheatsheet_id': cheatsheet_id,
                'section': section_title,
                'command': cmd,
                'error': 'Command must be object with id/example fields, not string',
                'fix': f'{{"id": "{cmd}", "example": "<filled command>", "shows": "<expected output>"}}'
            })
            return errors

        if not isinstance(cmd, dict):
            errors.append({
                'cheatsheet_id': cheatsheet_id,
                'section': section_title,
                'error': f'Command must be object, got {type(cmd).__name__}'
            })
            return errors

        # Check required fields
        if 'id' not in cmd:
            errors.append({
                'cheatsheet_id': cheatsheet_id,
                'section': section_title,
                'command': cmd,
                'error': 'Missing required field: id'
            })

        if 'example' not in cmd:
            errors.append({
                'cheatsheet_id': cheatsheet_id,
                'section': section_title,
                'command_id': cmd.get('id', 'unknown'),
                'error': 'Missing required field: example'
            })

        # Validate command ID exists (if we have the full list)
        cmd_id = cmd.get('id')
        if cmd_id and self.all_command_ids and cmd_id not in self.all_command_ids:
            errors.append({
                'cheatsheet_id': cheatsheet_id,
                'section': section_title,
                'command_id': cmd_id,
                'error': f'Command ID "{cmd_id}" not found in commands database'
            })

        # Validate example is non-empty string
        example = cmd.get('example')
        if example is not None:
            if not isinstance(example, str) or not example.strip():
                errors.append({
                    'cheatsheet_id': cheatsheet_id,
                    'section': section_title,
                    'command_id': cmd.get('id', 'unknown'),
                    'error': 'Example must be non-empty string'
                })

        return errors

    def validate_file(self, json_file: Path) -> Dict:
        """Validate a single cheatsheet JSON file"""
        file_violations = defaultdict(list)

        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            return {'json_parse_error': str(e)}

        # Must have 'cheatsheets' wrapper
        cheatsheets = data.get('cheatsheets', [])
        if not cheatsheets:
            file_violations['invalid_format'].append({
                'file': str(json_file),
                'error': 'Missing "cheatsheets" array wrapper'
            })
            return dict(file_violations)

        self.stats['total_cheatsheets'] += len(cheatsheets)

        for cs in cheatsheets:
            cs_id = cs.get('id', 'unknown')

            # Validate sections
            sections = cs.get('sections', [])
            for section in sections:
                section_title = section.get('title', 'untitled')
                commands = section.get('commands', [])

                self.stats['total_section_commands'] += len(commands)

                for cmd in commands:
                    errors = self.validate_section_command(cmd, section_title, cs_id)
                    if errors:
                        file_violations['section_command_errors'].extend(errors)
                        self.stats['section_command_errors'] += len(errors)
                    else:
                        self.stats['valid_section_commands'] += 1

        return dict(file_violations)

    def validate_all(self) -> Dict:
        """Validate all cheatsheet JSON files"""
        print(f"Validating cheatsheets in {self.cheatsheets_dir}...")

        file_results = {}
        for json_file in sorted(self.cheatsheets_dir.rglob('*.json')):
            rel_path = str(json_file.relative_to(self.base_path))
            violations = self.validate_file(json_file)
            if violations:
                file_results[rel_path] = violations

        return file_results

    def generate_report(self, file_results: Dict) -> str:
        """Generate cheatsheet validation report"""
        report = []
        report.append("=" * 80)
        report.append("CHEATSHEET VALIDATION REPORT")
        report.append("=" * 80)
        report.append("")

        total = self.stats['total_section_commands']
        valid = self.stats['valid_section_commands']
        errors = self.stats['section_command_errors']
        compliance_rate = (valid / total * 100) if total > 0 else 0

        report.append("SUMMARY STATISTICS")
        report.append("-" * 80)
        report.append(f"Total Cheatsheets: {self.stats['total_cheatsheets']}")
        report.append(f"Total Section Commands: {total}")
        report.append(f"Valid Section Commands: {valid} ({compliance_rate:.1f}%)")
        report.append(f"Commands with Errors: {errors}")
        report.append("")

        if file_results:
            report.append("FILES WITH VIOLATIONS")
            report.append("-" * 80)
            for file_path, violations in sorted(file_results.items()):
                error_count = sum(len(v) for v in violations.values() if isinstance(v, list))
                report.append(f"❌ {Path(file_path).name}: {error_count} errors")

                # Show first 3 errors per file
                for vtype, verrors in violations.items():
                    if isinstance(verrors, list):
                        for err in verrors[:3]:
                            cmd_info = err.get('command_id') or err.get('command', '')
                            section = err.get('section', '')
                            error_msg = err.get('error', '')
                            report.append(f"    [{section}] {cmd_info}: {error_msg}")
                        if len(verrors) > 3:
                            report.append(f"    ... and {len(verrors) - 3} more")
            report.append("")

        report.append("=" * 80)
        if compliance_rate >= 100:
            report.append("Status: ✓ ALL SECTION COMMANDS VALID")
        else:
            report.append(f"Status: ❌ {errors} COMMANDS NEED MIGRATION TO OBJECT FORMAT")
            report.append("")
            report.append("Required format for section commands:")
            report.append('  {"id": "command-id", "example": "filled command", "shows": "expected output"}')

        return "\n".join(report)


class SchemaValidator:
    """Validates command JSON files against schema requirements"""

    VALID_CATEGORIES = {
        'recon', 'web', 'exploitation', 'post-exploit', 'file-transfer',
        'pivoting', 'custom', 'enumeration', 'monitoring', 'utilities',
        'active-directory', 'post-exploitation', 'password-attacks',
        'tunneling', 'privilege-escalation', 'research', 'debugging',
        'amsi-bypass', 'uac-bypass', 'heuristic-evasion', 'signature-evasion',
        'shellcode-runners', 'vba-evasion', 'jscript-evasion'
    }

    REQUIRED_FIELDS = {'id', 'name', 'category', 'command', 'description'}

    def __init__(self, base_path: Path):
        self.base_path = base_path
        self.commands_dir = base_path / 'reference' / 'data' / 'commands'
        self.all_command_ids: Set[str] = set()
        self.violations: Dict[str, List[Dict]] = defaultdict(list)
        self.stats = defaultdict(int)
        self.command_id_files: Dict[str, str] = {}

    def load_all_command_ids(self):
        """Load all command IDs to detect duplicates and orphaned references"""
        for json_file in self.commands_dir.rglob('*.json'):
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)

                commands = data.get('commands', [])
                for cmd in commands:
                    cmd_id = cmd.get('id', '')
                    if cmd_id:
                        if cmd_id in self.all_command_ids:
                            # Duplicate ID
                            self.violations['duplicate_ids'].append({
                                'id': cmd_id,
                                'file': str(json_file.relative_to(self.base_path)),
                                'previous_file': self.command_id_files.get(cmd_id)
                            })
                        else:
                            self.all_command_ids.add(cmd_id)
                            self.command_id_files[cmd_id] = str(json_file.relative_to(self.base_path))
            except Exception as e:
                self.violations['json_parse_errors'].append({
                    'file': str(json_file.relative_to(self.base_path)),
                    'error': str(e)
                })

    def validate_file(self, json_file: Path) -> Dict:
        """Validate a single JSON file"""
        file_violations = defaultdict(list)

        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            return {'json_parse_error': str(e)}

        commands = data.get('commands', [])
        self.stats['total_commands'] += len(commands)

        for idx, cmd in enumerate(commands):
            cmd_id = cmd.get('id', f'UNNAMED_{idx}')

            # Check required fields
            missing_fields = self.REQUIRED_FIELDS - set(cmd.keys())
            if missing_fields:
                file_violations['missing_required_fields'].append({
                    'id': cmd_id,
                    'missing': list(missing_fields)
                })
                self.stats['missing_required_fields'] += 1

            # Check ID format (kebab-case)
            if cmd.get('id'):
                if not re.match(r'^[a-z0-9]+(-[a-z0-9]+)*$', cmd['id']):
                    file_violations['invalid_id_format'].append({
                        'id': cmd_id,
                        'issue': 'ID must be lowercase kebab-case'
                    })
                    self.stats['invalid_id_format'] += 1

            # Check category validity
            if cmd.get('category') and cmd['category'] not in self.VALID_CATEGORIES:
                file_violations['invalid_category'].append({
                    'id': cmd_id,
                    'category': cmd['category'],
                    'valid_categories': sorted(list(self.VALID_CATEGORIES))
                })
                self.stats['invalid_category'] += 1

            # Check placeholders match variables
            command_text = cmd.get('command', '')
            placeholders = set(re.findall(r'<([A-Z0-9_]+)>', command_text))

            variables = cmd.get('variables', [])
            defined_vars = set()
            for var in variables:
                # Handle both string and dict variable formats
                if isinstance(var, dict):
                    var_name = var.get('name', '')
                elif isinstance(var, str):
                    var_name = var
                else:
                    continue

                if var_name:
                    defined_vars.add(var_name.strip('<>'))

            # Missing variable definitions
            missing_vars = placeholders - defined_vars
            if missing_vars:
                file_violations['missing_variable_definitions'].append({
                    'id': cmd_id,
                    'placeholders': list(missing_vars),
                    'command': command_text[:100]
                })
                self.stats['missing_variable_definitions'] += len(missing_vars)

            # Unused variable definitions
            unused_vars = defined_vars - placeholders
            if unused_vars:
                file_violations['unused_variable_definitions'].append({
                    'id': cmd_id,
                    'unused': list(unused_vars)
                })
                self.stats['unused_variable_definitions'] += len(unused_vars)

            # Check for hardcoded values (common patterns)
            hardcoded_patterns = [
                (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'IP address'),
                (r'\b(password|passwd|pwd):\s*\w+', 'password'),
                (r'--password\s+\w+', 'password flag'),
                (r'-p\s+\d+\s+', 'port number'),
                (r'user(name)?:\s*\w+', 'username')
            ]

            for pattern, desc in hardcoded_patterns:
                if re.search(pattern, command_text, re.IGNORECASE):
                    # Exclude if it's clearly a placeholder or example
                    if '<' not in command_text[max(0, command_text.find(re.search(pattern, command_text, re.IGNORECASE).group())-10):]:
                        file_violations['hardcoded_values'].append({
                            'id': cmd_id,
                            'type': desc,
                            'match': re.search(pattern, command_text, re.IGNORECASE).group(),
                            'command': command_text[:100]
                        })
                        self.stats['hardcoded_values'] += 1

            # Check relationship fields use IDs not text
            # Note: next_steps is allowed to contain text (it's documentation, not a relationship)
            for rel_field in ['alternatives', 'prerequisites']:
                if rel_field in cmd:
                    for item in cmd[rel_field]:
                        # Text violations: contains spaces, commands, or description-like content
                        if ' ' in item or len(item) > 60 or any(char in item for char in [':', '.', '(', ')']):
                            file_violations[f'{rel_field}_using_text'].append({
                                'id': cmd_id,
                                'text_value': item
                            })
                            self.stats[f'{rel_field}_using_text'] += 1

            # Check for orphaned references (command IDs that don't exist)
            # next_steps can contain text so we don't check it for orphaned refs
            for rel_field in ['alternatives', 'prerequisites']:
                if rel_field in cmd:
                    for ref_id in cmd[rel_field]:
                        # Only check if it looks like a valid ID (kebab-case)
                        if re.match(r'^[a-z0-9]+(-[a-z0-9]+)*$', ref_id):
                            if ref_id not in self.all_command_ids:
                                file_violations['orphaned_references'].append({
                                    'id': cmd_id,
                                    'field': rel_field,
                                    'missing_ref': ref_id
                                })
                                self.stats['orphaned_references'] += 1

            # Track compliance
            has_violations = any(v for v in file_violations.values())
            if not has_violations:
                self.stats['compliant_commands'] += 1
            else:
                self.stats['non_compliant_commands'] += 1

        return dict(file_violations)

    def validate_all(self) -> Dict:
        """Validate all JSON files"""
        print("Loading all command IDs...")
        self.load_all_command_ids()

        print(f"Validating {len(list(self.commands_dir.rglob('*.json')))} files...")

        file_results = {}
        for json_file in sorted(self.commands_dir.rglob('*.json')):
            rel_path = str(json_file.relative_to(self.base_path))
            violations = self.validate_file(json_file)
            if violations:
                file_results[rel_path] = violations

        return file_results

    def generate_report(self, file_results: Dict) -> str:
        """Generate comprehensive validation report"""
        report = []
        report.append("=" * 80)
        report.append("SCHEMA VALIDATION REPORT - Phase 2D.3")
        report.append("=" * 80)
        report.append("")

        # Summary statistics
        total_commands = self.stats['total_commands']
        compliant = self.stats['compliant_commands']
        non_compliant = self.stats['non_compliant_commands']
        compliance_rate = (compliant / total_commands * 100) if total_commands > 0 else 0

        report.append("SUMMARY STATISTICS")
        report.append("-" * 80)
        report.append(f"Total Commands Validated: {total_commands}")
        report.append(f"Compliant Commands: {compliant} ({compliance_rate:.1f}%)")
        report.append(f"Non-Compliant Commands: {non_compliant} ({100-compliance_rate:.1f}%)")
        report.append(f"Total Files: {len(file_results)}")
        report.append("")

        # Violation breakdown
        report.append("VIOLATION BREAKDOWN (by type)")
        report.append("-" * 80)

        violation_types = [
            ('missing_required_fields', 'CRITICAL', 'Missing Required Fields'),
            ('invalid_id_format', 'CRITICAL', 'Invalid ID Format'),
            ('invalid_category', 'HIGH', 'Invalid Category'),
            ('duplicate_ids', 'CRITICAL', 'Duplicate Command IDs'),
            ('missing_variable_definitions', 'HIGH', 'Missing Variable Definitions'),
            ('alternatives_using_text', 'HIGH', 'Alternatives Using Text (should be IDs)'),
            ('prerequisites_using_text', 'HIGH', 'Prerequisites Using Text (should be IDs)'),
            ('orphaned_references', 'MEDIUM', 'Orphaned References (missing commands)'),
            ('hardcoded_values', 'MEDIUM', 'Hardcoded Values (should use placeholders)'),
            ('unused_variable_definitions', 'LOW', 'Unused Variable Definitions'),
        ]

        for vtype, severity, desc in violation_types:
            count = self.stats.get(vtype, 0)
            if count > 0:
                report.append(f"[{severity}] {desc}: {count}")

        report.append("")

        # Phase 2B & 2C specific files
        phase_2b_files = [
            'db/data/commands/active-directory/ad-powershell-imports.json',
            'db/data/commands/post-exploit/windows-powershell-cmdlets.json',
            'db/data/commands/utilities/verification-utilities.json',
            'db/data/commands/utilities/extracted-utilities.json',
            'db/data/commands/web/xss-test-payloads.json',
            'db/data/commands/enumeration/tool-specific.json',
        ]

        phase_2c_files = [
            'db/data/commands/post-exploit/auto-generated-full-syntax-post-exploit.json',
            'db/data/commands/exploitation/auto-generated-full-syntax-exploitation.json',
            'db/data/commands/monitoring/auto-generated-full-syntax-monitoring.json',
            'db/data/commands/pivoting/auto-generated-full-syntax-pivoting.json',
            'db/data/commands/enumeration/auto-generated-full-syntax-enumeration.json',
            'db/data/commands/web/auto-generated-full-syntax-web.json',
        ]

        report.append("PHASE 2B FILES (High-Priority Manual)")
        report.append("-" * 80)
        for file in phase_2b_files:
            if file in file_results:
                violations = file_results[file]
                total_v = sum(len(v) for v in violations.values() if isinstance(v, list))
                report.append(f"❌ {Path(file).name}: {total_v} violations")
            else:
                report.append(f"✓ {Path(file).name}: COMPLIANT")
        report.append("")

        report.append("PHASE 2C FILES (Batch Full Syntax)")
        report.append("-" * 80)
        for file in phase_2c_files:
            if file in file_results:
                violations = file_results[file]
                total_v = sum(len(v) for v in violations.values() if isinstance(v, list))
                report.append(f"❌ {Path(file).name}: {total_v} violations")
            else:
                report.append(f"✓ {Path(file).name}: COMPLIANT")
        report.append("")

        # Top violations by file
        report.append("TOP 10 FILES WITH MOST VIOLATIONS")
        report.append("-" * 80)
        file_violation_counts = []
        for file, violations in file_results.items():
            total_v = sum(len(v) for v in violations.values() if isinstance(v, list))
            file_violation_counts.append((file, total_v))

        for file, count in sorted(file_violation_counts, key=lambda x: x[1], reverse=True)[:10]:
            report.append(f"{count:4d} violations - {Path(file).name}")
        report.append("")

        # Detailed examples
        report.append("SAMPLE VIOLATIONS (First 5 of each type)")
        report.append("-" * 80)

        for vtype, severity, desc in violation_types:
            examples = []
            for file, violations in file_results.items():
                if vtype in violations:
                    for violation in violations[vtype][:5-len(examples)]:
                        examples.append({
                            'file': Path(file).name,
                            'violation': violation
                        })
                        if len(examples) >= 5:
                            break
                if len(examples) >= 5:
                    break

            if examples:
                report.append(f"\n[{severity}] {desc}:")
                for ex in examples:
                    report.append(f"  File: {ex['file']}")
                    report.append(f"  {json.dumps(ex['violation'], indent=4)}")

        report.append("")
        report.append("=" * 80)
        report.append("RECOMMENDATIONS")
        report.append("=" * 80)

        if self.stats.get('duplicate_ids', 0) > 0:
            report.append("1. CRITICAL: Resolve duplicate IDs before migration")
        if self.stats.get('missing_variable_definitions', 0) > 0:
            report.append("2. HIGH: Add variable definitions for all placeholders")
        if self.stats.get('alternatives_using_text', 0) + self.stats.get('prerequisites_using_text', 0) > 0:
            report.append("3. HIGH: Convert text relationships to command IDs")
        if self.stats.get('orphaned_references', 0) > 0:
            report.append("4. MEDIUM: Create missing commands or remove invalid references")

        report.append("")
        report.append(f"Overall Compliance Rate: {compliance_rate:.1f}%")
        if compliance_rate >= 95:
            report.append("Status: ✓ READY FOR MIGRATION")
        elif compliance_rate >= 80:
            report.append("Status: ⚠ NEEDS FIXES (minor violations)")
        else:
            report.append("Status: ❌ NOT READY (critical violations)")

        return "\n".join(report)


def main():
    base_path = Path(__file__).resolve().parents[4]  # crack/
    validator = SchemaValidator(base_path)

    print("Starting schema validation...")
    file_results = validator.validate_all()

    report = validator.generate_report(file_results)

    # Write to file
    output_file = base_path / 'db' / 'neo4j-migration' / 'data' / 'SCHEMA_VALIDATION_REPORT.md'
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, 'w') as f:
        f.write(report)

    print(f"\nReport written to: {output_file}")
    print("\n" + "=" * 80)
    print("QUICK SUMMARY")
    print("=" * 80)
    print(f"Total Commands: {validator.stats['total_commands']}")
    print(f"Compliant: {validator.stats['compliant_commands']}")
    print(f"Non-Compliant: {validator.stats['non_compliant_commands']}")
    print(f"Compliance Rate: {(validator.stats['compliant_commands']/validator.stats['total_commands']*100):.1f}%")

    # Exit with error code if critical violations
    if validator.stats.get('duplicate_ids', 0) > 0 or validator.stats.get('missing_required_fields', 0) > 0:
        sys.exit(1)
    else:
        sys.exit(0)


def validate_cheatsheets():
    """Standalone cheatsheet validation"""
    base_path = Path(__file__).resolve().parents[4]  # crack/

    # First load all command IDs for reference validation
    commands_dir = base_path / 'db' / 'data' / 'commands'
    all_command_ids = set()
    for json_file in commands_dir.rglob('*.json'):
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            for cmd in data.get('commands', []):
                if cmd.get('id'):
                    all_command_ids.add(cmd['id'])
        except Exception:
            pass

    print(f"Loaded {len(all_command_ids)} command IDs for reference validation")

    validator = CheatsheetValidator(base_path, all_command_ids)
    file_results = validator.validate_all()

    report = validator.generate_report(file_results)

    # Write to file
    output_file = base_path / 'db' / 'neo4j-migration' / 'data' / 'CHEATSHEET_VALIDATION_REPORT.md'
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, 'w') as f:
        f.write(report)

    print(f"\nReport written to: {output_file}")
    print(report)

    # Exit with error code if there are validation errors
    if validator.stats.get('section_command_errors', 0) > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Validate schema compliance')
    parser.add_argument('--cheatsheets', action='store_true',
                        help='Validate cheatsheets instead of commands')
    args = parser.parse_args()

    if args.cheatsheets:
        validate_cheatsheets()
    else:
        main()
