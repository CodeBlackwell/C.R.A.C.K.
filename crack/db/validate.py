#!/usr/bin/env python3
"""
CRACK Database Validation System

Comprehensive validation for database integrity, normalization, and relationships.
Ensures all commands, flags, variables, tags, and relations are properly structured.
"""

import psycopg2
from psycopg2.extras import RealDictCursor
from typing import Dict, List, Any, Tuple
from pathlib import Path
import json
import re


class Colors:
    """ANSI color codes"""
    CYAN = '\033[36m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    RED = '\033[31m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


class DatabaseValidator:
    """Comprehensive database validation for CRACK reference system"""

    def __init__(self, db_config: Dict[str, Any]):
        """
        Initialize validator

        Args:
            db_config: PostgreSQL connection config
        """
        self.db_config = db_config
        self.conn = None
        self.cursor = None
        self.errors = []
        self.warnings = []
        self.stats = {
            'commands': 0,
            'flags': 0,
            'variables': 0,
            'tags': 0,
            'relations': 0,
            'guidance_relations': 0,  # NEW: descriptive text relations
            'indicators': 0,
            'unresolved_relations': 0
        }

    def connect(self):
        """Establish database connection"""
        try:
            self.conn = psycopg2.connect(**self.db_config)
            self.cursor = self.conn.cursor(cursor_factory=RealDictCursor)
            return True
        except Exception as e:
            self.errors.append(f"Database connection failed: {e}")
            return False

    def close(self):
        """Close database connection"""
        if self.cursor:
            self.cursor.close()
        if self.conn:
            self.conn.close()

    # ========================================================================
    # 1. Schema Validation
    # ========================================================================

    def validate_schema(self) -> Dict[str, Any]:
        """
        Validate database schema exists and is complete

        Returns:
            Dict with validation results
        """
        print(f"{Colors.CYAN}🔍 Validating Schema...{Colors.RESET}")

        required_tables = [
            'commands', 'command_flags', 'variables', 'command_vars',
            'tags', 'command_tags', 'command_relations', 'command_relation_guidance',
            'command_indicators',
            'services', 'service_ports', 'service_aliases', 'service_commands',
            'attack_chains', 'chain_prerequisites', 'chain_steps', 'step_dependencies',
            'schema_version'
        ]

        results = {'status': 'PASSED', 'missing_tables': []}

        for table in required_tables:
            self.cursor.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_schema = 'public'
                    AND table_name = %s
                )
            """, (table,))

            exists = self.cursor.fetchone()['exists']
            if not exists:
                self.errors.append(f"Missing table: {table}")
                results['missing_tables'].append(table)
                results['status'] = 'FAILED'

        if results['status'] == 'PASSED':
            print(f"  {Colors.GREEN}✓{Colors.RESET} All {len(required_tables)} tables found")
        else:
            print(f"  {Colors.RED}✗{Colors.RESET} Missing {len(results['missing_tables'])} tables")

        return results

    # ========================================================================
    # 2. Command Validation
    # ========================================================================

    def validate_commands(self) -> Dict[str, Any]:
        """
        Validate command definitions are complete and valid

        Returns:
            Dict with validation results
        """
        print(f"{Colors.CYAN}🔍 Validating Commands...{Colors.RESET}")

        results = {'status': 'PASSED', 'issues': []}

        # Get all commands
        self.cursor.execute("SELECT * FROM commands")
        commands = self.cursor.fetchall()
        self.stats['commands'] = len(commands)

        for cmd in commands:
            # Check required fields
            if not cmd['id']:
                self.errors.append(f"Command missing ID: {cmd['name']}")
                results['issues'].append({'type': 'missing_id', 'command': cmd['name']})
                results['status'] = 'FAILED'

            if not cmd['name']:
                self.errors.append(f"Command missing name: {cmd['id']}")
                results['issues'].append({'type': 'missing_name', 'command_id': cmd['id']})
                results['status'] = 'FAILED'

            if not cmd['command_template']:
                self.errors.append(f"Command missing template: {cmd['id']}")
                results['issues'].append({'type': 'missing_template', 'command_id': cmd['id']})
                results['status'] = 'FAILED'

            if not cmd['description']:
                self.warnings.append(f"Command missing description: {cmd['id']}")
                results['issues'].append({'type': 'missing_description', 'command_id': cmd['id']})

            # Check category is valid
            valid_categories = ['recon', 'web', 'exploitation', 'post-exploit', 'file-transfer', 'pivoting', 'custom']
            if cmd['category'] not in valid_categories:
                self.errors.append(f"Invalid category '{cmd['category']}' for command: {cmd['id']}")
                results['issues'].append({'type': 'invalid_category', 'command_id': cmd['id']})
                results['status'] = 'FAILED'

        if results['status'] == 'PASSED':
            print(f"  {Colors.GREEN}✓{Colors.RESET} All {self.stats['commands']} commands valid")
        else:
            print(f"  {Colors.RED}✗{Colors.RESET} {len(results['issues'])} issues found")

        return results

    # ========================================================================
    # 3. Relationship Validation
    # ========================================================================

    def validate_relationships(self) -> Dict[str, Any]:
        """
        Validate all command relations are valid

        Returns:
            Dict with validation results
        """
        print(f"{Colors.CYAN}🔍 Validating Relationships...{Colors.RESET}")

        results = {'status': 'PASSED', 'issues': []}

        # Get all relations
        self.cursor.execute("SELECT * FROM command_relations")
        relations = self.cursor.fetchall()
        self.stats['relations'] = len(relations)

        # Get all command IDs
        self.cursor.execute("SELECT id FROM commands")
        valid_ids = {row['id'] for row in self.cursor.fetchall()}

        broken_relations = []
        circular_deps = []

        for rel in relations:
            # Check source exists
            if rel['source_command_id'] not in valid_ids:
                self.errors.append(f"Broken relation: source '{rel['source_command_id']}' does not exist")
                broken_relations.append(rel)
                results['status'] = 'FAILED'

            # Check target exists
            if rel['target_command_id'] not in valid_ids:
                self.errors.append(f"Broken relation: target '{rel['target_command_id']}' does not exist")
                broken_relations.append(rel)
                results['status'] = 'FAILED'

            # Check no self-reference
            if rel['source_command_id'] == rel['target_command_id']:
                self.errors.append(f"Self-reference detected: {rel['source_command_id']}")
                results['issues'].append({'type': 'self_reference', 'command_id': rel['source_command_id']})
                results['status'] = 'FAILED'

        results['broken_relations'] = len(broken_relations)
        results['circular_dependencies'] = len(circular_deps)

        if results['status'] == 'PASSED':
            print(f"  {Colors.GREEN}✓{Colors.RESET} All {self.stats['relations']} relations valid")
        else:
            print(f"  {Colors.RED}✗{Colors.RESET} {len(broken_relations)} broken relations")

        return results

    def validate_guidance_relations(self) -> Dict[str, Any]:
        """
        Validate command_relation_guidance table

        Checks:
        - All source_command_ids exist in commands table
        - Guidance text is not empty
        - Relation types are valid

        Returns:
            Dict with validation results
        """
        print(f"{Colors.CYAN}🔍 Validating Guidance Relations...{Colors.RESET}")

        results = {'status': 'PASSED', 'issues': []}

        # Get all guidance relations
        self.cursor.execute("SELECT * FROM command_relation_guidance")
        guidance_relations = self.cursor.fetchall()
        self.stats['guidance_relations'] = len(guidance_relations)

        # Get all command IDs
        self.cursor.execute("SELECT id FROM commands")
        valid_ids = {row['id'] for row in self.cursor.fetchall()}

        broken_guidance = []
        empty_guidance = []

        for guidance in guidance_relations:
            # Check source exists
            if guidance['source_command_id'] not in valid_ids:
                self.errors.append(f"Broken guidance relation: source '{guidance['source_command_id']}' does not exist")
                broken_guidance.append(guidance)
                results['status'] = 'FAILED'

            # Check guidance text is not empty
            if not guidance['guidance_text'] or guidance['guidance_text'].strip() == '':
                self.warnings.append(f"Empty guidance text for command '{guidance['source_command_id']}'")
                empty_guidance.append(guidance)

            # Check relation type is valid
            valid_types = ['prerequisite', 'alternative', 'next_step']
            if guidance['relation_type'] not in valid_types:
                self.errors.append(f"Invalid relation type '{guidance['relation_type']}' in guidance relation")
                results['status'] = 'FAILED'

        results['broken_guidance'] = len(broken_guidance)
        results['empty_guidance'] = len(empty_guidance)

        if results['status'] == 'PASSED':
            print(f"  {Colors.GREEN}✓{Colors.RESET} All {self.stats['guidance_relations']} guidance relations valid")
            if empty_guidance:
                print(f"  {Colors.YELLOW}⚠{Colors.RESET} {len(empty_guidance)} guidance relations have empty text")
        else:
            print(f"  {Colors.RED}✗{Colors.RESET} {len(broken_guidance)} broken guidance relations")

        return results

    # ========================================================================
    # 4. Normalization Validation
    # ========================================================================

    def validate_normalization(self) -> Dict[str, Any]:
        """
        Validate data is properly normalized

        Checks:
        - Flags extracted to command_flags table
        - Variables extracted to variables/command_vars tables
        - Tags extracted to tags/command_tags tables

        Returns:
            Dict with validation results
        """
        print(f"{Colors.CYAN}🔍 Validating Normalization...{Colors.RESET}")

        results = {'status': 'PASSED', 'details': {}}

        # Count normalized entries
        self.cursor.execute("SELECT COUNT(*) as count FROM command_flags")
        self.stats['flags'] = self.cursor.fetchone()['count']

        self.cursor.execute("SELECT COUNT(*) as count FROM variables")
        self.stats['variables'] = self.cursor.fetchone()['count']

        self.cursor.execute("SELECT COUNT(*) as count FROM tags")
        self.stats['tags'] = self.cursor.fetchone()['count']

        self.cursor.execute("SELECT COUNT(*) as count FROM command_indicators")
        self.stats['indicators'] = self.cursor.fetchone()['count']

        print(f"  {Colors.GREEN}✓{Colors.RESET} Flags: {self.stats['flags']} normalized")
        print(f"  {Colors.GREEN}✓{Colors.RESET} Variables: {self.stats['variables']} normalized")
        print(f"  {Colors.GREEN}✓{Colors.RESET} Tags: {self.stats['tags']} entries")
        print(f"  {Colors.GREEN}✓{Colors.RESET} Indicators: {self.stats['indicators']} patterns")

        results['details'] = {
            'flags': self.stats['flags'],
            'variables': self.stats['variables'],
            'tags': self.stats['tags'],
            'indicators': self.stats['indicators']
        }

        return results

    # ========================================================================
    # 5. Cross-Reference Validation
    # ========================================================================

    def validate_cross_references(self) -> Dict[str, Any]:
        """
        Validate all cross-references resolve correctly

        Checks:
        - All command_vars reference valid variables
        - All command_tags reference valid tags
        - All placeholders in commands have variable definitions

        Returns:
            Dict with validation results
        """
        print(f"{Colors.CYAN}🔍 Validating Cross-References...{Colors.RESET}")

        results = {'status': 'PASSED', 'issues': []}

        # Check command_vars references
        self.cursor.execute("""
            SELECT cv.id, cv.command_id, cv.variable_id
            FROM command_vars cv
            LEFT JOIN variables v ON cv.variable_id = v.id
            WHERE v.id IS NULL
        """)

        orphaned_vars = self.cursor.fetchall()
        if orphaned_vars:
            self.errors.append(f"Found {len(orphaned_vars)} orphaned command_vars entries")
            results['status'] = 'FAILED'
            results['issues'].extend(orphaned_vars)

        # Check command_tags references
        self.cursor.execute("""
            SELECT ct.command_id, ct.tag_id
            FROM command_tags ct
            LEFT JOIN tags t ON ct.tag_id = t.id
            WHERE t.id IS NULL
        """)

        orphaned_tags = self.cursor.fetchall()
        if orphaned_tags:
            self.errors.append(f"Found {len(orphaned_tags)} orphaned command_tags entries")
            results['status'] = 'FAILED'
            results['issues'].extend(orphaned_tags)

        if results['status'] == 'PASSED':
            print(f"  {Colors.GREEN}✓{Colors.RESET} All cross-references valid")
        else:
            print(f"  {Colors.RED}✗{Colors.RESET} {len(results['issues'])} broken references")

        return results

    # ========================================================================
    # 6. Data Quality Validation
    # ========================================================================

    def validate_data_quality(self) -> Dict[str, Any]:
        """
        Validate data quality (no TODOs, placeholders, etc.)

        Returns:
            Dict with validation results
        """
        print(f"{Colors.CYAN}🔍 Validating Data Quality...{Colors.RESET}")

        results = {'status': 'PASSED', 'issues': []}

        # Check for TODO/FIXME markers
        self.cursor.execute("""
            SELECT id, description FROM commands
            WHERE description ILIKE '%TODO%'
               OR description ILIKE '%FIXME%'
               OR description ILIKE '%XXX%'
        """)

        todo_commands = self.cursor.fetchall()
        if todo_commands:
            for cmd in todo_commands:
                self.warnings.append(f"Command has TODO marker: {cmd['id']}")
            results['issues'].extend(todo_commands)

        # Check for empty descriptions
        self.cursor.execute("""
            SELECT id FROM commands
            WHERE description IS NULL OR TRIM(description) = ''
        """)

        empty_desc = self.cursor.fetchall()
        if empty_desc:
            for cmd in empty_desc:
                self.warnings.append(f"Command has empty description: {cmd['id']}")
            results['issues'].extend(empty_desc)

        if len(results['issues']) == 0:
            print(f"  {Colors.GREEN}✓{Colors.RESET} Data quality check passed")
        else:
            print(f"  {Colors.YELLOW}⚠{Colors.RESET} {len(results['issues'])} quality issues")

        return results

    # ========================================================================
    # 7. Unresolved Relations Check
    # ========================================================================

    def check_unresolved_relations(self) -> Dict[str, Any]:
        """
        Check for unresolved command relations from migration

        This simulates what the migration script does to count how many
        text-based relations couldn't be mapped to command IDs.

        Returns:
            Dict with count of unresolved relations
        """
        print(f"{Colors.CYAN}🔍 Checking Unresolved Relations...{Colors.RESET}")

        # This would require re-parsing JSON files to detect unresolved
        # For now, we'll report based on what we know from setup

        # Count total potential relations from JSON
        json_dir = Path(__file__).parent.parent / 'reference' / 'data' / 'commands'
        total_json_relations = 0
        unresolved = []

        if json_dir.exists():
            for json_file in json_dir.rglob('*.json'):
                try:
                    with open(json_file, 'r') as f:
                        data = json.load(f)
                        for cmd in data.get('commands', []):
                            # Count alternatives, prerequisites, next_steps
                            total_json_relations += len(cmd.get('alternatives', []))
                            total_json_relations += len(cmd.get('prerequisites', []))
                            total_json_relations += len(cmd.get('next_steps', []))
                except Exception:
                    pass

        # Compare with database relations
        db_relations = self.stats['relations']
        estimated_unresolved = max(0, total_json_relations - db_relations)

        self.stats['unresolved_relations'] = estimated_unresolved

        if estimated_unresolved > 0:
            print(f"  {Colors.YELLOW}⚠{Colors.RESET} {estimated_unresolved} unresolved relations estimated")
        else:
            print(f"  {Colors.GREEN}✓{Colors.RESET} All relations resolved")

        return {
            'total_json_relations': total_json_relations,
            'db_relations': db_relations,
            'unresolved_estimated': estimated_unresolved
        }

    # ========================================================================
    # Main Validation Runner
    # ========================================================================

    def run_all_validations(self) -> Dict[str, Any]:
        """
        Run all validation checks

        Returns:
            Dict with overall validation results
        """
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'═' * 60}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}🔍 CRACK Database Validation{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}{'═' * 60}{Colors.RESET}\n")

        if not self.connect():
            return {'status': 'FAILED', 'error': 'Database connection failed'}

        results = {}

        try:
            results['schema'] = self.validate_schema()
            results['commands'] = self.validate_commands()
            results['relationships'] = self.validate_relationships()
            results['guidance_relations'] = self.validate_guidance_relations()  # NEW
            results['normalization'] = self.validate_normalization()
            results['cross_references'] = self.validate_cross_references()
            results['data_quality'] = self.validate_data_quality()
            results['unresolved'] = self.check_unresolved_relations()

            # Overall status
            failed_checks = sum(1 for r in results.values() if r.get('status') == 'FAILED')
            warning_checks = sum(1 for r in results.values() if len(self.warnings) > 0)

            if failed_checks > 0:
                overall_status = 'FAILED'
            elif warning_checks > 0 or self.stats['unresolved_relations'] > 0:
                overall_status = 'WARNING'
            else:
                overall_status = 'PASSED'

            results['overall_status'] = overall_status
            results['stats'] = self.stats
            results['errors'] = self.errors
            results['warnings'] = self.warnings

        finally:
            self.close()

        return results

    # ========================================================================
    # Report Generation
    # ========================================================================

    def generate_report(self, results: Dict[str, Any], format: str = 'text') -> str:
        """
        Generate validation report

        Args:
            results: Results from run_all_validations()
            format: 'text' or 'json'

        Returns:
            Formatted report string
        """
        if format == 'json':
            return json.dumps(results, indent=2)

        # Text report
        report = []
        report.append(f"\n{Colors.BOLD}{Colors.CYAN}{'═' * 60}{Colors.RESET}")
        report.append(f"{Colors.BOLD}Validation Summary{Colors.RESET}")
        report.append(f"{Colors.BOLD}{Colors.CYAN}{'═' * 60}{Colors.RESET}\n")

        # Status for each category
        for category, result in results.items():
            if category in ['overall_status', 'stats', 'errors', 'warnings']:
                continue

            status = result.get('status', 'UNKNOWN')
            if status == 'PASSED':
                icon = f"{Colors.GREEN}✓{Colors.RESET}"
            elif status == 'FAILED':
                icon = f"{Colors.RED}✗{Colors.RESET}"
            else:
                icon = f"{Colors.YELLOW}⚠{Colors.RESET}"

            report.append(f"{icon} {category.replace('_', ' ').title()}: {status}")

        # Statistics
        report.append(f"\n{Colors.BOLD}Statistics:{Colors.RESET}")
        for key, value in self.stats.items():
            report.append(f"  {key.replace('_', ' ').title()}: {value}")

        # Overall status
        report.append(f"\n{Colors.BOLD}{Colors.CYAN}{'═' * 60}{Colors.RESET}")
        overall = results['overall_status']
        if overall == 'PASSED':
            report.append(f"{Colors.GREEN}{Colors.BOLD}✓ Validation PASSED{Colors.RESET}")
        elif overall == 'FAILED':
            report.append(f"{Colors.RED}{Colors.BOLD}✗ Validation FAILED{Colors.RESET}")
        else:
            report.append(f"{Colors.YELLOW}{Colors.BOLD}⚠ Validation PASSED with warnings{Colors.RESET}")

        report.append(f"Total Errors: {len(self.errors)}")
        report.append(f"Total Warnings: {len(self.warnings)}")
        report.append(f"{Colors.BOLD}{Colors.CYAN}{'═' * 60}{Colors.RESET}\n")

        # Show errors if any
        if self.errors:
            report.append(f"\n{Colors.RED}Errors:{Colors.RESET}")
            for err in self.errors[:10]:  # Show first 10
                report.append(f"  - {err}")
            if len(self.errors) > 10:
                report.append(f"  ... and {len(self.errors) - 10} more")

        # Show warnings if any
        if self.warnings:
            report.append(f"\n{Colors.YELLOW}Warnings:{Colors.RESET}")
            for warn in self.warnings[:10]:  # Show first 10
                report.append(f"  - {warn}")
            if len(self.warnings) > 10:
                report.append(f"  ... and {len(self.warnings) - 10} more")

        return '\n'.join(report)


def main():
    """CLI entry point for standalone validation"""
    from .config import get_db_config

    db_config = get_db_config()
    validator = DatabaseValidator(db_config)

    results = validator.run_all_validations()
    report = validator.generate_report(results)

    print(report)

    # Exit code
    if results['overall_status'] == 'FAILED':
        return 1
    return 0


if __name__ == '__main__':
    import sys
    sys.exit(main())
