#!/usr/bin/env python3
"""
Validate writeup JSON files against schema and cross-reference commands

Checks:
- JSON schema compliance
- Command ID references exist in commands database
- Phase names are valid
- Time estimates present
- CVE format correct
- OSCP relevance tags present
- Failed attempts have lesson_learned
"""

import json
import jsonschema
import sys
from pathlib import Path
from typing import List, Dict, Tuple, Set


# Valid phase names
VALID_PHASES = {'enumeration', 'foothold', 'lateral_movement', 'privilege_escalation', 'post_exploitation'}

# Valid difficulty levels
VALID_DIFFICULTIES = {'easy', 'medium', 'hard', 'insane'}

# Valid OS types
VALID_OS = {'linux', 'windows', 'other'}

# Valid OSCP relevance scores
VALID_OSCP_SCORES = {'high', 'medium', 'low'}


class WriteupValidator:
    """Validator for writeup JSON files"""

    def __init__(self, schema_file: str = None, commands_dir: str = None):
        """
        Initialize validator

        Args:
            schema_file: Path to writeup-schema.json
            commands_dir: Path to commands directory for cross-reference
        """
        self.schema = None
        self.known_commands = set()

        if schema_file:
            self.load_schema(schema_file)

        if commands_dir:
            self.load_commands(commands_dir)

    def load_schema(self, schema_file: str):
        """Load JSON schema for validation"""
        try:
            with open(schema_file, 'r') as f:
                self.schema = json.load(f)
        except Exception as e:
            print(f"ERROR: Could not load schema from {schema_file}: {e}")
            self.schema = None

    def load_commands(self, commands_dir: str):
        """Load all command IDs from commands directory"""
        commands_path = Path(commands_dir)

        if not commands_path.exists():
            print(f"WARNING: Commands directory not found: {commands_dir}")
            return

        for json_file in commands_path.rglob('*.json'):
            try:
                with open(json_file, 'r') as f:
                    data = json.load(f)

                    # Handle both single-command and multi-command JSON files
                    if 'commands' in data:
                        for cmd in data['commands']:
                            self.known_commands.add(cmd.get('id', ''))
                    elif 'id' in data:
                        self.known_commands.add(data['id'])

            except Exception as e:
                print(f"WARNING: Error loading {json_file}: {e}")

        print(f"Loaded {len(self.known_commands)} known command IDs")

    def validate_writeup(self, writeup_file: str) -> Tuple[bool, List[str]]:
        """
        Validate a writeup JSON file

        Returns:
            Tuple of (is_valid, list of errors/warnings)
        """
        errors = []

        try:
            with open(writeup_file, 'r') as f:
                writeup = json.load(f)
        except json.JSONDecodeError as e:
            return False, [f"JSON decode error: {e}"]
        except FileNotFoundError:
            return False, [f"File not found: {writeup_file}"]
        except Exception as e:
            return False, [f"Error loading file: {e}"]

        # Schema validation
        if self.schema:
            try:
                jsonschema.validate(instance=writeup, schema=self.schema)
            except jsonschema.ValidationError as e:
                errors.append(f"Schema validation failed: {e.message}")

        # Custom validations
        errors.extend(self._validate_structure(writeup))
        errors.extend(self._validate_phases(writeup))
        errors.extend(self._validate_commands(writeup))
        errors.extend(self._validate_cves(writeup))
        errors.extend(self._validate_oscp_tags(writeup))
        errors.extend(self._validate_failed_attempts(writeup))
        errors.extend(self._validate_time_estimates(writeup))

        is_valid = len(errors) == 0
        return is_valid, errors

    def _validate_structure(self, writeup: Dict) -> List[str]:
        """Validate basic writeup structure"""
        errors = []

        # Required top-level fields
        required = ['id', 'name', 'source', 'metadata', 'oscp_relevance', 'synopsis', 'skills', 'tags', 'attack_phases', 'time_breakdown']
        for field in required:
            if field not in writeup:
                errors.append(f"Missing required field: {field}")

        # Validate ID format (kebab-case)
        writeup_id = writeup.get('id', '')
        if writeup_id and not self._is_kebab_case(writeup_id):
            errors.append(f"ID must be kebab-case: {writeup_id}")

        # Validate difficulty
        difficulty = writeup.get('metadata', {}).get('difficulty', '')
        if difficulty and difficulty not in VALID_DIFFICULTIES:
            errors.append(f"Invalid difficulty: {difficulty} (must be one of {VALID_DIFFICULTIES})")

        # Validate OS
        os_type = writeup.get('metadata', {}).get('os', '')
        if os_type and os_type not in VALID_OS:
            errors.append(f"Invalid OS: {os_type} (must be one of {VALID_OS})")

        # Validate OSCP relevance score
        oscp_score = writeup.get('oscp_relevance', {}).get('score', '')
        if oscp_score and oscp_score not in VALID_OSCP_SCORES:
            errors.append(f"Invalid OSCP relevance score: {oscp_score} (must be one of {VALID_OSCP_SCORES})")

        return errors

    def _validate_phases(self, writeup: Dict) -> List[str]:
        """Validate attack phases"""
        errors = []

        phases = writeup.get('attack_phases', [])

        if not phases:
            errors.append("No attack phases defined")

        for i, phase in enumerate(phases):
            phase_name = phase.get('phase', '')

            if not phase_name:
                errors.append(f"Phase {i+1}: Missing phase name")
            elif phase_name not in VALID_PHASES:
                errors.append(f"Phase {i+1}: Invalid phase name '{phase_name}' (must be one of {VALID_PHASES})")

            # Check required phase fields
            if 'duration_minutes' not in phase:
                errors.append(f"Phase {i+1} ({phase_name}): Missing duration_minutes")

            if 'commands_used' not in phase:
                errors.append(f"Phase {i+1} ({phase_name}): Missing commands_used")

            if 'key_findings' not in phase:
                errors.append(f"Phase {i+1} ({phase_name}): Missing key_findings")

        return errors

    def _validate_commands(self, writeup: Dict) -> List[str]:
        """Validate command references"""
        errors = []

        if not self.known_commands:
            return errors  # Skip if commands not loaded

        phases = writeup.get('attack_phases', [])

        for phase in phases:
            phase_name = phase.get('phase', '')

            for cmd in phase.get('commands_used', []):
                command_id = cmd.get('command_id', '')

                if not command_id:
                    errors.append(f"Phase {phase_name}: Command missing ID")
                elif command_id not in self.known_commands:
                    errors.append(f"Phase {phase_name}: Unknown command ID '{command_id}'")

                # Check required command fields
                if 'context' not in cmd:
                    errors.append(f"Phase {phase_name}, Command {command_id}: Missing context")

                if 'step_number' not in cmd:
                    errors.append(f"Phase {phase_name}, Command {command_id}: Missing step_number")

                if 'success' not in cmd:
                    errors.append(f"Phase {phase_name}, Command {command_id}: Missing success field")

        return errors

    def _validate_cves(self, writeup: Dict) -> List[str]:
        """Validate CVE format"""
        errors = []

        phases = writeup.get('attack_phases', [])

        for phase in phases:
            phase_name = phase.get('phase', '')

            for vuln in phase.get('vulnerabilities', []):
                cve_id = vuln.get('cve')

                if cve_id and cve_id != 'null':
                    # Validate CVE format: CVE-YYYY-NNNNN
                    if not self._is_valid_cve(cve_id):
                        errors.append(f"Phase {phase_name}: Invalid CVE format '{cve_id}' (must be CVE-YYYY-NNNNN)")

        return errors

    def _validate_oscp_tags(self, writeup: Dict) -> List[str]:
        """Validate OSCP relevance tags present"""
        errors = []

        tags = writeup.get('tags', [])

        # Must have exactly one OSCP priority tag
        oscp_tags = [t for t in tags if t.startswith('OSCP:')]

        if not oscp_tags:
            errors.append("Missing OSCP priority tag (must include OSCP:HIGH, OSCP:MEDIUM, or OSCP:LOW)")
        elif len(oscp_tags) > 1:
            errors.append(f"Multiple OSCP priority tags found: {oscp_tags} (must have exactly one)")

        return errors

    def _validate_failed_attempts(self, writeup: Dict) -> List[str]:
        """Validate failed attempts have lesson_learned"""
        errors = []

        phases = writeup.get('attack_phases', [])

        for phase in phases:
            phase_name = phase.get('phase', '')

            for failed in phase.get('failed_attempts', []):
                if 'lesson_learned' not in failed:
                    errors.append(f"Phase {phase_name}: Failed attempt missing lesson_learned")
                elif len(failed.get('lesson_learned', '')) < 30:
                    errors.append(f"Phase {phase_name}: Failed attempt lesson_learned too short (min 30 chars)")

                # Check other required fields
                required = ['attempt', 'reason', 'solution']
                for field in required:
                    if field not in failed:
                        errors.append(f"Phase {phase_name}: Failed attempt missing {field}")

        return errors

    def _validate_time_estimates(self, writeup: Dict) -> List[str]:
        """Validate time breakdown"""
        errors = []

        time_breakdown = writeup.get('time_breakdown', {})

        if 'total_minutes' not in time_breakdown:
            errors.append("Missing total_minutes in time_breakdown")

        if 'flags_captured' not in time_breakdown:
            errors.append("Missing flags_captured in time_breakdown")

        # Validate phase durations present
        phases = writeup.get('attack_phases', [])
        for phase in phases:
            if 'duration_minutes' not in phase:
                errors.append(f"Phase {phase.get('phase', 'unknown')}: Missing duration_minutes")

        return errors

    @staticmethod
    def _is_kebab_case(text: str) -> bool:
        """Check if text is in kebab-case format"""
        import re
        return bool(re.match(r'^[a-z0-9]+(-[a-z0-9]+)*$', text))

    @staticmethod
    def _is_valid_cve(cve_id: str) -> bool:
        """Check if CVE ID format is valid"""
        import re
        return bool(re.match(r'^CVE-\d{4}-\d{4,7}$', cve_id))


def main():
    import argparse
    from collections import defaultdict

    parser = argparse.ArgumentParser(description="Validate writeup JSON files")
    parser.add_argument('writeup_file', help="Path to writeup JSON file to validate")
    parser.add_argument('--schema', default=None, help="Path to writeup-schema.json")
    parser.add_argument('--commands-dir', default=None, help="Path to commands directory for cross-reference")
    parser.add_argument('--summary', action='store_true', help="Show error summary grouped by type")
    parser.add_argument('--missing-only', action='store_true', help="Show only missing command IDs")

    args = parser.parse_args()

    # Default paths if not specified
    if not args.schema:
        script_dir = Path(__file__).parent
        args.schema = script_dir.parent / "data" / "writeups" / "writeup-schema.json"

    if not args.commands_dir:
        script_dir = Path(__file__).parent
        args.commands_dir = script_dir.parent.parent / "reference" / "data" / "commands"

    # Create validator
    validator = WriteupValidator(
        schema_file=str(args.schema) if Path(args.schema).exists() else None,
        commands_dir=str(args.commands_dir) if Path(args.commands_dir).exists() else None
    )

    # Validate writeup
    print(f"Validating: {args.writeup_file}")
    print()

    is_valid, errors = validator.validate_writeup(args.writeup_file)

    if is_valid:
        print("✓ Writeup is VALID")
        return 0
    else:
        # Group errors by type
        error_groups = defaultdict(list)
        for error in errors:
            if "Unknown command ID" in error:
                error_groups["Missing Command IDs"].append(error)
            elif "Missing" in error:
                error_groups["Missing Fields"].append(error)
            elif "Invalid" in error:
                error_groups["Invalid Values"].append(error)
            elif "lesson_learned" in error:
                error_groups["Failed Attempt Issues"].append(error)
            else:
                error_groups["Other"].append(error)

        # Show summary if requested
        if args.summary:
            print(f"✗ Writeup has {len(errors)} validation error(s):\n")
            for group, group_errors in error_groups.items():
                print(f"  {group} ({len(group_errors)}):")
                for error in group_errors[:5]:  # Show first 5 of each type
                    print(f"    - {error}")
                if len(group_errors) > 5:
                    print(f"    ... and {len(group_errors) - 5} more")
                print()
        elif args.missing_only:
            print(f"✗ Missing Command IDs ({len(error_groups['Missing Command IDs'])}):\n")
            # Extract unique command IDs
            missing_ids = set()
            for error in error_groups["Missing Command IDs"]:
                # Extract ID from error message like "Phase X: Unknown command ID 'foo-bar'"
                import re
                match = re.search(r"Unknown command ID '([^']+)'", error)
                if match:
                    missing_ids.add(match.group(1))

            for cmd_id in sorted(missing_ids):
                print(f"  - {cmd_id}")
        else:
            print(f"✗ Writeup has {len(errors)} validation error(s):")
            for i, error in enumerate(errors, 1):
                print(f"  {i}. {error}")

        return 1


if __name__ == '__main__':
    sys.exit(main())
