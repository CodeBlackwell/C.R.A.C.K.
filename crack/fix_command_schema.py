#!/usr/bin/env python3
"""
Fix AV Evasion Command Schema Violations

Transforms command JSON files to comply with Command dataclass schema:
1. Convert variables from dict to list format
2. Remove unsupported fields (syntax, examples, flags, etc.)
3. Map unsupported fields to schema-compliant alternatives
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Any


def transform_variables(variables: Any) -> List[Dict[str, Any]]:
    """
    Transform variables from dict to list format.

    From: {"<VAR>": {"description": "...", "example": "..."}}
    To: [{"name": "<VAR>", "description": "...", "example": "..."}]
    """
    if isinstance(variables, list):
        # Already in correct format
        for var in variables:
            # Fix 'default' → 'example' if present
            if 'default' in var and 'example' not in var:
                var['example'] = var.pop('default')
        return variables

    if isinstance(variables, dict):
        # Transform dict to list
        result = []
        for var_name, var_data in variables.items():
            if isinstance(var_data, dict):
                # Create new variable object
                var_obj = {
                    "name": var_name,
                    "description": var_data.get("description", ""),
                    "example": var_data.get("example", var_data.get("default", "")),
                    "required": var_data.get("required", True)
                }
                result.append(var_obj)
        return result

    return []


def relocate_unsupported_fields(command: Dict[str, Any]) -> Dict[str, Any]:
    """
    Remove unsupported fields and integrate content into schema-compliant fields.

    Unsupported fields:
    - syntax → notes
    - examples → remove (redundant with command template)
    - flags → remove (use flag_explanations)
    - manual_alternative → alternatives
    - expected_output → success_indicators
    - common_failures → failure_indicators
    - oscp_notes, time_estimate, references → notes
    """
    notes_parts = []

    # Collect content for notes field
    if 'syntax' in command:
        notes_parts.append(f"Syntax: {command.pop('syntax')}")

    if 'oscp_notes' in command:
        notes_parts.append(command.pop('oscp_notes'))

    if 'time_estimate' in command:
        notes_parts.append(f"Time estimate: {command.pop('time_estimate')}")

    if 'references' in command:
        refs = command.pop('references')
        if refs:
            if isinstance(refs, list):
                notes_parts.append(f"References: {', '.join(refs)}")
            else:
                notes_parts.append(f"References: {refs}")

    # Combine into notes field
    if notes_parts:
        existing_notes = command.get('notes', '')
        if existing_notes:
            notes_parts.insert(0, existing_notes)
        command['notes'] = ' '.join(notes_parts)

    # Map manual_alternative → alternatives
    if 'manual_alternative' in command:
        manual_alt = command.pop('manual_alternative')
        if manual_alt and not command.get('alternatives'):
            # Store as notes since it's usually descriptive text, not command IDs
            alt_note = f"Manual alternative: {manual_alt}"
            if 'notes' in command:
                command['notes'] = f"{command['notes']} {alt_note}"
            else:
                command['notes'] = alt_note

    # Map expected_output → success_indicators
    if 'expected_output' in command:
        output = command.pop('expected_output')
        if output and not command.get('success_indicators'):
            command['success_indicators'] = [output] if isinstance(output, str) else output

    # Map common_failures → failure_indicators
    if 'common_failures' in command:
        failures = command.pop('common_failures')
        if failures and not command.get('failure_indicators'):
            if isinstance(failures, list):
                command['failure_indicators'] = failures
            elif isinstance(failures, str):
                command['failure_indicators'] = [failures]

    # Remove truly redundant fields
    for field in ['examples', 'flags']:
        command.pop(field, None)

    return command


def fix_command_file(file_path: Path) -> Dict[str, Any]:
    """
    Fix a single command JSON file.

    Returns dict with:
    - success: bool
    - commands_fixed: int
    - errors: List[str]
    """
    result = {
        'success': False,
        'commands_fixed': 0,
        'errors': []
    }

    try:
        # Read JSON file
        with open(file_path, 'r') as f:
            data = json.load(f)

        if 'commands' not in data:
            result['errors'].append("No 'commands' array found")
            return result

        # Process each command
        for command in data['commands']:
            try:
                # Fix variables format
                if 'variables' in command:
                    command['variables'] = transform_variables(command['variables'])

                # Relocate unsupported fields
                command = relocate_unsupported_fields(command)

                result['commands_fixed'] += 1
            except Exception as e:
                result['errors'].append(f"Error processing command {command.get('id', 'unknown')}: {e}")

        # Write fixed JSON
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        result['success'] = True
        return result

    except json.JSONDecodeError as e:
        result['errors'].append(f"JSON decode error: {e}")
        return result
    except Exception as e:
        result['errors'].append(f"Unexpected error: {e}")
        return result


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 fix_command_schema.py <file1.json> [file2.json ...]")
        print("\nOr fix all AV evasion files:")
        print("  python3 fix_command_schema.py reference/data/commands/av-evasion/*.json")
        sys.exit(1)

    files = [Path(f) for f in sys.argv[1:]]

    print("=" * 70)
    print("COMMAND SCHEMA FIX TOOL")
    print("=" * 70)
    print()

    total_files = len(files)
    total_commands = 0
    successful_files = 0

    for file_path in files:
        if not file_path.exists():
            print(f"❌ {file_path.name}: File not found")
            continue

        print(f"Processing: {file_path.name}")
        result = fix_command_file(file_path)

        if result['success']:
            print(f"  ✓ Fixed {result['commands_fixed']} commands")
            total_commands += result['commands_fixed']
            successful_files += 1
        else:
            print(f"  ❌ Failed")
            for error in result['errors']:
                print(f"     Error: {error}")
        print()

    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Files processed: {successful_files}/{total_files}")
    print(f"Commands fixed: {total_commands}")
    print()

    if successful_files == total_files:
        print("✓ ALL FILES FIXED SUCCESSFULLY")
        sys.exit(0)
    else:
        print("❌ SOME FILES FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()
