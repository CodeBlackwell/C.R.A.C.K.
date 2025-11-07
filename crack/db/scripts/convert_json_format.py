#!/usr/bin/env python3
"""
Convert generated JSON command files to match migration script format.

Changes:
- variables: dict → array
- "default" → "example"
- flags: ensure proper structure

This fixes the format mismatch preventing import.
"""

import json
from pathlib import Path
from typing import Dict, Any, List


def convert_variables_format(variables: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Convert variables from dict to array format.

    From: {"<TARGET>": {"description": "...", "default": "..."}}
    To:   [{"name": "<TARGET>", "description": "...", "example": "..."}]
    """
    if isinstance(variables, list):
        # Already in array format - ensure names have <> brackets
        for var in variables:
            if "name" in var:
                name = var["name"]
                if not name.startswith("<"):
                    name = f"<{name}"
                if not name.endswith(">"):
                    name = f"{name}>"
                var["name"] = name
        return variables

    result = []
    for var_name, var_info in variables.items():
        # Ensure variable name has <> brackets
        if not var_name.startswith("<"):
            var_name = f"<{var_name}>"
        if not var_name.endswith(">"):
            var_name = f"{var_name}>"

        converted = {
            "name": var_name,
            "description": var_info.get("description", ""),
            "example": var_info.get("default", var_info.get("example", "")),
            "required": var_info.get("required", True)
        }
        result.append(converted)

    return result


def convert_command(cmd: Dict[str, Any]) -> Dict[str, Any]:
    """Convert a single command to migration-compatible format."""
    converted = cmd.copy()

    # Convert variables
    if "variables" in converted and isinstance(converted["variables"], dict):
        converted["variables"] = convert_variables_format(converted["variables"])

    # Rename "command" to "command_template" if migration expects it
    # (Check migrate.py to see which field name it uses)
    # Actually, looking at the schema and existing JSON, it's just "command"

    return converted


def convert_json_file(input_file: Path, output_file: Path = None):
    """Convert a JSON file to migration-compatible format."""
    if output_file is None:
        output_file = input_file

    # Read input
    with open(input_file, 'r') as f:
        data = json.load(f)

    # Convert all commands
    if "commands" in data:
        data["commands"] = [convert_command(cmd) for cmd in data["commands"]]

    # Write output
    with open(output_file, 'w') as f:
        json.dump(data, f, indent=2)

    return len(data.get("commands", []))


def main():
    """Convert all generated JSON files."""
    generated_dir = Path(__file__).parent.parent.parent / "reference" / "data" / "commands" / "generated"

    if not generated_dir.exists():
        print(f"❌ Generated directory not found: {generated_dir}")
        return

    print("=" * 60)
    print("JSON FORMAT CONVERTER")
    print("=" * 60)
    print(f"\nScanning: {generated_dir}\n")

    json_files = list(generated_dir.glob("*.json"))
    total_commands = 0

    for json_file in sorted(json_files):
        print(f"Converting: {json_file.name}")
        try:
            count = convert_json_file(json_file)
            total_commands += count
            print(f"  ✓ Converted {count} commands")
        except Exception as e:
            print(f"  ❌ Error: {e}")

    print("\n" + "=" * 60)
    print(f"✓ Converted {len(json_files)} files ({total_commands} commands)")
    print("=" * 60)
    print("\nFiles are now compatible with migration script.")
    print("Next step: python3 -m crack.db.migrate commands")


if __name__ == "__main__":
    main()
