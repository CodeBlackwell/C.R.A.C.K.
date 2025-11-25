#!/usr/bin/env python3
"""
Convert old-format cheatsheet files (single object) to new format (cheatsheets array).

Old format:
{
  "id": "...",
  "name": "...",
  ...
}

New format:
{
  "cheatsheets": [
    {
      "id": "...",
      "name": "...",
      ...
    }
  ]
}
"""

import json
import sys
from pathlib import Path

def convert_file(filepath: Path) -> bool:
    """Convert a single file from old format to new format."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # Check if already in new format
        if 'cheatsheets' in data and isinstance(data['cheatsheets'], list):
            print(f"✓ Already in new format: {filepath}")
            return False

        # Check if it's a valid old-format cheatsheet (has required fields)
        if not all(k in data for k in ['id', 'name', 'description']):
            print(f"✗ Invalid format (missing required fields): {filepath}")
            return False

        # Convert to new format
        new_data = {
            "cheatsheets": [data]
        }

        # Write back to file
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(new_data, f, indent=2, ensure_ascii=False)
            f.write('\n')  # Add trailing newline

        print(f"✓ Converted: {filepath}")
        return True

    except json.JSONDecodeError as e:
        print(f"✗ Invalid JSON: {filepath} - {e}")
        return False
    except Exception as e:
        print(f"✗ Error processing {filepath}: {e}")
        return False

def main():
    base_path = Path('/home/kali/Desktop/OSCP/crack/db/data/cheatsheets')

    if not base_path.exists():
        print(f"Error: Directory not found: {base_path}")
        sys.exit(1)

    # Find all JSON files
    json_files = list(base_path.rglob('*.json'))

    print(f"Found {len(json_files)} JSON files\n")

    converted = 0
    already_converted = 0
    errors = 0

    for filepath in sorted(json_files):
        result = convert_file(filepath)
        if result is True:
            converted += 1
        elif result is False:
            already_converted += 1
        else:
            errors += 1

    print(f"\n{'='*60}")
    print(f"Summary:")
    print(f"  Converted: {converted}")
    print(f"  Already in new format: {already_converted}")
    print(f"  Errors: {errors}")
    print(f"  Total: {len(json_files)}")

if __name__ == '__main__':
    main()
