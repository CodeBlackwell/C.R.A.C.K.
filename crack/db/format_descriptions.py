#!/usr/bin/env python3
"""
Format description fields in JSON command files for better readability.
Adds newlines between sentences and improves spacing.
Preserves all content exactly - formatting changes only.
"""

import json
import re
import sys
from pathlib import Path


def format_description(desc):
    """
    Format a description string for better readability.
    - Add newlines between sentences
    - Improve spacing around dashes and hyphens
    - Preserve exact content
    """
    if not desc or not isinstance(desc, str):
        return desc

    # Strip leading/trailing whitespace
    desc = desc.strip()

    # If already has newlines, it's likely already formatted
    if '\n' in desc:
        return desc

    # Check if we have multiple sentences by looking for ". " pattern
    # Avoid splitting on abbreviations like "e.g." or "i.e."
    # Split on ". " followed by a capital letter or end of string
    sentences = []
    current = ""

    i = 0
    while i < len(desc):
        current += desc[i]

        # Check if we're at a potential sentence boundary
        if desc[i] == '.' and i + 1 < len(desc):
            # Look ahead to see if this is a sentence boundary
            next_char = desc[i + 1]

            # Check for space followed by capital letter (new sentence)
            if next_char == ' ' and i + 2 < len(desc) and desc[i + 2].isupper():
                # Check if this might be an abbreviation
                # Look back for common abbreviations
                prev_chars = current[-4:] if len(current) >= 4 else current
                if not any(abbr in prev_chars.lower() for abbr in ['e.g', 'i.e', 'etc']):
                    # This is a sentence boundary
                    sentences.append(current.strip())
                    current = ""
                    i += 1  # Skip the space after period
        i += 1

    # Add the last sentence
    if current.strip():
        sentences.append(current.strip())

    # Join sentences with newlines if we have multiple sentences
    if len(sentences) > 1:
        return '\n'.join(sentences)

    # Single sentence - check for dash-separated clauses for longer descriptions
    if ' - ' in desc and len(desc) > 100:
        # Check if splitting on the dash would improve readability
        parts = desc.split(' - ', 1)
        if len(parts) == 2 and len(parts[0]) > 30:
            return ' - '.join(parts)  # Keep as is for now

    return desc


def process_json_file(filepath):
    """Process a JSON file and format all description fields."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            data = json.load(f)

        changes_made = False

        # Format file-level description
        if 'description' in data:
            original = data['description']
            formatted = format_description(original)
            if original != formatted:
                data['description'] = formatted
                changes_made = True

        # Format command-level descriptions
        if 'commands' in data and isinstance(data['commands'], list):
            for cmd in data['commands']:
                if 'description' in cmd:
                    original = cmd['description']
                    formatted = format_description(original)
                    if original != formatted:
                        cmd['description'] = formatted
                        changes_made = True

        # Write back if changes were made
        if changes_made:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return True, "Formatted"
        else:
            return False, "No changes needed"

    except json.JSONDecodeError as e:
        return False, f"JSON Error: {e}"
    except Exception as e:
        return False, f"Error: {e}"


def main():
    if len(sys.argv) < 2:
        print("Usage: python format_descriptions.py <file1.json> [file2.json ...]")
        sys.exit(1)

    files = sys.argv[1:]
    results = []

    for filepath in files:
        path = Path(filepath)
        if not path.exists():
            results.append((filepath, False, "File not found"))
            continue

        changed, message = process_json_file(filepath)
        results.append((filepath, changed, message))

    # Print results
    print("\n=== Formatting Results ===\n")
    for filepath, changed, message in results:
        status = "✓ MODIFIED" if changed else "○ UNCHANGED"
        print(f"{status}: {Path(filepath).name}")
        if message != "Formatted" and message != "No changes needed":
            print(f"  {message}")

    print(f"\n=== Summary ===")
    modified = sum(1 for _, changed, _ in results if changed)
    print(f"Files processed: {len(results)}")
    print(f"Files modified: {modified}")
    print(f"Files unchanged: {len(results) - modified}")


if __name__ == '__main__':
    main()
