#!/usr/bin/env python3
"""
Load writeup JSON files from data/writeups directory

Scans writeup directory structure and loads all writeup JSON files.
"""

import json
import os
from pathlib import Path
from typing import List, Dict, Tuple


def load_writeup_jsons(writeups_dir: str) -> Tuple[List[Dict], List[str]]:
    """
    Load all writeup JSON files from writeups directory structure

    Directory structure:
    writeups/
      hackthebox/
        Usage/
          Usage.json
        Stocker/
          Stocker.json
      proving_grounds/
        ...

    Args:
        writeups_dir: Path to writeups directory

    Returns:
        Tuple of (list of writeup dicts, list of error messages)
    """
    writeups = []
    errors = []

    if not os.path.exists(writeups_dir):
        errors.append(f"Writeups directory not found: {writeups_dir}")
        return writeups, errors

    writeups_path = Path(writeups_dir)

    # Scan platform directories (hackthebox, proving_grounds, tryhackme, etc.)
    for platform_dir in writeups_path.iterdir():
        if not platform_dir.is_dir():
            continue

        platform_name = platform_dir.name

        # Scan machine directories within platform
        for machine_dir in platform_dir.iterdir():
            if not machine_dir.is_dir():
                continue

            machine_name = machine_dir.name

            # Look for {machine_name}.json file
            json_file = machine_dir / f"{machine_name}.json"

            if not json_file.exists():
                # Also check for writeup.json or metadata.json as alternatives
                alternatives = [
                    machine_dir / "writeup.json",
                    machine_dir / "metadata.json"
                ]
                for alt_file in alternatives:
                    if alt_file.exists():
                        json_file = alt_file
                        break
                else:
                    # No JSON file found - skip
                    continue

            try:
                with open(json_file, 'r', encoding='utf-8') as f:
                    writeup = json.load(f)

                # Add source file information
                writeup['_source_file'] = str(json_file)
                writeup['_platform_dir'] = platform_name
                writeup['_machine_dir'] = machine_name

                # Basic validation
                required_fields = ['id', 'name', 'source', 'metadata', 'attack_phases']
                missing = [f for f in required_fields if f not in writeup]
                if missing:
                    errors.append(f"{json_file}: Missing required fields: {', '.join(missing)}")
                    continue

                writeups.append(writeup)

            except json.JSONDecodeError as e:
                errors.append(f"{json_file}: JSON decode error: {e}")
            except Exception as e:
                errors.append(f"{json_file}: Error loading: {e}")

    return writeups, errors


def load_single_writeup(json_file: str) -> Tuple[Dict, List[str]]:
    """
    Load a single writeup JSON file

    Args:
        json_file: Path to writeup JSON file

    Returns:
        Tuple of (writeup dict, list of error messages)
    """
    errors = []

    try:
        with open(json_file, 'r', encoding='utf-8') as f:
            writeup = json.load(f)

        writeup['_source_file'] = json_file

        # Basic validation
        required_fields = ['id', 'name', 'source', 'metadata', 'attack_phases']
        missing = [f for f in required_fields if f not in writeup]
        if missing:
            errors.append(f"Missing required fields: {', '.join(missing)}")
            return {}, errors

        return writeup, errors

    except json.JSONDecodeError as e:
        errors.append(f"JSON decode error: {e}")
        return {}, errors
    except FileNotFoundError:
        errors.append(f"File not found: {json_file}")
        return {}, errors
    except Exception as e:
        errors.append(f"Error loading: {e}")
        return {}, errors


if __name__ == '__main__':
    # Test loading
    import sys

    if len(sys.argv) > 1:
        writeups_dir = sys.argv[1]
    else:
        # Default path relative to script location
        script_dir = Path(__file__).parent
        writeups_dir = script_dir.parent.parent / "data" / "writeups"

    writeups, errors = load_writeup_jsons(str(writeups_dir))

    if errors:
        print(f"Errors loading writeups:")
        for err in errors:
            print(f"  ERROR: {err}")
        sys.exit(1)

    print(f"Loaded {len(writeups)} writeups:")
    for w in writeups:
        print(f"  {w['id']}: {w['name']} ({w['source']['platform']}) - {w['metadata']['difficulty']}")
