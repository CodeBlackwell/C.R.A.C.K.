#!/usr/bin/env python3
"""
Find the 1 missing command between JSON files (197) and database (196).

This script compares command IDs from all JSON files against the database
to identify which command failed to migrate.
"""

import json
import sys
from pathlib import Path
from typing import Set

# Add parent directory to path for imports
crack_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(crack_root))

# Import from db module directly
db_dir = crack_root / "db"
sys.path.insert(0, str(db_dir))

from config import get_db_config
import psycopg2


def get_json_command_ids() -> Set[str]:
    """Extract all command IDs from JSON files."""
    json_ids = set()
    json_dir = Path(__file__).parent.parent.parent / "reference" / "data" / "commands"

    print(f"Scanning JSON files in: {json_dir}")

    for json_file in json_dir.rglob("*.json"):
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)

            # Handle both single command and command list formats
            if 'commands' in data:
                for cmd in data['commands']:
                    json_ids.add(cmd['id'])
            elif 'id' in data:
                json_ids.add(data['id'])

            print(f"  ✓ {json_file.name}: {len(json_ids)} total commands so far")

        except Exception as e:
            print(f"  ✗ Error reading {json_file.name}: {e}")

    return json_ids


def get_database_command_ids() -> Set[str]:
    """Extract all command IDs from database."""
    try:
        config = get_db_config()
        conn = psycopg2.connect(**config)
        cursor = conn.cursor()

        cursor.execute('SELECT id FROM commands ORDER BY id;')
        db_ids = set(row[0] for row in cursor.fetchall())

        conn.close()

        print(f"\n✓ Database: {len(db_ids)} commands")
        return db_ids

    except Exception as e:
        print(f"✗ Database error: {e}")
        return set()


def main():
    """Find missing commands."""
    print("=" * 60)
    print("CRACK Database - Missing Command Finder")
    print("=" * 60)

    # Get command IDs from both sources
    json_ids = get_json_command_ids()
    print(f"\n✓ JSON files: {len(json_ids)} commands")

    db_ids = get_database_command_ids()

    # Find differences
    missing_from_db = json_ids - db_ids
    extra_in_db = db_ids - json_ids

    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)

    if missing_from_db:
        print(f"\n✗ {len(missing_from_db)} command(s) in JSON but NOT in database:")
        for cmd_id in sorted(missing_from_db):
            print(f"   - {cmd_id}")
    else:
        print("\n✓ All JSON commands are in database!")

    if extra_in_db:
        print(f"\n⚠ {len(extra_in_db)} command(s) in database but NOT in JSON:")
        for cmd_id in sorted(extra_in_db):
            print(f"   - {cmd_id}")
    else:
        print("\n✓ No extra commands in database!")

    # Summary
    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"JSON files:     {len(json_ids)} commands")
    print(f"Database:       {len(db_ids)} commands")
    print(f"Missing:        {len(missing_from_db)} commands")
    print(f"Extra:          {len(extra_in_db)} commands")
    print(f"Match:          {'✓ YES' if len(missing_from_db) == 0 and len(extra_in_db) == 0 else '✗ NO'}")
    print("=" * 60)


if __name__ == "__main__":
    main()
