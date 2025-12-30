#!/usr/bin/env python3
"""Sync chain JSON id fields to match their filenames."""

import json
from pathlib import Path

CHAINS_DIR = Path(__file__).parent.parent / "data" / "chains"

def sync_ids():
    fixed = 0
    for json_file in CHAINS_DIR.rglob("*.json"):
        if json_file.name == "metadata.json":
            continue

        expected_id = json_file.stem  # filename without .json

        with open(json_file) as f:
            data = json.load(f)

        current_id = data.get("id")
        if current_id != expected_id:
            print(f"FIX: {json_file.name}")
            print(f"     {current_id} → {expected_id}")
            data["id"] = expected_id

            with open(json_file, "w") as f:
                json.dump(data, f, indent=2)
            fixed += 1

    print(f"\nFixed {fixed} files")

if __name__ == "__main__":
    sync_ids()
