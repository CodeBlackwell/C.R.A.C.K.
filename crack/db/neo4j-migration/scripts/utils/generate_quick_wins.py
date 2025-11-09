#!/usr/bin/env python3
"""
Generate quick-win update files for Category A and D items.
"""

import json
from pathlib import Path
from collections import defaultdict

CATEGORIZED = Path("/home/kali/Desktop/OSCP/crack/db/neo4j-migration/data/FAILED_MAPPINGS_CATEGORIZED.json")
OUTPUT = Path("/home/kali/Desktop/OSCP/crack/db/neo4j-migration/data/QUICK_WIN_UPDATES.json")

def main():
    with open(CATEGORIZED) as f:
        data = json.load(f)

    # Group updates by file
    updates_by_file = defaultdict(list)

    # Process Category A (already exists)
    for item in data["categories"]["A"]:
        text = item["text"]
        new_id = item["metadata"]["match"]
        score = item["metadata"]["score"]

        for occurrence in item["occurrences"]:
            file_path = occurrence["file"]
            updates_by_file[file_path].append({
                "command_id": occurrence["command_id"],
                "field": occurrence["field"],
                "old_text": text,
                "new_id": new_id,
                "confidence": "high" if score >= 0.9 else "medium",
                "score": score,
                "category": "A",
                "reason": f"Command exists in index (score: {score:.2f})"
            })

    # Process Category D (fuzzy match)
    for item in data["categories"]["D"]:
        text = item["text"]
        new_id = item["metadata"]["match"]
        score = item["metadata"]["score"]

        for occurrence in item["occurrences"]:
            file_path = occurrence["file"]
            updates_by_file[file_path].append({
                "command_id": occurrence["command_id"],
                "field": occurrence["field"],
                "old_text": text,
                "new_id": new_id,
                "confidence": "medium" if score >= 0.6 else "low",
                "score": score,
                "category": "D",
                "reason": f"Fuzzy match to existing command (score: {score:.2f})"
            })

    # Convert to list format
    updates = []
    for file_path, file_updates in updates_by_file.items():
        updates.append({
            "file": file_path,
            "update_count": len(file_updates),
            "updates": file_updates
        })

    # Sort by update count (descending)
    updates.sort(key=lambda x: x["update_count"], reverse=True)

    output_data = {
        "summary": {
            "total_files": len(updates),
            "total_updates": sum(u["update_count"] for u in updates),
            "high_confidence": sum(1 for f in updates for u in f["updates"] if u["confidence"] == "high"),
            "medium_confidence": sum(1 for f in updates for u in f["updates"] if u["confidence"] == "medium"),
            "low_confidence": sum(1 for f in updates for u in f["updates"] if u["confidence"] == "low"),
        },
        "files": updates
    }

    with open(OUTPUT, "w") as f:
        json.dump(output_data, f, indent=2)

    print(f"Quick-win updates generated: {OUTPUT}")
    print(f"\nSummary:")
    print(f"  Total files:         {output_data['summary']['total_files']}")
    print(f"  Total updates:       {output_data['summary']['total_updates']}")
    print(f"  High confidence:     {output_data['summary']['high_confidence']}")
    print(f"  Medium confidence:   {output_data['summary']['medium_confidence']}")
    print(f"  Low confidence:      {output_data['summary']['low_confidence']}")

    print(f"\nTop 10 files with most updates:")
    for i, file_data in enumerate(updates[:10], 1):
        print(f"  {i:2d}. {file_data['file']}: {file_data['update_count']} updates")

if __name__ == "__main__":
    main()
