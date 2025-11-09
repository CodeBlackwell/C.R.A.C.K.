#!/usr/bin/env python3
"""
Categorize failed mappings into actionable categories.

Categories:
A - Already Exists (Quick Fix): Command exists in index, just needs ID update
B - Create Simple Command: Clear executable command that should be created
C - Not a Command (Remove): Instruction text, notes, state conditions
D - Fuzzy Match (Update): Close to existing command, update to exact ID
E - Context-Dependent (Manual Review): Needs source file context
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Tuple

# Load mapping report and command index
MAPPING_REPORT = Path("/home/kali/Desktop/OSCP/crack/db/neo4j-migration/data/mapping_report.json")
COMMAND_INDEX = Path("/home/kali/Desktop/OSCP/crack/db/neo4j-migration/data/command_index.json")

def load_json(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)

def get_all_command_ids(index: dict) -> set:
    """Extract all command IDs from index."""
    # Command index has IDs as keys
    return set(index.keys())

def normalize_text(text: str) -> str:
    """Normalize text for fuzzy matching."""
    return text.lower().strip().replace("-", " ").replace("_", " ")

def is_state_condition(text: str) -> bool:
    """Check if text is a state condition (not a command)."""
    state_patterns = [
        r"^[A-Z].*\binstalled\b",
        r"^[A-Z].*\brunning\b",
        r"^[A-Z].*\bavailable\b",
        r"^[A-Z].*\bobtained\b",
        r"^[A-Z].*\benabled\b",
        r"^[A-Z].*\bopen\b",
        r"^[A-Z].*\bextracted\b",
        r"^[A-Z].*\bidentified\b",
        r"^[A-Z].*\bexecuted\b",
        r"^[A-Z].*\bconnection\b",
        r"^[A-Z].*\baccess\b",
        r"^[A-Z].*\bpermission\b",
        r"^\w+\sservice\b",
        r"^(default|Default)",
        r"^(port|Port)\s+\d+",
        r"^NTLM hash",
        r"^Kerberos ticket",
        r"^\.kirbi\s",
    ]
    return any(re.match(pattern, text) for pattern in state_patterns)

def is_instruction(text: str) -> bool:
    """Check if text is an instruction (not a command)."""
    instruction_patterns = [
        r"^Check\s",
        r"^Verify\s",
        r"^Test\s",
        r"^Identify\s",
        r"^Find\s",
        r"^Search\s",
        r"^Note\s",
        r"^Manual\s",
        r"^Use\s(?!mimikatz|docker|pspy)",  # "Use X" is instruction unless specific tool
        r"^Download from:",
        r"^# ",  # Comments
        r"^Capture\s",
        r"^Copy\s",
        r"^Update\s",
        r"^Upload\s",
        r"^Transfer\s(?!LinEnum|PowerUp|Seatbelt|pspy|linpeas)",  # Generic transfer instruction
        r"^Start\s",
        r"^Run\s(directly|gobuster|first)",
        r"GTFOBins technique",
    ]
    return any(re.match(pattern, text) for pattern in instruction_patterns)

def is_file_reference(text: str) -> bool:
    """Check if text is a file reference."""
    return bool(re.match(r"^\.\w+\s+.*file$", text))

def is_powershell_cmdlet_instruction(text: str) -> bool:
    """Check if text is a PowerShell cmdlet used as instruction (not executable command)."""
    # These are PowerShell cmdlets used in prerequisites/alternatives but not standalone commands
    cmdlets = [
        r"^Get-ADGroup\s+-Filter\s+\*$",
        r"^Get-ADUser\s+\$env:USERNAME$",
        r"^Get-ADUser\s+-Filter\s+\*$",
        r"^Get-Acl$",
        r"^Get-Acl\s+HKLM:",
        r"^Get-Acl\s+in\s+PowerShell$",
        r"^Get-CimInstance\s+win32_process$",
        r"^Get-ItemProperty\s+for\s+PowerShell$",
        r"^Get-ItemProperty\s+\"?HKLM:",
        r"^Get-NetGroup$",
        r"^Get-NetUser\s+-AdminCount$",
        r"^Get-Process\s+",
        r"^Get-ScheduledTask",
    ]
    return any(re.match(pattern, text) for pattern in cmdlets)

def find_fuzzy_match(text: str, command_ids: set) -> Tuple[str, float]:
    """Find fuzzy match in command IDs."""
    norm_text = normalize_text(text)
    text_words = set(norm_text.split())

    # Skip if too short or generic
    if len(norm_text) < 3 or not text_words:
        return None, 0.0

    # Filter out very short/generic command IDs for matching
    valid_ids = {
        cmd_id for cmd_id in command_ids
        if len(cmd_id) >= 3 and cmd_id not in {
            'ss', 'w', 'id', 'ps', 'ls', 'cd', 'cp', 'mv', 'rm', 'ln',
            'at', 'nc', 'dd', 'du', 'df', 'od', 'wc', 'tr', 'vi', 'awk',
            'sed', 'tar', 'zip', 'ftp', 'ssh', 'dig', 'rpc', 'smb',
            'http', 'dns', 'tcp', 'udp', 'ip', 'ad'
        }
    }

    best_match = None
    best_score = 0.0

    for cmd_id in valid_ids:
        norm_id = normalize_text(cmd_id)
        id_words = set(norm_id.split())

        # Direct exact word match (high confidence)
        if text_words == id_words:
            return cmd_id, 1.0

        # Substring match (only if substantial)
        if len(norm_text) >= 5 and len(norm_id) >= 5:
            if norm_text in norm_id:
                score = len(norm_text) / len(norm_id)
                if score >= 0.7:
                    return cmd_id, 0.9
            if norm_id in norm_text:
                score = len(norm_id) / len(norm_text)
                if score >= 0.7:
                    return cmd_id, 0.9

        # Word overlap (must have significant overlap)
        overlap = text_words & id_words
        if overlap:
            # Calculate Jaccard similarity
            union = text_words | id_words
            jaccard = len(overlap) / len(union)

            # Require at least 2 word overlap or high Jaccard
            if len(overlap) >= 2 or jaccard >= 0.6:
                if jaccard > best_score:
                    best_score = jaccard
                    best_match = cmd_id

    if best_score >= 0.5:
        return best_match, best_score

    return None, 0.0

def categorize_failed_mapping(text: str, command_ids: set) -> Tuple[str, str, dict]:
    """
    Categorize a failed mapping.

    Returns: (category, reason, metadata)
    """
    # Category C: Not a command
    if is_state_condition(text):
        return "C", "State condition - not a command", {"type": "state_condition"}

    if is_instruction(text):
        return "C", "Instruction text - not a command", {"type": "instruction"}

    if is_file_reference(text):
        return "C", "File reference - not a command", {"type": "file_reference"}

    if is_powershell_cmdlet_instruction(text):
        return "C", "PowerShell cmdlet used as instruction", {"type": "ps_instruction"}

    # Category A/D: Fuzzy match
    match, score = find_fuzzy_match(text, command_ids)
    if match:
        if score >= 0.7:
            return "A", f"Already exists as '{match}'", {"match": match, "score": score}
        else:
            return "D", f"Fuzzy match to '{match}'", {"match": match, "score": score}

    # Category B: Potential command to create
    # Check if it looks like an executable command
    if re.match(r"^[a-z0-9_-]+(\s+|$)", text) and not text.startswith(("Get-", "Set-", "New-")):
        return "B", "Potential command to create", {"type": "command_candidate"}

    # Category E: Needs manual review
    return "E", "Needs manual context review", {"type": "ambiguous"}

def main():
    print("Loading data...")
    mapping_report = load_json(MAPPING_REPORT)
    command_index = load_json(COMMAND_INDEX)

    command_ids = get_all_command_ids(command_index)
    print(f"Found {len(command_ids)} command IDs in index")

    failed_mappings = mapping_report["failed_mappings"]
    print(f"Analyzing {len(failed_mappings)} failed mappings...")

    # Get unique failed values
    unique_values = {}
    for failure in failed_mappings:
        text = failure["old_value"]
        if text not in unique_values:
            unique_values[text] = {
                "text": text,
                "occurrences": [],
            }
        unique_values[text]["occurrences"].append({
            "file": failure["file"],
            "command_id": failure["command_id"],
            "field": failure["field"],
        })

    print(f"Found {len(unique_values)} unique failed values")

    # Categorize each
    categorized = {
        "A": [],  # Already exists
        "B": [],  # Create command
        "C": [],  # Remove
        "D": [],  # Fuzzy match
        "E": [],  # Manual review
    }

    for text, data in unique_values.items():
        category, reason, metadata = categorize_failed_mapping(text, command_ids)
        categorized[category].append({
            "text": text,
            "reason": reason,
            "metadata": metadata,
            "occurrences": data["occurrences"],
            "count": len(data["occurrences"]),
        })

    # Generate report
    output = {
        "summary": {
            "total_unique_values": len(unique_values),
            "total_failures": len(failed_mappings),
            "categories": {
                "A_already_exists": len(categorized["A"]),
                "B_create_command": len(categorized["B"]),
                "C_remove_not_command": len(categorized["C"]),
                "D_fuzzy_match": len(categorized["D"]),
                "E_manual_review": len(categorized["E"]),
            }
        },
        "categories": categorized,
    }

    # Save full report
    output_path = Path("/home/kali/Desktop/OSCP/crack/db/neo4j-migration/data/FAILED_MAPPINGS_CATEGORIZED.json")
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nCategorization complete!")
    print(f"\nSummary:")
    print(f"  Category A (Already Exists):      {len(categorized['A']):3d} items ({len([i for c in categorized['A'] for i in c['occurrences']]):3d} occurrences)")
    print(f"  Category B (Create Command):      {len(categorized['B']):3d} items ({len([i for c in categorized['B'] for i in c['occurrences']]):3d} occurrences)")
    print(f"  Category C (Remove - Not Cmd):    {len(categorized['C']):3d} items ({len([i for c in categorized['C'] for i in c['occurrences']]):3d} occurrences)")
    print(f"  Category D (Fuzzy Match):         {len(categorized['D']):3d} items ({len([i for c in categorized['D'] for i in c['occurrences']]):3d} occurrences)")
    print(f"  Category E (Manual Review):       {len(categorized['E']):3d} items ({len([i for c in categorized['E'] for i in c['occurrences']]):3d} occurrences)")
    print(f"\nFull report: {output_path}")

    # Show quick-win opportunities (Category A + D)
    quick_wins = len(categorized["A"]) + len(categorized["D"])
    quick_win_occurrences = (
        len([i for c in categorized["A"] for i in c["occurrences"]]) +
        len([i for c in categorized["D"] for i in c["occurrences"]])
    )
    print(f"\nQuick-Win Opportunities: {quick_wins} items ({quick_win_occurrences} occurrences)")

    # Estimate new mapping success rate
    stats = mapping_report.get("stats", {})
    current_successes = len(mapping_report.get("successful_mappings", []))
    total_mappings = current_successes + len(failed_mappings)
    current_success = (current_successes / total_mappings * 100) if total_mappings > 0 else 0

    # If we fix Category A+D and remove Category C
    removals = len([i for c in categorized["C"] for i in c["occurrences"]])
    new_total = total_mappings - removals
    new_successes = current_successes + quick_win_occurrences
    estimated_rate = (new_successes / new_total * 100) if new_total > 0 else 0

    print(f"\nEstimated Impact if Quick-Wins Applied:")
    print(f"  Current:   {current_success:.1f}% ({current_successes}/{total_mappings})")
    print(f"  After A+D: {estimated_rate:.1f}% ({new_successes}/{new_total})")
    print(f"  Gain:      +{estimated_rate - current_success:.1f}%")

if __name__ == "__main__":
    main()
