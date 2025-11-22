#!/usr/bin/env python3
"""
Semi-Automated Writeup Image Enrichment Tool

Uses image_metadata.json (from extract_htb_pdf_enhanced.py) to automatically
insert screenshot references into writeup JSON files.

Features:
- Automatic insertion for high-confidence correlations
- Manual review tagging for medium/low confidence
- Preserves existing JSON structure
- Generates enriched JSON for review

Usage:
    python3 enrich_writeup_with_images.py --target Usage [--confidence-threshold high]
"""

import json
import argparse
import sys
from pathlib import Path
from typing import Dict, List
from difflib import SequenceMatcher


class WriteupImageEnricher:
    """Enrich writeup JSON with screenshot references from metadata"""

    def __init__(self, confidence_threshold: str = "medium"):
        self.confidence_threshold = confidence_threshold
        self.confidence_levels = {"high": 3, "medium": 2, "low": 1}
        self.min_confidence = self.confidence_levels.get(confidence_threshold, 2)

    def similarity_ratio(self, str1: str, str2: str) -> float:
        """Calculate string similarity (0.0 to 1.0)"""
        return SequenceMatcher(None, str1.lower(), str2.lower()).ratio()

    def find_matching_command(
        self,
        image_meta: Dict,
        commands: List[Dict]
    ) -> tuple[Dict | None, float]:
        """
        Find command that best matches image metadata

        Returns:
            (command_dict, match_score) or (None, 0.0)
        """
        best_match = None
        best_score = 0.0

        nearest_text = image_meta.get("nearest_text_above") or image_meta.get("nearest_command_above")

        if not nearest_text:
            return None, 0.0

        for command in commands:
            # Check context field (most likely to match)
            context_score = self.similarity_ratio(nearest_text, command.get("context", ""))

            # Check command_executed field
            cmd_score = self.similarity_ratio(nearest_text, command.get("command_executed", ""))

            # Check notes field
            notes_score = self.similarity_ratio(nearest_text, command.get("notes", ""))

            # Take highest score
            max_score = max(context_score, cmd_score, notes_score)

            if max_score > best_score:
                best_score = max_score
                best_match = command

        return best_match, best_score

    def enrich_writeup(
        self,
        writeup: Dict,
        image_metadata: Dict
    ) -> tuple[Dict, Dict]:
        """
        Enrich writeup with screenshot references

        Returns:
            (enriched_writeup, stats_dict)
        """
        stats = {
            "total_images": image_metadata["total_images"],
            "high_confidence_added": 0,
            "medium_confidence_added": 0,
            "low_confidence_skipped": 0,
            "manual_review_needed": []
        }

        correlations = image_metadata["image_correlations"]

        # Process each attack phase
        for phase in writeup.get("attack_phases", []):
            phase_name = phase["phase"]
            commands = phase["commands_used"]

            for correlation in correlations:
                confidence = correlation["confidence"]
                confidence_val = self.confidence_levels.get(confidence, 1)

                # Skip low confidence unless explicitly requested
                if confidence_val < self.min_confidence:
                    stats["low_confidence_skipped"] += 1
                    continue

                # Find matching command
                matched_command, match_score = self.find_matching_command(correlation, commands)

                if matched_command and match_score > 0.4:  # Require 40% similarity
                    # Initialize screenshots array if not exists
                    if "screenshots" not in matched_command:
                        matched_command["screenshots"] = []

                    # Create screenshot reference
                    screenshot_ref = {
                        "file": correlation["file"],
                        "caption": correlation["suggested_caption"],
                        "extracted_from_page": correlation["page"],
                        "confidence": confidence
                    }

                    # Add context if available
                    if correlation.get("nearest_command_above"):
                        screenshot_ref["context"] = f"Matches: {correlation['nearest_command_above'][:80]}"

                    # Check if already exists (avoid duplicates)
                    if not any(s["file"] == screenshot_ref["file"] for s in matched_command["screenshots"]):
                        matched_command["screenshots"].append(screenshot_ref)

                        # Update stats
                        if confidence == "high":
                            stats["high_confidence_added"] += 1
                        elif confidence == "medium":
                            stats["medium_confidence_added"] += 1

                        # Tag for manual review if medium/low confidence
                        if confidence != "high":
                            stats["manual_review_needed"].append({
                                "phase": phase_name,
                                "command_step": matched_command.get("step_number"),
                                "command_id": matched_command.get("command_id"),
                                "image": correlation["file"],
                                "confidence": confidence,
                                "match_score": round(match_score, 2)
                            })

        return writeup, stats

    def process_target(
        self,
        target_dir: Path
    ) -> tuple[bool, Dict]:
        """
        Process target writeup with enrichment

        Returns:
            (success, stats_dict)
        """
        # Load files
        writeup_file = target_dir / f"{target_dir.name}.json"
        metadata_file = target_dir / "image_metadata.json"
        output_file = target_dir / f"{target_dir.name}_enriched.json"

        if not writeup_file.exists():
            print(f"[!] Writeup JSON not found: {writeup_file}")
            return False, {}

        if not metadata_file.exists():
            print(f"[!] Image metadata not found: {metadata_file}")
            print(f"    Run: python3 extract_htb_pdf_enhanced.py --target {target_dir.name}")
            return False, {}

        # Load JSON
        with open(writeup_file, "r", encoding="utf-8") as f:
            writeup = json.load(f)

        with open(metadata_file, "r", encoding="utf-8") as f:
            image_metadata = json.load(f)

        print(f"[*] Enriching writeup: {target_dir.name}")
        print(f"    Total images:    {image_metadata['total_images']}")
        print(f"    High confidence: {image_metadata['confidence_distribution']['high']}")
        print(f"    Medium:          {image_metadata['confidence_distribution']['medium']}")
        print(f"    Low:             {image_metadata['confidence_distribution']['low']}")
        print(f"    Min threshold:   {self.confidence_threshold}\n")

        # Enrich
        enriched_writeup, stats = self.enrich_writeup(writeup, image_metadata)

        # Save enriched JSON
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(enriched_writeup, f, indent=2, ensure_ascii=False)

        print(f"[✓] Enrichment complete!")
        print(f"    High-confidence added:  {stats['high_confidence_added']}")
        print(f"    Medium-confidence added: {stats['medium_confidence_added']}")
        print(f"    Low-confidence skipped:  {stats['low_confidence_skipped']}")
        print(f"    Saved to: {output_file}\n")

        if stats["manual_review_needed"]:
            print(f"[!] Manual review recommended for {len(stats['manual_review_needed'])} items:")
            for item in stats["manual_review_needed"][:5]:  # Show first 5
                print(f"    - {item['phase']}, step {item['command_step']}: "
                      f"{item['image']} (conf: {item['confidence']}, match: {item['match_score']})")
            if len(stats["manual_review_needed"]) > 5:
                print(f"    ... and {len(stats['manual_review_needed']) - 5} more")
            print()

        print("[i] Next steps:")
        print(f"    1. Review: {output_file}")
        print(f"    2. Manually adjust captions and verify medium-confidence matches")
        print(f"    3. Replace original: mv {output_file} {writeup_file}")
        print(f"    4. Validate: python3 validate_writeups.py --target {target_dir.name}")
        print()

        return True, stats


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Enrich writeup JSON with screenshot references",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    script_dir = Path(__file__).parent.resolve()
    default_base = script_dir.parent / "data" / "writeups" / "hackthebox"

    parser.add_argument(
        '--target',
        type=str,
        required=True,
        help="Target name (e.g., Usage, Sea)"
    )

    parser.add_argument(
        '--base-dir',
        type=Path,
        default=default_base,
        help=f"Base directory for writeups (default: {default_base})"
    )

    parser.add_argument(
        '--confidence-threshold',
        type=str,
        choices=["high", "medium", "low"],
        default="medium",
        help="Minimum confidence level to auto-insert (default: medium)"
    )

    args = parser.parse_args()

    # Construct target path
    target_dir = args.base_dir / args.target

    if not target_dir.exists():
        print(f"[!] Error: Target directory not found: {target_dir}")
        return 1

    # Enrich writeup
    enricher = WriteupImageEnricher(confidence_threshold=args.confidence_threshold)
    success, stats = enricher.process_target(target_dir)

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
