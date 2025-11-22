#!/usr/bin/env python3
"""
Enhanced HackTheBox PDF Extraction with Positional Metadata

Extracts text and images from PDFs with spatial positioning to enable
automatic image-to-command correlation for writeup generation.

Features:
- Text block extraction with bounding boxes
- Image extraction with coordinates
- Proximity-based image-to-text correlation
- Generates image_metadata.json for semi-automated annotation

Usage:
    python3 extract_htb_pdf_enhanced.py [--target TARGET_NAME]
"""

import pymupdf  # PyMuPDF
import json
import argparse
import sys
from pathlib import Path
from typing import List, Dict, Tuple, Optional
import re


class EnhancedPDFExtractor:
    """Extract PDF content with positional metadata for automatic image correlation"""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.proximity_threshold = 150  # pixels - images within 150px of command are candidates

    def log(self, message: str, force: bool = False):
        """Log message if verbose mode enabled"""
        if self.verbose or force:
            print(f"  {message}")

    def is_command_block(self, text: str) -> bool:
        """
        Heuristically detect if text block contains a command

        Detection criteria:
        - Contains common pentesting commands (nmap, curl, etc.)
        - Has shell prompt indicators ($, #)
        - Contains command line flags (--, -)
        - Monospace-like characteristics (to be enhanced)
        """
        command_keywords = [
            'nmap', 'curl', 'gobuster', 'ffuf', 'sqlmap', 'burpsuite',
            'nc', 'netcat', 'python', 'php', 'bash', 'sh',
            'sudo', 'cat', 'echo', 'grep', 'find', 'ls',
            'john', 'hashcat', 'hydra', 'ssh', 'ftp', 'telnet',
            'wget', 'git', 'docker', 'mysql', 'psql'
        ]

        text_lower = text.lower()

        # Check for command keywords
        has_command = any(cmd in text_lower for cmd in command_keywords)

        # Check for command-line patterns
        has_flags = re.search(r'\s-[a-zA-Z]|\s--[a-z-]+', text)
        has_prompt = re.search(r'^\s*[$#>]', text, re.MULTILINE)
        has_url = 'http://' in text_lower or 'https://' in text_lower

        return has_command or has_flags or has_prompt or has_url

    def extract_text_blocks_with_positions(self, pdf_path: Path) -> List[Dict]:
        """
        Extract text blocks with bounding box coordinates

        Returns:
            List of dicts with: {page, bbox, text, is_command}
        """
        doc = pymupdf.open(pdf_path)
        all_blocks = []

        for page_num, page in enumerate(doc, 1):
            blocks = page.get_text("dict")["blocks"]

            for block in blocks:
                if block.get("type") == 0:  # Text block
                    bbox = block["bbox"]  # (x0, y0, x1, y1)
                    text_content = ""

                    # Extract text from lines within block
                    for line in block.get("lines", []):
                        for span in line.get("spans", []):
                            text_content += span.get("text", "") + " "

                    text_content = text_content.strip()

                    if text_content:
                        all_blocks.append({
                            "page": page_num,
                            "bbox": {
                                "x0": bbox[0],
                                "y0": bbox[1],
                                "x1": bbox[2],
                                "y1": bbox[3]
                            },
                            "text": text_content,
                            "is_command": self.is_command_block(text_content)
                        })

        doc.close()
        return all_blocks

    def extract_images_with_positions(self, pdf_path: Path, output_dir: Path) -> List[Dict]:
        """
        Extract images with bounding box coordinates

        Returns:
            List of dicts with: {page, bbox, file, filename}
        """
        doc = pymupdf.open(pdf_path)
        images_data = []

        # Create images directory
        images_dir = output_dir / "images"
        images_dir.mkdir(exist_ok=True)

        for page_num, page in enumerate(doc, 1):
            image_list = page.get_images(full=True)

            for img_index, img in enumerate(image_list):
                xref = img[0]

                # Get image bounding boxes (can be multiple instances)
                rects = page.get_image_rects(xref)

                # Extract and save image
                base_image = doc.extract_image(xref)
                image_bytes = base_image["image"]
                image_ext = base_image["ext"]

                image_filename = f"page{page_num:02d}_img{img_index+1:02d}.{image_ext}"
                image_path = images_dir / image_filename

                with open(image_path, "wb") as img_file:
                    img_file.write(image_bytes)

                # Store position data for first instance (rects can have multiple)
                if rects:
                    rect = rects[0]
                    images_data.append({
                        "page": page_num,
                        "bbox": {
                            "x0": rect.x0,
                            "y0": rect.y0,
                            "x1": rect.x1,
                            "y1": rect.y1
                        },
                        "file": f"images/{image_filename}",
                        "filename": image_filename
                    })

                self.log(f"Extracted: {image_filename} (page {page_num})")

        doc.close()
        return images_data

    def correlate_images_to_text(
        self,
        images: List[Dict],
        text_blocks: List[Dict]
    ) -> List[Dict]:
        """
        Correlate images to nearby text blocks using proximity

        Algorithm:
        - For each image, find text blocks on same page
        - Calculate vertical distance (y-axis) between image and text
        - Prefer text ABOVE the image (within threshold)
        - Assign confidence based on proximity and command detection
        """
        correlations = []

        for image in images:
            page = image["page"]
            image_y = image["bbox"]["y0"]

            # Find text blocks on same page
            page_blocks = [b for b in text_blocks if b["page"] == page]

            # Find blocks ABOVE the image (within threshold)
            candidates = []
            for block in page_blocks:
                block_y_bottom = block["bbox"]["y1"]
                distance = image_y - block_y_bottom

                # Text should be above image (positive distance) and within threshold
                if 0 < distance < self.proximity_threshold:
                    candidates.append({
                        "block": block,
                        "distance": distance
                    })

            # Sort by proximity (closest first)
            candidates.sort(key=lambda x: x["distance"])

            # Build correlation metadata
            nearest_command = None
            nearest_text = None
            confidence = "low"

            if candidates:
                # Prefer command blocks
                command_candidates = [c for c in candidates if c["block"]["is_command"]]

                if command_candidates:
                    nearest_command = command_candidates[0]["block"]["text"]
                    confidence = "high" if command_candidates[0]["distance"] < 100 else "medium"

                # Always include nearest text (command or not)
                nearest_text = candidates[0]["block"]["text"]

            # Generate suggested caption from nearby text
            suggested_caption = self._generate_caption(nearest_text or nearest_command)

            correlations.append({
                "file": image["file"],
                "filename": image["filename"],
                "page": page,
                "y_position": image_y,
                "nearest_command_above": nearest_command,
                "nearest_text_above": nearest_text,
                "confidence": confidence,
                "suggested_caption": suggested_caption
            })

        return correlations

    def _generate_caption(self, text: Optional[str]) -> str:
        """Generate a suggested caption from nearby text"""
        if not text:
            return "Screenshot"

        # Truncate to reasonable length
        max_len = 80
        if len(text) > max_len:
            text = text[:max_len] + "..."

        return text

    def process_pdf(self, pdf_path: Path, output_dir: Path) -> Dict:
        """
        Process PDF with enhanced extraction

        Generates:
        - Text file (existing functionality)
        - Images with original naming (existing functionality)
        - image_metadata.json (NEW - positional correlations)
        """
        target_name = pdf_path.stem

        print(f"\n[*] Enhanced extraction: {pdf_path.name}")
        print(f"    Target: {target_name}")

        # Ensure output directory exists
        output_dir.mkdir(exist_ok=True, parents=True)

        # Extract text blocks with positions
        print("    [+] Extracting text blocks with positions...")
        text_blocks = self.extract_text_blocks_with_positions(pdf_path)
        command_count = sum(1 for b in text_blocks if b["is_command"])
        print(f"        - {len(text_blocks)} text blocks found ({command_count} potential commands)")

        # Extract images with positions
        print("    [+] Extracting images with positions...")
        images = self.extract_images_with_positions(pdf_path, output_dir)
        print(f"        - {len(images)} images extracted")

        # Correlate images to text
        print("    [+] Correlating images to nearby text...")
        correlations = self.correlate_images_to_text(images, text_blocks)

        # Count confidence levels
        confidence_counts = {
            "high": sum(1 for c in correlations if c["confidence"] == "high"),
            "medium": sum(1 for c in correlations if c["confidence"] == "medium"),
            "low": sum(1 for c in correlations if c["confidence"] == "low")
        }

        print(f"        - Confidence: {confidence_counts['high']} high, "
              f"{confidence_counts['medium']} medium, {confidence_counts['low']} low")

        # Save metadata to JSON
        metadata_file = output_dir / "image_metadata.json"
        with open(metadata_file, "w", encoding="utf-8") as f:
            json.dump({
                "target": target_name,
                "total_images": len(images),
                "total_text_blocks": len(text_blocks),
                "command_blocks_detected": command_count,
                "confidence_distribution": confidence_counts,
                "image_correlations": correlations
            }, f, indent=2)

        print(f"    [+] Metadata saved: {metadata_file}")

        return {
            "images": len(images),
            "text_blocks": len(text_blocks),
            "commands": command_count,
            "correlations": len(correlations)
        }


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Enhanced PDF extraction with positional metadata",
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
        '--verbose',
        action='store_true',
        help="Show detailed extraction logs"
    )

    args = parser.parse_args()

    # Construct paths
    target_dir = args.base_dir / args.target
    pdf_path = target_dir / f"{args.target}.pdf"

    # Validate inputs
    if not pdf_path.exists():
        print(f"[!] Error: PDF not found: {pdf_path}")
        return 1

    # Extract with metadata
    extractor = EnhancedPDFExtractor(verbose=args.verbose)
    stats = extractor.process_pdf(pdf_path, target_dir)

    print(f"\n[✓] Enhanced extraction complete!")
    print(f"    Images:      {stats['images']}")
    print(f"    Text blocks: {stats['text_blocks']}")
    print(f"    Commands:    {stats['commands']}")
    print(f"    Review:      {target_dir}/image_metadata.json\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
