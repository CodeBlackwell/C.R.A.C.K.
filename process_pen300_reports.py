#!/usr/bin/env python3
"""
Agent 2: PEN300 Mining Reports Cleanup Specialist

Processes all PEN300_*.md files in plugin_docs directory:
- Standardizes naming (lowercase with underscores)
- Adds Table of Contents
- Consolidates duplicates (keeps REMINE versions)
- Adds breadcrumb navigation
- Handles PEN300_MINING_PLAN.md specially
"""

import re
import os
from pathlib import Path
from typing import List, Tuple, Dict

class PEN300ReportProcessor:
    def __init__(self, docs_dir: Path):
        self.docs_dir = docs_dir
        self.processed = []
        self.renamed = []
        self.consolidated = []
        self.errors = []
        self.special_cases = []

    def find_pen300_files(self) -> List[Path]:
        """Find all PEN300_*.md files"""
        return sorted(self.docs_dir.glob("PEN300_*.md"))

    def standardize_filename(self, original: Path) -> str:
        """Convert PEN300_TOPIC_MINING_REPORT.md to pen300_topic_mining_report.md"""
        # Keep original if it's the mining plan
        if original.name == "PEN300_MINING_PLAN.md":
            return original.name

        # Convert to lowercase with underscores
        return original.name.lower()

    def extract_headers(self, content: str) -> List[Tuple[str, str, int]]:
        """Extract all markdown headers (level, text, line_number)"""
        headers = []
        lines = content.split('\n')

        for i, line in enumerate(lines, 1):
            # Match markdown headers (## or #)
            match = re.match(r'^(#{1,6})\s+(.+)$', line)
            if match:
                level = len(match.group(1))
                text = match.group(2).strip()
                headers.append((level, text, i))

        return headers

    def generate_toc(self, headers: List[Tuple[str, str, int]]) -> str:
        """Generate Table of Contents from headers"""
        if not headers:
            return ""

        # Skip the first header (document title)
        toc_headers = headers[1:]

        if not toc_headers:
            return ""

        toc_lines = ["## Table of Contents\n"]

        for level, text, _ in toc_headers:
            # Create anchor link
            anchor = text.lower()
            anchor = re.sub(r'[^\w\s-]', '', anchor)  # Remove special chars
            anchor = re.sub(r'\s+', '-', anchor)       # Replace spaces with hyphens

            # Create indentation based on level
            indent = "  " * (level - 2) if level > 2 else ""

            toc_lines.append(f"{indent}- [{text}](#{anchor})")

        toc_lines.append("")  # Blank line after TOC
        return '\n'.join(toc_lines)

    def add_breadcrumb(self, content: str) -> str:
        """Add breadcrumb navigation at the top"""
        breadcrumb = "[← Back to Index](README.md) | [PEN-300 Reports](#)\n\n---\n\n"
        return breadcrumb + content

    def process_file(self, file_path: Path) -> bool:
        """Process a single PEN300 file"""
        try:
            # Read original content
            content = file_path.read_text()

            # Remove existing breadcrumb if present
            if content.startswith("[← Back to Index]"):
                lines = content.split('\n')
                # Find where breadcrumb ends (look for ---  separator)
                content_start = 0
                for i, line in enumerate(lines):
                    if line.strip() == '---':
                        content_start = i + 2  # Skip --- and blank line
                        break
                content = '\n'.join(lines[content_start:])

            # Extract headers from clean content
            headers = self.extract_headers(content)

            # Remove existing TOC if present
            if "## Table of Contents" in content:
                # Find TOC section and remove it
                lines = content.split('\n')
                toc_start = -1
                toc_end = -1

                for i, line in enumerate(lines):
                    if line.strip() == "## Table of Contents":
                        toc_start = i
                        # Find end of TOC (next ## header or end of file)
                        for j in range(i + 1, len(lines)):
                            if lines[j].startswith('##') and lines[j].strip() != "## Table of Contents":
                                toc_end = j
                                break
                        if toc_end == -1:
                            toc_end = len(lines)
                        break

                if toc_start != -1:
                    # Remove TOC section
                    lines = lines[:toc_start] + lines[toc_end:]
                    content = '\n'.join(lines)

            # Find first header
            lines = content.split('\n')
            first_header_idx = -1
            for i, line in enumerate(lines):
                if line.startswith('#'):
                    first_header_idx = i
                    break

            if first_header_idx == -1:
                # No header found, skip file
                self.errors.append((file_path.name, "No headers found in file"))
                return False

            # Split into title/meta and rest
            title_section = '\n'.join(lines[:first_header_idx+1])

            # Find any content between title and first ## section
            meta_end = first_header_idx + 1
            for i in range(first_header_idx + 1, len(lines)):
                if lines[i].startswith('##'):
                    meta_end = i
                    break

            meta_content = '\n'.join(lines[first_header_idx+1:meta_end])
            rest_content = '\n'.join(lines[meta_end:])

            # Generate new TOC
            toc = self.generate_toc(headers)

            # Reconstruct content
            if meta_content.strip():
                new_content = f"{title_section}\n{meta_content}\n\n{toc}\n{rest_content}"
            else:
                new_content = f"{title_section}\n\n{toc}\n{rest_content}"

            # Add breadcrumb
            new_content = self.add_breadcrumb(new_content)

            # Clean up multiple blank lines
            new_content = re.sub(r'\n{4,}', '\n\n\n', new_content)

            # Write back
            file_path.write_text(new_content)

            self.processed.append(file_path.name)
            return True

        except Exception as e:
            self.errors.append((file_path.name, str(e)))
            return False

    def check_for_duplicates(self, files: List[Path]) -> Dict[str, List[Path]]:
        """Identify duplicate base names (original vs REMINE)"""
        duplicates = {}

        for file in files:
            # Extract base name without REMINE suffix
            base = file.stem
            if "_REMINE_REPORT" in base:
                base = base.replace("_REMINE_REPORT", "_MINING_REPORT")

            if base not in duplicates:
                duplicates[base] = []
            duplicates[base].append(file)

        # Filter to only actual duplicates
        return {k: v for k, v in duplicates.items() if len(v) > 1}

    def consolidate_duplicates(self, duplicate_groups: Dict[str, List[Path]]) -> None:
        """Consolidate duplicates - keep REMINE, delete original"""
        for base_name, files in duplicate_groups.items():
            # Find REMINE version
            remine_file = None
            original_file = None

            for f in files:
                if "REMINE" in f.name:
                    remine_file = f
                else:
                    original_file = f

            if remine_file and original_file:
                # Rename REMINE to standard naming
                new_name = self.standardize_filename(original_file)
                new_path = self.docs_dir / new_name

                # Process REMINE file first
                self.process_file(remine_file)

                # Rename REMINE to standard name
                remine_file.rename(new_path)

                # Delete original
                original_file.unlink()

                self.consolidated.append(f"{original_file.name} + {remine_file.name} → {new_name}")

    def rename_files(self, files: List[Path]) -> None:
        """Rename files to standardized naming"""
        for file in files:
            new_name = self.standardize_filename(file)

            if new_name != file.name:
                new_path = self.docs_dir / new_name

                # Process before renaming
                self.process_file(file)

                # Rename
                file.rename(new_path)

                self.renamed.append(f"{file.name} → {new_name}")

    def process_all(self) -> None:
        """Main processing pipeline"""
        print("=" * 70)
        print("Agent 2: PEN300 Mining Reports Cleanup Specialist")
        print("=" * 70)
        print()

        # Find all files
        files = self.find_pen300_files()
        print(f"📁 Found {len(files)} PEN300_*.md files")
        print()

        # Handle special case
        mining_plan = self.docs_dir / "PEN300_MINING_PLAN.md"
        if mining_plan.exists():
            self.special_cases.append(str(mining_plan))
            print(f"⚠️  Special case identified: {mining_plan.name}")
            print("   This file will NOT be processed (planning document)")
            print()
            files = [f for f in files if f != mining_plan]

        # Check for duplicates
        duplicate_groups = self.check_for_duplicates(files)

        if duplicate_groups:
            print(f"🔄 Found {len(duplicate_groups)} duplicate groups:")
            for base, group in duplicate_groups.items():
                print(f"   - {base}:")
                for f in group:
                    print(f"     • {f.name}")
            print()

            # Consolidate duplicates
            print("🔧 Consolidating duplicates (keeping REMINE versions)...")
            self.consolidate_duplicates(duplicate_groups)
            print()

        # Get remaining files after consolidation
        files = self.find_pen300_files()
        files = [f for f in files if f != mining_plan]

        # Process and rename remaining files
        print(f"📝 Processing {len(files)} remaining files...")
        for file in files:
            new_name = self.standardize_filename(file)

            # Skip if already processed during consolidation
            if any(new_name in c for c in self.consolidated):
                continue

            # Process
            self.process_file(file)

            # Rename if needed
            if new_name != file.name:
                new_path = self.docs_dir / new_name
                file.rename(new_path)
                self.renamed.append(f"{file.name} → {new_name}")

        print()
        self.print_report()

    def print_report(self) -> None:
        """Print final processing report"""
        print("=" * 70)
        print("PROCESSING REPORT")
        print("=" * 70)
        print()

        print(f"✅ Files Processed: {len(self.processed)}")
        print()

        if self.renamed:
            print(f"📝 Files Renamed: {len(self.renamed)}")
            for item in self.renamed:
                print(f"   • {item}")
            print()

        if self.consolidated:
            print(f"🔄 Duplicates Consolidated: {len(self.consolidated)}")
            for item in self.consolidated:
                print(f"   • {item}")
            print()

        if self.special_cases:
            print(f"⚠️  Special Cases:")
            for item in self.special_cases:
                print(f"   • {item} (NOT processed - planning document)")
            print()

        if self.errors:
            print(f"❌ Errors: {len(self.errors)}")
            for filename, error in self.errors:
                print(f"   • {filename}: {error}")
            print()

        # Summary
        print("=" * 70)
        print("SUMMARY")
        print("=" * 70)
        print(f"Total files found: {len(self.find_pen300_files())}")
        print(f"Files processed: {len(self.processed)}")
        print(f"Files renamed: {len(self.renamed)}")
        print(f"Duplicates consolidated: {len(self.consolidated)}")
        print(f"Special cases noted: {len(self.special_cases)}")
        print(f"Errors encountered: {len(self.errors)}")
        print()

        if not self.errors:
            print("✅ All files processed successfully!")
        else:
            print("⚠️  Some errors encountered. See details above.")


def main():
    """Main entry point"""
    docs_dir = Path("/home/kali/OSCP/crack/track/services/plugin_docs")

    if not docs_dir.exists():
        print(f"❌ Error: Directory not found: {docs_dir}")
        return 1

    processor = PEN300ReportProcessor(docs_dir)
    processor.process_all()

    return 0 if not processor.errors else 1


if __name__ == "__main__":
    exit(main())
