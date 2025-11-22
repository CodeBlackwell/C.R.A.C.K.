#!/usr/bin/env python3
"""
HackTheBox PDF Text Extraction Utility

Extracts text and images from HackTheBox-style writeup PDFs, organizing
each target into its own subdirectory with original PDF, extracted text,
and images.

Usage:
    python3 extract_htb_pdf.py [options]

Options:
    --input-dir PATH    Source directory containing PDFs (default: ../data/writeups/hackthebox/)
    --output-dir PATH   Output directory for organized extractions (default: same as input)
    --verbose           Show detailed extraction logs
    --skip-images       Skip image extraction (text only)
    --help              Show this help message
"""

import pymupdf  # PyMuPDF
import argparse
import sys
from pathlib import Path
from typing import Tuple, List, Dict
import shutil


class HTBPDFExtractor:
    """Extract text and images from HackTheBox PDF writeups"""

    def __init__(self, verbose: bool = False, skip_images: bool = False):
        self.verbose = verbose
        self.skip_images = skip_images
        self.stats = {
            'pdfs_processed': 0,
            'pdfs_failed': 0,
            'total_pages': 0,
            'total_images': 0,
            'targets_created': []
        }

    def log(self, message: str, force: bool = False):
        """Log message if verbose mode enabled"""
        if self.verbose or force:
            print(f"  {message}")

    def extract_text(self, pdf_path: Path) -> str:
        """
        Extract text from PDF with structure preservation

        Args:
            pdf_path: Path to PDF file

        Returns:
            Extracted text content
        """
        try:
            doc = pymupdf.open(pdf_path)
            text_content = []

            for page_num, page in enumerate(doc, 1):
                self.log(f"Extracting text from page {page_num}/{len(doc)}")

                # Extract text blocks with position information
                blocks = page.get_text("blocks")

                page_text = []
                for block in blocks:
                    # block format: (x0, y0, x1, y1, "text", block_no, block_type)
                    if len(block) >= 5:
                        text = block[4].strip()
                        if text:
                            page_text.append(text)

                if page_text:
                    text_content.append("\n\n".join(page_text))
                    text_content.append("\n" + "="*80 + f"\nPage {page_num}\n" + "="*80 + "\n")

            # Save page count before closing document
            page_count = len(doc)
            doc.close()
            self.stats['total_pages'] += page_count

            return "\n".join(text_content)

        except Exception as e:
            raise RuntimeError(f"Text extraction failed: {e}")

    def extract_images(self, pdf_path: Path, output_dir: Path) -> int:
        """
        Extract all images from PDF

        Args:
            pdf_path: Path to PDF file
            output_dir: Directory to save extracted images

        Returns:
            Number of images extracted
        """
        if self.skip_images:
            return 0

        try:
            doc = pymupdf.open(pdf_path)
            image_count = 0

            # Create images subdirectory
            images_dir = output_dir / "images"
            images_dir.mkdir(exist_ok=True)

            for page_num, page in enumerate(doc, 1):
                # Get list of images on page
                image_list = page.get_images(full=True)

                self.log(f"Page {page_num}: found {len(image_list)} images")

                for img_index, img in enumerate(image_list):
                    xref = img[0]  # Image XREF number

                    # Extract image
                    base_image = doc.extract_image(xref)
                    image_bytes = base_image["image"]
                    image_ext = base_image["ext"]

                    # Save image with descriptive name
                    image_filename = f"page{page_num:02d}_img{img_index+1:02d}.{image_ext}"
                    image_path = images_dir / image_filename

                    with open(image_path, "wb") as img_file:
                        img_file.write(image_bytes)

                    image_count += 1
                    self.log(f"  Saved: {image_filename}")

            doc.close()
            self.stats['total_images'] += image_count

            return image_count

        except Exception as e:
            self.log(f"Warning: Image extraction failed: {e}")
            return 0

    def process_pdf(self, pdf_path: Path, output_base_dir: Path) -> bool:
        """
        Process a single PDF file

        Creates target subdirectory structure:
        target_name/
        ├── target_name.pdf (moved original)
        ├── target_name.txt (extracted text)
        └── images/ (extracted images)

        Args:
            pdf_path: Path to source PDF
            output_base_dir: Base directory for organized output

        Returns:
            True if successful, False otherwise
        """
        try:
            # Get target name from PDF filename (without .pdf extension)
            target_name = pdf_path.stem

            print(f"\n[*] Processing: {pdf_path.name}")
            print(f"    Target: {target_name}")

            # Create target subdirectory
            target_dir = output_base_dir / target_name
            target_dir.mkdir(exist_ok=True, parents=True)
            self.log(f"Created directory: {target_dir}")

            # Extract text
            print(f"    [+] Extracting text...")
            text_content = self.extract_text(pdf_path)

            # Save text to file
            text_file = target_dir / f"{target_name}.txt"
            text_file.write_text(text_content, encoding='utf-8')
            self.log(f"Saved text to: {text_file}")
            print(f"    [+] Text extracted: {len(text_content)} chars")

            # Extract images
            if not self.skip_images:
                print(f"    [+] Extracting images...")
                image_count = self.extract_images(pdf_path, target_dir)
                print(f"    [+] Images extracted: {image_count}")
            else:
                image_count = 0
                print(f"    [+] Skipping images (--skip-images)")

            # Move original PDF to target directory
            dest_pdf = target_dir / pdf_path.name
            if dest_pdf.exists():
                dest_pdf.unlink()  # Remove if exists
            shutil.move(str(pdf_path), str(dest_pdf))
            self.log(f"Moved PDF to: {dest_pdf}")
            print(f"    [+] Organized into: {target_dir}/")

            # Update stats
            self.stats['pdfs_processed'] += 1
            self.stats['targets_created'].append(target_name)

            return True

        except Exception as e:
            print(f"    [!] Error processing {pdf_path.name}: {e}")
            self.stats['pdfs_failed'] += 1
            return False

    def process_directory(self, input_dir: Path, output_dir: Path) -> Dict:
        """
        Process all PDFs in a directory

        Args:
            input_dir: Directory containing PDF files
            output_dir: Directory for organized output

        Returns:
            Statistics dictionary
        """
        # Find all PDF files
        pdf_files = list(input_dir.glob("*.pdf"))

        if not pdf_files:
            print(f"[!] No PDF files found in {input_dir}")
            return self.stats

        print(f"\n{'='*80}")
        print(f"HackTheBox PDF Extractor")
        print(f"{'='*80}")
        print(f"Input directory:  {input_dir}")
        print(f"Output directory: {output_dir}")
        print(f"PDF files found:  {len(pdf_files)}")
        print(f"{'='*80}\n")

        # Process each PDF
        for pdf_path in pdf_files:
            self.process_pdf(pdf_path, output_dir)

        # Print summary
        self.print_summary()

        return self.stats

    def print_summary(self):
        """Print extraction summary"""
        print(f"\n{'='*80}")
        print(f"EXTRACTION SUMMARY")
        print(f"{'='*80}")
        print(f"PDFs processed:    {self.stats['pdfs_processed']}")
        print(f"PDFs failed:       {self.stats['pdfs_failed']}")
        print(f"Total pages:       {self.stats['total_pages']}")
        print(f"Total images:      {self.stats['total_images']}")

        if self.stats['targets_created']:
            print(f"\nTargets created:")
            for target in self.stats['targets_created']:
                print(f"  - {target}/")

        print(f"{'='*80}\n")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Extract text and images from HackTheBox PDF writeups",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Process all PDFs in default directory
  python3 extract_htb_pdf.py

  # Process with verbose logging
  python3 extract_htb_pdf.py --verbose

  # Process specific directory
  python3 extract_htb_pdf.py --input-dir /path/to/pdfs --output-dir /path/to/output

  # Text only, skip images
  python3 extract_htb_pdf.py --skip-images
        """
    )

    # Get script directory
    script_dir = Path(__file__).parent.resolve()
    default_input = script_dir.parent / "data" / "writeups" / "hackthebox"

    parser.add_argument(
        '--input-dir',
        type=Path,
        default=default_input,
        help=f"Input directory containing PDF files (default: {default_input})"
    )

    parser.add_argument(
        '--output-dir',
        type=Path,
        default=None,
        help="Output directory for organized extractions (default: same as input-dir)"
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help="Show detailed extraction logs"
    )

    parser.add_argument(
        '--skip-images',
        action='store_true',
        help="Skip image extraction (text only)"
    )

    args = parser.parse_args()

    # Validate input directory
    if not args.input_dir.exists():
        print(f"[!] Error: Input directory does not exist: {args.input_dir}")
        return 1

    if not args.input_dir.is_dir():
        print(f"[!] Error: Input path is not a directory: {args.input_dir}")
        return 1

    # Set output directory (default to input directory)
    output_dir = args.output_dir if args.output_dir else args.input_dir
    output_dir.mkdir(exist_ok=True, parents=True)

    # Create extractor and process
    extractor = HTBPDFExtractor(verbose=args.verbose, skip_images=args.skip_images)
    stats = extractor.process_directory(args.input_dir, output_dir)

    # Exit with error code if any failures
    if stats['pdfs_failed'] > 0:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
