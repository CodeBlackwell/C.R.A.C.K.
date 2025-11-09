"""
Enhanced CSV writer with statistics and validation integration.
"""

import csv
import os
from pathlib import Path
from typing import List, Dict, Any
from dataclasses import dataclass, field


@dataclass
class CSVWriteStats:
    """Statistics for CSV write operations"""
    filename: str
    rows_written: int
    file_size_bytes: int

    @property
    def file_size_kb(self) -> float:
        """File size in kilobytes"""
        return self.file_size_bytes / 1024

    @property
    def file_size_mb(self) -> float:
        """File size in megabytes"""
        return self.file_size_bytes / (1024 * 1024)


@dataclass
class CSVWriteReport:
    """Report of all CSV write operations"""
    output_dir: str
    node_stats: List[CSVWriteStats] = field(default_factory=list)
    relationship_stats: List[CSVWriteStats] = field(default_factory=list)

    @property
    def total_rows(self) -> int:
        """Total rows written across all files"""
        return sum(s.rows_written for s in self.node_stats + self.relationship_stats)

    @property
    def total_size_bytes(self) -> int:
        """Total size in bytes"""
        return sum(s.file_size_bytes for s in self.node_stats + self.relationship_stats)

    @property
    def total_size_mb(self) -> float:
        """Total size in megabytes"""
        return self.total_size_bytes / (1024 * 1024)

    def print_report(self):
        """Print formatted CSV write report"""
        print()
        print("=" * 60)
        print("CSV Write Report")
        print("=" * 60)
        print(f"Output directory: {self.output_dir}")
        print()

        if self.node_stats:
            print("Node CSVs:")
            for stat in self.node_stats:
                print(f"  {stat.filename:30s} {stat.rows_written:6d} rows  {stat.file_size_kb:8.1f} KB")

        if self.relationship_stats:
            print()
            print("Relationship CSVs:")
            for stat in self.relationship_stats:
                print(f"  {stat.filename:30s} {stat.rows_written:6d} rows  {stat.file_size_kb:8.1f} KB")

        print()
        print(f"Total: {len(self.node_stats + self.relationship_stats)} files, "
              f"{self.total_rows} rows, {self.total_size_mb:.2f} MB")
        print("=" * 60)


class CSVWriter:
    """
    Enhanced CSV writer with statistics collection.

    Provides:
    - Consistent CSV formatting (QUOTE_ALL)
    - Automatic directory creation
    - Statistics collection
    - None to empty string conversion
    - File size tracking
    """

    def __init__(self, output_dir: str):
        """
        Initialize CSV writer.

        Args:
            output_dir: Directory to write CSV files
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.stats: List[CSVWriteStats] = []

    def write_csv(self, filename: str, data: List[Dict[str, Any]], fieldnames: List[str]) -> CSVWriteStats:
        """
        Write data to CSV file with statistics collection.

        Args:
            filename: CSV filename (without path)
            data: List of dictionaries to write
            fieldnames: Ordered list of field names for CSV header

        Returns:
            CSVWriteStats with write statistics
        """
        filepath = self.output_dir / filename

        # Write CSV with proper escaping
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
            writer.writeheader()

            for row in data:
                # Convert None to empty string
                clean_row = {k: (v if v is not None else '') for k, v in row.items()}
                writer.writerow(clean_row)

        # Collect statistics
        file_size = filepath.stat().st_size
        stat = CSVWriteStats(
            filename=filename,
            rows_written=len(data),
            file_size_bytes=file_size
        )
        self.stats.append(stat)

        return stat

    def get_stats(self) -> List[CSVWriteStats]:
        """Get all write statistics"""
        return self.stats

    def reset_stats(self):
        """Reset statistics"""
        self.stats = []
