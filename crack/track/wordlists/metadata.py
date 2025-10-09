"""
Wordlist Metadata Generator

Generates metadata for wordlist files with performance optimizations:
- Fast line counting for small files, estimation for large files
- Sample-based word length calculation for large files
- Pattern-based category detection
"""

import os
import re
from pathlib import Path
from typing import Tuple
from datetime import datetime


def generate_metadata(file_path: str):
    """
    Generate metadata for a wordlist file

    Args:
        file_path: Path to wordlist file

    Returns:
        WordlistEntry with generated metadata

    Performance:
    - Small files (<10K lines): Exact counts
    - Large files (>10K lines): Sampling and estimation
    - Target: <200ms for rockyou.txt (14M lines)
    """
    from .manager import WordlistEntry

    path = Path(file_path).resolve()

    # Basic file info
    name = path.stem  # Filename without extension
    size_bytes = path.stat().st_size

    # Count lines (fast method)
    line_count = _count_lines_fast(str(path), size_bytes)

    # Calculate average word length (sample-based for large files)
    avg_word_length = _calculate_avg_word_length(str(path), line_count)

    # Detect category from path/filename
    category = detect_category(str(path), name)

    # Generate description
    description = _generate_description(name, category, line_count)

    return WordlistEntry(
        path=str(path),
        name=name,
        category=category,
        size_bytes=size_bytes,
        line_count=line_count,
        avg_word_length=avg_word_length,
        description=description,
        last_scanned=datetime.now().isoformat()
    )


def _count_lines_fast(file_path: str, size_bytes: int) -> int:
    """
    Fast line counting with estimation for large files

    Strategy:
    - Files <1MB: Exact count
    - Files >1MB: Sample-based estimation

    Args:
        file_path: Path to file
        size_bytes: File size in bytes

    Returns:
        Line count (exact or estimated)
    """
    # Small files: exact count
    if size_bytes < 1_000_000:  # 1MB threshold
        try:
            with open(file_path, 'rb') as f:
                return sum(1 for _ in f)
        except OSError:
            return 0

    # Large files: sample-based estimation
    try:
        with open(file_path, 'rb') as f:
            # Sample first 100KB
            sample = f.read(100_000)
            sample_lines = sample.count(b'\n')

            # Estimate total lines
            if sample_lines > 0:
                lines_per_byte = sample_lines / len(sample)
                estimated_lines = int(size_bytes * lines_per_byte)
                return estimated_lines

            return 0

    except OSError:
        return 0


def _calculate_avg_word_length(file_path: str, line_count: int) -> float:
    """
    Calculate average word length (sample-based for large files)

    Args:
        file_path: Path to file
        line_count: Number of lines in file

    Returns:
        Average word length in characters
    """
    # Sample size for large files
    SAMPLE_SIZE = 1000

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            # Small files: read all lines
            if line_count < 10_000:
                lines = f.readlines()
            else:
                # Large files: sample first/middle/last 1000 lines each
                lines = []

                # First 1000
                lines.extend([f.readline().strip() for _ in range(SAMPLE_SIZE)])

                # Middle 1000
                middle_pos = (line_count // 2) * 50  # Estimate byte position
                try:
                    f.seek(middle_pos)
                    f.readline()  # Skip partial line
                    lines.extend([f.readline().strip() for _ in range(SAMPLE_SIZE)])
                except OSError:
                    pass

                # Last 1000 (work backwards from end)
                try:
                    f.seek(0, 2)  # End of file
                    file_size = f.tell()
                    if file_size > 100_000:
                        f.seek(file_size - 100_000)
                        f.readline()  # Skip partial line
                        last_lines = f.readlines()
                        lines.extend(last_lines[-SAMPLE_SIZE:])
                except OSError:
                    pass

            # Calculate average
            if not lines:
                return 0.0

            total_length = sum(len(line.strip()) for line in lines)
            return round(total_length / len(lines), 2)

    except (OSError, UnicodeDecodeError):
        return 0.0


def detect_category(path: str, filename: str) -> str:
    """
    Detect wordlist category from path and filename patterns

    Args:
        path: Full path to file
        filename: Filename without extension

    Returns:
        Category string (web, passwords, subdomains, usernames, general)
    """
    from .manager import (
        CATEGORY_WEB, CATEGORY_PASSWORDS, CATEGORY_SUBDOMAINS,
        CATEGORY_USERNAMES, CATEGORY_GENERAL
    )

    path_lower = path.lower()
    name_lower = filename.lower()

    # Web enumeration patterns
    web_patterns = [
        'dirb', 'dirbuster', 'directory', 'web', 'content',
        'common', 'apache', 'nginx', 'iis', 'asp', 'php',
        'jsp', 'cgi', 'api', 'endpoint', 'parameter'
    ]
    if any(pattern in path_lower or pattern in name_lower for pattern in web_patterns):
        return CATEGORY_WEB

    # Password patterns
    password_patterns = [
        'password', 'pass', 'rockyou', 'creds', 'credential',
        'combo', 'leak', 'breach', 'hash', 'wordlist'
    ]
    if any(pattern in path_lower or pattern in name_lower for pattern in password_patterns):
        return CATEGORY_PASSWORDS

    # Subdomain patterns
    subdomain_patterns = [
        'subdomain', 'dns', 'vhost', 'domain', 'host'
    ]
    if any(pattern in path_lower or pattern in name_lower for pattern in subdomain_patterns):
        return CATEGORY_SUBDOMAINS

    # Username patterns
    username_patterns = [
        'user', 'username', 'login', 'account', 'names'
    ]
    if any(pattern in path_lower or pattern in name_lower for pattern in username_patterns):
        return CATEGORY_USERNAMES

    # Default to general
    return CATEGORY_GENERAL


def _generate_description(name: str, category: str, line_count: int) -> str:
    """
    Generate human-readable description

    Args:
        name: Filename
        category: Detected category
        line_count: Number of lines

    Returns:
        Description string
    """
    # Format line count
    if line_count < 1_000:
        size_desc = f"{line_count} entries"
    elif line_count < 1_000_000:
        size_desc = f"{line_count / 1_000:.1f}K entries"
    else:
        size_desc = f"{line_count / 1_000_000:.1f}M entries"

    # Build description
    return f"{category.capitalize()} wordlist with {size_desc}"
