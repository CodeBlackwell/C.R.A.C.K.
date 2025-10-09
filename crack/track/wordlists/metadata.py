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
    name = path.name  # Filename with extension
    size_bytes = path.stat().st_size

    # Count lines (fast method)
    line_count = _count_lines_fast(str(path))

    # Calculate average word length (sample-based for large files)
    avg_word_length = _calculate_avg_word_length(str(path))

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


def _count_lines_fast(file_path: str) -> int:
    """
    Fast line counting with estimation for large files

    Strategy:
    - Files <1MB: Exact count
    - Files >1MB: Sample-based estimation

    Args:
        file_path: Path to file

    Returns:
        Line count (exact or estimated)
    """
    # Get file size
    try:
        size_bytes = Path(file_path).stat().st_size
    except OSError:
        return 0

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


def _calculate_avg_word_length(file_path: str) -> float:
    """
    Calculate average word length (sample-based for large files)

    Args:
        file_path: Path to file

    Returns:
        Average word length in characters
    """
    # Get line count
    line_count = _count_lines_fast(file_path)

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

            # Calculate average (skip empty lines)
            if not lines:
                return 0.0

            # Strip and filter out empty lines
            stripped_lines = [line.strip() for line in lines]
            non_empty_lines = [line for line in stripped_lines if line]

            if not non_empty_lines:
                return 0.0

            total_length = sum(len(line) for line in non_empty_lines)
            return round(total_length / len(non_empty_lines), 2)

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

    # Password patterns (check FIRST - higher priority than web)
    password_patterns = [
        'password', 'pass', 'rockyou', 'creds', 'credential',
        'combo', 'leak', 'breach', 'hash'
    ]
    if any(pattern in path_lower or pattern in name_lower for pattern in password_patterns):
        return CATEGORY_PASSWORDS

    # Web enumeration patterns
    web_patterns = [
        'dirb', 'dirbuster', 'directory', 'web', 'content',
        'apache', 'nginx', 'iis', 'asp', 'php',
        'jsp', 'cgi', 'api', 'endpoint', 'parameter'
    ]
    if any(pattern in path_lower or pattern in name_lower for pattern in web_patterns):
        return CATEGORY_WEB

    # Subdomain patterns
    subdomain_patterns = [
        'subdomain', 'dns', 'vhost', 'domain', 'host'
    ]
    if any(pattern in path_lower or pattern in name_lower for pattern in subdomain_patterns):
        return CATEGORY_SUBDOMAINS

    # Username patterns (check filename more strictly to avoid false positives from paths like /home/user/)
    username_patterns = ['username', 'usernames', 'login', 'account']
    # Check filename first with specific patterns
    if any(pattern in name_lower for pattern in username_patterns):
        return CATEGORY_USERNAMES
    # Then check path for more specific patterns
    if any(pattern in path_lower for pattern in ['usernames/', 'users/', 'logins/', 'accounts/']):
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
