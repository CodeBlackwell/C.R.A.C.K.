"""
SMBMap Parser Regex Patterns

Compiled regex patterns for parsing smbmap output.
"""

import re
from datetime import datetime
from typing import Optional


# ============================================================================
# File Detection Patterns (for can_parse)
# ============================================================================

# SMBMap banner/header
SMBMAP_BANNER = re.compile(
    r'SMBMap\s+-\s+Samba\s+Share\s+Enumerator',
    re.IGNORECASE
)

# IP status line: [+] IP: 10.10.10.100:445    Name: hostname    Status: Authenticated
IP_STATUS = re.compile(
    r'^\[\+\]\s+IP:\s+(\d+\.\d+\.\d+\.\d+)(?::(\d+))?\s+'
    r'Name:\s+(\S+)\s+'
    r'(?:Status:\s+(\w+))?',
    re.MULTILINE
)

# Alternative format: [*] 10.10.10.100 - Share Enumeration
ALT_IP_HEADER = re.compile(
    r'^\[\*\]\s+(\d+\.\d+\.\d+\.\d+)\s+-\s+',
    re.MULTILINE
)


# ============================================================================
# Share Table Patterns
# ============================================================================

# Share table header detection
SHARE_TABLE_HEADER = re.compile(
    r'^\s*Disk\s+Permissions\s+Comment',
    re.IGNORECASE | re.MULTILINE
)

# Share separator line (dashes)
SHARE_SEPARATOR = re.compile(r'^\s*-{4,}\s+-{4,}', re.MULTILINE)

# Share entry: ADMIN$    NO ACCESS    Remote Admin
# Using whitespace detection for columns
SHARE_ENTRY = re.compile(
    r'^\s{8}(\S+)\s{2,}(NO ACCESS|READ ONLY|READ,?\s*WRITE|WRITE ONLY)\s*(.*)?$',
    re.IGNORECASE
)

# Alternative share pattern for different smbmap versions
SHARE_ENTRY_ALT = re.compile(
    r'^(\S+)\s{2,}(NO ACCESS|READ ONLY|READ,?\s*WRITE|WRITE ONLY)\s*(.*)?$',
    re.IGNORECASE
)


# ============================================================================
# Directory Listing Patterns
# ============================================================================

# Directory context line: ./ShareName or ./ShareName/subdir
DIR_CONTEXT = re.compile(
    r'^\s*\./([\w$\-\.]+(?:/[\w\-\.\s]+)*)\s*$'
)

# Directory entry: dr--r--r--    0 Sat Jul 21 00:37:44 2018    dirname
# File entry:      -r--r--r--    1234 Sat Jul 21 00:37:44 2018    filename.txt
DIR_ENTRY = re.compile(
    r'^\s*([d\-][rwx\-]{9})\s+'      # permissions (d for dir, - for file)
    r'(\d+)\s+'                       # size
    r'([A-Za-z]{3}\s+[A-Za-z]{3}\s+\d+\s+\d+:\d+:\d+\s+\d{4})\s+'  # date
    r'(.+)$',                         # name
    re.MULTILINE
)

# Alternative date format: 2018-07-21 00:37:44
DIR_ENTRY_ALT = re.compile(
    r'^\s*([d\-][rwx\-]{9})\s+'
    r'(\d+)\s+'
    r'(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(.+)$',
    re.MULTILINE
)


# ============================================================================
# Authentication Patterns
# ============================================================================

# Authentication info
AUTH_SUCCESS = re.compile(
    r'\[\+\]\s+(?:Guest|Authenticated|Read)',
    re.IGNORECASE
)

AUTH_FAILED = re.compile(
    r'\[\-\]\s+(?:Authentication failed|Access denied|Invalid credentials)',
    re.IGNORECASE
)

# Username/domain extraction from command or output
USERNAME_PATTERN = re.compile(
    r'(?:-u\s+|user[:\s]+)([^\s/\\]+)',
    re.IGNORECASE
)

DOMAIN_PATTERN = re.compile(
    r'(?:-d\s+|domain[:\s]+)([^\s]+)',
    re.IGNORECASE
)


# ============================================================================
# Error/Warning Patterns
# ============================================================================

ERROR_PATTERN = re.compile(r'^\[\-\]\s+(.+)$', re.MULTILINE)
WARNING_PATTERN = re.compile(r'^\[!\]\s+(.+)$', re.MULTILINE)


# ============================================================================
# Utility Functions
# ============================================================================

def parse_datetime(date_str: str) -> Optional[datetime]:
    """Parse smbmap date/time formats"""
    formats = [
        '%a %b %d %H:%M:%S %Y',    # Sat Jul 21 00:37:44 2018
        '%a %b  %d %H:%M:%S %Y',   # Sat Jul  7 00:37:44 2018 (extra space)
        '%Y-%m-%d %H:%M:%S',       # 2018-07-21 00:37:44
    ]

    date_str = date_str.strip()
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue

    return None


def is_share_table_line(line: str) -> bool:
    """Check if line is part of share table"""
    return bool(SHARE_ENTRY.match(line) or SHARE_ENTRY_ALT.match(line.strip()))


def is_dir_entry_line(line: str) -> bool:
    """Check if line is a directory listing entry"""
    return bool(DIR_ENTRY.match(line.strip()) or DIR_ENTRY_ALT.match(line.strip()))


def is_dir_context_line(line: str) -> bool:
    """Check if line is a directory context (./ShareName)"""
    return bool(DIR_CONTEXT.match(line.strip()))
