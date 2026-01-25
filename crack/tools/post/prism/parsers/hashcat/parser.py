"""
Hashcat Potfile Parser

Parses cracked hashes from hashcat potfile output:
- Format: hash:password (one per line)
- Supports all common hash types (MD5, SHA1, NTLM, SHA256, SHA512, etc.)
- Detects hash type from length and format

Common hash lengths:
- MD5/NTLM: 32 hex chars
- SHA1: 40 hex chars
- SHA256: 64 hex chars
- SHA512: 128 hex chars
"""

import re
from typing import Optional, List, Tuple
from pathlib import Path

from ..base import PrismParser
from ..registry import PrismParserRegistry
from ...models import ParsedSummary, Credential, CredentialType


# Hash type detection by length and format
HASH_PATTERNS = {
    # MD5 (32 hex)
    'md5': re.compile(r'^[a-fA-F0-9]{32}$'),
    # NTLM (32 hex, same as MD5 but context determines)
    'ntlm': re.compile(r'^[a-fA-F0-9]{32}$'),
    # SHA1 (40 hex)
    'sha1': re.compile(r'^[a-fA-F0-9]{40}$'),
    # SHA256 (64 hex)
    'sha256': re.compile(r'^[a-fA-F0-9]{64}$'),
    # SHA512 (128 hex)
    'sha512': re.compile(r'^[a-fA-F0-9]{128}$'),
    # bcrypt ($2a$, $2b$, $2y$)
    'bcrypt': re.compile(r'^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$'),
    # Linux SHA256 crypt ($5$)
    'sha256crypt': re.compile(r'^\$5\$[^$]+\$[./A-Za-z0-9]{43}$'),
    # Linux SHA512 crypt ($6$)
    'sha512crypt': re.compile(r'^\$6\$[^$]+\$[./A-Za-z0-9]{86}$'),
    # Linux yescrypt ($y$)
    'yescrypt': re.compile(r'^\$y\$[^$]+\$[^$]+\$[A-Za-z0-9./]+$'),
    # MD5 crypt ($1$)
    'md5crypt': re.compile(r'^\$1\$[^$]+\$[./A-Za-z0-9]{22}$'),
    # NTLM in SAM format (user:rid:lm:nt:::)
    'sam_hash': re.compile(r'^[^:]+:\d+:[a-fA-F0-9]{32}:[a-fA-F0-9]{32}:::$'),
}

# Potfile detection pattern (hash:password format with hex hash)
POTFILE_LINE = re.compile(r'^[a-fA-F0-9]{32,}:.+$')
POTFILE_LINE_CRYPT = re.compile(r'^\$[0-9a-zy]+\$[^:]+:.+$')


@PrismParserRegistry.register
class HashcatPotfileParser(PrismParser):
    """Parser for hashcat potfile output (cracked passwords)"""

    @property
    def name(self) -> str:
        return "hashcat"

    @property
    def description(self) -> str:
        return "Hashcat potfile parser (cracked passwords)"

    def can_parse(self, filepath: str) -> bool:
        """Detect hashcat potfile by extension or content pattern"""
        if not self.validate_file(filepath):
            return False

        path = Path(filepath)

        # Check extension first (fast path)
        if path.suffix.lower() == '.potfile':
            return True

        # Check content pattern
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read(4096)

            # Count lines matching potfile format
            lines = content.strip().split('\n')[:20]
            potfile_lines = 0

            for line in lines:
                line = line.strip()
                if not line:
                    continue

                # Check for hash:password format
                if POTFILE_LINE.match(line) or POTFILE_LINE_CRYPT.match(line):
                    potfile_lines += 1

            # If at least 3 lines match, likely a potfile
            return potfile_lines >= 3

        except Exception:
            return False

    def parse(self, filepath: str, hostname: Optional[str] = None) -> ParsedSummary:
        """Parse hashcat potfile

        Args:
            filepath: Path to potfile
            hostname: Optional source hostname hint

        Returns:
            ParsedSummary with cracked password credentials
        """
        content = self.read_file(filepath)

        summary = ParsedSummary(
            source_file=filepath,
            source_tool='hashcat',
            lines_parsed=len(content.splitlines()),
        )

        credentials = self._parse_potfile(content)
        summary.credentials.extend(credentials)

        self.set_hostname(summary, None, hostname)

        return summary.deduplicate()

    def _parse_potfile(self, content: str) -> List[Credential]:
        """Parse potfile content (hash:password per line)"""
        credentials = []
        seen = set()

        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Split on last colon to handle passwords with colons
            # Format: hash:password
            parts = line.rsplit(':', 1)
            if len(parts) != 2:
                continue

            hash_value, password = parts

            # Skip empty passwords
            if not password:
                continue

            # Detect hash type
            hash_type = self._detect_hash_type(hash_value)

            # Create dedup key
            key = (hash_value.lower(), password)
            if key in seen:
                continue
            seen.add(key)

            # Try to extract username from hash if in SAM format
            username, domain = self._extract_user_from_hash(hash_value)

            cred = Credential(
                username=username,
                domain=domain,
                cred_type=CredentialType.CRACKED_PASSWORD,
                value=password,
                first_seen_line=line_num,
            )
            credentials.append(cred)

        return credentials

    def _detect_hash_type(self, hash_value: str) -> str:
        """Detect hash type from format and length"""
        # Check crypt-style hashes first
        if hash_value.startswith('$'):
            if hash_value.startswith('$6$'):
                return 'sha512crypt'
            elif hash_value.startswith('$5$'):
                return 'sha256crypt'
            elif hash_value.startswith('$1$'):
                return 'md5crypt'
            elif hash_value.startswith('$y$'):
                return 'yescrypt'
            elif hash_value.startswith('$2'):
                return 'bcrypt'
            else:
                return 'crypt'

        # Check SAM format
        if HASH_PATTERNS['sam_hash'].match(hash_value):
            return 'sam_hash'

        # Check by length for raw hex hashes
        hash_len = len(hash_value)

        if hash_len == 32:
            return 'md5_or_ntlm'  # Cannot distinguish without context
        elif hash_len == 40:
            return 'sha1'
        elif hash_len == 64:
            return 'sha256'
        elif hash_len == 128:
            return 'sha512'
        else:
            return 'unknown'

    def _extract_user_from_hash(self, hash_value: str) -> Tuple[str, str]:
        """Try to extract username from hash string

        SAM format: user:rid:lm:nt:::
        Returns (username, domain)
        """
        # Check SAM format
        if ':' in hash_value and ':::' in hash_value:
            parts = hash_value.split(':')
            if len(parts) >= 4:
                full_user = parts[0]

                # Parse DOMAIN\user format
                if '\\' in full_user:
                    domain, username = full_user.split('\\', 1)
                    return username, domain

                return full_user, ""

        # No embedded username
        return "cracked", ""
