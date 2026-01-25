"""
Linux Shadow File Parser

Parses /etc/shadow format files:
- Format: username:$algo$salt$hash:lastchg:min:max:warn:inactive:expire:reserved
- Supports hash algorithms: $1$ (MD5), $5$ (SHA256), $6$ (SHA512), $y$ (yescrypt), $2a$/$2b$ (bcrypt)
- Skips locked accounts (password field starts with ! or *)
- Skips accounts with no password (empty or :: pattern)

Shadow file format reference:
- Field 1: Username
- Field 2: Password hash (or !, *, !!, empty)
- Fields 3-9: Age/expiry info (integers or empty)
"""

import re
from typing import Optional, List, Tuple
from pathlib import Path

from ..base import PrismParser
from ..registry import PrismParserRegistry
from ...models import ParsedSummary, Credential, CredentialType


# Shadow hash patterns for detection
SHADOW_HASH_PATTERNS = [
    r'\$1\$',      # MD5 crypt
    r'\$5\$',      # SHA256 crypt
    r'\$6\$',      # SHA512 crypt
    r'\$y\$',      # yescrypt (modern default)
    r'\$2a\$',     # bcrypt
    r'\$2b\$',     # bcrypt
    r'\$2y\$',     # bcrypt
]

# Combined detection regex
SHADOW_HASH_DETECT = re.compile('|'.join(SHADOW_HASH_PATTERNS))

# Hash algorithm names for display
HASH_ALGO_NAMES = {
    '$1$': 'MD5-crypt',
    '$5$': 'SHA256-crypt',
    '$6$': 'SHA512-crypt',
    '$y$': 'yescrypt',
    '$2a$': 'bcrypt',
    '$2b$': 'bcrypt',
    '$2y$': 'bcrypt',
}

# Locked account indicators
LOCKED_PATTERNS = frozenset(['!', '*', '!!', '!*'])


@PrismParserRegistry.register
class ShadowParser(PrismParser):
    """Parser for Linux /etc/shadow files"""

    @property
    def name(self) -> str:
        return "shadow"

    @property
    def description(self) -> str:
        return "Linux /etc/shadow hash parser"

    def can_parse(self, filepath: str) -> bool:
        """Detect shadow file by content patterns"""
        if not self.validate_file(filepath):
            return False

        path = Path(filepath)

        # Check filename hint (fast path)
        if path.name == 'shadow' or path.name.endswith('.shadow'):
            return True

        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read(4096)

            # Check for shadow hash patterns
            if not SHADOW_HASH_DETECT.search(content):
                return False

            # Validate shadow file structure (9 colon-separated fields)
            lines = content.strip().split('\n')[:20]
            shadow_lines = 0

            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                parts = line.split(':')
                # Shadow files have exactly 9 fields (some may be empty)
                if len(parts) == 9:
                    # Field 2 should be a hash or lock indicator
                    password_field = parts[1]
                    if (SHADOW_HASH_DETECT.search(password_field) or
                            password_field in LOCKED_PATTERNS or
                            password_field == ''):
                        shadow_lines += 1

            # If at least 2 valid lines, likely a shadow file
            return shadow_lines >= 2

        except Exception:
            return False

    def parse(self, filepath: str, hostname: Optional[str] = None) -> ParsedSummary:
        """Parse shadow file

        Args:
            filepath: Path to shadow file
            hostname: Optional source hostname hint

        Returns:
            ParsedSummary with Linux hash credentials
        """
        content = self.read_file(filepath)

        summary = ParsedSummary(
            source_file=filepath,
            source_tool='shadow',
            lines_parsed=len(content.splitlines()),
        )

        credentials = self._parse_shadow(content)
        summary.credentials.extend(credentials)

        self.set_hostname(summary, None, hostname)

        return summary.deduplicate()

    def _parse_shadow(self, content: str) -> List[Credential]:
        """Parse shadow file content"""
        credentials = []
        seen = set()

        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.split(':')

            # Shadow files have exactly 9 fields
            if len(parts) != 9:
                continue

            username = parts[0]
            password_hash = parts[1]

            # Skip locked accounts (!, *, !!, etc.)
            if password_hash in LOCKED_PATTERNS or password_hash.startswith('!'):
                continue

            # Skip empty passwords
            if not password_hash or password_hash == '':
                continue

            # Skip accounts without valid hash
            if not SHADOW_HASH_DETECT.search(password_hash):
                continue

            # Dedup key
            key = (username.lower(), password_hash)
            if key in seen:
                continue
            seen.add(key)

            # Detect hash algorithm
            algo = self._detect_algorithm(password_hash)

            cred = Credential(
                username=username,
                domain="",  # Linux systems don't have Windows domains
                cred_type=CredentialType.LINUX_HASH,
                value=password_hash,
                first_seen_line=line_num,
                session_type=algo,  # Store algorithm info in session_type
            )
            credentials.append(cred)

        return credentials

    def _detect_algorithm(self, hash_value: str) -> str:
        """Detect hash algorithm from prefix"""
        for prefix, name in HASH_ALGO_NAMES.items():
            if hash_value.startswith(prefix):
                return name
        return "unknown"
