"""
Apache Htpasswd Parser

Extracts usernames and password hashes from .htpasswd files.

Supported hash formats:
- APR1 ($apr1$salt$hash) - Apache-specific MD5
- Bcrypt ($2y$..., $2a$..., $2b$...) - Secure bcrypt
- SHA1 ({SHA}base64hash) - SHA1 (deprecated)
- Crypt (13-char DES crypt) - Legacy DES
- MD5 crypt ($1$salt$hash) - MD5 crypt
- Plain (no prefix, not recommended) - Plaintext

Detection:
- Filename: .htpasswd, htpasswd, passwd.txt, .htdigest
- Content: Lines with username:hash format using APR1/bcrypt patterns
"""

import re
from typing import Optional, List
from pathlib import Path

from ..base import PrismParser
from ..registry import PrismParserRegistry
from ...models import ParsedSummary, Credential, CredentialType


# Htpasswd filename patterns
HTPASSWD_FILENAMES = frozenset([
    '.htpasswd',
    'htpasswd',
    '.htdigest',
    'htdigest',
])

# Hash format patterns
HASH_PATTERNS = {
    'apr1': re.compile(r'^\$apr1\$[^\$]+\$[a-zA-Z0-9./]+$'),
    'bcrypt': re.compile(r'^\$2[aby]\$\d{2}\$[a-zA-Z0-9./]{53}$'),
    'sha1': re.compile(r'^{SHA}[a-zA-Z0-9+/=]{28}$'),
    'md5crypt': re.compile(r'^\$1\$[^\$]+\$[a-zA-Z0-9./]+$'),
    'sha256crypt': re.compile(r'^\$5\$[^\$]+\$[a-zA-Z0-9./]+$'),
    'sha512crypt': re.compile(r'^\$6\$[^\$]+\$[a-zA-Z0-9./]+$'),
    'des': re.compile(r'^[a-zA-Z0-9./]{13}$'),
}

# Content detection pattern - matches typical htpasswd lines
HTPASSWD_LINE_PATTERN = re.compile(
    r'^[a-zA-Z0-9._@-]+:'  # username
    r'(?:'
    r'\$apr1\$|'          # APR1
    r'\$2[aby]\$|'        # bcrypt
    r'{SHA}|'             # SHA1
    r'\$1\$|'             # MD5 crypt
    r'\$5\$|'             # SHA256 crypt
    r'\$6\$'              # SHA512 crypt
    r')',
    re.MULTILINE
)


@PrismParserRegistry.register
class HtpasswdParser(PrismParser):
    """Parser for Apache .htpasswd files"""

    @property
    def name(self) -> str:
        return "htpasswd"

    @property
    def description(self) -> str:
        return "Apache .htpasswd password hash parser (APR1, bcrypt, SHA1)"

    def can_parse(self, filepath: str) -> bool:
        """Detect htpasswd files by filename or content"""
        if not self.validate_file(filepath):
            return False

        path = Path(filepath)
        filename = path.name.lower()

        # Check by filename
        if filename in HTPASSWD_FILENAMES:
            return True

        # Check for passwd in filename
        if 'passwd' in filename and path.suffix.lower() in ['', '.txt', '.bak', '.old']:
            # Verify content
            try:
                with open(filepath, 'r', errors='ignore') as f:
                    content = f.read(2048)
                return bool(HTPASSWD_LINE_PATTERN.search(content))
            except Exception:
                return False

        # Check content for htpasswd patterns
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read(2048)

            # Must have at least one valid htpasswd line
            return bool(HTPASSWD_LINE_PATTERN.search(content))
        except Exception:
            return False

    def parse(self, filepath: str, hostname: Optional[str] = None) -> ParsedSummary:
        """Parse htpasswd file and extract credentials

        Args:
            filepath: Path to htpasswd file
            hostname: Optional source hostname hint

        Returns:
            ParsedSummary with extracted credentials
        """
        content = self.read_file(filepath)
        path = Path(filepath)

        summary = ParsedSummary(
            source_file=filepath,
            source_tool='htpasswd',
            lines_parsed=len(content.splitlines()),
        )

        credentials = self._extract_credentials(content, filepath)
        summary.credentials.extend(credentials)

        # Try to infer domain/host from path
        summary.source_hostname = hostname or self._infer_host_from_path(filepath)
        summary.source_domain = self._infer_domain_from_path(filepath)

        return summary.deduplicate()

    def _extract_credentials(self, content: str, filepath: str) -> List[Credential]:
        """Extract all credentials from htpasswd content"""
        credentials = []

        for line_num, line in enumerate(content.splitlines(), 1):
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith('#'):
                continue

            # Parse username:hash format
            if ':' not in line:
                continue

            parts = line.split(':', 1)
            if len(parts) != 2:
                continue

            username, hash_value = parts
            username = username.strip()
            hash_value = hash_value.strip()

            # Validate username (basic sanity check)
            if not username or not re.match(r'^[a-zA-Z0-9._@-]+$', username):
                continue

            # Validate and identify hash type
            hash_type = self._identify_hash_type(hash_value)
            if not hash_type:
                continue

            credential = Credential(
                username=username,
                domain="",  # htpasswd is typically local
                cred_type=CredentialType.HTPASSWD_HASH,
                value=hash_value,
                first_seen_line=line_num,
            )

            credentials.append(credential)

        return credentials

    def _identify_hash_type(self, hash_value: str) -> Optional[str]:
        """Identify the hash type and validate format

        Returns hash type name or None if invalid
        """
        if not hash_value:
            return None

        # Check each known pattern
        for hash_type, pattern in HASH_PATTERNS.items():
            if pattern.match(hash_value):
                return hash_type

        # Check for plaintext (no special format, but valid ASCII)
        # This is insecure but some old htpasswd files have it
        if re.match(r'^[a-zA-Z0-9!@#$%^&*()_+=\[\]{}|;:,.<>?/-]+$', hash_value):
            if len(hash_value) < 50:  # Reasonable password length
                return 'plaintext'

        return None

    def _infer_host_from_path(self, filepath: str) -> str:
        """Try to infer hostname from file path

        Common patterns:
        - /var/www/sitename/.htpasswd
        - /etc/apache2/sites/domain.com/.htpasswd
        """
        path = Path(filepath)

        # Look for domain-like names in path
        for part in path.parts:
            # Check for domain pattern (contains dot, not a file extension)
            if '.' in part and not part.startswith('.'):
                if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', part):
                    return part

            # Check for IP address
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', part):
                return part

        # Check for www directory structure
        for i, part in enumerate(path.parts):
            if part == 'www' and i + 1 < len(path.parts):
                next_part = path.parts[i + 1]
                if next_part not in ['html', 'public', 'cgi-bin', 'data']:
                    return next_part

        return ""

    def _infer_domain_from_path(self, filepath: str) -> str:
        """Try to infer domain from file path

        Look for virtual host or site configurations
        """
        path = Path(filepath)

        # Look for sites-enabled, vhosts patterns
        for i, part in enumerate(path.parts):
            if part in ['sites-enabled', 'sites-available', 'vhosts']:
                if i + 1 < len(path.parts):
                    site_name = path.parts[i + 1]
                    # Remove .conf extension if present
                    if site_name.endswith('.conf'):
                        site_name = site_name[:-5]
                    return site_name

        return ""
