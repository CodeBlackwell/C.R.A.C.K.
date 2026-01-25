"""
SSH Private Key Parser

Identifies and extracts information from SSH private key files.

Supported formats:
- RSA private keys (-----BEGIN RSA PRIVATE KEY-----)
- OpenSSH format keys (-----BEGIN OPENSSH PRIVATE KEY-----)
- EC private keys (-----BEGIN EC PRIVATE KEY-----)
- DSA private keys (-----BEGIN DSA PRIVATE KEY-----)
- Generic private keys (-----BEGIN PRIVATE KEY-----)
- Encrypted variants (ENCRYPTED marker or Proc-Type: 4,ENCRYPTED)

Detection:
- File extensions: .pem, .key, id_rsa, id_ed25519, id_ecdsa, id_dsa
- PEM headers in content
"""

import re
import hashlib
from typing import Optional, List
from pathlib import Path

from ..base import PrismParser
from ..registry import PrismParserRegistry
from ...models import ParsedSummary, Credential, CredentialType


# SSH key file name patterns (exact matches or patterns)
SSH_KEY_FILENAMES = frozenset([
    'id_rsa',
    'id_ed25519',
    'id_ecdsa',
    'id_dsa',
    'id_rsa_root',
    'id_ed25519_root',
])

# Extensions that commonly contain SSH keys
SSH_KEY_EXTENSIONS = frozenset([
    '.pem',
    '.key',
    '.ppk',
])

# PEM header patterns for SSH private keys
PEM_HEADERS = [
    re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----'),
    re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----'),  # Also valuable
]

# Pattern to detect encrypted keys
ENCRYPTED_PATTERNS = [
    re.compile(r'Proc-Type:\s*4,ENCRYPTED', re.IGNORECASE),
    re.compile(r'-----BEGIN ENCRYPTED PRIVATE KEY-----'),
    re.compile(r'DEK-Info:', re.IGNORECASE),
]


@PrismParserRegistry.register
class SSHKeyParser(PrismParser):
    """Parser for SSH private key files"""

    @property
    def name(self) -> str:
        return "sshkey"

    @property
    def description(self) -> str:
        return "SSH private key parser (id_rsa, id_ed25519, .pem, .key files)"

    def can_parse(self, filepath: str) -> bool:
        """Detect SSH private key files by filename or content"""
        if not self.validate_file(filepath):
            return False

        path = Path(filepath)
        filename = path.name.lower()
        stem = path.stem.lower()

        # Check by filename (exact match)
        if filename in SSH_KEY_FILENAMES or stem in SSH_KEY_FILENAMES:
            return True

        # Check by extension
        if path.suffix.lower() in SSH_KEY_EXTENSIONS:
            # Verify it's actually a private key by checking content
            try:
                with open(filepath, 'r', errors='ignore') as f:
                    content = f.read(1024)
                return any(pattern.search(content) for pattern in PEM_HEADERS)
            except Exception:
                return False

        # Check content for PEM headers in any file
        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read(1024)
            return any(pattern.search(content) for pattern in PEM_HEADERS)
        except Exception:
            return False

    def parse(self, filepath: str, hostname: Optional[str] = None) -> ParsedSummary:
        """Parse SSH private key file

        Args:
            filepath: Path to SSH key file
            hostname: Optional source hostname hint

        Returns:
            ParsedSummary with extracted key credential
        """
        content = self.read_file(filepath)
        path = Path(filepath)

        summary = ParsedSummary(
            source_file=filepath,
            source_tool='sshkey',
            lines_parsed=len(content.splitlines()),
        )

        # Extract key information
        key_type = self._detect_key_type(content)
        is_encrypted = self._is_encrypted(content)
        key_fingerprint = self._compute_fingerprint(content)

        # Determine username from filepath or filename
        username = self._infer_username(filepath)

        # Create credential
        # Value is a summary: type, encrypted status, and fingerprint/preview
        if is_encrypted:
            value_summary = f"[ENCRYPTED {key_type}] {key_fingerprint}"
        else:
            value_summary = f"[{key_type}] {key_fingerprint}"

        credential = Credential(
            username=username,
            domain=hostname or self._infer_host_from_path(filepath),
            cred_type=CredentialType.SSH_KEY,
            value=value_summary,
        )

        summary.credentials.append(credential)
        summary.source_hostname = hostname or ""

        return summary

    def _detect_key_type(self, content: str) -> str:
        """Detect the type of SSH key"""
        if '-----BEGIN RSA PRIVATE KEY-----' in content:
            return 'RSA'
        elif '-----BEGIN OPENSSH PRIVATE KEY-----' in content:
            # OpenSSH format can contain various key types
            # Check for algorithm hints
            if 'ed25519' in content.lower():
                return 'ED25519'
            elif 'ecdsa' in content.lower():
                return 'ECDSA'
            return 'OPENSSH'
        elif '-----BEGIN EC PRIVATE KEY-----' in content:
            return 'EC'
        elif '-----BEGIN DSA PRIVATE KEY-----' in content:
            return 'DSA'
        elif '-----BEGIN ENCRYPTED PRIVATE KEY-----' in content:
            return 'ENCRYPTED-PKCS8'
        elif '-----BEGIN PRIVATE KEY-----' in content:
            return 'PKCS8'
        elif '-----BEGIN PGP PRIVATE KEY BLOCK-----' in content:
            return 'PGP'
        return 'UNKNOWN'

    def _is_encrypted(self, content: str) -> bool:
        """Check if the private key is encrypted"""
        # Check for encryption markers
        for pattern in ENCRYPTED_PATTERNS:
            if pattern.search(content):
                return True

        # PKCS#8 encrypted format
        if '-----BEGIN ENCRYPTED PRIVATE KEY-----' in content:
            return True

        return False

    def _compute_fingerprint(self, content: str) -> str:
        """Compute a fingerprint/identifier for the key

        For display purposes, we hash the key content to create
        a short identifier without exposing the full key.
        """
        # Extract just the key body (between headers)
        lines = content.strip().split('\n')
        key_lines = []
        in_key = False

        for line in lines:
            if line.startswith('-----BEGIN'):
                in_key = True
                continue
            elif line.startswith('-----END'):
                break
            elif in_key and not line.startswith('Proc-Type') and not line.startswith('DEK-Info'):
                key_lines.append(line.strip())

        if key_lines:
            key_body = ''.join(key_lines)
            # Create short hash of key body
            key_hash = hashlib.sha256(key_body.encode()).hexdigest()[:16]
            return f"SHA256:{key_hash}"

        return "INVALID_KEY"

    def _infer_username(self, filepath: str) -> str:
        """Infer username from filepath

        Common patterns:
        - /home/username/.ssh/id_rsa -> username
        - /root/.ssh/id_rsa -> root
        - /path/to/username_id_rsa -> username
        """
        path = Path(filepath)
        parts = path.parts

        # Check for /home/username/.ssh pattern
        for i, part in enumerate(parts):
            if part == 'home' and i + 1 < len(parts):
                return parts[i + 1]
            if part == 'root':
                return 'root'
            if part == 'Users' and i + 1 < len(parts):  # Windows path
                return parts[i + 1]

        # Check for username in filename (e.g., john_id_rsa, id_rsa_admin)
        stem = path.stem.lower()
        for key_name in ['id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa']:
            if key_name in stem:
                # Extract prefix or suffix as potential username
                remaining = stem.replace(key_name, '').strip('_-')
                if remaining and remaining not in ['root', 'backup']:
                    return remaining

        return 'unknown'

    def _infer_host_from_path(self, filepath: str) -> str:
        """Try to infer hostname from file path"""
        path = Path(filepath)

        # Check for hostname patterns in path
        # e.g., /loot/192.168.1.100/id_rsa or /targets/webserver/keys/
        for part in path.parts:
            # IP address pattern
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', part):
                return part
            # Hostname-like pattern (not common path names)
            if re.match(r'^[a-zA-Z][a-zA-Z0-9-]+[a-zA-Z0-9]$', part):
                if part.lower() not in ['home', 'root', 'ssh', 'keys', 'loot', 'targets', 'users', 'tmp', 'var']:
                    return part

        return ""
