"""
Kerbrute Parser

Parses password spray and user enumeration results from kerbrute:
- Valid logins from passwordspray
- Valid usernames from userenum
- Bruteforce results

Output formats:
- Valid login: [+] VALID LOGIN: username@DOMAIN.COM:password
- Valid user: [+] VALID USERNAME: username@DOMAIN.COM
- Bruteforce: [+] VALID LOGIN: username@DOMAIN.COM:password

kerbrute is a Kerberos authentication testing tool that performs:
- User enumeration via AS-REQ
- Password spraying via Kerberos pre-auth
- Brute force attacks
"""

import re
from typing import Optional, List
from pathlib import Path

from ..base import PrismParser
from ..registry import PrismParserRegistry
from ...models import ParsedSummary, Credential, CredentialType


# Regex patterns for kerbrute output
PATTERNS = {
    # Valid login: [+] VALID LOGIN:	user@DOMAIN.COM:password
    # Note: kerbrute uses tabs, but we match any whitespace
    'valid_login': re.compile(
        r'\[\+\]\s*VALID\s+LOGIN:\s*([^@\s]+)@([^:\s]+):(.+?)\s*$',
        re.IGNORECASE | re.MULTILINE
    ),
    # Valid username (from userenum): [+] VALID USERNAME:	user@DOMAIN.COM
    'valid_user': re.compile(
        r'\[\+\]\s*VALID\s+USERNAME:\s*([^@\s]+)@([^\s]+)\s*$',
        re.IGNORECASE | re.MULTILINE
    ),
    # Kerbrute markers for detection
    'kerbrute_marker': re.compile(
        r'kerbrute|VALID\s+LOGIN:|VALID\s+USERNAME:|Kerberos\s+Pre-Auth',
        re.IGNORECASE
    ),
    # Banner line
    'kerbrute_banner': re.compile(
        r'__\s*_\s*__\s*.*kerbrute',
        re.IGNORECASE | re.DOTALL
    ),
    # Version/tool identifier
    'kerbrute_version': re.compile(
        r'Version:\s*v?\d+\.\d+',
        re.IGNORECASE
    ),
    # Summary line
    'kerbrute_summary': re.compile(
        r'\[\+\]\s+Done!.*tested',
        re.IGNORECASE
    ),
}


@PrismParserRegistry.register
class KerbruteParser(PrismParser):
    """Parser for kerbrute password spray and enumeration output"""

    @property
    def name(self) -> str:
        return "kerbrute"

    @property
    def description(self) -> str:
        return "Kerbrute password spray and user enumeration parser"

    def can_parse(self, filepath: str) -> bool:
        """Detect kerbrute output by content patterns"""
        if not self.validate_file(filepath):
            return False

        try:
            # Check filename hints
            filename = Path(filepath).name.lower()
            if 'kerbrute' in filename:
                return True

            with open(filepath, 'r', errors='ignore') as f:
                content = f.read(8192)

            # Check for kerbrute-specific markers
            checks = [
                PATTERNS['valid_login'].search(content),
                PATTERNS['valid_user'].search(content),
                PATTERNS['kerbrute_banner'].search(content),
                PATTERNS['kerbrute_version'].search(content),
                'kerbrute' in content.lower(),
            ]

            return any(checks)

        except Exception:
            return False

    def parse(self, filepath: str, hostname: Optional[str] = None) -> ParsedSummary:
        """Parse kerbrute output file

        Args:
            filepath: Path to kerbrute output file
            hostname: Optional source hostname hint

        Returns:
            ParsedSummary with extracted credentials
        """
        content = self.read_file(filepath)

        summary = ParsedSummary(
            source_file=filepath,
            source_tool='kerbrute',
            lines_parsed=len(content.splitlines()),
        )

        # Parse valid logins (with passwords)
        credentials = self._parse_valid_logins(content)
        summary.credentials.extend(credentials)

        # Infer domain from credentials
        if summary.credentials and not summary.source_domain:
            for cred in summary.credentials:
                if cred.domain:
                    summary.source_domain = cred.domain.upper()
                    break

        summary.source_hostname = hostname or ""

        return summary.deduplicate()

    def _parse_valid_logins(self, content: str) -> List[Credential]:
        """Parse valid login lines with credentials"""
        credentials = []
        seen = set()

        for match in PATTERNS['valid_login'].finditer(content):
            username, domain, password = match.groups()

            # Clean up values
            username = username.strip()
            domain = domain.strip().upper()
            password = password.strip()

            # Skip empty passwords
            if not password:
                continue

            # Dedup key
            key = (username.lower(), domain.lower(), password)
            if key in seen:
                continue
            seen.add(key)

            cred = Credential(
                username=username,
                domain=domain,
                cred_type=CredentialType.CLEARTEXT,
                value=password,
            )
            credentials.append(cred)

        return credentials
