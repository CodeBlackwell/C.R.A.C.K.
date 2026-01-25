"""
CrackMapExec Parser

Parses credential spray results from CrackMapExec (CME) and NetExec:
- Successful authentications: [+] markers
- Failed attempts: [-] markers
- Informational: [*] markers

Supported protocols: SMB, WinRM, LDAP, MSSQL, SSH, RDP

Output formats:
- SMB: SMB 10.10.10.5 445 DC01 [+] DOMAIN\\user:password
- Hash auth: SMB 10.10.10.5 445 DC01 [+] DOMAIN\\user:NTLM_HASH (Pwn3d!)
- WinRM: WINRM 10.10.10.5 5985 DC01 [+] DOMAIN\\user:password
"""

import re
from typing import Optional, List, Tuple
from pathlib import Path

from ..base import PrismParser
from ..registry import PrismParserRegistry
from ...models import ParsedSummary, Credential, CredentialType


# Regex patterns for CME output
PATTERNS = {
    # Generic CME success line: PROTOCOL IP PORT HOST [+] DOMAIN\\user:credential
    # Examples:
    #   SMB 10.10.10.5 445 DC01 [+] CORP\\admin:Password123
    #   SMB 10.10.10.5 445 DC01 [+] CORP\\admin:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
    'cme_success': re.compile(
        r'^(SMB|WINRM|LDAP|MSSQL|SSH|RDP|FTP|WMIC)\s+'
        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+'
        r'(\d+)\s+'
        r'(\S+)\s+'
        r'\[\+\]\s+'
        r'([^\\]+)\\([^:]+):(.+?)(?:\s+\(.*\))?\s*$',
        re.IGNORECASE | re.MULTILINE
    ),
    # CME success without domain: [+] user:password
    'cme_success_no_domain': re.compile(
        r'^(SMB|WINRM|LDAP|MSSQL|SSH|RDP|FTP|WMIC)\s+'
        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+'
        r'(\d+)\s+'
        r'(\S+)\s+'
        r'\[\+\]\s+'
        r'([^:\\]+):(.+?)(?:\s+\(.*\))?\s*$',
        re.IGNORECASE | re.MULTILINE
    ),
    # CME markers for detection
    'cme_marker': re.compile(
        r'^\s*(SMB|WINRM|LDAP|MSSQL|SSH|RDP|FTP|WMIC)\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d+\s+\S+\s+\[[\+\*\-]\]',
        re.IGNORECASE | re.MULTILINE
    ),
    # Pwn3d! marker indicates admin access
    'pwned': re.compile(r'\(Pwn3d!\)', re.IGNORECASE),
    # NTLM hash pattern (32 hex chars or LM:NT format)
    'ntlm_hash': re.compile(r'^[a-fA-F0-9]{32}$'),
    'lm_nt_hash': re.compile(r'^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$'),
}


@PrismParserRegistry.register
class CrackMapExecParser(PrismParser):
    """Parser for CrackMapExec/NetExec credential spray output"""

    @property
    def name(self) -> str:
        return "crackmapexec"

    @property
    def description(self) -> str:
        return "CrackMapExec/NetExec credential spray parser"

    def can_parse(self, filepath: str) -> bool:
        """Detect CME output by content patterns"""
        if not self.validate_file(filepath):
            return False

        try:
            # Check filename hints
            filename = Path(filepath).name.lower()
            if any(hint in filename for hint in ['cme', 'crackmapexec', 'netexec', 'nxc']):
                return True

            with open(filepath, 'r', errors='ignore') as f:
                content = f.read(8192)

            # Look for CME output pattern: PROTOCOL IP PORT HOST [status]
            return PATTERNS['cme_marker'].search(content) is not None

        except Exception:
            return False

    def parse(self, filepath: str, hostname: Optional[str] = None) -> ParsedSummary:
        """Parse CrackMapExec output file

        Args:
            filepath: Path to CME output file
            hostname: Optional source hostname hint

        Returns:
            ParsedSummary with extracted credentials
        """
        content = self.read_file(filepath)

        summary = ParsedSummary(
            source_file=filepath,
            source_tool='crackmapexec',
            lines_parsed=len(content.splitlines()),
        )

        # Parse successful authentications
        credentials = self._parse_successes(content)
        summary.credentials.extend(credentials)

        # Infer domain from credentials
        if summary.credentials and not summary.source_domain:
            for cred in summary.credentials:
                if cred.domain and cred.domain.upper() not in ('WORKGROUP', '.'):
                    summary.source_domain = cred.domain.upper()
                    break

        self.set_hostname(summary, None, hostname)

        return summary.deduplicate()

    def _parse_successes(self, content: str) -> List[Credential]:
        """Parse successful authentication lines"""
        credentials = []
        seen = set()

        # Parse lines with domain prefix
        for match in PATTERNS['cme_success'].finditer(content):
            protocol, target_ip, port, host, domain, username, cred_value = match.groups()
            full_line = match.group(0)

            # Determine credential type
            cred_type = self._determine_cred_type(cred_value)

            # Clean credential value (remove trailing notes)
            cred_value = cred_value.strip()

            # Create dedup key
            key = (domain.lower(), username.lower(), cred_value.lower())
            if key in seen:
                continue
            seen.add(key)

            cred = Credential(
                username=username.strip(),
                domain=domain.strip().upper(),
                cred_type=cred_type,
                value=cred_value,
                logon_server=target_ip,
            )
            credentials.append(cred)

        # Parse lines without domain prefix
        for match in PATTERNS['cme_success_no_domain'].finditer(content):
            protocol, target_ip, port, host, username, cred_value = match.groups()

            # Skip if already captured with domain
            cred_type = self._determine_cred_type(cred_value)
            cred_value = cred_value.strip()

            key = ('', username.lower(), cred_value.lower())
            if key in seen:
                continue
            seen.add(key)

            cred = Credential(
                username=username.strip(),
                domain='',
                cred_type=cred_type,
                value=cred_value,
                logon_server=target_ip,
            )
            credentials.append(cred)

        return credentials

    def _determine_cred_type(self, cred_value: str) -> CredentialType:
        """Determine if credential is cleartext or NTLM hash"""
        cred_value = cred_value.strip()

        # LM:NT hash format (64 hex chars with colon)
        if PATTERNS['lm_nt_hash'].match(cred_value):
            return CredentialType.NTLM

        # Single 32-char hex string (NT hash only)
        if PATTERNS['ntlm_hash'].match(cred_value):
            return CredentialType.NTLM

        # Otherwise treat as cleartext
        return CredentialType.CLEARTEXT
