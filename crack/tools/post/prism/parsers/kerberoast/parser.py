"""
Kerberoast Parser

Parses Kerberos TGS hashes from various sources:
- GetUserSPNs.py (Impacket) - both stdout and -outputfile
- Rubeus kerberoast command output
- Raw hashcat-compatible $krb5tgs$ files
- AS-REP roast ($krb5asrep$) hashes

Hash formats:
- krb5tgs$23$*user$realm$spn*$... (hashcat mode 13100)
- krb5asrep$23$user@realm:hash... (hashcat mode 18200)
"""

import re
from typing import Optional, List, Tuple
from pathlib import Path

from ..base import PrismParser
from ..registry import PrismParserRegistry
from ...models import ParsedSummary, Credential, CredentialType


# Regex patterns for Kerberos hashes
PATTERNS = {
    # $krb5tgs$23$*user$realm$spn*$hash...
    'krb5tgs': re.compile(
        r'\$krb5tgs\$(\d+)\$\*?([^$*]+)\$([^$*]+)\$([^$*]+)\*?\$([a-fA-F0-9$]+)',
        re.IGNORECASE
    ),
    # $krb5asrep$23$user@REALM:hash...
    'krb5asrep': re.compile(
        r'\$krb5asrep\$(\d+)\$([^@:]+)@([^:]+):([a-fA-F0-9$]+)',
        re.IGNORECASE
    ),
    # GetUserSPNs.py table header
    'getuserspns_header': re.compile(
        r'ServicePrincipalName\s+Name\s+MemberOf',
        re.IGNORECASE
    ),
    # Rubeus kerberoast markers
    'rubeus_kerberoast': re.compile(
        r'\[\*\]\s*SamAccountName\s*:\s*(\S+)',
        re.IGNORECASE
    ),
    'rubeus_hash': re.compile(
        r'\[\*\]\s*Hash\s*:\s*(\$krb5tgs\$.+)',
        re.IGNORECASE
    ),
    # Simple detection of TGS hash lines
    'tgs_hash_line': re.compile(r'^\$krb5tgs\$', re.IGNORECASE | re.MULTILINE),
    'asrep_hash_line': re.compile(r'^\$krb5asrep\$', re.IGNORECASE | re.MULTILINE),
}


@PrismParserRegistry.register
class KerberoastParser(PrismParser):
    """Parser for Kerberoast/AS-REP roast output"""

    @property
    def name(self) -> str:
        return "kerberoast"

    @property
    def description(self) -> str:
        return "Kerberoast/AS-REP hash parser (GetUserSPNs, Rubeus, hashcat)"

    def can_parse(self, filepath: str) -> bool:
        """Detect Kerberoast output by content patterns"""
        if not self.validate_file(filepath):
            return False

        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read(8192)

            # Check for Kerberos hash signatures
            checks = [
                PATTERNS['tgs_hash_line'].search(content),
                PATTERNS['asrep_hash_line'].search(content),
                PATTERNS['getuserspns_header'].search(content),
                PATTERNS['rubeus_kerberoast'].search(content),
                # Plain hash file
                content.strip().startswith('$krb5'),
            ]

            return any(checks)

        except Exception:
            return False

    def parse(self, filepath: str, hostname: Optional[str] = None) -> ParsedSummary:
        """Parse Kerberoast output file

        Args:
            filepath: Path to kerberoast output file
            hostname: Optional source hostname hint

        Returns:
            ParsedSummary with extracted hash credentials
        """
        content = self.read_file(filepath)

        summary = ParsedSummary(
            source_file=filepath,
            source_tool='kerberoast',
            lines_parsed=len(content.splitlines()),
        )

        # Detect format and parse accordingly
        if PATTERNS['rubeus_kerberoast'].search(content):
            credentials = self._parse_rubeus_output(content)
        elif PATTERNS['getuserspns_header'].search(content):
            credentials = self._parse_getuserspns_output(content)
        else:
            # Generic hash extraction
            credentials = self._extract_all_hashes(content)

        summary.credentials.extend(credentials)

        # Infer domain from hashes
        if summary.credentials and not summary.source_domain:
            for cred in summary.credentials:
                if cred.domain:
                    summary.source_domain = cred.domain.upper()
                    break

        self.set_hostname(summary, None, hostname)

        return summary.deduplicate()

    def _parse_rubeus_output(self, content: str) -> List[Credential]:
        """Parse Rubeus kerberoast output

        Rubeus format:
        [*] SamAccountName         : sqlsvc
        [*] DistinguishedName      : CN=sqlsvc,CN=Users,DC=corp,DC=local
        [*] ServicePrincipalName   : MSSQLSvc/sql.corp.local:1433
        [*] Hash                   : $krb5tgs$23$*sqlsvc$...
        """
        credentials = []

        # Split into user blocks
        blocks = re.split(r'\[\*\]\s*SamAccountName\s*:', content)

        for block in blocks[1:]:  # Skip first empty split
            lines = block.strip().split('\n')
            if not lines:
                continue

            username = lines[0].strip()
            domain = ""
            spn = ""
            hash_value = ""

            for line in lines:
                line = line.strip()

                # Extract domain from DN
                dn_match = re.search(r'DistinguishedName\s*:\s*.+DC=([^,]+)', line, re.I)
                if dn_match:
                    domain = dn_match.group(1).upper()

                # Extract SPN
                spn_match = re.search(r'ServicePrincipalName\s*:\s*(\S+)', line, re.I)
                if spn_match:
                    spn = spn_match.group(1)

                # Extract hash
                hash_match = re.search(r'Hash\s*:\s*(\$krb5tgs\$.+)', line, re.I)
                if hash_match:
                    hash_value = hash_match.group(1).strip()

            if hash_value:
                cred = Credential(
                    username=username,
                    domain=domain,
                    cred_type=CredentialType.KRB5TGS,
                    value=hash_value,
                )
                credentials.append(cred)

        return credentials

    def _parse_getuserspns_output(self, content: str) -> List[Credential]:
        """Parse GetUserSPNs.py output

        GetUserSPNs format (table):
        ServicePrincipalName          Name     MemberOf  PasswordLastSet  ...
        MSSQLSvc/sql.corp.local:1433  sqlsvc   ...       2023-01-01 ...

        Then hashes at the bottom:
        $krb5tgs$23$*sqlsvc$CORP.LOCAL$...
        """
        credentials = []

        # First extract any hashes directly
        hash_creds = self._extract_all_hashes(content)

        # Try to enrich with SPN info from table
        lines = content.splitlines()
        in_table = False
        spn_map = {}  # Map username -> SPN

        for line in lines:
            if PATTERNS['getuserspns_header'].search(line):
                in_table = True
                continue

            if in_table and line.strip():
                # Table row: SPN, Name, MemberOf, ...
                parts = line.split()
                if len(parts) >= 2 and '/' in parts[0]:
                    spn = parts[0]
                    username = parts[1]
                    spn_map[username.lower()] = spn

            # End of table when we see hash
            if line.strip().startswith('$krb5'):
                in_table = False

        # If no hashes found directly, we may have just the table
        if not hash_creds:
            return credentials

        credentials.extend(hash_creds)
        return credentials

    def _extract_all_hashes(self, content: str) -> List[Credential]:
        """Extract all Kerberos hashes from content"""
        credentials = []
        seen_hashes = set()

        # Find TGS hashes
        for match in PATTERNS['krb5tgs'].finditer(content):
            etype, username, realm, spn, hash_body = match.groups()
            full_hash = match.group(0)

            # Avoid duplicates
            if full_hash in seen_hashes:
                continue
            seen_hashes.add(full_hash)

            cred = Credential(
                username=username,
                domain=realm.upper(),
                cred_type=CredentialType.KRB5TGS,
                value=full_hash,
            )
            credentials.append(cred)

        # Find AS-REP hashes
        for match in PATTERNS['krb5asrep'].finditer(content):
            etype, username, realm, hash_body = match.groups()
            full_hash = match.group(0)

            if full_hash in seen_hashes:
                continue
            seen_hashes.add(full_hash)

            cred = Credential(
                username=username,
                domain=realm.upper(),
                cred_type=CredentialType.KRB5ASREP,
                value=full_hash,
            )
            credentials.append(cred)

        # Handle raw hash lines (one hash per line)
        for line in content.splitlines():
            line = line.strip()
            if line.startswith('$krb5tgs$') and line not in seen_hashes:
                # Parse username/realm if possible
                username, domain = self._parse_hash_metadata(line)
                seen_hashes.add(line)
                cred = Credential(
                    username=username,
                    domain=domain,
                    cred_type=CredentialType.KRB5TGS,
                    value=line,
                )
                credentials.append(cred)

            elif line.startswith('$krb5asrep$') and line not in seen_hashes:
                username, domain = self._parse_asrep_metadata(line)
                seen_hashes.add(line)
                cred = Credential(
                    username=username,
                    domain=domain,
                    cred_type=CredentialType.KRB5ASREP,
                    value=line,
                )
                credentials.append(cred)

        return credentials

    def _parse_hash_metadata(self, hash_line: str) -> Tuple[str, str]:
        """Extract username and domain from TGS hash line"""
        # Try standard format: $krb5tgs$23$*user$REALM$spn*$...
        match = PATTERNS['krb5tgs'].match(hash_line)
        if match:
            return match.group(2), match.group(3).upper()

        # Fallback
        return 'unknown', ''

    def _parse_asrep_metadata(self, hash_line: str) -> Tuple[str, str]:
        """Extract username and domain from AS-REP hash line"""
        # Try standard format: $krb5asrep$23$user@REALM:...
        match = PATTERNS['krb5asrep'].match(hash_line)
        if match:
            return match.group(2), match.group(3).upper()

        return 'unknown', ''
