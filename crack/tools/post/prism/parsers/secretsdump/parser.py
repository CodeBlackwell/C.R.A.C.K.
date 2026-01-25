"""
Secretsdump Parser

Parses hash dumps from Impacket secretsdump.py, SAM databases, and NTDS.dit:
- SAM dump: user:rid:lmhash:nthash:::
- NTDS dump: DOMAIN\\user:rid:lmhash:nthash:::
- DCC2 (cached): $DCC2$iterations#user#hash
- Responder NetNTLM captures

Format reference:
- LM hash (usually empty): aad3b435b51404eeaad3b435b51404ee
- NT hash: 32 hex characters
- RID: relative identifier (integer)
"""

import re
from typing import Optional, List, Tuple
from pathlib import Path

from ..base import PrismParser
from ..registry import PrismParserRegistry
from ...models import ParsedSummary, Credential, CredentialType


# Empty LM hash (indicates no LM hash stored)
EMPTY_LM = "aad3b435b51404eeaad3b435b51404ee"
EMPTY_NT = "31d6cfe0d16ae931b73c59d7e0c089c0"

# Regex patterns
PATTERNS = {
    # SAM/NTDS format: [DOMAIN\]user:rid:lmhash:nthash:::
    'sam_ntds': re.compile(
        r'^([^:]+):(\d+):([a-fA-F0-9]{32}):([a-fA-F0-9]{32}):::?\s*$',
        re.MULTILINE
    ),
    # DCC2 (cached credentials): $DCC2$iterations#user#hash
    'dcc2': re.compile(
        r'\$DCC2\$(\d+)#([^#]+)#([a-fA-F0-9]+)',
        re.IGNORECASE
    ),
    # NetNTLMv1: user::DOMAIN:lmresp:ntresp:challenge
    'netntlmv1': re.compile(
        r'^([^:]+)::([^:]*):([a-fA-F0-9]+):([a-fA-F0-9]+):([a-fA-F0-9]+)\s*$',
        re.MULTILINE
    ),
    # NetNTLMv2: user::DOMAIN:challenge:ntproofstr:ntresp
    'netntlmv2': re.compile(
        r'^([^:]+)::([^:]*):([a-fA-F0-9]+):([a-fA-F0-9]+):([a-fA-F0-9]+)\s*$',
        re.MULTILINE
    ),
    # Secretsdump markers
    'secretsdump_header': re.compile(
        r'\[\*\]\s*Dumping (SAM|local SAM|domain)',
        re.IGNORECASE
    ),
    'ntds_header': re.compile(
        r'\[\*\]\s*Dumping Domain Credentials',
        re.IGNORECASE
    ),
    # History hashes: user_history0:rid:lm:nt:::
    'history': re.compile(r'_history\d+:', re.IGNORECASE),
}


@PrismParserRegistry.register
class SecretsdumpParser(PrismParser):
    """Parser for secretsdump.py and hash dump output"""

    @property
    def name(self) -> str:
        return "secretsdump"

    @property
    def description(self) -> str:
        return "SAM/NTDS/secretsdump hash parser"

    def can_parse(self, filepath: str) -> bool:
        """Detect secretsdump/hash dump by content patterns"""
        if not self.validate_file(filepath):
            return False

        try:
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read(8192)

            # Check for hash dump signatures
            checks = [
                PATTERNS['secretsdump_header'].search(content),
                PATTERNS['ntds_header'].search(content),
                PATTERNS['dcc2'].search(content),
                # Look for hash lines (user:rid:lm:nt format)
                self._looks_like_hash_dump(content),
            ]

            return any(checks)

        except Exception:
            return False

    def _looks_like_hash_dump(self, content: str) -> bool:
        """Check if content looks like a hash dump file"""
        lines = content.strip().split('\n')[:20]  # Check first 20 lines

        hash_line_count = 0
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('['):
                continue

            # Count lines matching SAM/NTDS format
            if PATTERNS['sam_ntds'].match(line):
                hash_line_count += 1

        # If more than 3 lines match, likely a hash dump
        return hash_line_count >= 3

    def parse(self, filepath: str, hostname: Optional[str] = None) -> ParsedSummary:
        """Parse secretsdump/hash dump file

        Args:
            filepath: Path to hash dump file
            hostname: Optional source hostname hint

        Returns:
            ParsedSummary with extracted hash credentials
        """
        content = self.read_file(filepath)

        summary = ParsedSummary(
            source_file=filepath,
            source_tool='secretsdump',
            lines_parsed=len(content.splitlines()),
        )

        # Determine dump type
        is_ntds = self._is_ntds_dump(content)
        is_sam = self._is_sam_dump(content)

        # Parse SAM/NTDS hashes
        sam_ntds_creds = self._parse_sam_ntds(content, is_ntds)
        summary.credentials.extend(sam_ntds_creds)

        # Parse DCC2 (cached credentials)
        dcc2_creds = self._parse_dcc2(content)
        summary.credentials.extend(dcc2_creds)

        # Parse NetNTLM hashes (from responder captures)
        netntlm_creds = self._parse_netntlm(content)
        summary.credentials.extend(netntlm_creds)

        # Set both detected and user-specified hostnames
        detected_hostname = self._infer_hostname(summary.credentials)
        self.set_hostname(summary, detected_hostname, hostname)

        # Infer domain
        for cred in summary.credentials:
            if cred.domain and cred.domain.upper() not in ('WORKGROUP', 'BUILTIN'):
                summary.source_domain = cred.domain.upper()
                break

        return summary.deduplicate()

    def _is_ntds_dump(self, content: str) -> bool:
        """Check if this is an NTDS.dit dump"""
        return (
            PATTERNS['ntds_header'].search(content) is not None or
            'NTDS.dit' in content or
            # NTDS dumps typically have domain prefixes
            bool(re.search(r'^[A-Z0-9]+\\', content, re.MULTILINE))
        )

    def _is_sam_dump(self, content: str) -> bool:
        """Check if this is a SAM dump"""
        return (
            PATTERNS['secretsdump_header'].search(content) is not None or
            'SAM' in content.upper()
        )

    def _parse_sam_ntds(self, content: str, is_ntds: bool = False) -> List[Credential]:
        """Parse SAM/NTDS format hashes"""
        credentials = []
        seen = set()

        for match in PATTERNS['sam_ntds'].finditer(content):
            full_user, rid, lm_hash, nt_hash = match.groups()

            # Skip history hashes
            if PATTERNS['history'].search(full_user):
                continue

            # Skip empty NT hashes
            if nt_hash.lower() == EMPTY_NT.lower():
                continue

            # Dedup key
            key = (full_user.lower(), nt_hash.lower())
            if key in seen:
                continue
            seen.add(key)

            # Parse domain from username (DOMAIN\user format)
            domain = ""
            username = full_user

            if '\\' in full_user:
                domain, username = full_user.split('\\', 1)

            # Determine credential type
            if is_ntds or domain:
                cred_type = CredentialType.NTDS_HASH
            else:
                cred_type = CredentialType.SAM_HASH

            # Build full hash string for hashcat
            full_hash = f"{full_user}:{rid}:{lm_hash}:{nt_hash}:::"

            cred = Credential(
                username=username,
                domain=domain,
                cred_type=cred_type,
                value=full_hash,
            )
            credentials.append(cred)

        return credentials

    def _parse_dcc2(self, content: str) -> List[Credential]:
        """Parse DCC2 (cached domain credentials)"""
        credentials = []
        seen = set()

        for match in PATTERNS['dcc2'].finditer(content):
            iterations, username, hash_value = match.groups()
            full_hash = match.group(0)

            if full_hash.lower() in seen:
                continue
            seen.add(full_hash.lower())

            cred = Credential(
                username=username,
                domain="",  # DCC2 doesn't include domain
                cred_type=CredentialType.DCC2,
                value=full_hash,
            )
            credentials.append(cred)

        return credentials

    def _parse_netntlm(self, content: str) -> List[Credential]:
        """Parse NetNTLMv1/v2 hashes (from Responder)"""
        credentials = []
        seen = set()

        # Check for NetNTLMv2 format (more common)
        # Format: user::DOMAIN:challenge:ntproofstr:ntresp
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            parts = line.split(':')
            if len(parts) < 6:
                continue

            # NetNTLMv2: user::domain:serverchallenge:ntproofstr:rest
            if parts[1] == '' and len(parts[3]) == 16:  # Challenge is 16 hex chars
                username = parts[0]
                domain = parts[2] if parts[2] else ""

                if line.lower() in seen:
                    continue
                seen.add(line.lower())

                # Determine v1 or v2 by response length
                # NTLMv2 responses are longer (variable length)
                # NTLMv1 responses are 48 hex chars
                if len(parts[4]) > 32:
                    cred_type = CredentialType.NET_NTLMV2
                else:
                    cred_type = CredentialType.NET_NTLMV1

                cred = Credential(
                    username=username,
                    domain=domain,
                    cred_type=cred_type,
                    value=line,
                )
                credentials.append(cred)

        return credentials

    def _infer_hostname(self, credentials: List[Credential]) -> str:
        """Try to infer source hostname from machine accounts"""
        for cred in credentials:
            if cred.is_machine_account:
                # Machine account is HOSTNAME$
                return cred.username.rstrip('$')
        return ""
