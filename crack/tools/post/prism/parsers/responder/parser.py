"""
Responder Parser

Parses captured NetNTLM hashes from Responder and similar tools:
- Responder log files
- ntlmrelayx captured hashes
- Inveigh output

Hash formats:
- NTLMv1: user::domain:lm_response:ntlm_response:challenge
- NTLMv2: user::domain:challenge:ntlm_response:blob
- NTLMv2-SSP: user::domain:challenge:ntproofstr:ntlmv2_response

The NetNTLM hash can be cracked offline with hashcat:
- NTLMv1: mode 5500
- NTLMv2: mode 5600
"""

import re
from typing import Optional, List, Tuple
from pathlib import Path

from ..base import PrismParser
from ..registry import PrismParserRegistry
from ...models import ParsedSummary, Credential, CredentialType


# Regex patterns for Responder output
PATTERNS = {
    # NetNTLMv2 hash format (most common):
    # user::domain:serverchallenge:ntproofstr:rest_of_ntlmv2_response
    # Example: Administrator::CORP:1122334455667788:AABBCCDD...:0101000000...
    'netntlmv2': re.compile(
        r'^([^:]+)::([^:]*):([a-fA-F0-9]{16}):([a-fA-F0-9]{32}):([a-fA-F0-9]+)\s*$',
        re.MULTILINE
    ),
    # NetNTLMv1 hash format:
    # user::domain:lm_response:ntlm_response:challenge
    # LM response is 48 hex chars, NTLM response is 48 hex chars, challenge is 16 hex chars
    'netntlmv1': re.compile(
        r'^([^:]+)::([^:]*):([a-fA-F0-9]{48}):([a-fA-F0-9]{48}):([a-fA-F0-9]{16})\s*$',
        re.MULTILINE
    ),
    # Responder log markers
    'responder_header': re.compile(
        r'NBT-NS|LLMNR|mDNS|MDNS|Responder|SMB\s+NTLMv[12]',
        re.IGNORECASE
    ),
    # Hash type markers in Responder output
    'ntlmv1_marker': re.compile(r'NTLMv1(-SSP)?(-Client)?', re.IGNORECASE),
    'ntlmv2_marker': re.compile(r'NTLMv2(-SSP)?(-Client)?', re.IGNORECASE),
    # Generic NetNTLM detection (user::domain format with colons)
    'netntlm_generic': re.compile(
        r'^[^:\s]+::[^:]*:[a-fA-F0-9]+:[a-fA-F0-9]+:[a-fA-F0-9]+\s*$',
        re.MULTILINE
    ),
    # Responder log file format: [timestamp] [protocol] NTLMv2 Hash : user::domain:...
    'responder_log_hash': re.compile(
        r'\[.*?\]\s+\[.*?\]\s+NTLMv[12](-SSP)?(-Client)?\s+Hash\s*:\s*(.+)',
        re.IGNORECASE
    ),
}


@PrismParserRegistry.register
class ResponderParser(PrismParser):
    """Parser for Responder NetNTLM hash captures"""

    @property
    def name(self) -> str:
        return "responder"

    @property
    def description(self) -> str:
        return "Responder/NetNTLM hash capture parser"

    def can_parse(self, filepath: str) -> bool:
        """Detect Responder output by content patterns"""
        if not self.validate_file(filepath):
            return False

        try:
            # Check filename hints
            filename = Path(filepath).name.lower()
            if any(hint in filename for hint in ['responder', 'ntlm', 'inveigh', 'relay']):
                return True

            with open(filepath, 'r', errors='ignore') as f:
                content = f.read(16384)  # Read more for log files

            # Check for Responder markers
            if PATTERNS['responder_header'].search(content):
                return True

            # Check for NTLMv1/v2 type markers
            if PATTERNS['ntlmv1_marker'].search(content) or PATTERNS['ntlmv2_marker'].search(content):
                return True

            # Check for hash format: user::domain:... pattern
            if PATTERNS['netntlm_generic'].search(content):
                return True

            return False

        except Exception:
            return False

    def parse(self, filepath: str, hostname: Optional[str] = None) -> ParsedSummary:
        """Parse Responder output file

        Args:
            filepath: Path to Responder log or hash file
            hostname: Optional source hostname hint

        Returns:
            ParsedSummary with extracted NetNTLM credentials
        """
        content = self.read_file(filepath)

        summary = ParsedSummary(
            source_file=filepath,
            source_tool='responder',
            lines_parsed=len(content.splitlines()),
        )

        # Parse NetNTLM hashes
        credentials = self._parse_netntlm_hashes(content)
        summary.credentials.extend(credentials)

        # Infer domain from credentials
        if summary.credentials and not summary.source_domain:
            for cred in summary.credentials:
                if cred.domain and cred.domain.upper() not in ('WORKGROUP', ''):
                    summary.source_domain = cred.domain.upper()
                    break

        # Set user-specified hostname (responder doesn't have hostname detection)
        self.set_hostname(summary, None, hostname)

        return summary.deduplicate()

    def _parse_netntlm_hashes(self, content: str) -> List[Credential]:
        """Parse all NetNTLM hashes from content"""
        credentials = []
        seen = set()

        # First try to extract hashes from Responder log format
        for match in PATTERNS['responder_log_hash'].finditer(content):
            hash_line = match.group(3).strip()
            cred = self._parse_hash_line(hash_line)
            if cred and cred.value.lower() not in seen:
                seen.add(cred.value.lower())
                credentials.append(cred)

        # Parse raw hash lines (one per line)
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('['):
                continue

            # Skip if already captured from log format
            if line.lower() in seen:
                continue

            cred = self._parse_hash_line(line)
            if cred and cred.value.lower() not in seen:
                seen.add(cred.value.lower())
                credentials.append(cred)

        return credentials

    def _parse_hash_line(self, line: str) -> Optional[Credential]:
        """Parse a single NetNTLM hash line"""
        line = line.strip()

        # Skip empty or comment lines
        if not line or line.startswith('#'):
            return None

        # Check for user::domain:... format
        if '::' not in line:
            return None

        parts = line.split(':')
        if len(parts) < 6:
            return None

        username = parts[0]
        # parts[1] is empty (between :: )
        domain = parts[2] if parts[2] else ""

        # Determine hash type by response lengths
        # NTLMv2: challenge (16), ntproofstr (32), blob (variable, usually long)
        # NTLMv1: lm_response (48), ntlm_response (48), challenge (16)

        # Try NTLMv2 format first (more common)
        match_v2 = PATTERNS['netntlmv2'].match(line)
        if match_v2:
            return Credential(
                username=username,
                domain=domain.upper() if domain else "",
                cred_type=CredentialType.NET_NTLMV2,
                value=line,
            )

        # Try NTLMv1 format
        match_v1 = PATTERNS['netntlmv1'].match(line)
        if match_v1:
            return Credential(
                username=username,
                domain=domain.upper() if domain else "",
                cred_type=CredentialType.NET_NTLMV1,
                value=line,
            )

        # Generic fallback - try to determine type by field lengths
        if len(parts) >= 6:
            # Field 3 (challenge/lm_response), Field 4 (ntproofstr/ntlm_response), Field 5 (blob/challenge)
            field3, field4, field5 = parts[3], parts[4], parts[5] if len(parts) > 5 else ""

            # NTLMv2: challenge is 16 hex, ntproofstr is 32 hex, blob is long
            if len(field3) == 16 and len(field4) == 32:
                cred_type = CredentialType.NET_NTLMV2
            # NTLMv1: lm_response is 48, ntlm_response is 48, challenge is 16
            elif len(field3) == 48 and len(field4) == 48:
                cred_type = CredentialType.NET_NTLMV1
            else:
                # Default to v2 as it's more common
                cred_type = CredentialType.NET_NTLMV2

            return Credential(
                username=username,
                domain=domain.upper() if domain else "",
                cred_type=cred_type,
                value=line,
            )

        return None
