"""
Main Mimikatz parser - orchestrates subparsers

Supports:
- sekurlsa::logonpasswords
- sekurlsa::tickets
"""

from typing import Optional, List
from pathlib import Path

from ..base import PrismParser
from ..registry import PrismParserRegistry
from ...models import ParsedSummary, LogonSession

from .patterns import PATTERNS
from .logonpasswords import LogonPasswordsParser
from .tickets import TicketsParser


@PrismParserRegistry.register
class MimikatzParser(PrismParser):
    """Parser for mimikatz output"""

    @property
    def name(self) -> str:
        return "mimikatz"

    @property
    def description(self) -> str:
        return "Mimikatz credential dump parser (logonpasswords, tickets)"

    def can_parse(self, filepath: str) -> bool:
        """Detect mimikatz output by signature patterns"""
        if not self.validate_file(filepath):
            return False

        try:
            # Read first 4KB for detection
            with open(filepath, 'r', errors='ignore') as f:
                content = f.read(4096)

            # Check for mimikatz signatures
            checks = [
                PATTERNS['mimikatz_banner'].search(content),
                PATTERNS['sekurlsa_cmd'].search(content),
                (PATTERNS['auth_id_marker'].search(content) and
                 'NTLM' in content.upper()),
            ]

            return any(checks)

        except Exception:
            return False

    def parse(self, filepath: str, hostname: Optional[str] = None) -> ParsedSummary:
        """Parse mimikatz output file

        Args:
            filepath: Path to mimikatz output file
            hostname: Optional source hostname hint

        Returns:
            ParsedSummary with extracted credentials and tickets
        """
        content = self.read_file(filepath)
        lines = content.splitlines()

        # Initialize summary
        summary = ParsedSummary(
            source_file=filepath,
            source_tool='mimikatz',
            lines_parsed=len(lines),
        )

        # Detect what's in the file
        has_logonpasswords = self._has_logonpasswords(content)
        has_tickets = self._has_tickets(content)

        # Parse logonpasswords
        if has_logonpasswords:
            lp_parser = LogonPasswordsParser()
            sessions = lp_parser.parse(lines)
            for session in sessions:
                summary.add_session(session)

        # Parse tickets (may be interleaved or separate)
        if has_tickets:
            ticket_parser = TicketsParser()
            tickets = ticket_parser.parse(lines)
            summary.tickets.extend(tickets)

        # Set both detected and user-specified hostnames
        detected_hostname = self._infer_hostname(summary)
        self.set_hostname(summary, detected_hostname, hostname)

        # Infer domain
        summary.source_domain = self._infer_domain(summary)

        # Deduplicate credentials (conservative - exact match)
        summary = summary.deduplicate()

        return summary

    def _has_logonpasswords(self, content: str) -> bool:
        """Check if output contains logonpasswords data"""
        return (
            'sekurlsa::logonpasswords' in content.lower() or
            (PATTERNS['auth_id_marker'].search(content) and
             ('msv :' in content.lower() or
              'kerberos :' in content.lower() or
              'wdigest :' in content.lower()))
        )

    def _has_tickets(self, content: str) -> bool:
        """Check if output contains ticket data"""
        return (
            'sekurlsa::tickets' in content.lower() or
            ('Group 0 - Ticket Granting Service' in content) or
            ('Group 2 - Ticket Granting Ticket' in content) or
            ('.kirbi' in content.lower())
        )

    def _infer_hostname(self, summary: ParsedSummary) -> Optional[str]:
        """Try to infer hostname from parsed data"""
        # Look for machine account in credentials
        for cred in summary.credentials:
            if cred.is_machine_account and cred.domain:
                # Machine account username is HOSTNAME$
                return cred.username.rstrip('$')

        # Look for logon server
        for session in summary.sessions:
            if session.logon_server and session.logon_server != '(null)':
                return session.logon_server

        return None

    def _infer_domain(self, summary: ParsedSummary) -> str:
        """Try to infer domain from parsed data"""
        domains = set()

        # Collect domains from credentials
        for cred in summary.credentials:
            if cred.domain and cred.domain.upper() not in (
                'NT AUTHORITY', 'FONT DRIVER HOST', 'WINDOW MANAGER'
            ):
                domains.add(cred.domain.upper())

        # Collect realms from tickets
        for ticket in summary.tickets:
            if ticket.client_realm:
                domains.add(ticket.client_realm.upper())

        # Return most common or first
        if domains:
            # Prefer FQDN-looking domains
            for d in domains:
                if '.' in d:
                    return d
            return sorted(domains)[0]

        return ""
