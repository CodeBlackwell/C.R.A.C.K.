"""
Parsed summary model - aggregates all extracted data
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime

from .credential import Credential, CredentialType
from .ticket import KerberosTicket
from .session import LogonSession


@dataclass
class ParsedSummary:
    """Aggregated results from parsing security tool output"""

    # Source information
    source_file: str
    source_tool: str
    parse_time: datetime = field(default_factory=datetime.now)

    # Extracted data
    sessions: List[LogonSession] = field(default_factory=list)
    credentials: List[Credential] = field(default_factory=list)
    tickets: List[KerberosTicket] = field(default_factory=list)

    # Inferred metadata (auto-detected from parsed data)
    source_hostname: str = ""  # Detected hostname from file content
    source_domain: str = ""

    # User-specified context
    specified_hostname: str = ""  # User-provided --host value

    # Statistics
    lines_parsed: int = 0

    @property
    def effective_hostname(self) -> str:
        """Get the hostname to use (user-specified takes precedence)"""
        return self.specified_hostname or self.source_hostname or "Unknown Host"

    @property
    def display_hostname(self) -> str:
        """Get display string showing both specified and detected hosts"""
        if self.specified_hostname and self.source_hostname:
            if self.specified_hostname.upper() != self.source_hostname.upper():
                return f"{self.specified_hostname} (detected: {self.source_hostname})"
        return self.effective_hostname

    @property
    def cleartext_creds(self) -> List[Credential]:
        """Filter to cleartext passwords only"""
        return [c for c in self.credentials
                if c.cred_type == CredentialType.CLEARTEXT and not c.is_null_password]

    @property
    def ntlm_hashes(self) -> List[Credential]:
        """Filter to NTLM hashes only"""
        return [c for c in self.credentials
                if c.cred_type == CredentialType.NTLM]

    @property
    def sha1_hashes(self) -> List[Credential]:
        """Filter to SHA1 hashes only"""
        return [c for c in self.credentials
                if c.cred_type == CredentialType.SHA1]

    @property
    def gpp_creds(self) -> List[Credential]:
        """Filter to GPP passwords (decrypted and raw)"""
        return [c for c in self.credentials
                if c.cred_type in (CredentialType.GPP_PASSWORD, CredentialType.GPP_CPASSWORD)]

    @property
    def kerberoast_hashes(self) -> List[Credential]:
        """Filter to Kerberoast TGS and AS-REP hashes"""
        return [c for c in self.credentials
                if c.cred_type in (CredentialType.KRB5TGS, CredentialType.KRB5ASREP)]

    @property
    def ntds_hashes(self) -> List[Credential]:
        """Filter to NTDS/SAM hashes"""
        return [c for c in self.credentials
                if c.cred_type in (CredentialType.NTDS_HASH, CredentialType.SAM_HASH)]

    @property
    def netntlm_hashes(self) -> List[Credential]:
        """Filter to NetNTLM hashes (Responder captures)"""
        return [c for c in self.credentials
                if c.cred_type in (CredentialType.NET_NTLMV1, CredentialType.NET_NTLMV2)]

    @property
    def linux_hashes(self) -> List[Credential]:
        """Filter to Linux shadow hashes"""
        return [c for c in self.credentials
                if c.cred_type == CredentialType.LINUX_HASH]

    @property
    def cracked_passwords(self) -> List[Credential]:
        """Filter to cracked passwords from potfiles"""
        return [c for c in self.credentials
                if c.cred_type == CredentialType.CRACKED_PASSWORD]

    @property
    def connection_strings(self) -> List[Credential]:
        """Filter to database connection string credentials"""
        return [c for c in self.credentials
                if c.cred_type == CredentialType.CONNECTION_STRING]

    @property
    def ssh_keys(self) -> List[Credential]:
        """Filter to SSH private keys"""
        return [c for c in self.credentials
                if c.cred_type == CredentialType.SSH_KEY]

    @property
    def htpasswd_hashes(self) -> List[Credential]:
        """Filter to htpasswd hashes"""
        return [c for c in self.credentials
                if c.cred_type == CredentialType.HTPASSWD_HASH]

    @property
    def aws_keys(self) -> List[Credential]:
        """Filter to AWS access keys"""
        return [c for c in self.credentials
                if c.cred_type == CredentialType.AWS_ACCESS_KEY]

    @property
    def machine_creds(self) -> List[Credential]:
        """Filter to machine account credentials"""
        return [c for c in self.credentials if c.is_machine_account]

    @property
    def user_creds(self) -> List[Credential]:
        """Filter to user (non-machine, non-service) credentials"""
        return [c for c in self.credentials
                if not c.is_machine_account and not c.is_service_account]

    @property
    def high_value_creds(self) -> List[Credential]:
        """Filter to high-value credentials"""
        return [c for c in self.credentials if c.high_value]

    @property
    def tgt_tickets(self) -> List[KerberosTicket]:
        """Filter to TGT tickets"""
        return [t for t in self.tickets if t.is_tgt]

    @property
    def tgs_tickets(self) -> List[KerberosTicket]:
        """Filter to TGS tickets"""
        return [t for t in self.tickets if t.is_tgs]

    @property
    def valid_tickets(self) -> List[KerberosTicket]:
        """Filter to non-expired tickets"""
        return [t for t in self.tickets if not t.is_expired]

    @property
    def unique_accounts(self) -> int:
        """Count of unique accounts with credentials"""
        return len(set(c.account_key for c in self.credentials))

    @property
    def unique_domains(self) -> List[str]:
        """List of unique domains found"""
        domains = set()
        for c in self.credentials:
            if c.domain:
                domains.add(c.domain.upper())
        for t in self.tickets:
            if t.client_realm:
                domains.add(t.client_realm.upper())
        return sorted(domains)

    @property
    def stats(self) -> Dict[str, int]:
        """Quick statistics summary"""
        return {
            'sessions': len(self.sessions),
            'total_creds': len(self.credentials),
            'cleartext': len(self.cleartext_creds),
            'ntlm': len(self.ntlm_hashes),
            'sha1': len(self.sha1_hashes),
            'gpp': len(self.gpp_creds),
            'kerberoast': len(self.kerberoast_hashes),
            'high_value': len(self.high_value_creds),
            'tgt_tickets': len(self.tgt_tickets),
            'tgs_tickets': len(self.tgs_tickets),
            'unique_accounts': self.unique_accounts,
        }

    def add_session(self, session: LogonSession) -> None:
        """Add a session and its credentials/tickets to summary"""
        self.sessions.append(session)
        self.credentials.extend(session.credentials)
        self.tickets.extend(session.tickets)

    def deduplicate(self) -> 'ParsedSummary':
        """Return new summary with deduplicated credentials (conservative - exact match)"""
        seen_creds = {}
        unique_creds = []

        for cred in self.credentials:
            key = cred.dedup_key
            if key not in seen_creds:
                seen_creds[key] = cred
                unique_creds.append(cred)
            else:
                # Increment occurrence count on first occurrence
                seen_creds[key].occurrences += 1

        # Dedupe tickets by service+client
        seen_tickets = {}
        unique_tickets = []

        for ticket in self.tickets:
            key = (
                ticket.service_type.lower(),
                ticket.service_target.lower() if ticket.service_target else "",
                ticket.client_name.lower(),
                ticket.client_realm.lower(),
            )
            if key not in seen_tickets:
                seen_tickets[key] = ticket
                unique_tickets.append(ticket)

        return ParsedSummary(
            source_file=self.source_file,
            source_tool=self.source_tool,
            parse_time=self.parse_time,
            sessions=self.sessions,
            credentials=unique_creds,
            tickets=unique_tickets,
            source_hostname=self.source_hostname,
            source_domain=self.source_domain,
            specified_hostname=self.specified_hostname,
            lines_parsed=self.lines_parsed,
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary"""
        return {
            'source_file': self.source_file,
            'source_tool': self.source_tool,
            'parse_time': self.parse_time.isoformat(),
            'source_hostname': self.source_hostname,
            'source_domain': self.source_domain,
            'stats': self.stats,
            'credentials': [c.to_dict() for c in self.credentials],
            'tickets': [t.to_dict() for t in self.tickets],
        }

    def __repr__(self) -> str:
        return (f"<ParsedSummary tool={self.source_tool} "
                f"creds={len(self.credentials)} tickets={len(self.tickets)}>")
