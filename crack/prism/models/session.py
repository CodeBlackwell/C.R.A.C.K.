"""
Logon session model for parsed session data
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from datetime import datetime

from .credential import Credential
from .ticket import KerberosTicket


@dataclass
class LogonSession:
    """Represents a Windows logon session from mimikatz"""

    # Session identifiers
    auth_id_high: int
    auth_id_low: int

    # Session info
    session_type: str           # Interactive, Service, Network, etc.
    username: str
    domain: str
    logon_server: Optional[str] = None
    logon_time: Optional[datetime] = None
    sid: Optional[str] = None

    # Extracted data
    credentials: List[Credential] = field(default_factory=list)
    tickets: List[KerberosTicket] = field(default_factory=list)

    @property
    def auth_id(self) -> str:
        """Formatted authentication ID"""
        return f"0x{self.auth_id_high:08x}:0x{self.auth_id_low:08x}"

    @property
    def auth_id_short(self) -> str:
        """Short authentication ID for display"""
        return f"{self.auth_id_high};{self.auth_id_low}"

    @property
    def is_interactive(self) -> bool:
        """Interactive or RemoteInteractive session"""
        return 'interactive' in self.session_type.lower()

    @property
    def is_service(self) -> bool:
        """Service session"""
        return self.session_type.lower() == 'service'

    @property
    def account_name(self) -> str:
        """Full account name"""
        if self.domain:
            return f"{self.domain}\\{self.username}"
        return self.username

    @property
    def has_credentials(self) -> bool:
        """Check if any credentials were extracted"""
        return len(self.credentials) > 0

    @property
    def has_tickets(self) -> bool:
        """Check if any tickets were extracted"""
        return len(self.tickets) > 0

    @property
    def has_cleartext(self) -> bool:
        """Check if any cleartext passwords were found"""
        from .credential import CredentialType
        return any(c.cred_type == CredentialType.CLEARTEXT for c in self.credentials)

    @property
    def has_ntlm(self) -> bool:
        """Check if any NTLM hashes were found"""
        from .credential import CredentialType
        return any(c.cred_type == CredentialType.NTLM for c in self.credentials)

    def add_credential(self, credential: Credential) -> None:
        """Add a credential to this session"""
        credential.source_session_id = self.auth_id_short
        credential.session_type = self.session_type
        self.credentials.append(credential)

    def add_ticket(self, ticket: KerberosTicket) -> None:
        """Add a ticket to this session"""
        self.tickets.append(ticket)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary"""
        return {
            'auth_id': self.auth_id,
            'session_type': self.session_type,
            'username': self.username,
            'domain': self.domain,
            'logon_server': self.logon_server,
            'logon_time': self.logon_time.isoformat() if self.logon_time else None,
            'sid': self.sid,
            'credential_count': len(self.credentials),
            'ticket_count': len(self.tickets),
            'has_cleartext': self.has_cleartext,
            'has_ntlm': self.has_ntlm,
        }

    def __repr__(self) -> str:
        return f"<LogonSession {self.account_name} type={self.session_type} creds={len(self.credentials)}>"
