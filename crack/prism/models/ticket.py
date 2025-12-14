"""
Kerberos ticket model for parsed ticket data
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from datetime import datetime


@dataclass
class KerberosTicket:
    """Represents a Kerberos ticket (TGT or TGS)"""

    # Service information
    service_type: str           # krbtgt, cifs, ldap, HOST, DNS, etc.
    service_target: str         # Server/service name
    service_realm: str          # Kerberos realm (domain)

    # Client information
    client_name: str
    client_realm: str

    # Timing
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    max_renew_time: Optional[datetime] = None

    # Ticket properties
    flags: str = ""
    flags_hex: str = ""
    session_key_type: str = ""
    session_key_value: str = ""
    ticket_encryption: str = ""
    kvno: Optional[int] = None

    # Export info
    saved_path: Optional[str] = None

    # Metadata
    group_type: int = 0         # 0=TGS, 1=Client, 2=TGT

    @property
    def is_tgt(self) -> bool:
        """Ticket Granting Ticket (krbtgt service)"""
        return self.service_type.lower() == 'krbtgt'

    @property
    def is_tgs(self) -> bool:
        """Ticket Granting Service (any non-krbtgt)"""
        return not self.is_tgt

    @property
    def is_expired(self) -> bool:
        """Check if ticket has expired"""
        if self.end_time:
            return datetime.now() > self.end_time
        return False

    @property
    def is_renewable(self) -> bool:
        """Check if ticket has renewable flag"""
        return 'renewable' in self.flags.lower()

    @property
    def is_forwardable(self) -> bool:
        """Check if ticket is forwardable"""
        return 'forwardable' in self.flags.lower()

    @property
    def is_delegation_ticket(self) -> bool:
        """Check if this is a delegation ticket"""
        return '$delegation ticket$' in self.client_name.lower()

    @property
    def service_display(self) -> str:
        """Display-friendly service name"""
        if self.service_target:
            return f"{self.service_type}/{self.service_target}"
        return self.service_type

    @property
    def time_remaining(self) -> Optional[str]:
        """Human-readable time until expiration"""
        if not self.end_time:
            return None

        delta = self.end_time - datetime.now()
        if delta.total_seconds() < 0:
            return "EXPIRED"

        hours = int(delta.total_seconds() // 3600)
        minutes = int((delta.total_seconds() % 3600) // 60)

        if hours > 24:
            days = hours // 24
            return f"{days}d {hours % 24}h"
        return f"{hours}h {minutes}m"

    @property
    def parsed_flags(self) -> List[str]:
        """Parse flags string into list"""
        if not self.flags:
            return []
        # Flags format: "name_canonicalize ; ok_as_delegate ; pre_authent ; renewable ; forwardable ;"
        return [f.strip() for f in self.flags.split(';') if f.strip()]

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary"""
        return {
            'service_type': self.service_type,
            'service_target': self.service_target,
            'service_realm': self.service_realm,
            'client_name': self.client_name,
            'client_realm': self.client_realm,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': self.end_time.isoformat() if self.end_time else None,
            'max_renew_time': self.max_renew_time.isoformat() if self.max_renew_time else None,
            'flags': self.parsed_flags,
            'session_key_type': self.session_key_type,
            'ticket_encryption': self.ticket_encryption,
            'saved_path': self.saved_path,
            'is_tgt': self.is_tgt,
            'is_expired': self.is_expired,
        }

    def __repr__(self) -> str:
        ticket_type = "TGT" if self.is_tgt else "TGS"
        return f"<{ticket_type} {self.client_name}@{self.client_realm} -> {self.service_display}>"
