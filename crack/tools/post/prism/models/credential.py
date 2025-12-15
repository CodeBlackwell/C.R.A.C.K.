"""
Credential model for parsed authentication data
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any
from enum import Enum


class CredentialType(Enum):
    """Types of credentials extracted from security tools"""
    CLEARTEXT = "cleartext"
    NTLM = "ntlm"
    SHA1 = "sha1"
    MACHINE_HEX = "machine_hex"      # Machine account hex blob password
    LM = "lm"                         # Legacy LM hash
    AES128 = "aes128"                 # Kerberos AES128 key
    AES256 = "aes256"                 # Kerberos AES256 key
    DES_CBC_MD5 = "des_cbc_md5"       # Kerberos DES key
    RC4_HMAC = "rc4_hmac"             # Kerberos RC4 key (same as NTLM)


# Well-known service accounts to identify
SERVICE_ACCOUNTS = frozenset([
    'DWM-1', 'DWM-2', 'DWM-3', 'DWM-4',
    'UMFD-0', 'UMFD-1', 'UMFD-2', 'UMFD-3',
    'ANONYMOUS LOGON',
    'LOCAL SERVICE',
    'NETWORK SERVICE',
])

# Well-known service domains
SERVICE_DOMAINS = frozenset([
    'FONT DRIVER HOST',
    'WINDOW MANAGER',
    'NT AUTHORITY',
])


@dataclass
class Credential:
    """Represents a single extracted credential"""

    username: str
    domain: str
    cred_type: CredentialType
    value: str

    # Optional metadata
    sid: Optional[str] = None
    logon_server: Optional[str] = None
    session_type: Optional[str] = None
    source_session_id: Optional[str] = None

    # For deduplication tracking
    first_seen_line: int = 0
    occurrences: int = 1

    @property
    def is_machine_account(self) -> bool:
        """Machine accounts end with $"""
        return self.username.endswith('$')

    @property
    def is_service_account(self) -> bool:
        """Check if this is a well-known service account"""
        return (
            self.username.upper() in SERVICE_ACCOUNTS or
            self.domain.upper() in SERVICE_DOMAINS
        )

    @property
    def is_null_password(self) -> bool:
        """Check if password is null/empty"""
        return self.value in ('(null)', '', None)

    @property
    def high_value(self) -> bool:
        """Cleartext passwords or real user accounts are high value"""
        if self.is_null_password:
            return False
        if self.cred_type == CredentialType.CLEARTEXT:
            return True
        # Non-service, non-machine accounts with NTLM are interesting
        return not self.is_machine_account and not self.is_service_account

    @property
    def display_type(self) -> str:
        """Human-readable credential type"""
        type_labels = {
            CredentialType.CLEARTEXT: "Cleartext",
            CredentialType.NTLM: "NTLM",
            CredentialType.SHA1: "SHA1",
            CredentialType.MACHINE_HEX: "Machine Key",
            CredentialType.LM: "LM",
            CredentialType.AES256: "AES256",
            CredentialType.AES128: "AES128",
        }
        return type_labels.get(self.cred_type, self.cred_type.value)

    @property
    def dedup_key(self) -> tuple:
        """Key for conservative deduplication (exact match)"""
        return (
            self.username.lower(),
            self.domain.lower(),
            self.cred_type,
            self.value.lower() if self.value else ""
        )

    @property
    def account_key(self) -> str:
        """Unique account identifier for display"""
        if self.domain:
            return f"{self.domain}\\{self.username}"
        return self.username

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary"""
        return {
            'username': self.username,
            'domain': self.domain,
            'cred_type': self.cred_type.value,
            'value': self.value,
            'sid': self.sid,
            'logon_server': self.logon_server,
            'session_type': self.session_type,
            'is_machine_account': self.is_machine_account,
            'is_service_account': self.is_service_account,
            'high_value': self.high_value,
        }

    def to_neo4j_dict(self) -> Dict[str, Any]:
        """Serialize for Neo4j import"""
        return {
            'id': f"{self.username}@{self.domain}:{self.cred_type.value}",
            'username': self.username,
            'domain': self.domain,
            'cred_type': self.cred_type.value,
            'value': self.value,
            'sid': self.sid,
            'is_machine': self.is_machine_account,
            'is_service': self.is_service_account,
            'high_value': self.high_value,
        }

    def __repr__(self) -> str:
        return f"<Credential {self.account_key} type={self.cred_type.value}>"
