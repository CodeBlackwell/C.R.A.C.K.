"""
Nmap Port Model

Represents a single port from nmap scan output with service detection.
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from enum import Enum


class PortState(Enum):
    """Port states as reported by nmap"""
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    UNFILTERED = "unfiltered"
    OPEN_FILTERED = "open|filtered"
    CLOSED_FILTERED = "closed|filtered"

    @classmethod
    def from_string(cls, state_str: str) -> "PortState":
        """Parse state string to enum"""
        state_str = state_str.lower().strip()
        for state in cls:
            if state.value == state_str:
                return state
        # Default to filtered for unknown states
        return cls.FILTERED


@dataclass
class NmapScript:
    """NSE script output"""
    name: str
    output: str
    structured_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'output': self.output,
            'data': self.structured_data,
        }


@dataclass
class NmapPort:
    """Represents a single port from nmap output"""

    # Core port info
    port: int
    protocol: str  # tcp, udp
    state: PortState

    # Service detection
    service: str = ""
    version: str = ""
    product: str = ""
    extra_info: str = ""

    # Reasoning
    reason: str = ""
    reason_ttl: Optional[int] = None

    # NSE Scripts
    scripts: List[NmapScript] = field(default_factory=list)

    @property
    def is_open(self) -> bool:
        return self.state == PortState.OPEN

    @property
    def is_filtered(self) -> bool:
        return self.state in (PortState.FILTERED, PortState.OPEN_FILTERED)

    @property
    def port_id(self) -> str:
        """Standard port/protocol identifier"""
        return f"{self.port}/{self.protocol}"

    @property
    def service_version(self) -> str:
        """Combined service and version for display"""
        if self.version:
            return f"{self.service} {self.version}"
        return self.service

    @property
    def is_web(self) -> bool:
        """HTTP/HTTPS service"""
        if self.service in ('http', 'https', 'ssl/http', 'ssl/https', 'http-proxy'):
            return True
        if self.port in (80, 443, 8080, 8443, 8000, 8888):
            return True
        if self.product and 'http' in self.product.lower():
            return True
        return False

    @property
    def is_smb(self) -> bool:
        """SMB/CIFS service"""
        return self.service in ('microsoft-ds', 'netbios-ssn') or self.port in (445, 139)

    @property
    def is_rdp(self) -> bool:
        """RDP service"""
        return self.service == 'ms-wbt-server' or self.port == 3389

    @property
    def is_winrm(self) -> bool:
        """WinRM service"""
        return self.port in (5985, 5986) or 'wsman' in self.service.lower()

    @property
    def is_kerberos(self) -> bool:
        """Kerberos service"""
        return self.service == 'kerberos-sec' or self.port == 88

    @property
    def is_ldap(self) -> bool:
        """LDAP service"""
        return 'ldap' in self.service.lower() or self.port in (389, 636, 3268, 3269)

    @property
    def is_ssh(self) -> bool:
        """SSH service"""
        return self.service == 'ssh' or self.port == 22

    @property
    def is_dns(self) -> bool:
        """DNS service"""
        return self.service == 'domain' or self.port == 53

    @property
    def is_msrpc(self) -> bool:
        """MSRPC service"""
        return self.service == 'msrpc' or self.port == 135

    @property
    def is_mssql(self) -> bool:
        """MSSQL service"""
        return 'ms-sql' in self.service.lower() or self.port == 1433

    @property
    def is_mysql(self) -> bool:
        """MySQL/MariaDB service"""
        return 'mysql' in self.service.lower() or self.port == 3306

    @property
    def is_ftp(self) -> bool:
        """FTP service"""
        return self.service == 'ftp' or self.port == 21

    def get_script(self, name: str) -> Optional[NmapScript]:
        """Get script output by name"""
        for script in self.scripts:
            if script.name == name:
                return script
        return None

    def has_script(self, name: str) -> bool:
        """Check if script output exists"""
        return any(s.name == name for s in self.scripts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'port': self.port,
            'protocol': self.protocol,
            'state': self.state.value,
            'service': self.service,
            'version': self.version,
            'product': self.product,
            'reason': self.reason,
            'scripts': [s.to_dict() for s in self.scripts],
        }

    def to_neo4j_dict(self) -> Dict[str, Any]:
        """Serialize for Neo4j import"""
        return {
            'port': self.port,
            'protocol': self.protocol,
            'state': self.state.value,
            'service': self.service,
            'version': self.version,
            'product': self.product,
            'is_web': self.is_web,
            'is_smb': self.is_smb,
            'is_rdp': self.is_rdp,
            'is_winrm': self.is_winrm,
            'is_ssh': self.is_ssh,
        }
