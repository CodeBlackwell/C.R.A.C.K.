"""
Nmap Host Model

Represents a single host from nmap scan output.
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List

from .nmap_port import NmapPort, NmapScript


@dataclass
class NmapHost:
    """Represents a single host from nmap output"""

    # Host identification
    ip: str
    hostname: Optional[str] = None

    # Host status
    status: str = "up"  # up, down
    status_reason: str = ""
    ttl: Optional[int] = None
    latency: Optional[float] = None  # in seconds

    # Scan metadata
    scan_time: Optional[str] = None
    scan_duration: Optional[int] = None

    # Ports
    ports: List[NmapPort] = field(default_factory=list)

    # OS Detection
    os_name: Optional[str] = None
    os_cpe: Optional[str] = None
    os_accuracy: Optional[int] = None
    os_family: Optional[str] = None

    # Host scripts (smb2-time, etc.)
    host_scripts: List[NmapScript] = field(default_factory=list)

    # Service Info parsed from nmap
    service_info_os: Optional[str] = None
    service_info_host: Optional[str] = None

    # Domain info (extracted from LDAP, RDP-NTLM, etc.)
    domain: Optional[str] = None
    netbios_name: Optional[str] = None
    netbios_domain: Optional[str] = None
    dns_domain: Optional[str] = None
    dns_computer: Optional[str] = None

    # Traceroute
    traceroute_hops: List[Dict[str, Any]] = field(default_factory=list)

    # Network distance
    network_distance: Optional[int] = None

    # Uptime
    uptime_seconds: Optional[float] = None
    uptime_last_boot: Optional[str] = None

    @property
    def is_up(self) -> bool:
        return self.status == "up"

    @property
    def open_ports(self) -> List[NmapPort]:
        """Filter to only open ports"""
        return [p for p in self.ports if p.is_open]

    @property
    def open_port_numbers(self) -> List[int]:
        """List of open port numbers"""
        return [p.port for p in self.open_ports]

    @property
    def display_name(self) -> str:
        """Best name for display"""
        if self.hostname:
            return f"{self.hostname} ({self.ip})"
        return self.ip

    @property
    def best_name(self) -> str:
        """Best single name (prefer hostname)"""
        return self.hostname or self.netbios_name or self.dns_computer or self.ip

    @property
    def is_domain_controller(self) -> bool:
        """Heuristic: DC has Kerberos, LDAP, DNS"""
        dc_ports = {88, 389, 636, 3268}
        open_set = set(self.open_port_numbers)
        return len(dc_ports & open_set) >= 3

    @property
    def is_windows(self) -> bool:
        """Heuristic: Windows system"""
        if self.os_name and 'windows' in self.os_name.lower():
            return True
        if self.os_cpe and 'microsoft:windows' in self.os_cpe.lower():
            return True
        if self.service_info_os and 'windows' in self.service_info_os.lower():
            return True
        # Windows-specific services
        windows_ports = {135, 139, 445, 3389, 5985}
        return len(windows_ports & set(self.open_port_numbers)) >= 2

    @property
    def is_linux(self) -> bool:
        """Heuristic: Linux system"""
        if self.os_name and 'linux' in self.os_name.lower():
            return True
        if self.os_cpe and 'linux' in self.os_cpe.lower():
            return True
        if self.service_info_os and 'linux' in self.service_info_os.lower():
            return True
        return False

    @property
    def os_display(self) -> str:
        """OS for display (best guess)"""
        if self.os_name:
            return self.os_name
        if self.service_info_os:
            return self.service_info_os
        if self.is_windows:
            return "Windows"
        if self.is_linux:
            return "Linux"
        return "Unknown"

    @property
    def has_smb(self) -> bool:
        return any(p.is_smb for p in self.open_ports)

    @property
    def has_rdp(self) -> bool:
        return any(p.is_rdp for p in self.open_ports)

    @property
    def has_winrm(self) -> bool:
        return any(p.is_winrm for p in self.open_ports)

    @property
    def has_ssh(self) -> bool:
        return any(p.is_ssh for p in self.open_ports)

    @property
    def has_web(self) -> bool:
        return any(p.is_web for p in self.open_ports)

    @property
    def has_kerberos(self) -> bool:
        return any(p.is_kerberos for p in self.open_ports)

    @property
    def has_ldap(self) -> bool:
        return any(p.is_ldap for p in self.open_ports)

    @property
    def has_dns(self) -> bool:
        return any(p.is_dns for p in self.open_ports)

    @property
    def has_mssql(self) -> bool:
        return any(p.is_mssql for p in self.open_ports)

    @property
    def has_mysql(self) -> bool:
        return any(p.is_mysql for p in self.open_ports)

    @property
    def web_ports(self) -> List[NmapPort]:
        """Get all web service ports"""
        return [p for p in self.open_ports if p.is_web]

    def get_port(self, port_num: int, protocol: str = 'tcp') -> Optional[NmapPort]:
        """Get specific port by number"""
        for p in self.ports:
            if p.port == port_num and p.protocol == protocol:
                return p
        return None

    def get_host_script(self, name: str) -> Optional[NmapScript]:
        """Get host script output by name"""
        for script in self.host_scripts:
            if script.name == name:
                return script
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'ip': self.ip,
            'hostname': self.hostname,
            'status': self.status,
            'os': self.os_display,
            'os_cpe': self.os_cpe,
            'domain': self.domain or self.dns_domain,
            'netbios_name': self.netbios_name,
            'is_dc': self.is_domain_controller,
            'is_windows': self.is_windows,
            'is_linux': self.is_linux,
            'open_ports': [p.to_dict() for p in self.open_ports],
            'host_scripts': [s.to_dict() for s in self.host_scripts],
        }

    def to_neo4j_dict(self) -> Dict[str, Any]:
        """Serialize for Neo4j import"""
        return {
            'ip': self.ip,
            'hostname': self.hostname or self.ip,
            'name': self.best_name,
            'os': self.os_display,
            'os_cpe': self.os_cpe or '',
            'domain': self.domain or self.dns_domain or '',
            'netbios_name': self.netbios_name or '',
            'netbios_domain': self.netbios_domain or '',
            'is_dc': self.is_domain_controller,
            'is_windows': self.is_windows,
            'is_linux': self.is_linux,
            'open_port_count': len(self.open_ports),
            'has_smb': self.has_smb,
            'has_rdp': self.has_rdp,
            'has_winrm': self.has_winrm,
            'has_ssh': self.has_ssh,
            'has_web': self.has_web,
            'has_kerberos': self.has_kerberos,
            'has_ldap': self.has_ldap,
        }
