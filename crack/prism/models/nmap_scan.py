"""
Nmap Scan Summary Model

Aggregated results from parsing nmap output.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime

from .nmap_host import NmapHost


@dataclass
class NmapScanSummary:
    """Aggregated results from parsing nmap output"""

    # Source information
    source_file: str
    source_tool: str = "nmap"
    parse_time: datetime = field(default_factory=datetime.now)

    # Scan metadata
    nmap_command: str = ""
    nmap_version: str = ""
    scan_start: Optional[datetime] = None
    scan_end: Optional[datetime] = None
    scan_duration: Optional[float] = None  # seconds

    # Target info
    target_spec: str = ""

    # Hosts
    hosts: List[NmapHost] = field(default_factory=list)

    # Statistics
    lines_parsed: int = 0

    # Warnings/errors during parsing
    warnings: List[str] = field(default_factory=list)

    @property
    def hosts_up(self) -> List[NmapHost]:
        """Filter to hosts that are up"""
        return [h for h in self.hosts if h.is_up]

    @property
    def hosts_down(self) -> List[NmapHost]:
        """Filter to hosts that are down"""
        return [h for h in self.hosts if not h.is_up]

    @property
    def domain_controllers(self) -> List[NmapHost]:
        """Filter to likely domain controllers"""
        return [h for h in self.hosts_up if h.is_domain_controller]

    @property
    def windows_hosts(self) -> List[NmapHost]:
        """Filter to Windows hosts"""
        return [h for h in self.hosts_up if h.is_windows]

    @property
    def linux_hosts(self) -> List[NmapHost]:
        """Filter to Linux hosts"""
        return [h for h in self.hosts_up if h.is_linux]

    @property
    def hosts_with_smb(self) -> List[NmapHost]:
        """Filter to hosts with SMB"""
        return [h for h in self.hosts_up if h.has_smb]

    @property
    def hosts_with_rdp(self) -> List[NmapHost]:
        """Filter to hosts with RDP"""
        return [h for h in self.hosts_up if h.has_rdp]

    @property
    def hosts_with_winrm(self) -> List[NmapHost]:
        """Filter to hosts with WinRM"""
        return [h for h in self.hosts_up if h.has_winrm]

    @property
    def hosts_with_ssh(self) -> List[NmapHost]:
        """Filter to hosts with SSH"""
        return [h for h in self.hosts_up if h.has_ssh]

    @property
    def hosts_with_web(self) -> List[NmapHost]:
        """Filter to hosts with HTTP/HTTPS"""
        return [h for h in self.hosts_up if h.has_web]

    @property
    def hosts_with_kerberos(self) -> List[NmapHost]:
        """Filter to hosts with Kerberos"""
        return [h for h in self.hosts_up if h.has_kerberos]

    @property
    def hosts_with_ldap(self) -> List[NmapHost]:
        """Filter to hosts with LDAP"""
        return [h for h in self.hosts_up if h.has_ldap]

    @property
    def unique_domains(self) -> List[str]:
        """List of unique domains found"""
        domains = set()
        for h in self.hosts_up:
            if h.domain:
                domains.add(h.domain.upper())
            if h.dns_domain:
                domains.add(h.dns_domain.upper())
            if h.netbios_domain:
                domains.add(h.netbios_domain.upper())
        return sorted(domains)

    @property
    def all_open_ports(self) -> Dict[int, int]:
        """Count of each open port across all hosts"""
        port_counts: Dict[int, int] = {}
        for host in self.hosts_up:
            for port in host.open_ports:
                port_counts[port.port] = port_counts.get(port.port, 0) + 1
        return dict(sorted(port_counts.items()))

    @property
    def common_ports(self) -> List[int]:
        """Ports open on multiple hosts"""
        return [port for port, count in self.all_open_ports.items() if count > 1]

    @property
    def stats(self) -> Dict[str, int]:
        """Quick statistics summary"""
        return {
            'total_hosts': len(self.hosts),
            'hosts_up': len(self.hosts_up),
            'hosts_down': len(self.hosts_down),
            'domain_controllers': len(self.domain_controllers),
            'windows_hosts': len(self.windows_hosts),
            'linux_hosts': len(self.linux_hosts),
            'unique_open_ports': len(self.all_open_ports),
            'total_open_ports': sum(len(h.open_ports) for h in self.hosts_up),
            'hosts_with_smb': len(self.hosts_with_smb),
            'hosts_with_rdp': len(self.hosts_with_rdp),
            'hosts_with_winrm': len(self.hosts_with_winrm),
            'hosts_with_ssh': len(self.hosts_with_ssh),
            'hosts_with_web': len(self.hosts_with_web),
        }

    def get_hosts_with_port(self, port: int) -> List[NmapHost]:
        """Get all hosts with a specific port open"""
        return [h for h in self.hosts_up if port in h.open_port_numbers]

    def get_hosts_with_service(self, service: str) -> List[NmapHost]:
        """Get all hosts running a specific service"""
        service = service.lower()
        return [h for h in self.hosts_up
                if any(service in p.service.lower() for p in h.open_ports)]

    def get_host_by_ip(self, ip: str) -> Optional[NmapHost]:
        """Get host by IP address"""
        for host in self.hosts:
            if host.ip == ip:
                return host
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'source_file': self.source_file,
            'source_tool': self.source_tool,
            'parse_time': self.parse_time.isoformat(),
            'nmap_command': self.nmap_command,
            'nmap_version': self.nmap_version,
            'scan_start': self.scan_start.isoformat() if self.scan_start else None,
            'scan_end': self.scan_end.isoformat() if self.scan_end else None,
            'scan_duration': self.scan_duration,
            'stats': self.stats,
            'unique_domains': self.unique_domains,
            'hosts': [h.to_dict() for h in self.hosts_up],
        }

    def to_json(self) -> str:
        """Serialize to JSON string"""
        import json
        return json.dumps(self.to_dict(), indent=2, default=str)
