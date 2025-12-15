"""
Engagement Tracking Data Models

Dataclasses for engagement tracking entities:
- Client: Organization or individual
- Engagement: Pentest engagement with scope
- Target: IP address or hostname
- Finding: Vulnerability or issue
- Service: Port/service on target
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional
import uuid


class EngagementStatus(Enum):
    """Engagement lifecycle status"""
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class FindingSeverity(Enum):
    """Finding severity levels (CVSS-aligned)"""
    CRITICAL = "critical"  # CVSS 9.0-10.0
    HIGH = "high"          # CVSS 7.0-8.9
    MEDIUM = "medium"      # CVSS 4.0-6.9
    LOW = "low"            # CVSS 0.1-3.9
    INFO = "info"          # Informational


class TargetStatus(Enum):
    """Target enumeration status"""
    NEW = "new"
    SCANNING = "scanning"
    ENUMERATED = "enumerated"
    EXPLOITED = "exploited"
    COMPLETED = "completed"


class FindingStatus(Enum):
    """Finding lifecycle status"""
    OPEN = "open"
    CONFIRMED = "confirmed"
    EXPLOITED = "exploited"
    REPORTED = "reported"
    REMEDIATED = "remediated"


def generate_id(prefix: str = "") -> str:
    """Generate unique ID with optional prefix"""
    short_uuid = str(uuid.uuid4())[:8]
    return f"{prefix}-{short_uuid}" if prefix else short_uuid


@dataclass
class Client:
    """Organization or individual client"""
    id: str
    name: str
    organization: str = ""
    contact_email: str = ""
    industry: str = ""
    notes: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

    @classmethod
    def create(cls, name: str, **kwargs) -> 'Client':
        """Factory method to create new client"""
        return cls(
            id=generate_id("client"),
            name=name,
            **kwargs
        )

    def to_dict(self) -> dict:
        """Convert to dictionary for storage"""
        return {
            'id': self.id,
            'name': self.name,
            'organization': self.organization,
            'contact_email': self.contact_email,
            'industry': self.industry,
            'notes': self.notes,
            'created_at': self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'Client':
        """Create from dictionary"""
        return cls(
            id=data.get('id', ''),
            name=data.get('name', ''),
            organization=data.get('organization', ''),
            contact_email=data.get('contact_email', ''),
            industry=data.get('industry', ''),
            notes=data.get('notes', ''),
            created_at=data.get('created_at', ''),
        )


@dataclass
class Engagement:
    """Pentest engagement with scope and timeline"""
    id: str
    name: str
    client_id: str
    status: EngagementStatus = EngagementStatus.ACTIVE
    start_date: str = ""
    end_date: str = ""
    scope_type: str = ""  # external, internal, web, mobile, etc.
    scope_text: str = ""  # CIDR ranges, domains, etc.
    rules_of_engagement: str = ""
    notes: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

    @classmethod
    def create(cls, name: str, client_id: str, **kwargs) -> 'Engagement':
        """Factory method to create new engagement"""
        return cls(
            id=generate_id("eng"),
            name=name,
            client_id=client_id,
            start_date=datetime.now().strftime("%Y-%m-%d"),
            **kwargs
        )

    def to_dict(self) -> dict:
        """Convert to dictionary for storage"""
        return {
            'id': self.id,
            'name': self.name,
            'client_id': self.client_id,
            'status': self.status.value if isinstance(self.status, EngagementStatus) else self.status,
            'start_date': self.start_date,
            'end_date': self.end_date,
            'scope_type': self.scope_type,
            'scope_text': self.scope_text,
            'rules_of_engagement': self.rules_of_engagement,
            'notes': self.notes,
            'created_at': self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'Engagement':
        """Create from dictionary"""
        status = data.get('status', 'active')
        if isinstance(status, str):
            status = EngagementStatus(status)

        return cls(
            id=data.get('id', ''),
            name=data.get('name', ''),
            client_id=data.get('client_id', ''),
            status=status,
            start_date=data.get('start_date', ''),
            end_date=data.get('end_date', ''),
            scope_type=data.get('scope_type', ''),
            scope_text=data.get('scope_text', ''),
            rules_of_engagement=data.get('rules_of_engagement', ''),
            notes=data.get('notes', ''),
            created_at=data.get('created_at', ''),
        )


@dataclass
class Target:
    """IP address or hostname in engagement scope"""
    id: str
    ip_address: str = ""
    hostname: str = ""
    os_guess: str = ""
    status: TargetStatus = TargetStatus.NEW
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    last_seen: str = ""
    notes: str = ""

    @classmethod
    def create(cls, ip_or_hostname: str, **kwargs) -> 'Target':
        """Factory method to create new target"""
        # Detect if IP or hostname
        import re
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'

        if re.match(ip_pattern, ip_or_hostname):
            ip_address = ip_or_hostname
            hostname = kwargs.pop('hostname', '')
        else:
            hostname = ip_or_hostname
            ip_address = kwargs.pop('ip_address', '')

        return cls(
            id=generate_id("target"),
            ip_address=ip_address,
            hostname=hostname,
            **kwargs
        )

    @property
    def display_name(self) -> str:
        """Human-readable target identifier"""
        if self.hostname and self.ip_address:
            return f"{self.hostname} ({self.ip_address})"
        return self.hostname or self.ip_address or self.id

    def to_dict(self) -> dict:
        """Convert to dictionary for storage"""
        return {
            'id': self.id,
            'ip_address': self.ip_address,
            'hostname': self.hostname,
            'os_guess': self.os_guess,
            'status': self.status.value if isinstance(self.status, TargetStatus) else self.status,
            'first_seen': self.first_seen,
            'last_seen': self.last_seen,
            'notes': self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'Target':
        """Create from dictionary"""
        status = data.get('status', 'new')
        if isinstance(status, str):
            try:
                status = TargetStatus(status)
            except ValueError:
                status = TargetStatus.NEW

        return cls(
            id=data.get('id', ''),
            ip_address=data.get('ip_address', ''),
            hostname=data.get('hostname', ''),
            os_guess=data.get('os_guess', ''),
            status=status,
            first_seen=data.get('first_seen', ''),
            last_seen=data.get('last_seen', ''),
            notes=data.get('notes', ''),
        )


@dataclass
class Service:
    """Service running on target port"""
    id: str
    target_id: str
    port: int
    protocol: str = "tcp"
    service_name: str = ""
    version: str = ""
    banner: str = ""
    state: str = "open"
    found_at: str = field(default_factory=lambda: datetime.now().isoformat())

    @classmethod
    def create(cls, target_id: str, port: int, **kwargs) -> 'Service':
        """Factory method to create new service"""
        return cls(
            id=generate_id("svc"),
            target_id=target_id,
            port=port,
            **kwargs
        )

    @property
    def display_name(self) -> str:
        """Human-readable service identifier"""
        name = self.service_name or "unknown"
        version = f" {self.version}" if self.version else ""
        return f"{self.port}/{self.protocol} {name}{version}"

    def to_dict(self) -> dict:
        """Convert to dictionary for storage"""
        return {
            'id': self.id,
            'target_id': self.target_id,
            'port': self.port,
            'protocol': self.protocol,
            'service_name': self.service_name,
            'version': self.version,
            'banner': self.banner,
            'state': self.state,
            'found_at': self.found_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'Service':
        """Create from dictionary"""
        return cls(
            id=data.get('id', ''),
            target_id=data.get('target_id', ''),
            port=data.get('port', 0),
            protocol=data.get('protocol', 'tcp'),
            service_name=data.get('service_name', ''),
            version=data.get('version', ''),
            banner=data.get('banner', ''),
            state=data.get('state', 'open'),
            found_at=data.get('found_at', ''),
        )


@dataclass
class Finding:
    """Vulnerability or issue discovered during engagement"""
    id: str
    title: str
    severity: FindingSeverity = FindingSeverity.MEDIUM
    cvss_score: str = ""
    cve_id: str = ""
    description: str = ""
    impact: str = ""
    remediation: str = ""
    evidence: str = ""
    status: FindingStatus = FindingStatus.OPEN
    found_at: str = field(default_factory=lambda: datetime.now().isoformat())
    affected_targets: List[str] = field(default_factory=list)

    @classmethod
    def create(cls, title: str, severity: str = "medium", **kwargs) -> 'Finding':
        """Factory method to create new finding"""
        if isinstance(severity, str):
            severity = FindingSeverity(severity.lower())

        return cls(
            id=generate_id("finding"),
            title=title,
            severity=severity,
            **kwargs
        )

    def to_dict(self) -> dict:
        """Convert to dictionary for storage"""
        return {
            'id': self.id,
            'title': self.title,
            'severity': self.severity.value if isinstance(self.severity, FindingSeverity) else self.severity,
            'cvss_score': self.cvss_score,
            'cve_id': self.cve_id,
            'description': self.description,
            'impact': self.impact,
            'remediation': self.remediation,
            'evidence': self.evidence,
            'status': self.status.value if isinstance(self.status, FindingStatus) else self.status,
            'found_at': self.found_at,
            'affected_targets': self.affected_targets,
        }

    @classmethod
    def from_dict(cls, data: dict) -> 'Finding':
        """Create from dictionary"""
        severity = data.get('severity', 'medium')
        if isinstance(severity, str):
            try:
                severity = FindingSeverity(severity.lower())
            except ValueError:
                severity = FindingSeverity.MEDIUM

        status = data.get('status', 'open')
        if isinstance(status, str):
            try:
                status = FindingStatus(status.lower())
            except ValueError:
                status = FindingStatus.OPEN

        return cls(
            id=data.get('id', ''),
            title=data.get('title', ''),
            severity=severity,
            cvss_score=data.get('cvss_score', ''),
            cve_id=data.get('cve_id', ''),
            description=data.get('description', ''),
            impact=data.get('impact', ''),
            remediation=data.get('remediation', ''),
            evidence=data.get('evidence', ''),
            status=status,
            found_at=data.get('found_at', ''),
            affected_targets=data.get('affected_targets', []),
        )


if __name__ == '__main__':
    # Test models
    print("Testing engagement models...")

    # Create client
    client = Client.create("ACME Corp", organization="ACME Corporation")
    print(f"Client: {client.to_dict()}")

    # Create engagement
    eng = Engagement.create("Q4 External Pentest", client.id, scope_type="external")
    print(f"Engagement: {eng.to_dict()}")

    # Create target
    target = Target.create("192.168.1.100", hostname="web01.acme.local")
    print(f"Target: {target.display_name}")

    # Create service
    svc = Service.create(target.id, 80, service_name="http", version="Apache/2.4.41")
    print(f"Service: {svc.display_name}")

    # Create finding
    finding = Finding.create(
        "SQL Injection in Login Form",
        severity="critical",
        cve_id="CVE-2024-12345",
        affected_targets=[target.id]
    )
    print(f"Finding: {finding.to_dict()}")

    print("\nAll models working!")
