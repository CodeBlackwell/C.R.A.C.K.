"""
UnifiedFinding model with provenance tracking.

Every finding references its source RawInput or FileInput,
enabling "what command found this?" queries.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class FindingType(Enum):
    """Types of findings that can be extracted."""
    # Credentials
    CREDENTIAL = "credential"
    PASSWORD = "password"
    HASH = "hash"
    TICKET = "ticket"
    SSH_KEY = "ssh_key"

    # AD/LDAP
    LDAP_ATTRIBUTE = "ldap_attribute"
    USER_FLAG = "user_flag"
    GROUP_MEMBERSHIP = "group_membership"
    KERBEROASTABLE = "kerberoastable"
    ASREP_ROASTABLE = "asrep_roastable"
    DELEGATION = "delegation"

    # Files
    FILE = "file"
    CONFIG_FILE = "config_file"
    DATABASE = "database"
    REGISTRY = "registry"

    # Network
    HOST = "host"
    SERVICE = "service"
    PORT = "port"
    VULNERABILITY = "vulnerability"

    # Generic
    INFO = "info"
    SENSITIVE_DATA = "sensitive_data"


class FindingPriority(Enum):
    """Priority levels for findings."""
    CRITICAL = 1  # Act immediately (valid credential, admin access)
    HIGH = 2      # Strong attack vector (AS-REP roastable, Kerberoastable)
    MEDIUM = 3    # Worth investigating (interesting file, custom attribute)
    LOW = 4       # Background task (general enumeration)
    INFO = 5      # For reference only (domain info collected)


@dataclass
class UnifiedFinding:
    """
    Unified finding model - merger of PRISM and BloodTrail finding concepts.

    Every finding MUST reference its source RawInput or FileInput to enable
    provenance tracking ("what command found this?").

    Attributes:
        id: UUID for this finding
        finding_type: Category of finding
        source: What generated this ('ldap_enum', 'smb_crawl', 'mimikatz', etc.)
        target: Entity affected (username, file path, attribute name)
        raw_value: Original extracted value
        decoded_value: Decoded/decrypted value (if applicable)
        decode_method: How it was decoded ('base64', 'vnc_des', etc.)

        confidence: How confident we are (0.0-1.0)
        priority: Action priority (1=critical, 5=info)
        tags: Classification tags
        metadata: Additional context

        source_input_id: REQUIRED - RawInput.id or FileInput.id
        source_input_type: 'raw' or 'file'
        extraction_method: Parser/extractor that found this

        engagement_id: Link to engagement
        discovered_at: When finding was extracted
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    finding_type: FindingType = FindingType.INFO
    source: str = ""
    target: str = ""
    raw_value: Any = None
    decoded_value: Optional[str] = None
    decode_method: Optional[str] = None

    # Classification
    confidence: float = 1.0
    priority: FindingPriority = FindingPriority.MEDIUM
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    # PROVENANCE - links back to source input
    source_input_id: str = ""  # REQUIRED: RawInput.id or FileInput.id
    source_input_type: str = "raw"  # 'raw' or 'file'
    extraction_method: str = ""  # Parser/extractor name
    extraction_line: Optional[int] = None  # Line number in output (optional)

    # Context
    engagement_id: Optional[str] = None
    discovered_at: datetime = field(default_factory=datetime.now)

    def __post_init__(self):
        """Convert enum strings to enums if needed."""
        if isinstance(self.finding_type, str):
            self.finding_type = FindingType(self.finding_type)
        if isinstance(self.priority, int):
            self.priority = FindingPriority(self.priority)

    @property
    def has_provenance(self) -> bool:
        """Check if finding has source provenance."""
        return bool(self.source_input_id)

    @property
    def is_credential(self) -> bool:
        """Check if this is a credential-type finding."""
        return self.finding_type in (
            FindingType.CREDENTIAL,
            FindingType.PASSWORD,
            FindingType.HASH,
            FindingType.TICKET,
            FindingType.SSH_KEY,
        )

    @property
    def is_high_value(self) -> bool:
        """Check if this is a high-value finding."""
        return self.priority.value <= FindingPriority.HIGH.value

    def add_tag(self, tag: str):
        """Add a tag if not already present."""
        if tag not in self.tags:
            self.tags.append(tag)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "finding_type": self.finding_type.value,
            "source": self.source,
            "target": self.target,
            "raw_value": str(self.raw_value) if self.raw_value else None,
            "decoded_value": self.decoded_value,
            "decode_method": self.decode_method,
            "confidence": self.confidence,
            "priority": self.priority.value,
            "tags": self.tags,
            "metadata": self.metadata,
            "source_input_id": self.source_input_id,
            "source_input_type": self.source_input_type,
            "extraction_method": self.extraction_method,
            "extraction_line": self.extraction_line,
            "engagement_id": self.engagement_id,
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
        }

    def to_neo4j_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for Neo4j node creation."""
        return {
            "id": self.id,
            "finding_type": self.finding_type.value,
            "source": self.source,
            "target": self.target,
            "raw_value": str(self.raw_value)[:500] if self.raw_value else None,
            "decoded_value": self.decoded_value,
            "decode_method": self.decode_method,
            "confidence": self.confidence,
            "priority": self.priority.value,
            "tags": self.tags,
            "source_input_id": self.source_input_id,
            "source_input_type": self.source_input_type,
            "extraction_method": self.extraction_method,
            "engagement_id": self.engagement_id,
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
            "is_credential": self.is_credential,
            "is_high_value": self.is_high_value,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UnifiedFinding":
        """Create from dictionary."""
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            finding_type=FindingType(data["finding_type"]) if data.get("finding_type") else FindingType.INFO,
            source=data.get("source", ""),
            target=data.get("target", ""),
            raw_value=data.get("raw_value"),
            decoded_value=data.get("decoded_value"),
            decode_method=data.get("decode_method"),
            confidence=data.get("confidence", 1.0),
            priority=FindingPriority(data["priority"]) if data.get("priority") else FindingPriority.MEDIUM,
            tags=data.get("tags", []),
            metadata=data.get("metadata", {}),
            source_input_id=data.get("source_input_id", ""),
            source_input_type=data.get("source_input_type", "raw"),
            extraction_method=data.get("extraction_method", ""),
            extraction_line=data.get("extraction_line"),
            engagement_id=data.get("engagement_id"),
            discovered_at=datetime.fromisoformat(data["discovered_at"]) if data.get("discovered_at") else datetime.now(),
        )

    @classmethod
    def create_credential_finding(
        cls,
        username: str,
        password: str,
        source_input_id: str,
        extraction_method: str,
        *,
        source: str = "unknown",
        confidence: float = 1.0,
        engagement_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> "UnifiedFinding":
        """
        Factory method for credential findings.

        Args:
            username: The username
            password: The password/hash value
            source_input_id: ID of the RawInput/FileInput that contained this
            extraction_method: Parser that extracted it
            source: Source tool/module
            confidence: Confidence level
            engagement_id: Optional engagement link
            metadata: Additional context
        """
        return cls(
            finding_type=FindingType.CREDENTIAL,
            source=source,
            target=username,
            raw_value=password,
            decoded_value=password,
            confidence=confidence,
            priority=FindingPriority.CRITICAL,
            tags=["credential", "plaintext"],
            metadata={
                "username": username,
                "password": password,
                **(metadata or {}),
            },
            source_input_id=source_input_id,
            source_input_type="raw",
            extraction_method=extraction_method,
            engagement_id=engagement_id,
        )

    @classmethod
    def from_bloodtrail_finding(
        cls,
        bt_finding: Any,
        source_input_id: str,
    ) -> "UnifiedFinding":
        """
        Convert a BloodTrail Finding to UnifiedFinding.

        Args:
            bt_finding: BloodTrail Finding object
            source_input_id: ID of the RawInput that generated it
        """
        # Map BloodTrail finding types to our types
        type_map = {
            "LDAP_ATTRIBUTE": FindingType.LDAP_ATTRIBUTE,
            "FILE": FindingType.FILE,
            "GROUP_MEMBERSHIP": FindingType.GROUP_MEMBERSHIP,
            "USER_FLAG": FindingType.USER_FLAG,
            "CREDENTIAL": FindingType.CREDENTIAL,
        }

        finding_type = type_map.get(
            bt_finding.finding_type.name if hasattr(bt_finding.finding_type, "name") else str(bt_finding.finding_type),
            FindingType.INFO
        )

        return cls(
            id=bt_finding.id,
            finding_type=finding_type,
            source=bt_finding.source,
            target=bt_finding.target,
            raw_value=bt_finding.raw_value,
            decoded_value=bt_finding.decoded_value,
            decode_method=bt_finding.decode_method,
            confidence=bt_finding.confidence,
            priority=FindingPriority.MEDIUM,  # BloodTrail doesn't have priority
            tags=bt_finding.tags,
            metadata=bt_finding.metadata,
            source_input_id=source_input_id,
            source_input_type="raw",
            extraction_method="bloodtrail",
        )
