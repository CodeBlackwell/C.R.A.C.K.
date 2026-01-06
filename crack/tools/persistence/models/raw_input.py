"""
RawInput and FileInput models for capturing command/file data.

Every subprocess execution or file parse is stored with:
- UUID for provenance tracking
- Raw bytes (stdout/stderr or file content)
- Metadata (source tool, target, timing)
- Processing status (parsed, finding count)
"""

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional


@dataclass
class RawInput:
    """
    Captures every subprocess execution with full input/output.

    Stored in SQLite for blob efficiency, referenced by ID in Neo4j.

    Attributes:
        id: UUID for this execution (used for provenance)
        command: Full command string
        args: Command arguments as list
        stdout: Raw stdout bytes
        stderr: Raw stderr bytes
        exit_code: Process exit code
        started_at: When execution started
        ended_at: When execution completed
        duration_ms: Execution time in milliseconds

        source_tool: Tool that triggered this ('bloodtrail', 'prism', etc.)
        source_module: Specific module (e.g., 'enumerators.enum4linux')

        target_ip: Target IP address (if applicable)
        target_hostname: Target hostname (if applicable)
        target_domain: Target domain (if applicable)

        engagement_id: Link to engagement (optional)

        parsed: Whether output has been parsed
        parser_used: Parser that processed this output
        finding_count: Number of findings extracted
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    command: str = ""
    args: List[str] = field(default_factory=list)
    stdout: bytes = b""
    stderr: bytes = b""
    exit_code: Optional[int] = None
    started_at: datetime = field(default_factory=datetime.now)
    ended_at: Optional[datetime] = None
    duration_ms: Optional[int] = None

    # Source tracking
    source_tool: str = ""
    source_module: str = ""

    # Target context
    target_ip: Optional[str] = None
    target_hostname: Optional[str] = None
    target_domain: Optional[str] = None

    # Engagement link
    engagement_id: Optional[str] = None

    # Processing status
    parsed: bool = False
    parser_used: Optional[str] = None
    finding_count: int = 0

    # Additional metadata
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def stdout_text(self) -> str:
        """Decode stdout as text (UTF-8 with fallback to latin-1)."""
        if not self.stdout:
            return ""
        try:
            return self.stdout.decode("utf-8")
        except UnicodeDecodeError:
            return self.stdout.decode("latin-1")

    @property
    def stderr_text(self) -> str:
        """Decode stderr as text (UTF-8 with fallback to latin-1)."""
        if not self.stderr:
            return ""
        try:
            return self.stderr.decode("utf-8")
        except UnicodeDecodeError:
            return self.stderr.decode("latin-1")

    @property
    def output_text(self) -> str:
        """Combined stdout + stderr as text."""
        return self.stdout_text + self.stderr_text

    @property
    def success(self) -> bool:
        """Command completed successfully (exit code 0)."""
        return self.exit_code == 0

    @property
    def failed(self) -> bool:
        """Command failed (non-zero exit code)."""
        return self.exit_code is not None and self.exit_code != 0

    @property
    def stdout_preview(self) -> str:
        """First 500 chars of stdout for display."""
        text = self.stdout_text
        if len(text) > 500:
            return text[:500] + "..."
        return text

    def mark_parsed(self, parser_name: str, finding_count: int = 0):
        """Mark this input as parsed."""
        self.parsed = True
        self.parser_used = parser_name
        self.finding_count = finding_count

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "command": self.command,
            "args": self.args,
            "exit_code": self.exit_code,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "ended_at": self.ended_at.isoformat() if self.ended_at else None,
            "duration_ms": self.duration_ms,
            "source_tool": self.source_tool,
            "source_module": self.source_module,
            "target_ip": self.target_ip,
            "target_hostname": self.target_hostname,
            "target_domain": self.target_domain,
            "engagement_id": self.engagement_id,
            "parsed": self.parsed,
            "parser_used": self.parser_used,
            "finding_count": self.finding_count,
            "metadata": self.metadata,
            # Blobs stored separately
            "stdout_size": len(self.stdout),
            "stderr_size": len(self.stderr),
        }

    def to_neo4j_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary for Neo4j node creation.

        Excludes blobs (stored in SQLite).
        """
        return {
            "id": self.id,
            "command": self.command,
            "exit_code": self.exit_code,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "duration_ms": self.duration_ms,
            "source_tool": self.source_tool,
            "source_module": self.source_module,
            "target_ip": self.target_ip,
            "target_hostname": self.target_hostname,
            "target_domain": self.target_domain,
            "engagement_id": self.engagement_id,
            "parsed": self.parsed,
            "parser_used": self.parser_used,
            "finding_count": self.finding_count,
            "stdout_preview": self.stdout_preview[:200] if self.stdout else None,
            "success": self.success,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], stdout: bytes = b"", stderr: bytes = b"") -> "RawInput":
        """Create from dictionary (blobs provided separately)."""
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            command=data.get("command", ""),
            args=data.get("args", []),
            stdout=stdout,
            stderr=stderr,
            exit_code=data.get("exit_code"),
            started_at=datetime.fromisoformat(data["started_at"]) if data.get("started_at") else datetime.now(),
            ended_at=datetime.fromisoformat(data["ended_at"]) if data.get("ended_at") else None,
            duration_ms=data.get("duration_ms"),
            source_tool=data.get("source_tool", ""),
            source_module=data.get("source_module", ""),
            target_ip=data.get("target_ip"),
            target_hostname=data.get("target_hostname"),
            target_domain=data.get("target_domain"),
            engagement_id=data.get("engagement_id"),
            parsed=data.get("parsed", False),
            parser_used=data.get("parser_used"),
            finding_count=data.get("finding_count", 0),
            metadata=data.get("metadata", {}),
        )


@dataclass
class FileInput:
    """
    Captures file-based input (for PRISM file parsing).

    Tracks files that have been parsed along with their content
    and extraction results.

    Attributes:
        id: UUID for this file input
        file_path: Original path to the file
        file_hash: SHA256 hash for deduplication
        file_size: Size in bytes
        content: File content (optional - may store externally)
        engagement_id: Link to engagement
        parsed: Whether file has been parsed
        parser_used: Parser that processed this file
        finding_count: Number of findings extracted
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    file_path: str = ""
    file_hash: Optional[str] = None
    file_size: int = 0
    content: Optional[bytes] = None
    engagement_id: Optional[str] = None
    parsed: bool = False
    parser_used: Optional[str] = None
    finding_count: int = 0
    created_at: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def content_text(self) -> str:
        """Decode content as text."""
        if not self.content:
            return ""
        try:
            return self.content.decode("utf-8")
        except UnicodeDecodeError:
            return self.content.decode("latin-1")

    def mark_parsed(self, parser_name: str, finding_count: int = 0):
        """Mark this file as parsed."""
        self.parsed = True
        self.parser_used = parser_name
        self.finding_count = finding_count

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "file_path": self.file_path,
            "file_hash": self.file_hash,
            "file_size": self.file_size,
            "engagement_id": self.engagement_id,
            "parsed": self.parsed,
            "parser_used": self.parser_used,
            "finding_count": self.finding_count,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], content: Optional[bytes] = None) -> "FileInput":
        """Create from dictionary."""
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            file_path=data.get("file_path", ""),
            file_hash=data.get("file_hash"),
            file_size=data.get("file_size", 0),
            content=content,
            engagement_id=data.get("engagement_id"),
            parsed=data.get("parsed", False),
            parser_used=data.get("parser_used"),
            finding_count=data.get("finding_count", 0),
            created_at=datetime.fromisoformat(data["created_at"]) if data.get("created_at") else datetime.now(),
            metadata=data.get("metadata", {}),
        )

    @classmethod
    def from_file(cls, file_path: str, engagement_id: Optional[str] = None) -> "FileInput":
        """Create from file path, reading content and computing hash."""
        import hashlib
        from pathlib import Path

        path = Path(file_path)
        content = path.read_bytes()
        file_hash = hashlib.sha256(content).hexdigest()

        return cls(
            file_path=str(path.absolute()),
            file_hash=file_hash,
            file_size=len(content),
            content=content,
            engagement_id=engagement_id,
        )
