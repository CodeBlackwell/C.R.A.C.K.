"""
Unified dual-store interface (SQLite + Neo4j).

Provides a single interface that:
- Stores blobs in SQLite
- Stores relationships and metadata in Neo4j
- Handles --no-prism mode (no-op when disabled)
"""

from typing import Any, Dict, List, Optional

from ..config import PersistenceConfig
from ..models.raw_input import RawInput, FileInput
from ..models.finding import UnifiedFinding
from .sqlite_store import SQLiteStore


class DualStore:
    """
    Unified storage interface combining SQLite and Neo4j.

    SQLite handles:
    - Raw command output blobs
    - File content blobs
    - Finding metadata

    Neo4j handles (when enabled):
    - RawInput metadata nodes
    - Finding nodes
    - EXTRACTED_FROM relationships
    - Target/Engagement relationships

    Respects --no-prism mode for standalone operation.
    """

    def __init__(
        self,
        sqlite_path: Optional[str] = None,
        neo4j_enabled: bool = True,
    ):
        """
        Initialize dual store.

        Args:
            sqlite_path: Path to SQLite database
            neo4j_enabled: Whether to write to Neo4j
        """
        self.config = PersistenceConfig.get()
        self._sqlite: Optional[SQLiteStore] = None
        self._neo4j_enabled = neo4j_enabled and self.config.neo4j_enabled
        self._neo4j = None  # Lazy-loaded

        # Override paths if provided
        if sqlite_path:
            self.config.sqlite_path = sqlite_path

    @property
    def sqlite(self) -> SQLiteStore:
        """Lazy-load SQLite store."""
        if self._sqlite is None:
            self._sqlite = SQLiteStore(self.config.sqlite_path)
        return self._sqlite

    @property
    def neo4j(self):
        """Lazy-load Neo4j adapter."""
        if self._neo4j is None and self._neo4j_enabled:
            try:
                from .neo4j_store import PersistenceNeo4jAdapter
                self._neo4j = PersistenceNeo4jAdapter()
            except ImportError:
                self._neo4j_enabled = False
            except Exception:
                # Neo4j not available
                self._neo4j_enabled = False
        return self._neo4j

    def is_enabled(self) -> bool:
        """Check if persistence is enabled (respects --no-prism)."""
        return PersistenceConfig.is_enabled()

    # ==================== RawInput Operations ====================

    def save_raw_input(self, raw_input: RawInput) -> Optional[str]:
        """
        Save a RawInput to both stores.

        Args:
            raw_input: The RawInput to save

        Returns:
            The raw_input ID, or None if persistence disabled
        """
        if not self.is_enabled():
            return None

        # Always save to SQLite (blobs)
        self.sqlite.save_raw_input(raw_input)

        # Save metadata to Neo4j (if enabled)
        if self.neo4j:
            try:
                self.neo4j.save_raw_input_metadata(raw_input)
            except Exception:
                pass  # Neo4j is optional

        return raw_input.id

    def get_raw_input(self, raw_input_id: str) -> Optional[RawInput]:
        """
        Retrieve a RawInput by ID.

        Always reads from SQLite (has the blobs).
        """
        if not self.is_enabled():
            return None
        return self.sqlite.get_raw_input(raw_input_id)

    def query_raw_inputs(
        self,
        source_tool: Optional[str] = None,
        target_ip: Optional[str] = None,
        engagement_id: Optional[str] = None,
        unparsed_only: bool = False,
        limit: int = 100,
    ) -> List[RawInput]:
        """Query raw inputs with filters."""
        if not self.is_enabled():
            return []
        return self.sqlite.query_raw_inputs(
            source_tool=source_tool,
            target_ip=target_ip,
            engagement_id=engagement_id,
            unparsed_only=unparsed_only,
            limit=limit,
        )

    def mark_parsed(
        self,
        raw_input_id: str,
        parser_used: str,
        finding_count: int = 0,
    ):
        """Mark a raw input as parsed."""
        if not self.is_enabled():
            return

        self.sqlite.mark_raw_input_parsed(raw_input_id, parser_used, finding_count)

        if self.neo4j:
            try:
                self.neo4j.mark_raw_input_parsed(raw_input_id, parser_used, finding_count)
            except Exception:
                pass

    # ==================== FileInput Operations ====================

    def save_file_input(self, file_input: FileInput) -> Optional[str]:
        """Save a FileInput to both stores."""
        if not self.is_enabled():
            return None

        # Check for duplicate by hash
        existing = self.sqlite.get_file_input_by_hash(file_input.file_hash)
        if existing:
            return existing.id

        self.sqlite.save_file_input(file_input)

        if self.neo4j:
            try:
                self.neo4j.save_file_input_metadata(file_input)
            except Exception:
                pass

        return file_input.id

    def get_file_input(self, file_input_id: str) -> Optional[FileInput]:
        """Retrieve a FileInput by ID."""
        if not self.is_enabled():
            return None
        return self.sqlite.get_file_input(file_input_id)

    # ==================== Finding Operations ====================

    def save_finding(self, finding: UnifiedFinding) -> Optional[str]:
        """
        Save a Finding to both stores.

        Creates EXTRACTED_FROM relationship in Neo4j.
        """
        if not self.is_enabled():
            return None

        self.sqlite.save_finding(finding)

        if self.neo4j:
            try:
                self.neo4j.save_finding(finding)
                # Create relationship to source input
                if finding.source_input_id:
                    self.neo4j.create_extracted_from_relationship(
                        finding.id,
                        finding.source_input_id,
                        finding.extraction_method,
                        finding.extraction_line,
                    )
            except Exception:
                pass

        return finding.id

    def save_findings(self, findings: List[UnifiedFinding]) -> List[str]:
        """Save multiple findings."""
        return [
            self.save_finding(f)
            for f in findings
            if self.save_finding(f) is not None
        ]

    def get_finding(self, finding_id: str) -> Optional[UnifiedFinding]:
        """Retrieve a Finding by ID."""
        if not self.is_enabled():
            return None
        return self.sqlite.get_finding(finding_id)

    def query_findings(
        self,
        finding_type: Optional[str] = None,
        source_input_id: Optional[str] = None,
        engagement_id: Optional[str] = None,
        priority_max: Optional[int] = None,
        limit: int = 100,
    ) -> List[UnifiedFinding]:
        """Query findings with filters."""
        if not self.is_enabled():
            return []
        return self.sqlite.query_findings(
            finding_type=finding_type,
            source_input_id=source_input_id,
            engagement_id=engagement_id,
            priority_max=priority_max,
            limit=limit,
        )

    def get_findings_for_input(self, source_input_id: str) -> List[UnifiedFinding]:
        """Get all findings extracted from a specific raw input."""
        if not self.is_enabled():
            return []
        return self.sqlite.get_findings_for_input(source_input_id)

    # ==================== Provenance Queries ====================

    def get_raw_input_for_finding(self, finding_id: str) -> Optional[RawInput]:
        """
        Get the raw input that generated a finding.

        This is the core provenance query: "what command found this?"
        """
        if not self.is_enabled():
            return None

        finding = self.sqlite.get_finding(finding_id)
        if not finding or not finding.source_input_id:
            return None

        if finding.source_input_type == "file":
            # Return file input as a "pseudo" raw input
            file_input = self.sqlite.get_file_input(finding.source_input_id)
            if file_input:
                return RawInput(
                    id=file_input.id,
                    command=f"file://{file_input.file_path}",
                    stdout=file_input.content or b"",
                    source_tool="prism",
                    source_module="file_parser",
                    engagement_id=file_input.engagement_id,
                )
            return None

        return self.sqlite.get_raw_input(finding.source_input_id)

    # ==================== Statistics ====================

    def get_stats(self) -> Dict[str, Any]:
        """Get storage statistics."""
        if not self.is_enabled():
            return {"enabled": False}

        stats = self.sqlite.get_stats()
        stats["enabled"] = True
        stats["neo4j_enabled"] = self._neo4j_enabled

        return stats


# Global singleton instance
_default_store: Optional[DualStore] = None


def get_store() -> DualStore:
    """Get the global DualStore instance."""
    global _default_store
    if _default_store is None:
        _default_store = DualStore()
    return _default_store


def reset_store():
    """Reset the global store (for testing)."""
    global _default_store
    _default_store = None
