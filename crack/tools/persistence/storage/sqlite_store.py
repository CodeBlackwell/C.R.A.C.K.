"""
SQLite storage for raw command/file blobs.

Stores large binary data (stdout/stderr, file contents) in SQLite,
with metadata for querying. Neo4j stores relationships.
"""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional, Tuple

from ..config import PersistenceConfig
from ..models.raw_input import RawInput, FileInput
from ..models.finding import UnifiedFinding


class SQLiteStore:
    """
    SQLite storage backend for raw inputs and findings.

    Handles:
    - Raw command output blobs (stdout/stderr)
    - File content blobs
    - Finding metadata (relationships in Neo4j)
    """

    SCHEMA = """
    -- Raw command executions
    CREATE TABLE IF NOT EXISTS raw_inputs (
        id TEXT PRIMARY KEY,
        command TEXT NOT NULL,
        args TEXT,
        stdout BLOB,
        stderr BLOB,
        exit_code INTEGER,
        started_at TEXT NOT NULL,
        ended_at TEXT,
        duration_ms INTEGER,

        source_tool TEXT NOT NULL,
        source_module TEXT,

        target_ip TEXT,
        target_hostname TEXT,
        target_domain TEXT,
        engagement_id TEXT,

        parsed INTEGER DEFAULT 0,
        parser_used TEXT,
        finding_count INTEGER DEFAULT 0,
        metadata TEXT,

        created_at TEXT DEFAULT (datetime('now'))
    );

    -- File inputs for PRISM parsing
    CREATE TABLE IF NOT EXISTS file_inputs (
        id TEXT PRIMARY KEY,
        file_path TEXT NOT NULL,
        file_hash TEXT,
        file_size INTEGER,
        content BLOB,
        engagement_id TEXT,
        parsed INTEGER DEFAULT 0,
        parser_used TEXT,
        finding_count INTEGER DEFAULT 0,
        metadata TEXT,
        created_at TEXT DEFAULT (datetime('now'))
    );

    -- Findings (metadata here, relationships in Neo4j)
    CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        finding_type TEXT NOT NULL,
        source TEXT,
        target TEXT,
        raw_value TEXT,
        decoded_value TEXT,
        decode_method TEXT,
        confidence REAL DEFAULT 1.0,
        priority INTEGER DEFAULT 3,
        tags TEXT,
        metadata TEXT,

        source_input_id TEXT NOT NULL,
        source_input_type TEXT DEFAULT 'raw',
        extraction_method TEXT,
        extraction_line INTEGER,

        engagement_id TEXT,
        discovered_at TEXT,
        created_at TEXT DEFAULT (datetime('now')),

        FOREIGN KEY (source_input_id) REFERENCES raw_inputs(id)
    );

    -- Indexes for common queries
    CREATE INDEX IF NOT EXISTS idx_raw_inputs_source ON raw_inputs(source_tool, created_at);
    CREATE INDEX IF NOT EXISTS idx_raw_inputs_target ON raw_inputs(target_ip, created_at);
    CREATE INDEX IF NOT EXISTS idx_raw_inputs_engagement ON raw_inputs(engagement_id);
    CREATE INDEX IF NOT EXISTS idx_raw_inputs_unparsed ON raw_inputs(parsed) WHERE parsed = 0;

    CREATE INDEX IF NOT EXISTS idx_file_inputs_hash ON file_inputs(file_hash);
    CREATE INDEX IF NOT EXISTS idx_file_inputs_engagement ON file_inputs(engagement_id);

    CREATE INDEX IF NOT EXISTS idx_findings_type ON findings(finding_type);
    CREATE INDEX IF NOT EXISTS idx_findings_source_input ON findings(source_input_id);
    CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement_id);
    CREATE INDEX IF NOT EXISTS idx_findings_priority ON findings(priority);
    """

    def __init__(self, db_path: Optional[str] = None):
        """
        Initialize SQLite store.

        Args:
            db_path: Path to SQLite database (default from config)
        """
        config = PersistenceConfig.get()
        self.db_path = db_path or config.sqlite_path
        self._ensure_schema()

    def _ensure_schema(self):
        """Create tables if they don't exist."""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(self.SCHEMA)

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        """Context manager for database connections."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ==================== RawInput Operations ====================

    def save_raw_input(self, raw_input: RawInput) -> str:
        """
        Save a RawInput to the database.

        Returns:
            The raw_input ID
        """
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO raw_inputs (
                    id, command, args, stdout, stderr, exit_code,
                    started_at, ended_at, duration_ms,
                    source_tool, source_module,
                    target_ip, target_hostname, target_domain,
                    engagement_id, parsed, parser_used, finding_count, metadata
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    raw_input.id,
                    raw_input.command,
                    json.dumps(raw_input.args),
                    raw_input.stdout,
                    raw_input.stderr,
                    raw_input.exit_code,
                    raw_input.started_at.isoformat() if raw_input.started_at else None,
                    raw_input.ended_at.isoformat() if raw_input.ended_at else None,
                    raw_input.duration_ms,
                    raw_input.source_tool,
                    raw_input.source_module,
                    raw_input.target_ip,
                    raw_input.target_hostname,
                    raw_input.target_domain,
                    raw_input.engagement_id,
                    1 if raw_input.parsed else 0,
                    raw_input.parser_used,
                    raw_input.finding_count,
                    json.dumps(raw_input.metadata),
                ),
            )
        return raw_input.id

    def get_raw_input(self, raw_input_id: str) -> Optional[RawInput]:
        """
        Retrieve a RawInput by ID.

        Args:
            raw_input_id: UUID of the raw input

        Returns:
            RawInput or None if not found
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM raw_inputs WHERE id = ?",
                (raw_input_id,)
            ).fetchone()

            if not row:
                return None

            return self._row_to_raw_input(row)

    def _row_to_raw_input(self, row: sqlite3.Row) -> RawInput:
        """Convert SQLite row to RawInput."""
        return RawInput(
            id=row["id"],
            command=row["command"],
            args=json.loads(row["args"]) if row["args"] else [],
            stdout=row["stdout"] or b"",
            stderr=row["stderr"] or b"",
            exit_code=row["exit_code"],
            started_at=datetime.fromisoformat(row["started_at"]) if row["started_at"] else datetime.now(),
            ended_at=datetime.fromisoformat(row["ended_at"]) if row["ended_at"] else None,
            duration_ms=row["duration_ms"],
            source_tool=row["source_tool"],
            source_module=row["source_module"],
            target_ip=row["target_ip"],
            target_hostname=row["target_hostname"],
            target_domain=row["target_domain"],
            engagement_id=row["engagement_id"],
            parsed=bool(row["parsed"]),
            parser_used=row["parser_used"],
            finding_count=row["finding_count"],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
        )

    def query_raw_inputs(
        self,
        source_tool: Optional[str] = None,
        target_ip: Optional[str] = None,
        engagement_id: Optional[str] = None,
        unparsed_only: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> List[RawInput]:
        """
        Query raw inputs with filters.

        Args:
            source_tool: Filter by source tool
            target_ip: Filter by target IP
            engagement_id: Filter by engagement
            unparsed_only: Only return unparsed inputs
            limit: Max results
            offset: Pagination offset

        Returns:
            List of matching RawInput objects
        """
        conditions = []
        params = []

        if source_tool:
            conditions.append("source_tool = ?")
            params.append(source_tool)
        if target_ip:
            conditions.append("target_ip = ?")
            params.append(target_ip)
        if engagement_id:
            conditions.append("engagement_id = ?")
            params.append(engagement_id)
        if unparsed_only:
            conditions.append("parsed = 0")

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        query = f"""
            SELECT * FROM raw_inputs
            {where_clause}
            ORDER BY started_at DESC
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_raw_input(row) for row in rows]

    def mark_raw_input_parsed(
        self,
        raw_input_id: str,
        parser_used: str,
        finding_count: int = 0,
    ):
        """Mark a raw input as parsed."""
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE raw_inputs
                SET parsed = 1, parser_used = ?, finding_count = ?
                WHERE id = ?
                """,
                (parser_used, finding_count, raw_input_id),
            )

    # ==================== FileInput Operations ====================

    def save_file_input(self, file_input: FileInput) -> str:
        """Save a FileInput to the database."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO file_inputs (
                    id, file_path, file_hash, file_size, content,
                    engagement_id, parsed, parser_used, finding_count,
                    metadata, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    file_input.id,
                    file_input.file_path,
                    file_input.file_hash,
                    file_input.file_size,
                    file_input.content,
                    file_input.engagement_id,
                    1 if file_input.parsed else 0,
                    file_input.parser_used,
                    file_input.finding_count,
                    json.dumps(file_input.metadata),
                    file_input.created_at.isoformat() if file_input.created_at else None,
                ),
            )
        return file_input.id

    def get_file_input(self, file_input_id: str) -> Optional[FileInput]:
        """Retrieve a FileInput by ID."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM file_inputs WHERE id = ?",
                (file_input_id,)
            ).fetchone()

            if not row:
                return None

            return FileInput(
                id=row["id"],
                file_path=row["file_path"],
                file_hash=row["file_hash"],
                file_size=row["file_size"],
                content=row["content"],
                engagement_id=row["engagement_id"],
                parsed=bool(row["parsed"]),
                parser_used=row["parser_used"],
                finding_count=row["finding_count"],
                metadata=json.loads(row["metadata"]) if row["metadata"] else {},
                created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else datetime.now(),
            )

    def get_file_input_by_hash(self, file_hash: str) -> Optional[FileInput]:
        """Retrieve a FileInput by file hash (deduplication)."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM file_inputs WHERE file_hash = ?",
                (file_hash,)
            ).fetchone()

            if not row:
                return None

            return FileInput(
                id=row["id"],
                file_path=row["file_path"],
                file_hash=row["file_hash"],
                file_size=row["file_size"],
                content=row["content"],
                engagement_id=row["engagement_id"],
                parsed=bool(row["parsed"]),
                parser_used=row["parser_used"],
                finding_count=row["finding_count"],
                metadata=json.loads(row["metadata"]) if row["metadata"] else {},
                created_at=datetime.fromisoformat(row["created_at"]) if row["created_at"] else datetime.now(),
            )

    # ==================== Finding Operations ====================

    def save_finding(self, finding: UnifiedFinding) -> str:
        """Save a Finding to the database."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO findings (
                    id, finding_type, source, target, raw_value, decoded_value,
                    decode_method, confidence, priority, tags, metadata,
                    source_input_id, source_input_type, extraction_method,
                    extraction_line, engagement_id, discovered_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.id,
                    finding.finding_type.value,
                    finding.source,
                    finding.target,
                    str(finding.raw_value) if finding.raw_value else None,
                    finding.decoded_value,
                    finding.decode_method,
                    finding.confidence,
                    finding.priority.value,
                    json.dumps(finding.tags),
                    json.dumps(finding.metadata),
                    finding.source_input_id,
                    finding.source_input_type,
                    finding.extraction_method,
                    finding.extraction_line,
                    finding.engagement_id,
                    finding.discovered_at.isoformat() if finding.discovered_at else None,
                ),
            )
        return finding.id

    def get_finding(self, finding_id: str) -> Optional[UnifiedFinding]:
        """Retrieve a Finding by ID."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM findings WHERE id = ?",
                (finding_id,)
            ).fetchone()

            if not row:
                return None

            return self._row_to_finding(row)

    def _row_to_finding(self, row: sqlite3.Row) -> UnifiedFinding:
        """Convert SQLite row to UnifiedFinding."""
        from ..models.finding import FindingType, FindingPriority

        return UnifiedFinding(
            id=row["id"],
            finding_type=FindingType(row["finding_type"]),
            source=row["source"],
            target=row["target"],
            raw_value=row["raw_value"],
            decoded_value=row["decoded_value"],
            decode_method=row["decode_method"],
            confidence=row["confidence"],
            priority=FindingPriority(row["priority"]),
            tags=json.loads(row["tags"]) if row["tags"] else [],
            metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            source_input_id=row["source_input_id"],
            source_input_type=row["source_input_type"],
            extraction_method=row["extraction_method"],
            extraction_line=row["extraction_line"],
            engagement_id=row["engagement_id"],
            discovered_at=datetime.fromisoformat(row["discovered_at"]) if row["discovered_at"] else datetime.now(),
        )

    def query_findings(
        self,
        finding_type: Optional[str] = None,
        source_input_id: Optional[str] = None,
        engagement_id: Optional[str] = None,
        priority_max: Optional[int] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[UnifiedFinding]:
        """Query findings with filters."""
        conditions = []
        params = []

        if finding_type:
            conditions.append("finding_type = ?")
            params.append(finding_type)
        if source_input_id:
            conditions.append("source_input_id = ?")
            params.append(source_input_id)
        if engagement_id:
            conditions.append("engagement_id = ?")
            params.append(engagement_id)
        if priority_max is not None:
            conditions.append("priority <= ?")
            params.append(priority_max)

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        query = f"""
            SELECT * FROM findings
            {where_clause}
            ORDER BY priority ASC, discovered_at DESC
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_finding(row) for row in rows]

    def get_findings_for_input(self, source_input_id: str) -> List[UnifiedFinding]:
        """Get all findings extracted from a specific raw input."""
        return self.query_findings(source_input_id=source_input_id, limit=1000)

    # ==================== Statistics ====================

    def get_stats(self) -> Dict[str, Any]:
        """Get storage statistics."""
        with self._connect() as conn:
            raw_count = conn.execute("SELECT COUNT(*) FROM raw_inputs").fetchone()[0]
            file_count = conn.execute("SELECT COUNT(*) FROM file_inputs").fetchone()[0]
            finding_count = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            unparsed_count = conn.execute("SELECT COUNT(*) FROM raw_inputs WHERE parsed = 0").fetchone()[0]

            return {
                "raw_inputs": raw_count,
                "file_inputs": file_count,
                "findings": finding_count,
                "unparsed_raw_inputs": unparsed_count,
            }
