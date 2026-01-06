"""
Neo4j storage for relationships and queryable metadata.

Stores:
- RawInput metadata nodes (blobs in SQLite)
- Finding nodes
- EXTRACTED_FROM relationships (provenance)
- Target/Engagement relationships
"""

from typing import Any, Dict, List, Optional

from ..config import PersistenceConfig
from ..models.raw_input import RawInput, FileInput
from ..models.finding import UnifiedFinding


class PersistenceNeo4jAdapter:
    """
    Neo4j adapter for the persistence layer.

    Stores metadata and relationships in Neo4j while
    SQLite handles the raw blobs.
    """

    def __init__(self):
        """Initialize Neo4j connection."""
        self.config = PersistenceConfig.get()
        self._driver = None

    @property
    def driver(self):
        """Lazy-load Neo4j driver."""
        if self._driver is None:
            try:
                from neo4j import GraphDatabase
                self._driver = GraphDatabase.driver(
                    self.config.neo4j_uri,
                    auth=(self.config.neo4j_user, self.config.neo4j_password),
                )
            except ImportError:
                raise ImportError("neo4j package not installed")
        return self._driver

    def close(self):
        """Close Neo4j connection."""
        if self._driver:
            self._driver.close()
            self._driver = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    # ==================== RawInput Operations ====================

    def save_raw_input_metadata(self, raw_input: RawInput):
        """
        Save RawInput metadata to Neo4j.

        Creates :RawInput node with metadata (blobs stored in SQLite).
        """
        query = """
        MERGE (r:RawInput {id: $id})
        SET r += $props
        SET r.updated_at = datetime()
        """

        props = raw_input.to_neo4j_dict()

        with self.driver.session() as session:
            session.run(query, id=raw_input.id, props=props)

            # Create relationship to target if we have one
            if raw_input.target_ip:
                self._link_to_target(
                    session,
                    raw_input.id,
                    raw_input.target_ip,
                    raw_input.target_hostname,
                )

            # Create relationship to engagement if we have one
            if raw_input.engagement_id:
                self._link_to_engagement(
                    session,
                    raw_input.id,
                    raw_input.engagement_id,
                )

    def _link_to_target(
        self,
        session,
        raw_input_id: str,
        target_ip: str,
        target_hostname: Optional[str] = None,
    ):
        """Create EXECUTED_AGAINST relationship to target."""
        query = """
        MATCH (r:RawInput {id: $raw_input_id})
        MERGE (t:Target {ip: $target_ip})
        ON CREATE SET t.hostname = $hostname, t.created_at = datetime()
        MERGE (r)-[:EXECUTED_AGAINST]->(t)
        """
        session.run(
            query,
            raw_input_id=raw_input_id,
            target_ip=target_ip,
            hostname=target_hostname,
        )

    def _link_to_engagement(self, session, raw_input_id: str, engagement_id: str):
        """Create HAS_INPUT relationship from engagement."""
        query = """
        MATCH (r:RawInput {id: $raw_input_id})
        MERGE (e:Engagement {id: $engagement_id})
        MERGE (e)-[:HAS_INPUT]->(r)
        """
        session.run(query, raw_input_id=raw_input_id, engagement_id=engagement_id)

    def mark_raw_input_parsed(
        self,
        raw_input_id: str,
        parser_used: str,
        finding_count: int = 0,
    ):
        """Mark a raw input as parsed."""
        query = """
        MATCH (r:RawInput {id: $id})
        SET r.parsed = true,
            r.parser_used = $parser_used,
            r.finding_count = $finding_count,
            r.parsed_at = datetime()
        """
        with self.driver.session() as session:
            session.run(
                query,
                id=raw_input_id,
                parser_used=parser_used,
                finding_count=finding_count,
            )

    # ==================== FileInput Operations ====================

    def save_file_input_metadata(self, file_input: FileInput):
        """Save FileInput metadata to Neo4j."""
        query = """
        MERGE (f:FileInput {id: $id})
        SET f += $props
        SET f.updated_at = datetime()
        """

        props = file_input.to_dict()
        # Remove blob fields
        props.pop("content", None)

        with self.driver.session() as session:
            session.run(query, id=file_input.id, props=props)

            if file_input.engagement_id:
                self._link_file_to_engagement(
                    session,
                    file_input.id,
                    file_input.engagement_id,
                )

    def _link_file_to_engagement(self, session, file_input_id: str, engagement_id: str):
        """Create HAS_FILE relationship from engagement."""
        query = """
        MATCH (f:FileInput {id: $file_input_id})
        MERGE (e:Engagement {id: $engagement_id})
        MERGE (e)-[:HAS_FILE]->(f)
        """
        session.run(query, file_input_id=file_input_id, engagement_id=engagement_id)

    # ==================== Finding Operations ====================

    def save_finding(self, finding: UnifiedFinding):
        """Save Finding to Neo4j."""
        query = """
        MERGE (f:Finding {id: $id})
        SET f += $props
        SET f.updated_at = datetime()
        """

        props = finding.to_neo4j_dict()

        with self.driver.session() as session:
            session.run(query, id=finding.id, props=props)

            # Link to engagement if we have one
            if finding.engagement_id:
                self._link_finding_to_engagement(
                    session,
                    finding.id,
                    finding.engagement_id,
                )

    def _link_finding_to_engagement(
        self,
        session,
        finding_id: str,
        engagement_id: str,
    ):
        """Create HAS_FINDING relationship from engagement."""
        query = """
        MATCH (f:Finding {id: $finding_id})
        MERGE (e:Engagement {id: $engagement_id})
        MERGE (e)-[:HAS_FINDING]->(f)
        """
        session.run(query, finding_id=finding_id, engagement_id=engagement_id)

    def create_extracted_from_relationship(
        self,
        finding_id: str,
        source_input_id: str,
        extraction_method: Optional[str] = None,
        extraction_line: Optional[int] = None,
    ):
        """
        Create EXTRACTED_FROM relationship between Finding and RawInput/FileInput.

        This is the core provenance relationship.
        """
        # Try RawInput first
        query = """
        MATCH (f:Finding {id: $finding_id})
        OPTIONAL MATCH (r:RawInput {id: $source_input_id})
        OPTIONAL MATCH (fi:FileInput {id: $source_input_id})
        WITH f, COALESCE(r, fi) AS source
        WHERE source IS NOT NULL
        MERGE (f)-[rel:EXTRACTED_FROM]->(source)
        SET rel.extraction_method = $extraction_method,
            rel.extraction_line = $extraction_line,
            rel.created_at = datetime()
        """
        with self.driver.session() as session:
            session.run(
                query,
                finding_id=finding_id,
                source_input_id=source_input_id,
                extraction_method=extraction_method,
                extraction_line=extraction_line,
            )

    # ==================== Query Operations ====================

    def get_findings_for_raw_input(self, raw_input_id: str) -> List[Dict[str, Any]]:
        """Get all findings extracted from a raw input."""
        query = """
        MATCH (f:Finding)-[:EXTRACTED_FROM]->(r:RawInput {id: $raw_input_id})
        RETURN f
        ORDER BY f.priority ASC, f.discovered_at DESC
        """
        with self.driver.session() as session:
            result = session.run(query, raw_input_id=raw_input_id)
            return [dict(record["f"]) for record in result]

    def get_raw_input_for_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """Get the raw input that generated a finding."""
        query = """
        MATCH (f:Finding {id: $finding_id})-[:EXTRACTED_FROM]->(r:RawInput)
        RETURN r
        """
        with self.driver.session() as session:
            result = session.run(query, finding_id=finding_id)
            record = result.single()
            if record:
                return dict(record["r"])
            return None

    def get_raw_inputs_for_target(self, target_ip: str) -> List[Dict[str, Any]]:
        """Get all raw inputs executed against a target."""
        query = """
        MATCH (r:RawInput)-[:EXECUTED_AGAINST]->(t:Target {ip: $target_ip})
        RETURN r
        ORDER BY r.started_at DESC
        """
        with self.driver.session() as session:
            result = session.run(query, target_ip=target_ip)
            return [dict(record["r"]) for record in result]

    def get_engagement_command_history(
        self,
        engagement_id: str,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get command history for an engagement."""
        query = """
        MATCH (e:Engagement {id: $engagement_id})-[:HAS_INPUT]->(r:RawInput)
        RETURN r
        ORDER BY r.started_at ASC
        LIMIT $limit
        """
        with self.driver.session() as session:
            result = session.run(query, engagement_id=engagement_id, limit=limit)
            return [dict(record["r"]) for record in result]

    def find_credential_provenance(self, username: str) -> List[Dict[str, Any]]:
        """
        Find the command that discovered a credential.

        This is the key provenance query: "what command found this?"
        """
        query = """
        MATCH (f:Finding)-[:EXTRACTED_FROM]->(r:RawInput)
        WHERE f.finding_type = 'credential'
        AND f.target = $username
        RETURN f, r
        ORDER BY f.discovered_at DESC
        """
        with self.driver.session() as session:
            result = session.run(query, username=username)
            return [
                {"finding": dict(record["f"]), "raw_input": dict(record["r"])}
                for record in result
            ]

    # ==================== Statistics ====================

    def get_stats(self) -> Dict[str, Any]:
        """Get Neo4j statistics."""
        query = """
        MATCH (r:RawInput) WITH count(r) AS raw_inputs
        MATCH (f:Finding) WITH raw_inputs, count(f) AS findings
        MATCH (fi:FileInput) WITH raw_inputs, findings, count(fi) AS file_inputs
        RETURN raw_inputs, findings, file_inputs
        """
        with self.driver.session() as session:
            result = session.run(query)
            record = result.single()
            if record:
                return {
                    "raw_inputs": record["raw_inputs"],
                    "findings": record["findings"],
                    "file_inputs": record["file_inputs"],
                }
            return {}
