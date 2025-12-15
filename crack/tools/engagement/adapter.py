"""
Engagement Adapter - Neo4j operations for engagement tracking

Provides CRUD operations for:
- Clients
- Engagements
- Targets
- Services
- Findings

Uses Neo4j graph database with MERGE for idempotent operations.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime
import time

try:
    from neo4j import GraphDatabase
    from neo4j.exceptions import ServiceUnavailable, SessionExpired
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False

from .models import (
    Client,
    Engagement,
    Target,
    Service,
    Finding,
    EngagementStatus,
    FindingSeverity,
)
from .storage import (
    get_active_engagement_id,
    set_active_engagement_id,
    clear_active_engagement,
)


class EngagementAdapterError(Exception):
    """Base exception for engagement adapter errors"""
    pass


class Neo4jUnavailableError(EngagementAdapterError):
    """Raised when Neo4j is not available"""
    pass


class EngagementAdapter:
    """
    Neo4j adapter for engagement tracking.

    Handles all CRUD operations for engagement entities.
    Uses MERGE for idempotent node creation.

    Usage:
        adapter = EngagementAdapter()

        # Create client
        client_id = adapter.create_client("ACME Corp")

        # Create engagement
        eng_id = adapter.create_engagement("Q4 Pentest", client_id)
        adapter.set_active_engagement(eng_id)

        # Add targets
        target_id = adapter.add_target(eng_id, "192.168.1.100")
        adapter.add_service(target_id, 80, service_name="http")

        # Add findings
        finding_id = adapter.add_finding(eng_id, "SQL Injection", severity="critical")
        adapter.link_finding_to_target(finding_id, target_id)
    """

    def __init__(self, neo4j_config: Optional[Dict] = None):
        """
        Initialize engagement adapter.

        Args:
            neo4j_config: Optional Neo4j config dict. If not provided,
                         loads from environment via db.config.Neo4jConfig

        Raises:
            Neo4jUnavailableError: If Neo4j package not installed or connection fails
        """
        if not NEO4J_AVAILABLE:
            raise Neo4jUnavailableError("neo4j package not installed. Run: pip install neo4j")

        # Load config
        try:
            from crack.db.config import Neo4jConfig
            config = neo4j_config or Neo4jConfig.from_env().to_dict()
        except ImportError:
            # Fallback to defaults
            import os
            config = neo4j_config or {
                'uri': os.environ.get('NEO4J_URI', 'bolt://localhost:7687'),
                'user': os.environ.get('NEO4J_USER', 'neo4j'),
                'password': os.environ.get('NEO4J_PASSWORD', 'neo4j'),
                'database': os.environ.get('NEO4J_DATABASE', 'neo4j'),
            }

        # Connect to Neo4j
        try:
            self.driver = GraphDatabase.driver(
                config['uri'],
                auth=(config['user'], config['password']),
                max_connection_lifetime=config.get('max_connection_lifetime', 3600),
            )
            self.database = config.get('database', 'neo4j')

            # Test connection
            with self.driver.session(database=self.database) as session:
                session.run("RETURN 1")

        except Exception as e:
            raise Neo4jUnavailableError(f"Failed to connect to Neo4j: {e}")

    def __del__(self):
        """Close driver on cleanup"""
        if hasattr(self, 'driver'):
            self.driver.close()

    # =========================================================================
    # Internal Methods
    # =========================================================================

    def _execute_read(self, query: str, **params) -> list:
        """Execute read query with retry logic"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                with self.driver.session(database=self.database) as session:
                    result = session.run(query, **params)
                    return list(result)
            except (ServiceUnavailable, SessionExpired):
                if attempt == max_retries - 1:
                    return []
                time.sleep(2 ** attempt)
        return []

    def _execute_write(self, query: str, **params) -> Any:
        """Execute write query with retry logic"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                with self.driver.session(database=self.database) as session:
                    result = session.run(query, **params)
                    return result.single()
            except (ServiceUnavailable, SessionExpired):
                if attempt == max_retries - 1:
                    raise
                time.sleep(2 ** attempt)

    # =========================================================================
    # Client Operations
    # =========================================================================

    def create_client(
        self,
        name: str,
        organization: str = "",
        contact_email: str = "",
        industry: str = "",
        notes: str = ""
    ) -> str:
        """
        Create or update a client.

        Args:
            name: Client name (required)
            organization: Organization name
            contact_email: Contact email
            industry: Industry sector
            notes: Additional notes

        Returns:
            Client ID
        """
        client = Client.create(
            name=name,
            organization=organization,
            contact_email=contact_email,
            industry=industry,
            notes=notes
        )

        query = """
        MERGE (c:Client {id: $id})
        SET c.name = $name,
            c.organization = $organization,
            c.contact_email = $contact_email,
            c.industry = $industry,
            c.notes = $notes,
            c.created_at = $created_at
        RETURN c.id AS id
        """

        result = self._execute_write(query, **client.to_dict())
        return result['id'] if result else client.id

    def get_client(self, client_id: str) -> Optional[Client]:
        """Get client by ID"""
        query = """
        MATCH (c:Client {id: $client_id})
        RETURN c
        """
        results = self._execute_read(query, client_id=client_id)
        if results:
            return Client.from_dict(dict(results[0]['c']))
        return None

    def list_clients(self) -> List[Client]:
        """List all clients"""
        query = """
        MATCH (c:Client)
        RETURN c
        ORDER BY c.name
        """
        results = self._execute_read(query)
        return [Client.from_dict(dict(r['c'])) for r in results]

    # =========================================================================
    # Engagement Operations
    # =========================================================================

    def create_engagement(
        self,
        name: str,
        client_id: str,
        scope_type: str = "",
        scope_text: str = "",
        rules_of_engagement: str = "",
        notes: str = ""
    ) -> str:
        """
        Create engagement and link to client.

        Args:
            name: Engagement name (required)
            client_id: Client ID to link to (required)
            scope_type: Type (external, internal, web, etc.)
            scope_text: Scope description (CIDRs, domains)
            rules_of_engagement: ROE text
            notes: Additional notes

        Returns:
            Engagement ID
        """
        engagement = Engagement.create(
            name=name,
            client_id=client_id,
            scope_type=scope_type,
            scope_text=scope_text,
            rules_of_engagement=rules_of_engagement,
            notes=notes
        )

        query = """
        MATCH (c:Client {id: $client_id})
        MERGE (e:Engagement {id: $id})
        SET e.name = $name,
            e.client_id = $client_id,
            e.status = $status,
            e.start_date = $start_date,
            e.end_date = $end_date,
            e.scope_type = $scope_type,
            e.scope_text = $scope_text,
            e.rules_of_engagement = $rules_of_engagement,
            e.notes = $notes,
            e.created_at = $created_at
        MERGE (c)-[:HAS_ENGAGEMENT]->(e)
        RETURN e.id AS id
        """

        result = self._execute_write(query, **engagement.to_dict())
        return result['id'] if result else engagement.id

    def get_engagement(self, engagement_id: str) -> Optional[Engagement]:
        """Get engagement by ID"""
        query = """
        MATCH (e:Engagement {id: $engagement_id})
        RETURN e
        """
        results = self._execute_read(query, engagement_id=engagement_id)
        if results:
            return Engagement.from_dict(dict(results[0]['e']))
        return None

    def list_engagements(self, client_id: Optional[str] = None) -> List[Engagement]:
        """
        List engagements, optionally filtered by client.

        Args:
            client_id: Optional client ID to filter by

        Returns:
            List of Engagement objects
        """
        if client_id:
            query = """
            MATCH (c:Client {id: $client_id})-[:HAS_ENGAGEMENT]->(e:Engagement)
            RETURN e
            ORDER BY e.created_at DESC
            """
            results = self._execute_read(query, client_id=client_id)
        else:
            query = """
            MATCH (e:Engagement)
            RETURN e
            ORDER BY e.created_at DESC
            """
            results = self._execute_read(query)

        return [Engagement.from_dict(dict(r['e'])) for r in results]

    def update_engagement_status(
        self,
        engagement_id: str,
        status: EngagementStatus
    ) -> bool:
        """Update engagement status"""
        query = """
        MATCH (e:Engagement {id: $engagement_id})
        SET e.status = $status
        RETURN e.id AS id
        """
        status_value = status.value if isinstance(status, EngagementStatus) else status
        result = self._execute_write(query, engagement_id=engagement_id, status=status_value)
        return result is not None

    def set_active_engagement(self, engagement_id: str) -> bool:
        """
        Set engagement as active (stores in local file).

        Args:
            engagement_id: ID of engagement to activate

        Returns:
            True if successful
        """
        engagement = self.get_engagement(engagement_id)
        if engagement:
            set_active_engagement_id(engagement_id, engagement.name)
            return True
        return False

    def get_active_engagement(self) -> Optional[Engagement]:
        """Get currently active engagement"""
        engagement_id = get_active_engagement_id()
        if engagement_id:
            return self.get_engagement(engagement_id)
        return None

    def deactivate_engagement(self) -> None:
        """Clear active engagement"""
        clear_active_engagement()

    # =========================================================================
    # Target Operations
    # =========================================================================

    def add_target(
        self,
        engagement_id: str,
        ip_or_hostname: str,
        hostname: str = "",
        os_guess: str = "",
        notes: str = "",
        in_scope: bool = True
    ) -> str:
        """
        Add target to engagement.

        Args:
            engagement_id: Engagement to add target to
            ip_or_hostname: IP address or hostname
            hostname: Explicit hostname (when ip_or_hostname is IP)
            os_guess: Operating system guess
            notes: Additional notes
            in_scope: Whether target is in scope

        Returns:
            Target ID
        """
        target = Target.create(
            ip_or_hostname,
            hostname=hostname,
            os_guess=os_guess,
            notes=notes
        )

        query = """
        MATCH (e:Engagement {id: $engagement_id})
        MERGE (t:Target {id: $id})
        SET t.ip_address = $ip_address,
            t.hostname = $hostname,
            t.os_guess = $os_guess,
            t.status = $status,
            t.first_seen = $first_seen,
            t.last_seen = $last_seen,
            t.notes = $notes
        MERGE (e)-[:TARGETS {in_scope: $in_scope, added_at: $added_at}]->(t)
        RETURN t.id AS id
        """

        params = target.to_dict()
        params['engagement_id'] = engagement_id
        params['in_scope'] = in_scope
        params['added_at'] = datetime.now().isoformat()

        result = self._execute_write(query, **params)
        return result['id'] if result else target.id

    def get_target(self, target_id: str) -> Optional[Target]:
        """Get target by ID"""
        query = """
        MATCH (t:Target {id: $target_id})
        RETURN t
        """
        results = self._execute_read(query, target_id=target_id)
        if results:
            return Target.from_dict(dict(results[0]['t']))
        return None

    def get_targets(self, engagement_id: str) -> List[Target]:
        """Get all targets for engagement"""
        query = """
        MATCH (e:Engagement {id: $engagement_id})-[:TARGETS]->(t:Target)
        RETURN t
        ORDER BY t.first_seen
        """
        results = self._execute_read(query, engagement_id=engagement_id)
        return [Target.from_dict(dict(r['t'])) for r in results]

    def update_target(self, target_id: str, **kwargs) -> bool:
        """
        Update target fields.

        Args:
            target_id: Target ID
            **kwargs: Fields to update (os_guess, status, notes, etc.)

        Returns:
            True if successful
        """
        # Build SET clause dynamically
        set_parts = []
        for key in kwargs:
            set_parts.append(f"t.{key} = ${key}")

        if not set_parts:
            return False

        kwargs['last_seen'] = datetime.now().isoformat()
        set_parts.append("t.last_seen = $last_seen")

        query = f"""
        MATCH (t:Target {{id: $target_id}})
        SET {', '.join(set_parts)}
        RETURN t.id AS id
        """

        kwargs['target_id'] = target_id
        result = self._execute_write(query, **kwargs)
        return result is not None

    # =========================================================================
    # Service Operations
    # =========================================================================

    def add_service(
        self,
        target_id: str,
        port: int,
        protocol: str = "tcp",
        service_name: str = "",
        version: str = "",
        banner: str = "",
        state: str = "open"
    ) -> str:
        """
        Add service to target.

        Args:
            target_id: Target to add service to
            port: Port number
            protocol: Protocol (tcp/udp)
            service_name: Service name (http, ssh, etc.)
            version: Service version
            banner: Service banner
            state: Port state (open, filtered, etc.)

        Returns:
            Service ID
        """
        service = Service.create(
            target_id=target_id,
            port=port,
            protocol=protocol,
            service_name=service_name,
            version=version,
            banner=banner,
            state=state
        )

        query = """
        MATCH (t:Target {id: $target_id})
        MERGE (s:Service {id: $id})
        SET s.target_id = $target_id,
            s.port = $port,
            s.protocol = $protocol,
            s.service_name = $service_name,
            s.version = $version,
            s.banner = $banner,
            s.state = $state,
            s.found_at = $found_at
        MERGE (t)-[:HAS_SERVICE]->(s)
        RETURN s.id AS id
        """

        result = self._execute_write(query, **service.to_dict())
        return result['id'] if result else service.id

    def get_services(self, target_id: str) -> List[Service]:
        """Get all services for target"""
        query = """
        MATCH (t:Target {id: $target_id})-[:HAS_SERVICE]->(s:Service)
        RETURN s
        ORDER BY s.port
        """
        results = self._execute_read(query, target_id=target_id)
        return [Service.from_dict(dict(r['s'])) for r in results]

    # =========================================================================
    # Finding Operations
    # =========================================================================

    def add_finding(
        self,
        engagement_id: str,
        title: str,
        severity: str = "medium",
        cvss_score: str = "",
        cve_id: str = "",
        description: str = "",
        impact: str = "",
        remediation: str = "",
        evidence: str = ""
    ) -> str:
        """
        Add finding to engagement.

        Args:
            engagement_id: Engagement to add finding to
            title: Finding title (required)
            severity: Severity level (critical, high, medium, low, info)
            cvss_score: CVSS score
            cve_id: CVE identifier (e.g., CVE-2024-12345)
            description: Detailed description
            impact: Business impact
            remediation: Remediation steps
            evidence: Proof/evidence

        Returns:
            Finding ID
        """
        finding = Finding.create(
            title=title,
            severity=severity,
            cvss_score=cvss_score,
            cve_id=cve_id,
            description=description,
            impact=impact,
            remediation=remediation,
            evidence=evidence
        )

        query = """
        MATCH (e:Engagement {id: $engagement_id})
        MERGE (f:Finding {id: $id})
        SET f.title = $title,
            f.severity = $severity,
            f.cvss_score = $cvss_score,
            f.cve_id = $cve_id,
            f.description = $description,
            f.impact = $impact,
            f.remediation = $remediation,
            f.evidence = $evidence,
            f.status = $status,
            f.found_at = $found_at
        MERGE (e)-[:HAS_FINDING]->(f)
        RETURN f.id AS id
        """

        params = finding.to_dict()
        params['engagement_id'] = engagement_id
        # Remove affected_targets as it's handled separately
        params.pop('affected_targets', None)

        result = self._execute_write(query, **params)

        # Link to CVE if provided
        if cve_id:
            self._link_finding_to_cve(finding.id, cve_id)

        return result['id'] if result else finding.id

    def _link_finding_to_cve(self, finding_id: str, cve_id: str) -> None:
        """Link finding to CVE node (creates CVE if not exists)"""
        query = """
        MATCH (f:Finding {id: $finding_id})
        MERGE (c:CVE {cve_id: $cve_id})
        MERGE (f)-[:EXPLOITS]->(c)
        """
        self._execute_write(query, finding_id=finding_id, cve_id=cve_id)

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        """Get finding by ID"""
        query = """
        MATCH (f:Finding {id: $finding_id})
        RETURN f
        """
        results = self._execute_read(query, finding_id=finding_id)
        if results:
            return Finding.from_dict(dict(results[0]['f']))
        return None

    def get_findings(
        self,
        engagement_id: str,
        severity: Optional[str] = None
    ) -> List[Finding]:
        """
        Get findings for engagement.

        Args:
            engagement_id: Engagement ID
            severity: Optional severity filter

        Returns:
            List of Finding objects
        """
        if severity:
            query = """
            MATCH (e:Engagement {id: $engagement_id})-[:HAS_FINDING]->(f:Finding)
            WHERE f.severity = $severity
            RETURN f
            ORDER BY f.found_at DESC
            """
            results = self._execute_read(query, engagement_id=engagement_id, severity=severity)
        else:
            query = """
            MATCH (e:Engagement {id: $engagement_id})-[:HAS_FINDING]->(f:Finding)
            RETURN f
            ORDER BY f.found_at DESC
            """
            results = self._execute_read(query, engagement_id=engagement_id)

        return [Finding.from_dict(dict(r['f'])) for r in results]

    def link_finding_to_target(self, finding_id: str, target_id: str) -> bool:
        """
        Link finding to affected target.

        Args:
            finding_id: Finding ID
            target_id: Target ID

        Returns:
            True if successful
        """
        query = """
        MATCH (f:Finding {id: $finding_id})
        MATCH (t:Target {id: $target_id})
        MERGE (f)-[:AFFECTS]->(t)
        RETURN f.id AS id
        """
        result = self._execute_write(query, finding_id=finding_id, target_id=target_id)
        return result is not None

    # =========================================================================
    # Command/Chain Tracking
    # =========================================================================

    def log_command_usage(
        self,
        engagement_id: str,
        command_id: str,
        target_id: Optional[str] = None,
        success: bool = True,
        notes: str = ""
    ) -> bool:
        """
        Log command usage in engagement.

        Args:
            engagement_id: Engagement ID
            command_id: Command ID from reference system
            target_id: Optional target ID
            success: Whether command succeeded
            notes: Additional notes

        Returns:
            True if successful
        """
        query = """
        MATCH (e:Engagement {id: $engagement_id})
        MATCH (c:Command {id: $command_id})
        MERGE (e)-[r:USED_COMMAND {command_id: $command_id}]->(c)
        SET r.used_at = $used_at,
            r.target_id = $target_id,
            r.success = $success,
            r.notes = $notes
        RETURN e.id AS id
        """
        result = self._execute_write(
            query,
            engagement_id=engagement_id,
            command_id=command_id,
            target_id=target_id or "",
            success=success,
            notes=notes,
            used_at=datetime.now().isoformat()
        )
        return result is not None

    def log_chain_usage(
        self,
        engagement_id: str,
        chain_id: str,
        effectiveness: str = "",
        notes: str = ""
    ) -> bool:
        """
        Log attack chain usage in engagement.

        Args:
            engagement_id: Engagement ID
            chain_id: Chain ID from reference system
            effectiveness: How effective the chain was
            notes: Additional notes

        Returns:
            True if successful
        """
        query = """
        MATCH (e:Engagement {id: $engagement_id})
        MATCH (c:AttackChain {id: $chain_id})
        MERGE (e)-[r:USED_CHAIN {chain_id: $chain_id}]->(c)
        SET r.used_at = $used_at,
            r.effectiveness = $effectiveness,
            r.notes = $notes
        RETURN e.id AS id
        """
        result = self._execute_write(
            query,
            engagement_id=engagement_id,
            chain_id=chain_id,
            effectiveness=effectiveness,
            notes=notes,
            used_at=datetime.now().isoformat()
        )
        return result is not None

    # =========================================================================
    # Statistics & Summary
    # =========================================================================

    def get_engagement_stats(self, engagement_id: str) -> Dict[str, Any]:
        """
        Get engagement statistics.

        Args:
            engagement_id: Engagement ID

        Returns:
            Dict with counts and summaries
        """
        query = """
        MATCH (e:Engagement {id: $engagement_id})
        OPTIONAL MATCH (e)-[:TARGETS]->(t:Target)
        OPTIONAL MATCH (t)-[:HAS_SERVICE]->(s:Service)
        OPTIONAL MATCH (e)-[:HAS_FINDING]->(f:Finding)
        RETURN
            e.name AS name,
            e.status AS status,
            count(DISTINCT t) AS target_count,
            count(DISTINCT s) AS service_count,
            count(DISTINCT f) AS finding_count
        """
        results = self._execute_read(query, engagement_id=engagement_id)

        if results:
            r = results[0]
            return {
                'name': r['name'],
                'status': r['status'],
                'targets': r['target_count'],
                'services': r['service_count'],
                'findings': r['finding_count'],
            }

        return {
            'name': '',
            'status': '',
            'targets': 0,
            'services': 0,
            'findings': 0,
        }

    def get_finding_summary(self, engagement_id: str) -> Dict[str, int]:
        """
        Get finding counts by severity.

        Args:
            engagement_id: Engagement ID

        Returns:
            Dict mapping severity to count
        """
        query = """
        MATCH (e:Engagement {id: $engagement_id})-[:HAS_FINDING]->(f:Finding)
        RETURN f.severity AS severity, count(f) AS count
        """
        results = self._execute_read(query, engagement_id=engagement_id)

        summary = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for r in results:
            severity = r['severity']
            if severity in summary:
                summary[severity] = r['count']

        return summary


if __name__ == '__main__':
    print("EngagementAdapter requires Neo4j connection.")
    print("Run integration tests with: pytest tests/engagement/")
