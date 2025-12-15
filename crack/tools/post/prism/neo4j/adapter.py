"""
PRISM Neo4j Adapter - Credential storage and relationship mapping

Stores extracted credentials in Neo4j with relationships to
hosts, domains, and users.

Integrates with engagement tracking when active.
"""

from typing import Optional, Dict, Any, List
import logging
from datetime import datetime

try:
    from neo4j import GraphDatabase
    from neo4j.exceptions import ServiceUnavailable, SessionExpired
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False

from ..models import ParsedSummary, Credential, KerberosTicket
from ..models import NmapScanSummary, NmapHost, NmapPort

logger = logging.getLogger(__name__)


def _log_to_engagement(source_hostname: str, source_ip: str, cred_count: int) -> None:
    """Log credential extraction to engagement if active"""
    try:
        from crack.tools.engagement.integration import EngagementIntegration

        if not EngagementIntegration.is_active():
            return

        # Try to find target by hostname or IP
        target_id = None
        if source_ip:
            target_id = EngagementIntegration.find_target_by_ip(source_ip)

        if target_id:
            # Log finding
            EngagementIntegration.add_finding(
                title=f"Credentials Extracted ({cred_count} total)",
                severity="high",
                description=f"Extracted {cred_count} credentials from {source_hostname or source_ip}",
                evidence=f"Source: {source_hostname or source_ip}",
                target_id=target_id
            )
            logger.info(f"Logged credential extraction to engagement target {target_id}")

    except ImportError:
        pass
    except Exception as e:
        logger.debug(f"Failed to log to engagement: {e}")


class PrismNeo4jAdapter:
    """Neo4j adapter for PRISM credential storage"""

    def __init__(self, neo4j_config: Optional[Dict] = None):
        """Initialize adapter

        Args:
            neo4j_config: Optional Neo4j connection config.
                          If not provided, uses environment variables.
        """
        self.driver = None
        self.database = 'neo4j'
        self._connected = False

        if not NEO4J_AVAILABLE:
            logger.warning("neo4j package not installed")
            return

        try:
            from db.config import Neo4jConfig
            config = neo4j_config or Neo4jConfig.from_env().to_dict()

            self.driver = GraphDatabase.driver(
                config['uri'],
                auth=(config['user'], config['password']),
                max_connection_lifetime=config.get('max_connection_lifetime', 3600),
                max_connection_pool_size=config.get('max_connection_pool_size', 10)
            )
            self.database = config.get('database', 'neo4j')

        except Exception as e:
            logger.warning(f"Failed to initialize Neo4j driver: {e}")

    def __del__(self):
        """Close driver on cleanup"""
        if self.driver:
            try:
                self.driver.close()
            except Exception:
                pass

    def connect(self) -> bool:
        """Test connection to Neo4j

        Returns:
            True if connected successfully
        """
        if not self.driver:
            return False

        try:
            with self.driver.session(database=self.database) as session:
                session.run("RETURN 1")
            self._connected = True
            return True

        except Exception as e:
            logger.error(f"Neo4j connection failed: {e}")
            return False

    def import_summary(self, summary: ParsedSummary) -> Dict[str, int]:
        """Import parsed summary to Neo4j

        Creates:
        - Credential nodes for each credential
        - Computer node for source host
        - Domain node if detected
        - Relationships between them

        Args:
            summary: ParsedSummary to import

        Returns:
            Dict with counts of imported items
        """
        if not self._connected and not self.connect():
            raise RuntimeError("Not connected to Neo4j")

        results = {
            'credentials': 0,
            'tickets': 0,
            'hosts': 0,
            'domains': 0,
        }

        with self.driver.session(database=self.database) as session:
            # Create host node if we have hostname
            if summary.source_hostname:
                session.execute_write(
                    self._create_host,
                    summary.source_hostname,
                    summary.source_domain
                )
                results['hosts'] = 1

            # Create domain node if detected
            if summary.source_domain:
                session.execute_write(
                    self._create_domain,
                    summary.source_domain
                )
                results['domains'] = 1

            # Import credentials
            for cred in summary.credentials:
                session.execute_write(
                    self._create_credential,
                    cred,
                    summary.source_hostname,
                    summary.source_tool
                )
                results['credentials'] += 1

            # Import tickets
            for ticket in summary.tickets:
                session.execute_write(
                    self._create_ticket,
                    ticket,
                    summary.source_hostname
                )
                results['tickets'] += 1

        # Log to engagement if active
        if results['credentials'] > 0:
            _log_to_engagement(
                summary.source_hostname or "",
                getattr(summary, 'source_ip', ''),
                results['credentials']
            )

        return results

    @staticmethod
    def _create_host(tx, hostname: str, domain: str) -> None:
        """Create or update Computer node"""
        query = """
        MERGE (c:Computer {name: $hostname})
        ON CREATE SET
            c.first_seen = datetime(),
            c.domain = $domain
        ON MATCH SET
            c.last_seen = datetime()
        """
        tx.run(query, hostname=hostname.upper(), domain=domain.upper() if domain else "")

    @staticmethod
    def _create_domain(tx, domain: str) -> None:
        """Create or update Domain node"""
        query = """
        MERGE (d:Domain {name: $domain})
        ON CREATE SET d.first_seen = datetime()
        ON MATCH SET d.last_seen = datetime()
        """
        tx.run(query, domain=domain.upper())

    @staticmethod
    def _create_credential(tx, cred: Credential, hostname: str, source_tool: str) -> None:
        """Create Credential node with relationships"""
        # Create credential node
        cred_query = """
        MERGE (c:Credential {id: $cred_id})
        ON CREATE SET
            c.username = $username,
            c.domain = $domain,
            c.cred_type = $cred_type,
            c.value = $value,
            c.sid = $sid,
            c.source_tool = $source_tool,
            c.is_machine = $is_machine,
            c.is_service = $is_service,
            c.high_value = $high_value,
            c.first_seen = datetime()
        ON MATCH SET
            c.last_seen = datetime(),
            c.occurrences = COALESCE(c.occurrences, 0) + 1
        """

        cred_id = f"{cred.username}@{cred.domain}:{cred.cred_type.value}"

        tx.run(cred_query,
               cred_id=cred_id,
               username=cred.username,
               domain=cred.domain,
               cred_type=cred.cred_type.value,
               value=cred.value,
               sid=cred.sid or "",
               source_tool=source_tool,
               is_machine=cred.is_machine_account,
               is_service=cred.is_service_account,
               high_value=cred.high_value)

        # Link to host if available
        if hostname:
            host_rel_query = """
            MATCH (c:Credential {id: $cred_id})
            MATCH (h:Computer {name: $hostname})
            MERGE (c)-[:EXTRACTED_FROM]->(h)
            """
            tx.run(host_rel_query, cred_id=cred_id, hostname=hostname.upper())

        # Link to domain if available
        if cred.domain:
            domain_rel_query = """
            MATCH (c:Credential {id: $cred_id})
            MATCH (d:Domain {name: $domain})
            MERGE (c)-[:BELONGS_TO]->(d)
            """
            tx.run(domain_rel_query, cred_id=cred_id, domain=cred.domain.upper())

    @staticmethod
    def _create_ticket(tx, ticket: KerberosTicket, hostname: str) -> None:
        """Create KerberosTicket node with relationships"""
        ticket_query = """
        MERGE (t:KerberosTicket {id: $ticket_id})
        ON CREATE SET
            t.service_type = $service_type,
            t.service_target = $service_target,
            t.client_name = $client_name,
            t.client_realm = $client_realm,
            t.end_time = $end_time,
            t.is_tgt = $is_tgt,
            t.saved_path = $saved_path,
            t.first_seen = datetime()
        ON MATCH SET
            t.last_seen = datetime()
        """

        ticket_id = f"{ticket.client_name}@{ticket.client_realm}:{ticket.service_type}"
        if ticket.service_target:
            ticket_id += f"/{ticket.service_target}"

        tx.run(ticket_query,
               ticket_id=ticket_id,
               service_type=ticket.service_type,
               service_target=ticket.service_target or "",
               client_name=ticket.client_name,
               client_realm=ticket.client_realm,
               end_time=ticket.end_time.isoformat() if ticket.end_time else "",
               is_tgt=ticket.is_tgt,
               saved_path=ticket.saved_path or "")

        # Link to host
        if hostname:
            host_rel_query = """
            MATCH (t:KerberosTicket {id: $ticket_id})
            MATCH (h:Computer {name: $hostname})
            MERGE (t)-[:EXTRACTED_FROM]->(h)
            """
            tx.run(host_rel_query, ticket_id=ticket_id, hostname=hostname.upper())

    def query_credentials(
        self,
        cred_type: Optional[str] = None,
        domain: Optional[str] = None,
        high_value_only: bool = False
    ) -> List[Dict[str, Any]]:
        """Query stored credentials

        Args:
            cred_type: Filter by credential type (ntlm, cleartext, etc.)
            domain: Filter by domain
            high_value_only: Only return high-value credentials

        Returns:
            List of credential dictionaries
        """
        if not self._connected and not self.connect():
            return []

        conditions = []
        params = {}

        if cred_type:
            conditions.append("c.cred_type = $cred_type")
            params['cred_type'] = cred_type

        if domain:
            conditions.append("c.domain = $domain")
            params['domain'] = domain.upper()

        if high_value_only:
            conditions.append("c.high_value = true")

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        query = f"""
        MATCH (c:Credential)
        {where_clause}
        RETURN c
        ORDER BY c.high_value DESC, c.username
        """

        with self.driver.session(database=self.database) as session:
            result = session.run(query, **params)
            return [dict(record['c']) for record in result]

    def get_credential_stats(self) -> Dict[str, int]:
        """Get credential statistics

        Returns:
            Dict with counts by type
        """
        if not self._connected and not self.connect():
            return {}

        query = """
        MATCH (c:Credential)
        RETURN c.cred_type AS type, COUNT(*) AS count
        """

        with self.driver.session(database=self.database) as session:
            result = session.run(query)
            return {record['type']: record['count'] for record in result}

    # ========================================================================
    # Nmap Import Methods
    # ========================================================================

    def import_nmap_summary(self, summary: NmapScanSummary) -> Dict[str, int]:
        """Import nmap scan summary to Neo4j

        Creates:
        - Computer nodes for each discovered host
        - Port nodes for each open port
        - Domain nodes for discovered domains
        - Relationships between them

        Args:
            summary: NmapScanSummary to import

        Returns:
            Dict with counts of imported items
        """
        if not self._connected and not self.connect():
            raise RuntimeError("Not connected to Neo4j")

        results = {
            'hosts': 0,
            'ports': 0,
            'domains': 0,
        }

        with self.driver.session(database=self.database) as session:
            # Create domain nodes for discovered domains
            for domain in summary.unique_domains:
                session.execute_write(self._create_domain, domain)
                results['domains'] += 1

            # Import each host
            for host in summary.hosts_up:
                session.execute_write(self._create_nmap_host, host)
                results['hosts'] += 1

                # Import ports for this host
                for port in host.open_ports:
                    session.execute_write(self._create_nmap_port, host.ip, port)
                    results['ports'] += 1

                # Link host to domain if found
                host_domain = host.domain or host.dns_domain or host.netbios_domain
                if host_domain:
                    session.execute_write(
                        self._link_host_to_domain,
                        host.ip,
                        host_domain
                    )

        # Log to engagement if active
        self._log_nmap_to_engagement(summary)

        return results

    def _log_nmap_to_engagement(self, summary: NmapScanSummary) -> None:
        """Log nmap scan results to engagement if active"""
        try:
            from crack.tools.engagement.integration import EngagementIntegration

            if not EngagementIntegration.is_active():
                return

            for host in summary.hosts_up:
                # Ensure target exists in engagement
                target_id = EngagementIntegration.ensure_target(
                    host.ip,
                    hostname=host.hostname or "",
                    os_guess=host.os_display or ""
                )

                if target_id:
                    # Add services
                    services = []
                    for port in host.open_ports:
                        services.append({
                            'port': port.port,
                            'protocol': port.protocol,
                            'service_name': port.service or "",
                            'version': port.version or "",
                            'banner': ""
                        })

                    if services:
                        EngagementIntegration.add_services_batch(target_id, services)

            logger.info(f"Logged {len(summary.hosts_up)} hosts to engagement")

        except ImportError:
            pass
        except Exception as e:
            logger.debug(f"Failed to log nmap to engagement: {e}")

    @staticmethod
    def _create_nmap_host(tx, host: NmapHost) -> None:
        """Create or update Computer node from nmap data"""
        query = """
        MERGE (c:Computer {ip: $ip})
        ON CREATE SET
            c.first_seen = datetime(),
            c.name = $name,
            c.hostname = $hostname,
            c.os = $os,
            c.os_cpe = $os_cpe,
            c.is_dc = $is_dc,
            c.is_windows = $is_windows,
            c.is_linux = $is_linux,
            c.netbios_name = $netbios_name,
            c.netbios_domain = $netbios_domain,
            c.dns_domain = $dns_domain,
            c.source = 'nmap'
        ON MATCH SET
            c.last_seen = datetime(),
            c.os = COALESCE($os, c.os),
            c.os_cpe = COALESCE($os_cpe, c.os_cpe),
            c.is_dc = $is_dc OR c.is_dc,
            c.is_windows = $is_windows OR c.is_windows,
            c.is_linux = $is_linux OR c.is_linux,
            c.hostname = COALESCE($hostname, c.hostname),
            c.netbios_name = COALESCE($netbios_name, c.netbios_name)
        """

        tx.run(query,
               ip=host.ip,
               name=host.best_name.upper(),
               hostname=host.hostname,
               os=host.os_display,
               os_cpe=host.os_cpe or "",
               is_dc=host.is_domain_controller,
               is_windows=host.is_windows,
               is_linux=host.is_linux,
               netbios_name=host.netbios_name or "",
               netbios_domain=host.netbios_domain or "",
               dns_domain=host.dns_domain or "")

    @staticmethod
    def _create_nmap_port(tx, host_ip: str, port: NmapPort) -> None:
        """Create Port node and link to host"""
        port_id = f"{host_ip}:{port.port}/{port.protocol}"

        query = """
        MERGE (p:Port {id: $port_id})
        ON CREATE SET
            p.port = $port,
            p.protocol = $protocol,
            p.state = $state,
            p.service = $service,
            p.version = $version,
            p.product = $product,
            p.is_web = $is_web,
            p.is_smb = $is_smb,
            p.is_rdp = $is_rdp,
            p.is_winrm = $is_winrm,
            p.is_ssh = $is_ssh,
            p.first_seen = datetime()
        ON MATCH SET
            p.last_seen = datetime(),
            p.service = COALESCE($service, p.service),
            p.version = COALESCE($version, p.version)

        WITH p
        MATCH (c:Computer {ip: $host_ip})
        MERGE (c)-[:HAS_PORT]->(p)
        """

        tx.run(query,
               port_id=port_id,
               host_ip=host_ip,
               port=port.port,
               protocol=port.protocol,
               state=port.state.value,
               service=port.service,
               version=port.version,
               product=port.product,
               is_web=port.is_web,
               is_smb=port.is_smb,
               is_rdp=port.is_rdp,
               is_winrm=port.is_winrm,
               is_ssh=port.is_ssh)

    @staticmethod
    def _link_host_to_domain(tx, host_ip: str, domain: str) -> None:
        """Link Computer to Domain"""
        query = """
        MATCH (c:Computer {ip: $ip})
        MATCH (d:Domain {name: $domain})
        MERGE (c)-[:MEMBER_OF]->(d)
        """
        tx.run(query, ip=host_ip, domain=domain.upper())

    def query_hosts(
        self,
        is_dc: Optional[bool] = None,
        is_windows: Optional[bool] = None,
        has_port: Optional[int] = None,
        domain: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Query discovered hosts

        Args:
            is_dc: Filter for domain controllers
            is_windows: Filter for Windows hosts
            has_port: Filter for hosts with specific port open
            domain: Filter by domain

        Returns:
            List of host dictionaries
        """
        if not self._connected and not self.connect():
            return []

        conditions = []
        params = {}

        if is_dc is not None:
            conditions.append("c.is_dc = $is_dc")
            params['is_dc'] = is_dc

        if is_windows is not None:
            conditions.append("c.is_windows = $is_windows")
            params['is_windows'] = is_windows

        if domain:
            conditions.append("c.dns_domain = $domain OR c.netbios_domain = $domain")
            params['domain'] = domain.upper()

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        if has_port:
            query = f"""
            MATCH (c:Computer)-[:HAS_PORT]->(p:Port {{port: $port}})
            {where_clause}
            RETURN DISTINCT c
            ORDER BY c.ip
            """
            params['port'] = has_port
        else:
            query = f"""
            MATCH (c:Computer)
            {where_clause}
            RETURN c
            ORDER BY c.ip
            """

        with self.driver.session(database=self.database) as session:
            result = session.run(query, **params)
            return [dict(record['c']) for record in result]

    def get_host_stats(self) -> Dict[str, int]:
        """Get host statistics from nmap scans

        Returns:
            Dict with counts by category
        """
        if not self._connected and not self.connect():
            return {}

        query = """
        MATCH (c:Computer)
        RETURN
            COUNT(*) AS total_hosts,
            SUM(CASE WHEN c.is_dc THEN 1 ELSE 0 END) AS domain_controllers,
            SUM(CASE WHEN c.is_windows THEN 1 ELSE 0 END) AS windows_hosts,
            SUM(CASE WHEN c.is_linux THEN 1 ELSE 0 END) AS linux_hosts
        """

        with self.driver.session(database=self.database) as session:
            result = session.run(query)
            record = result.single()
            if record:
                return dict(record)
            return {}
