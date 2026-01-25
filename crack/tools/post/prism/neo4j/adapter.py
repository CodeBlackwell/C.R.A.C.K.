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
from ..models import LdapSummary
from ..models.ldap_entry import LdapUser, LdapComputer, LdapGroup, LdapDomainInfo

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
            from crack.db.config import Neo4jConfig
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

    def import_summary(self, summary) -> Dict[str, int]:
        """Unified import - dispatches based on summary type

        Args:
            summary: ParsedSummary, NmapScanSummary, or LdapSummary

        Returns:
            Dict with counts of imported items
        """
        if not self._connected and not self.connect():
            raise RuntimeError("Not connected to Neo4j")

        handlers = {
            ParsedSummary: self._import_credentials,
            NmapScanSummary: self._import_nmap,
            LdapSummary: self._import_ldap,
        }

        handler = handlers.get(type(summary))
        if not handler:
            raise ValueError(f"Unsupported summary type: {type(summary).__name__}")

        return handler(summary)

    def _import_credentials(self, summary: ParsedSummary) -> Dict[str, int]:
        """Import credential summary to Neo4j (internal handler)"""
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

    def _import_nmap(self, summary: NmapScanSummary) -> Dict[str, int]:
        """Import nmap scan summary to Neo4j (internal handler)"""
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

    # ========================================================================
    # LDAP Import Methods
    # ========================================================================

    def _import_ldap(self, summary: LdapSummary) -> Dict[str, int]:
        """Import LDAP summary to Neo4j (internal handler)"""
        results = {'users': 0, 'computers': 0, 'groups': 0, 'domains': 0}
        domain = summary.domain_name

        with self.driver.session(database=self.database) as session:
            # Domain + password policy
            if summary.domain_info:
                session.execute_write(self._create_ldap_domain, summary.domain_info)
                results['domains'] = 1

            # Users
            for user in summary.users:
                if not user.is_machine_account:
                    session.execute_write(self._create_ldap_user, user, domain)
                    results['users'] += 1

            # Computers
            for computer in summary.computers:
                session.execute_write(self._create_ldap_computer, computer, domain)
                results['computers'] += 1

            # Groups
            for group in summary.groups:
                session.execute_write(self._create_ldap_group, group, domain)
                results['groups'] += 1

        return results

    @staticmethod
    def _create_ldap_domain(tx, domain_info: LdapDomainInfo) -> None:
        """Create Domain and PasswordPolicy nodes"""
        query = """
        MERGE (d:Domain {name: $name})
        SET d.dns_name = $dns_name,
            d.functional_level = $functional_level,
            d.functional_level_name = $functional_level_name,
            d.source = 'ldapsearch'

        MERGE (p:PasswordPolicy {domain: $name})
        SET p.min_length = $min_length,
            p.history_length = $history_length,
            p.lockout_threshold = $lockout_threshold,
            p.lockout_duration_minutes = $lockout_duration,
            p.max_pwd_age_days = $max_pwd_age,
            p.complexity_required = $complexity,
            p.is_weak = $is_weak

        MERGE (d)-[:HAS_POLICY]->(p)
        """
        tx.run(query,
               name=domain_info.domain_name.upper() or domain_info.dns_name.upper(),
               dns_name=domain_info.dns_name,
               functional_level=domain_info.functional_level,
               functional_level_name=domain_info.functional_level_name,
               min_length=domain_info.min_pwd_length,
               history_length=domain_info.pwd_history_length,
               lockout_threshold=domain_info.lockout_threshold,
               lockout_duration=domain_info.lockout_duration_minutes,
               max_pwd_age=domain_info.max_pwd_age_days,
               complexity=domain_info.pwd_complexity_required,
               is_weak=domain_info.is_weak_policy)

    @staticmethod
    def _create_ldap_user(tx, user: LdapUser, domain: str) -> None:
        """Create User node with properties and domain relationship"""
        query = """
        MERGE (u:User {name: $name, domain: $domain})
        SET u.display_name = $display_name,
            u.description = $description,
            u.dn = $dn,
            u.uac = $uac,
            u.spns = $spns,
            u.is_enabled = $is_enabled,
            u.is_kerberoastable = $is_kerberoastable,
            u.is_asrep_roastable = $is_asrep_roastable,
            u.admin_count = $admin_count,
            u.trusted_for_delegation = $trusted_for_delegation,
            u.high_value = $high_value,
            u.source = 'ldapsearch'

        WITH u
        MATCH (d:Domain {name: $domain})
        MERGE (u)-[:BELONGS_TO]->(d)
        """
        tx.run(query,
               name=user.sam_account_name.upper(),
               domain=domain.upper(),
               display_name=user.display_name,
               description=user.description or "",
               dn=user.dn,
               uac=user.user_account_control,
               spns=user.service_principal_names,
               is_enabled=not user.is_disabled,
               is_kerberoastable=user.is_kerberoastable,
               is_asrep_roastable=user.dont_require_preauth,
               admin_count=user.admin_count,
               trusted_for_delegation=user.trusted_for_delegation,
               high_value=user.high_value)

    @staticmethod
    def _create_ldap_computer(tx, computer: LdapComputer, domain: str) -> None:
        """Create Computer node with properties and domain relationship"""
        query = """
        MERGE (c:Computer {name: $name})
        SET c.dns_hostname = $dns_hostname,
            c.os = $os,
            c.os_version = $os_version,
            c.dn = $dn,
            c.is_dc = $is_dc,
            c.trusted_for_delegation = $trusted_for_delegation,
            c.source = 'ldapsearch'

        WITH c
        MATCH (d:Domain {name: $domain})
        MERGE (c)-[:MEMBER_OF]->(d)
        """
        tx.run(query,
               name=computer.sam_account_name.upper().rstrip('$'),
               dns_hostname=computer.dns_hostname or "",
               os=computer.operating_system or "",
               os_version=computer.os_version or "",
               dn=computer.dn,
               is_dc=computer.is_domain_controller,
               trusted_for_delegation=computer.trusted_for_delegation,
               domain=domain.upper())

    @staticmethod
    def _create_ldap_group(tx, group: LdapGroup, domain: str) -> None:
        """Create Group node with properties"""
        query = """
        MERGE (g:Group {name: $name, domain: $domain})
        SET g.description = $description,
            g.dn = $dn,
            g.admin_count = $admin_count,
            g.is_high_value = $is_high_value,
            g.member_count = $member_count,
            g.source = 'ldapsearch'
        """
        tx.run(query,
               name=group.sam_account_name.upper(),
               domain=domain.upper(),
               description=group.description or "",
               dn=group.dn,
               admin_count=group.admin_count,
               is_high_value=group.is_high_value,
               member_count=len(group.members))

    # ========================================================================
    # Domain Report Query Methods
    # ========================================================================

    def list_domains(self) -> List[Dict[str, Any]]:
        """List all domains in database with counts

        Returns:
            List of domain dicts with name, dns_name, source, user_count
        """
        if not self._connected and not self.connect():
            return []

        query = """
        MATCH (d:Domain)
        OPTIONAL MATCH (u:User)-[:BELONGS_TO]->(d)
        OPTIONAL MATCH (c:Computer)-[:MEMBER_OF]->(d)
        OPTIONAL MATCH (cr:Credential)-[:BELONGS_TO]->(d)
        RETURN d.name AS name,
               d.dns_name AS dns_name,
               d.source AS source,
               d.functional_level_name AS functional_level,
               COUNT(DISTINCT u) AS user_count,
               COUNT(DISTINCT c) AS computer_count,
               COUNT(DISTINCT cr) AS credential_count
        ORDER BY d.name
        """

        with self.driver.session(database=self.database) as session:
            result = session.run(query)
            return [dict(record) for record in result]

    def query_domain_report(self, domain: str) -> Dict[str, Any]:
        """Get comprehensive report for a domain

        Args:
            domain: Domain name (case-insensitive)

        Returns:
            Dict with domain, policy, users, computers, credentials, groups, tickets, stats
        """
        if not self._connected and not self.connect():
            return {}

        domain_upper = domain.upper()

        return {
            'domain': self._get_domain_info(domain_upper),
            'policy': self._get_password_policy(domain_upper),
            'users': self._get_domain_users(domain_upper),
            'computers': self._get_domain_computers(domain_upper),
            'credentials': self._get_domain_credentials(domain_upper),
            'groups': self._get_domain_groups(domain_upper),
            'tickets': self._get_domain_tickets(domain_upper),
            'stats': self._get_domain_stats(domain_upper),
        }

    def _get_domain_info(self, domain: str) -> Dict[str, Any]:
        """Get domain information"""
        query = """
        MATCH (d:Domain)
        WHERE d.name = $domain OR toUpper(d.dns_name) CONTAINS $domain
        RETURN d.name AS name,
               d.dns_name AS dns_name,
               d.functional_level AS functional_level,
               d.functional_level_name AS functional_level_name,
               d.source AS source
        LIMIT 1
        """
        with self.driver.session(database=self.database) as session:
            result = session.run(query, domain=domain)
            record = result.single()
            return dict(record) if record else {}

    def _get_password_policy(self, domain: str) -> Dict[str, Any]:
        """Get password policy for domain"""
        query = """
        MATCH (d:Domain)-[:HAS_POLICY]->(p:PasswordPolicy)
        WHERE d.name = $domain OR toUpper(d.dns_name) CONTAINS $domain
        RETURN p.min_length AS min_length,
               p.history_length AS history_length,
               p.lockout_threshold AS lockout_threshold,
               p.lockout_duration_minutes AS lockout_duration,
               p.max_pwd_age_days AS max_pwd_age,
               p.complexity_required AS complexity,
               p.is_weak AS is_weak
        LIMIT 1
        """
        with self.driver.session(database=self.database) as session:
            result = session.run(query, domain=domain)
            record = result.single()
            return dict(record) if record else {}

    def _get_domain_users(self, domain: str) -> List[Dict[str, Any]]:
        """Get users for domain with attack flags"""
        query = """
        MATCH (u:User)-[:BELONGS_TO]->(d:Domain)
        WHERE d.name = $domain OR toUpper(d.dns_name) CONTAINS $domain
        RETURN u.name AS name,
               u.display_name AS display_name,
               u.description AS description,
               u.is_enabled AS is_enabled,
               u.is_kerberoastable AS is_kerberoastable,
               u.is_asrep_roastable AS is_asrep_roastable,
               u.admin_count AS admin_count,
               u.trusted_for_delegation AS trusted_for_delegation,
               u.high_value AS high_value,
               u.spns AS spns,
               u.first_seen AS first_seen,
               u.last_seen AS last_seen
        ORDER BY u.high_value DESC, u.name
        """
        with self.driver.session(database=self.database) as session:
            result = session.run(query, domain=domain)
            return [dict(record) for record in result]

    def _get_domain_computers(self, domain: str) -> List[Dict[str, Any]]:
        """Get computers for domain"""
        query = """
        MATCH (c:Computer)-[:MEMBER_OF]->(d:Domain)
        WHERE d.name = $domain OR toUpper(d.dns_name) CONTAINS $domain
        RETURN c.name AS name,
               c.dns_hostname AS dns_hostname,
               c.os AS os,
               c.os_version AS os_version,
               c.ip AS ip,
               c.is_dc AS is_dc,
               c.trusted_for_delegation AS trusted_for_delegation,
               c.first_seen AS first_seen,
               c.last_seen AS last_seen
        ORDER BY c.is_dc DESC, c.name
        """
        with self.driver.session(database=self.database) as session:
            result = session.run(query, domain=domain)
            return [dict(record) for record in result]

    def _get_domain_credentials(self, domain: str) -> List[Dict[str, Any]]:
        """Get credentials for domain"""
        query = """
        MATCH (c:Credential)-[:BELONGS_TO]->(d:Domain)
        WHERE d.name = $domain OR toUpper(d.dns_name) CONTAINS $domain
        RETURN c.username AS username,
               c.cred_type AS cred_type,
               c.value AS value,
               c.source_tool AS source_tool,
               c.high_value AS high_value,
               c.is_machine AS is_machine,
               c.first_seen AS first_seen,
               c.last_seen AS last_seen,
               COALESCE(c.occurrences, 1) AS occurrences
        ORDER BY c.high_value DESC, c.username
        """
        with self.driver.session(database=self.database) as session:
            result = session.run(query, domain=domain)
            return [dict(record) for record in result]

    def _get_domain_groups(self, domain: str) -> List[Dict[str, Any]]:
        """Get groups for domain (high-value first)"""
        query = """
        MATCH (g:Group)
        WHERE g.domain = $domain
        RETURN g.name AS name,
               g.description AS description,
               g.is_high_value AS is_high_value,
               g.admin_count AS admin_count,
               g.member_count AS member_count
        ORDER BY g.is_high_value DESC, g.admin_count DESC, g.name
        """
        with self.driver.session(database=self.database) as session:
            result = session.run(query, domain=domain)
            return [dict(record) for record in result]

    def _get_domain_tickets(self, domain: str) -> List[Dict[str, Any]]:
        """Get Kerberos tickets for domain"""
        query = """
        MATCH (t:KerberosTicket)
        WHERE toUpper(t.client_realm) CONTAINS $domain
        RETURN t.client_name AS client_name,
               t.client_realm AS client_realm,
               t.service_type AS service_type,
               t.service_target AS service_target,
               t.is_tgt AS is_tgt,
               t.end_time AS end_time,
               t.saved_path AS saved_path
        ORDER BY t.is_tgt DESC, t.client_name
        """
        with self.driver.session(database=self.database) as session:
            result = session.run(query, domain=domain)
            return [dict(record) for record in result]

    def _get_domain_stats(self, domain: str) -> Dict[str, int]:
        """Get statistics for domain"""
        query = """
        MATCH (d:Domain)
        WHERE d.name = $domain OR toUpper(d.dns_name) CONTAINS $domain
        OPTIONAL MATCH (u:User)-[:BELONGS_TO]->(d)
        OPTIONAL MATCH (c:Computer)-[:MEMBER_OF]->(d)
        OPTIONAL MATCH (cr:Credential)-[:BELONGS_TO]->(d)
        OPTIONAL MATCH (g:Group {domain: $domain})
        OPTIONAL MATCH (t:KerberosTicket)
        WHERE toUpper(t.client_realm) CONTAINS $domain
        WITH d, u, c, cr, g, t
        RETURN COUNT(DISTINCT u) AS total_users,
               COUNT(DISTINCT CASE WHEN u.is_enabled THEN u END) AS enabled_users,
               COUNT(DISTINCT CASE WHEN u.is_kerberoastable THEN u END) AS kerberoastable,
               COUNT(DISTINCT CASE WHEN u.is_asrep_roastable THEN u END) AS asrep_roastable,
               COUNT(DISTINCT CASE WHEN u.high_value THEN u END) AS high_value_users,
               COUNT(DISTINCT c) AS total_computers,
               COUNT(DISTINCT CASE WHEN c.is_dc THEN c END) AS domain_controllers,
               COUNT(DISTINCT cr) AS total_credentials,
               COUNT(DISTINCT g) AS total_groups,
               COUNT(DISTINCT CASE WHEN g.is_high_value THEN g END) AS high_value_groups,
               COUNT(DISTINCT t) AS total_tickets
        """
        with self.driver.session(database=self.database) as session:
            result = session.run(query, domain=domain)
            record = result.single()
            return dict(record) if record else {}

    # ============================================================
    # PURGE OPERATIONS
    # ============================================================

    def purge_domain(self, domain: str) -> Dict[str, int]:
        """Remove all data for a specific domain

        Deletes: Domain, Users, Computers, Credentials, Groups, KerberosTickets

        Args:
            domain: Domain name (e.g., 'CORP.LOCAL')

        Returns:
            Dict with counts of deleted nodes by type
        """
        counts = {}

        # Delete credentials linked to domain
        query = """
        MATCH (c:Credential)-[:BELONGS_TO]->(d:Domain)
        WHERE d.name = $domain OR toUpper(d.dns_name) CONTAINS $domain
        WITH c, count(c) AS cnt
        DETACH DELETE c
        RETURN cnt
        """
        with self.driver.session(database=self.database) as session:
            result = session.run(query, domain=domain)
            record = result.single()
            counts['credentials'] = record['cnt'] if record else 0

        # Delete users linked to domain
        query = """
        MATCH (u:User)-[:BELONGS_TO]->(d:Domain)
        WHERE d.name = $domain OR toUpper(d.dns_name) CONTAINS $domain
        WITH u, count(u) AS cnt
        DETACH DELETE u
        RETURN cnt
        """
        with self.driver.session(database=self.database) as session:
            result = session.run(query, domain=domain)
            record = result.single()
            counts['users'] = record['cnt'] if record else 0

        # Delete computers linked to domain
        query = """
        MATCH (c:Computer)-[:MEMBER_OF]->(d:Domain)
        WHERE d.name = $domain OR toUpper(d.dns_name) CONTAINS $domain
        WITH c, count(c) AS cnt
        DETACH DELETE c
        RETURN cnt
        """
        with self.driver.session(database=self.database) as session:
            result = session.run(query, domain=domain)
            record = result.single()
            counts['computers'] = record['cnt'] if record else 0

        # Delete groups for domain
        query = """
        MATCH (g:Group)
        WHERE g.domain = $domain
        WITH g, count(g) AS cnt
        DETACH DELETE g
        RETURN cnt
        """
        with self.driver.session(database=self.database) as session:
            result = session.run(query, domain=domain)
            record = result.single()
            counts['groups'] = record['cnt'] if record else 0

        # Delete Kerberos tickets for domain
        query = """
        MATCH (t:KerberosTicket)
        WHERE toUpper(t.client_realm) CONTAINS $domain
        WITH t, count(t) AS cnt
        DETACH DELETE t
        RETURN cnt
        """
        with self.driver.session(database=self.database) as session:
            result = session.run(query, domain=domain)
            record = result.single()
            counts['tickets'] = record['cnt'] if record else 0

        # Delete the domain node itself
        query = """
        MATCH (d:Domain)
        WHERE d.name = $domain OR toUpper(d.dns_name) CONTAINS $domain
        WITH d, count(d) AS cnt
        DETACH DELETE d
        RETURN cnt
        """
        with self.driver.session(database=self.database) as session:
            result = session.run(query, domain=domain)
            record = result.single()
            counts['domains'] = record['cnt'] if record else 0

        return counts

    def purge_all(self) -> Dict[str, int]:
        """Remove ALL PRISM data from Neo4j

        WARNING: This deletes all credential-related nodes stored by PRISM.
        Does NOT touch BloodHound data (different node types).

        Returns:
            Dict with counts of deleted nodes by type
        """
        counts = {}

        # Node types managed by PRISM
        prism_labels = ['Credential', 'KerberosTicket', 'Domain', 'User', 'Computer', 'Group']

        for label in prism_labels:
            query = f"""
            MATCH (n:{label})
            WITH n, count(n) AS cnt
            DETACH DELETE n
            RETURN cnt
            """
            with self.driver.session(database=self.database) as session:
                result = session.run(query)
                record = result.single()
                counts[label.lower() + 's'] = record['cnt'] if record else 0

        return counts

    def get_purge_preview(self, domain: str = None) -> Dict[str, int]:
        """Preview what would be deleted without actually deleting

        Args:
            domain: If specified, preview for domain only. Otherwise preview all.

        Returns:
            Dict with counts of nodes that would be deleted
        """
        if domain:
            return self._get_domain_stats(domain)
        else:
            # Count all PRISM nodes
            counts = {}
            prism_labels = ['Credential', 'KerberosTicket', 'Domain', 'User', 'Computer', 'Group']

            for label in prism_labels:
                query = f"MATCH (n:{label}) RETURN count(n) AS cnt"
                with self.driver.session(database=self.database) as session:
                    result = session.run(query)
                    record = result.single()
                    counts[label.lower() + 's'] = record['cnt'] if record else 0

            return counts
