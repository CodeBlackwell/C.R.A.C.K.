"""
Engagement Integration Helper

Provides a simple interface for other tools to interact with the
active engagement without requiring full adapter setup.

Usage:
    from crack.tools.engagement.integration import EngagementIntegration

    # Check if engagement is active
    if EngagementIntegration.is_active():
        # Log a discovered target
        target_id = EngagementIntegration.ensure_target("192.168.1.100")

        # Log services
        EngagementIntegration.add_service(target_id, 80, service_name="http")

        # Log a finding
        EngagementIntegration.add_finding("SQL Injection", severity="critical")
"""

from typing import Optional, List, Dict, Any
import logging

logger = logging.getLogger(__name__)


class EngagementIntegration:
    """
    Static helper for engagement integration.

    Provides lightweight methods for tools to log data to the active engagement.
    Handles cases where Neo4j is unavailable gracefully.
    """

    _adapter = None
    _adapter_initialized = False

    @classmethod
    def _get_adapter(cls):
        """Lazy-load adapter on first use"""
        if cls._adapter_initialized:
            return cls._adapter

        cls._adapter_initialized = True

        try:
            from .adapter import EngagementAdapter
            cls._adapter = EngagementAdapter()
            return cls._adapter
        except Exception as e:
            logger.debug(f"Engagement adapter not available: {e}")
            cls._adapter = None
            return None

    @classmethod
    def is_active(cls) -> bool:
        """
        Check if there's an active engagement.

        Returns:
            True if an engagement is active
        """
        try:
            from .storage import get_active_engagement_id
            return get_active_engagement_id() is not None
        except Exception:
            return False

    @classmethod
    def get_active_engagement_id(cls) -> Optional[str]:
        """
        Get active engagement ID without full adapter.

        Returns:
            Engagement ID or None
        """
        try:
            from .storage import get_active_engagement_id
            return get_active_engagement_id()
        except Exception:
            return None

    @classmethod
    def get_active_engagement(cls) -> Optional[Dict[str, Any]]:
        """
        Get active engagement details.

        Returns:
            Dict with engagement info or None
        """
        adapter = cls._get_adapter()
        if not adapter:
            return None

        try:
            engagement = adapter.get_active_engagement()
            if engagement:
                return engagement.to_dict()
        except Exception as e:
            logger.debug(f"Failed to get active engagement: {e}")

        return None

    @classmethod
    def ensure_target(
        cls,
        ip_address: str,
        hostname: str = "",
        os_guess: str = ""
    ) -> Optional[str]:
        """
        Ensure target exists in active engagement.

        If no engagement is active, returns None silently.

        Args:
            ip_address: Target IP address
            hostname: Optional hostname
            os_guess: OS detection guess

        Returns:
            Target ID or None
        """
        adapter = cls._get_adapter()
        if not adapter:
            return None

        try:
            engagement = adapter.get_active_engagement()
            if not engagement:
                return None

            # Check if target already exists
            targets = adapter.get_targets(engagement.id)
            for target in targets:
                if target.ip_address == ip_address:
                    # Update if we have new info
                    if (hostname and not target.hostname) or (os_guess and not target.os_guess):
                        adapter.update_target(
                            target.id,
                            hostname=hostname or target.hostname,
                            os_guess=os_guess or target.os_guess
                        )
                    return target.id

            # Create new target
            return adapter.add_target(
                engagement.id,
                ip_address,
                hostname=hostname,
                os_guess=os_guess
            )

        except Exception as e:
            logger.debug(f"Failed to ensure target: {e}")
            return None

    @classmethod
    def find_target_by_ip(cls, ip_address: str) -> Optional[str]:
        """
        Find target ID by IP address in active engagement.

        Args:
            ip_address: IP to search for

        Returns:
            Target ID or None
        """
        adapter = cls._get_adapter()
        if not adapter:
            return None

        try:
            engagement = adapter.get_active_engagement()
            if not engagement:
                return None

            targets = adapter.get_targets(engagement.id)
            for target in targets:
                if target.ip_address == ip_address:
                    return target.id

        except Exception as e:
            logger.debug(f"Failed to find target: {e}")

        return None

    @classmethod
    def add_service(
        cls,
        target_id: str,
        port: int,
        protocol: str = "tcp",
        service_name: str = "",
        version: str = "",
        banner: str = ""
    ) -> Optional[str]:
        """
        Add service to target.

        Args:
            target_id: Target ID
            port: Port number
            protocol: tcp/udp
            service_name: Service name (http, ssh, etc)
            version: Version string
            banner: Service banner

        Returns:
            Service ID or None
        """
        adapter = cls._get_adapter()
        if not adapter or not target_id:
            return None

        try:
            return adapter.add_service(
                target_id,
                port,
                protocol=protocol,
                service_name=service_name,
                version=version,
                banner=banner
            )
        except Exception as e:
            logger.debug(f"Failed to add service: {e}")
            return None

    @classmethod
    def add_services_batch(
        cls,
        target_id: str,
        services: List[Dict[str, Any]]
    ) -> int:
        """
        Add multiple services to target.

        Args:
            target_id: Target ID
            services: List of service dicts with keys:
                      port, protocol, service_name, version, banner

        Returns:
            Number of services added
        """
        if not target_id:
            return 0

        count = 0
        for svc in services:
            if cls.add_service(
                target_id,
                svc.get('port', 0),
                protocol=svc.get('protocol', 'tcp'),
                service_name=svc.get('service_name', ''),
                version=svc.get('version', ''),
                banner=svc.get('banner', '')
            ):
                count += 1

        return count

    @classmethod
    def add_finding(
        cls,
        title: str,
        severity: str = "medium",
        cve_id: str = "",
        description: str = "",
        evidence: str = "",
        target_id: Optional[str] = None
    ) -> Optional[str]:
        """
        Add finding to active engagement.

        Args:
            title: Finding title
            severity: critical, high, medium, low, info
            cve_id: CVE identifier
            description: Detailed description
            evidence: Proof/evidence
            target_id: Optional target to link

        Returns:
            Finding ID or None
        """
        adapter = cls._get_adapter()
        if not adapter:
            return None

        try:
            engagement = adapter.get_active_engagement()
            if not engagement:
                return None

            finding_id = adapter.add_finding(
                engagement.id,
                title,
                severity=severity,
                cve_id=cve_id,
                description=description,
                evidence=evidence
            )

            # Link to target if provided
            if finding_id and target_id:
                adapter.link_finding_to_target(finding_id, target_id)

            return finding_id

        except Exception as e:
            logger.debug(f"Failed to add finding: {e}")
            return None

    @classmethod
    def log_session(
        cls,
        target_ip: str,
        port: int,
        session_type: str,
        session_id: str
    ) -> bool:
        """
        Log reverse shell session to engagement.

        Links session to target via metadata.

        Args:
            target_ip: Target IP address
            port: Connection port
            session_type: tcp, http, dns, icmp
            session_id: Session UUID

        Returns:
            True if logged successfully
        """
        adapter = cls._get_adapter()
        if not adapter:
            return False

        try:
            engagement = adapter.get_active_engagement()
            if not engagement:
                return False

            # Find or create target
            target_id = cls.ensure_target(target_ip)
            if not target_id:
                return False

            # Update target status to exploited
            adapter.update_target(target_id, status='exploited')

            # Add a finding for the session
            cls.add_finding(
                title=f"Shell Access Obtained ({session_type.upper()})",
                severity="critical",
                description=f"Reverse shell established via {session_type} on port {port}",
                evidence=f"Session ID: {session_id}",
                target_id=target_id
            )

            return True

        except Exception as e:
            logger.debug(f"Failed to log session: {e}")
            return False

    @classmethod
    def link_credential_to_target(
        cls,
        target_ip: str,
        credential_info: str
    ) -> bool:
        """
        Log credential extraction to engagement.

        Args:
            target_ip: Source host IP
            credential_info: Credential summary

        Returns:
            True if logged
        """
        adapter = cls._get_adapter()
        if not adapter:
            return False

        try:
            engagement = adapter.get_active_engagement()
            if not engagement:
                return False

            target_id = cls.find_target_by_ip(target_ip)
            if not target_id:
                return False

            # Log as finding
            cls.add_finding(
                title="Credentials Extracted",
                severity="high",
                description=f"Credentials obtained from {target_ip}",
                evidence=credential_info,
                target_id=target_id
            )

            return True

        except Exception as e:
            logger.debug(f"Failed to link credential: {e}")
            return False
