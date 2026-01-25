"""Engagement state management tools for CRACK MCP server."""

import json
from typing import Optional

from ..adapters.crack_api import api


def _response(success: bool, data=None, error: str = None) -> str:
    """Format consistent JSON response."""
    return json.dumps({"success": success, "data": data, "error": error})


def register_state_tools(mcp):
    """Register all state management tools with the MCP server."""

    @mcp.tool()
    async def get_engagement_context() -> str:
        """Get current engagement state.

        Returns:
            JSON with active flag, engagement info, targets (max 10), findings counts, configured variables

        Example:
            {"success": true, "data": {
                "active": true,
                "engagement": {"id": "eng-001", "name": "Lab Pentest"},
                "targets": [{"id": "t-001", "ip": "10.10.10.5", "hostname": "dc01", "status": "enumerated"}],
                "findings": {"critical": 1, "high": 3, "medium": 5, "low": 2, "info": 10},
                "variables": {"LHOST": "10.10.14.5", "TARGET": "10.10.10.5"}
            }}
        """
        try:
            result = api.get_engagement_context()
            return _response(True, result)
        except Exception as e:
            return _response(False, error=str(e))

    @mcp.tool()
    async def add_target(ip_address: str, hostname: str = "", os_guess: str = "") -> str:
        """Add target to active engagement.

        Args:
            ip_address: Target IP address
            hostname: Optional hostname (e.g., 'dc01.corp.local')
            os_guess: Optional OS identification (e.g., 'Windows Server 2019')

        Returns:
            JSON with target_id and ip_address confirmation

        Example:
            {"success": true, "data": {"target_id": "t-abc123", "ip_address": "10.10.10.5"}}
        """
        try:
            result = api.add_target(ip_address, hostname, os_guess)
            if result:
                return _response(True, {"target_id": result, "ip_address": ip_address})
            return _response(False, error="No active engagement or failed to add target")
        except Exception as e:
            return _response(False, error=str(e))

    @mcp.tool()
    async def add_finding(
        title: str,
        severity: str = "medium",
        description: str = "",
        cve_id: str = "",
        target_id: str = ""
    ) -> str:
        """Record a vulnerability finding.

        Args:
            title: Finding title (e.g., 'SQL Injection in login form')
            severity: critical, high, medium, low, info
            description: Detailed description of the vulnerability
            cve_id: CVE identifier if applicable (e.g., 'CVE-2021-44228')
            target_id: Link to specific target (from add_target)

        Returns:
            JSON with finding_id, title, and severity confirmation

        Example:
            {"success": true, "data": {"finding_id": "f-xyz789", "title": "SQL Injection", "severity": "high"}}
        """
        try:
            result = api.add_finding(
                title=title,
                severity=severity,
                description=description,
                cve_id=cve_id,
                target_id=target_id if target_id else None
            )
            if result:
                return _response(True, {"finding_id": result, "title": title, "severity": severity})
            return _response(False, error="No active engagement or failed to add finding")
        except Exception as e:
            return _response(False, error=str(e))

    @mcp.tool()
    async def add_credential(
        username: str,
        credential_type: str,
        value: str,
        target_id: str = "",
        notes: str = ""
    ) -> str:
        """Store discovered credential.

        Args:
            username: Username or account name (e.g., 'administrator', 'svc_sql')
            credential_type: password, hash, ticket, key
            value: The credential value
            target_id: Associated target (from add_target)
            notes: Additional context (e.g., 'Found in web.config')

        Returns:
            JSON with credential_id, username, and type confirmation

        Example:
            {"success": true, "data": {"credential_id": "c-def456", "username": "admin", "type": "password"}}
        """
        try:
            result = api.add_credential(
                username=username,
                credential_type=credential_type,
                value=value,
                target_id=target_id if target_id else None,
                notes=notes
            )
            if result:
                return _response(True, {
                    "credential_id": result,
                    "username": username,
                    "type": credential_type
                })
            return _response(False, error="No active engagement or failed to add credential")
        except Exception as e:
            return _response(False, error=str(e))

    @mcp.tool()
    async def get_server_info() -> str:
        """Get MCP server status and configuration.

        Returns:
            JSON with version, tool count, backend availability, engagement status

        Example:
            {"success": true, "data": {
                "version": "1.0.0",
                "tools_registered": 15,
                "backends": {"neo4j": true, "config": true},
                "engagement_active": true
            }}
        """
        try:
            result = api.get_server_info()
            return _response(True, result)
        except Exception as e:
            return _response(False, error=str(e))

    @mcp.tool()
    async def get_target_graph(target_id: str, depth: int = 1) -> str:
        """Get all relationships for a target.

        Args:
            target_id: Target ID or IP address
            depth: Traversal depth 1-3 (default 1, capped at 3)

        Returns:
            JSON with target info, services, findings, credentials, sessions, relationships

        Example:
            {"success": true, "data": {
                "target": {"id": "t-001", "ip": "10.10.10.5", "hostname": "dc01", "os": "Windows Server 2019", "status": "enumerated"},
                "services": [{"port": 445, "protocol": "tcp", "name": "microsoft-ds", "version": "10.0"}],
                "findings": [],
                "credentials": [],
                "sessions": [{"id": "s-001", "type": "reverse_shell", "status": "active"}],
                "relationships": [{"type": "HAS_SERVICE", "count": 5}, {"type": "HAS_SESSION", "count": 1}]
            }}
        """
        try:
            result = api.get_target_graph(target_id, depth)
            return _response(True, result)
        except Exception as e:
            return _response(False, error=str(e))

    @mcp.tool()
    async def get_engagement_relationships(summary: bool = True) -> str:
        """Get cross-node relationship summary for the engagement.

        Args:
            summary: If true (default), return counts only. If false, include relationship details.

        Returns:
            JSON with credential_access, session_targets, finding_targets mappings, and counts

        Example:
            {"success": true, "data": {
                "credential_access": [],
                "session_targets": [{"session_id": "s-001", "target_id": "t-001", "type": "reverse_shell"}],
                "finding_targets": [{"finding_id": "f-001", "target_id": "t-001", "severity": "high"}],
                "counts": {"targets": 3, "services": 15, "findings": 7, "credentials": 2, "sessions": 1}
            }}
        """
        try:
            result = api.get_engagement_relationships(summary)
            return _response(True, result)
        except Exception as e:
            return _response(False, error=str(e))
