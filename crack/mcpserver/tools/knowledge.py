"""Knowledge query tools for CRACK MCP server."""

import json
from typing import List, Optional

from ..adapters.crack_api import api


def _response(success: bool, data=None, error: str = None) -> str:
    """Format consistent JSON response."""
    return json.dumps({"success": success, "data": data, "error": error})


def register_knowledge_tools(mcp):
    """Register all knowledge tools with the MCP server."""

    @mcp.tool()
    async def search_commands(
        query: str,
        category: str = None,
        tags: str = None,
        oscp_only: bool = False
    ) -> str:
        """Search CRACK command database (795+ commands).

        Args:
            query: Search term (command name, technique, keyword like 'winrm lateral' or 'sqli')
            category: Filter by category (recon, web, exploitation, post-exploit, enumeration, pivoting, file-transfer)
            tags: Comma-separated tags to filter (LINUX, WINDOWS, AD, QUICK_WIN, KERBEROS)
            oscp_only: Return only OSCP high-relevance commands

        Returns:
            JSON with count and commands array (max 20 results, descriptions truncated to 100 chars)

        Example:
            {"success": true, "data": {"count": 3, "commands": [
                {"id": "nmap-service-scan", "name": "Nmap Service Scan", "description": "Detect services...",
                 "category": "recon", "tags": ["LINUX", "WINDOWS"], "oscp_relevance": "high"}
            ]}}
        """
        try:
            tag_list = [t.strip() for t in tags.split(",")] if tags else None
            results = api.search_commands(query, category, tag_list, oscp_only)
            return _response(True, {"count": len(results), "commands": results})
        except Exception as e:
            return _response(False, error=str(e))

    @mcp.tool()
    async def get_command(command_id: str) -> str:
        """Get full command details by ID.

        Args:
            command_id: Exact command ID (e.g., 'impacket-getnpusers-asreproast', 'nmap-service-scan')

        Returns:
            JSON with full command details including template, variables, flags, troubleshooting

        Example:
            {"success": true, "data": {
                "id": "nmap-service-scan", "name": "Nmap Service Scan",
                "command": "nmap -sV -sC -p<PORTS> <TARGET>",
                "description": "Detect service versions and run default scripts",
                "category": "recon", "subcategory": "port-scanning", "tags": ["LINUX", "WINDOWS"],
                "variables": [{"name": "<TARGET>", "description": "Target IP", "example": "10.10.10.5", "required": true}],
                "flag_explanations": {"-sV": "Version detection", "-sC": "Default scripts"},
                "prerequisites": [], "alternatives": ["masscan-fast"], "next_steps": ["nmap-vuln-scan"],
                "oscp_relevance": "high"
            }}
        """
        try:
            result = api.get_command(command_id)
            if result:
                return _response(True, result)
            return _response(False, error=f"Command not found: {command_id}")
        except Exception as e:
            return _response(False, error=str(e))

    @mcp.tool()
    async def fill_command(command_id: str, variables: str = None) -> str:
        """Fill command placeholders with values.

        Args:
            command_id: Command ID to fill
            variables: JSON object mapping placeholder names to values,
                       e.g., '{"TARGET": "10.10.10.70", "LHOST": "10.10.14.5"}'
                       If not provided, uses values from ~/.crack/config.json

        Returns:
            JSON with filled command string ready for execution

        Example:
            {"success": true, "data": {
                "command": "nmap -sV -sC -p22,80,443 10.10.10.70",
                "command_id": "nmap-service-scan"
            }}
        """
        try:
            var_dict = json.loads(variables) if variables else None
            result = api.fill_command(command_id, var_dict)
            if result:
                return _response(True, {"command": result, "command_id": command_id})
            return _response(False, error=f"Command not found: {command_id}")
        except json.JSONDecodeError:
            return _response(False, error="Invalid JSON in variables parameter")
        except Exception as e:
            return _response(False, error=str(e))

    @mcp.tool()
    async def get_cheatsheet(topic: str) -> str:
        """Get penetration testing cheatsheet with scenarios.

        Args:
            topic: Topic to search (linux-privesc, ad-password-spraying, sqli, log-poisoning, etc.)

        Returns:
            JSON with id, name, scenarios (max 3), sections (max 5 with 5 commands each), tags

        Example:
            {"success": true, "data": {
                "id": "linux-privesc", "name": "Linux Privilege Escalation",
                "description": "Common Linux privesc techniques",
                "scenarios": [{"title": "SUID Binary", "context": "Found unusual SUID binary", "approach": "Check GTFOBins"}],
                "sections": [{"title": "SUID Enumeration", "commands": ["find-suid-binaries", "linpeas-run"]}],
                "tags": ["LINUX", "PRIVESC"]
            }}
        """
        try:
            result = api.get_cheatsheet(topic)
            if result:
                return _response(True, result)
            return _response(False, error=f"Cheatsheet not found: {topic}")
        except Exception as e:
            return _response(False, error=str(e))

    @mcp.tool()
    async def get_attack_chain(chain_id: str) -> str:
        """Get ordered attack chain workflow.

        Args:
            chain_id: Chain ID (e.g., 'ad-asreproast-full', 'linux-privesc-suid-basic',
                      'windows-lateral-psexec-full')

        Returns:
            JSON with id, name, difficulty, time_estimate, prerequisites, and ordered steps

        Example:
            {"success": true, "data": {
                "id": "ad-asreproast-full", "name": "AS-REP Roasting Attack",
                "description": "Extract AS-REP hashes for offline cracking",
                "difficulty": "medium", "time_estimate": "15-30 min",
                "prerequisites": ["domain-user-list"],
                "steps": [{"id": "step-1", "name": "Enumerate users", "objective": "Find users without preauth",
                           "command_ref": "impacket-getnpusers", "dependencies": [], "next_steps": ["step-2"]}]
            }}
        """
        try:
            result = api.get_attack_chain(chain_id)
            if result:
                return _response(True, result)
            return _response(False, error=f"Attack chain not found: {chain_id}")
        except Exception as e:
            return _response(False, error=str(e))

    @mcp.tool()
    async def suggest_next_steps(current_command_id: str = None) -> str:
        """Suggest next commands based on current progress.

        Args:
            current_command_id: Command just executed (uses its next_steps field)

        Returns:
            JSON with suggestions array (max 5) and the command they're based on

        Example:
            {"success": true, "data": {
                "suggestions": [
                    {"id": "nmap-vuln-scan", "name": "Nmap Vulnerability Scan",
                     "description": "Run vulnerability scripts against target",
                     "rationale": "Follows from nmap-service-scan"}
                ],
                "based_on": "nmap-service-scan"
            }}
        """
        try:
            results = api.suggest_next_steps(current_command_id)
            return _response(True, {"suggestions": results, "based_on": current_command_id})
        except Exception as e:
            return _response(False, error=str(e))
