"""Configuration introspection tools for CRACK MCP server."""

import json

from ..adapters.crack_api import api


def _response(success: bool, data=None, error: str = None) -> str:
    """Format consistent JSON response."""
    return json.dumps({"success": success, "data": data, "error": error})


def register_config_tools(mcp):
    """Register all configuration tools with the MCP server."""

    @mcp.tool()
    async def list_configured_variables(category: str = None) -> str:
        """List configured variable values.

        Args:
            category: Optional filter by category (network, web, credentials, enumeration,
                      exploitation, file-transfer, sql-injection, miscellaneous)

        Returns:
            JSON with variables array and count

        Example:
            {"success": true, "data": {
                "count": 12,
                "variables": [
                    {"name": "LHOST", "value": "10.10.14.5", "category": "network", "required": true},
                    {"name": "TARGET", "value": "10.10.10.70", "category": "network", "required": true}
                ]
            }}
        """
        try:
            results = api.list_variables(category)
            return _response(True, {"count": len(results), "variables": results})
        except Exception as e:
            return _response(False, error=str(e))

    @mcp.tool()
    async def describe_variable(name: str) -> str:
        """Get full metadata for a variable.

        Args:
            name: Variable name (e.g., 'LHOST', 'TARGET', '<WORDLIST>')

        Returns:
            JSON with name, category, description, example, required, validation pattern, aliases, current value

        Example:
            {"success": true, "data": {
                "name": "LHOST",
                "category": "network",
                "description": "Local/attacker IP address (your machine)",
                "example": "10.10.14.5",
                "required": true,
                "validation": "^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$",
                "aliases": [],
                "current_value": "10.10.14.5"
            }}
        """
        try:
            result = api.describe_variable(name)
            if result:
                return _response(True, result)
            return _response(False, error=f"Variable not found: {name}")
        except Exception as e:
            return _response(False, error=str(e))
