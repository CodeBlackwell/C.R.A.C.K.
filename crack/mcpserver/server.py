#!/usr/bin/env python3
"""CRACK MCP Server - Penetration Testing Knowledge Interface for LLMs.

Run with: python -m crack.mcpserver.server
"""

import logging
import sys

# Critical: Log to stderr, never stdout (corrupts STDIO transport)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr
)
logger = logging.getLogger("crack-mcp")

# Import FastMCP
try:
    from mcp.server.fastmcp import FastMCP
except ImportError:
    logger.error("MCP SDK not installed. Run: pip install 'mcp[cli]'")
    sys.exit(1)

# Create MCP server instance
mcp = FastMCP("crack")

# Register tools
from .tools.knowledge import register_knowledge_tools
from .tools.state import register_state_tools
from .tools.config import register_config_tools

register_knowledge_tools(mcp)
register_state_tools(mcp)
register_config_tools(mcp)

logger.info("Registered 15 tools: 6 knowledge, 7 state, 2 config")


def main():
    """Run CRACK MCP server via stdio transport."""
    logger.info("Starting CRACK MCP server")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
