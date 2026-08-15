"""MCP (Model Context Protocol) server package.

Exposes ARGUS OSINT tools via the MCP protocol for integration
with AI assistants and automation workflows.

Provides:
    - MCP server with stdio and HTTP transports
    - Tools: search, scrape, analyze_iocs, run_pentest,
      create_investigation, export_stix, get_threats

Usage::

    from backend.mcp.server import MCPServer
    server = MCPServer()
    await server.run_stdio()
"""

from backend.mcp.server import MCPServer
from backend.mcp.tools import MCPTools

__all__ = [
    "MCPServer",
    "MCPTools",
]
