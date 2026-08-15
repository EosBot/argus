"""MCP server — exposes ARGOS OSINT tools via MCP protocol.

Implements the Model Context Protocol (MCP) server for exposing
ARGUS OSINT capabilities to AI assistants and automation tools.

Supports:
    - stdio transport (for CLI integrations)
    - HTTP/SSE transport (for web integrations)
    - JSON-RPC 2.0 protocol
    - Tool discovery and invocation

Usage::

    server = MCPServer()
    await server.run_stdio()  # Run with stdio transport
    # or
    await server.run_http(host="0.0.0.0", port=8080)  # Run with HTTP transport
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import Any

from backend.mcp.tools import MCPTools

logger = logging.getLogger(__name__)


class MCPServer:
    """MCP protocol server for ARGUS OSINT tools.

    Implements the Model Context Protocol specification for
    exposing tools to AI assistants. Supports stdio and HTTP
    transports.

    Usage::

        server = MCPServer()
        await server.run_stdio()
    """

    PROTOCOL_VERSION = "2024-11-05"
    SERVER_NAME = "argus-mcp-server"
    SERVER_VERSION = "1.0.0"

    def __init__(self) -> None:
        """Initialize MCP server."""
        self._tools = MCPTools()
        self._running = False

    @property
    def tool_definitions(self) -> list[dict[str, Any]]:
        """Return MCP tool definitions."""
        return self._tools.TOOL_DEFINITIONS

    async def run_stdio(self) -> None:
        """Run MCP server with stdio transport.

        Reads JSON-RPC messages from stdin and writes responses
        to stdout. This is the primary transport for CLI integrations
        with AI assistants like Claude Desktop.
        """
        logger.info("Starting MCP server (stdio transport)")
        self._running = True

        try:
            while self._running:
                # Read line from stdin
                line = await asyncio.to_thread(sys.stdin.readline)
                if not line:
                    break

                line = line.strip()
                if not line:
                    continue

                # Parse and handle message
                try:
                    message = json.loads(line)
                    response = await self._handle_message(message)
                    if response:
                        response_json = json.dumps(response, default=str)
                        sys.stdout.write(response_json + "\n")
                        sys.stdout.flush()
                except json.JSONDecodeError:
                    logger.warning("Invalid JSON received: %s", line[:100])
                except Exception as exc:
                    logger.error("Error handling message: %s", exc)
        except KeyboardInterrupt:
            logger.info("MCP server interrupted")
        finally:
            self._running = False
            logger.info("MCP server stopped")

    async def run_http(
        self,
        host: str = "0.0.0.0",
        port: int = 8080,
    ) -> None:
        """Run MCP server with HTTP/SSE transport.

        Starts an HTTP server with SSE endpoint for MCP clients
        that connect over the network.

        Args:
            host: Host address to bind.
            port: Port to listen on.
        """
        try:
            from fastapi import FastAPI, Request
            from fastapi.responses import JSONResponse, StreamingResponse
        except ImportError:
            logger.error("FastAPI required for HTTP transport")
            return

        app = FastAPI(title="ARGUS MCP Server", version=self.SERVER_VERSION)

        @app.get("/mcp")
        async def mcp_sse(request: Request) -> Any:
            """MCP SSE endpoint."""
            async def event_stream():
                while True:
                    if await request.is_disconnected():
                        break
                    yield f"event: message\ndata: {json.dumps({'type': 'ping'})}\n\n"
                    await asyncio.sleep(30)

            return StreamingResponse(
                event_stream(),
                media_type="text/event-stream",
            )

        @app.post("/mcp/tools/list")
        async def list_tools() -> JSONResponse:
            """List available MCP tools."""
            return JSONResponse({"tools": self.tool_definitions})

        @app.post("/mcp/tools/call")
        async def call_tool(request: Request) -> JSONResponse:
            """Call an MCP tool."""
            body = await request.json()
            name = body.get("name", "")
            arguments = body.get("arguments", {})

            try:
                result = await self._tools.call_tool(name, arguments)
                return JSONResponse({"result": result})
            except ValueError as exc:
                return JSONResponse({"error": str(exc)}, status_code=400)
            except Exception as exc:
                logger.error("Tool call failed: %s", exc)
                return JSONResponse({"error": str(exc)}, status_code=500)

        @app.get("/mcp/health")
        async def health() -> JSONResponse:
            """Health check endpoint."""
            return JSONResponse({
                "status": "ok",
                "server": self.SERVER_NAME,
                "version": self.SERVER_VERSION,
                "protocol_version": self.PROTOCOL_VERSION,
                "tools_count": len(self.tool_definitions),
            })

        import uvicorn
        logger.info("Starting MCP server (HTTP transport) on %s:%d", host, port)
        config = uvicorn.Config(app, host=host, port=port, log_level="info")
        server = uvicorn.Server(config)
        await server.serve()

    async def _handle_message(self, message: dict[str, Any]) -> dict[str, Any] | None:
        """Handle an incoming MCP JSON-RPC message.

        Args:
            message: Parsed JSON-RPC message dict.

        Returns:
            Response dict or None for notifications.
        """
        method = message.get("method", "")
        msg_id = message.get("id")
        params = message.get("params", {})

        # Handle initialization
        if method == "initialize":
            return self._make_response(msg_id, {
                "protocolVersion": self.PROTOCOL_VERSION,
                "capabilities": {
                    "tools": {},
                },
                "serverInfo": {
                    "name": self.SERVER_NAME,
                    "version": self.SERVER_VERSION,
                },
            })

        # Handle initialized notification
        if method == "initialized":
            return None  # No response for notifications

        # Handle tools/list
        if method == "tools/list":
            return self._make_response(msg_id, {
                "tools": self.tool_definitions,
            })

        # Handle tools/call
        if method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})

            try:
                result = await self._tools.call_tool(tool_name, arguments)
                return self._make_response(msg_id, {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result, indent=2, default=str),
                        }
                    ],
                })
            except ValueError as exc:
                return self._make_error(msg_id, -32602, str(exc))
            except Exception as exc:
                logger.error("Tool '%s' failed: %s", tool_name, exc)
                return self._make_error(msg_id, -32603, str(exc))

        # Handle ping
        if method == "ping":
            return self._make_response(msg_id, {})

        # Unknown method
        logger.warning("Unknown MCP method: %s", method)
        return self._make_error(msg_id, -32601, f"Method not found: {method}")

    def _make_response(self, msg_id: Any, result: dict[str, Any]) -> dict[str, Any]:
        """Create a JSON-RPC success response.

        Args:
            msg_id: Request ID.
            result: Response result.

        Returns:
            JSON-RPC response dict.
        """
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": result,
        }

    def _make_error(self, msg_id: Any, code: int, message: str) -> dict[str, Any]:
        """Create a JSON-RPC error response.

        Args:
            msg_id: Request ID.
            code: Error code.
            message: Error message.

        Returns:
            JSON-RPC error response dict.
        """
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {
                "code": code,
                "message": message,
            },
        }

    def stop(self) -> None:
        """Stop the MCP server."""
        self._running = False
