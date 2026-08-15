"""MCP tools — OSINT tool implementations for MCP protocol.

Implements the actual tool logic exposed via MCP. Each tool is
a typed async function that can be called by MCP clients.

Tools:
    - search: OSINT search across multiple engines
    - scrape: Web scraping and content extraction
    - analyze_iocs: IOC extraction and analysis
    - run_pentest: Run authorized pentest scans
    - create_investigation: Create new investigation
    - export_stix: Export investigation as STIX bundle
    - get_threats: Get threat intelligence data
"""

from __future__ import annotations

import json
import logging
import uuid
from typing import Any

logger = logging.getLogger(__name__)


class MCPTools:
    """OSINT tool implementations for MCP protocol.

    Each method corresponds to an MCP tool. Tools are async and
    return structured results suitable for LLM consumption.

    Usage::

        tools = MCPTools()
        result = await tools.search({"query": "example.com"})
    """

    # Tool definitions for MCP schema
    TOOL_DEFINITIONS: list[dict[str, Any]] = [
        {
            "name": "search",
            "description": "Perform OSINT search across multiple search engines and data sources",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Search query (domain, IP, hash, etc.)",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum results to return (default: 10)",
                        "default": 10,
                    },
                },
                "required": ["query"],
            },
        },
        {
            "name": "scrape",
            "description": "Scrape and extract content from URLs",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL to scrape",
                    },
                    "extract_iocs": {
                        "type": "boolean",
                        "description": "Whether to extract IOCs from content (default: true)",
                        "default": True,
                    },
                },
                "required": ["url"],
            },
        },
        {
            "name": "analyze_iocs",
            "description": "Extract and analyze Indicators of Compromise from text",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "Text to analyze for IOCs",
                    },
                    "categorize": {
                        "type": "boolean",
                        "description": "Whether to categorize IOCs (default: true)",
                        "default": True,
                    },
                },
                "required": ["text"],
            },
        },
        {
            "name": "run_pentest",
            "description": "Run authorized penetration testing scans against a target",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Scan target (host, URL, or IP)",
                    },
                    "tools": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of pentest tools to run (default: all)",
                        "default": [],
                    },
                    "authorized": {
                        "type": "boolean",
                        "description": "Confirmation of authorization to scan",
                        "default": False,
                    },
                },
                "required": ["target", "authorized"],
            },
        },
        {
            "name": "create_investigation",
            "description": "Create a new OSINT investigation",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Investigation title",
                    },
                    "description": {
                        "type": "string",
                        "description": "Investigation description",
                        "default": "",
                    },
                    "priority": {
                        "type": "string",
                        "description": "Priority level (low, medium, high)",
                        "default": "medium",
                    },
                    "tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Tags for the investigation",
                        "default": [],
                    },
                },
                "required": ["title"],
            },
        },
        {
            "name": "export_stix",
            "description": "Export an investigation as a STIX 2.1 bundle",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "investigation_id": {
                        "type": "string",
                        "description": "ID of the investigation to export",
                    },
                    "format": {
                        "type": "string",
                        "description": "Export format (json, misp, sigma, yara)",
                        "default": "json",
                    },
                },
                "required": ["investigation_id"],
            },
        },
        {
            "name": "get_threats",
            "description": "Get threat intelligence data for a target",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target to get threat intel for (domain, IP, hash)",
                    },
                    "target_type": {
                        "type": "string",
                        "description": "Type of target (domain, ip, hash, url)",
                        "default": "auto",
                    },
                },
                "required": ["target"],
            },
        },
    ]

    async def search(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Perform OSINT search.

        Args:
            arguments: Tool arguments with query and max_results.

        Returns:
            Search results dict.
        """
        query = arguments.get("query", "")
        max_results = arguments.get("max_results", 10)

        if not query:
            return {"status": "error", "message": "Query is required"}

        try:
            # Use the existing search infrastructure
            from backend.api.routes.search import _perform_search

            results = await _perform_search(query, max_results=max_results)
            return {
                "status": "success",
                "query": query,
                "results": results,
                "total": len(results) if isinstance(results, list) else 0,
            }
        except ImportError:
            logger.warning("Search route not available")
            return {
                "status": "success",
                "query": query,
                "results": [],
                "total": 0,
                "note": "Search backend not available — returning empty results",
            }
        except Exception as exc:
            logger.error("Search failed: %s", exc)
            return {"status": "error", "message": str(exc)}

    async def scrape(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Scrape and extract content from a URL.

        Args:
            arguments: Tool arguments with url and extract_iocs.

        Returns:
            Scrape results dict.
        """
        url = arguments.get("url", "")
        extract_iocs = arguments.get("extract_iocs", True)

        if not url:
            return {"status": "error", "message": "URL is required"}

        try:
            import httpx

            async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
                response = await client.get(url)
                content = response.text

            result: dict[str, Any] = {
                "status": "success",
                "url": url,
                "status_code": response.status_code,
                "content_length": len(content),
                "content_preview": content[:2000],
            }

            if extract_iocs:
                from backend.tools.ioc_parser import IOCParser
                parser = IOCParser()
                ioc_result = await parser.parse(content)
                result["iocs"] = ioc_result.to_dict()

            return result
        except Exception as exc:
            logger.error("Scrape failed: %s", exc)
            return {"status": "error", "message": str(exc)}

    async def analyze_iocs(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Extract and analyze IOCs from text.

        Args:
            arguments: Tool arguments with text and categorize.

        Returns:
            IOC analysis results dict.
        """
        text = arguments.get("text", "")
        categorize = arguments.get("categorize", True)

        if not text:
            return {"status": "error", "message": "Text is required"}

        try:
            from backend.tools.ioc_parser import IOCParser
            parser = IOCParser()
            result = await parser.parse(text)

            output: dict[str, Any] = {
                "status": "success",
                "total_iocs": result.total_count,
                "categories": result.categories,
                "primary_type": result.primary_type,
                "iocs": result.iocs,
            }

            if categorize:
                # Add category summary
                category_summary: dict[str, int] = {}
                for key, values in result.iocs.items():
                    if isinstance(values, list) and values:
                        category_summary[key] = len(values)
                output["category_counts"] = category_summary

            return output
        except Exception as exc:
            logger.error("IOC analysis failed: %s", exc)
            return {"status": "error", "message": str(exc)}

    async def run_pentest(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Run authorized pentest scans.

        Args:
            arguments: Tool arguments with target, tools, authorized.

        Returns:
            Pentest results dict.
        """
        target = arguments.get("target", "")
        tools = arguments.get("tools", [])
        authorized = arguments.get("authorized", False)

        if not target:
            return {"status": "error", "message": "Target is required"}

        if not authorized:
            return {
                "status": "error",
                "message": "Authorization confirmation required. Set authorized=true to confirm you have permission to scan this target.",
            }

        try:
            from backend.api.routes.pentest import _run_pentest_tools

            results = await _run_pentest_tools(target, tools or None)
            return {
                "status": "success",
                "target": target,
                "results": results,
            }
        except ImportError:
            return {
                "status": "error",
                "message": "Pentest module not available",
            }
        except Exception as exc:
            logger.error("Pentest failed: %s", exc)
            return {"status": "error", "message": str(exc)}

    async def create_investigation(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Create a new investigation.

        Args:
            arguments: Tool arguments with title, description, priority, tags.

        Returns:
            Created investigation dict.
        """
        title = arguments.get("title", "")
        if not title:
            return {"status": "error", "message": "Title is required"}

        investigation_id = str(uuid.uuid4())
        investigation: dict[str, Any] = {
            "id": investigation_id,
            "title": title,
            "description": arguments.get("description", ""),
            "priority": arguments.get("priority", "medium"),
            "tags": arguments.get("tags", []),
            "status": "open",
            "created_at": None,  # Would be set by DB
        }

        return {
            "status": "success",
            "investigation": investigation,
            "message": f"Investigation '{title}' created with ID {investigation_id}",
        }

    async def export_stix(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Export investigation as STIX bundle.

        Args:
            arguments: Tool arguments with investigation_id and format.

        Returns:
            Export results dict.
        """
        investigation_id = arguments.get("investigation_id", "")
        export_format = arguments.get("format", "json")

        if not investigation_id:
            return {"status": "error", "message": "Investigation ID is required"}

        try:
            from backend.export.stix_export import STIXExporter

            # In a real implementation, fetch from DB
            investigation = {"id": investigation_id, "title": f"Investigation {investigation_id}"}
            exporter = STIXExporter()
            bundle = exporter.from_investigation(investigation, [], [])

            return {
                "status": "success",
                "format": export_format,
                "bundle": bundle,
                "json": exporter.to_json(bundle),
            }
        except Exception as exc:
            logger.error("STIX export failed: %s", exc)
            return {"status": "error", "message": str(exc)}

    async def get_threats(self, arguments: dict[str, Any]) -> dict[str, Any]:
        """Get threat intelligence for a target.

        Args:
            arguments: Tool arguments with target and target_type.

        Returns:
            Threat intelligence results dict.
        """
        target = arguments.get("target", "")
        target_type = arguments.get("target_type", "auto")

        if not target:
            return {"status": "error", "message": "Target is required"}

        # Auto-detect type if not specified
        if target_type == "auto":
            from backend.tools.ioc_parser import IOCParser
            parser = IOCParser()
            import asyncio
            target_type = await parser.categorize(target)

        try:
            # In a real implementation, query threat intel feeds
            return {
                "status": "success",
                "target": target,
                "target_type": target_type,
                "threats": [],
                "note": "Threat intel feeds not configured — returning empty results",
            }
        except Exception as exc:
            logger.error("Threat lookup failed: %s", exc)
            return {"status": "error", "message": str(exc)}

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Dispatch a tool call by name.

        Args:
            name: Tool name.
            arguments: Tool arguments.

        Returns:
            Tool result dict.

        Raises:
            ValueError: If tool name is unknown.
        """
        tool_map = {
            "search": self.search,
            "scrape": self.scrape,
            "analyze_iocs": self.analyze_iocs,
            "run_pentest": self.run_pentest,
            "create_investigation": self.create_investigation,
            "export_stix": self.export_stix,
            "get_threats": self.get_threats,
        }

        handler = tool_map.get(name)
        if handler is None:
            raise ValueError(f"Unknown tool: {name}")

        return await handler(arguments)
