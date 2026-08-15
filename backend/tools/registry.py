"""ToolRegistry — central registry for supported investigation tools.

Provides dynamic registration, discovery by name/category, capability-based
search, and metadata management for all investigation tools.

Usage::

    from backend.tools.registry import get_tool_registry

    registry = get_tool_registry()
    tool = registry.get("nmap_scan")
    tools = registry.find_by_category("infra")
    tools = registry.find_by_capability("port_scanning")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

# Tool categories
CATEGORY_DARK_WEB = "dark_web"
CATEGORY_FORENSIC = "forensic"
CATEGORY_CRYPTO = "crypto"
CATEGORY_PEOPLE = "people"
CATEGORY_INFRA = "infra"
CATEGORY_THREAT_INTEL = "threat_intel"
CATEGORY_OSINT = "osint"
CATEGORY_REPORT = "report"

ALL_CATEGORIES = frozenset({
    CATEGORY_DARK_WEB,
    CATEGORY_FORENSIC,
    CATEGORY_CRYPTO,
    CATEGORY_PEOPLE,
    CATEGORY_INFRA,
    CATEGORY_THREAT_INTEL,
    CATEGORY_OSINT,
    CATEGORY_REPORT,
})


@dataclass
class ToolMetadata:
    """Metadata for a registered investigation tool.

    Attributes:
        name: Unique tool identifier.
        description: Human-readable description.
        category: Tool category (dark_web, forensic, crypto, etc.).
        capabilities: List of capability strings.
        cost: Cost tier (free, low, medium, high).
        reliability_score: Reliability score 0.0-1.0.
        async_interface: Whether the tool exposes async API.
        requires_llm: Whether the tool requires LLM availability.
        agent_name: Associated agent name (if wrapped from agents/).
        extra: Additional metadata dict.
        registered_at: ISO timestamp of registration.
    """

    name: str
    description: str
    category: str
    capabilities: list[str] = field(default_factory=list)
    cost: str = "free"
    reliability_score: float = 0.8
    async_interface: bool = True
    requires_llm: bool = False
    agent_name: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    registered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "capabilities": self.capabilities,
            "cost": self.cost,
            "reliability_score": self.reliability_score,
            "async_interface": self.async_interface,
            "requires_llm": self.requires_llm,
            "agent_name": self.agent_name,
            "extra": self.extra,
            "registered_at": self.registered_at,
        }


class ToolRegistry:
    """Central registry for investigation tools.

    Supports dynamic registration, discovery by name/category/capability,
    and metadata-based search for tool selection.
    """

    def __init__(self) -> None:
        self._tools: dict[str, ToolMetadata] = {}

    def register(self, tool: ToolMetadata) -> None:
        """Register a tool with its metadata.

        Args:
            tool: ToolMetadata instance to register.

        Raises:
            TypeError: If tool is not a ToolMetadata instance.
            ValueError: If tool category is invalid.
        """
        if not isinstance(tool, ToolMetadata):
            raise TypeError(
                f"Expected ToolMetadata instance, got {type(tool).__name__}"
            )
        if tool.category not in ALL_CATEGORIES:
            raise ValueError(
                f"Invalid category '{tool.category}'. "
                f"Valid: {', '.join(sorted(ALL_CATEGORIES))}"
            )
        self._tools[tool.name] = tool
        logger.debug("Registered tool: %s (%s)", tool.name, tool.category)

    def unregister(self, name: str) -> bool:
        """Remove a tool from the registry.

        Args:
            name: Tool name to remove.

        Returns:
            True if removed, False if not found.
        """
        if name in self._tools:
            del self._tools[name]
            logger.debug("Unregistered tool: %s", name)
            return True
        return False

    def get(self, name: str) -> ToolMetadata | None:
        """Retrieve tool metadata by name."""
        return self._tools.get(name)

    def list_tools(self) -> list[dict[str, Any]]:
        """List all registered tools with metadata."""
        return [t.to_dict() for t in self._tools.values()]

    def find_by_category(self, category: str) -> list[ToolMetadata]:
        """Find all tools in a given category."""
        return [t for t in self._tools.values() if t.category == category]

    def find_by_capability(self, capability: str) -> list[ToolMetadata]:
        """Find all tools that have a specific capability."""
        return [
            t for t in self._tools.values()
            if capability in t.capabilities
        ]

    def search(self, query: str) -> list[ToolMetadata]:
        """Search tools by name/description/capability (case-insensitive)."""
        query_lower = query.lower()
        results: list[ToolMetadata] = []
        for tool in self._tools.values():
            if (query_lower in tool.name.lower()
                    or query_lower in tool.description.lower()
                    or any(query_lower in c.lower() for c in tool.capabilities)):
                results.append(tool)
        return results

    def get_categories(self) -> list[str]:
        """Get all categories that have at least one registered tool."""
        return sorted({t.category for t in self._tools.values()})

    def get_capabilities(self) -> list[str]:
        """Get all unique capabilities across registered tools."""
        caps: set[str] = set()
        for tool in self._tools.values():
            caps.update(tool.capabilities)
        return sorted(caps)

    def register_all_defaults(self) -> None:
        """Register the supported default investigation tools."""
        default_tools = _build_default_tools()
        for tool in default_tools:
            self.register(tool)
        logger.info("Registered %d default tools", len(default_tools))

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def __len__(self) -> int:
        return len(self._tools)


def _build_default_tools() -> list[ToolMetadata]:
    """Build tools that have a concrete execution path in ARGUS."""
    tools: list[ToolMetadata] = []

    def _add(
        entries: list[tuple[str, str, list[str]] | tuple[str, str, list[str], str]],
        category: str,
        cost: str,
        reliability: float,
    ) -> None:
        """Helper to add tool entries with optional agent_name."""
        for entry in entries:
            name, desc, caps = entry[0], entry[1], entry[2]
            agent = entry[3] if len(entry) > 3 else None  # type: ignore[index]
            tools.append(ToolMetadata(
                name=name, description=desc, category=category,
                capabilities=caps, cost=cost, reliability_score=reliability,
                agent_name=agent,
            ))

    # === DARK WEB ===
    _add([
        ("tor_crawler", "Tor hidden service crawler — discovers and scrapes .onion sites",
         ["crawling", "scraping", "dark_web", "onion_discovery"], "dark_web_crawler"),
        ("onion_search", "Onion service search engine — searches multiple Tor indexes",
         ["search", "onion", "discovery", "dark_web"], "dark_web_crawler"),
    ], CATEGORY_DARK_WEB, "free", 0.75)

    # === FORENSIC (10 tools) ===
    _add([
        ("ioc_extractor", "IOC extraction engine — extracts indicators from text and URLs",
         ["ioc", "extraction", "parsing", "indicators"], "forensic_analyst"),
        ("ip_geolocator", "IP geolocation — maps IPs to physical locations",
         ["geolocation", "ip", "mapping", "location"], "forensic_analyst"),
        ("subdomain_discoverer", "Subdomain discovery — finds subdomains via certificate transparency",
         ["subdomain", "discovery", "dns", "enumeration"], "forensic_analyst"),
        ("wayback_machine", "Wayback availability lookup — checks the nearest archived snapshot through Tor",
         ["archive", "history", "wayback", "temporal"]),
        ("hash_analyzer", "Text hash analyzer — computes deterministic MD5/SHA digests and entropy",
         ["hash", "text", "digest", "identification"]),
        ("email_header_analyzer", "Email header analyzer — parses routing and authentication headers",
         ["email", "header", "analysis", "tracing"]),
    ], CATEGORY_FORENSIC, "free", 0.85)

    # === CRYPTO (8 tools) ===
    _add([
        ("btc_tracer", "Bitcoin transaction tracer — traces BTC transactions via Blockchair",
         ["btc", "tracing", "blockchain", "transactions"], "crypto_tracer"),
        ("eth_tracer", "Ethereum transaction tracer — traces ETH/ERC-20 via Etherscan",
         ["eth", "tracing", "blockchain", "erc20"], "crypto_tracer"),
        ("wallet_identifier", "Crypto wallet identifier — identifies wallet types and owners",
         ["wallet", "identification", "blockchain", "clustering"]),
    ], CATEGORY_CRYPTO, "low", 0.8)

    # === PEOPLE (8 tools) ===
    _add([
        ("username_search", "Username search engine — searches username across 300+ platforms",
         ["username", "search", "osint", "platforms"], "people_finder"),
        ("email_lookup", "Email OSINT search — finds indexed references through Tor search sources",
         ["email", "lookup", "search", "indexed_references"], "people_finder"),
    ], CATEGORY_PEOPLE, "low", 0.7)

    # === INFRA (10 tools) ===
    _add([
        ("nmap_scanner", "Nmap port scanner — network port scanning and service detection",
         ["nmap", "port_scan", "network", "services"], "infrastructure_mapper"),
        ("nuclei_scanner", "Nuclei vulnerability scanner — template-based vulnerability scanning",
         ["nuclei", "vulnerability", "scanning", "templates"], "infrastructure_mapper"),
        ("subfinder", "Subfinder — passive subdomain enumeration",
         ["subfinder", "subdomain", "enumeration", "passive"], "infrastructure_mapper"),
        ("dns_resolver", "DNS resolver — resolves DNS records (A, AAAA, MX, TXT, NS)",
         ["dns", "resolution", "records", "lookup"], "infrastructure_mapper"),
        ("whois_lookup", "Privacy-filtered WHOIS lookup — returns registry, lifecycle, status and DNS fields without registrant contacts",
         ["whois", "domain", "registration", "lookup"]),
        ("ssl_analyzer", "SSL/TLS certificate analyzer — analyzes certificate chain and validity",
         ["ssl", "tls", "certificate", "analysis"], "infrastructure_mapper"),
        ("http_header_analyzer", "HTTP header analyzer — assesses pasted response security headers without network access",
         ["http", "headers", "security", "analysis"]),
        ("technology_detector", "Technology detector — identifies web technologies and frameworks",
         ["technology", "detection", "wappalyzer", "fingerprinting"], "infrastructure_mapper"),
        ("shodan_query", "Shodan query — searches Shodan for internet-connected devices",
         ["shodan", "search", "devices", "internet"]),
        ("censys_query", "Censys Platform v3 lookup — retrieves a public IP host record",
         ["censys", "lookup", "hosts", "public_ip"]),
    ], CATEGORY_INFRA, "free", 0.85)

    # === THREAT INTEL (10 tools) ===
    _add([
        ("virustotal_lookup", "VirusTotal lookup — queries VT for file/URL/IP/domain reputation",
         ["virustotal", "reputation", "lookup", "scanning"]),
        ("abuseipdb_check", "AbuseIPDB check — checks IP abuse reports and confidence score",
         ["abuseipdb", "ip", "abuse", "reputation"]),
        ("otx_query", "AlienVault OTX query — queries OTX for threat intelligence pulses",
         ["otx", "threat_intel", "pulses", "indicators"]),
        ("threatfox_query", "ThreatFox query — searches ThreatFox for IOC data",
         ["threatfox", "ioc", "malware", "search"]),
        ("urlhaus_query", "URLhaus query — checks URLhaus for malicious URLs",
         ["urlhaus", "url", "malware", "check"]),
        ("attribution_engine", "Threat actor attribution — multi-factor actor attribution",
         ["attribution", "actor", "threat_intel", "correlation"], "threat_intel_analyst"),
    ], CATEGORY_THREAT_INTEL, "low", 0.8)

    # === OSINT (8 tools) ===
    _add([
        ("github_leak_scanner", "GitHub leak scanner — scans GitHub for leaked secrets",
         ["github", "secrets", "leak", "scanning"], "infrastructure_mapper"),
    ], CATEGORY_OSINT, "free", 0.7)

    # === REPORT (6 tools) ===
    _add([
        ("report_generator", "Investigation report generator — generates structured investigation reports",
         ["report", "generation", "structured", "investigation"], "report_writer"),
        ("ioc_report", "IOC report generator — creates IOC summary reports",
         ["ioc", "report", "summary", "indicators"]),
        ("threat_report", "Threat assessment report — generates threat assessment documents",
         ["threat", "report", "assessment", "analysis"]),
        ("timeline_generator", "Timeline generator — creates event timelines from findings",
         ["timeline", "events", "chronology", "visualization"]),
        ("graph_visualizer", "Relationship graph visualizer — creates entity relationship graphs",
         ["graph", "visualization", "relationships", "network"]),
        ("export_engine", "Data export engine — exports findings to JSON/CSV/PDF",
         ["export", "json", "csv", "pdf"]),
    ], CATEGORY_REPORT, "free", 0.9)

    return tools


# Singleton registry — initialized at import time with supported tools only.
_default_tool_registry = ToolRegistry()
_default_tool_registry.register_all_defaults()


def get_tool_registry() -> ToolRegistry:
    """Get the singleton ToolRegistry with all default tools registered.

    Returns:
        The default ToolRegistry instance with supported tools.
    """
    return _default_tool_registry
