"""ARGUS Specialized Investigation Agents.

This package provides 7 specialized agents that wrap legacy argus_engine/ modules
for investigation tasks. Each agent exposes a unified ``async def run(task: dict) -> dict``
interface and is registered in the AgentRegistry for dynamic discovery.

Agents:
    - DarkWebCrawler: Dark web search + scraping via Tor
    - ForensicAnalyst: IOC extraction + geolocation
    - CryptoTracer: BTC/ETH wallet tracing
    - PeopleFinder: Username/email/phone search
    - InfrastructureMapper: Nmap/Nuclei/Subfinder scanning
    - ThreatIntelAnalyst: Attribution + IOC analysis
    - OSINTCollector: General OSINT collection
    - ReportWriter: Investigation report generation
"""

from backend.agents.base import BaseAgent, AgentResult
from backend.agents.registry import AgentRegistry, get_registry
from backend.agents.dark_web import DarkWebCrawler
from backend.agents.forensic import ForensicAnalyst
from backend.agents.crypto import CryptoTracerAgent
from backend.agents.people import PeopleFinder
from backend.agents.infra import InfrastructureMapper
from backend.agents.threat_intel import ThreatIntelAnalyst
from backend.agents.osint import OSINTCollector
from backend.agents.report_writer import ReportWriter

__all__ = [
    "BaseAgent",
    "AgentResult",
    "AgentRegistry",
    "get_registry",
    "DarkWebCrawler",
    "ForensicAnalyst",
    "CryptoTracerAgent",
    "PeopleFinder",
    "InfrastructureMapper",
    "ThreatIntelAnalyst",
    "OSINTCollector",
    "ReportWriter",
]

# Singleton registry with all agents pre-registered
_default_registry = AgentRegistry()
_default_registry.register(DarkWebCrawler())
_default_registry.register(ForensicAnalyst())
_default_registry.register(CryptoTracerAgent())
_default_registry.register(PeopleFinder())
_default_registry.register(InfrastructureMapper())
_default_registry.register(ThreatIntelAnalyst())
_default_registry.register(OSINTCollector())
_default_registry.register(ReportWriter())
